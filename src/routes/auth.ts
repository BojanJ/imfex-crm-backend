import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { prisma } from '../lib/prisma';
import { resend, EMAIL_FROM } from '../lib/email';
import {
  SAFE_PROFILE_SELECT,
  AuthenticatedRequest,
  invalidateAuthUserCache,
  signAuthToken,
  stripPasswordHash,
} from '../auth';
import { escapeHtml, isValidEmail, createRateLimiter } from '../security';
import { handleRouteError } from '../validation';
import { logger } from '../logger';
import { recordAudit, getClientIp } from '../audit';
import { generateResetToken, hashResetToken, buildResetPasswordUrl } from '../password-reset';

// Precomputed valid bcrypt hash (cost 10) for constant-time login mitigation when account does not exist (SEC-16)
const DUMMY_PASSWORD_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8d2P0tV8V8lX8m5P2uW5m2v8H0y5xW';

const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 15,
  keyPrefix: 'login',
  message: 'Too many login attempts. Please wait 15 minutes and try again.',
});

const passwordLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyPrefix: 'password',
  message: 'Too many password change attempts. Please wait and try again.',
});

export const publicAuthRouter = Router();

publicAuthRouter.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const cleanPassword = typeof password === 'string' ? password : '';

    if (!cleanEmail || !cleanPassword) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await prisma.profile.findUnique({
      where: { email: cleanEmail },
    });

    if (!user || user.status === 'DISABLED' || !user.passwordHash) {
      // Constant-time mitigation against email/status enumeration (SEC-16)
      await bcrypt.compare(cleanPassword, DUMMY_PASSWORD_HASH);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValid = await bcrypt.compare(cleanPassword, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signAuthToken(user);
    void recordAudit(prisma, undefined, {
      action: 'AUTH_LOGIN',
      entityType: 'Profile',
      entityId: user.id,
      actorUserId: user.id,
      actorEmail: user.email,
      ipAddress: getClientIp(req as AuthenticatedRequest),
    });
    res.json({
      token,
      user: stripPasswordHash(user),
    });
  } catch (error: any) {
    logger.error('login_error', { error: error?.message || String(error) });
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Public Forgot Password Endpoint (IMP-06) — always returns generic 200 to prevent account enumeration
publicAuthRouter.post('/forgot-password', passwordLimiter, async (req, res) => {
  try {
    const cleanEmail = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }

    const genericResponse = {
      success: true,
      message: 'If an active account exists for this email, password reset instructions have been sent.',
    };

    const user = await prisma.profile.findUnique({ where: { email: cleanEmail } });
    if (!user || user.status === 'DISABLED') {
      return res.json(genericResponse);
    }

    const { rawToken, tokenHash, expiresAt } = generateResetToken();
    await prisma.passwordResetToken.create({
      data: {
        profileId: user.id,
        tokenHash,
        expiresAt,
      },
    });

    const resetUrl = buildResetPasswordUrl(rawToken);
    if (resend) {
      const company = await prisma.companySettings.findUnique({ where: { id: 'default' } }).catch(() => null);
      const safeCompanyName = escapeHtml(company?.companyName || 'IMFEX CRM');
      const safeUserName = escapeHtml(user.fullName || user.email);
      const safeResetUrl = escapeHtml(resetUrl);

      await resend.emails
        .send({
          from: EMAIL_FROM,
          to: [user.email],
          subject: `Ресетирање на лозинка - ${company?.companyName || 'IMFEX CRM'}`,
          html: `
          <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; color: #1e293b;">
            <div style="background-color: #0f172a; padding: 20px; text-align: center; border-radius: 12px 12px 0 0;">
              <h1 style="color: #ffffff; margin: 0; font-size: 18px;">${safeCompanyName}</h1>
            </div>
            <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px;">
              <p style="font-size: 14px; font-weight: 700;">Почитувани ${safeUserName},</p>
              <p style="font-size: 13px;">Примивме барање за ресетирање на вашата лозинка. Кликнете на копчето подолу за да поставите нова лозинка (линкот важи 1 час):</p>
              <p style="text-align: center; margin: 24px 0;">
                <a href="${safeResetUrl}" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 13px;">Ресетирај лозинка</a>
              </p>
              <p style="font-size: 11px; color: #64748b;">Доколку не сте го побарале ова, слободно игнорирајте ја оваа порака.</p>
            </div>
          </div>
        `,
        })
        .catch((err) => {
          logger.error('forgot_password_email_error', { error: err?.message || String(err) });
        });
    } else {
      logger.warn('forgot_password_email_skipped_no_resend', { profileId: user.id });
    }

    void recordAudit(prisma, undefined, {
      action: 'PASSWORD_RESET_REQUESTED',
      entityType: 'Profile',
      entityId: user.id,
      actorUserId: user.id,
      actorEmail: user.email,
      ipAddress: getClientIp(req as AuthenticatedRequest),
    });

    return res.json(genericResponse);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/auth/forgot-password');
  }
});

// Public Reset Password Endpoint (IMP-06, SEC-14, SEC-16) — atomically claims single-use token, revokes active JWTs
publicAuthRouter.post('/reset-password', passwordLimiter, async (req, res) => {
  try {
    const rawToken = typeof req.body?.token === 'string' ? req.body.token.trim() : '';
    const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

    if (!rawToken || rawToken.length < 16) {
      return res.status(400).json({ error: 'Invalid or missing reset token.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }

    const tokenHash = hashResetToken(rawToken);
    const record = await prisma.passwordResetToken.findUnique({
      where: { tokenHash },
      include: { profile: true },
    });

    const now = new Date();
    if (!record || record.usedAt || record.expiresAt.getTime() <= now.getTime()) {
      return res.status(400).json({ error: 'This password reset link is invalid or has expired.' });
    }
    if (record.profile.status === 'DISABLED') {
      return res.status(403).json({ error: 'Account is disabled.' });
    }

    const nextHash = await bcrypt.hash(newPassword, 10);
    const claimed = await prisma.$transaction(async (tx) => {
      // Atomic single-use token claim prevents concurrent TOCTOU reuse (SEC-16)
      const claimRes = await tx.passwordResetToken.updateMany({
        where: {
          id: record.id,
          usedAt: null,
          expiresAt: { gt: now },
        },
        data: { usedAt: now },
      });
      if (claimRes.count !== 1) {
        return false;
      }

      // Invalidate any other unused reset tokens for the same user
      await tx.passwordResetToken.updateMany({
        where: {
          profileId: record.profileId,
          usedAt: null,
        },
        data: { usedAt: now },
      });

      await tx.profile.update({
        where: { id: record.profileId },
        data: {
          passwordHash: nextHash,
          mustChangePassword: false,
          tokenVersion: { increment: 1 },
        },
      });
      return true;
    });

    if (!claimed) {
      return res.status(400).json({ error: 'This password reset link is invalid or has expired.' });
    }

    invalidateAuthUserCache(record.profileId);
    void recordAudit(prisma, undefined, {
      action: 'PASSWORD_RESET_COMPLETED',
      entityType: 'Profile',
      entityId: record.profileId,
      actorUserId: record.profileId,
      actorEmail: record.profile.email,
      ipAddress: getClientIp(req as AuthenticatedRequest),
    });

    return res.json({ success: true, message: 'Password has been reset successfully.' });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/auth/reset-password');
  }
});

export const protectedAuthRouter = Router();

protectedAuthRouter.get('/me', (req: AuthenticatedRequest, res) => {
  res.json({ user: req.user });
});

protectedAuthRouter.post('/change-password', passwordLimiter, async (req: AuthenticatedRequest, res) => {
  try {
    const { currentPassword, newPassword } = req.body ?? {};
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string' || !currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
    }
    if (newPassword === currentPassword) {
      return res.status(400).json({ error: 'New password must be different from your current password.' });
    }

    const user = await prisma.profile.findUnique({ where: { id: req.user!.id } });
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: 'Account not found.' });
    }

    const matches = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!matches) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const nextHash = await bcrypt.hash(newPassword, 10);
    const updatedWithVersion = await prisma.profile.update({
      where: { id: user.id },
      data: {
        passwordHash: nextHash,
        mustChangePassword: false,
        tokenVersion: { increment: 1 },
      },
      select: {
        ...SAFE_PROFILE_SELECT,
        tokenVersion: true,
      },
    });
    invalidateAuthUserCache(user.id);
    const freshToken = signAuthToken(updatedWithVersion);
    const updated = stripPasswordHash(updatedWithVersion);
    void recordAudit(prisma, req, { action: 'PASSWORD_CHANGED', entityType: 'Profile', entityId: user.id });

    res.json({ success: true, token: freshToken, user: updated });
  } catch (error: any) {
    logger.error('change_password_error', { error: error?.message || String(error) });
    res.status(500).json({ error: 'Failed to change password.' });
  }
});
