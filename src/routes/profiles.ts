import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { prisma } from '../lib/prisma';
import {
  SAFE_PROFILE_SELECT,
  AuthenticatedRequest,
  invalidateAuthUserCache,
  requireRole,
} from '../auth';
import { isValidEmail, generateSecureTempPassword } from '../security';
import {
  isUuid,
  USER_ROLES,
  parseEnum,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const profilesRouter = Router();

profilesRouter.get('/', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [profiles, totalCount] = await Promise.all([
      prisma.profile.findMany({
        select: SAFE_PROFILE_SELECT,
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.profile.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(profiles);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/profiles');
  }
});

profilesRouter.post('/', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    const { email, fullName, role, password } = req.body ?? {};
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    const roleCheck = parseEnum(role, USER_ROLES, 'role', 'USER');
    if (!roleCheck.ok) return res.status(400).json({ error: roleCheck.error });

    const providedPassword = typeof password === 'string' ? password.trim() : '';
    if (providedPassword.length > 0 && providedPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }
    const rawPassword = providedPassword.length >= 8 ? providedPassword : generateSecureTempPassword(12);
    const passwordHash = await bcrypt.hash(rawPassword, 10);
    const profile = await prisma.profile.upsert({
      where: { email: email.trim().toLowerCase() },
      update: { fullName, role: roleCheck.value, status: 'ACTIVE' },
      create: {
        email: email.trim().toLowerCase(),
        fullName,
        role: roleCheck.value,
        passwordHash,
        mustChangePassword: true,
        status: 'ACTIVE',
      },
      select: SAFE_PROFILE_SELECT,
    });
    invalidateAuthUserCache(profile.id);
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PROFILE_UPSERTED',
      entityType: 'Profile',
      entityId: profile.id,
      metadata: { email: profile.email, role: profile.role },
    });
    res.json(profile);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/profiles');
  }
});

profilesRouter.put('/:id', async (req: AuthenticatedRequest, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid profile ID format.' });
    }
    const isSuperAdmin = req.user?.role === 'SUPER_ADMIN';
    const isSelf = req.user?.id === id;

    if (!isSuperAdmin && !isSelf) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const { fullName, role, status, password, mustChangePassword } = req.body ?? {};
    const updateData: any = {};
    let shouldRevokeSessions = false;

    if (fullName !== undefined) updateData.fullName = fullName;
    if (isSuperAdmin) {
      if (role !== undefined) {
        const roleCheck = parseEnum(role, USER_ROLES, 'role');
        if (!roleCheck.ok) return res.status(400).json({ error: roleCheck.error });
        if (isSelf && roleCheck.value !== 'SUPER_ADMIN') {
          return res.status(400).json({ error: 'Cannot demote your own SUPER_ADMIN account.' });
        }
        updateData.role = roleCheck.value;
      }
      if (status !== undefined) {
        if (status !== 'ACTIVE' && status !== 'DISABLED') {
          return res.status(400).json({ error: 'Invalid status. Allowed values: ACTIVE, DISABLED.' });
        }
        if (isSelf && status === 'DISABLED') {
          return res.status(400).json({ error: 'Cannot disable your own active account.' });
        }
        updateData.status = status;
      }
    } else if (role !== undefined || status !== undefined) {
      return res.status(403).json({ error: 'Only SUPER_ADMIN can modify role or status' });
    }

    // SEC-12: Prevent self-service password change bypass without currentPassword/rate limit
    if (password !== undefined && password !== null && password !== '') {
      if (isSelf) {
        return res.status(400).json({
          error: 'Use POST /api/auth/change-password to change your own password.',
        });
      }
      if (!isSuperAdmin) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
      if (typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
      }
      updateData.passwordHash = await bcrypt.hash(password, 10);
      updateData.mustChangePassword = mustChangePassword !== undefined ? Boolean(mustChangePassword) : true;
      shouldRevokeSessions = true;
    } else if (isSuperAdmin && mustChangePassword !== undefined) {
      updateData.mustChangePassword = Boolean(mustChangePassword);
    }

    // SEC-16: Prevent demoting or disabling the last active SUPER_ADMIN
    if (
      isSuperAdmin &&
      ((updateData.role !== undefined && updateData.role !== 'SUPER_ADMIN') ||
        updateData.status === 'DISABLED')
    ) {
      const targetUser = await prisma.profile.findUnique({
        where: { id },
        select: { role: true, status: true },
      });
      if (!targetUser) {
        return res.status(404).json({ error: 'Profile not found.' });
      }
      if (targetUser.role === 'SUPER_ADMIN' && targetUser.status === 'ACTIVE') {
        const otherActiveAdmins = await prisma.profile.count({
          where: { role: 'SUPER_ADMIN', status: 'ACTIVE', id: { not: id } },
        });
        if (otherActiveAdmins === 0) {
          return res.status(400).json({
            error: 'Cannot demote or disable the last active SUPER_ADMIN account.',
          });
        }
      }
    }

    if (updateData.role !== undefined || updateData.status !== undefined) {
      shouldRevokeSessions = true;
    }
    if (shouldRevokeSessions) {
      updateData.tokenVersion = { increment: 1 };
    }

    const profile = await prisma.profile.update({
      where: { id },
      data: updateData,
      select: SAFE_PROFILE_SELECT,
    });
    invalidateAuthUserCache(id);
    void recordAudit(prisma, req, { action: 'PROFILE_UPDATED', entityType: 'Profile', entityId: id });
    res.json(profile);
  } catch (error) {
    return handleRouteError(res, error, 'PUT /api/profiles/:id');
  }
});

profilesRouter.delete('/:id', requireRole('SUPER_ADMIN'), async (req: AuthenticatedRequest, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid profile ID format.' });
    }
    if (req.user?.id === id) {
      return res.status(400).json({ error: 'Cannot delete your own active account' });
    }
    await prisma.profile.delete({ where: { id } });
    invalidateAuthUserCache(id);
    void recordAudit(prisma, req, { action: 'PROFILE_DELETED', entityType: 'Profile', entityId: id });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/profiles/:id');
  }
});
