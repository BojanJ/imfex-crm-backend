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

    const profiles = await prisma.profile.findMany({
      select: SAFE_PROFILE_SELECT,
      orderBy: { createdAt: 'asc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.profile.count()));
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

    const rawPassword =
      typeof password === 'string' && password.trim().length >= 8
        ? password.trim()
        : generateSecureTempPassword(12);
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
    if (fullName !== undefined) updateData.fullName = fullName;
    if (isSuperAdmin) {
      if (role !== undefined) {
        const roleCheck = parseEnum(role, USER_ROLES, 'role');
        if (!roleCheck.ok) return res.status(400).json({ error: roleCheck.error });
        updateData.role = roleCheck.value;
      }
      if (status !== undefined) {
        if (status !== 'ACTIVE' && status !== 'DISABLED') {
          return res.status(400).json({ error: 'Invalid status. Allowed values: ACTIVE, DISABLED.' });
        }
        updateData.status = status;
      }
    } else if (role !== undefined || status !== undefined) {
      return res.status(403).json({ error: 'Only SUPER_ADMIN can modify role or status' });
    }
    if (typeof password === 'string' && password.length > 0) {
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
      }
      updateData.passwordHash = await bcrypt.hash(password, 10);
      if (isSuperAdmin && !isSelf) {
        updateData.mustChangePassword = mustChangePassword !== undefined ? Boolean(mustChangePassword) : true;
      } else {
        updateData.mustChangePassword = false;
      }
    } else if (isSuperAdmin && mustChangePassword !== undefined) {
      updateData.mustChangePassword = Boolean(mustChangePassword);
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
