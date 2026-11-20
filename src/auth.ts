import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { PrismaClient, UserRole } from '@prisma/client';

export const SAFE_PROFILE_SELECT = {
  id: true,
  email: true,
  fullName: true,
  role: true,
  mustChangePassword: true,
  status: true,
  createdAt: true,
} as const;

export interface SafeUserProfile {
  id: string;
  email: string;
  fullName: string | null;
  role: UserRole;
  mustChangePassword: boolean;
  status: string;
  createdAt: Date;
}

export interface AuthTokenPayload {
  sub: string;
  email: string;
  role: UserRole;
  iat: number;
  exp: number;
}

export interface AuthenticatedRequest extends Request {
  user?: SafeUserProfile;
}

const DEFAULT_TOKEN_TTL_SECONDS = 60 * 60 * 12; // 12 hours

let cachedEphemeralSecret: string | null = null;

function getJwtSecret(): string {
  const envSecret = process.env.JWT_SECRET?.trim();
  if (envSecret && envSecret.length >= 32) {
    return envSecret;
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'JWT_SECRET environment variable must be set (at least 32 characters) in production.'
    );
  }

  if (!cachedEphemeralSecret) {
    cachedEphemeralSecret = crypto.randomBytes(32).toString('hex');
    console.warn(
      '⚠️  JWT_SECRET is not set (or < 32 chars). Using an ephemeral development secret; sessions will reset on restart.'
    );
  }

  return cachedEphemeralSecret;
}

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + '='.repeat(padding), 'base64');
}

export function signAuthToken(user: { id: string; email: string; role: UserRole }): string {
  const secret = getJwtSecret();
  const ttlRaw = Number(process.env.JWT_EXPIRES_IN_SECONDS);
  const ttlSeconds = Number.isFinite(ttlRaw) && ttlRaw > 0 ? ttlRaw : DEFAULT_TOKEN_TTL_SECONDS;
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: 'HS256', typ: 'JWT' };
  const payload: AuthTokenPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    iat: now,
    exp: now + ttlSeconds,
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest();

  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export function verifyAuthToken(token: string): AuthTokenPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = JSON.parse(base64UrlDecode(encodedHeader).toString('utf8'));
    if (!header || header.alg !== 'HS256' || header.typ !== 'JWT') {
      return null;
    }

    const secret = getJwtSecret();
    const expectedSig = crypto
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest();
    const providedSig = base64UrlDecode(encodedSignature);

    if (
      expectedSig.length !== providedSig.length ||
      !crypto.timingSafeEqual(expectedSig, providedSig)
    ) {
      return null;
    }

    const payload = JSON.parse(base64UrlDecode(encodedPayload).toString('utf8')) as AuthTokenPayload;
    const now = Math.floor(Date.now() / 1000);
    if (!payload.sub || !payload.exp || payload.exp <= now) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export function createRequireAuth(prisma: PrismaClient) {
  return async function requireAuth(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    // Allow CORS preflight requests through
    if (req.method === 'OPTIONS') {
      return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.slice('Bearer '.length).trim();
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const payload = verifyAuthToken(token);
    if (!payload) {
      return res.status(401).json({ error: 'Invalid or expired authentication token' });
    }

    try {
      const user = await prisma.profile.findUnique({
        where: { id: payload.sub },
        select: SAFE_PROFILE_SELECT,
      });

      if (!user || user.status === 'DISABLED') {
        return res.status(401).json({ error: 'Account not found or disabled' });
      }

      req.user = user;
      return next();
    } catch (error) {
      console.error('Auth verification DB error:', error);
      return res.status(500).json({ error: 'Authentication verification failed' });
    }
  };
}

export function requireRole(...allowedRoles: UserRole[]) {
  return function roleGuard(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    return next();
  };
}

export function stripPasswordHash<T extends { passwordHash?: unknown }>(
  profile: T
): Omit<T, 'passwordHash'> {
  const { passwordHash: _removed, ...safe } = profile;
  return safe;
}
