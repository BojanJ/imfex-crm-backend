import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { CorsOptions } from 'cors';

export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function isValidEmail(email: unknown): boolean {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length === 0 || trimmed.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

export function generateSecureTempPassword(length = 12): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

export function securityHeaders(req: Request, res: Response, next: NextFunction) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production' || req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

export function createRateLimiter(options: {
  windowMs: number;
  max: number;
  keyPrefix: string;
  message?: string;
}) {
  const buckets = new Map<string, RateLimitBucket>();

  return function rateLimiter(req: Request, res: Response, next: NextFunction) {
    const now = Date.now();
    // Opportunistic cleanup to keep memory bounded
    if (buckets.size > 5000) {
      for (const [k, v] of buckets.entries()) {
        if (v.resetAt <= now) buckets.delete(k);
      }
    }

    const ip =
      (typeof req.headers['x-forwarded-for'] === 'string'
        ? req.headers['x-forwarded-for'].split(',')[0].trim()
        : '') ||
      req.ip ||
      req.socket.remoteAddress ||
      'unknown';

    const key = `${options.keyPrefix}:${ip}`;
    const current = buckets.get(key);

    if (!current || current.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + options.windowMs });
      return next();
    }

    if (current.count >= options.max) {
      const retryAfterSec = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      return res.status(429).json({
        error: options.message || 'Too many requests. Please try again later.',
      });
    }

    current.count += 1;
    return next();
  };
}

export function buildCorsOptions(): CorsOptions {
  const envOrigins = [
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : []),
    ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []),
  ]
    .map((o) => o.trim().replace(/\/$/, ''))
    .filter(Boolean);

  const staticAllowed = new Set<string>([
    'http://localhost:3000',
    'http://localhost:3001',
    'http://127.0.0.1:3000',
    ...envOrigins,
  ]);

  const vercelPreviewPattern = /^https:\/\/imfex-crm-frontend(?:-[a-z0-9-]+)?\.vercel\.app$/i;

  return {
    origin(origin, callback) {
      // Allow same-origin / server-to-server / curl requests without an Origin header
      if (!origin) return callback(null, true);
      const normalized = origin.replace(/\/$/, '');
      if (staticAllowed.has(normalized) || vercelPreviewPattern.test(normalized)) {
        return callback(null, true);
      }
      return callback(new Error(`Origin ${origin} not allowed by CORS`));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 600,
  };
}

const ALLOWED_DATA_MIME_TYPES = new Set<string>([
  'application/pdf',
  'image/png',
  'image/jpeg',
  'image/jpg',
  'image/webp',
  'image/gif',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel',
  'text/csv',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/msword',
  'text/plain',
]);

const FORBIDDEN_EXTENSIONS = /\.(html?|svgz?|xhtml|js|mjs|cjs|exe|bat|cmd|ps1|sh|php)$/i;

export function validateDocumentUpload(
  fileUrl: unknown,
  fileName?: unknown
): { ok: true } | { ok: false; error: string } {
  if (typeof fileName === 'string' && FORBIDDEN_EXTENSIONS.test(fileName.trim())) {
    return { ok: false, error: 'Unsafe file extension is not permitted.' };
  }

  if (fileUrl === undefined || fileUrl === null || fileUrl === '' || fileUrl === '#') {
    return { ok: true };
  }

  if (typeof fileUrl !== 'string') {
    return { ok: false, error: 'Invalid fileUrl value.' };
  }

  const trimmed = fileUrl.trim();
  if (/^(javascript|vbscript):/i.test(trimmed)) {
    return { ok: false, error: 'Unsafe URI scheme is not permitted.' };
  }

  if (trimmed.startsWith('https://') || trimmed.startsWith('http://')) {
    return { ok: true };
  }

  if (!trimmed.startsWith('data:')) {
    return { ok: false, error: 'Only safe data URLs or HTTP(S) document URLs are permitted.' };
  }

  const match = trimmed.match(/^data:([^;]+);base64,(.+)$/s);
  if (!match) {
    return { ok: false, error: 'Malformed base64 data URI.' };
  }

  const mime = match[1].toLowerCase().trim();
  const base64Body = match[2].trim();

  if (!ALLOWED_DATA_MIME_TYPES.has(mime)) {
    return { ok: false, error: `Unsupported or unsafe file MIME type: ${mime}` };
  }

  // Verify magic bytes for PDF and raster images to block MIME spoofing (e.g. HTML disguised as PDF)
  const headBuf = Buffer.from(base64Body.slice(0, 32), 'base64');
  if (mime === 'application/pdf') {
    if (!headBuf.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
      return { ok: false, error: 'Invalid PDF file header (magic bytes mismatch).' };
    }
  } else if (mime === 'image/png') {
    const pngMagic = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
    if (!headBuf.subarray(0, 4).equals(pngMagic)) {
      return { ok: false, error: 'Invalid PNG file header.' };
    }
  } else if (mime === 'image/jpeg' || mime === 'image/jpg') {
    if (!(headBuf[0] === 0xff && headBuf[1] === 0xd8 && headBuf[2] === 0xff)) {
      return { ok: false, error: 'Invalid JPEG file header.' };
    }
  } else if (mime === 'image/gif') {
    const sig = headBuf.subarray(0, 6).toString('ascii');
    if (sig !== 'GIF87a' && sig !== 'GIF89a') {
      return { ok: false, error: 'Invalid GIF file header.' };
    }
  } else if (mime === 'image/webp') {
    if (headBuf.subarray(0, 4).toString('ascii') !== 'RIFF' || headBuf.subarray(8, 12).toString('ascii') !== 'WEBP') {
      return { ok: false, error: 'Invalid WEBP file header.' };
    }
  }

  return { ok: true };
}
