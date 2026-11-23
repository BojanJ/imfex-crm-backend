import { describe, it, expect, beforeAll } from 'vitest';
import {
  signAuthToken,
  verifyAuthToken,
  stripPasswordHash,
  requireRole,
  ROLE_GROUPS,
  createRequireAuth,
  invalidateAuthUserCache,
} from '../auth';
import {
  escapeHtml,
  isValidEmail,
  generateSecureTempPassword,
  createRateLimiter,
  validateDocumentUpload,
  validateSignatureUrl,
  buildCorsOptions,
} from '../security';
import { getClientIp } from '../audit';
import { generateResetToken, hashResetToken } from '../password-reset';

beforeAll(() => {
  process.env.JWT_SECRET = 'test-secret-key-at-least-32-characters-long-123456';
});

describe('Auth JWT & RBAC (SEC-01, SEC-04)', () => {
  it('signs and verifies valid HS256 tokens', () => {
    const token = signAuthToken({
      id: '11111111-1111-4111-8111-111111111111',
      email: 'admin@imfex.com',
      role: 'SUPER_ADMIN',
    });
    const payload = verifyAuthToken(token);
    expect(payload).not.toBeNull();
    expect(payload?.sub).toBe('11111111-1111-4111-8111-111111111111');
    expect(payload?.email).toBe('admin@imfex.com');
    expect(payload?.role).toBe('SUPER_ADMIN');
  });

  it('rejects tampered JWT signatures', () => {
    const token = signAuthToken({
      id: '11111111-1111-4111-8111-111111111111',
      email: 'user@imfex.com',
      role: 'USER',
    });
    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}.invalid_signature_xyz`;
    expect(verifyAuthToken(tampered)).toBeNull();
  });

  it('strips passwordHash cleanly from profile objects', () => {
    const clean = stripPasswordHash({
      id: '1',
      email: 'a@b.com',
      passwordHash: '$2b$10$secret',
      role: 'USER',
    });
    expect('passwordHash' in clean).toBe(false);
    expect(clean.email).toBe('a@b.com');
  });

  it('enforces RBAC role restrictions', () => {
    const middleware = requireRole('SUPER_ADMIN');
    let statusCode = 200;
    let nextCalled = false;
    const res: any = {
      status(code: number) {
        statusCode = code;
        return this;
      },
      json() {
        return this;
      },
    };
    middleware({ user: { role: 'USER' } } as any, res, () => {
      nextCalled = true;
    });
    expect(statusCode).toBe(403);
    expect(nextCalled).toBe(false);

    statusCode = 200;
    middleware({ user: { role: 'SUPER_ADMIN' } } as any, res, () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
  });
});

describe('Security helpers (SEC-05, SEC-06, SEC-07, SEC-09)', () => {
  it('escapes HTML special characters', () => {
    expect(escapeHtml(`<script>alert("x" & 'y')</script>`)).toBe(
      '&lt;script&gt;alert(&quot;x&quot; &amp; &#39;y&#39;)&lt;/script&gt;'
    );
  });

  it('validates email addresses strictly', () => {
    expect(isValidEmail('user@imfex.com')).toBe(true);
    expect(isValidEmail('not-an-email')).toBe(false);
    expect(isValidEmail('')).toBe(false);
    expect(isValidEmail(null)).toBe(false);
  });

  it('generates strong random temporary passwords', () => {
    const p1 = generateSecureTempPassword(12);
    const p2 = generateSecureTempPassword(12);
    expect(p1.length).toBe(12);
    expect(p1).not.toBe(p2);
  });

  it('blocks XSS file uploads (HTML, SVG, spoofed PDF) and accepts valid PDF', () => {
    const htmlUrl = `data:text/html;base64,${Buffer.from('<script>alert(1)</script>').toString('base64')}`;
    const svgUrl = `data:image/svg+xml;base64,${Buffer.from('<svg onload=alert(1)/>').toString('base64')}`;
    const fakePdfUrl = `data:application/pdf;base64,${Buffer.from('<html>xss</html>').toString('base64')}`;
    const realPdfUrl = `data:application/pdf;base64,${Buffer.from('%PDF-1.7\n').toString('base64')}`;

    expect(validateDocumentUpload(htmlUrl, 'doc.html').ok).toBe(false);
    expect(validateDocumentUpload(svgUrl, 'img.svg').ok).toBe(false);
    expect(validateDocumentUpload(fakePdfUrl, 'spoof.pdf').ok).toBe(false);
    expect(validateDocumentUpload(realPdfUrl, 'evil.html').ok).toBe(false);
    expect(validateDocumentUpload(realPdfUrl, 'quote.pdf').ok).toBe(true);
  });

  it('enforces sliding-window rate limits with 429 and Retry-After and ignores spoofed X-Forwarded-For (SEC-13)', () => {
    const limiter = createRateLimiter({ windowMs: 60_000, max: 2, keyPrefix: 'test', maxBuckets: 3 });
    let lastStatus = 200;
    const headers: Record<string, string> = {};
    const res: any = {
      setHeader: (k: string, v: string) => {
        headers[k] = v;
      },
      status(code: number) {
        lastStatus = code;
        return this;
      },
      json() {
        return this;
      },
    };
    let nextCount = 0;
    // Rotating spoofed X-Forwarded-For headers from the same real req.ip must NOT bypass the limiter
    limiter({ ip: '198.51.100.10', headers: { 'x-forwarded-for': '1.1.1.1' }, socket: {} } as any, res, () => nextCount++);
    limiter({ ip: '198.51.100.10', headers: { 'x-forwarded-for': '2.2.2.2' }, socket: {} } as any, res, () => nextCount++);
    limiter({ ip: '198.51.100.10', headers: { 'x-forwarded-for': '3.3.3.3' }, socket: {} } as any, res, () => nextCount++);

    expect(nextCount).toBe(2);
    expect(lastStatus).toBe(429);
    expect(Number(headers['Retry-After'])).toBeGreaterThan(0);

    // getClientIp also relies on req.ip instead of untrusted X-Forwarded-For
    expect(
      getClientIp({ ip: '198.51.100.10', headers: { 'x-forwarded-for': '9.9.9.9' } } as any)
    ).toBe('198.51.100.10');
  });
});

describe('Round 2 Security Hardening (SEC-11, SEC-14, SEC-15, SEC-17)', () => {
  it('enforces granular RBAC role groups (SEC-11)', () => {
    const runGuard = (roles: readonly any[], userRole: string) => {
      const mw = requireRole(...(roles as any));
      let status = 200;
      let passed = false;
      const res: any = {
        status(code: number) {
          status = code;
          return this;
        },
        json() {
          return this;
        },
      };
      mw({ user: { role: userRole } } as any, res, () => {
        passed = true;
      });
      return { status, passed };
    };

    expect(runGuard(ROLE_GROUPS.DESTRUCTIVE_DELETE, 'USER').status).toBe(403);
    expect(runGuard(ROLE_GROUPS.DESTRUCTIVE_DELETE, 'ACCOUNTANT').status).toBe(403);
    expect(runGuard(ROLE_GROUPS.DESTRUCTIVE_DELETE, 'SUPER_ADMIN').passed).toBe(true);

    expect(runGuard(ROLE_GROUPS.FINANCE_WRITE, 'TECHNICIAN').status).toBe(403);
    expect(runGuard(ROLE_GROUPS.FINANCE_WRITE, 'USER').status).toBe(403);
    expect(runGuard(ROLE_GROUPS.FINANCE_WRITE, 'ACCOUNTANT').passed).toBe(true);

    expect(runGuard(ROLE_GROUPS.CATALOG_WRITE, 'TECHNICIAN').status).toBe(403);
    expect(runGuard(ROLE_GROUPS.CATALOG_WRITE, 'SALES').passed).toBe(true);
  });

  it('revokes JWTs on tokenVersion mismatch and enforces mustChangePassword server-side (SEC-14)', async () => {
    invalidateAuthUserCache();
    const userId = '22222222-2222-4222-8222-222222222222';
    let dbUser = {
      id: userId,
      email: 'staff@imfex.com',
      fullName: 'Staff User',
      role: 'SALES' as const,
      mustChangePassword: true,
      status: 'ACTIVE',
      createdAt: new Date(),
      tokenVersion: 2,
    };

    const mockPrisma: any = {
      profile: {
        findUnique: async () => ({ ...dbUser }),
      },
    };
    const requireAuth = createRequireAuth(mockPrisma);

    const makeRes = () => {
      const state: { status: number; body: any } = { status: 200, body: null };
      const res: any = {
        status(code: number) {
          state.status = code;
          return this;
        },
        json(payload: any) {
          state.body = payload;
          return this;
        },
      };
      return { res, state };
    };

    // Old token (tv=1 vs DB tv=2) must be rejected with 401
    const oldToken = signAuthToken({ id: userId, email: dbUser.email, role: 'SALES', tokenVersion: 1 });
    const r1 = makeRes();
    let next1 = false;
    await requireAuth(
      { method: 'GET', path: '/offers', headers: { authorization: `Bearer ${oldToken}` } } as any,
      r1.res,
      () => {
        next1 = true;
      }
    );
    expect(next1).toBe(false);
    expect(r1.state.status).toBe(401);

    // Valid token (tv=2) with mustChangePassword=true: blocked on /offers (403), allowed on /auth/change-password
    const currentToken = signAuthToken({ id: userId, email: dbUser.email, role: 'SALES', tokenVersion: 2 });
    const r2 = makeRes();
    let next2 = false;
    await requireAuth(
      { method: 'GET', path: '/offers', headers: { authorization: `Bearer ${currentToken}` } } as any,
      r2.res,
      () => {
        next2 = true;
      }
    );
    expect(next2).toBe(false);
    expect(r2.state.status).toBe(403);
    expect(r2.state.body?.code).toBe('MUST_CHANGE_PASSWORD');

    const r3 = makeRes();
    let next3 = false;
    await requireAuth(
      { method: 'POST', path: '/auth/change-password', headers: { authorization: `Bearer ${currentToken}` } } as any,
      r3.res,
      () => {
        next3 = true;
      }
    );
    expect(next3).toBe(true);
    expect(r3.state.status).toBe(200);
  });

  it('validates project signatureUrl strictly against XSS and spoofed images (SEC-15)', () => {
    const validPng = `data:image/png;base64,${Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).toString('base64')}`;
    const fakePng = `data:image/png;base64,${Buffer.from('<script>alert(1)</script>').toString('base64')}`;
    const svgSig = `data:image/svg+xml;base64,${Buffer.from('<svg onload=alert(1)/>').toString('base64')}`;

    expect(validateSignatureUrl('').ok).toBe(true);
    expect(validateSignatureUrl(null).ok).toBe(true);
    expect(validateSignatureUrl(validPng).ok).toBe(true);
    expect(validateSignatureUrl('storage://docs/sig.png').ok).toBe(true);

    expect(validateSignatureUrl('javascript:alert(1)').ok).toBe(false);
    expect(validateSignatureUrl('https://evil.example/sig.png').ok).toBe(false);
    expect(validateSignatureUrl(svgSig).ok).toBe(false);
    expect(validateSignatureUrl(fakePng).ok).toBe(false);
  });

  it('hardens production CORS origins (SEC-17)', async () => {
    const prevNodeEnv = process.env.NODE_ENV;
    const prevPreviews = process.env.ALLOW_VERCEL_PREVIEWS;
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.ALLOW_VERCEL_PREVIEWS;
      const corsOpts = buildCorsOptions();
      const checkOrigin = (origin: string) =>
        new Promise<boolean>((resolve) => {
          (corsOpts.origin as any)(origin, (err: Error | null, allowed?: boolean) => {
            resolve(!err && Boolean(allowed));
          });
        });

      expect(await checkOrigin('https://imfex-crm-frontend.vercel.app')).toBe(true);
      expect(await checkOrigin('https://imfex-crm-frontend-4yu1.vercel.app')).toBe(true);
      expect(await checkOrigin('http://localhost:3000')).toBe(false);
      expect(await checkOrigin('https://imfex-crm-frontend-attacker.vercel.app')).toBe(false);
    } finally {
      process.env.NODE_ENV = prevNodeEnv;
      if (prevPreviews !== undefined) process.env.ALLOW_VERCEL_PREVIEWS = prevPreviews;
    }
  });
});

describe('Password reset token utilities (IMP-06)', () => {
  it('generates unique tokens whose SHA-256 hash matches deterministically', () => {
    const a = generateResetToken();
    const b = generateResetToken();
    expect(a.rawToken).not.toBe(b.rawToken);
    expect(a.tokenHash).toBe(hashResetToken(a.rawToken));
    expect(a.tokenHash).not.toBe(a.rawToken);
    expect(a.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });
});
