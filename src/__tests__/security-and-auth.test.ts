import { describe, it, expect, beforeAll } from 'vitest';
import { signAuthToken, verifyAuthToken, stripPasswordHash, requireRole } from '../auth';
import {
  escapeHtml,
  isValidEmail,
  generateSecureTempPassword,
  createRateLimiter,
  validateDocumentUpload,
} from '../security';
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

  it('enforces sliding-window rate limits with 429 and Retry-After', () => {
    const limiter = createRateLimiter({ windowMs: 60_000, max: 2, keyPrefix: 'test' });
    const req: any = { headers: { 'x-forwarded-for': '203.0.113.5' }, socket: {} };
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
    limiter(req, res, () => nextCount++);
    limiter(req, res, () => nextCount++);
    limiter(req, res, () => nextCount++);

    expect(nextCount).toBe(2);
    expect(lastStatus).toBe(429);
    expect(Number(headers['Retry-After'])).toBeGreaterThan(0);
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
