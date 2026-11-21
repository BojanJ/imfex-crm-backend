import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { AuthenticatedRequest } from './auth';

export type LogLevel = 'info' | 'warn' | 'error';

export function logStructured(level: LogLevel, message: string, fields: Record<string, unknown> = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service: 'imfex-crm-backend',
    message,
    ...fields,
  };
  const line = JSON.stringify(entry);
  if (level === 'error') {
    console.error(line);
  } else if (level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export const logger = {
  info: (message: string, fields?: Record<string, unknown>) => logStructured('info', message, fields),
  warn: (message: string, fields?: Record<string, unknown>) => logStructured('warn', message, fields),
  error: (message: string, fields?: Record<string, unknown>) => logStructured('error', message, fields),
};

export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const requestId =
    (typeof req.headers['x-request-id'] === 'string' && req.headers['x-request-id'].trim()) ||
    crypto.randomUUID();
  const startMs = Date.now();
  res.setHeader('X-Request-Id', requestId);
  (req as Request & { requestId?: string }).requestId = requestId;

  res.on('finish', () => {
    // Skip noisy health checks in routine logs unless error
    if (req.path === '/health' && res.statusCode < 400) return;
    const authReq = req as AuthenticatedRequest;
    const durationMs = Date.now() - startMs;
    const level: LogLevel =
      res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';

    logStructured(level, 'http_request', {
      requestId,
      method: req.method,
      path: req.originalUrl || req.path,
      status: res.statusCode,
      durationMs,
      userId: authReq.user?.id || null,
      userRole: authReq.user?.role || null,
    });
  });

  next();
}
