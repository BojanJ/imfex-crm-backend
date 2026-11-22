import express from 'express';
import cors from 'cors';
import { prisma } from './lib/prisma';
import { isEmailConfigured } from './lib/email';
import { createRequireAuth } from './auth';
import { securityHeaders, buildCorsOptions } from './security';
import { isObjectStorageConfigured } from './storage';
import { requestLogger } from './logger';
import { publicAuthRouter, protectedAuthRouter } from './routes/auth';
import { adminRouter } from './routes/admin';
import { emailRouter } from './routes/email';
import { profilesRouter } from './routes/profiles';
import { catalogRouter } from './routes/catalog';
import { customersRouter } from './routes/customers';
import { offersRouter } from './routes/offers';
import { projectsRouter } from './routes/projects';
import { serviceRouter } from './routes/service';
import { documentsRouter } from './routes/documents';
import { calendarRouter } from './routes/calendar';
import { financeRouter } from './routes/finance';
import { settingsRouter } from './routes/settings';

export function createApp() {
  const app = express();
  const requireAuth = createRequireAuth(prisma);

  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use(securityHeaders);
  app.use(requestLogger);
  app.use(cors(buildCorsOptions()));

  // Keep global body limit tight (1mb); allow 15mb only on PDF email & document upload routes
  const standardJson = express.json({ limit: '1mb' });
  const largeJson = express.json({ limit: '15mb' });
  app.use((req, res, next) => {
    const normalizedPath = req.path.replace(/\/+$/, '') || '/';
    if (normalizedPath.startsWith('/api/email/') || normalizedPath === '/api/client-documents') {
      return largeJson(req, res, next);
    }
    return standardJson(req, res, next);
  });
  app.use(express.urlencoded({ limit: '1mb', extended: true }));

  // Health & Root endpoints
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'IMFEX Enterprise CRM Backend',
      emailConfigured: isEmailConfigured(),
      objectStorageConfigured: isObjectStorageConfigured(),
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/', (_req, res) => {
    res.json({
      message: 'Welcome to IMFEX Enterprise CRM Backend API',
      health: '/health',
      emailConfigured: isEmailConfigured(),
      version: '1.0.0',
    });
  });

  // Public auth routes (/api/auth/login, /api/auth/forgot-password, /api/auth/reset-password)
  app.use('/api/auth', publicAuthRouter);

  // Global authentication middleware for all remaining /api/* routes
  app.use('/api', requireAuth);

  // Protected routes
  app.use('/api/auth', protectedAuthRouter);
  app.use('/api', adminRouter);
  app.use('/api/email', emailRouter);
  app.use('/api/profiles', profilesRouter);
  app.use('/api', catalogRouter);
  app.use('/api/customers', customersRouter);
  app.use('/api/offers', offersRouter);
  app.use('/api/projects', projectsRouter);
  app.use('/api', serviceRouter);
  app.use('/api/client-documents', documentsRouter);
  app.use('/api/calendar-events', calendarRouter);
  app.use('/api', financeRouter);
  app.use('/api/company-settings', settingsRouter);

  // JSON 404 fallback for unknown /api/* routes (API-19)
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  // Global Express JSON error handler (CORS rejections, malformed JSON, payload too large) (API-19)
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (res.headersSent) return;
    if (err?.type === 'entity.too.large' || err?.status === 413) {
      return res.status(413).json({ error: 'Request payload is too large.' });
    }
    if (err instanceof SyntaxError && (err as any)?.status === 400 && 'body' in err) {
      return res.status(400).json({ error: 'Malformed JSON request body.' });
    }
    if (typeof err?.message === 'string' && err.message.includes('not allowed by CORS')) {
      return res.status(403).json({ error: 'Origin not allowed by CORS policy.' });
    }
    return res.status(err?.status && err.status >= 400 && err.status < 600 ? err.status : 500).json({
      error: 'Internal server error.',
    });
  });

  return app;
}
