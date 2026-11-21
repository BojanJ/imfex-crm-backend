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
    if (req.path.startsWith('/api/email/') || req.path === '/api/client-documents') {
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

  return app;
}
