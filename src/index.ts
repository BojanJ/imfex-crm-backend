import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { Resend } from 'resend';
import {
  SAFE_PROFILE_SELECT,
  AuthenticatedRequest,
  createRequireAuth,
  requireRole,
  signAuthToken,
  stripPasswordHash,
} from './auth';
import {
  escapeHtml,
  isValidEmail,
  generateSecureTempPassword,
  securityHeaders,
  createRateLimiter,
  buildCorsOptions,
  validateDocumentUpload,
} from './security';

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;
const requireAuth = createRequireAuth(prisma);

const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 15,
  keyPrefix: 'login',
  message: 'Too many login attempts. Please wait 15 minutes and try again.',
});
const emailLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyPrefix: 'email',
  message: 'Email rate limit exceeded. Please try again shortly.',
});
const passwordLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  keyPrefix: 'password',
  message: 'Too many password change attempts. Please wait and try again.',
});

// Initialize Resend Email Service
const resendApiKey = process.env.RESEND_API_KEY || '';
const resend = resendApiKey ? new Resend(resendApiKey) : null;
const EMAIL_FROM = process.env.EMAIL_FROM || 'IMFEX CRM <onboarding@resend.dev>';

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(securityHeaders);
app.use(cors(buildCorsOptions()));

// Keep global body limit tight (1mb); allow 15mb only on PDF email & document upload routes
const standardJson = express.json({ limit: '1mb' });
const largeJson = express.json({ limit: '15mb' });
app.use((req, res, next) => {
  if (req.path === '/api/email/send-offer' || req.path === '/api/client-documents') {
    return largeJson(req, res, next);
  }
  return standardJson(req, res, next);
});
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// Automatically ensure new columns exist in PostgreSQL on startup
async function ensureSchemaColumns() {
  try {
    await prisma.$executeRawUnsafe(
      `ALTER TABLE specification_keys ADD COLUMN IF NOT EXISTS default_value TEXT;`
    );
    await prisma.$executeRawUnsafe(
      `ALTER TABLE specification_options ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT FALSE;`
    );
    await prisma.$executeRawUnsafe(
      `ALTER TABLE offer_item_specifications ALTER COLUMN specification_key_id DROP NOT NULL;`
    );
    await prisma.$executeRawUnsafe(
      `ALTER TABLE offer_item_specifications ADD COLUMN IF NOT EXISTS custom_key_name TEXT;`
    );
    await prisma.$executeRawUnsafe(
      `ALTER TABLE offer_item_specifications ADD COLUMN IF NOT EXISTS custom_price_modifier DECIMAL(10, 2) DEFAULT 0.00;`
    );
    await prisma.$executeRawUnsafe(
      `ALTER TABLE client_documents ADD COLUMN IF NOT EXISTS file_name TEXT;`
    );
    await prisma.$executeRawUnsafe(
      `ALTER TABLE client_documents ADD COLUMN IF NOT EXISTS size_bytes INTEGER;`
    );
  } catch (err: any) {
    console.warn('Auto schema evolution notice:', err?.message || err);
  }
}
ensureSchemaColumns();

// Health Check Endpoint for Render
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'IMFEX Enterprise CRM Backend',
    emailConfigured: Boolean(resendApiKey),
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to IMFEX Enterprise CRM Backend API',
    health: '/health',
    emailConfigured: Boolean(resendApiKey),
    version: '1.0.0',
  });
});

// ==========================================
// PUBLIC AUTHENTICATION ENDPOINT
// ==========================================

app.post('/api/auth/login', loginLimiter, async (req, res) => {
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
      return res.status(401).json({ error: 'Invalid credentials or account disabled' });
    }

    const isValid = await bcrypt.compare(cleanPassword, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signAuthToken(user);
    res.json({
      token,
      user: stripPasswordHash(user),
    });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// ==========================================
// GLOBAL AUTHENTICATION MIDDLEWARE FOR /api/*
// ==========================================
app.use('/api', requireAuth);

// Verify current authenticated session
app.get('/api/auth/me', (req: AuthenticatedRequest, res) => {
  res.json({ user: req.user });
});

// Change current user's password (verifies currentPassword, clears mustChangePassword)
app.post('/api/auth/change-password', passwordLimiter, async (req: AuthenticatedRequest, res) => {
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
    const updated = await prisma.profile.update({
      where: { id: user.id },
      data: { passwordHash: nextHash, mustChangePassword: false },
      select: SAFE_PROFILE_SELECT,
    });

    res.json({ success: true, user: updated });
  } catch (error: any) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password.' });
  }
});

// ==========================================
// PROTECTED ADMIN MAINTENANCE ENDPOINTS
// ==========================================
function isAdminDbToolsAllowed(): boolean {
  if (process.env.NODE_ENV === 'production') {
    return process.env.ALLOW_ADMIN_DB_TOOLS === 'true';
  }
  return true;
}

// Admin Database Cleanup & UTF-8 Sync Endpoint (POST + SUPER_ADMIN + explicit confirmation)
app.post('/api/admin/clean-database', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    if (!isAdminDbToolsAllowed()) {
      return res.status(403).json({
        error: 'Admin database maintenance endpoints are disabled in production.',
      });
    }

    if (req.body?.confirm !== 'CLEAN_DATABASE') {
      return res.status(400).json({
        error: 'Explicit confirmation { "confirm": "CLEAN_DATABASE" } is required.',
      });
    }

    const allCust = await prisma.customer.findMany();
    const corruptedCust = allCust.filter(
      (c) => (c.name && c.name.includes('?')) || (c.companyName && c.companyName.includes('?'))
    );

    for (const c of corruptedCust) {
      await prisma.offerItem.deleteMany({ where: { offer: { customerId: c.id } } });
      await prisma.offer.deleteMany({ where: { customerId: c.id } });
      await prisma.project.deleteMany({ where: { customerId: c.id } });
      await prisma.serviceTicket.deleteMany({ where: { customerId: c.id } });
      await prisma.installedItem.deleteMany({ where: { customerId: c.id } });
      await prisma.customer.delete({ where: { id: c.id } });
    }

    res.json({
      success: true,
      message: 'Database cleaned and verified with clean UTF-8 records.',
      purgedCorruptedCount: corruptedCust.length,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Admin Fresh Database Wipe Endpoint (POST + SUPER_ADMIN + explicit confirmation + disabled in prod)
app.post('/api/admin/reset-database', requireRole('SUPER_ADMIN'), async (req: AuthenticatedRequest, res) => {
  try {
    if (!isAdminDbToolsAllowed()) {
      return res.status(403).json({
        error: 'Admin database reset endpoint is disabled in production.',
      });
    }

    if (req.body?.confirm !== 'RESET_DATABASE') {
      return res.status(400).json({
        error: 'Explicit confirmation { "confirm": "RESET_DATABASE" } is required.',
      });
    }

    const currentAdmin = await prisma.profile.findUnique({
      where: { id: req.user!.id },
    });

    if (!currentAdmin || !currentAdmin.passwordHash) {
      return res.status(400).json({ error: 'Active super admin account not found.' });
    }

    await prisma.offerItemSpecification.deleteMany();
    await prisma.offerItem.deleteMany();
    await prisma.offer.deleteMany();
    await prisma.project.deleteMany();
    await prisma.serviceTicket.deleteMany();
    await prisma.installedItem.deleteMany();
    await prisma.clientDocument.deleteMany();
    await prisma.calendarEvent.deleteMany();
    await prisma.paymentRecord.deleteMany();
    await prisma.dispatchNote.deleteMany();
    await prisma.salesInvoice.deleteMany();
    await prisma.purchaseInvoice.deleteMany();
    await prisma.inventoryMovement.deleteMany();
    await prisma.customer.deleteMany();
    await prisma.specificationOption.deleteMany();
    await prisma.specificationKey.deleteMany();
    await prisma.productModel.deleteMany();
    await prisma.product.deleteMany();
    await prisma.productCategory.deleteMany();

    // Preserve the executing SUPER_ADMIN account and its existing password hash
    await prisma.profile.deleteMany({
      where: {
        id: { not: currentAdmin.id },
      },
    });

    res.json({
      success: true,
      message: `Database reset cleanly to fresh state. 0 records, 1 system user active (${currentAdmin.email}).`,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// EMAIL TRANSACTIONAL API ENDPOINTS
// ==========================================

// 1. Send Offer PDF to Customer (authenticated, rate-limited, HTML-escaped)
app.post('/api/email/send-offer', emailLimiter, async (req, res) => {
  try {
    const { to, customerName, offerNumber, totalAmount, pdfBase64, customMessage } = req.body ?? {};

    if (!isValidEmail(to)) {
      return res.status(400).json({ error: 'A valid recipient email address (to) is required.' });
    }

    if (!resend) {
      return res.status(503).json({
        error: 'Email service is not configured. Please add RESEND_API_KEY to environment variables in Render.',
      });
    }

    const safeOfferNumber = escapeHtml(offerNumber || '');
    const safeCustomerName = escapeHtml(customerName || 'Клиент');
    const safeCustomMessage = customMessage ? escapeHtml(customMessage) : '';
    const safeAmount = Number.isFinite(Number(totalAmount)) ? Number(totalAmount).toFixed(2) : '0.00';
    const cleanFilename = String(offerNumber || 'Offer').replace(/[^a-zA-Z0-9_-]/g, '_');

    let attachments: { filename: string; content: Buffer }[] = [];
    if (pdfBase64) {
      const cleanBase64 = String(pdfBase64).replace(/^data:.*?;base64,/, '').trim();
      const pdfBuffer = Buffer.from(cleanBase64, 'base64');
      if (!pdfBuffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
        return res.status(400).json({ error: 'Invalid PDF attachment.' });
      }
      attachments = [
        {
          filename: `${cleanFilename}.pdf`,
          content: pdfBuffer,
        },
      ];
    }

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #1e293b; line-height: 1.6;">
        <div style="background-color: #0f172a; padding: 24px; text-align: center; border-radius: 12px 12px 0 0;">
          <h1 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 800; letter-spacing: 0.5px;">
            ИМФЕКС ЕКСПОРТ-ИМПОРТ ДООЕЛ
          </h1>
          <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 12px;">Комерцијална Понуда • ${safeOfferNumber}</p>
        </div>

        <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; background-color: #ffffff;">
          <p style="font-size: 14px; font-weight: 700; color: #0f172a;">Почитувани ${safeCustomerName},</p>
          <p style="font-size: 13px; color: #334155;">
            Во прилог на оваа порака Ви ја испраќаме официјалната комерцијална понуда <strong>${safeOfferNumber}</strong> со вкупен износ од <strong>€${safeAmount}</strong>.
          </p>

          ${
            safeCustomMessage
              ? `<div style="background-color: #f8fafc; border-left: 4px solid #2563eb; padding: 12px; margin: 16px 0; font-size: 12px; color: #475569; font-style: italic; white-space: pre-wrap;">
                  "${safeCustomMessage}"
                </div>`
              : ''
          }

          <p style="font-size: 13px; color: #334155;">
            Ве молиме прегледајте го прикачениот PDF документ за детална спецификација на производите и условите за испорака.
          </p>

          <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #64748b; text-align: center;">
            <p style="margin: 0; font-weight: 700;">ИМФЕКС ЕКСПОРТ-ИМПОРТ ДООЕЛ Скопје</p>
            <p style="margin: 2px 0 0 0;">Ул. Качанички Пат бб, Скопје | Тел: +389 2 3123 456 | Email: info@imfex.com</p>
          </div>
        </div>
      </div>
    `;

    const result = await resend.emails.send({
      from: EMAIL_FROM,
      to: [String(to).trim()],
      subject: `Комерцијална Понуда ${String(offerNumber || '').replace(/[\r\n]/g, '')} - ИМФЕКС ЕКСПОРТ-ИМПОРТ`,
      html: htmlContent,
      attachments,
    });

    if (result.error) {
      return res.status(400).json({ error: result.error.message });
    }

    res.json({ success: true, id: result.data?.id });
  } catch (error: any) {
    console.error('Send offer email error:', error);
    res.status(500).json({ error: 'Failed to send email.' });
  }
});

// ==========================================
// EXISTING CRUD ENDPOINTS (PROTECTED BY requireAuth)
// ==========================================

// Profiles / User Accounts API
app.get('/api/profiles', async (req, res) => {
  try {
    const profiles = await prisma.profile.findMany({
      select: SAFE_PROFILE_SELECT,
    });
    res.json(profiles);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/profiles', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    const { email, fullName, role, password } = req.body ?? {};
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    const rawPassword =
      typeof password === 'string' && password.trim().length >= 8
        ? password.trim()
        : generateSecureTempPassword(12);
    const passwordHash = await bcrypt.hash(rawPassword, 10);
    const profile = await prisma.profile.upsert({
      where: { email: email.trim().toLowerCase() },
      update: { fullName, role, status: 'ACTIVE' },
      create: {
        email: email.trim().toLowerCase(),
        fullName,
        role: role || 'USER',
        passwordHash,
        mustChangePassword: true,
        status: 'ACTIVE',
      },
      select: SAFE_PROFILE_SELECT,
    });
    res.json(profile);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/profiles/:id', async (req: AuthenticatedRequest, res) => {
  try {
    const id = String(req.params.id);
    const isSuperAdmin = req.user?.role === 'SUPER_ADMIN';
    const isSelf = req.user?.id === id;

    if (!isSuperAdmin && !isSelf) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const { fullName, role, status, password, mustChangePassword } = req.body ?? {};
    const updateData: any = {};
    if (fullName !== undefined) updateData.fullName = fullName;
    if (isSuperAdmin) {
      if (role !== undefined) updateData.role = role;
      if (status !== undefined) updateData.status = status;
    } else if (role !== undefined || status !== undefined) {
      return res.status(403).json({ error: 'Only SUPER_ADMIN can modify role or status' });
    }
    if (typeof password === 'string' && password.length > 0) {
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
      }
      updateData.passwordHash = await bcrypt.hash(password, 10);
      // Admin resetting another user's password defaults to mustChangePassword = true
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
    res.json(profile);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/profiles/:id', requireRole('SUPER_ADMIN'), async (req: AuthenticatedRequest, res) => {
  try {
    const id = String(req.params.id);
    if (req.user?.id === id) {
      return res.status(400).json({ error: 'Cannot delete your own active account' });
    }
    await prisma.profile.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Categories API
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await prisma.productCategory.findMany({
      include: {
        children: true,
      },
    });
    res.json(categories);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/categories', async (req, res) => {
  try {
    const { id, name, parentId } = req.body;
    const isUuid = id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    let category;

    if (isUuid) {
      category = await prisma.productCategory.upsert({
        where: { id },
        update: { name, parentId: parentId || null },
        create: { id, name, parentId: parentId || null },
      });
    } else {
      category = await prisma.productCategory.create({
        data: { name, parentId: parentId || null },
      });
    }
    res.json(category);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/categories/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.productCategory.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

const formatProductForResponse = (p: any) => {
  if (!p) return p;
  return {
    ...p,
    stockType: p.stockType || 'STOCK',
    stockQuantity: Number(p.stockQuantity ?? 0),
    reservedQuantity: Number(p.reservedQuantity ?? 0),
    purchasePrice: Number(p.purchasePrice ?? 0),
    models: (p.models || []).map((m: any) => ({
      ...m,
      basePrice: Number(m.basePrice ?? 0),
    })),
    specificationKeys: (p.specificationKeys || []).map((sk: any) => ({
      ...sk,
      options: (sk.options || []).map((opt: any) => ({
        ...opt,
        priceModifier: Number(opt.priceModifier ?? 0),
      })),
    })),
  };
};

// Products API
app.get('/api/products', async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      include: {
        category: true,
        models: true,
        specificationKeys: {
          include: {
            options: true,
          },
        },
      },
    });
    res.json(products.map(formatProductForResponse));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const {
      id,
      name,
      code,
      description,
      isActive,
      stockType,
      stockQuantity,
      reservedQuantity,
      purchasePrice,
      models,
      specificationKeys,
      categoryId,
    } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Product code is required' });
    }

    const stockFields = {
      ...(stockType !== undefined ? { stockType } : {}),
      ...(stockQuantity !== undefined ? { stockQuantity: Math.max(0, Math.round(Number(stockQuantity) || 0)) } : {}),
      ...(reservedQuantity !== undefined ? { reservedQuantity: Math.max(0, Math.round(Number(reservedQuantity) || 0)) } : {}),
      ...(purchasePrice !== undefined ? { purchasePrice: Number(purchasePrice) || 0 } : {}),
    };

    const isUuid = id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    let product;

    if (isUuid) {
      product = await prisma.product.upsert({
        where: { id },
        update: {
          name,
          code,
          description,
          isActive: isActive !== undefined ? isActive : true,
          categoryId: categoryId || null,
          ...stockFields,
        },
        create: {
          id,
          name,
          code,
          description,
          isActive: isActive !== undefined ? isActive : true,
          categoryId: categoryId || null,
          ...stockFields,
        },
        include: {
          category: true,
          models: true,
          specificationKeys: { include: { options: true } },
        },
      });
    } else {
      product = await prisma.product.upsert({
        where: { code },
        update: {
          name,
          description,
          isActive: isActive !== undefined ? isActive : true,
          categoryId: categoryId || null,
          ...stockFields,
        },
        create: {
          name,
          code,
          description,
          isActive: isActive !== undefined ? isActive : true,
          categoryId: categoryId || null,
          ...stockFields,
        },
        include: {
          category: true,
          models: true,
          specificationKeys: { include: { options: true } },
        },
      });
    }

    if (Array.isArray(models)) {
      const keptModelIds: string[] = [];
      for (const m of models) {
        if (m.name) {
          const isModelUuid = m.id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(m.id);
          let existingModel = isModelUuid
            ? await prisma.productModel.findUnique({ where: { id: m.id } }).catch(() => null)
            : null;
          if (!existingModel) {
            existingModel = await prisma.productModel.findFirst({
              where: { productId: product.id, name: m.name },
            });
          }
          if (existingModel) {
            const updatedMod = await prisma.productModel.update({
              where: { id: existingModel.id },
              data: {
                name: m.name,
                basePrice: m.basePrice !== undefined ? Number(m.basePrice) : existingModel.basePrice,
              },
            });
            keptModelIds.push(updatedMod.id);
          } else {
            const createdMod = await prisma.productModel.create({
              data: {
                productId: product.id,
                name: m.name,
                basePrice: m.basePrice || 0,
              },
            });
            keptModelIds.push(createdMod.id);
          }
        }
      }
      await prisma.productModel.deleteMany({
        where: {
          productId: product.id,
          id: { notIn: keptModelIds },
        },
      });
    }

    if (Array.isArray(specificationKeys)) {
      const keptKeyIds: string[] = [];
      for (const sk of specificationKeys) {
        if (sk.name) {
          const isKeyUuid = sk.id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sk.id);
          let specKey = isKeyUuid
            ? await prisma.specificationKey.findUnique({ where: { id: sk.id } }).catch(() => null)
            : null;
          if (!specKey) {
            specKey = await prisma.specificationKey.findFirst({
              where: { productId: product.id, name: sk.name },
            });
          }
          if (!specKey) {
            specKey = await prisma.specificationKey.create({
              data: {
                productId: product.id,
                name: sk.name,
                inputType: sk.inputType || 'SELECT',
                defaultValue: sk.defaultValue || null,
              },
            });
          } else {
            specKey = await prisma.specificationKey.update({
              where: { id: specKey.id },
              data: {
                name: sk.name,
                inputType: sk.inputType || specKey.inputType,
                defaultValue: sk.defaultValue !== undefined ? sk.defaultValue || null : specKey.defaultValue,
              },
            });
          }
          keptKeyIds.push(specKey.id);

          if (Array.isArray(sk.options)) {
            const keptOptIds: string[] = [];
            for (const opt of sk.options) {
              if (opt.label) {
                const isOptUuid = opt.id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(opt.id);
                let existingOpt = isOptUuid
                  ? await prisma.specificationOption.findUnique({ where: { id: opt.id } }).catch(() => null)
                  : null;
                if (!existingOpt) {
                  existingOpt = await prisma.specificationOption.findFirst({
                    where: { specificationKeyId: specKey.id, label: opt.label },
                  });
                }
                if (!existingOpt) {
                  const createdOpt = await prisma.specificationOption.create({
                    data: {
                      specificationKeyId: specKey.id,
                      label: opt.label,
                      priceModifier: opt.priceModifier || 0,
                      isDefault: Boolean(opt.isDefault),
                    },
                  });
                  keptOptIds.push(createdOpt.id);
                } else {
                  const updatedOpt = await prisma.specificationOption.update({
                    where: { id: existingOpt.id },
                    data: {
                      label: opt.label,
                      priceModifier: opt.priceModifier !== undefined ? Number(opt.priceModifier) : existingOpt.priceModifier,
                      isDefault: opt.isDefault !== undefined ? Boolean(opt.isDefault) : existingOpt.isDefault,
                    },
                  });
                  keptOptIds.push(updatedOpt.id);
                }
              }
            }
            await prisma.specificationOption.deleteMany({
              where: {
                specificationKeyId: specKey.id,
                id: { notIn: keptOptIds },
              },
            });
          }
        }
      }
      await prisma.specificationKey.deleteMany({
        where: {
          productId: product.id,
          id: { notIn: keptKeyIds },
        },
      });
    }

    const updatedProduct = await prisma.product.findUnique({
      where: { id: product.id },
      include: { category: true, models: true, specificationKeys: { include: { options: true } } },
    });

    res.json(formatProductForResponse(updatedProduct));
  } catch (error: any) {
    if (error.code === 'P2002') {
      return res.status(400).json({ error: 'Product with this code already exists.' });
    }
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.product.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Customers API
app.get('/api/customers', async (req, res) => {
  try {
    const customers = await prisma.customer.findMany({
      include: {
        offers: true,
        projects: true,
        installedItems: true,
        serviceTickets: true,
      },
    });
    res.json(customers);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/customers', async (req, res) => {
  try {
    const { id, name, companyName, customerType, email, phone, address, city, notes } = req.body;
    const isUuid = id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    let customer;
    if (isUuid) {
      customer = await prisma.customer.upsert({
        where: { id },
        update: { name: name || 'Клиент', companyName, customerType: customerType || 'COMPANY', email, phone, address, city, notes },
        create: { id, name: name || 'Клиент', companyName, customerType: customerType || 'COMPANY', email, phone, address, city, notes },
      });
    } else {
      customer = await prisma.customer.create({
        data: { name: name || 'Клиент', companyName, customerType: customerType || 'COMPANY', email, phone, address, city, notes },
      });
    }
    res.json(customer);
  } catch (error: any) {
    console.error('POST /api/customers error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.customer.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Helper to format offer item specifications and serialize Decimal numbers
const formatOfferForResponse = (offer: any) => {
  if (!offer) return offer;
  return {
    ...offer,
    taxRate: Number(offer.taxRate || 0),
    discountRate: Number(offer.discountRate || 0),
    discountAmount: Number(offer.discountAmount || 0),
    subtotal: Number(offer.subtotal || 0),
    taxAmount: Number(offer.taxAmount || 0),
    totalAmount: Number(offer.totalAmount || 0),
    items: (offer.items || []).map((item: any) => ({
      ...item,
      quantity: Number(item.quantity || 1),
      unitPrice: Number(item.unitPrice || 0),
      totalPrice: Number(item.totalPrice || 0),
      specifications: (item.offerItemSpecifications || item.specifications || []).map((s: any) => ({
        specificationKeyId: s.specificationKeyId || `custom-${s.id}`,
        specificationOptionId: s.specificationOptionId || undefined,
        customValue: s.customValue || undefined,
        customKeyName: s.customKeyName || undefined,
        customPriceModifier: s.customPriceModifier !== undefined && s.customPriceModifier !== null ? Number(s.customPriceModifier) : undefined,
      })),
    })),
  };
};

// Offers API
app.get('/api/offers', async (req, res) => {
  try {
    const offers = await prisma.offer.findMany({
      include: {
        customer: true,
        createdByUser: { select: SAFE_PROFILE_SELECT },
        items: {
          include: {
            offerItemSpecifications: true,
          },
        },
      },
    });
    res.json(offers.map(formatOfferForResponse));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/offers/:id', async (req, res) => {
  try {
    const offer = await prisma.offer.findUnique({
      where: { id: req.params.id },
      include: {
        customer: true,
        createdByUser: { select: SAFE_PROFILE_SELECT },
        items: {
          include: {
            offerItemSpecifications: true,
          },
        },
      },
    });
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    res.json(formatOfferForResponse(offer));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/offers', async (req, res) => {
  try {
    let {
      id,
      offerNumber,
      customerId,
      createdByUserId,
      status,
      taxRate,
      discountRate,
      discountAmount,
      subtotal,
      taxAmount,
      totalAmount,
      validUntil,
      items,
    } = req.body;

    const isUuid = (val?: string | null) =>
      Boolean(val && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val));

    let validCustomerId = isUuid(customerId) ? customerId : null;
    if (validCustomerId) {
      const custExists = await prisma.customer.findUnique({ where: { id: validCustomerId } }).catch(() => null);
      if (!custExists) validCustomerId = null;
    }
    if (!validCustomerId) {
      const firstCust = await prisma.customer.findFirst();
      if (firstCust) {
        validCustomerId = firstCust.id;
      } else {
        const newCust = await prisma.customer.create({
          data: { name: 'Главен Клиент', email: 'nabavki@logistika.mk' },
        });
        validCustomerId = newCust.id;
      }
    }

    let validUserId: string | null = null;
    if (isUuid(createdByUserId)) {
      const userExists = await prisma.profile.findUnique({ where: { id: createdByUserId } }).catch(() => null);
      if (userExists) validUserId = userExists.id;
    }

    // Check if offer exists by ID or offerNumber
    let existingOffer = null;
    if (isUuid(id)) {
      existingOffer = await prisma.offer.findUnique({ where: { id } }).catch(() => null);
    }
    if (!existingOffer && offerNumber) {
      existingOffer = await prisma.offer.findUnique({ where: { offerNumber } }).catch(() => null);
    }

    let offer;
    if (existingOffer) {
      offer = await prisma.offer.update({
        where: { id: existingOffer.id },
        data: {
          customerId: validCustomerId,
          createdByUserId: validUserId,
          status: status || existingOffer.status || 'DRAFT',
          taxRate: taxRate !== undefined ? Number(taxRate) : existingOffer.taxRate,
          discountRate: discountRate !== undefined ? Number(discountRate) : existingOffer.discountRate,
          discountAmount: discountAmount !== undefined ? Number(discountAmount) : existingOffer.discountAmount,
          subtotal: subtotal !== undefined ? Number(subtotal) : existingOffer.subtotal,
          taxAmount: taxAmount !== undefined ? Number(taxAmount) : existingOffer.taxAmount,
          totalAmount: totalAmount !== undefined ? Number(totalAmount) : existingOffer.totalAmount,
          ...(validUntil !== undefined ? { validUntil: validUntil ? new Date(validUntil) : null } : {}),
        },
      });
    } else {
      let uniqueOfferNumber = offerNumber;
      if (!uniqueOfferNumber) {
        const count = await prisma.offer.count();
        uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${String(count + 1).padStart(4, '0')}`;
      }

      let conflict = await prisma.offer.findUnique({ where: { offerNumber: uniqueOfferNumber } }).catch(() => null);
      let attempts = 0;
      while (conflict && attempts < 10) {
        attempts++;
        const rand = Math.floor(1000 + Math.random() * 9000);
        uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${rand}`;
        conflict = await prisma.offer.findUnique({ where: { offerNumber: uniqueOfferNumber } }).catch(() => null);
      }

      offer = await prisma.offer.create({
        data: {
          ...(isUuid(id) ? { id } : {}),
          offerNumber: uniqueOfferNumber,
          customerId: validCustomerId,
          createdByUserId: validUserId,
          status: status || 'DRAFT',
          taxRate: taxRate !== undefined && taxRate !== null ? Number(taxRate) : 18.0,
          discountRate: discountRate !== undefined && discountRate !== null ? Number(discountRate) : 0.0,
          discountAmount: discountAmount !== undefined && discountAmount !== null ? Number(discountAmount) : 0.0,
          subtotal: subtotal !== undefined && subtotal !== null ? Number(subtotal) : 0.0,
          taxAmount: taxAmount !== undefined && taxAmount !== null ? Number(taxAmount) : 0.0,
          totalAmount: totalAmount !== undefined && totalAmount !== null ? Number(totalAmount) : 0.0,
          validUntil: validUntil ? new Date(validUntil) : null,
        },
      });
    }

    if (Array.isArray(items)) {
      await prisma.offerItem.deleteMany({ where: { offerId: offer.id } });
      for (const item of items) {
        const isProdUuid = item.productId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item.productId);
        const isModelUuid = item.productModelId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item.productModelId);
        const createdItem = await prisma.offerItem.create({
          data: {
            offerId: offer.id,
            productId: isProdUuid ? item.productId : null,
            productModelId: isModelUuid ? item.productModelId : null,
            customTitle: item.customTitle || '',
            serviceTypes: Array.isArray(item.serviceTypes) ? item.serviceTypes : [],
            widthMm: item.widthMm ? Number(item.widthMm) : null,
            heightMm: item.heightMm ? Number(item.heightMm) : null,
            quantity: item.quantity ? Number(item.quantity) : 1,
            unitPrice: item.unitPrice ? Number(item.unitPrice) : 0,
            totalPrice: item.totalPrice ? Number(item.totalPrice) : 0,
          },
        });

        const rawSpecs = Array.isArray(item.specifications)
          ? item.specifications
          : Array.isArray(item.offerItemSpecifications)
          ? item.offerItemSpecifications
          : [];

        for (const spec of rawSpecs) {
          const isSpecKeyUuid = spec.specificationKeyId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(spec.specificationKeyId);
          const isSpecOptUuid = spec.specificationOptionId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(spec.specificationOptionId);
          if (isSpecKeyUuid) {
            const specKeyExists = await prisma.specificationKey.findUnique({ where: { id: spec.specificationKeyId } }).catch(() => null);
            if (specKeyExists) {
              let validOptId: string | null = null;
              if (isSpecOptUuid) {
                const optExists = await prisma.specificationOption.findUnique({ where: { id: spec.specificationOptionId } }).catch(() => null);
                if (optExists) validOptId = spec.specificationOptionId;
              }
              await prisma.offerItemSpecification.create({
                data: {
                  offerItemId: createdItem.id,
                  specificationKeyId: spec.specificationKeyId,
                  specificationOptionId: validOptId,
                  customValue: spec.customValue || null,
                  customKeyName: spec.customKeyName || null,
                  customPriceModifier: spec.customPriceModifier ? Number(spec.customPriceModifier) : 0,
                },
              }).catch((e) => console.warn('Skipping offerItemSpecification insert warning:', e?.message || e));
            }
          } else if (spec.customKeyName || spec.customValue) {
            await prisma.offerItemSpecification.create({
              data: {
                offerItemId: createdItem.id,
                specificationKeyId: null,
                specificationOptionId: null,
                customValue: spec.customValue || null,
                customKeyName: spec.customKeyName || 'Прилагодена спецификација',
                customPriceModifier: spec.customPriceModifier ? Number(spec.customPriceModifier) : 0,
              },
            }).catch((e) => console.warn('Skipping custom offerItemSpecification insert warning:', e?.message || e));
          }
        }
      }
    }

    const fullOffer = await prisma.offer.findUnique({
      where: { id: offer.id },
      include: {
        customer: true,
        createdByUser: { select: SAFE_PROFILE_SELECT },
        items: {
          include: {
            offerItemSpecifications: true,
          },
        },
      },
    });

    res.json(formatOfferForResponse(fullOffer));
  } catch (error: any) {
    console.error('POST /api/offers error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/offers/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.offer.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

const WORKFLOW_KEYS = [
  'acceptedAt',
  'advancePaid',
  'advancePaidAt',
  'supplierOrdered',
  'supplierOrderedAt',
  'warehouseReceived',
  'warehouseReceivedAt',
  'dispatchIssued',
  'dispatchIssuedAt',
  'selectedMotorId',
  'selectedRailId',
  'reservedAccessoryIds',
  'missingAccessoryNames',
] as const;

const extractWorkflowData = (body: any) => {
  const wf: Record<string, any> = {};
  let hasAny = false;
  for (const key of WORKFLOW_KEYS) {
    if (body[key] !== undefined) {
      wf[key] = body[key];
      hasAny = true;
    }
  }
  return hasAny ? wf : undefined;
};

const formatProjectForResponse = (project: any) => {
  if (!project) return project;
  const wf = project.workflowData && typeof project.workflowData === 'object' ? project.workflowData : {};
  return {
    ...wf,
    ...project,
    offer: project.offer
      ? {
          ...project.offer,
          taxRate: Number(project.offer.taxRate || 0),
          discountRate: Number(project.offer.discountRate || 0),
          discountAmount: Number(project.offer.discountAmount || 0),
          subtotal: Number(project.offer.subtotal || 0),
          taxAmount: Number(project.offer.taxAmount || 0),
          totalAmount: Number(project.offer.totalAmount || 0),
        }
      : project.offer,
  };
};

// Projects API
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await prisma.project.findMany({
      include: {
        customer: true,
        offer: true,
        responsibleUser: { select: SAFE_PROFILE_SELECT },
        installedItems: true,
        documents: true,
      },
    });
    res.json(projects.map(formatProjectForResponse));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/projects/:id', async (req, res) => {
  try {
    const project = await prisma.project.findUnique({
      where: { id: req.params.id },
      include: {
        customer: true,
        offer: true,
        responsibleUser: { select: SAFE_PROFILE_SELECT },
        installedItems: true,
        documents: true,
      },
    });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(formatProjectForResponse(project));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects', async (req, res) => {
  try {
    const {
      projectNumber,
      offerId,
      customerId,
      status,
      procurementStatus,
      procurementNotes,
      responsibleUserId,
      startDate,
      targetDeliveryDate,
      actualDeliveryDate,
      installationTeam,
      installationDate,
      installationAddress,
      installationContact,
      installationMinutes,
      signatureUrl,
    } = req.body;

    let validOfferId = offerId;
    if (validOfferId) {
      const offerExists = await prisma.offer.findUnique({ where: { id: validOfferId } }).catch(() => null);
      if (!offerExists) validOfferId = null;
    }

    let validCustomerId = customerId;
    if (validCustomerId) {
      const custExists = await prisma.customer.findUnique({ where: { id: validCustomerId } }).catch(() => null);
      if (!custExists) {
        const firstCust = await prisma.customer.findFirst();
        if (firstCust) validCustomerId = firstCust.id;
      }
    }

    if (!validCustomerId || !validOfferId) {
      if (!validCustomerId) {
        const newCust = await prisma.customer.create({ data: { name: 'Главен Клиент' } });
        validCustomerId = newCust.id;
      }
      if (!validOfferId) {
        const newOffer = await prisma.offer.create({
          data: {
            offerNumber: `OFF-TMP-${Date.now()}`,
            customerId: validCustomerId,
            status: 'ACCEPTED',
          },
        });
        validOfferId = newOffer.id;
      }
    }

    let validRespUser = responsibleUserId;
    if (validRespUser) {
      const userExists = await prisma.profile.findUnique({ where: { id: validRespUser } }).catch(() => null);
      if (!userExists) validRespUser = null;
    }

    const existingProj = await prisma.project.findUnique({
      where: { projectNumber },
      select: { workflowData: true },
    }).catch(() => null);
    const incomingWorkflow = extractWorkflowData(req.body);
    const mergedWorkflowData = incomingWorkflow
      ? {
          ...(existingProj?.workflowData && typeof existingProj.workflowData === 'object'
            ? (existingProj.workflowData as Record<string, any>)
            : {}),
          ...incomingWorkflow,
        }
      : undefined;

    const project = await prisma.project.upsert({
      where: { projectNumber },
      update: {
        status: status || 'PLANNED',
        procurementStatus,
        procurementNotes,
        responsibleUserId: validRespUser,
        startDate: startDate ? new Date(startDate) : undefined,
        targetDeliveryDate: targetDeliveryDate ? new Date(targetDeliveryDate) : undefined,
        actualDeliveryDate: actualDeliveryDate ? new Date(actualDeliveryDate) : undefined,
        installationTeam,
        installationDate: installationDate ? new Date(installationDate) : undefined,
        installationAddress,
        installationContact,
        installationMinutes,
        signatureUrl,
        ...(mergedWorkflowData !== undefined ? { workflowData: mergedWorkflowData } : {}),
      },
      create: {
        projectNumber,
        offerId: validOfferId,
        customerId: validCustomerId,
        status: status || 'PLANNED',
        procurementStatus,
        procurementNotes,
        responsibleUserId: validRespUser,
        startDate: startDate ? new Date(startDate) : undefined,
        targetDeliveryDate: targetDeliveryDate ? new Date(targetDeliveryDate) : undefined,
        actualDeliveryDate: actualDeliveryDate ? new Date(actualDeliveryDate) : undefined,
        installationTeam,
        installationDate: installationDate ? new Date(installationDate) : undefined,
        installationAddress,
        installationContact,
        installationMinutes,
        signatureUrl,
        ...(mergedWorkflowData !== undefined ? { workflowData: mergedWorkflowData } : {}),
      },
      include: { customer: true, offer: true, responsibleUser: { select: SAFE_PROFILE_SELECT } },
    });
    res.json(formatProjectForResponse(project));
  } catch (error: any) {
    console.error('POST /api/projects error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/projects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.project.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Helper to format service ticket Decimal fields
const formatTicketForResponse = (ticket: any) => {
  if (!ticket) return ticket;
  return {
    ...ticket,
    laborHours: Number(ticket.laborHours || 0),
  };
};

// Service Tickets API
app.get('/api/service-tickets', async (req, res) => {
  try {
    const tickets = await prisma.serviceTicket.findMany({
      include: {
        customer: true,
        installedItem: true,
        assignedTechnician: { select: SAFE_PROFILE_SELECT },
      },
    });
    res.json(tickets.map(formatTicketForResponse));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/service-tickets/:id', async (req, res) => {
  try {
    const ticket = await prisma.serviceTicket.findUnique({
      where: { id: req.params.id },
      include: {
        customer: true,
        installedItem: true,
        assignedTechnician: { select: SAFE_PROFILE_SELECT },
      },
    });
    if (!ticket) return res.status(404).json({ error: 'Service ticket not found' });
    res.json(formatTicketForResponse(ticket));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/service-tickets', async (req, res) => {
  try {
    const {
      ticketNumber,
      customerId,
      installedItemId,
      defectDescription,
      priority,
      status,
      laborHours,
      solution,
      assignedTechnicianId,
      scheduledDate,
      partsConsumed,
      closedAt,
    } = req.body;

    let validCustomerId = customerId;
    if (validCustomerId) {
      const custExists = await prisma.customer.findUnique({ where: { id: validCustomerId } }).catch(() => null);
      if (!custExists) {
        const firstCust = await prisma.customer.findFirst();
        if (firstCust) validCustomerId = firstCust.id;
      }
    }
    if (!validCustomerId) {
      const newCust = await prisma.customer.create({ data: { name: 'Главен Клиент' } });
      validCustomerId = newCust.id;
    }

    let validItem = installedItemId;
    if (validItem) {
      const itemExists = await prisma.installedItem.findUnique({ where: { id: validItem } }).catch(() => null);
      if (!itemExists) validItem = null;
    }

    let validTech = assignedTechnicianId;
    if (validTech) {
      const techExists = await prisma.profile.findUnique({ where: { id: validTech } }).catch(() => null);
      if (!techExists) validTech = null;
    }

    const ticket = await prisma.serviceTicket.upsert({
      where: { ticketNumber },
      update: {
        priority: priority || 'MEDIUM',
        status: status || 'OPEN',
        defectDescription: defectDescription || 'Пријавен дефект',
        laborHours: laborHours ? Number(laborHours) : 0,
        solution,
        assignedTechnicianId: validTech,
        scheduledDate: scheduledDate ? new Date(scheduledDate) : undefined,
        partsConsumed,
        closedAt: closedAt ? new Date(closedAt) : undefined,
      },
      create: {
        ticketNumber,
        customerId: validCustomerId,
        installedItemId: validItem,
        defectDescription: defectDescription || 'Пријавен дефект',
        priority: priority || 'MEDIUM',
        status: status || 'OPEN',
        laborHours: laborHours ? Number(laborHours) : 0,
        solution,
        assignedTechnicianId: validTech,
        scheduledDate: scheduledDate ? new Date(scheduledDate) : undefined,
        partsConsumed,
        closedAt: closedAt ? new Date(closedAt) : undefined,
      },
      include: { customer: true, installedItem: true, assignedTechnician: { select: SAFE_PROFILE_SELECT } },
    });
    res.json(ticket);
  } catch (error: any) {
    console.error('POST /api/service-tickets error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/service-tickets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.serviceTicket.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Installed Items API
app.get('/api/installed-items', async (req, res) => {
  try {
    const items = await prisma.installedItem.findMany({
      include: { customer: true, project: true, product: true },
    });
    res.json(items);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/installed-items', async (req, res) => {
  try {
    const { id, customerId, projectId, productId, title, serialNumber, installationDate } = req.body;
    const isUuid = id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    let validCustomerId = customerId;
    if (validCustomerId) {
      const custExists = await prisma.customer.findUnique({ where: { id: validCustomerId } }).catch(() => null);
      if (!custExists) {
        const firstCust = await prisma.customer.findFirst();
        if (firstCust) validCustomerId = firstCust.id;
      }
    }
    if (!validCustomerId) {
      const newCust = await prisma.customer.create({ data: { name: 'Главен Клиент' } });
      validCustomerId = newCust.id;
    }

    let item;
    if (isUuid) {
      item = await prisma.installedItem.upsert({
        where: { id },
        update: { title, serialNumber, installationDate: installationDate ? new Date(installationDate) : undefined },
        create: { id, customerId: validCustomerId, projectId, productId, title, serialNumber, installationDate: installationDate ? new Date(installationDate) : undefined },
      });
    } else {
      item = await prisma.installedItem.create({
        data: { customerId: validCustomerId, projectId, productId, title, serialNumber, installationDate: installationDate ? new Date(installationDate) : undefined },
      });
    }
    res.json(item);
  } catch (error: any) {
    console.error('POST /api/installed-items error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/installed-items/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.installedItem.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Client Documents API
app.get('/api/client-documents', async (req, res) => {
  try {
    const docs = await prisma.clientDocument.findMany({
      include: { customer: true },
    });
    res.json(docs);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/client-documents', async (req, res) => {
  try {
    const { id, customerId, offerId, projectId, serviceId, title, fileType, fileUrl, fileName, sizeBytes } = req.body;

    const uploadValidation = validateDocumentUpload(fileUrl, fileName || title);
    if (!uploadValidation.ok) {
      return res.status(400).json({ error: uploadValidation.error });
    }

    const isUuid = (val?: string | null) =>
      Boolean(val && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val));

    let validProjectId: string | null = null;
    let resolvedProject: { id: string; customerId: string; offerId: string } | null = null;
    if (projectId) {
      if (isUuid(projectId)) {
        resolvedProject = await prisma.project
          .findUnique({ where: { id: projectId }, select: { id: true, customerId: true, offerId: true } })
          .catch(() => null);
      }
      if (!resolvedProject) {
        resolvedProject = await prisma.project
          .findUnique({ where: { projectNumber: String(projectId) }, select: { id: true, customerId: true, offerId: true } })
          .catch(() => null);
      }
      if (resolvedProject) {
        validProjectId = resolvedProject.id;
      }
    }

    let validCustomerId = isUuid(customerId) ? customerId : null;
    if (validCustomerId) {
      const custExists = await prisma.customer.findUnique({ where: { id: validCustomerId } }).catch(() => null);
      if (!custExists) validCustomerId = null;
    }
    if (!validCustomerId && resolvedProject?.customerId) {
      validCustomerId = resolvedProject.customerId;
    }
    if (!validCustomerId) {
      const firstCust = await prisma.customer.findFirst();
      if (firstCust) {
        validCustomerId = firstCust.id;
      } else {
        const newCust = await prisma.customer.create({ data: { name: 'Главен Клиент' } });
        validCustomerId = newCust.id;
      }
    }

    let validOfferId: string | null = null;
    if (isUuid(offerId)) {
      const offExists = await prisma.offer.findUnique({ where: { id: offerId }, select: { id: true } }).catch(() => null);
      if (offExists) validOfferId = offExists.id;
    } else if (offerId) {
      const offByNum = await prisma.offer
        .findUnique({ where: { offerNumber: String(offerId) }, select: { id: true } })
        .catch(() => null);
      if (offByNum) validOfferId = offByNum.id;
    }
    if (!validOfferId && resolvedProject?.offerId) {
      validOfferId = resolvedProject.offerId;
    }

    let validServiceId: string | null = null;
    if (isUuid(serviceId)) {
      const srvExists = await prisma.serviceTicket
        .findUnique({ where: { id: serviceId }, select: { id: true } })
        .catch(() => null);
      if (srvExists) validServiceId = srvExists.id;
    }

    const parsedSize = sizeBytes !== undefined && sizeBytes !== null && !Number.isNaN(Number(sizeBytes)) ? Number(sizeBytes) : null;

    let doc;
    if (isUuid(id)) {
      doc = await prisma.clientDocument.upsert({
        where: { id },
        update: {
          title: title || 'Документ',
          fileType: fileType || 'application/pdf',
          fileUrl: fileUrl || '',
          fileName: fileName || null,
          sizeBytes: parsedSize,
          offerId: validOfferId,
          projectId: validProjectId,
          serviceId: validServiceId,
        },
        create: {
          id,
          customerId: validCustomerId,
          offerId: validOfferId,
          projectId: validProjectId,
          serviceId: validServiceId,
          title: title || 'Документ',
          fileType: fileType || 'application/pdf',
          fileUrl: fileUrl || '',
          fileName: fileName || null,
          sizeBytes: parsedSize,
        },
      });
    } else {
      const existingDoc = await prisma.clientDocument
        .findFirst({
          where: {
            title: title || 'Документ',
            ...(validProjectId ? { projectId: validProjectId } : { customerId: validCustomerId }),
          },
        })
        .catch(() => null);

      if (existingDoc) {
        doc = await prisma.clientDocument.update({
          where: { id: existingDoc.id },
          data: {
            title: title || 'Документ',
            fileType: fileType || existingDoc.fileType || 'application/pdf',
            fileUrl: fileUrl || existingDoc.fileUrl || '',
            fileName: fileName ?? existingDoc.fileName ?? null,
            sizeBytes: parsedSize ?? existingDoc.sizeBytes ?? null,
            offerId: validOfferId ?? existingDoc.offerId,
            projectId: validProjectId ?? existingDoc.projectId,
            serviceId: validServiceId ?? existingDoc.serviceId,
          },
        });
      } else {
        doc = await prisma.clientDocument.create({
          data: {
            customerId: validCustomerId,
            offerId: validOfferId,
            projectId: validProjectId,
            serviceId: validServiceId,
            title: title || 'Документ',
            fileType: fileType || 'application/pdf',
            fileUrl: fileUrl || '',
            fileName: fileName || null,
            sizeBytes: parsedSize,
          },
        });
      }
    }
    res.json(doc);
  } catch (error: any) {
    console.error('POST /api/client-documents error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/client-documents/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.clientDocument.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Calendar Events API
app.get('/api/calendar-events', async (req, res) => {
  try {
    const events = await prisma.calendarEvent.findMany({
      include: {
        customer: true,
      },
    });
    res.json(events);
  } catch (error: any) {
    console.error('GET /api/calendar-events database error:', error?.message || error);
    res.json([]);
  }
});

app.post('/api/calendar-events', async (req, res) => {
  try {
    const { id, title, description, startDate, endDate, allDay, eventType, customerId, projectId, location, color } = req.body;

    if (!title || !startDate) {
      return res.status(400).json({ error: 'Title and startDate are required' });
    }

    let validCustomerId = customerId;
    if (validCustomerId) {
      const custExists = await prisma.customer.findUnique({ where: { id: validCustomerId } }).catch(() => null);
      if (!custExists) validCustomerId = null;
    }

    const isUuid = id && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);

    let event;
    if (isUuid) {
      event = await prisma.calendarEvent.upsert({
        where: { id },
        update: {
          title,
          description,
          startDate,
          endDate,
          allDay: Boolean(allDay),
          eventType: eventType || 'MEETING',
          customerId: validCustomerId,
          projectId: projectId || null,
          location,
          color,
        },
        create: {
          id,
          title,
          description,
          startDate,
          endDate,
          allDay: Boolean(allDay),
          eventType: eventType || 'MEETING',
          customerId: validCustomerId,
          projectId: projectId || null,
          location,
          color,
        },
        include: { customer: true },
      });
    } else {
      event = await prisma.calendarEvent.create({
        data: {
          title,
          description,
          startDate,
          endDate,
          allDay: Boolean(allDay),
          eventType: eventType || 'MEETING',
          customerId: validCustomerId,
          projectId: projectId || null,
          location,
          color,
        },
        include: { customer: true },
      });
    }

    res.json(event);
  } catch (error: any) {
    console.error('POST /api/calendar-events error:', error?.message || error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/calendar-events/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.calendarEvent.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// FINANCE, INVENTORY & COMPANY SETTINGS APIs
// ==========================================

const formatPurchaseInvoice = (inv: any) => ({
  ...inv,
  taxRate: Number(inv.taxRate ?? 18),
  subtotal: Number(inv.subtotal ?? 0),
  taxAmount: Number(inv.taxAmount ?? 0),
  totalAmount: Number(inv.totalAmount ?? 0),
  paidAmount: Number(inv.paidAmount ?? 0),
  items: Array.isArray(inv.items) ? inv.items : [],
});

const formatSalesInvoice = (inv: any) => ({
  ...inv,
  taxRate: Number(inv.taxRate ?? 18),
  discountRate: Number(inv.discountRate ?? 0),
  discountAmount: Number(inv.discountAmount ?? 0),
  subtotal: Number(inv.subtotal ?? 0),
  taxAmount: Number(inv.taxAmount ?? 0),
  grossTotalAmount: Number(inv.grossTotalAmount ?? 0),
  advanceDeductedAmount: Number(inv.advanceDeductedAmount ?? 0),
  totalAmount: Number(inv.totalAmount ?? 0),
  paidAmount: Number(inv.paidAmount ?? 0),
  items: Array.isArray(inv.items) ? inv.items : [],
});

const formatPaymentRecord = (p: any) => ({
  ...p,
  amount: Number(p.amount ?? 0),
});

// Purchase Invoices
app.get('/api/purchase-invoices', async (_req, res) => {
  try {
    const rows = await prisma.purchaseInvoice.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(rows.map(formatPurchaseInvoice));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/purchase-invoices', async (req, res) => {
  try {
    const b = req.body;
    if (!b?.id || !b?.internalNumber) {
      return res.status(400).json({ error: 'id and internalNumber are required' });
    }
    const data = {
      internalNumber: String(b.internalNumber),
      supplierInvoiceNumber: b.supplierInvoiceNumber ?? null,
      supplierId: String(b.supplierId || ''),
      supplierName: String(b.supplierName || 'Добавувач'),
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      issueDate: String(b.issueDate || new Date().toISOString().split('T')[0]),
      dueDate: b.dueDate ?? null,
      status: String(b.status || 'INVOICED'),
      receiptStatus: String(b.receiptStatus || 'PENDING'),
      taxRate: Number(b.taxRate ?? 18),
      subtotal: Number(b.subtotal ?? 0),
      taxAmount: Number(b.taxAmount ?? 0),
      totalAmount: Number(b.totalAmount ?? 0),
      paidAmount: Number(b.paidAmount ?? 0),
      notes: b.notes ?? null,
      items: Array.isArray(b.items) ? b.items : [],
    };
    const saved = await prisma.purchaseInvoice.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json(formatPurchaseInvoice(saved));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/purchase-invoices/:id', async (req, res) => {
  try {
    await prisma.purchaseInvoice.delete({ where: { id: req.params.id } }).catch(() => null);
    res.json({ success: true, id: req.params.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Sales Invoices
app.get('/api/sales-invoices', async (_req, res) => {
  try {
    const rows = await prisma.salesInvoice.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(rows.map(formatSalesInvoice));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sales-invoices', async (req, res) => {
  try {
    const b = req.body;
    if (!b?.id || !b?.invoiceNumber) {
      return res.status(400).json({ error: 'id and invoiceNumber are required' });
    }
    const data = {
      invoiceNumber: String(b.invoiceNumber),
      externalAccountingNumber: b.externalAccountingNumber ?? null,
      invoiceType: String(b.invoiceType || 'FINAL'),
      status: String(b.status || 'ISSUED'),
      customerId: String(b.customerId || ''),
      offerId: b.offerId ?? null,
      projectId: b.projectId ?? null,
      issueDate: String(b.issueDate || new Date().toISOString().split('T')[0]),
      dueDate: b.dueDate ?? null,
      taxRate: Number(b.taxRate ?? 18),
      discountRate: Number(b.discountRate ?? 0),
      discountAmount: Number(b.discountAmount ?? 0),
      subtotal: Number(b.subtotal ?? 0),
      taxAmount: Number(b.taxAmount ?? 0),
      grossTotalAmount: Number(b.grossTotalAmount ?? 0),
      linkedAdvanceInvoiceId: b.linkedAdvanceInvoiceId ?? null,
      linkedAdvanceInvoiceNumber: b.linkedAdvanceInvoiceNumber ?? null,
      advanceDeductedAmount: Number(b.advanceDeductedAmount ?? 0),
      totalAmount: Number(b.totalAmount ?? 0),
      paidAmount: Number(b.paidAmount ?? 0),
      notes: b.notes ?? null,
      items: Array.isArray(b.items) ? b.items : [],
    };
    const saved = await prisma.salesInvoice.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json(formatSalesInvoice(saved));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/sales-invoices/:id', async (req, res) => {
  try {
    await prisma.salesInvoice.delete({ where: { id: req.params.id } }).catch(() => null);
    res.json({ success: true, id: req.params.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Dispatch Notes
app.get('/api/dispatch-notes', async (_req, res) => {
  try {
    const rows = await prisma.dispatchNote.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(rows.map((r) => ({ ...r, items: Array.isArray(r.items) ? r.items : [] })));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/dispatch-notes', async (req, res) => {
  try {
    const b = req.body;
    if (!b?.id || !b?.dispatchNumber) {
      return res.status(400).json({ error: 'id and dispatchNumber are required' });
    }
    const data = {
      dispatchNumber: String(b.dispatchNumber),
      status: String(b.status || 'DRAFT'),
      customerId: String(b.customerId || ''),
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      salesInvoiceId: b.salesInvoiceId ?? null,
      issueDate: String(b.issueDate || new Date().toISOString().split('T')[0]),
      deliveryAddress: b.deliveryAddress ?? null,
      receivedBy: b.receivedBy ?? null,
      issuedBy: b.issuedBy ?? null,
      notes: b.notes ?? null,
      items: Array.isArray(b.items) ? b.items : [],
      stockDeducted: Boolean(b.stockDeducted),
    };
    const saved = await prisma.dispatchNote.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json({ ...saved, items: Array.isArray(saved.items) ? saved.items : [] });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/dispatch-notes/:id', async (req, res) => {
  try {
    await prisma.dispatchNote.delete({ where: { id: req.params.id } }).catch(() => null);
    res.json({ success: true, id: req.params.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Payments
app.get('/api/payments', async (_req, res) => {
  try {
    const rows = await prisma.paymentRecord.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(rows.map(formatPaymentRecord));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/payments', async (req, res) => {
  try {
    const b = req.body;
    if (!b?.id || !b?.paymentNumber) {
      return res.status(400).json({ error: 'id and paymentNumber are required' });
    }
    const data = {
      paymentNumber: String(b.paymentNumber),
      direction: String(b.direction || 'IN'),
      amount: Number(b.amount ?? 0),
      date: String(b.date || new Date().toISOString().split('T')[0]),
      method: String(b.method || 'BANK'),
      bankAccount: b.bankAccount ?? null,
      customerId: b.customerId ?? null,
      partnerName: b.partnerName ?? null,
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      salesInvoiceId: b.salesInvoiceId ?? null,
      purchaseInvoiceId: b.purchaseInvoiceId ?? null,
      isAdvance: Boolean(b.isAdvance),
      notes: b.notes ?? null,
    };
    const saved = await prisma.paymentRecord.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json(formatPaymentRecord(saved));
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/payments/:id', async (req, res) => {
  try {
    await prisma.paymentRecord.delete({ where: { id: req.params.id } }).catch(() => null);
    res.json({ success: true, id: req.params.id });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Inventory Movements
app.get('/api/inventory-movements', async (_req, res) => {
  try {
    const rows = await prisma.inventoryMovement.findMany({ orderBy: { createdAt: 'desc' }, take: 500 });
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/inventory-movements', async (req, res) => {
  try {
    const b = req.body;
    if (!b?.id || !b?.kind || !b?.detail) {
      return res.status(400).json({ error: 'id, kind, and detail are required' });
    }
    const data = {
      kind: String(b.kind),
      detail: String(b.detail),
      productId: b.productId ?? null,
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      quantity: b.quantity !== undefined && b.quantity !== null ? Number(b.quantity) : null,
      at: String(b.at || new Date().toISOString()),
    };
    const saved = await prisma.inventoryMovement.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json(saved);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Company Settings
app.get('/api/company-settings', async (_req, res) => {
  try {
    let settings = await prisma.companySettings.findUnique({ where: { id: 'default' } });
    if (!settings) {
      settings = await prisma.companySettings.create({ data: { id: 'default' } });
    }
    res.json(settings);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/company-settings', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    const { companyName, address, taxId, phone, email, bankAccount, defaultAdvancePercent } = req.body ?? {};
    const updateData = {
      ...(companyName !== undefined ? { companyName: String(companyName) } : {}),
      ...(address !== undefined ? { address: String(address) } : {}),
      ...(taxId !== undefined ? { taxId: String(taxId) } : {}),
      ...(phone !== undefined ? { phone: String(phone) } : {}),
      ...(email !== undefined ? { email: String(email) } : {}),
      ...(bankAccount !== undefined ? { bankAccount: bankAccount ? String(bankAccount) : null } : {}),
      ...(defaultAdvancePercent !== undefined
        ? { defaultAdvancePercent: Math.min(100, Math.max(0, Math.round(Number(defaultAdvancePercent) || 50))) }
        : {}),
    };
    const settings = await prisma.companySettings.upsert({
      where: { id: 'default' },
      update: updateData,
      create: { id: 'default', ...updateData },
    });
    res.json(settings);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 IMFEX CRM Express Backend running on port ${PORT}`);
});
