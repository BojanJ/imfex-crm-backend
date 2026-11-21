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
import {
  isUuid,
  USER_ROLES,
  SPEC_INPUT_TYPES,
  CUSTOMER_TYPES,
  OFFER_STATUSES,
  PROJECT_STATUSES,
  SERVICE_PRIORITIES,
  SERVICE_STATUSES,
  parseEnum,
  parseOptionalDate,
  parseIsoDateString,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from './validation';
import {
  isObjectStorageConfigured,
  persistDocumentPayload,
  resolveDocumentBinary,
  deleteStoredDocumentObject,
  formatDocumentForList,
  isStorageRef,
} from './storage';

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

// Health Check Endpoint for Render
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'IMFEX Enterprise CRM Backend',
    emailConfigured: Boolean(resendApiKey),
    objectStorageConfigured: isObjectStorageConfigured(),
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
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/admin/clean-database');
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
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/admin/reset-database');
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

    const company = await prisma.companySettings.findUnique({ where: { id: 'default' } }).catch(() => null);
    const companyName = company?.companyName || 'ИМФЕКС ЕКСПОРТ-ИМПОРТ ДООЕЛ';
    const companyAddress = company?.address || 'Ул. Качанички Пат бб, Скопје';
    const companyPhone = company?.phone || '+389 2 3123 456';
    const companyEmail = company?.email || 'info@imfex.com';

    const safeCompanyName = escapeHtml(companyName);
    const safeCompanyAddress = escapeHtml(companyAddress);
    const safeCompanyPhone = escapeHtml(companyPhone);
    const safeCompanyEmail = escapeHtml(companyEmail);
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
            ${safeCompanyName}
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
            <p style="margin: 0; font-weight: 700;">${safeCompanyName}</p>
            <p style="margin: 2px 0 0 0;">${safeCompanyAddress} | Тел: ${safeCompanyPhone} | Email: ${safeCompanyEmail}</p>
          </div>
        </div>
      </div>
    `;

    const result = await resend.emails.send({
      from: EMAIL_FROM,
      to: [String(to).trim()],
      subject: `Комерцијална Понуда ${String(offerNumber || '').replace(/[\r\n]/g, '')} - ${companyName.replace(/[\r\n]/g, '')}`,
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

app.post('/api/profiles', requireRole('SUPER_ADMIN'), async (req, res) => {
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
    res.json(profile);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/profiles');
  }
});

app.put('/api/profiles/:id', async (req: AuthenticatedRequest, res) => {
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
    res.json(profile);
  } catch (error) {
    return handleRouteError(res, error, 'PUT /api/profiles/:id');
  }
});

app.delete('/api/profiles/:id', requireRole('SUPER_ADMIN'), async (req: AuthenticatedRequest, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid profile ID format.' });
    }
    if (req.user?.id === id) {
      return res.status(400).json({ error: 'Cannot delete your own active account' });
    }
    await prisma.profile.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/profiles/:id');
  }
});

// Categories API
app.get('/api/categories', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const categories = await prisma.productCategory.findMany({
      include: { children: true },
      orderBy: { createdAt: 'asc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.productCategory.count()));
    }
    res.json(categories);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/categories');
  }
});

app.post('/api/categories', async (req, res) => {
  try {
    const { id, name, parentId } = req.body ?? {};
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanName) {
      return res.status(400).json({ error: 'Category name is required.' });
    }
    if (parentId !== undefined && parentId !== null && parentId !== '' && !isUuid(parentId)) {
      return res.status(400).json({ error: 'Invalid parentId UUID format.' });
    }
    const cleanParentId = isUuid(parentId) ? parentId : null;

    let category;
    if (isUuid(id)) {
      category = await prisma.productCategory.upsert({
        where: { id },
        update: { name: cleanName, parentId: cleanParentId },
        create: { id, name: cleanName, parentId: cleanParentId },
      });
    } else {
      category = await prisma.productCategory.create({
        data: { name: cleanName, parentId: cleanParentId },
      });
    }
    res.json(category);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/categories');
  }
});

app.delete('/api/categories/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid category ID format.' });
    }
    await prisma.productCategory.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/categories/:id');
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
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

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
      orderBy: { createdAt: 'asc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.product.count()));
    }
    res.json(products.map(formatProductForResponse));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/products');
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
    } = req.body ?? {};

    const cleanCode = typeof code === 'string' ? code.trim() : '';
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanCode) {
      return res.status(400).json({ error: 'Product code is required.' });
    }
    if (!cleanName) {
      return res.status(400).json({ error: 'Product name is required.' });
    }
    if (categoryId !== undefined && categoryId !== null && categoryId !== '' && !isUuid(categoryId)) {
      return res.status(400).json({ error: 'Invalid categoryId UUID format.' });
    }
    const cleanCategoryId = isUuid(categoryId) ? categoryId : null;

    const stockQtyCheck =
      stockQuantity !== undefined
        ? parseFiniteNumber(stockQuantity, 'stockQuantity', { min: 0, integer: true })
        : null;
    if (stockQtyCheck && !stockQtyCheck.ok) return res.status(400).json({ error: stockQtyCheck.error });

    const reservedQtyCheck =
      reservedQuantity !== undefined
        ? parseFiniteNumber(reservedQuantity, 'reservedQuantity', { min: 0, integer: true })
        : null;
    if (reservedQtyCheck && !reservedQtyCheck.ok) return res.status(400).json({ error: reservedQtyCheck.error });

    const purchasePriceCheck =
      purchasePrice !== undefined
        ? parseFiniteNumber(purchasePrice, 'purchasePrice', { min: 0 })
        : null;
    if (purchasePriceCheck && !purchasePriceCheck.ok) return res.status(400).json({ error: purchasePriceCheck.error });

    if (Array.isArray(specificationKeys)) {
      for (const sk of specificationKeys) {
        if (sk?.inputType !== undefined) {
          const check = parseEnum(sk.inputType, SPEC_INPUT_TYPES, 'specificationKey.inputType');
          if (!check.ok) return res.status(400).json({ error: check.error });
        }
      }
    }

    const stockFields = {
      ...(stockType !== undefined ? { stockType: String(stockType) } : {}),
      ...(stockQtyCheck?.ok ? { stockQuantity: stockQtyCheck.value } : {}),
      ...(reservedQtyCheck?.ok ? { reservedQuantity: reservedQtyCheck.value } : {}),
      ...(purchasePriceCheck?.ok ? { purchasePrice: purchasePriceCheck.value } : {}),
    };

    const updatedProduct = await prisma.$transaction(
      async (tx) => {
        const product = isUuid(id)
          ? await tx.product.upsert({
              where: { id },
              update: {
                name: cleanName,
                code: cleanCode,
                description: description ?? null,
                isActive: isActive !== undefined ? Boolean(isActive) : true,
                categoryId: cleanCategoryId,
                ...stockFields,
              },
              create: {
                id,
                name: cleanName,
                code: cleanCode,
                description: description ?? null,
                isActive: isActive !== undefined ? Boolean(isActive) : true,
                categoryId: cleanCategoryId,
                ...stockFields,
              },
            })
          : await tx.product.upsert({
              where: { code: cleanCode },
              update: {
                name: cleanName,
                description: description ?? null,
                isActive: isActive !== undefined ? Boolean(isActive) : true,
                categoryId: cleanCategoryId,
                ...stockFields,
              },
              create: {
                name: cleanName,
                code: cleanCode,
                description: description ?? null,
                isActive: isActive !== undefined ? Boolean(isActive) : true,
                categoryId: cleanCategoryId,
                ...stockFields,
              },
            });

        if (Array.isArray(models)) {
          const existingModels = await tx.productModel.findMany({ where: { productId: product.id } });
          const byId = new Map(existingModels.map((m) => [m.id, m]));
          const byName = new Map(existingModels.map((m) => [m.name, m]));
          const keptModelIds: string[] = [];

          for (const m of models) {
            if (!m?.name) continue;
            const existingModel = (isUuid(m.id) ? byId.get(m.id) : undefined) || byName.get(m.name);
            const price = m.basePrice !== undefined ? Number(m.basePrice) : undefined;
            if (existingModel) {
              const updatedMod = await tx.productModel.update({
                where: { id: existingModel.id },
                data: {
                  name: m.name,
                  basePrice: price !== undefined && Number.isFinite(price) ? price : existingModel.basePrice,
                },
              });
              keptModelIds.push(updatedMod.id);
            } else {
              const createdMod = await tx.productModel.create({
                data: {
                  productId: product.id,
                  name: m.name,
                  basePrice: price !== undefined && Number.isFinite(price) ? price : 0,
                },
              });
              keptModelIds.push(createdMod.id);
            }
          }

          await tx.productModel.deleteMany({
            where: {
              productId: product.id,
              id: { notIn: keptModelIds },
            },
          });
        }

        if (Array.isArray(specificationKeys)) {
          const existingKeys = await tx.specificationKey.findMany({
            where: { productId: product.id },
            include: { options: true },
          });
          const keyById = new Map(existingKeys.map((k) => [k.id, k]));
          const keyByName = new Map(existingKeys.map((k) => [k.name, k]));
          const keptKeyIds: string[] = [];

          for (const sk of specificationKeys) {
            if (!sk?.name) continue;
            const existingKey = (isUuid(sk.id) ? keyById.get(sk.id) : undefined) || keyByName.get(sk.name);

            const specKey = existingKey
              ? await tx.specificationKey.update({
                  where: { id: existingKey.id },
                  data: {
                    name: sk.name,
                    inputType: sk.inputType || existingKey.inputType,
                    defaultValue: sk.defaultValue !== undefined ? sk.defaultValue || null : existingKey.defaultValue,
                  },
                })
              : await tx.specificationKey.create({
                  data: {
                    productId: product.id,
                    name: sk.name,
                    inputType: sk.inputType || 'SELECT',
                    defaultValue: sk.defaultValue || null,
                  },
                });
            keptKeyIds.push(specKey.id);

            if (Array.isArray(sk.options)) {
              const existingOpts = existingKey?.options || [];
              const optById = new Map(existingOpts.map((o) => [o.id, o]));
              const optByLabel = new Map(existingOpts.map((o) => [o.label, o]));
              const keptOptIds: string[] = [];

              for (const opt of sk.options) {
                if (!opt?.label) continue;
                const existingOpt = (isUuid(opt.id) ? optById.get(opt.id) : undefined) || optByLabel.get(opt.label);
                const modifier = opt.priceModifier !== undefined ? Number(opt.priceModifier) : undefined;

                if (existingOpt) {
                  const updatedOpt = await tx.specificationOption.update({
                    where: { id: existingOpt.id },
                    data: {
                      label: opt.label,
                      priceModifier: modifier !== undefined && Number.isFinite(modifier) ? modifier : existingOpt.priceModifier,
                      isDefault: opt.isDefault !== undefined ? Boolean(opt.isDefault) : existingOpt.isDefault,
                    },
                  });
                  keptOptIds.push(updatedOpt.id);
                } else {
                  const createdOpt = await tx.specificationOption.create({
                    data: {
                      specificationKeyId: specKey.id,
                      label: opt.label,
                      priceModifier: modifier !== undefined && Number.isFinite(modifier) ? modifier : 0,
                      isDefault: Boolean(opt.isDefault),
                    },
                  });
                  keptOptIds.push(createdOpt.id);
                }
              }

              await tx.specificationOption.deleteMany({
                where: {
                  specificationKeyId: specKey.id,
                  id: { notIn: keptOptIds },
                },
              });
            }
          }

          await tx.specificationKey.deleteMany({
            where: {
              productId: product.id,
              id: { notIn: keptKeyIds },
            },
          });
        }

        return tx.product.findUnique({
          where: { id: product.id },
          include: { category: true, models: true, specificationKeys: { include: { options: true } } },
        });
      },
      { timeout: 20000 }
    );

    res.json(formatProductForResponse(updatedProduct));
  } catch (error: any) {
    if (error?.code === 'P2002') {
      return res.status(409).json({ error: 'Product with this code already exists.' });
    }
    return handleRouteError(res, error, 'POST /api/products');
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid product ID format.' });
    }
    await prisma.product.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/products/:id');
  }
});

// Customers API
app.get('/api/customers', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const customers = await prisma.customer.findMany({
      include: {
        offers: true,
        projects: true,
        installedItems: true,
        serviceTickets: true,
      },
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.customer.count()));
    }
    res.json(
      customers.map((c) => ({
        ...c,
        offers: (c.offers || []).map(formatOfferForResponse),
        serviceTickets: (c.serviceTickets || []).map(formatTicketForResponse),
      }))
    );
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/customers');
  }
});

app.post('/api/customers', async (req, res) => {
  try {
    const { id, name, companyName, taxId, customerType, email, phone, address, city, notes } = req.body ?? {};
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanName) {
      return res.status(400).json({ error: 'Customer name is required.' });
    }
    const typeCheck = parseEnum(customerType, CUSTOMER_TYPES, 'customerType', 'COMPANY');
    if (!typeCheck.ok) return res.status(400).json({ error: typeCheck.error });

    if (email !== undefined && email !== null && String(email).trim() !== '' && !isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid customer email address.' });
    }

    const data = {
      name: cleanName,
      companyName: companyName ?? null,
      taxId: taxId !== undefined ? (taxId ? String(taxId).trim() : null) : null,
      customerType: typeCheck.value,
      email: email ? String(email).trim() : null,
      phone: phone ?? null,
      address: address ?? null,
      city: city ?? null,
      notes: notes ?? null,
    };

    const customer = isUuid(id)
      ? await prisma.customer.upsert({
          where: { id },
          update: data,
          create: { id, ...data },
        })
      : await prisma.customer.create({ data });

    res.json(customer);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/customers');
  }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid customer ID format.' });
    }
    await prisma.customer.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error: any) {
    if (error?.code === 'P2003') {
      return res.status(409).json({
        error: 'Cannot delete customer because linked offers, projects, service tickets, or documents exist.',
      });
    }
    return handleRouteError(res, error, 'DELETE /api/customers/:id');
  }
});

// Helper to format offer item specifications and serialize Decimal numbers
const formatOfferForResponse = (offer: any) => {
  if (!offer) return offer;
  return {
    ...offer,
    taxRate: Number(offer.taxRate ?? 0),
    discountRate: Number(offer.discountRate ?? 0),
    discountAmount: Number(offer.discountAmount ?? 0),
    subtotal: Number(offer.subtotal ?? 0),
    taxAmount: Number(offer.taxAmount ?? 0),
    totalAmount: Number(offer.totalAmount ?? 0),
    items: (offer.items || []).map((item: any) => ({
      ...item,
      quantity: Number(item.quantity ?? 1),
      unitPrice: Number(item.unitPrice ?? 0),
      totalPrice: Number(item.totalPrice ?? 0),
      specifications: (item.offerItemSpecifications || item.specifications || []).map((s: any) => ({
        specificationKeyId: s.specificationKeyId || `custom-${s.id}`,
        specificationOptionId: s.specificationOptionId || undefined,
        customValue: s.customValue || undefined,
        customKeyName: s.customKeyName || undefined,
        customPriceModifier:
          s.customPriceModifier !== undefined && s.customPriceModifier !== null
            ? Number(s.customPriceModifier)
            : undefined,
      })),
    })),
  };
};

// Offers API
app.get('/api/offers', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

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
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.offer.count()));
    }
    res.json(offers.map(formatOfferForResponse));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/offers');
  }
});

app.get('/api/offers/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid offer ID format.' });
    }
    const offer = await prisma.offer.findUnique({
      where: { id },
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
    if (!offer) return res.status(404).json({ error: 'Offer not found.' });
    res.json(formatOfferForResponse(offer));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/offers/:id');
  }
});

app.post('/api/offers', async (req, res) => {
  try {
    const {
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
    } = req.body ?? {};

    // API-01: Strictly require a real, existing customerId — never silently fall back to first customer
    if (!isUuid(customerId)) {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }
    const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
    if (!custExists) {
      return res.status(404).json({ error: 'Referenced customer not found.' });
    }

    const statusCheck = parseEnum(status, OFFER_STATUSES, 'status', 'DRAFT');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });

    const validUntilCheck = parseOptionalDate(validUntil, 'validUntil');
    if (!validUntilCheck.ok) return res.status(400).json({ error: validUntilCheck.error });

    // API-03: Preserve 0% taxRate explicitly (only default to 18 when omitted/null/empty)
    const taxRateCheck = parseFiniteNumber(taxRate, 'taxRate', { min: 0, max: 100, defaultVal: 18 });
    if (!taxRateCheck.ok) return res.status(400).json({ error: taxRateCheck.error });

    const discountRateCheck = parseFiniteNumber(discountRate, 'discountRate', { min: 0, max: 100, defaultVal: 0 });
    if (!discountRateCheck.ok) return res.status(400).json({ error: discountRateCheck.error });

    const discountAmountCheck = parseFiniteNumber(discountAmount, 'discountAmount', { min: 0, defaultVal: 0 });
    if (!discountAmountCheck.ok) return res.status(400).json({ error: discountAmountCheck.error });

    const subtotalCheck = parseFiniteNumber(subtotal, 'subtotal', { min: 0, defaultVal: 0 });
    if (!subtotalCheck.ok) return res.status(400).json({ error: subtotalCheck.error });

    const taxAmountCheck = parseFiniteNumber(taxAmount, 'taxAmount', { min: 0, defaultVal: 0 });
    if (!taxAmountCheck.ok) return res.status(400).json({ error: taxAmountCheck.error });

    const totalAmountCheck = parseFiniteNumber(totalAmount, 'totalAmount', { min: 0, defaultVal: 0 });
    if (!totalAmountCheck.ok) return res.status(400).json({ error: totalAmountCheck.error });

    let validUserId: string | null = null;
    if (isUuid(createdByUserId)) {
      const userExists = await prisma.profile.findUnique({ where: { id: createdByUserId }, select: { id: true } });
      if (userExists) validUserId = userExists.id;
    }

    // API-02: Wrap offer upsert + item replacement + specification snapshots in a single transaction
    const fullOffer = await prisma.$transaction(
      async (tx) => {
        let existingOffer = null;
        if (isUuid(id)) {
          existingOffer = await tx.offer.findUnique({ where: { id } });
        }
        if (!existingOffer && offerNumber) {
          existingOffer = await tx.offer.findUnique({ where: { offerNumber: String(offerNumber) } });
        }

        let offer;
        if (existingOffer) {
          offer = await tx.offer.update({
            where: { id: existingOffer.id },
            data: {
              customerId,
              createdByUserId: validUserId ?? existingOffer.createdByUserId,
              status: status !== undefined ? statusCheck.value : existingOffer.status,
              taxRate: taxRate !== undefined && taxRate !== null && taxRate !== '' ? taxRateCheck.value : existingOffer.taxRate,
              discountRate:
                discountRate !== undefined && discountRate !== null && discountRate !== ''
                  ? discountRateCheck.value
                  : existingOffer.discountRate,
              discountAmount:
                discountAmount !== undefined && discountAmount !== null && discountAmount !== ''
                  ? discountAmountCheck.value
                  : existingOffer.discountAmount,
              subtotal: subtotal !== undefined && subtotal !== null && subtotal !== '' ? subtotalCheck.value : existingOffer.subtotal,
              taxAmount:
                taxAmount !== undefined && taxAmount !== null && taxAmount !== '' ? taxAmountCheck.value : existingOffer.taxAmount,
              totalAmount:
                totalAmount !== undefined && totalAmount !== null && totalAmount !== ''
                  ? totalAmountCheck.value
                  : existingOffer.totalAmount,
              ...(validUntil !== undefined ? { validUntil: validUntilCheck.value ?? null } : {}),
            },
          });
        } else {
          let uniqueOfferNumber = offerNumber ? String(offerNumber).trim() : '';
          if (!uniqueOfferNumber) {
            const count = await tx.offer.count();
            uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${String(count + 1).padStart(4, '0')}`;
          }

          let conflict = await tx.offer.findUnique({ where: { offerNumber: uniqueOfferNumber }, select: { id: true } });
          let attempts = 0;
          while (conflict && attempts < 10) {
            attempts++;
            const rand = Math.floor(1000 + Math.random() * 9000);
            uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${rand}`;
            conflict = await tx.offer.findUnique({ where: { offerNumber: uniqueOfferNumber }, select: { id: true } });
          }

          offer = await tx.offer.create({
            data: {
              ...(isUuid(id) ? { id } : {}),
              offerNumber: uniqueOfferNumber,
              customerId,
              createdByUserId: validUserId,
              status: statusCheck.value,
              taxRate: taxRateCheck.value,
              discountRate: discountRateCheck.value,
              discountAmount: discountAmountCheck.value,
              subtotal: subtotalCheck.value,
              taxAmount: taxAmountCheck.value,
              totalAmount: totalAmountCheck.value,
              validUntil: validUntilCheck.value ?? null,
            },
          });
        }

        if (Array.isArray(items)) {
          // Pre-fetch referenced spec keys & options once for fast lookup and API-05 snapshots
          const keyIds = new Set<string>();
          const optIds = new Set<string>();
          for (const item of items) {
            const rawSpecs = Array.isArray(item?.specifications)
              ? item.specifications
              : Array.isArray(item?.offerItemSpecifications)
              ? item.offerItemSpecifications
              : [];
            for (const spec of rawSpecs) {
              if (isUuid(spec?.specificationKeyId)) keyIds.add(spec.specificationKeyId);
              if (isUuid(spec?.specificationOptionId)) optIds.add(spec.specificationOptionId);
            }
          }

          const [specKeys, specOpts] = await Promise.all([
            keyIds.size > 0
              ? tx.specificationKey.findMany({ where: { id: { in: Array.from(keyIds) } }, select: { id: true, name: true } })
              : Promise.resolve([]),
            optIds.size > 0
              ? tx.specificationOption.findMany({ where: { id: { in: Array.from(optIds) } }, select: { id: true, label: true } })
              : Promise.resolve([]),
          ]);
          const specKeyMap = new Map(specKeys.map((k) => [k.id, k]));
          const specOptMap = new Map(specOpts.map((o) => [o.id, o]));

          await tx.offerItem.deleteMany({ where: { offerId: offer.id } });

          for (const item of items) {
            const createdItem = await tx.offerItem.create({
              data: {
                offerId: offer.id,
                productId: isUuid(item?.productId) ? item.productId : null,
                productModelId: isUuid(item?.productModelId) ? item.productModelId : null,
                customTitle: item?.customTitle || '',
                serviceTypes: Array.isArray(item?.serviceTypes) ? item.serviceTypes : [],
                widthMm: item?.widthMm !== undefined && item?.widthMm !== null && item?.widthMm !== '' ? Math.round(Number(item.widthMm)) : null,
                heightMm: item?.heightMm !== undefined && item?.heightMm !== null && item?.heightMm !== '' ? Math.round(Number(item.heightMm)) : null,
                quantity: Math.max(1, Math.round(Number(item?.quantity ?? 1) || 1)),
                unitPrice: Number.isFinite(Number(item?.unitPrice)) ? Number(item.unitPrice) : 0,
                totalPrice: Number.isFinite(Number(item?.totalPrice)) ? Number(item.totalPrice) : 0,
              },
            });

            const rawSpecs = Array.isArray(item?.specifications)
              ? item.specifications
              : Array.isArray(item?.offerItemSpecifications)
              ? item.offerItemSpecifications
              : [];

            const specRows: any[] = [];
            for (const spec of rawSpecs) {
              if (isUuid(spec?.specificationKeyId) && specKeyMap.has(spec.specificationKeyId)) {
                const keyInfo = specKeyMap.get(spec.specificationKeyId)!;
                const optInfo = isUuid(spec?.specificationOptionId) ? specOptMap.get(spec.specificationOptionId) : undefined;
                specRows.push({
                  offerItemId: createdItem.id,
                  specificationKeyId: keyInfo.id,
                  specificationOptionId: optInfo ? optInfo.id : null,
                  // Snapshot readable key & option text so API-05 SetNull preserves historical quotes
                  customValue: spec.customValue || optInfo?.label || null,
                  customKeyName: spec.customKeyName || keyInfo.name,
                  customPriceModifier: Number.isFinite(Number(spec.customPriceModifier)) ? Number(spec.customPriceModifier) : 0,
                });
              } else if (spec?.customKeyName || spec?.customValue) {
                specRows.push({
                  offerItemId: createdItem.id,
                  specificationKeyId: null,
                  specificationOptionId: null,
                  customValue: spec.customValue || null,
                  customKeyName: spec.customKeyName || 'Прилагодена спецификација',
                  customPriceModifier: Number.isFinite(Number(spec.customPriceModifier)) ? Number(spec.customPriceModifier) : 0,
                });
              }
            }
            if (specRows.length > 0) {
              await tx.offerItemSpecification.createMany({ data: specRows });
            }
          }
        }

        return tx.offer.findUnique({
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
      },
      { timeout: 20000 }
    );

    res.json(formatOfferForResponse(fullOffer));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/offers');
  }
});

app.delete('/api/offers/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid offer ID format.' });
    }
    await prisma.offer.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error: any) {
    if (error?.code === 'P2003') {
      return res.status(409).json({ error: 'Cannot delete offer because a linked project exists.' });
    }
    return handleRouteError(res, error, 'DELETE /api/offers/:id');
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

const formatProjectForResponse = (project: any, includeDocumentData = false) => {
  if (!project) return project;
  const wf = project.workflowData && typeof project.workflowData === 'object' ? project.workflowData : {};
  return {
    ...wf,
    ...project,
    offer: project.offer ? formatOfferForResponse(project.offer) : project.offer,
    documents: Array.isArray(project.documents)
      ? project.documents.map((d: any) => formatDocumentForList(d, includeDocumentData))
      : project.documents,
  };
};

// Projects API
app.get('/api/projects', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });
    const includeData = req.query.includeData === 'true';

    const projects = await prisma.project.findMany({
      include: {
        customer: true,
        offer: true,
        responsibleUser: { select: SAFE_PROFILE_SELECT },
        installedItems: true,
        documents: true,
      },
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.project.count()));
    }
    res.json(projects.map((p) => formatProjectForResponse(p, includeData)));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/projects');
  }
});

app.get('/api/projects/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid project ID format.' });
    }
    const includeData = req.query.includeData === 'true';
    const project = await prisma.project.findUnique({
      where: { id },
      include: {
        customer: true,
        offer: true,
        responsibleUser: { select: SAFE_PROFILE_SELECT },
        installedItems: true,
        documents: true,
      },
    });
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    res.json(formatProjectForResponse(project, includeData));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/projects/:id');
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
    } = req.body ?? {};

    const cleanProjectNumber = typeof projectNumber === 'string' ? projectNumber.trim() : '';
    if (!cleanProjectNumber) {
      return res.status(400).json({ error: 'projectNumber is required.' });
    }

    const statusCheck = parseEnum(status, PROJECT_STATUSES, 'status', 'PLANNED');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });

    const startDateCheck = parseOptionalDate(startDate, 'startDate');
    if (!startDateCheck.ok) return res.status(400).json({ error: startDateCheck.error });
    const targetDeliveryCheck = parseOptionalDate(targetDeliveryDate, 'targetDeliveryDate');
    if (!targetDeliveryCheck.ok) return res.status(400).json({ error: targetDeliveryCheck.error });
    const actualDeliveryCheck = parseOptionalDate(actualDeliveryDate, 'actualDeliveryDate');
    if (!actualDeliveryCheck.ok) return res.status(400).json({ error: actualDeliveryCheck.error });
    const installDateCheck = parseOptionalDate(installationDate, 'installationDate');
    if (!installDateCheck.ok) return res.status(400).json({ error: installDateCheck.error });

    const existingProj = await prisma.project.findUnique({
      where: { projectNumber: cleanProjectNumber },
      select: { id: true, offerId: true, customerId: true, workflowData: true },
    });

    // API-01: Strictly require valid existing offerId & customerId — never fabricate fake customers or OFF-TMP offers
    let validOfferId: string | null = null;
    let resolvedOfferCustomerId: string | null = null;
    if (offerId !== undefined && offerId !== null && offerId !== '') {
      if (!isUuid(offerId)) {
        return res.status(400).json({ error: 'Invalid offerId UUID format.' });
      }
      const offerExists = await prisma.offer.findUnique({
        where: { id: offerId },
        select: { id: true, customerId: true },
      });
      if (!offerExists) {
        return res.status(404).json({ error: 'Referenced offer not found.' });
      }
      validOfferId = offerExists.id;
      resolvedOfferCustomerId = offerExists.customerId;
    } else if (existingProj) {
      validOfferId = existingProj.offerId;
    } else {
      return res.status(400).json({ error: 'A valid offerId UUID is required to create a project.' });
    }

    let validCustomerId: string | null = null;
    if (customerId !== undefined && customerId !== null && customerId !== '') {
      if (!isUuid(customerId)) {
        return res.status(400).json({ error: 'Invalid customerId UUID format.' });
      }
      const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
      if (!custExists) {
        return res.status(404).json({ error: 'Referenced customer not found.' });
      }
      validCustomerId = custExists.id;
    } else if (existingProj) {
      validCustomerId = existingProj.customerId;
    } else if (resolvedOfferCustomerId) {
      validCustomerId = resolvedOfferCustomerId;
    } else {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }

    let validRespUser: string | null = null;
    if (responsibleUserId !== undefined && responsibleUserId !== null && responsibleUserId !== '') {
      if (!isUuid(responsibleUserId)) {
        return res.status(400).json({ error: 'Invalid responsibleUserId UUID format.' });
      }
      const userExists = await prisma.profile.findUnique({ where: { id: responsibleUserId }, select: { id: true } });
      if (!userExists) {
        return res.status(404).json({ error: 'Referenced responsible user not found.' });
      }
      validRespUser = userExists.id;
    }

    const incomingWorkflow = extractWorkflowData(req.body ?? {});
    const mergedWorkflowData = incomingWorkflow
      ? {
          ...(existingProj?.workflowData && typeof existingProj.workflowData === 'object'
            ? (existingProj.workflowData as Record<string, any>)
            : {}),
          ...incomingWorkflow,
        }
      : undefined;

    const project = await prisma.project.upsert({
      where: { projectNumber: cleanProjectNumber },
      update: {
        status: statusCheck.value,
        procurementStatus,
        procurementNotes,
        responsibleUserId: responsibleUserId !== undefined ? validRespUser : undefined,
        startDate: startDateCheck.value,
        targetDeliveryDate: targetDeliveryCheck.value,
        actualDeliveryDate: actualDeliveryCheck.value,
        installationTeam,
        installationDate: installDateCheck.value,
        installationAddress,
        installationContact,
        installationMinutes,
        signatureUrl,
        ...(mergedWorkflowData !== undefined ? { workflowData: mergedWorkflowData } : {}),
      },
      create: {
        projectNumber: cleanProjectNumber,
        offerId: validOfferId,
        customerId: validCustomerId,
        status: statusCheck.value,
        procurementStatus,
        procurementNotes,
        responsibleUserId: validRespUser,
        startDate: startDateCheck.value ?? undefined,
        targetDeliveryDate: targetDeliveryCheck.value ?? undefined,
        actualDeliveryDate: actualDeliveryCheck.value ?? undefined,
        installationTeam,
        installationDate: installDateCheck.value ?? undefined,
        installationAddress,
        installationContact,
        installationMinutes,
        signatureUrl,
        ...(mergedWorkflowData !== undefined ? { workflowData: mergedWorkflowData } : {}),
      },
      include: { customer: true, offer: true, responsibleUser: { select: SAFE_PROFILE_SELECT } },
    });
    res.json(formatProjectForResponse(project));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/projects');
  }
});

app.delete('/api/projects/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid project ID format.' });
    }
    await prisma.project.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/projects/:id');
  }
});

// Helper to format service ticket Decimal fields
const formatTicketForResponse = (ticket: any) => {
  if (!ticket) return ticket;
  return {
    ...ticket,
    laborHours: Number(ticket.laborHours ?? 0),
  };
};

// Service Tickets API
app.get('/api/service-tickets', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const tickets = await prisma.serviceTicket.findMany({
      include: {
        customer: true,
        installedItem: true,
        assignedTechnician: { select: SAFE_PROFILE_SELECT },
      },
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.serviceTicket.count()));
    }
    res.json(tickets.map(formatTicketForResponse));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/service-tickets');
  }
});

app.get('/api/service-tickets/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid service ticket ID format.' });
    }
    const ticket = await prisma.serviceTicket.findUnique({
      where: { id },
      include: {
        customer: true,
        installedItem: true,
        assignedTechnician: { select: SAFE_PROFILE_SELECT },
      },
    });
    if (!ticket) return res.status(404).json({ error: 'Service ticket not found.' });
    res.json(formatTicketForResponse(ticket));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/service-tickets/:id');
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
    } = req.body ?? {};

    const cleanTicketNumber = typeof ticketNumber === 'string' ? ticketNumber.trim() : '';
    if (!cleanTicketNumber) {
      return res.status(400).json({ error: 'ticketNumber is required.' });
    }

    // API-01: Strictly validate customerId
    if (!isUuid(customerId)) {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }
    const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
    if (!custExists) {
      return res.status(404).json({ error: 'Referenced customer not found.' });
    }

    const priorityCheck = parseEnum(priority, SERVICE_PRIORITIES, 'priority', 'MEDIUM');
    if (!priorityCheck.ok) return res.status(400).json({ error: priorityCheck.error });

    const statusCheck = parseEnum(status, SERVICE_STATUSES, 'status', 'OPEN');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });

    const laborCheck = parseFiniteNumber(laborHours, 'laborHours', { min: 0, defaultVal: 0 });
    if (!laborCheck.ok) return res.status(400).json({ error: laborCheck.error });

    const scheduledCheck = parseOptionalDate(scheduledDate, 'scheduledDate');
    if (!scheduledCheck.ok) return res.status(400).json({ error: scheduledCheck.error });

    const closedAtCheck = parseOptionalDate(closedAt, 'closedAt');
    if (!closedAtCheck.ok) return res.status(400).json({ error: closedAtCheck.error });

    let validItem: string | null = null;
    if (installedItemId !== undefined && installedItemId !== null && installedItemId !== '') {
      if (!isUuid(installedItemId)) {
        return res.status(400).json({ error: 'Invalid installedItemId UUID format.' });
      }
      const itemExists = await prisma.installedItem.findUnique({ where: { id: installedItemId }, select: { id: true } });
      if (!itemExists) return res.status(404).json({ error: 'Referenced installed item not found.' });
      validItem = itemExists.id;
    }

    let validTech: string | null = null;
    if (assignedTechnicianId !== undefined && assignedTechnicianId !== null && assignedTechnicianId !== '') {
      if (!isUuid(assignedTechnicianId)) {
        return res.status(400).json({ error: 'Invalid assignedTechnicianId UUID format.' });
      }
      const techExists = await prisma.profile.findUnique({ where: { id: assignedTechnicianId }, select: { id: true } });
      if (!techExists) return res.status(404).json({ error: 'Referenced technician not found.' });
      validTech = techExists.id;
    }

    const ticket = await prisma.serviceTicket.upsert({
      where: { ticketNumber: cleanTicketNumber },
      update: {
        priority: priorityCheck.value,
        status: statusCheck.value,
        defectDescription: defectDescription || 'Пријавен дефект',
        laborHours: laborCheck.value,
        solution,
        assignedTechnicianId: assignedTechnicianId !== undefined ? validTech : undefined,
        scheduledDate: scheduledCheck.value,
        partsConsumed,
        closedAt: closedAtCheck.value,
      },
      create: {
        ticketNumber: cleanTicketNumber,
        customerId,
        installedItemId: validItem,
        defectDescription: defectDescription || 'Пријавен дефект',
        priority: priorityCheck.value,
        status: statusCheck.value,
        laborHours: laborCheck.value,
        solution,
        assignedTechnicianId: validTech,
        scheduledDate: scheduledCheck.value ?? undefined,
        partsConsumed,
        closedAt: closedAtCheck.value ?? undefined,
      },
      include: { customer: true, installedItem: true, assignedTechnician: { select: SAFE_PROFILE_SELECT } },
    });
    res.json(formatTicketForResponse(ticket));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/service-tickets');
  }
});

app.delete('/api/service-tickets/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid service ticket ID format.' });
    }
    await prisma.serviceTicket.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/service-tickets/:id');
  }
});

// Installed Items API
app.get('/api/installed-items', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const items = await prisma.installedItem.findMany({
      include: { customer: true, project: true, product: true },
      orderBy: { installationDate: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.installedItem.count()));
    }
    res.json(
      items.map((it) => ({
        ...it,
        product: it.product ? formatProductForResponse(it.product) : it.product,
      }))
    );
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/installed-items');
  }
});

app.post('/api/installed-items', async (req, res) => {
  try {
    const { id, customerId, projectId, productId, title, serialNumber, installationDate } = req.body ?? {};
    const cleanTitle = typeof title === 'string' ? title.trim() : '';
    if (!cleanTitle) {
      return res.status(400).json({ error: 'title is required.' });
    }

    // API-01: Strictly validate customerId
    if (!isUuid(customerId)) {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }
    const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
    if (!custExists) {
      return res.status(404).json({ error: 'Referenced customer not found.' });
    }

    // API-07: Validate optional projectId, productId UUIDs & installationDate
    let validProjectId: string | null = null;
    if (projectId !== undefined && projectId !== null && projectId !== '') {
      if (!isUuid(projectId)) return res.status(400).json({ error: 'Invalid projectId UUID format.' });
      const projExists = await prisma.project.findUnique({ where: { id: projectId }, select: { id: true } });
      if (!projExists) return res.status(404).json({ error: 'Referenced project not found.' });
      validProjectId = projExists.id;
    }

    let validProductId: string | null = null;
    if (productId !== undefined && productId !== null && productId !== '') {
      if (!isUuid(productId)) return res.status(400).json({ error: 'Invalid productId UUID format.' });
      const prodExists = await prisma.product.findUnique({ where: { id: productId }, select: { id: true } });
      if (!prodExists) return res.status(404).json({ error: 'Referenced product not found.' });
      validProductId = prodExists.id;
    }

    const installDateCheck = parseOptionalDate(installationDate, 'installationDate');
    if (!installDateCheck.ok) return res.status(400).json({ error: installDateCheck.error });

    const item = isUuid(id)
      ? await prisma.installedItem.upsert({
          where: { id },
          update: {
            title: cleanTitle,
            serialNumber: serialNumber ?? null,
            installationDate: installDateCheck.value ?? undefined,
          },
          create: {
            id,
            customerId,
            projectId: validProjectId,
            productId: validProductId,
            title: cleanTitle,
            serialNumber: serialNumber ?? null,
            installationDate: installDateCheck.value ?? undefined,
          },
        })
      : await prisma.installedItem.create({
          data: {
            customerId,
            projectId: validProjectId,
            productId: validProductId,
            title: cleanTitle,
            serialNumber: serialNumber ?? null,
            installationDate: installDateCheck.value ?? undefined,
          },
        });
    res.json(item);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/installed-items');
  }
});

app.delete('/api/installed-items/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid installed item ID format.' });
    }
    await prisma.installedItem.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/installed-items/:id');
  }
});

// Client Documents API
app.get('/api/client-documents', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const includeData = req.query.includeData === 'true';
    const where: any = {};
    if (req.query.customerId) {
      if (!isUuid(req.query.customerId)) return res.status(400).json({ error: 'Invalid customerId filter.' });
      where.customerId = req.query.customerId;
    }
    if (req.query.projectId) {
      if (!isUuid(req.query.projectId)) return res.status(400).json({ error: 'Invalid projectId filter.' });
      where.projectId = req.query.projectId;
    }

    const docs = await prisma.clientDocument.findMany({
      where,
      include: { customer: true },
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.clientDocument.count({ where })));
    }
    res.json(docs.map((d) => formatDocumentForList(d, includeData)));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/client-documents');
  }
});

// API-04: On-demand full document fetch (resolves Supabase Storage ref or returns stored data URL)
app.get('/api/client-documents/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid document ID format.' });
    }
    const doc = await prisma.clientDocument.findUnique({
      where: { id },
      include: { customer: true },
    });
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    let resolvedUrl = doc.fileUrl;
    if (isStorageRef(doc.fileUrl)) {
      const bin = await resolveDocumentBinary(doc.fileUrl);
      if (bin) {
        resolvedUrl = `data:${bin.mime};base64,${bin.buffer.toString('base64')}`;
      }
    }
    res.json({
      ...doc,
      fileUrl: resolvedUrl,
      hasFile: Boolean(resolvedUrl && resolvedUrl !== '#'),
    });
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/client-documents/:id');
  }
});

app.get('/api/client-documents/:id/download', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid document ID format.' });
    }
    const doc = await prisma.clientDocument.findUnique({ where: { id } });
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    const bin = await resolveDocumentBinary(doc.fileUrl);
    if (!bin) {
      return res.status(404).json({ error: 'Document file content is unavailable.' });
    }
    const safeDownloadName = (doc.fileName || doc.title || 'document').replace(/[^a-zA-Z0-9._-]/g, '_');
    res.setHeader('Content-Type', bin.mime);
    res.setHeader('Content-Disposition', `attachment; filename="${safeDownloadName}"`);
    res.send(bin.buffer);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/client-documents/:id/download');
  }
});

app.post('/api/client-documents', async (req, res) => {
  try {
    const { id, customerId, offerId, projectId, serviceId, title, fileType, fileUrl, fileName, sizeBytes } = req.body ?? {};

    const uploadValidation = validateDocumentUpload(fileUrl, fileName || title);
    if (!uploadValidation.ok) {
      return res.status(400).json({ error: uploadValidation.error });
    }

    let validProjectId: string | null = null;
    let resolvedProject: { id: string; customerId: string; offerId: string } | null = null;
    if (projectId !== undefined && projectId !== null && projectId !== '') {
      if (isUuid(projectId)) {
        resolvedProject = await prisma.project.findUnique({
          where: { id: projectId },
          select: { id: true, customerId: true, offerId: true },
        });
      } else {
        resolvedProject = await prisma.project.findUnique({
          where: { projectNumber: String(projectId) },
          select: { id: true, customerId: true, offerId: true },
        });
      }
      if (!resolvedProject) {
        return res.status(404).json({ error: 'Referenced project not found.' });
      }
      validProjectId = resolvedProject.id;
    }

    // API-01: Strictly require a real customerId (explicitly or derived from valid project)
    let validCustomerId: string | null = null;
    if (customerId !== undefined && customerId !== null && customerId !== '') {
      if (!isUuid(customerId)) {
        return res.status(400).json({ error: 'Invalid customerId UUID format.' });
      }
      const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
      if (!custExists) {
        return res.status(404).json({ error: 'Referenced customer not found.' });
      }
      validCustomerId = custExists.id;
    } else if (resolvedProject?.customerId) {
      validCustomerId = resolvedProject.customerId;
    } else {
      return res.status(400).json({ error: 'A valid customerId UUID (or valid projectId) is required.' });
    }

    let validOfferId: string | null = null;
    if (offerId !== undefined && offerId !== null && offerId !== '') {
      const off = isUuid(offerId)
        ? await prisma.offer.findUnique({ where: { id: offerId }, select: { id: true } })
        : await prisma.offer.findUnique({ where: { offerNumber: String(offerId) }, select: { id: true } });
      if (!off) return res.status(404).json({ error: 'Referenced offer not found.' });
      validOfferId = off.id;
    } else if (resolvedProject?.offerId) {
      validOfferId = resolvedProject.offerId;
    }

    let validServiceId: string | null = null;
    if (serviceId !== undefined && serviceId !== null && serviceId !== '') {
      if (!isUuid(serviceId)) return res.status(400).json({ error: 'Invalid serviceId UUID format.' });
      const srvExists = await prisma.serviceTicket.findUnique({ where: { id: serviceId }, select: { id: true } });
      if (!srvExists) return res.status(404).json({ error: 'Referenced service ticket not found.' });
      validServiceId = srvExists.id;
    }

    // API-04: Persist file in Supabase Storage if configured, otherwise store validated data URL
    const persisted = await persistDocumentPayload(String(fileUrl || ''), fileName || title);
    const parsedSize =
      sizeBytes !== undefined && sizeBytes !== null && Number.isFinite(Number(sizeBytes))
        ? Math.max(0, Math.round(Number(sizeBytes)))
        : persisted.sizeBytes ?? null;

    // API-06: Always create a new document when no valid existing UUID is provided (never overwrite by title)
    const doc = isUuid(id)
      ? await prisma.clientDocument.upsert({
          where: { id },
          update: {
            title: title || 'Документ',
            fileType: fileType || 'application/pdf',
            fileUrl: persisted.storedUrl,
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
            fileUrl: persisted.storedUrl,
            fileName: fileName || null,
            sizeBytes: parsedSize,
          },
        })
      : await prisma.clientDocument.create({
          data: {
            customerId: validCustomerId,
            offerId: validOfferId,
            projectId: validProjectId,
            serviceId: validServiceId,
            title: title || 'Документ',
            fileType: fileType || 'application/pdf',
            fileUrl: persisted.storedUrl,
            fileName: fileName || null,
            sizeBytes: parsedSize,
          },
        });

    res.json({
      ...doc,
      hasFile: Boolean(doc.fileUrl && doc.fileUrl !== '#'),
    });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/client-documents');
  }
});

app.delete('/api/client-documents/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid document ID format.' });
    }
    const deleted = await prisma.clientDocument.delete({ where: { id } });
    await deleteStoredDocumentObject(deleted.fileUrl);
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/client-documents/:id');
  }
});

// Calendar Events API
app.get('/api/calendar-events', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const events = await prisma.calendarEvent.findMany({
      include: { customer: true },
      orderBy: { startDate: 'asc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.calendarEvent.count()));
    }
    res.json(events);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/calendar-events');
  }
});

app.post('/api/calendar-events', async (req, res) => {
  try {
    const { id, title, description, startDate, endDate, allDay, eventType, customerId, projectId, location, color } =
      req.body ?? {};

    const cleanTitle = typeof title === 'string' ? title.trim() : '';
    if (!cleanTitle) {
      return res.status(400).json({ error: 'title is required.' });
    }

    const startCheck = parseIsoDateString(startDate, 'startDate', true);
    if (!startCheck.ok || !startCheck.value) {
      return res.status(400).json({ error: startCheck.ok ? 'startDate is required.' : startCheck.error });
    }
    const endCheck = parseIsoDateString(endDate, 'endDate', false);
    if (!endCheck.ok) return res.status(400).json({ error: endCheck.error });

    let validCustomerId: string | null = null;
    if (customerId !== undefined && customerId !== null && customerId !== '') {
      if (!isUuid(customerId)) return res.status(400).json({ error: 'Invalid customerId UUID format.' });
      const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
      if (!custExists) return res.status(404).json({ error: 'Referenced customer not found.' });
      validCustomerId = custExists.id;
    }

    const data = {
      title: cleanTitle,
      description: description ?? null,
      startDate: startCheck.value,
      endDate: endCheck.value,
      allDay: Boolean(allDay),
      eventType: eventType || 'MEETING',
      customerId: validCustomerId,
      projectId: projectId || null,
      location: location ?? null,
      color: color ?? null,
    };

    const event = isUuid(id)
      ? await prisma.calendarEvent.upsert({
          where: { id },
          update: data,
          create: { id, ...data },
          include: { customer: true },
        })
      : await prisma.calendarEvent.create({
          data,
          include: { customer: true },
        });

    res.json(event);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/calendar-events');
  }
});

app.delete('/api/calendar-events/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid calendar event ID format.' });
    }
    await prisma.calendarEvent.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/calendar-events/:id');
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
app.get('/api/purchase-invoices', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const rows = await prisma.purchaseInvoice.findMany({
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.purchaseInvoice.count()));
    }
    res.json(rows.map(formatPurchaseInvoice));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/purchase-invoices');
  }
});

app.post('/api/purchase-invoices', async (req, res) => {
  try {
    const b = req.body ?? {};
    if (!b?.id || !b?.internalNumber) {
      return res.status(400).json({ error: 'id and internalNumber are required' });
    }
    const taxRateCheck = parseFiniteNumber(b.taxRate, 'taxRate', { min: 0, max: 100, defaultVal: 18 });
    if (!taxRateCheck.ok) return res.status(400).json({ error: taxRateCheck.error });
    const subtotalCheck = parseFiniteNumber(b.subtotal, 'subtotal', { min: 0, defaultVal: 0 });
    if (!subtotalCheck.ok) return res.status(400).json({ error: subtotalCheck.error });
    const taxAmountCheck = parseFiniteNumber(b.taxAmount, 'taxAmount', { min: 0, defaultVal: 0 });
    if (!taxAmountCheck.ok) return res.status(400).json({ error: taxAmountCheck.error });
    const totalAmountCheck = parseFiniteNumber(b.totalAmount, 'totalAmount', { min: 0, defaultVal: 0 });
    if (!totalAmountCheck.ok) return res.status(400).json({ error: totalAmountCheck.error });
    const paidAmountCheck = parseFiniteNumber(b.paidAmount, 'paidAmount', { min: 0, defaultVal: 0 });
    if (!paidAmountCheck.ok) return res.status(400).json({ error: paidAmountCheck.error });

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
      taxRate: taxRateCheck.value,
      subtotal: subtotalCheck.value,
      taxAmount: taxAmountCheck.value,
      totalAmount: totalAmountCheck.value,
      paidAmount: paidAmountCheck.value,
      notes: b.notes ?? null,
      items: Array.isArray(b.items) ? b.items : [],
    };
    const saved = await prisma.purchaseInvoice.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json(formatPurchaseInvoice(saved));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/purchase-invoices');
  }
});

app.delete('/api/purchase-invoices/:id', async (req, res) => {
  try {
    await prisma.purchaseInvoice.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/purchase-invoices/:id');
  }
});

// Sales Invoices
app.get('/api/sales-invoices', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const rows = await prisma.salesInvoice.findMany({
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.salesInvoice.count()));
    }
    res.json(rows.map(formatSalesInvoice));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/sales-invoices');
  }
});

app.post('/api/sales-invoices', async (req, res) => {
  try {
    const b = req.body ?? {};
    if (!b?.id || !b?.invoiceNumber) {
      return res.status(400).json({ error: 'id and invoiceNumber are required' });
    }
    const taxRateCheck = parseFiniteNumber(b.taxRate, 'taxRate', { min: 0, max: 100, defaultVal: 18 });
    if (!taxRateCheck.ok) return res.status(400).json({ error: taxRateCheck.error });
    const discountRateCheck = parseFiniteNumber(b.discountRate, 'discountRate', { min: 0, max: 100, defaultVal: 0 });
    if (!discountRateCheck.ok) return res.status(400).json({ error: discountRateCheck.error });
    const totalAmountCheck = parseFiniteNumber(b.totalAmount, 'totalAmount', { min: 0, defaultVal: 0 });
    if (!totalAmountCheck.ok) return res.status(400).json({ error: totalAmountCheck.error });
    const paidAmountCheck = parseFiniteNumber(b.paidAmount, 'paidAmount', { min: 0, defaultVal: 0 });
    if (!paidAmountCheck.ok) return res.status(400).json({ error: paidAmountCheck.error });

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
      taxRate: taxRateCheck.value,
      discountRate: discountRateCheck.value,
      discountAmount: Number(b.discountAmount ?? 0) || 0,
      subtotal: Number(b.subtotal ?? 0) || 0,
      taxAmount: Number(b.taxAmount ?? 0) || 0,
      grossTotalAmount: Number(b.grossTotalAmount ?? 0) || 0,
      linkedAdvanceInvoiceId: b.linkedAdvanceInvoiceId ?? null,
      linkedAdvanceInvoiceNumber: b.linkedAdvanceInvoiceNumber ?? null,
      advanceDeductedAmount: Number(b.advanceDeductedAmount ?? 0) || 0,
      totalAmount: totalAmountCheck.value,
      paidAmount: paidAmountCheck.value,
      notes: b.notes ?? null,
      items: Array.isArray(b.items) ? b.items : [],
    };
    const saved = await prisma.salesInvoice.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json(formatSalesInvoice(saved));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/sales-invoices');
  }
});

app.delete('/api/sales-invoices/:id', async (req, res) => {
  try {
    await prisma.salesInvoice.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/sales-invoices/:id');
  }
});

// Dispatch Notes
app.get('/api/dispatch-notes', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const rows = await prisma.dispatchNote.findMany({
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.dispatchNote.count()));
    }
    res.json(rows.map((r) => ({ ...r, items: Array.isArray(r.items) ? r.items : [] })));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/dispatch-notes');
  }
});

app.post('/api/dispatch-notes', async (req, res) => {
  try {
    const b = req.body ?? {};
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
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/dispatch-notes');
  }
});

app.delete('/api/dispatch-notes/:id', async (req, res) => {
  try {
    await prisma.dispatchNote.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/dispatch-notes/:id');
  }
});

// Payments
app.get('/api/payments', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const rows = await prisma.paymentRecord.findMany({
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.paymentRecord.count()));
    }
    res.json(rows.map(formatPaymentRecord));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/payments');
  }
});

app.post('/api/payments', async (req, res) => {
  try {
    const b = req.body ?? {};
    if (!b?.id || !b?.paymentNumber) {
      return res.status(400).json({ error: 'id and paymentNumber are required' });
    }
    const amountCheck = parseFiniteNumber(b.amount, 'amount', { min: 0, defaultVal: 0 });
    if (!amountCheck.ok) return res.status(400).json({ error: amountCheck.error });

    const data = {
      paymentNumber: String(b.paymentNumber),
      direction: String(b.direction || 'IN'),
      amount: amountCheck.value,
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
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/payments');
  }
});

app.delete('/api/payments/:id', async (req, res) => {
  try {
    await prisma.paymentRecord.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/payments/:id');
  }
});

// Inventory Movements
app.get('/api/inventory-movements', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const rows = await prisma.inventoryMovement.findMany({
      orderBy: { createdAt: 'desc' },
      ...(page.value.isPaginated ? buildPrismaPaginationArgs(page.value) : { take: 500 }),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.inventoryMovement.count()));
    }
    res.json(rows);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/inventory-movements');
  }
});

app.post('/api/inventory-movements', async (req, res) => {
  try {
    const b = req.body ?? {};
    if (!b?.id || !b?.kind || !b?.detail) {
      return res.status(400).json({ error: 'id, kind, and detail are required' });
    }
    const data = {
      kind: String(b.kind),
      detail: String(b.detail),
      productId: b.productId ?? null,
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      quantity: b.quantity !== undefined && b.quantity !== null && Number.isFinite(Number(b.quantity)) ? Math.round(Number(b.quantity)) : null,
      at: String(b.at || new Date().toISOString()),
    };
    const saved = await prisma.inventoryMovement.upsert({
      where: { id: String(b.id) },
      update: data,
      create: { id: String(b.id), ...data },
    });
    res.json(saved);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/inventory-movements');
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
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/company-settings');
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
  } catch (error) {
    return handleRouteError(res, error, 'PUT /api/company-settings');
  }
});

app.listen(PORT, () => {
  console.log(`🚀 IMFEX CRM Express Backend running on port ${PORT}`);
});
