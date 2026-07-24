import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { Resend } from 'resend';

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;

// Initialize Resend Email Service
const resendApiKey = process.env.RESEND_API_KEY || '';
const resend = resendApiKey ? new Resend(resendApiKey) : null;
const EMAIL_FROM = process.env.EMAIL_FROM || 'IMFEX CRM <onboarding@resend.dev>';

// Support payload up to 10MB for PDF base64 attachments
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

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
// EMAIL TRANSACTIONAL API ENDPOINTS
// ==========================================

// 1. Send Offer PDF to Customer
app.post('/api/email/send-offer', async (req, res) => {
  try {
    const { to, customerName, offerNumber, totalAmount, pdfBase64, customMessage } = req.body;

    if (!to) {
      return res.status(400).json({ error: 'Recipient email address (to) is required.' });
    }

    if (!resend) {
      return res.status(503).json({
        error: 'Email service is not configured. Please add RESEND_API_KEY to environment variables in Render.',
      });
    }

    let attachments: { filename: string; content: Buffer }[] = [];
    if (pdfBase64) {
      const cleanBase64 = String(pdfBase64).replace(/^data:.*?;base64,/, '').trim();
      const pdfBuffer = Buffer.from(cleanBase64, 'base64');
      attachments = [
        {
          filename: `${offerNumber || 'Offer'}.pdf`,
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
          <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 12px;">Комерцијална Понуда • ${offerNumber || ''}</p>
        </div>

        <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; background-color: #ffffff;">
          <p style="font-size: 14px; font-weight: 700; color: #0f172a;">Почитувани ${customerName || 'Клиент'},</p>
          <p style="font-size: 13px; color: #334155;">
            Во прилог на оваа порака Ви ја испраќаме официјалната комерцијална понуда <strong>${offerNumber || ''}</strong> со вкупен износ од <strong>€${Number(totalAmount || 0).toFixed(2)}</strong>.
          </p>

          ${
            customMessage
              ? `<div style="background-color: #f8fafc; border-left: 4px solid #2563eb; padding: 12px; margin: 16px 0; font-size: 12px; color: #475569; font-style: italic;">
                  "${customMessage}"
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
      to: [to],
      subject: `Комерцијална Понуда ${offerNumber || ''} - ИМФЕКС ЕКСПОРТ-ИМПОРТ`,
      html: htmlContent,
      attachments,
    });

    if (result.error) {
      return res.status(400).json({ error: result.error.message });
    }

    res.json({ success: true, id: result.data?.id });
  } catch (error: any) {
    console.error('Send offer email error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 2. Send Welcome & Temporary Password Email to New User
app.post('/api/email/welcome-user', async (req, res) => {
  try {
    const { to, fullName, tempPassword, role } = req.body;

    if (!to || !fullName) {
      return res.status(400).json({ error: 'Recipient email and full name are required.' });
    }

    if (!resend) {
      return res.status(503).json({
        error: 'Email service is not configured. Please add RESEND_API_KEY to environment variables.',
      });
    }

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #1e293b;">
        <div style="background-color: #0f172a; padding: 24px; text-align: center; border-radius: 12px 12px 0 0;">
          <h1 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 800;">
            Добредојдовте во IMFEX Enterprise CRM
          </h1>
        </div>

        <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; background-color: #ffffff;">
          <p style="font-size: 14px; font-weight: 700;">Здраво ${fullName},</p>
          <p style="font-size: 13px;">
            Креиран е нов кориснички сметка за Вес на платформата за управување со клиенти и понуди на <strong>ИМФЕКС</strong>.
          </p>

          <div style="background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin: 16px 0; font-size: 13px;">
            <p style="margin: 0 0 8px 0;"><strong>Е-пошта:</strong> ${to}</p>
            <p style="margin: 0 0 8px 0;"><strong>Привремена лозинка:</strong> <span style="font-family: monospace; font-size: 14px; color: #2563eb; font-weight: 700;">${tempPassword || 'IMFEX123!'}</span></p>
            <p style="margin: 0;"><strong>Улога:</strong> ${role || 'Корисник'}</p>
          </div>

          <p style="font-size: 12px; color: #64748b;">
            При првата најава, ќе биде побарано да ја промените вашата привремена лозинка за безбедност.
          </p>
        </div>
      </div>
    `;

    const result = await resend.emails.send({
      from: EMAIL_FROM,
      to: [to],
      subject: `Добредојдовте во IMFEX Enterprise CRM - Податоци за најава`,
      html: htmlContent,
    });

    if (result.error) {
      return res.status(400).json({ error: result.error.message });
    }

    res.json({ success: true, id: result.data?.id });
  } catch (error: any) {
    console.error('Send welcome email error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 3. Send Password Reset Email
app.post('/api/email/reset-password', async (req, res) => {
  try {
    const { to, tempPassword } = req.body;

    if (!to) {
      return res.status(400).json({ error: 'Recipient email is required.' });
    }

    if (!resend) {
      return res.status(503).json({
        error: 'Email service is not configured. Please add RESEND_API_KEY to environment variables.',
      });
    }

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #1e293b;">
        <div style="background-color: #0f172a; padding: 24px; text-align: center; border-radius: 12px 12px 0 0;">
          <h1 style="color: #ffffff; margin: 0; font-size: 20px; font-weight: 800;">
            Ресетирање на Лозинка • IMFEX CRM
          </h1>
        </div>

        <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; background-color: #ffffff;">
          <p style="font-size: 14px;">Побарано е ресетирање на вашата лозинка за IMFEX CRM.</p>

          <div style="background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin: 16px 0; font-size: 13px;">
            <p style="margin: 0;"><strong>Вашата нова привремена лозинка е:</strong> <span style="font-family: monospace; font-size: 14px; color: #dc2626; font-weight: 700;">${tempPassword || 'TempPass2026!'}</span></p>
          </div>

          <p style="font-size: 12px; color: #64748b;">
            Ве молиме најавете се со оваа лозинка и веднаш променете ја во Нагодувања.
          </p>
        </div>
      </div>
    `;

    const result = await resend.emails.send({
      from: EMAIL_FROM,
      to: [to],
      subject: `Ресетирање на лозинка - IMFEX Enterprise CRM`,
      html: htmlContent,
    });

    if (result.error) {
      return res.status(400).json({ error: result.error.message });
    }

    res.json({ success: true, id: result.data?.id });
  } catch (error: any) {
    console.error('Send reset password email error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// EXISTING CRUD & AUTH ENDPOINTS
// ==========================================

// Auth API
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await prisma.profile.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user || user.status === 'DISABLED') {
      return res.status(401).json({ error: 'Invalid credentials or account disabled' });
    }

    if (user.passwordHash && password) {
      const isValid = bcrypt.compareSync(password, user.passwordHash);
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }

    const { passwordHash, ...userWithoutPassword } = user;
    res.json({
      token: `jwt-imfex-${user.id}-${Date.now()}`,
      user: userWithoutPassword,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Profiles / User Accounts API
app.get('/api/profiles', async (req, res) => {
  try {
    const profiles = await prisma.profile.findMany({
      select: {
        id: true,
        email: true,
        fullName: true,
        role: true,
        mustChangePassword: true,
        status: true,
        createdAt: true,
      },
    });
    res.json(profiles);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/profiles', async (req, res) => {
  try {
    const { email, fullName, role, password } = req.body;
    const passwordHash = password ? bcrypt.hashSync(password, 10) : bcrypt.hashSync('IMFEX2026!', 10);
    const profile = await prisma.profile.upsert({
      where: { email: email.toLowerCase() },
      update: { fullName, role, status: 'ACTIVE' },
      create: {
        email: email.toLowerCase(),
        fullName,
        role: role || 'USER',
        passwordHash,
        mustChangePassword: true,
        status: 'ACTIVE',
      },
    });
    res.json(profile);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Products API
app.get('/api/products', async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      include: {
        models: true,
        specificationKeys: {
          include: {
            options: true,
          },
        },
      },
    });
    res.json(products);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { name, code, description, isActive, models, specificationKeys } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Product code is required' });
    }

    const product = await prisma.product.upsert({
      where: { code },
      update: {
        name,
        description,
        isActive: isActive ?? true,
      },
      create: {
        name,
        code,
        description,
        isActive: isActive ?? true,
      },
      include: {
        models: true,
        specificationKeys: { include: { options: true } },
      },
    });

    if (Array.isArray(models)) {
      for (const m of models) {
        if (m.name) {
          const existingModel = await prisma.productModel.findFirst({
            where: { productId: product.id, name: m.name },
          });
          if (!existingModel) {
            await prisma.productModel.create({
              data: {
                productId: product.id,
                name: m.name,
                basePrice: m.basePrice || 0,
              },
            });
          }
        }
      }
    }

    if (Array.isArray(specificationKeys)) {
      for (const sk of specificationKeys) {
        if (sk.name) {
          let specKey = await prisma.specificationKey.findFirst({
            where: { productId: product.id, name: sk.name },
          });
          if (!specKey) {
            specKey = await prisma.specificationKey.create({
              data: {
                productId: product.id,
                name: sk.name,
                inputType: sk.inputType || 'SELECT',
              },
            });
          }
          if (Array.isArray(sk.options)) {
            for (const opt of sk.options) {
              if (opt.label) {
                const existingOpt = await prisma.specificationOption.findFirst({
                  where: { specificationKeyId: specKey.id, label: opt.label },
                });
                if (!existingOpt) {
                  await prisma.specificationOption.create({
                    data: {
                      specificationKeyId: specKey.id,
                      label: opt.label,
                      priceModifier: opt.priceModifier || 0,
                    },
                  });
                }
              }
            }
          }
        }
      }
    }

    const updatedProduct = await prisma.product.findUnique({
      where: { id: product.id },
      include: { models: true, specificationKeys: { include: { options: true } } },
    });

    res.json(updatedProduct);
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
    let customer;
    if (id) {
      customer = await prisma.customer.upsert({
        where: { id },
        update: { name, companyName, customerType, email, phone, address, city, notes },
        create: { name, companyName, customerType, email, phone, address, city, notes },
      });
    } else {
      customer = await prisma.customer.create({
        data: { name, companyName, customerType, email, phone, address, city, notes },
      });
    }
    res.json(customer);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Offers API
app.get('/api/offers', async (req, res) => {
  try {
    const offers = await prisma.offer.findMany({
      include: {
        customer: true,
        createdByUser: true,
        items: true,
      },
    });
    res.json(offers);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/offers', async (req, res) => {
  try {
    const {
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
    } = req.body;

    if (!offerNumber) {
      return res.status(400).json({ error: 'Offer number is required' });
    }

    // Verify valid customer ID or fallback to first available customer in DB
    let validCustomerId = customerId;
    if (validCustomerId) {
      const custExists = await prisma.customer.findUnique({ where: { id: validCustomerId } }).catch(() => null);
      if (!custExists) {
        const firstCust = await prisma.customer.findFirst();
        if (firstCust) validCustomerId = firstCust.id;
      }
    } else {
      const firstCust = await prisma.customer.findFirst();
      if (firstCust) validCustomerId = firstCust.id;
    }

    if (!validCustomerId) {
      const newCust = await prisma.customer.create({
        data: { name: 'Главен Клиент', email: 'nabavki@logistika.mk' },
      });
      validCustomerId = newCust.id;
    }

    // Verify valid user ID or leave null
    let validUserId: string | null = null;
    if (createdByUserId) {
      const userExists = await prisma.profile.findUnique({ where: { id: createdByUserId } }).catch(() => null);
      if (userExists) validUserId = userExists.id;
    }

    const offer = await prisma.offer.upsert({
      where: { offerNumber },
      update: {
        customerId: validCustomerId,
        createdByUserId: validUserId,
        status: status || 'DRAFT',
        taxRate: taxRate ? Number(taxRate) : 18.0,
        discountRate: discountRate ? Number(discountRate) : 0.0,
        discountAmount: discountAmount ? Number(discountAmount) : 0.0,
        subtotal: subtotal ? Number(subtotal) : 0.0,
        taxAmount: taxAmount ? Number(taxAmount) : 0.0,
        totalAmount: totalAmount ? Number(totalAmount) : 0.0,
      },
      create: {
        offerNumber,
        customerId: validCustomerId,
        createdByUserId: validUserId,
        status: status || 'DRAFT',
        taxRate: taxRate ? Number(taxRate) : 18.0,
        discountRate: discountRate ? Number(discountRate) : 0.0,
        discountAmount: discountAmount ? Number(discountAmount) : 0.0,
        subtotal: subtotal ? Number(subtotal) : 0.0,
        taxAmount: taxAmount ? Number(taxAmount) : 0.0,
        totalAmount: totalAmount ? Number(totalAmount) : 0.0,
      },
      include: { customer: true, items: true },
    });

    res.json(offer);
  } catch (error: any) {
    console.error('POST /api/offers error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Projects API
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await prisma.project.findMany({
      include: {
        customer: true,
        offer: true,
        responsibleUser: true,
        installedItems: true,
      },
    });
    res.json(projects);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects', async (req, res) => {
  try {
    const { projectNumber, offerId, customerId, status, procurementStatus, procurementNotes } = req.body;
    const project = await prisma.project.upsert({
      where: { projectNumber },
      update: { status, procurementStatus, procurementNotes },
      create: { projectNumber, offerId, customerId, status: status || 'PLANNED', procurementStatus, procurementNotes },
      include: { customer: true, offer: true },
    });
    res.json(project);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Service Tickets API
app.get('/api/service-tickets', async (req, res) => {
  try {
    const tickets = await prisma.serviceTicket.findMany({
      include: {
        customer: true,
        installedItem: true,
        assignedTechnician: true,
      },
    });
    res.json(tickets);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/service-tickets', async (req, res) => {
  try {
    const { ticketNumber, customerId, installedItemId, defectDescription, priority, status, laborHours, solution } = req.body;
    const ticket = await prisma.serviceTicket.upsert({
      where: { ticketNumber },
      update: { priority, status, laborHours, solution },
      create: { ticketNumber, customerId, installedItemId, defectDescription, priority: priority || 'MEDIUM', status: status || 'OPEN', laborHours, solution },
      include: { customer: true, installedItem: true },
    });
    res.json(ticket);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 IMFEX CRM Express Backend running on port ${PORT}`);
});
