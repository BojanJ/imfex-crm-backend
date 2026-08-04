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

// Admin Database Cleanup & UTF-8 Sync Endpoint
app.all('/api/admin/clean-database', async (req, res) => {
  try {
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

    let customerCorp = await prisma.customer.findFirst({ where: { taxId: 'MK4030012345678' } });
    if (!customerCorp || customerCorp.name.includes('?')) {
      customerCorp = await prisma.customer.create({
        data: {
          customerType: 'COMPANY',
          name: 'Логистички Центар Скопје ДООЕЛ',
          companyName: 'Логистички Центар Скопје ДООЕЛ',
          taxId: 'MK4030012345678',
          email: 'nabavki@logistika.mk',
          phone: '+389 2 3123 456',
          address: 'Ул. Индустриска бр. 42',
          city: 'Скопје',
          notes: 'Главен комерцијален клиент. Стандардно фактурирање со 18% ДДВ.',
        },
      });
    }

    let customerInd = await prisma.customer.findFirst({ where: { email: 'alex.stojanovski@gmail.com' } });
    if (!customerInd || customerInd.name.includes('?')) {
      customerInd = await prisma.customer.create({
        data: {
          customerType: 'INDIVIDUAL',
          name: 'Александар Стојановски',
          companyName: '',
          email: 'alex.stojanovski@gmail.com',
          phone: '+389 70 888 999',
          address: 'Ул. Партизански Одреди 74',
          city: 'Скопје',
          notes: 'Редовен индивидуален купувач.',
        },
      });
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

// Admin Fresh Database Wipe Endpoint (0 records, 2 System Users)
app.all('/api/admin/reset-database', async (req, res) => {
  try {
    await prisma.offerItem.deleteMany();
    await prisma.offer.deleteMany();
    await prisma.project.deleteMany();
    await prisma.serviceTicket.deleteMany();
    await prisma.installedItem.deleteMany();
    await prisma.clientDocument.deleteMany();
    await prisma.calendarEvent.deleteMany();
    await prisma.customer.deleteMany();
    await prisma.specificationOption.deleteMany();
    await prisma.specificationKey.deleteMany();
    await prisma.productModel.deleteMany();
    await prisma.product.deleteMany();

    await prisma.profile.deleteMany({
      where: {
        email: { notIn: ['admin@imfex.com', 'sales@imfex.com'] },
      },
    });

    const adminPasswordHash = bcrypt.hashSync('admin123', 10);
    const salesPasswordHash = bcrypt.hashSync('sales123', 10);

    await prisma.profile.upsert({
      where: { email: 'admin@imfex.com' },
      update: {
        passwordHash: adminPasswordHash,
        mustChangePassword: false,
        status: 'ACTIVE',
      },
      create: {
        id: '11111111-1111-1111-1111-111111111111',
        email: 'admin@imfex.com',
        fullName: 'Супер Администратор',
        role: 'SUPER_ADMIN',
        passwordHash: adminPasswordHash,
        mustChangePassword: false,
        status: 'ACTIVE',
      },
    });

    await prisma.profile.upsert({
      where: { email: 'sales@imfex.com' },
      update: {
        passwordHash: salesPasswordHash,
        mustChangePassword: false,
        status: 'ACTIVE',
      },
      create: {
        id: '22222222-2222-2222-2222-222222222222',
        email: 'sales@imfex.com',
        fullName: 'Менаџер за Продажба',
        role: 'USER',
        passwordHash: salesPasswordHash,
        mustChangePassword: false,
        status: 'ACTIVE',
      },
    });

    res.json({
      success: true,
      message: 'Database reset cleanly to fresh state. 0 records, 2 system users active (admin@imfex.com & sales@imfex.com).',
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
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

app.put('/api/profiles/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { fullName, role, status, password } = req.body;
    const updateData: any = {};
    if (fullName !== undefined) updateData.fullName = fullName;
    if (role !== undefined) updateData.role = role;
    if (status !== undefined) updateData.status = status;
    if (password) {
      updateData.passwordHash = bcrypt.hashSync(password, 10);
      updateData.mustChangePassword = false;
    }

    const profile = await prisma.profile.update({
      where: { id },
      data: updateData,
    });
    const { passwordHash, ...userWithoutPassword } = profile;
    res.json(userWithoutPassword);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/profiles/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.profile.delete({ where: { id } }).catch(() => null);
    res.json({ success: true, id });
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
    const { id, name, code, description, isActive, models, specificationKeys } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Product code is required' });
    }

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
        },
        create: {
          id,
          name,
          code,
          description,
          isActive: isActive !== undefined ? isActive : true,
        },
        include: {
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
        },
        create: {
          name,
          code,
          description,
          isActive: isActive !== undefined ? isActive : true,
        },
        include: {
          models: true,
          specificationKeys: { include: { options: true } },
        },
      });
    }

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

// Helper to format offer item specifications
const formatOfferForResponse = (offer: any) => {
  if (!offer) return offer;
  return {
    ...offer,
    items: (offer.items || []).map((item: any) => ({
      ...item,
      specifications: (item.offerItemSpecifications || item.specifications || []).map((s: any) => ({
        specificationKeyId: s.specificationKeyId,
        specificationOptionId: s.specificationOptionId || undefined,
        customValue: s.customValue || undefined,
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
        createdByUser: true,
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
        createdByUser: true,
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
          taxRate: taxRate ? Number(taxRate) : 18.0,
          discountRate: discountRate ? Number(discountRate) : 0.0,
          discountAmount: discountAmount ? Number(discountAmount) : 0.0,
          subtotal: subtotal ? Number(subtotal) : 0.0,
          taxAmount: taxAmount ? Number(taxAmount) : 0.0,
          totalAmount: totalAmount ? Number(totalAmount) : 0.0,
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
                },
              }).catch((e) => console.warn('Skipping offerItemSpecification insert warning:', e?.message || e));
            }
          }
        }
      }
    }

    const fullOffer = await prisma.offer.findUnique({
      where: { id: offer.id },
      include: {
        customer: true,
        createdByUser: true,
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
      },
      include: { customer: true, offer: true, responsibleUser: true },
    });
    res.json(project);
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
      include: { customer: true, installedItem: true, assignedTechnician: true },
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
    const { id, customerId, offerId, projectId, serviceId, title, fileType, fileUrl } = req.body;
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
        const newCust = await prisma.customer.create({ data: { name: 'Главен Клиент' } });
        validCustomerId = newCust.id;
      }
    }

    const validOfferId = isUuid(offerId) ? offerId : null;
    const validProjectId = isUuid(projectId) ? projectId : null;
    const validServiceId = isUuid(serviceId) ? serviceId : null;

    let doc;
    if (isUuid(id)) {
      doc = await prisma.clientDocument.upsert({
        where: { id },
        update: {
          title: title || 'Документ',
          fileType: fileType || 'application/pdf',
          fileUrl: fileUrl || '',
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
        },
      });
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
    const { id, title, description, startDate, endDate, allDay, eventType, customerId, location, color } = req.body;

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

app.listen(PORT, () => {
  console.log(`🚀 IMFEX CRM Express Backend running on port ${PORT}`);
});
