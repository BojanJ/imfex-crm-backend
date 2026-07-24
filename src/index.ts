import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Health Check Endpoint for Render
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'IMFEX Enterprise CRM Backend',
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to IMFEX Enterprise CRM Backend API',
    health: '/health',
    version: '1.0.0',
  });
});

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
    const profile = await prisma.profile.create({
      data: {
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
    const { name, code, description, isActive } = req.body;
    const product = await prisma.product.create({
      data: { name, code, description, isActive: isActive ?? true },
    });
    res.json(product);
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
    const customer = await prisma.customer.create({
      data: req.body,
    });
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
    const { offerNumber, customerId, createdByUserId, taxRate, subtotal, taxAmount, totalAmount, items } = req.body;
    const offer = await prisma.offer.create({
      data: {
        offerNumber,
        customerId,
        createdByUserId,
        taxRate,
        subtotal,
        taxAmount,
        totalAmount,
        items: {
          create: items || [],
        },
      },
      include: { customer: true, items: true },
    });
    res.json(offer);
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
    const project = await prisma.project.create({
      data: req.body,
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
    const ticket = await prisma.serviceTicket.create({
      data: req.body,
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
