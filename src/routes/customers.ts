import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { formatOfferForResponse, formatTicketForResponse } from '../lib/formatters';
import { ROLE_GROUPS, requireRole } from '../auth';
import { isValidEmail } from '../security';
import {
  isUuid,
  CUSTOMER_TYPES,
  parseEnum,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';

export const customersRouter = Router();

customersRouter.get('/', async (req, res) => {
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

customersRouter.post('/', requireRole(...ROLE_GROUPS.CRM_SALES_WRITE), async (req, res) => {
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

customersRouter.delete('/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
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
