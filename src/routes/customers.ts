import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { formatOfferForResponse, formatProjectForResponse, formatTicketForResponse } from '../lib/formatters';
import { AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import { isValidEmail } from '../security';
import {
  isUuid,
  CUSTOMER_TYPES,
  parseEnum,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const customersRouter = Router();

customersRouter.get('/', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [customers, totalCount] = await Promise.all([
      prisma.customer.findMany({
        include: {
          offers: true,
          projects: true,
          installedItems: true,
          serviceTickets: true,
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.customer.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(
      customers.map((c) => ({
        ...c,
        offers: (c.offers || []).map(formatOfferForResponse),
        projects: (c.projects || []).map((p) => formatProjectForResponse(p)),
        serviceTickets: (c.serviceTickets || []).map(formatTicketForResponse),
      }))
    );
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/customers');
  }
});

customersRouter.get('/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid customer ID format.' });
    }
    const customer = await prisma.customer.findUnique({
      where: { id },
      include: {
        offers: true,
        projects: true,
        installedItems: true,
        serviceTickets: true,
      },
    });
    if (!customer) return res.status(404).json({ error: 'Customer not found.' });
    res.json({
      ...customer,
      offers: (customer.offers || []).map(formatOfferForResponse),
      projects: (customer.projects || []).map((p) => formatProjectForResponse(p)),
      serviceTickets: (customer.serviceTickets || []).map(formatTicketForResponse),
    });
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/customers/:id');
  }
});

customersRouter.post('/', requireRole(...ROLE_GROUPS.CRM_SALES_WRITE), async (req, res) => {
  try {
    const {
      id,
      name,
      companyName,
      taxId,
      customerType,
      email,
      phone,
      address,
      city,
      notes,
      creditLimit,
      paymentTermsDays,
    } = req.body ?? {};
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanName) {
      return res.status(400).json({ error: 'Customer name is required.' });
    }
    const typeCheck = parseEnum(customerType, CUSTOMER_TYPES, 'customerType', 'COMPANY');
    if (!typeCheck.ok) return res.status(400).json({ error: typeCheck.error });

    if (email !== undefined && email !== null && String(email).trim() !== '' && !isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid customer email address.' });
    }

    let creditLimitVal: number | null | undefined;
    if (creditLimit !== undefined) {
      if (creditLimit === null || creditLimit === '') {
        creditLimitVal = null;
      } else {
        const clCheck = parseFiniteNumber(creditLimit, 'creditLimit', { min: 0 });
        if (!clCheck.ok) return res.status(400).json({ error: clCheck.error });
        creditLimitVal = clCheck.value;
      }
    }
    const termsCheck = parseFiniteNumber(paymentTermsDays, 'paymentTermsDays', {
      min: 0,
      max: 365,
      defaultVal: 15,
      integer: true,
    });
    if (!termsCheck.ok) return res.status(400).json({ error: termsCheck.error });

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
      ...(creditLimitVal !== undefined ? { creditLimit: creditLimitVal } : {}),
      ...(paymentTermsDays !== undefined ? { paymentTermsDays: termsCheck.value } : {}),
    };

    const customer = isUuid(id)
      ? await prisma.customer.upsert({
          where: { id },
          update: data,
          create: { id, ...data },
        })
      : await prisma.customer.create({ data });

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'CUSTOMER_SAVED',
      entityType: 'Customer',
      entityId: customer.id,
      metadata: { name: customer.name, companyName: customer.companyName },
    });
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
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'CUSTOMER_DELETED',
      entityType: 'Customer',
      entityId: id,
    });
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
