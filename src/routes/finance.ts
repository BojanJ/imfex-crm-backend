import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { ROLE_GROUPS, requireRole } from '../auth';
import { formatPurchaseInvoice, formatSalesInvoice, formatPaymentRecord } from '../lib/formatters';
import { parseFiniteNumber, parsePagination, buildPrismaPaginationArgs, handleRouteError } from '../validation';

export const financeRouter = Router();

// Purchase Invoices
financeRouter.get('/purchase-invoices', requireRole(...ROLE_GROUPS.FINANCE_READ), async (req, res) => {
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

financeRouter.post('/purchase-invoices', requireRole(...ROLE_GROUPS.FINANCE_WRITE), async (req, res) => {
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

financeRouter.delete('/purchase-invoices/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    await prisma.purchaseInvoice.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/purchase-invoices/:id');
  }
});

// Sales Invoices
financeRouter.get('/sales-invoices', requireRole(...ROLE_GROUPS.FINANCE_READ), async (req, res) => {
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

financeRouter.post('/sales-invoices', requireRole(...ROLE_GROUPS.FINANCE_SALES_WRITE), async (req, res) => {
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

financeRouter.delete('/sales-invoices/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    await prisma.salesInvoice.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/sales-invoices/:id');
  }
});

// Dispatch Notes
financeRouter.get('/dispatch-notes', async (req, res) => {
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

financeRouter.post('/dispatch-notes', requireRole(...ROLE_GROUPS.FINANCE_SALES_WRITE), async (req, res) => {
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

financeRouter.delete('/dispatch-notes/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    await prisma.dispatchNote.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/dispatch-notes/:id');
  }
});

// Payments
financeRouter.get('/payments', requireRole(...ROLE_GROUPS.FINANCE_READ), async (req, res) => {
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

financeRouter.post('/payments', requireRole(...ROLE_GROUPS.FINANCE_SALES_WRITE), async (req, res) => {
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

financeRouter.delete('/payments/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    await prisma.paymentRecord.delete({ where: { id: String(req.params.id) } });
    res.json({ success: true, id: req.params.id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/payments/:id');
  }
});

// Inventory Movements
financeRouter.get('/inventory-movements', async (req, res) => {
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

financeRouter.post('/inventory-movements', requireRole(...ROLE_GROUPS.FINANCE_SALES_WRITE), async (req, res) => {
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
      quantity:
        b.quantity !== undefined && b.quantity !== null && Number.isFinite(Number(b.quantity))
          ? Math.round(Number(b.quantity))
          : null,
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
