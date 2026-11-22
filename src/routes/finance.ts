import { Router } from 'express';
import type { Prisma } from '@prisma/client';
import { prisma } from '../lib/prisma';
import { AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import { formatPurchaseInvoice, formatSalesInvoice, formatPaymentRecord } from '../lib/formatters';
import {
  isUuid,
  PURCHASE_INVOICE_STATUSES,
  RECEIPT_STATUSES,
  SALES_INVOICE_TYPES,
  SALES_INVOICE_STATUSES,
  DISPATCH_STATUSES,
  PAYMENT_DIRECTIONS,
  PAYMENT_METHODS,
  INVENTORY_MOVE_KINDS,
  parseEnum,
  parseIsoDateString,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const financeRouter = Router();

const MAX_FINANCE_ITEMS = 500;

/**
 * Batch-attaches Customer objects (and fallback customerName) to SalesInvoice / DispatchNote rows
 * in a single IN query (zero N+1), fixing literal "Клиент" placeholders (API-12).
 */
async function attachCustomersToRows<T extends { customerId?: string | null; customerName?: string | null }>(
  rows: T[]
): Promise<Array<T & { customer?: any; customerName: string | null }>> {
  const uuidIds = Array.from(
    new Set(rows.map((r) => r.customerId).filter((cid): cid is string => isUuid(cid)))
  );
  if (uuidIds.length === 0) {
    return rows.map((r) => ({ ...r, customerName: r.customerName ?? null }));
  }

  const customers = await prisma.customer.findMany({
    where: { id: { in: uuidIds } },
  });
  const custMap = new Map(customers.map((c) => [c.id, c]));

  return rows.map((r) => {
    const cust = r.customerId ? custMap.get(r.customerId) : undefined;
    const resolvedName = cust ? cust.companyName || cust.name : r.customerName ?? null;
    return {
      ...r,
      ...(cust ? { customer: cust } : {}),
      customerName: resolvedName,
    };
  });
}

/**
 * Atomically recalculates `paidAmount` and `status` on linked SalesInvoice and/or PurchaseInvoice
 * inside a Prisma transaction whenever a PaymentRecord is created, updated, or deleted (API-10).
 */
async function recomputeInvoicePaymentStateTx(
  tx: Prisma.TransactionClient,
  refs: { salesInvoiceId?: string | null; purchaseInvoiceId?: string | null }
) {
  if (refs.salesInvoiceId) {
    const inv = await tx.salesInvoice.findUnique({ where: { id: refs.salesInvoiceId } });
    if (inv && inv.status !== 'CANCELLED') {
      const agg = await tx.paymentRecord.aggregate({
        where: { salesInvoiceId: inv.id, direction: 'IN' },
        _sum: { amount: true },
      });
      const paid = Math.round(Number(agg._sum.amount ?? 0) * 100) / 100;
      const total = Number(inv.totalAmount ?? 0);
      const nextStatus =
        total > 0 && paid >= total - 0.01
          ? 'PAID'
          : paid > 0
          ? 'PARTIAL_PAID'
          : inv.status === 'DRAFT'
          ? 'DRAFT'
          : 'ISSUED';
      await tx.salesInvoice.update({
        where: { id: inv.id },
        data: { paidAmount: paid, status: nextStatus },
      });
    }
  }

  if (refs.purchaseInvoiceId) {
    const pinv = await tx.purchaseInvoice.findUnique({ where: { id: refs.purchaseInvoiceId } });
    if (pinv && pinv.status !== 'CANCELLED') {
      const agg = await tx.paymentRecord.aggregate({
        where: { purchaseInvoiceId: pinv.id, direction: 'OUT' },
        _sum: { amount: true },
      });
      const paid = Math.round(Number(agg._sum.amount ?? 0) * 100) / 100;
      const total = Number(pinv.totalAmount ?? 0);
      const nextStatus =
        total > 0 && paid >= total - 0.01
          ? 'PAID'
          : paid > 0
          ? 'PARTIAL_PAID'
          : pinv.status === 'DRAFT'
          ? 'DRAFT'
          : 'INVOICED';
      await tx.purchaseInvoice.update({
        where: { id: pinv.id },
        data: { paidAmount: paid, status: nextStatus },
      });
    }
  }
}

// =========================================================================
// PURCHASE INVOICES
// =========================================================================

financeRouter.get('/purchase-invoices', requireRole(...ROLE_GROUPS.FINANCE_READ), async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [rows, totalCount] = await Promise.all([
      prisma.purchaseInvoice.findMany({
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.purchaseInvoice.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
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
      return res.status(400).json({ error: 'id and internalNumber are required.' });
    }
    if (b.items !== undefined && (!Array.isArray(b.items) || b.items.length > MAX_FINANCE_ITEMS)) {
      return res.status(400).json({ error: `items must be an array of at most ${MAX_FINANCE_ITEMS} entries.` });
    }

    const statusCheck = parseEnum(b.status, PURCHASE_INVOICE_STATUSES, 'status', 'INVOICED');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });
    const receiptCheck = parseEnum(b.receiptStatus, RECEIPT_STATUSES, 'receiptStatus', 'PENDING');
    if (!receiptCheck.ok) return res.status(400).json({ error: receiptCheck.error });
    const issueDateCheck = parseIsoDateString(
      b.issueDate || new Date().toISOString().split('T')[0],
      'issueDate',
      true
    );
    if (!issueDateCheck.ok || !issueDateCheck.value) {
      return res.status(400).json({ error: issueDateCheck.ok ? 'issueDate is required.' : issueDateCheck.error });
    }
    const dueDateCheck = parseIsoDateString(b.dueDate, 'dueDate', false);
    if (!dueDateCheck.ok) return res.status(400).json({ error: dueDateCheck.error });

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
      internalNumber: String(b.internalNumber).trim(),
      supplierInvoiceNumber: b.supplierInvoiceNumber ?? null,
      supplierId: String(b.supplierId || ''),
      supplierName: String(b.supplierName || 'Добавувач').trim(),
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      issueDate: issueDateCheck.value,
      dueDate: dueDateCheck.value,
      status: statusCheck.value,
      receiptStatus: receiptCheck.value,
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
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PURCHASE_INVOICE_SAVED',
      entityType: 'PurchaseInvoice',
      entityId: saved.id,
      metadata: { internalNumber: saved.internalNumber, totalAmount: Number(saved.totalAmount) },
    });
    res.json(formatPurchaseInvoice(saved));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/purchase-invoices');
  }
});

financeRouter.delete('/purchase-invoices/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    await prisma.purchaseInvoice.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PURCHASE_INVOICE_DELETED',
      entityType: 'PurchaseInvoice',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/purchase-invoices/:id');
  }
});

// =========================================================================
// SALES INVOICES
// =========================================================================

financeRouter.get('/sales-invoices', requireRole(...ROLE_GROUPS.FINANCE_READ), async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [rows, totalCount] = await Promise.all([
      prisma.salesInvoice.findMany({
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.salesInvoice.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    const enriched = await attachCustomersToRows(rows.map(formatSalesInvoice));
    res.json(enriched);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/sales-invoices');
  }
});

financeRouter.post('/sales-invoices', requireRole(...ROLE_GROUPS.FINANCE_SALES_WRITE), async (req, res) => {
  try {
    const b = req.body ?? {};
    if (!b?.id || !b?.invoiceNumber) {
      return res.status(400).json({ error: 'id and invoiceNumber are required.' });
    }
    if (b.items !== undefined && (!Array.isArray(b.items) || b.items.length > MAX_FINANCE_ITEMS)) {
      return res.status(400).json({ error: `items must be an array of at most ${MAX_FINANCE_ITEMS} entries.` });
    }

    // API-12: Require a real existing customerId and snapshot customerName
    if (!isUuid(b.customerId)) {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }
    const customer = await prisma.customer.findUnique({ where: { id: b.customerId } });
    if (!customer) {
      return res.status(404).json({ error: 'Referenced customer not found.' });
    }

    const invoiceTypeCheck = parseEnum(b.invoiceType, SALES_INVOICE_TYPES, 'invoiceType', 'FINAL');
    if (!invoiceTypeCheck.ok) return res.status(400).json({ error: invoiceTypeCheck.error });
    const statusCheck = parseEnum(b.status, SALES_INVOICE_STATUSES, 'status', 'ISSUED');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });

    const issueDateCheck = parseIsoDateString(
      b.issueDate || new Date().toISOString().split('T')[0],
      'issueDate',
      true
    );
    if (!issueDateCheck.ok || !issueDateCheck.value) {
      return res.status(400).json({ error: issueDateCheck.ok ? 'issueDate is required.' : issueDateCheck.error });
    }
    const dueDateCheck = parseIsoDateString(b.dueDate, 'dueDate', false);
    if (!dueDateCheck.ok) return res.status(400).json({ error: dueDateCheck.error });

    // API-13: Strictly validate all monetary fields (no negatives, NaN, or Infinity)
    const taxRateCheck = parseFiniteNumber(b.taxRate, 'taxRate', { min: 0, max: 100, defaultVal: 18 });
    if (!taxRateCheck.ok) return res.status(400).json({ error: taxRateCheck.error });
    const discountRateCheck = parseFiniteNumber(b.discountRate, 'discountRate', { min: 0, max: 100, defaultVal: 0 });
    if (!discountRateCheck.ok) return res.status(400).json({ error: discountRateCheck.error });
    const discountAmountCheck = parseFiniteNumber(b.discountAmount, 'discountAmount', { min: 0, defaultVal: 0 });
    if (!discountAmountCheck.ok) return res.status(400).json({ error: discountAmountCheck.error });
    const subtotalCheck = parseFiniteNumber(b.subtotal, 'subtotal', { min: 0, defaultVal: 0 });
    if (!subtotalCheck.ok) return res.status(400).json({ error: subtotalCheck.error });
    const taxAmountCheck = parseFiniteNumber(b.taxAmount, 'taxAmount', { min: 0, defaultVal: 0 });
    if (!taxAmountCheck.ok) return res.status(400).json({ error: taxAmountCheck.error });
    const grossTotalCheck = parseFiniteNumber(b.grossTotalAmount, 'grossTotalAmount', { min: 0, defaultVal: 0 });
    if (!grossTotalCheck.ok) return res.status(400).json({ error: grossTotalCheck.error });
    const advanceDeductedCheck = parseFiniteNumber(b.advanceDeductedAmount, 'advanceDeductedAmount', {
      min: 0,
      defaultVal: 0,
    });
    if (!advanceDeductedCheck.ok) return res.status(400).json({ error: advanceDeductedCheck.error });
    const totalAmountCheck = parseFiniteNumber(b.totalAmount, 'totalAmount', { min: 0, defaultVal: 0 });
    if (!totalAmountCheck.ok) return res.status(400).json({ error: totalAmountCheck.error });
    const paidAmountCheck = parseFiniteNumber(b.paidAmount, 'paidAmount', { min: 0, defaultVal: 0 });
    if (!paidAmountCheck.ok) return res.status(400).json({ error: paidAmountCheck.error });

    const resolvedCustomerName = customer.companyName || customer.name;
    const data = {
      invoiceNumber: String(b.invoiceNumber).trim(),
      externalAccountingNumber: b.externalAccountingNumber ?? null,
      invoiceType: invoiceTypeCheck.value,
      status: statusCheck.value,
      customerId: customer.id,
      customerName: resolvedCustomerName,
      offerId: b.offerId ?? null,
      projectId: b.projectId ?? null,
      issueDate: issueDateCheck.value,
      dueDate: dueDateCheck.value,
      taxRate: taxRateCheck.value,
      discountRate: discountRateCheck.value,
      discountAmount: discountAmountCheck.value,
      subtotal: subtotalCheck.value,
      taxAmount: taxAmountCheck.value,
      grossTotalAmount: grossTotalCheck.value,
      linkedAdvanceInvoiceId: b.linkedAdvanceInvoiceId ?? null,
      linkedAdvanceInvoiceNumber: b.linkedAdvanceInvoiceNumber ?? null,
      advanceDeductedAmount: advanceDeductedCheck.value,
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
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'SALES_INVOICE_SAVED',
      entityType: 'SalesInvoice',
      entityId: saved.id,
      metadata: {
        invoiceNumber: saved.invoiceNumber,
        invoiceType: saved.invoiceType,
        totalAmount: Number(saved.totalAmount),
      },
    });
    res.json({
      ...formatSalesInvoice(saved),
      customer,
      customerName: resolvedCustomerName,
    });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/sales-invoices');
  }
});

financeRouter.delete('/sales-invoices/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    await prisma.salesInvoice.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'SALES_INVOICE_DELETED',
      entityType: 'SalesInvoice',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/sales-invoices/:id');
  }
});

// =========================================================================
// DISPATCH NOTES (ATOMIC STOCK DEDUCTION + CUSTOMER HYDRATION)
// =========================================================================

financeRouter.get('/dispatch-notes', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [rows, totalCount] = await Promise.all([
      prisma.dispatchNote.findMany({
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.dispatchNote.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    const formatted = rows.map((r) => ({ ...r, items: Array.isArray(r.items) ? r.items : [] }));
    const enriched = await attachCustomersToRows(formatted);
    res.json(enriched);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/dispatch-notes');
  }
});

financeRouter.post('/dispatch-notes', requireRole(...ROLE_GROUPS.FINANCE_SALES_WRITE), async (req, res) => {
  try {
    const b = req.body ?? {};
    if (!b?.id || !b?.dispatchNumber) {
      return res.status(400).json({ error: 'id and dispatchNumber are required.' });
    }
    if (b.items !== undefined && (!Array.isArray(b.items) || b.items.length > MAX_FINANCE_ITEMS)) {
      return res.status(400).json({ error: `items must be an array of at most ${MAX_FINANCE_ITEMS} entries.` });
    }

    // API-12: Require a real existing customerId and snapshot customerName
    if (!isUuid(b.customerId)) {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }
    const customer = await prisma.customer.findUnique({ where: { id: b.customerId } });
    if (!customer) {
      return res.status(404).json({ error: 'Referenced customer not found.' });
    }

    const statusCheck = parseEnum(b.status, DISPATCH_STATUSES, 'status', 'DRAFT');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });
    const issueDateCheck = parseIsoDateString(
      b.issueDate || new Date().toISOString().split('T')[0],
      'issueDate',
      true
    );
    if (!issueDateCheck.ok || !issueDateCheck.value) {
      return res.status(400).json({ error: issueDateCheck.ok ? 'issueDate is required.' : issueDateCheck.error });
    }

    const resolvedCustomerName = customer.companyName || customer.name;
    const itemsArr = Array.isArray(b.items) ? b.items : [];
    const wantDeductStock = Boolean(b.stockDeducted);
    const shouldAdjustStock = Boolean(b.adjustStockOnServer);

    const data = {
      dispatchNumber: String(b.dispatchNumber).trim(),
      status: statusCheck.value,
      customerId: customer.id,
      customerName: resolvedCustomerName,
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      salesInvoiceId: b.salesInvoiceId ?? null,
      issueDate: issueDateCheck.value,
      deliveryAddress: b.deliveryAddress ?? null,
      receivedBy: b.receivedBy ?? null,
      issuedBy: b.issuedBy ?? null,
      notes: b.notes ?? null,
      items: itemsArr,
      stockDeducted: wantDeductStock,
    };

    // API-10: Atomically save dispatch note and deduct stock on false -> true transition when requested
    const saved = await prisma.$transaction(async (tx) => {
      const existing = await tx.dispatchNote.findUnique({
        where: { id: String(b.id) },
        select: { stockDeducted: true },
      });

      const upserted = await tx.dispatchNote.upsert({
        where: { id: String(b.id) },
        update: data,
        create: { id: String(b.id), ...data },
      });

      if (shouldAdjustStock && wantDeductStock && !existing?.stockDeducted) {
        for (const item of itemsArr) {
          if (isUuid(item?.productId)) {
            const qty = Math.max(0, Math.round(Number(item?.quantity || 0)));
            if (qty > 0) {
              const prod = await tx.product.findUnique({
                where: { id: item.productId },
                select: { id: true, stockQuantity: true, reservedQuantity: true },
              });
              if (prod) {
                const nextStock = Math.max(0, prod.stockQuantity - qty);
                const nextReserved = Math.max(0, prod.reservedQuantity - qty);
                await tx.product.update({
                  where: { id: prod.id },
                  data: { stockQuantity: nextStock, reservedQuantity: nextReserved },
                });
              }
            }
          }
        }
      }

      return upserted;
    });

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'DISPATCH_NOTE_SAVED',
      entityType: 'DispatchNote',
      entityId: saved.id,
      metadata: { dispatchNumber: saved.dispatchNumber, status: saved.status, stockDeducted: saved.stockDeducted },
    });

    res.json({
      ...saved,
      items: Array.isArray(saved.items) ? saved.items : [],
      customer,
      customerName: resolvedCustomerName,
    });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/dispatch-notes');
  }
});

financeRouter.delete('/dispatch-notes/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    await prisma.dispatchNote.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'DISPATCH_NOTE_DELETED',
      entityType: 'DispatchNote',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/dispatch-notes/:id');
  }
});

// =========================================================================
// PAYMENTS (ATOMIC INVOICE BALANCE RECALCULATION & DELETE REVERSAL)
// =========================================================================

financeRouter.get('/payments', requireRole(...ROLE_GROUPS.FINANCE_READ), async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [rows, totalCount] = await Promise.all([
      prisma.paymentRecord.findMany({
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.paymentRecord.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
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
      return res.status(400).json({ error: 'id and paymentNumber are required.' });
    }
    const directionCheck = parseEnum(b.direction, PAYMENT_DIRECTIONS, 'direction', 'IN');
    if (!directionCheck.ok) return res.status(400).json({ error: directionCheck.error });
    const methodCheck = parseEnum(b.method, PAYMENT_METHODS, 'method', 'BANK');
    if (!methodCheck.ok) return res.status(400).json({ error: methodCheck.error });
    const dateCheck = parseIsoDateString(b.date || new Date().toISOString().split('T')[0], 'date', true);
    if (!dateCheck.ok || !dateCheck.value) {
      return res.status(400).json({ error: dateCheck.ok ? 'date is required.' : dateCheck.error });
    }
    const amountCheck = parseFiniteNumber(b.amount, 'amount', { min: 0, defaultVal: 0 });
    if (!amountCheck.ok) return res.status(400).json({ error: amountCheck.error });

    const data = {
      paymentNumber: String(b.paymentNumber).trim(),
      direction: directionCheck.value,
      amount: amountCheck.value,
      date: dateCheck.value,
      method: methodCheck.value,
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

    // API-10: Atomically upsert payment and recompute linked invoice paidAmount & status
    const saved = await prisma.$transaction(async (tx) => {
      const existing = await tx.paymentRecord.findUnique({
        where: { id: String(b.id) },
        select: { salesInvoiceId: true, purchaseInvoiceId: true },
      });

      const upserted = await tx.paymentRecord.upsert({
        where: { id: String(b.id) },
        update: data,
        create: { id: String(b.id), ...data },
      });

      // Recompute previous linked invoices if payment was reassigned
      if (existing?.salesInvoiceId && existing.salesInvoiceId !== upserted.salesInvoiceId) {
        await recomputeInvoicePaymentStateTx(tx, { salesInvoiceId: existing.salesInvoiceId });
      }
      if (existing?.purchaseInvoiceId && existing.purchaseInvoiceId !== upserted.purchaseInvoiceId) {
        await recomputeInvoicePaymentStateTx(tx, { purchaseInvoiceId: existing.purchaseInvoiceId });
      }

      // Recompute current linked invoices
      await recomputeInvoicePaymentStateTx(tx, {
        salesInvoiceId: upserted.salesInvoiceId,
        purchaseInvoiceId: upserted.purchaseInvoiceId,
      });

      return upserted;
    });

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PAYMENT_SAVED',
      entityType: 'PaymentRecord',
      entityId: saved.id,
      metadata: {
        paymentNumber: saved.paymentNumber,
        direction: saved.direction,
        amount: Number(saved.amount),
        salesInvoiceId: saved.salesInvoiceId,
        purchaseInvoiceId: saved.purchaseInvoiceId,
      },
    });
    res.json(formatPaymentRecord(saved));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/payments');
  }
});

financeRouter.delete('/payments/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);

    // API-10: Atomically delete payment AND reverse linked invoice paidAmount & status
    const deleted = await prisma.$transaction(async (tx) => {
      const removed = await tx.paymentRecord.delete({ where: { id } });
      await recomputeInvoicePaymentStateTx(tx, {
        salesInvoiceId: removed.salesInvoiceId,
        purchaseInvoiceId: removed.purchaseInvoiceId,
      });
      return removed;
    });

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PAYMENT_DELETED',
      entityType: 'PaymentRecord',
      entityId: id,
      metadata: {
        paymentNumber: deleted.paymentNumber,
        amount: Number(deleted.amount),
        salesInvoiceId: deleted.salesInvoiceId,
        purchaseInvoiceId: deleted.purchaseInvoiceId,
      },
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/payments/:id');
  }
});

// =========================================================================
// INVENTORY MOVEMENTS
// =========================================================================

financeRouter.get('/inventory-movements', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [rows, totalCount] = await Promise.all([
      prisma.inventoryMovement.findMany({
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...(page.value.isPaginated ? buildPrismaPaginationArgs(page.value) : { take: 500 }),
      }),
      page.value.isPaginated ? prisma.inventoryMovement.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
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
      return res.status(400).json({ error: 'id, kind, and detail are required.' });
    }
    const kindCheck = parseEnum(b.kind, INVENTORY_MOVE_KINDS, 'kind');
    if (!kindCheck.ok) return res.status(400).json({ error: kindCheck.error });

    let parsedQty: number | null = null;
    if (b.quantity !== undefined && b.quantity !== null && b.quantity !== '') {
      const qCheck = parseFiniteNumber(b.quantity, 'quantity', { integer: true });
      if (!qCheck.ok) return res.status(400).json({ error: qCheck.error });
      parsedQty = qCheck.value;
    }

    const data = {
      kind: kindCheck.value,
      detail: String(b.detail).slice(0, 1000),
      productId: b.productId ?? null,
      projectId: b.projectId ?? null,
      offerId: b.offerId ?? null,
      quantity: parsedQty,
      at: String(b.at || new Date().toISOString()),
    };

    const saved = await prisma.$transaction(async (tx) => {
      const upserted = await tx.inventoryMovement.upsert({
        where: { id: String(b.id) },
        update: data,
        create: { id: String(b.id), ...data },
      });

      // Optional atomic stock adjustment when client explicitly requests server-side stock delta (API-10)
      if (b.applyStockDelta && isUuid(data.productId) && parsedQty && parsedQty > 0) {
        const prod = await tx.product.findUnique({
          where: { id: data.productId },
          select: { id: true, stockQuantity: true },
        });
        if (prod) {
          const isIncoming = data.kind === 'ПРИЕМ' || data.kind === 'IN';
          const isOutgoing = data.kind === 'ИЗЛЕЗ' || data.kind === 'OUT';
          if (isIncoming) {
            await tx.product.update({
              where: { id: prod.id },
              data: { stockQuantity: prod.stockQuantity + parsedQty },
            });
          } else if (isOutgoing) {
            await tx.product.update({
              where: { id: prod.id },
              data: { stockQuantity: Math.max(0, prod.stockQuantity - parsedQty) },
            });
          }
        }
      }
      return upserted;
    });

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'INVENTORY_MOVEMENT_SAVED',
      entityType: 'InventoryMovement',
      entityId: saved.id,
      metadata: { kind: saved.kind, productId: saved.productId, quantity: saved.quantity },
    });
    res.json(saved);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/inventory-movements');
  }
});
