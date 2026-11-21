import { formatDocumentForList } from '../storage';

export const formatProductForResponse = (p: any) => {
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

export const formatOfferForResponse = (offer: any) => {
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

export const extractWorkflowData = (body: any) => {
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

export const formatProjectForResponse = (project: any, includeDocumentData = false) => {
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

export const formatTicketForResponse = (ticket: any) => {
  if (!ticket) return ticket;
  return {
    ...ticket,
    laborHours: Number(ticket.laborHours ?? 0),
  };
};

export const formatPurchaseInvoice = (inv: any) => ({
  ...inv,
  taxRate: Number(inv.taxRate ?? 18),
  subtotal: Number(inv.subtotal ?? 0),
  taxAmount: Number(inv.taxAmount ?? 0),
  totalAmount: Number(inv.totalAmount ?? 0),
  paidAmount: Number(inv.paidAmount ?? 0),
  items: Array.isArray(inv.items) ? inv.items : [],
});

export const formatSalesInvoice = (inv: any) => ({
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

export const formatPaymentRecord = (p: any) => ({
  ...p,
  amount: Number(p.amount ?? 0),
});
