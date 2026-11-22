import { formatDocumentForList } from '../storage';

export const formatProductForResponse = (p: any) => {
  if (!p) return p;
  return {
    ...p,
    stockType: p.stockType || 'STOCK',
    stockQuantity: Number(p.stockQuantity ?? 0),
    reservedQuantity: Number(p.reservedQuantity ?? 0),
    minStockLevel: Number(p.minStockLevel ?? 3),
    primarySupplierId: p.primarySupplierId || null,
    barcode: p.barcode || null,
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
  const formatted: Record<string, any> = {
    ...offer,
    taxRate: Number(offer.taxRate ?? 0),
    discountRate: Number(offer.discountRate ?? 0),
    discountAmount: Number(offer.discountAmount ?? 0),
    subtotal: Number(offer.subtotal ?? 0),
    taxAmount: Number(offer.taxAmount ?? 0),
    totalAmount: Number(offer.totalAmount ?? 0),
  };

  // API-18: Only include `items` when explicitly loaded; avoid wiping items to [] on nested relations
  if (Array.isArray(offer.items)) {
    formatted.items = offer.items.map((item: any) => {
      const { offerItemSpecifications: rawOfferItemSpecs, ...restItem } = item;
      const rawSpecs = rawOfferItemSpecs || item.specifications || [];
      return {
        ...restItem,
        quantity: Number(item.quantity ?? 1),
        unitPrice: Number(item.unitPrice ?? 0),
        totalPrice: Number(item.totalPrice ?? 0),
        selectedAccessories:
          item.selectedAccessories && typeof item.selectedAccessories === 'object'
            ? item.selectedAccessories
            : undefined,
        serviceEquipmentTitle: item.serviceEquipmentTitle || undefined,
        serviceDefectDescription: item.serviceDefectDescription || undefined,
        defectDescription: item.serviceDefectDescription || undefined,
        serviceLaborHours:
          item.serviceLaborHours !== undefined && item.serviceLaborHours !== null
            ? Number(item.serviceLaborHours)
            : undefined,
        laborHours:
          item.serviceLaborHours !== undefined && item.serviceLaborHours !== null
            ? Number(item.serviceLaborHours)
            : undefined,
        serviceConsumedPartId: item.serviceConsumedPartId || undefined,
        consumedPartProductId: item.serviceConsumedPartId || undefined,
        specifications: rawSpecs.map((s: any) => ({
          specificationKeyId: s.specificationKeyId || `custom-${s.id}`,
          specificationOptionId: s.specificationOptionId || undefined,
          customValue: s.customValue || undefined,
          customKeyName: s.customKeyName || undefined,
          // Only expose customPriceModifier on custom specs (not standard catalog options) to prevent double-counting
          customPriceModifier:
            !s.specificationOptionId && s.customPriceModifier !== undefined && s.customPriceModifier !== null
              ? Number(s.customPriceModifier)
              : undefined,
        })),
      };
    });
  }

  return formatted;
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
  exchangeRate: inv.exchangeRate !== undefined && inv.exchangeRate !== null ? Number(inv.exchangeRate) : undefined,
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
  exchangeRate: inv.exchangeRate !== undefined && inv.exchangeRate !== null ? Number(inv.exchangeRate) : undefined,
  items: Array.isArray(inv.items) ? inv.items : [],
});

export const formatPaymentRecord = (p: any) => ({
  ...p,
  amount: Number(p.amount ?? 0),
});
