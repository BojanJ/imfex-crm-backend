import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { formatOfferForResponse } from '../lib/formatters';
import { SAFE_PROFILE_SELECT, AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import {
  isUuid,
  OFFER_STATUSES,
  parseEnum,
  parseOptionalDate,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const offersRouter = Router();

offersRouter.get('/', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [offers, totalCount] = await Promise.all([
      prisma.offer.findMany({
        include: {
          customer: true,
          createdByUser: { select: SAFE_PROFILE_SELECT },
          items: {
            include: {
              offerItemSpecifications: true,
            },
          },
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.offer.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(offers.map(formatOfferForResponse));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/offers');
  }
});

offersRouter.get('/:id', async (req, res) => {
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

offersRouter.post('/', requireRole(...ROLE_GROUPS.CRM_SALES_WRITE), async (req, res) => {
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

    // API-13: Validate line items (no negative prices, finite dimensions, bounded count) & compute server-side totals
    const validatedItems: Array<{
      productId: string | null;
      productModelId: string | null;
      customTitle: string;
      serviceTypes: string[];
      widthMm: number | null;
      heightMm: number | null;
      quantity: number;
      unitPrice: number;
      totalPrice: number;
      selectedAccessories: Record<string, string> | null;
      serviceEquipmentTitle: string | null;
      serviceDefectDescription: string | null;
      serviceLaborHours: number | null;
      serviceConsumedPartId: string | null;
      rawSpecs: any[];
    }> = [];

    if (items !== undefined) {
      if (!Array.isArray(items)) {
        return res.status(400).json({ error: 'items must be an array.' });
      }
      if (items.length > 200) {
        return res.status(400).json({ error: 'items exceeds maximum allowed count (200).' });
      }
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const qtyCheck = parseFiniteNumber(item?.quantity, `items[${i}].quantity`, {
          min: 1,
          max: 100000,
          defaultVal: 1,
          integer: true,
        });
        if (!qtyCheck.ok) return res.status(400).json({ error: qtyCheck.error });

        const unitPriceCheck = parseFiniteNumber(item?.unitPrice, `items[${i}].unitPrice`, {
          min: 0,
          defaultVal: 0,
        });
        if (!unitPriceCheck.ok) return res.status(400).json({ error: unitPriceCheck.error });

        let widthVal: number | null = null;
        if (item?.widthMm !== undefined && item?.widthMm !== null && item?.widthMm !== '') {
          const wCheck = parseFiniteNumber(item.widthMm, `items[${i}].widthMm`, { min: 0, max: 1000000, integer: true });
          if (!wCheck.ok) return res.status(400).json({ error: wCheck.error });
          widthVal = wCheck.value;
        }
        let heightVal: number | null = null;
        if (item?.heightMm !== undefined && item?.heightMm !== null && item?.heightMm !== '') {
          const hCheck = parseFiniteNumber(item.heightMm, `items[${i}].heightMm`, { min: 0, max: 1000000, integer: true });
          if (!hCheck.ok) return res.status(400).json({ error: hCheck.error });
          heightVal = hCheck.value;
        }

        const computedLineTotal = Math.round(unitPriceCheck.value * qtyCheck.value * 100) / 100;
        const rawSpecs = Array.isArray(item?.specifications)
          ? item.specifications
          : Array.isArray(item?.offerItemSpecifications)
          ? item.offerItemSpecifications
          : [];

        let selectedAcc: Record<string, string> | null = null;
        if (item?.selectedAccessories && typeof item.selectedAccessories === 'object' && !Array.isArray(item.selectedAccessories)) {
          const accObj: Record<string, string> = {};
          for (const [k, v] of Object.entries(item.selectedAccessories)) {
            if (typeof v === 'string' && v.trim()) {
              accObj[String(k).slice(0, 64)] = v.trim().slice(0, 128);
            }
          }
          if (Object.keys(accObj).length > 0) selectedAcc = accObj;
        }
        let serviceLaborHoursVal: number | null = null;
        const rawLaborHours = item?.serviceLaborHours ?? item?.laborHours;
        if (rawLaborHours !== undefined && rawLaborHours !== null && rawLaborHours !== '') {
          const slhCheck = parseFiniteNumber(rawLaborHours, `items[${i}].serviceLaborHours`, { min: 0, max: 10000 });
          if (!slhCheck.ok) return res.status(400).json({ error: slhCheck.error });
          serviceLaborHoursVal = slhCheck.value;
        }
        const rawDefect = item?.serviceDefectDescription ?? item?.defectDescription;
        const rawPartId = item?.serviceConsumedPartId ?? item?.consumedPartProductId;

        validatedItems.push({
          productId: isUuid(item?.productId) ? item.productId : null,
          productModelId: isUuid(item?.productModelId) ? item.productModelId : null,
          customTitle: typeof item?.customTitle === 'string' ? item.customTitle.slice(0, 500) : '',
          serviceTypes: Array.isArray(item?.serviceTypes)
            ? item.serviceTypes.filter((s: unknown): s is string => typeof s === 'string')
            : [],
          widthMm: widthVal,
          heightMm: heightVal,
          quantity: qtyCheck.value,
          unitPrice: unitPriceCheck.value,
          totalPrice: computedLineTotal,
          selectedAccessories: selectedAcc,
          serviceEquipmentTitle:
            typeof item?.serviceEquipmentTitle === 'string' && item.serviceEquipmentTitle.trim()
              ? item.serviceEquipmentTitle.trim().slice(0, 500)
              : null,
          serviceDefectDescription:
            typeof rawDefect === 'string' && rawDefect.trim()
              ? rawDefect.trim().slice(0, 2000)
              : null,
          serviceLaborHours: serviceLaborHoursVal,
          serviceConsumedPartId: isUuid(rawPartId) ? rawPartId : null,
          rawSpecs,
        });
      }
    }

    const hasItemsPayload = Array.isArray(items);
    const computedSubtotal = hasItemsPayload
      ? Math.round(validatedItems.reduce((sum, it) => sum + it.totalPrice, 0) * 100) / 100
      : subtotalCheck.value;
    const computedDiscountAmount = hasItemsPayload
      ? Math.round(((computedSubtotal * discountRateCheck.value) / 100) * 100) / 100
      : discountAmountCheck.value;
    const taxableSubtotal = Math.max(0, Math.round((computedSubtotal - computedDiscountAmount) * 100) / 100);
    const computedTaxAmount = hasItemsPayload
      ? Math.round(((taxableSubtotal * taxRateCheck.value) / 100) * 100) / 100
      : taxAmountCheck.value;
    const computedTotalAmount = hasItemsPayload
      ? Math.round((taxableSubtotal + computedTaxAmount) * 100) / 100
      : totalAmountCheck.value;

    let validUserId: string | null = null;
    if (isUuid(createdByUserId)) {
      const userExists = await prisma.profile.findUnique({ where: { id: createdByUserId }, select: { id: true } });
      if (userExists) validUserId = userExists.id;
    }

    // API-02 + API-13: Wrap offer upsert + item replacement + specification snapshots in a single transaction
    // Only update when matching by existing UUID; reject duplicate offerNumber with 409 Conflict
    const txResult = await prisma.$transaction(
      async (tx) => {
        const existingOffer = isUuid(id) ? await tx.offer.findUnique({ where: { id } }) : null;

        let offer;
        if (existingOffer) {
          const effTaxRate =
            taxRate !== undefined && taxRate !== null && taxRate !== '' ? taxRateCheck.value : Number(existingOffer.taxRate);
          const effDiscountRate =
            discountRate !== undefined && discountRate !== null && discountRate !== ''
              ? discountRateCheck.value
              : Number(existingOffer.discountRate);
          const nextSubtotal = hasItemsPayload
            ? computedSubtotal
            : subtotal !== undefined && subtotal !== null && subtotal !== ''
            ? subtotalCheck.value
            : Number(existingOffer.subtotal);
          const nextDiscount = hasItemsPayload
            ? Math.round(((nextSubtotal * effDiscountRate) / 100) * 100) / 100
            : discountAmount !== undefined && discountAmount !== null && discountAmount !== ''
            ? discountAmountCheck.value
            : Number(existingOffer.discountAmount);
          const nextTaxable = Math.max(0, Math.round((nextSubtotal - nextDiscount) * 100) / 100);
          const nextTax = hasItemsPayload
            ? Math.round(((nextTaxable * effTaxRate) / 100) * 100) / 100
            : taxAmount !== undefined && taxAmount !== null && taxAmount !== ''
            ? taxAmountCheck.value
            : Number(existingOffer.taxAmount);
          const nextTotal = hasItemsPayload
            ? Math.round((nextTaxable + nextTax) * 100) / 100
            : totalAmount !== undefined && totalAmount !== null && totalAmount !== ''
            ? totalAmountCheck.value
            : Number(existingOffer.totalAmount);

          offer = await tx.offer.update({
            where: { id: existingOffer.id },
            data: {
              customerId,
              createdByUserId: validUserId ?? existingOffer.createdByUserId,
              status: status !== undefined ? statusCheck.value : existingOffer.status,
              taxRate: effTaxRate,
              discountRate: effDiscountRate,
              discountAmount: nextDiscount,
              subtotal: nextSubtotal,
              taxAmount: nextTax,
              totalAmount: nextTotal,
              ...(validUntil !== undefined ? { validUntil: validUntilCheck.value ?? null } : {}),
            },
          });
        } else {
          let uniqueOfferNumber = offerNumber ? String(offerNumber).trim() : '';
          if (uniqueOfferNumber) {
            const duplicate = await tx.offer.findUnique({
              where: { offerNumber: uniqueOfferNumber },
              select: { id: true },
            });
            if (duplicate) {
              return { conflict: `An offer with number "${uniqueOfferNumber}" already exists.` as const };
            }
          } else {
            const count = await tx.offer.count();
            uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${String(count + 1).padStart(4, '0')}`;
            let conflict = await tx.offer.findUnique({ where: { offerNumber: uniqueOfferNumber }, select: { id: true } });
            let attempts = 0;
            while (conflict && attempts < 10) {
              attempts++;
              const rand = Math.floor(1000 + Math.random() * 9000);
              uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${rand}`;
              conflict = await tx.offer.findUnique({ where: { offerNumber: uniqueOfferNumber }, select: { id: true } });
            }
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
              discountAmount: computedDiscountAmount,
              subtotal: computedSubtotal,
              taxAmount: computedTaxAmount,
              totalAmount: computedTotalAmount,
              validUntil: validUntilCheck.value ?? null,
            },
          });
        }

        if (hasItemsPayload) {
          const keyIds = new Set<string>();
          const optIds = new Set<string>();
          for (const item of validatedItems) {
            for (const spec of item.rawSpecs) {
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

          for (const item of validatedItems) {
            const createdItem = await tx.offerItem.create({
              data: {
                offerId: offer.id,
                productId: item.productId,
                productModelId: item.productModelId,
                customTitle: item.customTitle,
                serviceTypes: item.serviceTypes,
                widthMm: item.widthMm,
                heightMm: item.heightMm,
                quantity: item.quantity,
                unitPrice: item.unitPrice,
                totalPrice: item.totalPrice,
                selectedAccessories: item.selectedAccessories ?? undefined,
                serviceEquipmentTitle: item.serviceEquipmentTitle,
                serviceDefectDescription: item.serviceDefectDescription,
                serviceLaborHours: item.serviceLaborHours,
                serviceConsumedPartId: item.serviceConsumedPartId,
              },
            });

            const specRows: any[] = [];
            for (const spec of item.rawSpecs) {
              if (isUuid(spec?.specificationKeyId) && specKeyMap.has(spec.specificationKeyId)) {
                const keyInfo = specKeyMap.get(spec.specificationKeyId)!;
                const optInfo = isUuid(spec?.specificationOptionId) ? specOptMap.get(spec.specificationOptionId) : undefined;
                specRows.push({
                  offerItemId: createdItem.id,
                  specificationKeyId: keyInfo.id,
                  specificationOptionId: optInfo ? optInfo.id : null,
                  customValue: spec.customValue || optInfo?.label || null,
                  customKeyName: spec.customKeyName || keyInfo.name,
                  // API-18: Keep customPriceModifier at 0 on standard catalog options so priceModifier is never double-counted
                  customPriceModifier: optInfo
                    ? 0
                    : Number.isFinite(Number(spec.customPriceModifier))
                    ? Number(spec.customPriceModifier)
                    : 0,
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

        const loaded = await tx.offer.findUnique({
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
        return { offer: loaded };
      },
      { timeout: 20000 }
    );

    if ('conflict' in txResult && txResult.conflict) {
      return res.status(409).json({ error: txResult.conflict });
    }
    const fullOffer = txResult.offer;

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'OFFER_SAVED',
      entityType: 'Offer',
      entityId: fullOffer?.id,
      metadata: { offerNumber: fullOffer?.offerNumber, status: fullOffer?.status },
    });
    res.json(formatOfferForResponse(fullOffer));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/offers');
  }
});

offersRouter.delete('/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid offer ID format.' });
    }
    await prisma.offer.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, { action: 'OFFER_DELETED', entityType: 'Offer', entityId: id });
    res.json({ success: true, id });
  } catch (error: any) {
    if (error?.code === 'P2003') {
      return res.status(409).json({ error: 'Cannot delete offer because a linked project exists.' });
    }
    return handleRouteError(res, error, 'DELETE /api/offers/:id');
  }
});
