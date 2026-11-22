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

    const offers = await prisma.offer.findMany({
      include: {
        customer: true,
        createdByUser: { select: SAFE_PROFILE_SELECT },
        items: {
          include: {
            offerItemSpecifications: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.offer.count()));
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

    let validUserId: string | null = null;
    if (isUuid(createdByUserId)) {
      const userExists = await prisma.profile.findUnique({ where: { id: createdByUserId }, select: { id: true } });
      if (userExists) validUserId = userExists.id;
    }

    // API-02: Wrap offer upsert + item replacement + specification snapshots in a single transaction
    const fullOffer = await prisma.$transaction(
      async (tx) => {
        let existingOffer = null;
        if (isUuid(id)) {
          existingOffer = await tx.offer.findUnique({ where: { id } });
        }
        if (!existingOffer && offerNumber) {
          existingOffer = await tx.offer.findUnique({ where: { offerNumber: String(offerNumber) } });
        }

        let offer;
        if (existingOffer) {
          offer = await tx.offer.update({
            where: { id: existingOffer.id },
            data: {
              customerId,
              createdByUserId: validUserId ?? existingOffer.createdByUserId,
              status: status !== undefined ? statusCheck.value : existingOffer.status,
              taxRate: taxRate !== undefined && taxRate !== null && taxRate !== '' ? taxRateCheck.value : existingOffer.taxRate,
              discountRate:
                discountRate !== undefined && discountRate !== null && discountRate !== ''
                  ? discountRateCheck.value
                  : existingOffer.discountRate,
              discountAmount:
                discountAmount !== undefined && discountAmount !== null && discountAmount !== ''
                  ? discountAmountCheck.value
                  : existingOffer.discountAmount,
              subtotal: subtotal !== undefined && subtotal !== null && subtotal !== '' ? subtotalCheck.value : existingOffer.subtotal,
              taxAmount:
                taxAmount !== undefined && taxAmount !== null && taxAmount !== '' ? taxAmountCheck.value : existingOffer.taxAmount,
              totalAmount:
                totalAmount !== undefined && totalAmount !== null && totalAmount !== ''
                  ? totalAmountCheck.value
                  : existingOffer.totalAmount,
              ...(validUntil !== undefined ? { validUntil: validUntilCheck.value ?? null } : {}),
            },
          });
        } else {
          let uniqueOfferNumber = offerNumber ? String(offerNumber).trim() : '';
          if (!uniqueOfferNumber) {
            const count = await tx.offer.count();
            uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${String(count + 1).padStart(4, '0')}`;
          }

          let conflict = await tx.offer.findUnique({ where: { offerNumber: uniqueOfferNumber }, select: { id: true } });
          let attempts = 0;
          while (conflict && attempts < 10) {
            attempts++;
            const rand = Math.floor(1000 + Math.random() * 9000);
            uniqueOfferNumber = `OFF-${new Date().getFullYear()}-${rand}`;
            conflict = await tx.offer.findUnique({ where: { offerNumber: uniqueOfferNumber }, select: { id: true } });
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
              discountAmount: discountAmountCheck.value,
              subtotal: subtotalCheck.value,
              taxAmount: taxAmountCheck.value,
              totalAmount: totalAmountCheck.value,
              validUntil: validUntilCheck.value ?? null,
            },
          });
        }

        if (Array.isArray(items)) {
          const keyIds = new Set<string>();
          const optIds = new Set<string>();
          for (const item of items) {
            const rawSpecs = Array.isArray(item?.specifications)
              ? item.specifications
              : Array.isArray(item?.offerItemSpecifications)
              ? item.offerItemSpecifications
              : [];
            for (const spec of rawSpecs) {
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

          for (const item of items) {
            const createdItem = await tx.offerItem.create({
              data: {
                offerId: offer.id,
                productId: isUuid(item?.productId) ? item.productId : null,
                productModelId: isUuid(item?.productModelId) ? item.productModelId : null,
                customTitle: item?.customTitle || '',
                serviceTypes: Array.isArray(item?.serviceTypes) ? item.serviceTypes : [],
                widthMm:
                  item?.widthMm !== undefined && item?.widthMm !== null && item?.widthMm !== ''
                    ? Math.round(Number(item.widthMm))
                    : null,
                heightMm:
                  item?.heightMm !== undefined && item?.heightMm !== null && item?.heightMm !== ''
                    ? Math.round(Number(item.heightMm))
                    : null,
                quantity: Math.max(1, Math.round(Number(item?.quantity ?? 1) || 1)),
                unitPrice: Number.isFinite(Number(item?.unitPrice)) ? Number(item.unitPrice) : 0,
                totalPrice: Number.isFinite(Number(item?.totalPrice)) ? Number(item.totalPrice) : 0,
              },
            });

            const rawSpecs = Array.isArray(item?.specifications)
              ? item.specifications
              : Array.isArray(item?.offerItemSpecifications)
              ? item.offerItemSpecifications
              : [];

            const specRows: any[] = [];
            for (const spec of rawSpecs) {
              if (isUuid(spec?.specificationKeyId) && specKeyMap.has(spec.specificationKeyId)) {
                const keyInfo = specKeyMap.get(spec.specificationKeyId)!;
                const optInfo = isUuid(spec?.specificationOptionId) ? specOptMap.get(spec.specificationOptionId) : undefined;
                specRows.push({
                  offerItemId: createdItem.id,
                  specificationKeyId: keyInfo.id,
                  specificationOptionId: optInfo ? optInfo.id : null,
                  customValue: spec.customValue || optInfo?.label || null,
                  customKeyName: spec.customKeyName || keyInfo.name,
                  customPriceModifier: Number.isFinite(Number(spec.customPriceModifier)) ? Number(spec.customPriceModifier) : 0,
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

        return tx.offer.findUnique({
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
      },
      { timeout: 20000 }
    );

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
