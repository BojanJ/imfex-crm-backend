import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { formatProductForResponse } from '../lib/formatters';
import { AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import {
  isUuid,
  SPEC_INPUT_TYPES,
  parseEnum,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const catalogRouter = Router();

// Categories API
catalogRouter.get('/categories', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [categories, totalCount] = await Promise.all([
      prisma.productCategory.findMany({
        include: { children: true },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.productCategory.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(categories);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/categories');
  }
});

catalogRouter.post('/categories', requireRole(...ROLE_GROUPS.CATALOG_WRITE), async (req, res) => {
  try {
    const { id, name, parentId } = req.body ?? {};
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanName) {
      return res.status(400).json({ error: 'Category name is required.' });
    }
    if (parentId !== undefined && parentId !== null && parentId !== '' && !isUuid(parentId)) {
      return res.status(400).json({ error: 'Invalid parentId UUID format.' });
    }
    const cleanParentId = isUuid(parentId) ? parentId : null;

    // API-19: Prevent self-parenting and ancestor cycles in category tree
    if (isUuid(id) && cleanParentId) {
      if (cleanParentId === id) {
        return res.status(400).json({ error: 'A category cannot be its own parent.' });
      }
      let cursor: string | null = cleanParentId;
      const visited = new Set<string>([id]);
      let depth = 0;
      while (cursor && depth < 32) {
        if (visited.has(cursor)) {
          return res.status(400).json({ error: 'Category hierarchy cannot contain cycles.' });
        }
        visited.add(cursor);
        const parentRow: { parentId: string | null } | null = await prisma.productCategory.findUnique({
          where: { id: cursor },
          select: { parentId: true },
        });
        cursor = parentRow?.parentId ?? null;
        depth++;
      }
    }

    let category;
    if (isUuid(id)) {
      category = await prisma.productCategory.upsert({
        where: { id },
        update: { name: cleanName, parentId: cleanParentId },
        create: { id, name: cleanName, parentId: cleanParentId },
      });
    } else {
      category = await prisma.productCategory.create({
        data: { name: cleanName, parentId: cleanParentId },
      });
    }
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'CATEGORY_SAVED',
      entityType: 'ProductCategory',
      entityId: category.id,
      metadata: { name: category.name },
    });
    res.json(category);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/categories');
  }
});

catalogRouter.delete('/categories/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid category ID format.' });
    }
    await prisma.productCategory.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'CATEGORY_DELETED',
      entityType: 'ProductCategory',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/categories/:id');
  }
});

// Products API
catalogRouter.get('/products', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [products, totalCount] = await Promise.all([
      prisma.product.findMany({
        include: {
          category: true,
          models: true,
          specificationKeys: {
            include: {
              options: true,
            },
          },
        },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.product.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(products.map(formatProductForResponse));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/products');
  }
});

catalogRouter.get('/products/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid product ID format.' });
    }
    const product = await prisma.product.findUnique({
      where: { id },
      include: {
        category: true,
        models: true,
        specificationKeys: {
          include: {
            options: true,
          },
        },
      },
    });
    if (!product) return res.status(404).json({ error: 'Product not found.' });
    res.json(formatProductForResponse(product));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/products/:id');
  }
});

catalogRouter.post('/products', requireRole(...ROLE_GROUPS.CATALOG_WRITE), async (req, res) => {
  try {
    const {
      id,
      name,
      code,
      description,
      isActive,
      stockType,
      stockQuantity,
      reservedQuantity,
      minStockLevel,
      primarySupplierId,
      barcode,
      purchasePrice,
      models,
      specificationKeys,
      categoryId,
    } = req.body ?? {};

    const cleanCode = typeof code === 'string' ? code.trim() : '';
    const cleanName = typeof name === 'string' ? name.trim() : '';
    if (!cleanCode) {
      return res.status(400).json({ error: 'Product code is required.' });
    }
    if (!cleanName) {
      return res.status(400).json({ error: 'Product name is required.' });
    }
    if (categoryId !== undefined && categoryId !== null && categoryId !== '' && !isUuid(categoryId)) {
      return res.status(400).json({ error: 'Invalid categoryId UUID format.' });
    }
    const cleanCategoryId = isUuid(categoryId) ? categoryId : null;

    const stockQtyCheck =
      stockQuantity !== undefined
        ? parseFiniteNumber(stockQuantity, 'stockQuantity', { min: 0, integer: true })
        : null;
    if (stockQtyCheck && !stockQtyCheck.ok) return res.status(400).json({ error: stockQtyCheck.error });

    const reservedQtyCheck =
      reservedQuantity !== undefined
        ? parseFiniteNumber(reservedQuantity, 'reservedQuantity', { min: 0, integer: true })
        : null;
    if (reservedQtyCheck && !reservedQtyCheck.ok) return res.status(400).json({ error: reservedQtyCheck.error });

    const purchasePriceCheck =
      purchasePrice !== undefined
        ? parseFiniteNumber(purchasePrice, 'purchasePrice', { min: 0 })
        : null;
    if (purchasePriceCheck && !purchasePriceCheck.ok) return res.status(400).json({ error: purchasePriceCheck.error });

    if (models !== undefined) {
      if (!Array.isArray(models) || models.length > 100) {
        return res.status(400).json({ error: 'models must be an array of at most 100 items.' });
      }
      for (let i = 0; i < models.length; i++) {
        if (models[i]?.basePrice !== undefined && models[i]?.basePrice !== null && models[i]?.basePrice !== '') {
          const bpCheck = parseFiniteNumber(models[i].basePrice, `models[${i}].basePrice`, { min: 0 });
          if (!bpCheck.ok) return res.status(400).json({ error: bpCheck.error });
        }
      }
    }

    if (Array.isArray(specificationKeys)) {
      if (specificationKeys.length > 100) {
        return res.status(400).json({ error: 'specificationKeys exceeds maximum allowed count (100).' });
      }
      for (const sk of specificationKeys) {
        if (sk?.inputType !== undefined) {
          const check = parseEnum(sk.inputType, SPEC_INPUT_TYPES, 'specificationKey.inputType');
          if (!check.ok) return res.status(400).json({ error: check.error });
        }
      }
    }

    const minStockCheck =
      minStockLevel !== undefined && minStockLevel !== null && minStockLevel !== ''
        ? parseFiniteNumber(minStockLevel, 'minStockLevel', { min: 0, max: 100000, integer: true })
        : null;
    if (minStockCheck && !minStockCheck.ok) return res.status(400).json({ error: minStockCheck.error });

    const stockFields = {
      ...(stockType !== undefined ? { stockType: String(stockType) } : {}),
      ...(stockQtyCheck?.ok ? { stockQuantity: stockQtyCheck.value } : {}),
      ...(reservedQtyCheck?.ok ? { reservedQuantity: reservedQtyCheck.value } : {}),
      ...(minStockCheck?.ok ? { minStockLevel: minStockCheck.value } : {}),
      ...(primarySupplierId !== undefined
        ? { primarySupplierId: typeof primarySupplierId === 'string' && primarySupplierId.trim() ? primarySupplierId.trim() : null }
        : {}),
      ...(barcode !== undefined
        ? { barcode: typeof barcode === 'string' && barcode.trim() ? barcode.trim().slice(0, 128) : null }
        : {}),
      ...(purchasePriceCheck?.ok ? { purchasePrice: purchasePriceCheck.value } : {}),
    };

    const txResult = await prisma.$transaction(
      async (tx) => {
        // API-13: Only update when matching by existing UUID; reject duplicate SKU code with 409 Conflict
        let product;
        if (isUuid(id)) {
          product = await tx.product.upsert({
            where: { id },
            update: {
              name: cleanName,
              code: cleanCode,
              description: description ?? null,
              isActive: isActive !== undefined ? Boolean(isActive) : true,
              categoryId: cleanCategoryId,
              ...stockFields,
            },
            create: {
              id,
              name: cleanName,
              code: cleanCode,
              description: description ?? null,
              isActive: isActive !== undefined ? Boolean(isActive) : true,
              categoryId: cleanCategoryId,
              ...stockFields,
            },
          });
        } else {
          const duplicate = await tx.product.findUnique({ where: { code: cleanCode }, select: { id: true } });
          if (duplicate) {
            return { conflict: `Product with code "${cleanCode}" already exists.` as const };
          }
          product = await tx.product.create({
            data: {
              name: cleanName,
              code: cleanCode,
              description: description ?? null,
              isActive: isActive !== undefined ? Boolean(isActive) : true,
              categoryId: cleanCategoryId,
              ...stockFields,
            },
          });
        }

        if (Array.isArray(models)) {
          const existingModels = await tx.productModel.findMany({ where: { productId: product.id } });
          const byId = new Map(existingModels.map((m) => [m.id, m]));
          const byName = new Map(existingModels.map((m) => [m.name, m]));
          const keptModelIds: string[] = [];

          for (const m of models) {
            if (!m?.name) continue;
            const existingModel = (isUuid(m.id) ? byId.get(m.id) : undefined) || byName.get(m.name);
            const price = m.basePrice !== undefined ? Number(m.basePrice) : undefined;
            if (existingModel) {
              const updatedMod = await tx.productModel.update({
                where: { id: existingModel.id },
                data: {
                  name: m.name,
                  basePrice: price !== undefined && Number.isFinite(price) ? price : existingModel.basePrice,
                },
              });
              keptModelIds.push(updatedMod.id);
            } else {
              const createdMod = await tx.productModel.create({
                data: {
                  productId: product.id,
                  name: m.name,
                  basePrice: price !== undefined && Number.isFinite(price) ? price : 0,
                },
              });
              keptModelIds.push(createdMod.id);
            }
          }

          await tx.productModel.deleteMany({
            where: {
              productId: product.id,
              id: { notIn: keptModelIds },
            },
          });
        }

        if (Array.isArray(specificationKeys)) {
          const existingKeys = await tx.specificationKey.findMany({
            where: { productId: product.id },
            include: { options: true },
          });
          const keyById = new Map(existingKeys.map((k) => [k.id, k]));
          const keyByName = new Map(existingKeys.map((k) => [k.name, k]));
          const keptKeyIds: string[] = [];

          for (const sk of specificationKeys) {
            if (!sk?.name) continue;
            const existingKey = (isUuid(sk.id) ? keyById.get(sk.id) : undefined) || keyByName.get(sk.name);

            const specKey = existingKey
              ? await tx.specificationKey.update({
                  where: { id: existingKey.id },
                  data: {
                    name: sk.name,
                    inputType: sk.inputType || existingKey.inputType,
                    defaultValue: sk.defaultValue !== undefined ? sk.defaultValue || null : existingKey.defaultValue,
                  },
                })
              : await tx.specificationKey.create({
                  data: {
                    productId: product.id,
                    name: sk.name,
                    inputType: sk.inputType || 'SELECT',
                    defaultValue: sk.defaultValue || null,
                  },
                });
            keptKeyIds.push(specKey.id);

            if (Array.isArray(sk.options)) {
              const existingOpts = existingKey?.options || [];
              const optById = new Map(existingOpts.map((o) => [o.id, o]));
              const optByLabel = new Map(existingOpts.map((o) => [o.label, o]));
              const keptOptIds: string[] = [];

              for (const opt of sk.options) {
                if (!opt?.label) continue;
                const existingOpt = (isUuid(opt.id) ? optById.get(opt.id) : undefined) || optByLabel.get(opt.label);
                const modifier = opt.priceModifier !== undefined ? Number(opt.priceModifier) : undefined;

                if (existingOpt) {
                  const updatedOpt = await tx.specificationOption.update({
                    where: { id: existingOpt.id },
                    data: {
                      label: opt.label,
                      priceModifier: modifier !== undefined && Number.isFinite(modifier) ? modifier : existingOpt.priceModifier,
                      isDefault: opt.isDefault !== undefined ? Boolean(opt.isDefault) : existingOpt.isDefault,
                    },
                  });
                  keptOptIds.push(updatedOpt.id);
                } else {
                  const createdOpt = await tx.specificationOption.create({
                    data: {
                      specificationKeyId: specKey.id,
                      label: opt.label,
                      priceModifier: modifier !== undefined && Number.isFinite(modifier) ? modifier : 0,
                      isDefault: Boolean(opt.isDefault),
                    },
                  });
                  keptOptIds.push(createdOpt.id);
                }
              }

              await tx.specificationOption.deleteMany({
                where: {
                  specificationKeyId: specKey.id,
                  id: { notIn: keptOptIds },
                },
              });
            }
          }

          await tx.specificationKey.deleteMany({
            where: {
              productId: product.id,
              id: { notIn: keptKeyIds },
            },
          });
        }

        const loaded = await tx.product.findUnique({
          where: { id: product.id },
          include: { category: true, models: true, specificationKeys: { include: { options: true } } },
        });
        return { product: loaded };
      },
      { timeout: 20000 }
    );

    if ('conflict' in txResult && txResult.conflict) {
      return res.status(409).json({ error: txResult.conflict });
    }
    const updatedProduct = txResult.product;
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PRODUCT_SAVED',
      entityType: 'Product',
      entityId: updatedProduct?.id,
      metadata: { code: updatedProduct?.code, name: updatedProduct?.name },
    });
    res.json(formatProductForResponse(updatedProduct));
  } catch (error: any) {
    if (error?.code === 'P2002') {
      return res.status(409).json({ error: 'Product with this code already exists.' });
    }
    return handleRouteError(res, error, 'POST /api/products');
  }
});

catalogRouter.delete('/products/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid product ID format.' });
    }
    await prisma.product.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PRODUCT_DELETED',
      entityType: 'Product',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/products/:id');
  }
});
