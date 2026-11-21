import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { formatProductForResponse } from '../lib/formatters';
import {
  isUuid,
  SPEC_INPUT_TYPES,
  parseEnum,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';

export const catalogRouter = Router();

// Categories API
catalogRouter.get('/categories', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const categories = await prisma.productCategory.findMany({
      include: { children: true },
      orderBy: { createdAt: 'asc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.productCategory.count()));
    }
    res.json(categories);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/categories');
  }
});

catalogRouter.post('/categories', async (req, res) => {
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
    res.json(category);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/categories');
  }
});

catalogRouter.delete('/categories/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid category ID format.' });
    }
    await prisma.productCategory.delete({ where: { id } });
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

    const products = await prisma.product.findMany({
      include: {
        category: true,
        models: true,
        specificationKeys: {
          include: {
            options: true,
          },
        },
      },
      orderBy: { createdAt: 'asc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.product.count()));
    }
    res.json(products.map(formatProductForResponse));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/products');
  }
});

catalogRouter.post('/products', async (req, res) => {
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

    if (Array.isArray(specificationKeys)) {
      for (const sk of specificationKeys) {
        if (sk?.inputType !== undefined) {
          const check = parseEnum(sk.inputType, SPEC_INPUT_TYPES, 'specificationKey.inputType');
          if (!check.ok) return res.status(400).json({ error: check.error });
        }
      }
    }

    const stockFields = {
      ...(stockType !== undefined ? { stockType: String(stockType) } : {}),
      ...(stockQtyCheck?.ok ? { stockQuantity: stockQtyCheck.value } : {}),
      ...(reservedQtyCheck?.ok ? { reservedQuantity: reservedQtyCheck.value } : {}),
      ...(purchasePriceCheck?.ok ? { purchasePrice: purchasePriceCheck.value } : {}),
    };

    const updatedProduct = await prisma.$transaction(
      async (tx) => {
        const product = isUuid(id)
          ? await tx.product.upsert({
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
            })
          : await tx.product.upsert({
              where: { code: cleanCode },
              update: {
                name: cleanName,
                description: description ?? null,
                isActive: isActive !== undefined ? Boolean(isActive) : true,
                categoryId: cleanCategoryId,
                ...stockFields,
              },
              create: {
                name: cleanName,
                code: cleanCode,
                description: description ?? null,
                isActive: isActive !== undefined ? Boolean(isActive) : true,
                categoryId: cleanCategoryId,
                ...stockFields,
              },
            });

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

        return tx.product.findUnique({
          where: { id: product.id },
          include: { category: true, models: true, specificationKeys: { include: { options: true } } },
        });
      },
      { timeout: 20000 }
    );

    res.json(formatProductForResponse(updatedProduct));
  } catch (error: any) {
    if (error?.code === 'P2002') {
      return res.status(409).json({ error: 'Product with this code already exists.' });
    }
    return handleRouteError(res, error, 'POST /api/products');
  }
});

catalogRouter.delete('/products/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid product ID format.' });
    }
    await prisma.product.delete({ where: { id } });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/products/:id');
  }
});
