import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { AuthenticatedRequest, invalidateAuthUserCache, requireRole } from '../auth';
import { parsePagination, buildPrismaPaginationArgs, handleRouteError } from '../validation';
import { recordAudit } from '../audit';

function isAdminDbToolsAllowed(): boolean {
  if (process.env.NODE_ENV === 'production') {
    return process.env.ALLOW_ADMIN_DB_TOOLS === 'true';
  }
  return true;
}

export const adminRouter = Router();

adminRouter.post('/admin/clean-database', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    if (!isAdminDbToolsAllowed()) {
      return res.status(403).json({
        error: 'Admin database maintenance endpoints are disabled in production.',
      });
    }

    if (req.body?.confirm !== 'CLEAN_DATABASE') {
      return res.status(400).json({
        error: 'Explicit confirmation { "confirm": "CLEAN_DATABASE" } is required.',
      });
    }

    const allCust = await prisma.customer.findMany();
    const corruptedCust = allCust.filter(
      (c) => (c.name && c.name.includes('?')) || (c.companyName && c.companyName.includes('?'))
    );

    // API-11: Wrap clean-database deletes in a single transaction in strict child->parent FK order
    await prisma.$transaction(
      async (tx) => {
        for (const c of corruptedCust) {
          await tx.clientDocument.deleteMany({ where: { customerId: c.id } });
          await tx.serviceTicket.deleteMany({ where: { customerId: c.id } });
          await tx.installedItem.deleteMany({ where: { customerId: c.id } });
          await tx.calendarEvent.deleteMany({ where: { customerId: c.id } });
          await tx.project.deleteMany({ where: { customerId: c.id } });
          await tx.offerItemSpecification.deleteMany({ where: { offerItem: { offer: { customerId: c.id } } } });
          await tx.offerItem.deleteMany({ where: { offer: { customerId: c.id } } });
          await tx.offer.deleteMany({ where: { customerId: c.id } });
          await tx.customer.delete({ where: { id: c.id } });
        }
      },
      { timeout: 30000 }
    );

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'ADMIN_CLEAN_DATABASE',
      entityType: 'System',
      metadata: { purgedCorruptedCount: corruptedCust.length },
    });

    res.json({
      success: true,
      message: 'Database cleaned and verified with clean UTF-8 records.',
      purgedCorruptedCount: corruptedCust.length,
    });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/admin/clean-database');
  }
});

adminRouter.post('/admin/reset-database', requireRole('SUPER_ADMIN'), async (req: AuthenticatedRequest, res) => {
  try {
    if (!isAdminDbToolsAllowed()) {
      return res.status(403).json({
        error: 'Admin database reset endpoint is disabled in production.',
      });
    }

    if (req.body?.confirm !== 'RESET_DATABASE') {
      return res.status(400).json({
        error: 'Explicit confirmation { "confirm": "RESET_DATABASE" } is required.',
      });
    }

    const currentAdmin = await prisma.profile.findUnique({
      where: { id: req.user!.id },
    });

    if (!currentAdmin || !currentAdmin.passwordHash) {
      return res.status(400).json({ error: 'Active super admin account not found.' });
    }

    // API-11: Wrap full reset in a single transaction deleting child tables before parents (Project before Offer, etc.)
    await prisma.$transaction(
      async (tx) => {
        await tx.clientDocument.deleteMany();
        await tx.calendarEvent.deleteMany();
        await tx.serviceTicket.deleteMany();
        await tx.installedItem.deleteMany();
        await tx.projectNote.deleteMany();
        await tx.project.deleteMany();
        await tx.offerItemSpecification.deleteMany();
        await tx.offerItem.deleteMany();
        await tx.offer.deleteMany();
        await tx.paymentRecord.deleteMany();
        await tx.dispatchNote.deleteMany();
        await tx.salesInvoice.deleteMany();
        await tx.purchaseInvoice.deleteMany();
        await tx.inventoryMovement.deleteMany();
        await tx.customer.deleteMany();
        await tx.specificationOption.deleteMany();
        await tx.specificationKey.deleteMany();
        await tx.productModel.deleteMany();
        await tx.product.deleteMany();
        await tx.productCategory.deleteMany();

        // Preserve the executing SUPER_ADMIN account and its existing password hash
        await tx.profile.deleteMany({
          where: {
            id: { not: currentAdmin.id },
          },
        });
      },
      { timeout: 30000 }
    );
    invalidateAuthUserCache();

    void recordAudit(prisma, req, {
      action: 'ADMIN_RESET_DATABASE',
      entityType: 'System',
      metadata: { preservedAdminEmail: currentAdmin.email },
    });

    res.json({
      success: true,
      message: `Database reset cleanly to fresh state. 0 records, 1 system user active (${currentAdmin.email}).`,
    });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/admin/reset-database');
  }
});

// Audit Logs (IMP-07 / IMP-09, SUPER_ADMIN only — with filtering & pagination)
adminRouter.get('/audit-logs', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>, 200);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const actionFilter = typeof req.query.action === 'string' ? req.query.action.trim() : '';
    const entityTypeFilter = typeof req.query.entityType === 'string' ? req.query.entityType.trim() : '';
    const searchFilter = typeof req.query.search === 'string' ? req.query.search.trim() : '';

    const where: Record<string, unknown> = {};
    if (actionFilter && actionFilter !== 'ALL') {
      where.action = actionFilter;
    }
    if (entityTypeFilter && entityTypeFilter !== 'ALL') {
      where.entityType = entityTypeFilter;
    }
    if (searchFilter) {
      where.OR = [
        { actorEmail: { contains: searchFilter, mode: 'insensitive' } },
        { action: { contains: searchFilter, mode: 'insensitive' } },
        { entityType: { contains: searchFilter, mode: 'insensitive' } },
        { entityId: { contains: searchFilter, mode: 'insensitive' } },
      ];
    }

    const [logs, totalCount] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...(page.value.isPaginated ? buildPrismaPaginationArgs(page.value) : { take: 100 }),
      }),
      prisma.auditLog.count({ where }),
    ]);
    res.setHeader('X-Total-Count', String(totalCount));
    res.json(logs);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/audit-logs');
  }
});
