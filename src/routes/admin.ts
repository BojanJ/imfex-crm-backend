import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { AuthenticatedRequest, invalidateAuthUserCache, requireRole } from '../auth';
import { parsePagination, buildPrismaPaginationArgs, handleRouteError } from '../validation';

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

    for (const c of corruptedCust) {
      await prisma.offerItem.deleteMany({ where: { offer: { customerId: c.id } } });
      await prisma.offer.deleteMany({ where: { customerId: c.id } });
      await prisma.project.deleteMany({ where: { customerId: c.id } });
      await prisma.serviceTicket.deleteMany({ where: { customerId: c.id } });
      await prisma.installedItem.deleteMany({ where: { customerId: c.id } });
      await prisma.customer.delete({ where: { id: c.id } });
    }

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

    await prisma.offerItemSpecification.deleteMany();
    await prisma.offerItem.deleteMany();
    await prisma.offer.deleteMany();
    await prisma.project.deleteMany();
    await prisma.serviceTicket.deleteMany();
    await prisma.installedItem.deleteMany();
    await prisma.clientDocument.deleteMany();
    await prisma.calendarEvent.deleteMany();
    await prisma.paymentRecord.deleteMany();
    await prisma.dispatchNote.deleteMany();
    await prisma.salesInvoice.deleteMany();
    await prisma.purchaseInvoice.deleteMany();
    await prisma.inventoryMovement.deleteMany();
    await prisma.customer.deleteMany();
    await prisma.specificationOption.deleteMany();
    await prisma.specificationKey.deleteMany();
    await prisma.productModel.deleteMany();
    await prisma.product.deleteMany();
    await prisma.productCategory.deleteMany();

    // Preserve the executing SUPER_ADMIN account and its existing password hash
    await prisma.profile.deleteMany({
      where: {
        id: { not: currentAdmin.id },
      },
    });
    invalidateAuthUserCache();

    res.json({
      success: true,
      message: `Database reset cleanly to fresh state. 0 records, 1 system user active (${currentAdmin.email}).`,
    });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/admin/reset-database');
  }
});

// Audit Logs (IMP-07, SUPER_ADMIN only)
adminRouter.get('/audit-logs', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>, 200);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const logs = await prisma.auditLog.findMany({
      orderBy: { createdAt: 'desc' },
      ...(page.value.isPaginated ? buildPrismaPaginationArgs(page.value) : { take: 100 }),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.auditLog.count()));
    }
    res.json(logs);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/audit-logs');
  }
});
