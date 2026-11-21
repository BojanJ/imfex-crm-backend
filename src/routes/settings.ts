import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { AuthenticatedRequest, requireRole } from '../auth';
import { handleRouteError } from '../validation';
import { recordAudit } from '../audit';

export const settingsRouter = Router();

settingsRouter.get('/', async (_req, res) => {
  try {
    let settings = await prisma.companySettings.findUnique({ where: { id: 'default' } });
    if (!settings) {
      settings = await prisma.companySettings.create({ data: { id: 'default' } });
    }
    res.json(settings);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/company-settings');
  }
});

settingsRouter.put('/', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    const { companyName, address, taxId, phone, email, bankAccount, defaultAdvancePercent } = req.body ?? {};
    const updateData = {
      ...(companyName !== undefined ? { companyName: String(companyName) } : {}),
      ...(address !== undefined ? { address: String(address) } : {}),
      ...(taxId !== undefined ? { taxId: String(taxId) } : {}),
      ...(phone !== undefined ? { phone: String(phone) } : {}),
      ...(email !== undefined ? { email: String(email) } : {}),
      ...(bankAccount !== undefined ? { bankAccount: bankAccount ? String(bankAccount) : null } : {}),
      ...(defaultAdvancePercent !== undefined
        ? { defaultAdvancePercent: Math.min(100, Math.max(0, Math.round(Number(defaultAdvancePercent) || 50))) }
        : {}),
    };
    const settings = await prisma.companySettings.upsert({
      where: { id: 'default' },
      update: updateData,
      create: { id: 'default', ...updateData },
    });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'COMPANY_SETTINGS_UPDATED',
      entityType: 'CompanySettings',
      entityId: 'default',
    });
    res.json(settings);
  } catch (error) {
    return handleRouteError(res, error, 'PUT /api/company-settings');
  }
});
