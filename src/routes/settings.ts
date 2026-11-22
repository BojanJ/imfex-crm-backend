import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { AuthenticatedRequest, requireRole } from '../auth';
import { isValidEmail } from '../security';
import { parseFiniteNumber, parseOptionalString, handleRouteError } from '../validation';
import { recordAudit } from '../audit';

export const settingsRouter = Router();

const formatSettings = (s: any) => ({
  ...s,
  oversizeAreaThreshold: Number(s.oversizeAreaThreshold ?? 8),
  oversizeRatePerSqm: Number(s.oversizeRatePerSqm ?? 45),
  defaultHourlyLaborRate: Number(s.defaultHourlyLaborRate ?? 25),
  minMarginPercent: Number(s.minMarginPercent ?? 15),
  eurToMkdRate: Number(s.eurToMkdRate ?? 61.5),
});

settingsRouter.get('/', async (_req, res) => {
  try {
    // Atomic upsert avoids duplicate-create race on fresh DB (API-17)
    const settings = await prisma.companySettings.upsert({
      where: { id: 'default' },
      update: {},
      create: { id: 'default' },
    });
    res.json(formatSettings(settings));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/company-settings');
  }
});

settingsRouter.put('/', requireRole('SUPER_ADMIN'), async (req, res) => {
  try {
    const {
      companyName,
      address,
      taxId,
      phone,
      email,
      bankAccount,
      defaultAdvancePercent,
      oversizeAreaThreshold,
      oversizeRatePerSqm,
      defaultHourlyLaborRate,
      minMarginPercent,
      eurToMkdRate,
    } = req.body ?? {};

    const companyNameCheck = parseOptionalString(companyName, 'companyName', 200);
    if (!companyNameCheck.ok) return res.status(400).json({ error: companyNameCheck.error });
    const addressCheck = parseOptionalString(address, 'address', 500);
    if (!addressCheck.ok) return res.status(400).json({ error: addressCheck.error });
    const taxIdCheck = parseOptionalString(taxId, 'taxId', 100);
    if (!taxIdCheck.ok) return res.status(400).json({ error: taxIdCheck.error });
    const phoneCheck = parseOptionalString(phone, 'phone', 100);
    if (!phoneCheck.ok) return res.status(400).json({ error: phoneCheck.error });
    const bankAccountCheck = parseOptionalString(bankAccount, 'bankAccount', 250);
    if (!bankAccountCheck.ok) return res.status(400).json({ error: bankAccountCheck.error });

    if (email !== undefined && email !== null && String(email).trim() !== '' && !isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid company email address.' });
    }

    let advancePercentValue: number | undefined;
    if (defaultAdvancePercent !== undefined) {
      // Preserve 0% explicitly (never coerce 0 -> 50 via `|| 50`) (API-17)
      const advCheck = parseFiniteNumber(defaultAdvancePercent, 'defaultAdvancePercent', {
        min: 0,
        max: 100,
        integer: true,
      });
      if (!advCheck.ok) return res.status(400).json({ error: advCheck.error });
      advancePercentValue = advCheck.value;
    }

    let oversizeThresholdVal: number | undefined;
    if (oversizeAreaThreshold !== undefined && oversizeAreaThreshold !== null && oversizeAreaThreshold !== '') {
      const check = parseFiniteNumber(oversizeAreaThreshold, 'oversizeAreaThreshold', { min: 0, max: 1000 });
      if (!check.ok) return res.status(400).json({ error: check.error });
      oversizeThresholdVal = check.value;
    }
    let oversizeRateVal: number | undefined;
    if (oversizeRatePerSqm !== undefined && oversizeRatePerSqm !== null && oversizeRatePerSqm !== '') {
      const check = parseFiniteNumber(oversizeRatePerSqm, 'oversizeRatePerSqm', { min: 0, max: 100000 });
      if (!check.ok) return res.status(400).json({ error: check.error });
      oversizeRateVal = check.value;
    }
    let hourlyLaborVal: number | undefined;
    if (defaultHourlyLaborRate !== undefined && defaultHourlyLaborRate !== null && defaultHourlyLaborRate !== '') {
      const check = parseFiniteNumber(defaultHourlyLaborRate, 'defaultHourlyLaborRate', { min: 0, max: 10000 });
      if (!check.ok) return res.status(400).json({ error: check.error });
      hourlyLaborVal = check.value;
    }
    let minMarginVal: number | undefined;
    if (minMarginPercent !== undefined && minMarginPercent !== null && minMarginPercent !== '') {
      const check = parseFiniteNumber(minMarginPercent, 'minMarginPercent', { min: 0, max: 100 });
      if (!check.ok) return res.status(400).json({ error: check.error });
      minMarginVal = check.value;
    }
    let eurToMkdVal: number | undefined;
    if (eurToMkdRate !== undefined && eurToMkdRate !== null && eurToMkdRate !== '') {
      const check = parseFiniteNumber(eurToMkdRate, 'eurToMkdRate', { min: 1, max: 10000 });
      if (!check.ok) return res.status(400).json({ error: check.error });
      eurToMkdVal = check.value;
    }

    const updateData = {
      ...(companyNameCheck.value ? { companyName: companyNameCheck.value.trim() } : {}),
      ...(addressCheck.value !== undefined && addressCheck.value !== null ? { address: addressCheck.value.trim() } : {}),
      ...(taxIdCheck.value !== undefined && taxIdCheck.value !== null ? { taxId: taxIdCheck.value.trim() } : {}),
      ...(phoneCheck.value !== undefined && phoneCheck.value !== null ? { phone: phoneCheck.value.trim() } : {}),
      ...(email !== undefined && email !== null && String(email).trim() !== '' ? { email: String(email).trim() } : {}),
      ...(bankAccountCheck.value !== undefined
        ? { bankAccount: bankAccountCheck.value ? bankAccountCheck.value.trim() : null }
        : {}),
      ...(advancePercentValue !== undefined ? { defaultAdvancePercent: advancePercentValue } : {}),
      ...(oversizeThresholdVal !== undefined ? { oversizeAreaThreshold: oversizeThresholdVal } : {}),
      ...(oversizeRateVal !== undefined ? { oversizeRatePerSqm: oversizeRateVal } : {}),
      ...(hourlyLaborVal !== undefined ? { defaultHourlyLaborRate: hourlyLaborVal } : {}),
      ...(minMarginVal !== undefined ? { minMarginPercent: minMarginVal } : {}),
      ...(eurToMkdVal !== undefined ? { eurToMkdRate: eurToMkdVal } : {}),
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
    res.json(formatSettings(settings));
  } catch (error) {
    return handleRouteError(res, error, 'PUT /api/company-settings');
  }
});
