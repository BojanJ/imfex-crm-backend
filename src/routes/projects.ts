import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { extractWorkflowData, formatProjectForResponse } from '../lib/formatters';
import { SAFE_PROFILE_SELECT, AuthenticatedRequest } from '../auth';
import {
  isUuid,
  PROJECT_STATUSES,
  parseEnum,
  parseOptionalDate,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const projectsRouter = Router();

projectsRouter.get('/', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });
    const includeData = req.query.includeData === 'true';

    const projects = await prisma.project.findMany({
      include: {
        customer: true,
        offer: true,
        responsibleUser: { select: SAFE_PROFILE_SELECT },
        installedItems: true,
        documents: true,
      },
      orderBy: { createdAt: 'desc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.project.count()));
    }
    res.json(projects.map((p) => formatProjectForResponse(p, includeData)));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/projects');
  }
});

projectsRouter.get('/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid project ID format.' });
    }
    const includeData = req.query.includeData === 'true';
    const project = await prisma.project.findUnique({
      where: { id },
      include: {
        customer: true,
        offer: true,
        responsibleUser: { select: SAFE_PROFILE_SELECT },
        installedItems: true,
        documents: true,
      },
    });
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    res.json(formatProjectForResponse(project, includeData));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/projects/:id');
  }
});

projectsRouter.post('/', async (req, res) => {
  try {
    const {
      projectNumber,
      offerId,
      customerId,
      status,
      procurementStatus,
      procurementNotes,
      responsibleUserId,
      startDate,
      targetDeliveryDate,
      actualDeliveryDate,
      installationTeam,
      installationDate,
      installationAddress,
      installationContact,
      installationMinutes,
      signatureUrl,
    } = req.body ?? {};

    const cleanProjectNumber = typeof projectNumber === 'string' ? projectNumber.trim() : '';
    if (!cleanProjectNumber) {
      return res.status(400).json({ error: 'projectNumber is required.' });
    }

    const statusCheck = parseEnum(status, PROJECT_STATUSES, 'status', 'PLANNED');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });

    const startDateCheck = parseOptionalDate(startDate, 'startDate');
    if (!startDateCheck.ok) return res.status(400).json({ error: startDateCheck.error });
    const targetDeliveryCheck = parseOptionalDate(targetDeliveryDate, 'targetDeliveryDate');
    if (!targetDeliveryCheck.ok) return res.status(400).json({ error: targetDeliveryCheck.error });
    const actualDeliveryCheck = parseOptionalDate(actualDeliveryDate, 'actualDeliveryDate');
    if (!actualDeliveryCheck.ok) return res.status(400).json({ error: actualDeliveryCheck.error });
    const installDateCheck = parseOptionalDate(installationDate, 'installationDate');
    if (!installDateCheck.ok) return res.status(400).json({ error: installDateCheck.error });

    const existingProj = await prisma.project.findUnique({
      where: { projectNumber: cleanProjectNumber },
      select: { id: true, offerId: true, customerId: true, workflowData: true },
    });

    // API-01: Strictly require valid existing offerId & customerId — never fabricate fake customers or OFF-TMP offers
    let validOfferId: string | null = null;
    let resolvedOfferCustomerId: string | null = null;
    if (offerId !== undefined && offerId !== null && offerId !== '') {
      if (!isUuid(offerId)) {
        return res.status(400).json({ error: 'Invalid offerId UUID format.' });
      }
      const offerExists = await prisma.offer.findUnique({
        where: { id: offerId },
        select: { id: true, customerId: true },
      });
      if (!offerExists) {
        return res.status(404).json({ error: 'Referenced offer not found.' });
      }
      validOfferId = offerExists.id;
      resolvedOfferCustomerId = offerExists.customerId;
    } else if (existingProj) {
      validOfferId = existingProj.offerId;
    } else {
      return res.status(400).json({ error: 'A valid offerId UUID is required to create a project.' });
    }

    let validCustomerId: string | null = null;
    if (customerId !== undefined && customerId !== null && customerId !== '') {
      if (!isUuid(customerId)) {
        return res.status(400).json({ error: 'Invalid customerId UUID format.' });
      }
      const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
      if (!custExists) {
        return res.status(404).json({ error: 'Referenced customer not found.' });
      }
      validCustomerId = custExists.id;
    } else if (existingProj) {
      validCustomerId = existingProj.customerId;
    } else if (resolvedOfferCustomerId) {
      validCustomerId = resolvedOfferCustomerId;
    } else {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }

    let validRespUser: string | null = null;
    if (responsibleUserId !== undefined && responsibleUserId !== null && responsibleUserId !== '') {
      if (!isUuid(responsibleUserId)) {
        return res.status(400).json({ error: 'Invalid responsibleUserId UUID format.' });
      }
      const userExists = await prisma.profile.findUnique({ where: { id: responsibleUserId }, select: { id: true } });
      if (!userExists) {
        return res.status(404).json({ error: 'Referenced responsible user not found.' });
      }
      validRespUser = userExists.id;
    }

    const incomingWorkflow = extractWorkflowData(req.body ?? {});
    const mergedWorkflowData = incomingWorkflow
      ? {
          ...(existingProj?.workflowData && typeof existingProj.workflowData === 'object'
            ? (existingProj.workflowData as Record<string, any>)
            : {}),
          ...incomingWorkflow,
        }
      : undefined;

    const project = await prisma.project.upsert({
      where: { projectNumber: cleanProjectNumber },
      update: {
        status: statusCheck.value,
        procurementStatus,
        procurementNotes,
        responsibleUserId: responsibleUserId !== undefined ? validRespUser : undefined,
        startDate: startDateCheck.value,
        targetDeliveryDate: targetDeliveryCheck.value,
        actualDeliveryDate: actualDeliveryCheck.value,
        installationTeam,
        installationDate: installDateCheck.value,
        installationAddress,
        installationContact,
        installationMinutes,
        signatureUrl,
        ...(mergedWorkflowData !== undefined ? { workflowData: mergedWorkflowData } : {}),
      },
      create: {
        projectNumber: cleanProjectNumber,
        offerId: validOfferId,
        customerId: validCustomerId,
        status: statusCheck.value,
        procurementStatus,
        procurementNotes,
        responsibleUserId: validRespUser,
        startDate: startDateCheck.value ?? undefined,
        targetDeliveryDate: targetDeliveryCheck.value ?? undefined,
        actualDeliveryDate: actualDeliveryCheck.value ?? undefined,
        installationTeam,
        installationDate: installDateCheck.value ?? undefined,
        installationAddress,
        installationContact,
        installationMinutes,
        signatureUrl,
        ...(mergedWorkflowData !== undefined ? { workflowData: mergedWorkflowData } : {}),
      },
      include: { customer: true, offer: true, responsibleUser: { select: SAFE_PROFILE_SELECT } },
    });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'PROJECT_SAVED',
      entityType: 'Project',
      entityId: project.id,
      metadata: { projectNumber: project.projectNumber, status: project.status },
    });
    res.json(formatProjectForResponse(project));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/projects');
  }
});

projectsRouter.delete('/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid project ID format.' });
    }
    await prisma.project.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, { action: 'PROJECT_DELETED', entityType: 'Project', entityId: id });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/projects/:id');
  }
});
