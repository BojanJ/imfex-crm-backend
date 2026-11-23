import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { extractWorkflowData, formatProjectForResponse } from '../lib/formatters';
import { SAFE_PROFILE_SELECT, AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import { validateSignatureUrl } from '../security';
import { DOCUMENT_LIST_SELECT } from '../storage';
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

function sanitizeProjectForRole(project: any, includeDocumentData: boolean, role?: string) {
  const formatted = formatProjectForResponse(project, includeDocumentData);
  if (!formatted) return formatted;
  const canReadOffers = Boolean(role && ROLE_GROUPS.OFFERS_READ.includes(role as any));
  if (!canReadOffers && formatted.offer) {
    // Strip commercial pricing/totals for field technicians while preserving offerNumber reference
    formatted.offer = {
      id: formatted.offer.id,
      offerNumber: formatted.offer.offerNumber,
      status: formatted.offer.status,
    };
  }
  return formatted;
}

projectsRouter.get('/', async (req: AuthenticatedRequest, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });
    const includeData = req.query.includeData === 'true';

    const [projects, totalCount] = await Promise.all([
      prisma.project.findMany({
        include: {
          customer: true,
          offer: true,
          responsibleUser: { select: SAFE_PROFILE_SELECT },
          installedItems: true,
          documents: includeData ? true : { select: DOCUMENT_LIST_SELECT },
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.project.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(projects.map((p) => sanitizeProjectForRole(p, includeData, req.user?.role)));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/projects');
  }
});

projectsRouter.get('/:id', async (req: AuthenticatedRequest, res) => {
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
        documents: includeData ? true : { select: DOCUMENT_LIST_SELECT },
      },
    });
    if (!project) return res.status(404).json({ error: 'Project not found.' });
    res.json(sanitizeProjectForRole(project, includeData, req.user?.role));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/projects/:id');
  }
});

projectsRouter.post('/', requireRole(...ROLE_GROUPS.OPERATIONS_WRITE), async (req, res) => {
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

    const hasExplicitStatus = status !== undefined && status !== null && status !== '';
    const statusCheck = hasExplicitStatus
      ? parseEnum(status, PROJECT_STATUSES, 'status')
      : ({ ok: true as const, value: 'PLANNED' as const });
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });

    const startDateCheck = parseOptionalDate(startDate, 'startDate');
    if (!startDateCheck.ok) return res.status(400).json({ error: startDateCheck.error });
    const targetDeliveryCheck = parseOptionalDate(targetDeliveryDate, 'targetDeliveryDate');
    if (!targetDeliveryCheck.ok) return res.status(400).json({ error: targetDeliveryCheck.error });
    const actualDeliveryCheck = parseOptionalDate(actualDeliveryDate, 'actualDeliveryDate');
    if (!actualDeliveryCheck.ok) return res.status(400).json({ error: actualDeliveryCheck.error });
    const installDateCheck = parseOptionalDate(installationDate, 'installationDate');
    if (!installDateCheck.ok) return res.status(400).json({ error: installDateCheck.error });

    const sigCheck = validateSignatureUrl(signatureUrl);
    if (!sigCheck.ok) {
      return res.status(400).json({ error: sigCheck.error });
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

    // API-14: Transactional lookup + workflowData merge + status preservation on partial updates
    const txResult = await prisma.$transaction(async (tx) => {
      const existingProj = await tx.project.findUnique({
        where: { projectNumber: cleanProjectNumber },
        select: { id: true, offerId: true, customerId: true, status: true, workflowData: true },
      });

      let validOfferId: string | null = null;
      let resolvedOfferCustomerId: string | null = null;
      if (offerId !== undefined && offerId !== null && offerId !== '') {
        if (!isUuid(offerId)) {
          return { errorStatus: 400, error: 'Invalid offerId UUID format.' } as const;
        }
        const offerExists = await tx.offer.findUnique({
          where: { id: offerId },
          select: { id: true, customerId: true },
        });
        if (!offerExists) {
          return { errorStatus: 404, error: 'Referenced offer not found.' } as const;
        }
        validOfferId = offerExists.id;
        resolvedOfferCustomerId = offerExists.customerId;
      } else if (existingProj) {
        validOfferId = existingProj.offerId;
      } else {
        return { errorStatus: 400, error: 'A valid offerId UUID is required to create a project.' } as const;
      }

      let validCustomerId: string | null = null;
      if (customerId !== undefined && customerId !== null && customerId !== '') {
        if (!isUuid(customerId)) {
          return { errorStatus: 400, error: 'Invalid customerId UUID format.' } as const;
        }
        const custExists = await tx.customer.findUnique({ where: { id: customerId }, select: { id: true } });
        if (!custExists) {
          return { errorStatus: 404, error: 'Referenced customer not found.' } as const;
        }
        if (resolvedOfferCustomerId && resolvedOfferCustomerId !== custExists.id) {
          return {
            errorStatus: 400,
            error: 'customerId does not match the customer of the referenced offer.',
          } as const;
        }
        validCustomerId = custExists.id;
      } else if (existingProj) {
        validCustomerId = existingProj.customerId;
      } else if (resolvedOfferCustomerId) {
        validCustomerId = resolvedOfferCustomerId;
      } else {
        return { errorStatus: 400, error: 'A valid customerId UUID is required.' } as const;
      }

      const mergedWorkflowData = incomingWorkflow
        ? {
            ...(existingProj?.workflowData && typeof existingProj.workflowData === 'object'
              ? (existingProj.workflowData as Record<string, any>)
              : {}),
            ...incomingWorkflow,
          }
        : undefined;

      // BIZ-05: Release un-dispatched reserved warehouse accessories if project is transitioning into CLOSED
      let finalWorkflowData = mergedWorkflowData;
      const prevStatus = existingProj?.status;
      if (hasExplicitStatus && statusCheck.value === 'CLOSED' && prevStatus !== 'CLOSED') {
        const prevWf =
          existingProj?.workflowData && typeof existingProj.workflowData === 'object'
            ? (existingProj.workflowData as Record<string, any>)
            : {};
        const reservedIds: string[] = Array.isArray(prevWf.reservedAccessoryIds)
          ? prevWf.reservedAccessoryIds.filter((rid: unknown): rid is string => typeof rid === 'string' && isUuid(rid))
          : [];
        if (reservedIds.length > 0 && !prevWf.dispatchIssued && !finalWorkflowData?.dispatchIssued) {
          for (const pid of reservedIds) {
            const prod = await tx.product.findUnique({ where: { id: pid }, select: { id: true, reservedQuantity: true } });
            if (prod && prod.reservedQuantity > 0) {
              await tx.product.update({
                where: { id: prod.id },
                data: { reservedQuantity: Math.max(0, prod.reservedQuantity - 1) },
              });
            }
          }
          finalWorkflowData = { ...(finalWorkflowData ?? prevWf), reservedAccessoryIds: [] };
        }
      }

      const project = await tx.project.upsert({
        where: { projectNumber: cleanProjectNumber },
        update: {
          // Preserve existing status when omitted in partial updates (API-14)
          ...(hasExplicitStatus ? { status: statusCheck.value } : {}),
          ...(procurementStatus !== undefined ? { procurementStatus } : {}),
          ...(procurementNotes !== undefined ? { procurementNotes } : {}),
          ...(responsibleUserId !== undefined ? { responsibleUserId: validRespUser } : {}),
          ...(startDate !== undefined ? { startDate: startDateCheck.value } : {}),
          ...(targetDeliveryDate !== undefined ? { targetDeliveryDate: targetDeliveryCheck.value } : {}),
          ...(actualDeliveryDate !== undefined ? { actualDeliveryDate: actualDeliveryCheck.value } : {}),
          ...(installationTeam !== undefined ? { installationTeam } : {}),
          ...(installationDate !== undefined ? { installationDate: installDateCheck.value } : {}),
          ...(installationAddress !== undefined ? { installationAddress } : {}),
          ...(installationContact !== undefined ? { installationContact } : {}),
          ...(installationMinutes !== undefined ? { installationMinutes } : {}),
          ...(signatureUrl !== undefined ? { signatureUrl } : {}),
          ...(finalWorkflowData !== undefined ? { workflowData: finalWorkflowData } : {}),
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
          ...(finalWorkflowData !== undefined ? { workflowData: finalWorkflowData } : {}),
        },
        include: { customer: true, offer: true, responsibleUser: { select: SAFE_PROFILE_SELECT } },
      });
      return { project } as const;
    });

    if ('error' in txResult && txResult.error) {
      return res.status(txResult.errorStatus).json({ error: txResult.error });
    }
    const project = txResult.project;
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

projectsRouter.delete('/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid project ID format.' });
    }
    // BIZ-05: Release any un-dispatched reserved accessories before deleting project
    await prisma.$transaction(async (tx) => {
      const existing = await tx.project.findUnique({ where: { id }, select: { id: true, workflowData: true } });
      if (existing?.workflowData && typeof existing.workflowData === 'object') {
        const wf = existing.workflowData as Record<string, any>;
        const reservedIds: string[] = Array.isArray(wf.reservedAccessoryIds)
          ? wf.reservedAccessoryIds.filter((rid: unknown): rid is string => typeof rid === 'string' && isUuid(rid))
          : [];
        if (reservedIds.length > 0 && !wf.dispatchIssued) {
          for (const pid of reservedIds) {
            const prod = await tx.product.findUnique({ where: { id: pid }, select: { id: true, reservedQuantity: true } });
            if (prod && prod.reservedQuantity > 0) {
              await tx.product.update({
                where: { id: prod.id },
                data: { reservedQuantity: Math.max(0, prod.reservedQuantity - 1) },
              });
            }
          }
        }
      }
      await tx.project.delete({ where: { id } });
    });
    void recordAudit(prisma, req as AuthenticatedRequest, { action: 'PROJECT_DELETED', entityType: 'Project', entityId: id });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/projects/:id');
  }
});

// Project Internal Notes / Comments Timeline (IMP-10)
projectsRouter.get('/:id/notes', async (req, res) => {
  try {
    const projectId = String(req.params.id);
    if (!isUuid(projectId)) {
      return res.status(400).json({ error: 'Invalid project ID format.' });
    }
    const exists = await prisma.project.findUnique({ where: { id: projectId }, select: { id: true } });
    if (!exists) return res.status(404).json({ error: 'Project not found.' });

    const notes = await prisma.projectNote.findMany({
      where: { projectId },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 200,
    });
    res.json(notes);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/projects/:id/notes');
  }
});

projectsRouter.post('/:id/notes', requireRole(...ROLE_GROUPS.OPERATIONS_WRITE), async (req: AuthenticatedRequest, res) => {
  try {
    const projectId = String(req.params.id);
    if (!isUuid(projectId)) {
      return res.status(400).json({ error: 'Invalid project ID format.' });
    }
    const rawContent = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
    if (!rawContent) {
      return res.status(400).json({ error: 'Note content is required.' });
    }
    if (rawContent.length > 2000) {
      return res.status(400).json({ error: 'Note content must be at most 2000 characters.' });
    }

    const exists = await prisma.project.findUnique({ where: { id: projectId }, select: { id: true, projectNumber: true } });
    if (!exists) return res.status(404).json({ error: 'Project not found.' });

    const authorName = req.user?.fullName || req.user?.email || 'Team Member';
    const note = await prisma.projectNote.create({
      data: {
        projectId,
        authorId: req.user?.id ?? null,
        authorName,
        content: rawContent,
      },
    });
    void recordAudit(prisma, req, {
      action: 'PROJECT_NOTE_ADDED',
      entityType: 'Project',
      entityId: projectId,
      metadata: { noteId: note.id, projectNumber: exists.projectNumber },
    });
    res.status(201).json(note);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/projects/:id/notes');
  }
});

projectsRouter.delete('/:id/notes/:noteId', requireRole(...ROLE_GROUPS.OPERATIONS_WRITE), async (req: AuthenticatedRequest, res) => {
  try {
    const projectId = String(req.params.id);
    const noteId = String(req.params.noteId);
    if (!isUuid(projectId) || !isUuid(noteId)) {
      return res.status(400).json({ error: 'Invalid project or note ID format.' });
    }
    const existing = await prisma.projectNote.findFirst({ where: { id: noteId, projectId } });
    if (!existing) return res.status(404).json({ error: 'Project note not found.' });

    const isSuperAdmin = req.user?.role === 'SUPER_ADMIN';
    const isAuthor = existing.authorId && req.user?.id === existing.authorId;
    if (!isSuperAdmin && !isAuthor) {
      return res.status(403).json({ error: 'You can only delete your own project notes.' });
    }

    await prisma.projectNote.delete({ where: { id: noteId } });
    void recordAudit(prisma, req, {
      action: 'PROJECT_NOTE_DELETED',
      entityType: 'Project',
      entityId: projectId,
      metadata: { noteId },
    });
    res.json({ success: true, id: noteId });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/projects/:id/notes/:noteId');
  }
});
