import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import { validateDocumentUpload } from '../security';
import { isUuid, parsePagination, buildPrismaPaginationArgs, handleRouteError } from '../validation';
import { recordAudit } from '../audit';
import {
  DOCUMENT_LIST_SELECT,
  persistDocumentPayload,
  resolveDocumentBinary,
  deleteStoredDocumentObject,
  formatDocumentForList,
  isStorageRef,
} from '../storage';

export const documentsRouter = Router();

documentsRouter.get('/', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const includeData = req.query.includeData === 'true';
    const where: any = {};
    if (req.query.customerId) {
      if (!isUuid(req.query.customerId)) return res.status(400).json({ error: 'Invalid customerId filter.' });
      where.customerId = req.query.customerId;
    }
    if (req.query.projectId) {
      if (!isUuid(req.query.projectId)) return res.status(400).json({ error: 'Invalid projectId filter.' });
      where.projectId = req.query.projectId;
    }

    // API-21: Exclude heavy fileUrl column at SQL level when includeData !== 'true'
    const [docs, totalCount] = await Promise.all([
      includeData
        ? prisma.clientDocument.findMany({
            where,
            include: { customer: true },
            orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
            ...buildPrismaPaginationArgs(page.value),
          })
        : prisma.clientDocument.findMany({
            where,
            select: {
              ...DOCUMENT_LIST_SELECT,
              customer: true,
            },
            orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
            ...buildPrismaPaginationArgs(page.value),
          }),
      page.value.isPaginated ? prisma.clientDocument.count({ where }) : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(docs.map((d) => formatDocumentForList(d, includeData)));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/client-documents');
  }
});

documentsRouter.get('/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid document ID format.' });
    }
    const doc = await prisma.clientDocument.findUnique({
      where: { id },
      include: { customer: true },
    });
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    let resolvedUrl = doc.fileUrl;
    if (isStorageRef(doc.fileUrl)) {
      const bin = await resolveDocumentBinary(doc.fileUrl);
      if (bin) {
        resolvedUrl = `data:${bin.mime};base64,${bin.buffer.toString('base64')}`;
      }
    }
    res.json({
      ...doc,
      fileUrl: resolvedUrl,
      hasFile: Boolean(resolvedUrl && resolvedUrl !== '#'),
    });
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/client-documents/:id');
  }
});

documentsRouter.get('/:id/download', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid document ID format.' });
    }
    const doc = await prisma.clientDocument.findUnique({ where: { id } });
    if (!doc) return res.status(404).json({ error: 'Document not found.' });

    const bin = await resolveDocumentBinary(doc.fileUrl);
    if (!bin) {
      return res.status(404).json({ error: 'Document file content is unavailable.' });
    }
    const safeDownloadName = (doc.fileName || doc.title || 'document').replace(/[^a-zA-Z0-9._-]/g, '_');
    res.setHeader('Content-Type', bin.mime);
    res.setHeader('Content-Disposition', `attachment; filename="${safeDownloadName}"`);
    res.send(bin.buffer);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/client-documents/:id/download');
  }
});

documentsRouter.post('/', requireRole(...ROLE_GROUPS.OPERATIONS_WRITE), async (req, res) => {
  try {
    const { id, customerId, offerId, projectId, serviceId, title, fileType, fileUrl, fileName, sizeBytes } = req.body ?? {};

    const uploadValidation = validateDocumentUpload(fileUrl, fileName || title);
    if (!uploadValidation.ok) {
      return res.status(400).json({ error: uploadValidation.error });
    }

    let validProjectId: string | null = null;
    let resolvedProject: { id: string; customerId: string; offerId: string } | null = null;
    if (projectId !== undefined && projectId !== null && projectId !== '') {
      if (isUuid(projectId)) {
        resolvedProject = await prisma.project.findUnique({
          where: { id: projectId },
          select: { id: true, customerId: true, offerId: true },
        });
      } else {
        resolvedProject = await prisma.project.findUnique({
          where: { projectNumber: String(projectId) },
          select: { id: true, customerId: true, offerId: true },
        });
      }
      if (!resolvedProject) {
        return res.status(404).json({ error: 'Referenced project not found.' });
      }
      validProjectId = resolvedProject.id;
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
    } else if (resolvedProject?.customerId) {
      validCustomerId = resolvedProject.customerId;
    } else {
      return res.status(400).json({ error: 'A valid customerId UUID (or valid projectId) is required.' });
    }

    let validOfferId: string | null = null;
    if (offerId !== undefined && offerId !== null && offerId !== '') {
      const off = isUuid(offerId)
        ? await prisma.offer.findUnique({ where: { id: offerId }, select: { id: true } })
        : await prisma.offer.findUnique({ where: { offerNumber: String(offerId) }, select: { id: true } });
      if (!off) return res.status(404).json({ error: 'Referenced offer not found.' });
      validOfferId = off.id;
    } else if (resolvedProject?.offerId) {
      validOfferId = resolvedProject.offerId;
    }

    let validServiceId: string | null = null;
    if (serviceId !== undefined && serviceId !== null && serviceId !== '') {
      if (!isUuid(serviceId)) return res.status(400).json({ error: 'Invalid serviceId UUID format.' });
      const srvExists = await prisma.serviceTicket.findUnique({ where: { id: serviceId }, select: { id: true } });
      if (!srvExists) return res.status(404).json({ error: 'Referenced service ticket not found.' });
      validServiceId = srvExists.id;
    }

    const existingDoc = isUuid(id)
      ? await prisma.clientDocument.findUnique({ where: { id }, select: { fileUrl: true } })
      : null;

    const persisted = await persistDocumentPayload(String(fileUrl || ''), fileName || title);
    const parsedSize =
      sizeBytes !== undefined && sizeBytes !== null && Number.isFinite(Number(sizeBytes))
        ? Math.max(0, Math.round(Number(sizeBytes)))
        : persisted.sizeBytes ?? null;

    let doc;
    try {
      doc = isUuid(id)
        ? await prisma.clientDocument.upsert({
            where: { id },
            update: {
              customerId: validCustomerId,
              title: title || 'Документ',
              fileType: fileType || 'application/pdf',
              fileUrl: persisted.storedUrl,
              fileName: fileName || null,
              sizeBytes: parsedSize,
              offerId: validOfferId,
              projectId: validProjectId,
              serviceId: validServiceId,
            },
            create: {
              id,
              customerId: validCustomerId,
              offerId: validOfferId,
              projectId: validProjectId,
              serviceId: validServiceId,
              title: title || 'Документ',
              fileType: fileType || 'application/pdf',
              fileUrl: persisted.storedUrl,
              fileName: fileName || null,
              sizeBytes: parsedSize,
            },
          })
        : await prisma.clientDocument.create({
            data: {
              customerId: validCustomerId,
              offerId: validOfferId,
              projectId: validProjectId,
              serviceId: validServiceId,
              title: title || 'Документ',
              fileType: fileType || 'application/pdf',
              fileUrl: persisted.storedUrl,
              fileName: fileName || null,
              sizeBytes: parsedSize,
            },
          });
    } catch (dbErr) {
      // API-20: Clean up newly uploaded storage object if DB write fails
      if (isStorageRef(persisted.storedUrl)) {
        await deleteStoredDocumentObject(persisted.storedUrl);
      }
      throw dbErr;
    }

    // API-20: Clean up replaced storage object after DB commit
    if (existingDoc?.fileUrl && existingDoc.fileUrl !== persisted.storedUrl && isStorageRef(existingDoc.fileUrl)) {
      void deleteStoredDocumentObject(existingDoc.fileUrl);
    }

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'DOCUMENT_SAVED',
      entityType: 'ClientDocument',
      entityId: doc.id,
      metadata: { title: doc.title, customerId: doc.customerId, projectId: doc.projectId },
    });

    // API-20: Never leak internal storage:// URI; return consistent format matching GET
    res.json({
      ...doc,
      fileUrl: isStorageRef(doc.fileUrl) ? '' : doc.fileUrl,
      hasFile: Boolean(doc.fileUrl && doc.fileUrl !== '#'),
    });
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/client-documents');
  }
});

documentsRouter.delete('/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid document ID format.' });
    }
    const deleted = await prisma.clientDocument.delete({ where: { id } });
    await deleteStoredDocumentObject(deleted.fileUrl);
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'DOCUMENT_DELETED',
      entityType: 'ClientDocument',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/client-documents/:id');
  }
});
