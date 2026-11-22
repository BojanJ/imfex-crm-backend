import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { formatProductForResponse, formatProjectForResponse, formatTicketForResponse } from '../lib/formatters';
import { SAFE_PROFILE_SELECT, AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import {
  isUuid,
  SERVICE_PRIORITIES,
  SERVICE_STATUSES,
  parseEnum,
  parseOptionalDate,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const serviceRouter = Router();

// Service Tickets API
serviceRouter.get('/service-tickets', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [tickets, totalCount] = await Promise.all([
      prisma.serviceTicket.findMany({
        include: {
          customer: true,
          installedItem: true,
          assignedTechnician: { select: SAFE_PROFILE_SELECT },
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.serviceTicket.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(tickets.map(formatTicketForResponse));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/service-tickets');
  }
});

serviceRouter.get('/service-tickets/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid service ticket ID format.' });
    }
    const ticket = await prisma.serviceTicket.findUnique({
      where: { id },
      include: {
        customer: true,
        installedItem: true,
        assignedTechnician: { select: SAFE_PROFILE_SELECT },
      },
    });
    if (!ticket) return res.status(404).json({ error: 'Service ticket not found.' });
    res.json(formatTicketForResponse(ticket));
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/service-tickets/:id');
  }
});

serviceRouter.post('/service-tickets', requireRole(...ROLE_GROUPS.OPERATIONS_WRITE), async (req, res) => {
  try {
    const {
      ticketNumber,
      customerId,
      installedItemId,
      defectDescription,
      priority,
      status,
      laborHours,
      solution,
      assignedTechnicianId,
      scheduledDate,
      partsConsumed,
      closedAt,
    } = req.body ?? {};

    const cleanTicketNumber = typeof ticketNumber === 'string' ? ticketNumber.trim() : '';
    if (!cleanTicketNumber) {
      return res.status(400).json({ error: 'ticketNumber is required.' });
    }

    if (!isUuid(customerId)) {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }
    const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
    if (!custExists) {
      return res.status(404).json({ error: 'Referenced customer not found.' });
    }

    const hasPriority = priority !== undefined && priority !== null && priority !== '';
    const priorityCheck = parseEnum(priority, SERVICE_PRIORITIES, 'priority', 'MEDIUM');
    if (!priorityCheck.ok) return res.status(400).json({ error: priorityCheck.error });

    const hasStatus = status !== undefined && status !== null && status !== '';
    const statusCheck = parseEnum(status, SERVICE_STATUSES, 'status', 'OPEN');
    if (!statusCheck.ok) return res.status(400).json({ error: statusCheck.error });

    const hasLabor = laborHours !== undefined && laborHours !== null && laborHours !== '';
    const laborCheck = parseFiniteNumber(laborHours, 'laborHours', { min: 0, defaultVal: 0 });
    if (!laborCheck.ok) return res.status(400).json({ error: laborCheck.error });

    const scheduledCheck = parseOptionalDate(scheduledDate, 'scheduledDate');
    if (!scheduledCheck.ok) return res.status(400).json({ error: scheduledCheck.error });

    const closedAtCheck = parseOptionalDate(closedAt, 'closedAt');
    if (!closedAtCheck.ok) return res.status(400).json({ error: closedAtCheck.error });

    let validItem: string | null = null;
    if (installedItemId !== undefined && installedItemId !== null && installedItemId !== '') {
      if (!isUuid(installedItemId)) {
        return res.status(400).json({ error: 'Invalid installedItemId UUID format.' });
      }
      const itemExists = await prisma.installedItem.findUnique({ where: { id: installedItemId }, select: { id: true } });
      if (!itemExists) return res.status(404).json({ error: 'Referenced installed item not found.' });
      validItem = itemExists.id;
    }

    let validTech: string | null = null;
    if (assignedTechnicianId !== undefined && assignedTechnicianId !== null && assignedTechnicianId !== '') {
      if (!isUuid(assignedTechnicianId)) {
        return res.status(400).json({ error: 'Invalid assignedTechnicianId UUID format.' });
      }
      const techExists = await prisma.profile.findUnique({ where: { id: assignedTechnicianId }, select: { id: true } });
      if (!techExists) return res.status(404).json({ error: 'Referenced technician not found.' });
      validTech = techExists.id;
    }

    // API-14: Preserve omitted fields during partial updates & persist installedItemId changes
    const ticket = await prisma.serviceTicket.upsert({
      where: { ticketNumber: cleanTicketNumber },
      update: {
        ...(hasPriority ? { priority: priorityCheck.value } : {}),
        ...(hasStatus ? { status: statusCheck.value } : {}),
        ...(defectDescription !== undefined && String(defectDescription).trim() !== ''
          ? { defectDescription: String(defectDescription) }
          : {}),
        ...(hasLabor ? { laborHours: laborCheck.value } : {}),
        ...(solution !== undefined ? { solution } : {}),
        ...(installedItemId !== undefined ? { installedItemId: validItem } : {}),
        ...(assignedTechnicianId !== undefined ? { assignedTechnicianId: validTech } : {}),
        ...(scheduledDate !== undefined ? { scheduledDate: scheduledCheck.value } : {}),
        ...(partsConsumed !== undefined ? { partsConsumed } : {}),
        ...(closedAt !== undefined ? { closedAt: closedAtCheck.value } : {}),
      },
      create: {
        ticketNumber: cleanTicketNumber,
        customerId,
        installedItemId: validItem,
        defectDescription: defectDescription || 'Пријавен дефект',
        priority: priorityCheck.value,
        status: statusCheck.value,
        laborHours: laborCheck.value,
        solution,
        assignedTechnicianId: validTech,
        scheduledDate: scheduledCheck.value ?? undefined,
        partsConsumed,
        closedAt: closedAtCheck.value ?? undefined,
      },
      include: { customer: true, installedItem: true, assignedTechnician: { select: SAFE_PROFILE_SELECT } },
    });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'SERVICE_TICKET_SAVED',
      entityType: 'ServiceTicket',
      entityId: ticket.id,
      metadata: { ticketNumber: ticket.ticketNumber, status: ticket.status, priority: ticket.priority },
    });
    res.json(formatTicketForResponse(ticket));
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/service-tickets');
  }
});

serviceRouter.delete('/service-tickets/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid service ticket ID format.' });
    }
    await prisma.serviceTicket.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'SERVICE_TICKET_DELETED',
      entityType: 'ServiceTicket',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/service-tickets/:id');
  }
});

// Installed Items API
serviceRouter.get('/installed-items', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [items, totalCount] = await Promise.all([
      prisma.installedItem.findMany({
        include: { customer: true, project: true, product: true },
        orderBy: [{ installationDate: 'desc' }, { id: 'desc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.installedItem.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(
      items.map((it) => ({
        ...it,
        project: it.project ? formatProjectForResponse(it.project) : it.project,
        product: it.product ? formatProductForResponse(it.product) : it.product,
      }))
    );
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/installed-items');
  }
});

serviceRouter.get('/installed-items/:id', async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid installed item ID format.' });
    }
    const item = await prisma.installedItem.findUnique({
      where: { id },
      include: { customer: true, project: true, product: true },
    });
    if (!item) return res.status(404).json({ error: 'Installed item not found.' });
    res.json({
      ...item,
      project: item.project ? formatProjectForResponse(item.project) : item.project,
      product: item.product ? formatProductForResponse(item.product) : item.product,
    });
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/installed-items/:id');
  }
});

serviceRouter.post('/installed-items', requireRole(...ROLE_GROUPS.OPERATIONS_WRITE), async (req, res) => {
  try {
    const { id, customerId, projectId, productId, title, serialNumber, installationDate } = req.body ?? {};
    const cleanTitle = typeof title === 'string' ? title.trim() : '';
    if (!cleanTitle) {
      return res.status(400).json({ error: 'title is required.' });
    }

    if (!isUuid(customerId)) {
      return res.status(400).json({ error: 'A valid customerId UUID is required.' });
    }
    const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
    if (!custExists) {
      return res.status(404).json({ error: 'Referenced customer not found.' });
    }

    let validProjectId: string | null = null;
    if (projectId !== undefined && projectId !== null && projectId !== '') {
      if (!isUuid(projectId)) return res.status(400).json({ error: 'Invalid projectId UUID format.' });
      const projExists = await prisma.project.findUnique({ where: { id: projectId }, select: { id: true } });
      if (!projExists) return res.status(404).json({ error: 'Referenced project not found.' });
      validProjectId = projExists.id;
    }

    let validProductId: string | null = null;
    if (productId !== undefined && productId !== null && productId !== '') {
      if (!isUuid(productId)) return res.status(400).json({ error: 'Invalid productId UUID format.' });
      const prodExists = await prisma.product.findUnique({ where: { id: productId }, select: { id: true } });
      if (!prodExists) return res.status(404).json({ error: 'Referenced product not found.' });
      validProductId = prodExists.id;
    }

    const installDateCheck = parseOptionalDate(installationDate, 'installationDate');
    if (!installDateCheck.ok) return res.status(400).json({ error: installDateCheck.error });

    const item = isUuid(id)
      ? await prisma.installedItem.upsert({
          where: { id },
          update: {
            customerId,
            ...(projectId !== undefined ? { projectId: validProjectId } : {}),
            ...(productId !== undefined ? { productId: validProductId } : {}),
            title: cleanTitle,
            serialNumber: serialNumber ?? null,
            installationDate: installDateCheck.value ?? undefined,
          },
          create: {
            id,
            customerId,
            projectId: validProjectId,
            productId: validProductId,
            title: cleanTitle,
            serialNumber: serialNumber ?? null,
            installationDate: installDateCheck.value ?? undefined,
          },
        })
      : await prisma.installedItem.create({
          data: {
            customerId,
            projectId: validProjectId,
            productId: validProductId,
            title: cleanTitle,
            serialNumber: serialNumber ?? null,
            installationDate: installDateCheck.value ?? undefined,
          },
        });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'INSTALLED_ITEM_SAVED',
      entityType: 'InstalledItem',
      entityId: item.id,
      metadata: { title: item.title, customerId: item.customerId },
    });
    res.json(item);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/installed-items');
  }
});

serviceRouter.delete('/installed-items/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid installed item ID format.' });
    }
    await prisma.installedItem.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'INSTALLED_ITEM_DELETED',
      entityType: 'InstalledItem',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/installed-items/:id');
  }
});
