import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { AuthenticatedRequest, ROLE_GROUPS, requireRole } from '../auth';
import {
  isUuid,
  CALENDAR_EVENT_TYPES,
  parseEnum,
  parseIsoDateString,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';
import { recordAudit } from '../audit';

export const calendarRouter = Router();

calendarRouter.get('/', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const [events, totalCount] = await Promise.all([
      prisma.calendarEvent.findMany({
        include: { customer: true },
        orderBy: [{ startDate: 'asc' }, { id: 'asc' }],
        ...buildPrismaPaginationArgs(page.value),
      }),
      page.value.isPaginated ? prisma.calendarEvent.count() : Promise.resolve(0),
    ]);
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(totalCount));
    }
    res.json(events);
  } catch (error) {
    return handleRouteError(res, error, 'GET /api/calendar-events');
  }
});

calendarRouter.post('/', requireRole(...ROLE_GROUPS.OPERATIONS_WRITE), async (req, res) => {
  try {
    const { id, title, description, startDate, endDate, allDay, eventType, customerId, projectId, location, color } =
      req.body ?? {};

    const cleanTitle = typeof title === 'string' ? title.trim() : '';
    if (!cleanTitle) {
      return res.status(400).json({ error: 'title is required.' });
    }

    const eventTypeCheck = parseEnum(eventType, CALENDAR_EVENT_TYPES, 'eventType', 'MEETING');
    if (!eventTypeCheck.ok) return res.status(400).json({ error: eventTypeCheck.error });

    const startCheck = parseIsoDateString(startDate, 'startDate', true);
    if (!startCheck.ok || !startCheck.value) {
      return res.status(400).json({ error: startCheck.ok ? 'startDate is required.' : startCheck.error });
    }
    const endCheck = parseIsoDateString(endDate, 'endDate', false);
    if (!endCheck.ok) return res.status(400).json({ error: endCheck.error });

    if (endCheck.value && new Date(endCheck.value).getTime() < new Date(startCheck.value).getTime()) {
      return res.status(400).json({ error: 'endDate cannot be earlier than startDate.' });
    }

    let validCustomerId: string | null = null;
    if (customerId !== undefined && customerId !== null && customerId !== '') {
      if (!isUuid(customerId)) return res.status(400).json({ error: 'Invalid customerId UUID format.' });
      const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
      if (!custExists) return res.status(404).json({ error: 'Referenced customer not found.' });
      validCustomerId = custExists.id;
    }

    let validProjectId: string | null = null;
    if (projectId !== undefined && projectId !== null && projectId !== '') {
      if (!isUuid(projectId)) return res.status(400).json({ error: 'Invalid projectId UUID format.' });
      validProjectId = projectId;
    }

    const data = {
      title: cleanTitle,
      description: description ?? null,
      startDate: startCheck.value,
      endDate: endCheck.value,
      allDay: Boolean(allDay),
      eventType: eventTypeCheck.value,
      customerId: validCustomerId,
      projectId: validProjectId,
      location: location ?? null,
      color: color ?? null,
    };

    const event = isUuid(id)
      ? await prisma.calendarEvent.upsert({
          where: { id },
          update: data,
          create: { id, ...data },
          include: { customer: true },
        })
      : await prisma.calendarEvent.create({
          data,
          include: { customer: true },
        });

    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'CALENDAR_EVENT_SAVED',
      entityType: 'CalendarEvent',
      entityId: event.id,
      metadata: { title: event.title, eventType: event.eventType, startDate: event.startDate },
    });
    res.json(event);
  } catch (error) {
    return handleRouteError(res, error, 'POST /api/calendar-events');
  }
});

calendarRouter.delete('/:id', requireRole(...ROLE_GROUPS.DESTRUCTIVE_DELETE), async (req, res) => {
  try {
    const id = String(req.params.id);
    if (!isUuid(id)) {
      return res.status(400).json({ error: 'Invalid calendar event ID format.' });
    }
    await prisma.calendarEvent.delete({ where: { id } });
    void recordAudit(prisma, req as AuthenticatedRequest, {
      action: 'CALENDAR_EVENT_DELETED',
      entityType: 'CalendarEvent',
      entityId: id,
    });
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/calendar-events/:id');
  }
});
