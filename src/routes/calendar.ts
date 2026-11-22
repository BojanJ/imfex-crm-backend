import { Router } from 'express';
import { prisma } from '../lib/prisma';
import { ROLE_GROUPS, requireRole } from '../auth';
import {
  isUuid,
  parseIsoDateString,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
} from '../validation';

export const calendarRouter = Router();

calendarRouter.get('/', async (req, res) => {
  try {
    const page = parsePagination(req.query as Record<string, unknown>);
    if (!page.ok) return res.status(400).json({ error: page.error });

    const events = await prisma.calendarEvent.findMany({
      include: { customer: true },
      orderBy: { startDate: 'asc' },
      ...buildPrismaPaginationArgs(page.value),
    });
    if (page.value.isPaginated) {
      res.setHeader('X-Total-Count', String(await prisma.calendarEvent.count()));
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

    const startCheck = parseIsoDateString(startDate, 'startDate', true);
    if (!startCheck.ok || !startCheck.value) {
      return res.status(400).json({ error: startCheck.ok ? 'startDate is required.' : startCheck.error });
    }
    const endCheck = parseIsoDateString(endDate, 'endDate', false);
    if (!endCheck.ok) return res.status(400).json({ error: endCheck.error });

    let validCustomerId: string | null = null;
    if (customerId !== undefined && customerId !== null && customerId !== '') {
      if (!isUuid(customerId)) return res.status(400).json({ error: 'Invalid customerId UUID format.' });
      const custExists = await prisma.customer.findUnique({ where: { id: customerId }, select: { id: true } });
      if (!custExists) return res.status(404).json({ error: 'Referenced customer not found.' });
      validCustomerId = custExists.id;
    }

    const data = {
      title: cleanTitle,
      description: description ?? null,
      startDate: startCheck.value,
      endDate: endCheck.value,
      allDay: Boolean(allDay),
      eventType: eventType || 'MEETING',
      customerId: validCustomerId,
      projectId: projectId || null,
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
    res.json({ success: true, id });
  } catch (error) {
    return handleRouteError(res, error, 'DELETE /api/calendar-events/:id');
  }
});
