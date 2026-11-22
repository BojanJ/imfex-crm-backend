import type { Response } from 'express';
import { logger } from './logger';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_REGEX.test(value.trim());
}

export const USER_ROLES = ['SUPER_ADMIN', 'SALES', 'ACCOUNTANT', 'TECHNICIAN', 'USER'] as const;
export const SPEC_INPUT_TYPES = ['SELECT', 'MULTISELECT', 'TEXT', 'NUMBER'] as const;
export const CUSTOMER_TYPES = ['INDIVIDUAL', 'COMPANY', 'PARTNER', 'OTHER'] as const;
export const OFFER_STATUSES = ['DRAFT', 'SENT', 'ACCEPTED', 'REJECTED', 'EXPIRED'] as const;
export const PROJECT_STATUSES = [
  'PLANNED',
  'PROCUREMENT',
  'PRODUCTION',
  'INSTALLATION',
  'COMPLETED',
  'CLOSED',
] as const;
export const SERVICE_PRIORITIES = ['LOW', 'MEDIUM', 'HIGH', 'URGENT'] as const;
export const SERVICE_STATUSES = ['OPEN', 'ASSIGNED', 'IN_PROGRESS', 'COMPLETED', 'CLOSED'] as const;

export type ValidationResult<T> = { ok: true; value: T } | { ok: false; error: string };

export function parseEnum<T extends string>(
  value: unknown,
  allowed: readonly T[],
  fieldName: string,
  defaultVal?: T
): ValidationResult<T> {
  if (value === undefined || value === null || value === '') {
    if (defaultVal !== undefined) return { ok: true, value: defaultVal };
    return { ok: false, error: `${fieldName} is required.` };
  }
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    return {
      ok: false,
      error: `Invalid ${fieldName}. Allowed values: ${allowed.join(', ')}.`,
    };
  }
  return { ok: true, value: value as T };
}

export function parseOptionalDate(
  value: unknown,
  fieldName: string
): ValidationResult<Date | null | undefined> {
  if (value === undefined) return { ok: true, value: undefined };
  if (value === null || value === '') return { ok: true, value: null };
  if (typeof value !== 'string' && typeof value !== 'number' && !(value instanceof Date)) {
    return { ok: false, error: `${fieldName} must be a valid date string.` };
  }
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) {
    return { ok: false, error: `${fieldName} is not a valid date.` };
  }
  return { ok: true, value: d };
}

export function parseIsoDateString(
  value: unknown,
  fieldName: string,
  required = false
): ValidationResult<string | null> {
  if (value === undefined || value === null || value === '') {
    if (required) return { ok: false, error: `${fieldName} is required.` };
    return { ok: true, value: null };
  }
  if (typeof value !== 'string') {
    return { ok: false, error: `${fieldName} must be a valid date string.` };
  }
  const trimmed = value.trim();
  const parsed = new Date(trimmed);
  if (Number.isNaN(parsed.getTime())) {
    return { ok: false, error: `${fieldName} is not a valid date.` };
  }
  return { ok: true, value: trimmed };
}

export function parseFiniteNumber(
  value: unknown,
  fieldName: string,
  opts: { min?: number; max?: number; defaultVal?: number; integer?: boolean } = {}
): ValidationResult<number> {
  if (value === undefined || value === null || value === '') {
    if (opts.defaultVal !== undefined) return { ok: true, value: opts.defaultVal };
    return { ok: false, error: `${fieldName} is required.` };
  }
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return { ok: false, error: `${fieldName} must be a valid finite number.` };
  }
  if (opts.min !== undefined && num < opts.min) {
    return { ok: false, error: `${fieldName} must be at least ${opts.min}.` };
  }
  if (opts.max !== undefined && num > opts.max) {
    return { ok: false, error: `${fieldName} must be at most ${opts.max}.` };
  }
  return { ok: true, value: opts.integer ? Math.round(num) : num };
}

export interface PaginationParams {
  isPaginated: boolean;
  take?: number;
  skip?: number;
  cursorId?: string;
}

export function parsePagination(
  query: Record<string, unknown>,
  maxLimit = 500
): ValidationResult<PaginationParams> {
  const rawLimit = query.limit;
  const rawOffset = query.offset;
  const rawCursor = query.cursor;

  const hasAny = rawLimit !== undefined || rawOffset !== undefined || rawCursor !== undefined;
  if (!hasAny) {
    return { ok: true, value: { isPaginated: false } };
  }

  let take = 50;
  if (rawLimit !== undefined && rawLimit !== '') {
    const parsedLimit = Number(rawLimit);
    if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > maxLimit) {
      return { ok: false, error: `limit must be an integer between 1 and ${maxLimit}.` };
    }
    take = parsedLimit;
  }

  let skip: number | undefined;
  if (rawOffset !== undefined && rawOffset !== '') {
    const parsedOffset = Number(rawOffset);
    if (!Number.isInteger(parsedOffset) || parsedOffset < 0) {
      return { ok: false, error: 'offset must be a non-negative integer.' };
    }
    skip = parsedOffset;
  }

  let cursorId: string | undefined;
  if (rawCursor !== undefined && rawCursor !== '') {
    if (typeof rawCursor !== 'string' || !rawCursor.trim()) {
      return { ok: false, error: 'cursor must be a non-empty string.' };
    }
    cursorId = rawCursor.trim();
  }

  return {
    ok: true,
    value: {
      isPaginated: true,
      take,
      skip: cursorId ? 1 : skip,
      cursorId,
    },
  };
}

export function buildPrismaPaginationArgs(p: PaginationParams): {
  take?: number;
  skip?: number;
  cursor?: { id: string };
} {
  if (!p.isPaginated) return {};
  return {
    ...(p.take !== undefined ? { take: p.take } : {}),
    ...(p.skip !== undefined ? { skip: p.skip } : {}),
    ...(p.cursorId ? { cursor: { id: p.cursorId } } : {}),
  };
}

/**
 * Centralized error mapper (API-08):
 * Never leaks raw Prisma/PostgreSQL messages or stack traces to clients.
 */
export function handleRouteError(res: Response, error: unknown, context: string) {
  const err = error as { code?: string; meta?: { target?: unknown; field_name?: string }; message?: string };
  logger.error('route_error', {
    context,
    code: err?.code || null,
    error: err?.message || String(error),
  });

  if (err?.code === 'P2025') {
    return res.status(404).json({ error: 'Record not found.' });
  }
  if (err?.code === 'P2002') {
    return res.status(409).json({ error: 'A record with this unique value already exists.' });
  }
  if (err?.code === 'P2003') {
    return res.status(409).json({
      error: 'Cannot complete operation because related records depend on this item or a referenced record does not exist.',
    });
  }
  if (err?.code === 'P2023') {
    return res.status(400).json({ error: 'Invalid identifier format.' });
  }

  return res.status(500).json({ error: 'Internal server error.' });
}
