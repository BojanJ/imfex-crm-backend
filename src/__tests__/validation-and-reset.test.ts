import { describe, it, expect } from 'vitest';
import {
  isUuid,
  parseEnum,
  parseOptionalDate,
  parseFiniteNumber,
  parsePagination,
  buildPrismaPaginationArgs,
  handleRouteError,
  OFFER_STATUSES,
} from '../validation';
import { formatOfferForResponse } from '../lib/formatters';
import { formatDocumentForList } from '../storage';
import { buildCorsOptions } from '../security';

describe('Validation helpers (API-07, API-08)', () => {
  it('validates UUIDs strictly', () => {
    expect(isUuid('11111111-1111-4111-8111-111111111111')).toBe(true);
    expect(isUuid('not-a-uuid')).toBe(false);
    expect(isUuid('')).toBe(false);
  });

  it('validates enums and defaults', () => {
    expect(parseEnum('ACCEPTED', OFFER_STATUSES, 'status')).toEqual({ ok: true, value: 'ACCEPTED' });
    expect(parseEnum(undefined, OFFER_STATUSES, 'status', 'DRAFT')).toEqual({ ok: true, value: 'DRAFT' });
    expect(parseEnum('INVALID', OFFER_STATUSES, 'status').ok).toBe(false);
  });

  it('rejects Invalid Date values cleanly', () => {
    expect(parseOptionalDate('2026-11-21', 'validUntil').ok).toBe(true);
    expect(parseOptionalDate('', 'validUntil')).toEqual({ ok: true, value: null });
    expect(parseOptionalDate('not-a-date', 'validUntil').ok).toBe(false);
  });

  it('preserves 0% numeric values while rejecting out-of-range values', () => {
    expect(parseFiniteNumber(0, 'taxRate', { min: 0, max: 100, defaultVal: 18 })).toEqual({ ok: true, value: 0 });
    expect(parseFiniteNumber(undefined, 'taxRate', { min: 0, max: 100, defaultVal: 18 })).toEqual({
      ok: true,
      value: 18,
    });
    expect(parseFiniteNumber(-1, 'taxRate', { min: 0, max: 100 }).ok).toBe(false);
    expect(parseFiniteNumber(150, 'taxRate', { min: 0, max: 100 }).ok).toBe(false);
  });

  it('parses pagination query parameters and rejects bad limits', () => {
    expect(parsePagination({})).toEqual({ ok: true, value: { isPaginated: false } });
    expect(parsePagination({ limit: '25', offset: '50' })).toEqual({
      ok: true,
      value: { isPaginated: true, take: 25, skip: 50, cursorId: undefined },
    });
    expect(parsePagination({ limit: 'abc' }).ok).toBe(false);
    expect(parsePagination({ limit: '9999' }).ok).toBe(false);
  });

  it('maps Prisma error codes to clean HTTP statuses without leaking internals', () => {
    const makeRes = () => {
      let status = 200;
      let body: any = null;
      return {
        res: {
          status(code: number) {
            status = code;
            return this;
          },
          json(data: any) {
            body = data;
            return this;
          },
        } as any,
        getStatus: () => status,
        getBody: () => body,
      };
    };

    const r404 = makeRes();
    handleRouteError(r404.res, { code: 'P2025', message: 'secret prisma details' }, 'test');
    expect(r404.getStatus()).toBe(404);
    expect(r404.getBody().error).not.toContain('secret');

    const r409 = makeRes();
    handleRouteError(r409.res, { code: 'P2003', message: 'fk detail' }, 'test');
    expect(r409.getStatus()).toBe(409);

    const r500 = makeRes();
    handleRouteError(r500.res, new Error('SELECT * FROM secret_table'), 'test');
    expect(r500.getStatus()).toBe(500);
    expect(r500.getBody().error).toBe('Internal server error.');
  });
});

describe('Round 2 API Hardening (API-15, API-18, API-19, API-21)', () => {
  it('rejects booleans, arrays, objects, and blank strings in parseFiniteNumber (API-19)', () => {
    expect(parseFiniteNumber(true, 'price').ok).toBe(false);
    expect(parseFiniteNumber(false, 'price').ok).toBe(false);
    expect(parseFiniteNumber([], 'price').ok).toBe(false);
    expect(parseFiniteNumber({}, 'price').ok).toBe(false);
    expect(parseFiniteNumber('   ', 'price').ok).toBe(false);
    expect(parseFiniteNumber('   ', 'price', { defaultVal: 10 })).toEqual({ ok: true, value: 10 });
    expect(parseFiniteNumber('42.5', 'price')).toEqual({ ok: true, value: 42.5 });
  });

  it('exposes pagination and rate-limit headers in CORS config (API-15)', () => {
    const cors = buildCorsOptions();
    expect(cors.exposedHeaders).toEqual(
      expect.arrayContaining(['X-Total-Count', 'X-Request-Id', 'Retry-After'])
    );
  });

  it('avoids fabricating empty items[] and strips duplicate spec keys in formatOfferForResponse (API-18)', () => {
    const nested = formatOfferForResponse({ id: 'o1', totalAmount: '500.00' });
    expect('items' in nested).toBe(false);

    const full = formatOfferForResponse({
      id: 'o2',
      totalAmount: '500.00',
      items: [
        {
          id: 'i1',
          quantity: 1,
          unitPrice: '500',
          totalPrice: '500',
          offerItemSpecifications: [
            { id: 's1', specificationKeyId: 'k1', specificationOptionId: 'opt1', customPriceModifier: '50' },
            { id: 's2', specificationKeyId: null, specificationOptionId: null, customKeyName: 'Extra', customPriceModifier: '25' },
          ],
        },
      ],
    });
    expect('offerItemSpecifications' in full.items[0]).toBe(false);
    expect(full.items[0].specifications[0].customPriceModifier).toBeUndefined();
    expect(full.items[0].specifications[1].customPriceModifier).toBe(25);
  });

  it('handles SQL-omitted fileUrl cleanly and caps unpaginated list queries (API-21)', () => {
    const projected = formatDocumentForList({ id: 'd1', title: 'Spec.pdf', fileName: 'spec.pdf', sizeBytes: 12000 }, false);
    expect(projected.fileUrl).toBe('');
    expect(projected.hasFile).toBe(true);

    const noFile = formatDocumentForList({ id: 'd2', title: 'Quote', fileName: null, sizeBytes: null }, false);
    expect(noFile.hasFile).toBe(false);

    expect(buildPrismaPaginationArgs({ isPaginated: false }).take).toBe(500);
  });
});
