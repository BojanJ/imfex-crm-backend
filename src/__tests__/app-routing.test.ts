import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { createApp } from '../app';
import { buildPooledDatabaseUrl } from '../lib/prisma';
import {
  formatOfferForResponse,
  formatProductForResponse,
  formatProjectForResponse,
  formatSalesInvoice,
} from '../lib/formatters';

describe('Modular Express App & Routing (IMP-01)', () => {
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    const app = createApp();
    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('serves /health with security headers and X-Request-Id', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('x-powered-by')).toBeNull();
    expect(res.headers.get('x-request-id')).toBeTruthy();

    const body = (await res.json()) as { status: string; service: string };
    expect(body.status).toBe('ok');
    expect(body.service).toContain('IMFEX');
  });

  it('enforces authentication across all protected modular routers', async () => {
    const protectedEndpoints = [
      '/api/auth/me',
      '/api/profiles',
      '/api/categories',
      '/api/products',
      '/api/customers',
      '/api/offers',
      '/api/projects',
      '/api/service-tickets',
      '/api/installed-items',
      '/api/client-documents',
      '/api/calendar-events',
      '/api/purchase-invoices',
      '/api/sales-invoices',
      '/api/dispatch-notes',
      '/api/payments',
      '/api/inventory-movements',
      '/api/company-settings',
      '/api/audit-logs',
    ];

    const responses = await Promise.all(protectedEndpoints.map((p) => fetch(`${baseUrl}${p}`)));
    for (const res of responses) {
      expect(res.status).toBe(401);
    }

    const invoiceEmailRes = await fetch(`${baseUrl}/api/email/send-invoice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: 'client@example.com', invoiceNumber: 'FAK-2026-0001' }),
    });
    expect(invoiceEmailRes.status).toBe(401);
  });

  it('validates public auth endpoints before hitting DB', async () => {
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: '', password: '' }),
    });
    expect(loginRes.status).toBe(400);

    const forgotRes = await fetch(`${baseUrl}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'not-an-email' }),
    });
    expect(forgotRes.status).toBe(400);

    const resetRes = await fetch(`${baseUrl}/api/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'short', newPassword: '123' }),
    });
    expect(resetRes.status).toBe(400);

    // Malformed JSON returns JSON 400 instead of Express HTML error page (API-19)
    const malformedRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{invalid-json',
    });
    expect(malformedRes.status).toBe(400);
    const malformedBody = (await malformedRes.json()) as { error?: string };
    expect(malformedBody.error).toContain('Malformed JSON');
  });

  it('upgrades Supabase session pooler URLs (5432 -> 6543) with pgbouncer params', () => {
    const upgraded = buildPooledDatabaseUrl(
      'postgresql://user:pass@aws-0-eu-north-1.pooler.supabase.com:5432/postgres'
    );
    expect(upgraded).toContain(':6543/');
    expect(upgraded).toContain('pgbouncer=true');
    expect(upgraded).toContain('statement_cache_size=0');
    expect(upgraded).toContain('connection_limit=5');
  });

  it('serializes Decimal-like fields cleanly in shared formatters', () => {
    const prod = formatProductForResponse({
      id: 'p1',
      stockQuantity: '4',
      purchasePrice: '125.50',
      models: [{ id: 'm1', basePrice: '399.99' }],
      specificationKeys: [{ id: 'k1', options: [{ id: 'o1', priceModifier: '15.25' }] }],
    });
    expect(prod.stockQuantity).toBe(4);
    expect(prod.purchasePrice).toBe(125.5);
    expect(prod.models[0].basePrice).toBe(399.99);
    expect(prod.specificationKeys[0].options[0].priceModifier).toBe(15.25);

    const offer = formatOfferForResponse({
      id: 'o1',
      taxRate: '0',
      totalAmount: '1000.00',
      items: [{ id: 'i1', quantity: '2', unitPrice: '500', totalPrice: '1000', offerItemSpecifications: [] }],
    });
    expect(offer.taxRate).toBe(0);
    expect(offer.totalAmount).toBe(1000);

    const inv = formatSalesInvoice({ id: 's1', totalAmount: '250.5', paidAmount: '100' });
    expect(inv.totalAmount).toBe(250.5);
    expect(inv.paidAmount).toBe(100);
  });

  it('enforces authentication on all single-entity GET /:id and project notes routes (IMP-10, IMP-11)', async () => {
    const sampleId = '00000000-0000-4000-8000-000000000001';
    const singleEndpoints = [
      `/api/customers/${sampleId}`,
      `/api/products/${sampleId}`,
      `/api/calendar-events/${sampleId}`,
      `/api/profiles/${sampleId}`,
      `/api/installed-items/${sampleId}`,
      `/api/purchase-invoices/${sampleId}`,
      `/api/sales-invoices/${sampleId}`,
      `/api/dispatch-notes/${sampleId}`,
      `/api/payments/${sampleId}`,
      `/api/projects/${sampleId}/notes`,
      `/api/audit-logs?limit=25&offset=0&entityType=Project&search=test`,
    ];

    const responses = await Promise.all(singleEndpoints.map((p) => fetch(`${baseUrl}${p}`)));
    for (const res of responses) {
      expect(res.status).toBe(401);
    }

    const postNoteRes = await fetch(`${baseUrl}/api/projects/${sampleId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: 'Site ready' }),
    });
    expect(postNoteRes.status).toBe(401);

    const delNoteRes = await fetch(`${baseUrl}/api/projects/${sampleId}/notes/${sampleId}`, {
      method: 'DELETE',
    });
    expect(delNoteRes.status).toBe(401);
  });

  it('flattens project workflowData and strips document base64 payloads by default (IMP-11)', () => {
    const formatted = formatProjectForResponse({
      id: 'proj-1',
      title: 'Gate Install',
      workflowData: { advancePaid: true, supplierOrdered: true, selectedMotorId: 'm-1' },
      offer: { id: 'o-1', totalAmount: '1250.50' },
      documents: [{ id: 'd-1', fileName: 'plan.pdf', fileType: 'application/pdf', fileUrl: 'data:application/pdf;base64,AAAA' }],
    });

    expect(formatted.advancePaid).toBe(true);
    expect(formatted.supplierOrdered).toBe(true);
    expect(formatted.selectedMotorId).toBe('m-1');
    expect(formatted.offer.totalAmount).toBe(1250.5);
    expect(formatted.documents[0].fileUrl).toBe('');
    expect(formatted.documents[0].hasFile).toBe(true);

    const withData = formatProjectForResponse(
      {
        id: 'proj-1',
        documents: [{ id: 'd-1', fileName: 'plan.pdf', fileType: 'application/pdf', fileUrl: 'data:application/pdf;base64,AAAA' }],
      },
      true
    );
    expect(withData.documents[0].fileUrl).toBe('data:application/pdf;base64,AAAA');
    expect(withData.documents[0].hasFile).toBe(true);
  });

  it('uses structured logger instead of raw console calls across backend runtime source (IMP-11)', () => {
    const srcRoot = path.resolve(__dirname, '..');
    const offenders: string[] = [];

    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === '__tests__') continue;
          walk(fullPath);
        } else if (entry.name.endsWith('.ts') && entry.name !== 'logger.ts') {
          const content = fs.readFileSync(fullPath, 'utf8');
          if (/\bconsole\.(log|warn|error)\s*\(/.test(content)) {
            offenders.push(path.relative(srcRoot, fullPath));
          }
        }
      }
    };

    walk(srcRoot);
    expect(offenders).toEqual([]);
  });
});
