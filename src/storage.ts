import crypto from 'node:crypto';
import { logger } from './logger';

const STORAGE_PREFIX = 'storage://';

function getStorageConfig() {
  const url = process.env.SUPABASE_URL?.trim().replace(/\/+$/, '');
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  const bucket = process.env.SUPABASE_STORAGE_BUCKET?.trim() || 'client-documents';
  if (!url || !key) return null;
  return { url, key, bucket };
}

export function isObjectStorageConfigured(): boolean {
  return getStorageConfig() !== null;
}

export function isStorageRef(fileUrl: unknown): boolean {
  return typeof fileUrl === 'string' && fileUrl.startsWith(STORAGE_PREFIX);
}

export function isInlineDataUrl(fileUrl: unknown): boolean {
  return typeof fileUrl === 'string' && fileUrl.startsWith('data:');
}

function parseDataUrl(dataUrl: string): { mime: string; buffer: Buffer } | null {
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/i);
  if (!match) return null;
  try {
    return {
      mime: match[1].toLowerCase().trim(),
      buffer: Buffer.from(match[2].trim(), 'base64'),
    };
  } catch {
    return null;
  }
}

/**
 * Uploads a validated `data:` URL to Supabase Storage if configured.
 * Falls back to storing the validated `data:` URL in Postgres when object storage
 * environment variables (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`) are not yet set.
 */
export async function persistDocumentPayload(
  fileUrl: string,
  fileName?: string | null
): Promise<{ storedUrl: string; sizeBytes?: number }> {
  if (!isInlineDataUrl(fileUrl)) {
    return { storedUrl: fileUrl };
  }

  const parsed = parseDataUrl(fileUrl);
  if (!parsed) {
    return { storedUrl: fileUrl };
  }

  const cfg = getStorageConfig();
  if (!cfg) {
    return { storedUrl: fileUrl, sizeBytes: parsed.buffer.length };
  }

  const safeName = (fileName || 'document')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, 80);
  const objectPath = `${new Date().getUTCFullYear()}/${crypto.randomUUID()}-${safeName}`;

  try {
    const uploadRes = await fetch(
      `${cfg.url}/storage/v1/object/${encodeURIComponent(cfg.bucket)}/${objectPath}`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${cfg.key}`,
          apikey: cfg.key,
          'Content-Type': parsed.mime,
          'x-upsert': 'false',
        },
        body: new Uint8Array(parsed.buffer),
      }
    );

    if (!uploadRes.ok) {
      logger.warn('storage_upload_fallback', { status: uploadRes.status });
      return { storedUrl: fileUrl, sizeBytes: parsed.buffer.length };
    }

    return {
      storedUrl: `${STORAGE_PREFIX}${cfg.bucket}/${objectPath}`,
      sizeBytes: parsed.buffer.length,
    };
  } catch (err: any) {
    logger.warn('storage_network_fallback', { error: err?.message || String(err) });
    return { storedUrl: fileUrl, sizeBytes: parsed.buffer.length };
  }
}

/**
 * Resolves a stored `storage://bucket/path` reference back to a `data:` URL or Buffer.
 */
export async function resolveDocumentBinary(
  storedUrl: string,
  fallbackMime = 'application/octet-stream'
): Promise<{ buffer: Buffer; mime: string } | null> {
  if (isInlineDataUrl(storedUrl)) {
    const parsed = parseDataUrl(storedUrl);
    return parsed ? { buffer: parsed.buffer, mime: parsed.mime } : null;
  }

  if (isStorageRef(storedUrl)) {
    const cfg = getStorageConfig();
    if (!cfg) return null;
    const refPath = storedUrl.slice(STORAGE_PREFIX.length);
    const slashIdx = refPath.indexOf('/');
    if (slashIdx <= 0) return null;
    const bucket = refPath.slice(0, slashIdx);
    const objectPath = refPath.slice(slashIdx + 1);

    const res = await fetch(
      `${cfg.url}/storage/v1/object/${encodeURIComponent(bucket)}/${objectPath}`,
      {
        headers: {
          Authorization: `Bearer ${cfg.key}`,
          apikey: cfg.key,
        },
      }
    );
    if (!res.ok) return null;
    const arrBuf = await res.arrayBuffer();
    const mime = res.headers.get('content-type') || fallbackMime;
    return { buffer: Buffer.from(arrBuf), mime };
  }

  return null;
}

export async function deleteStoredDocumentObject(storedUrl: string): Promise<void> {
  if (!isStorageRef(storedUrl)) return;
  const cfg = getStorageConfig();
  if (!cfg) return;
  const refPath = storedUrl.slice(STORAGE_PREFIX.length);
  const slashIdx = refPath.indexOf('/');
  if (slashIdx <= 0) return;
  const bucket = refPath.slice(0, slashIdx);
  const objectPath = refPath.slice(slashIdx + 1);

  try {
    await fetch(
      `${cfg.url}/storage/v1/object/${encodeURIComponent(bucket)}/${objectPath}`,
      {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${cfg.key}`,
          apikey: cfg.key,
        },
      }
    );
  } catch (err: any) {
    logger.warn('storage_delete_failed', { error: err?.message || String(err) });
  }
}

export const DOCUMENT_LIST_SELECT = {
  id: true,
  customerId: true,
  offerId: true,
  projectId: true,
  serviceId: true,
  title: true,
  fileType: true,
  fileName: true,
  sizeBytes: true,
  createdAt: true,
} as const;

/**
 * Strips heavy inline base64 blobs from document list responses unless `includeData` is true,
 * adding `hasFile` so the client knows it can fetch `/api/client-documents/:id` on demand.
 * Also supports SQL-projected rows where `fileUrl` was omitted at query time (API-21).
 */
export function formatDocumentForList(doc: any, includeData = false) {
  if (!doc) return doc;
  if (doc.fileUrl === undefined) {
    const hasFile = Boolean((typeof doc.sizeBytes === 'number' && doc.sizeBytes > 0) || doc.fileName);
    return {
      ...doc,
      fileUrl: '',
      hasFile,
    };
  }
  const rawUrl = typeof doc.fileUrl === 'string' ? doc.fileUrl : '';
  const hasFile = Boolean(rawUrl && rawUrl !== '#');
  if (includeData) {
    return { ...doc, hasFile };
  }
  const isHeavy = isInlineDataUrl(rawUrl) || isStorageRef(rawUrl);
  return {
    ...doc,
    fileUrl: isHeavy ? '' : rawUrl,
    hasFile,
  };
}
