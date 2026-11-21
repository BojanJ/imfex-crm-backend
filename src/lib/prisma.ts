import { PrismaClient } from '@prisma/client';

export function buildPooledDatabaseUrl(rawUrl?: string): string | undefined {
  if (!rawUrl) return undefined;
  try {
    const parsed = new URL(rawUrl);
    // Supabase Session Mode Pooler (port 5432) caps total clients at 15 on Free/Nano plans.
    // Upgrade runtime app queries automatically to Transaction Mode Pooler (port 6543) with pgbouncer=true.
    if (
      parsed.hostname.endsWith('.pooler.supabase.com') &&
      (parsed.port === '5432' || parsed.port === '') &&
      process.env.DISABLE_SUPABASE_TX_POOLER !== 'true'
    ) {
      parsed.port = '6543';
      parsed.searchParams.set('pgbouncer', 'true');
      parsed.searchParams.set('statement_cache_size', '0');
    }
    const desiredLimit = String(
      Math.max(1, Math.min(10, Number(process.env.PRISMA_CONNECTION_LIMIT) || 5))
    );
    if (!parsed.searchParams.has('connection_limit')) {
      parsed.searchParams.set('connection_limit', desiredLimit);
    }
    if (!parsed.searchParams.has('pool_timeout')) {
      parsed.searchParams.set('pool_timeout', '30');
    }
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

const pooledDbUrl = buildPooledDatabaseUrl(process.env.DATABASE_URL);

export const prisma = new PrismaClient(
  pooledDbUrl ? { datasources: { db: { url: pooledDbUrl } } } : undefined
);
