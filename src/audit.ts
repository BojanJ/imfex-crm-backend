import type { PrismaClient } from '@prisma/client';
import type { AuthenticatedRequest } from './auth';
import { logger } from './logger';

export interface AuditEntryInput {
  action: string;
  entityType: string;
  entityId?: string | null;
  metadata?: Record<string, unknown> | null;
  actorUserId?: string | null;
  actorEmail?: string | null;
  ipAddress?: string | null;
}

export function getClientIp(req?: AuthenticatedRequest): string | null {
  if (!req) return null;
  // Rely on Express req.ip (respecting `trust proxy`) instead of spoofable leftmost X-Forwarded-For
  return req.ip || req.socket?.remoteAddress || null;
}

/**
 * Best-effort audit logger (IMP-07): records who created, updated, or deleted key CRM records.
 * Never throws into the main request flow if the audit write encounters a transient issue.
 */
export async function recordAudit(
  prisma: PrismaClient,
  req: AuthenticatedRequest | undefined,
  input: AuditEntryInput
): Promise<void> {
  try {
    const actorUserId = input.actorUserId ?? req?.user?.id ?? null;
    const actorEmail = input.actorEmail ?? req?.user?.email ?? null;
    const ipAddress = input.ipAddress ?? getClientIp(req);

    await prisma.auditLog.create({
      data: {
        actorUserId,
        actorEmail,
        action: input.action,
        entityType: input.entityType,
        entityId: input.entityId ?? null,
        metadata: (input.metadata ?? undefined) as any,
        ipAddress,
      },
    });
  } catch (err) {
    logger.warn('audit_log_write_failed', {
      action: input.action,
      entityType: input.entityType,
      entityId: input.entityId ?? null,
      error: err instanceof Error ? err.message : String(err),
    });
  }
}
