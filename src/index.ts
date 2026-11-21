import { createApp } from './app';
import { prisma } from './lib/prisma';
import { logger } from './logger';

const PORT = process.env.PORT || 4000;
const app = createApp();

const server = app.listen(PORT, () => {
  logger.info('server_started', { port: Number(PORT) || PORT });
});

const shutdown = async (signal: string) => {
  logger.info('server_shutdown_started', { signal });
  server.close(async () => {
    await prisma.$disconnect().catch(() => {});
    process.exit(0);
  });
  setTimeout(async () => {
    await prisma.$disconnect().catch(() => {});
    process.exit(1);
  }, 5000).unref();
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
