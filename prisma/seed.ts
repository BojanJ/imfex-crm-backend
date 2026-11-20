import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import crypto from 'node:crypto';

const prisma = new PrismaClient();

export async function seedDatabase() {
  console.log('🌱 Starting IMFEX CRM Minimal Database Seeding...');

  const envPassword = process.env.ADMIN_SEED_PASSWORD?.trim();
  const generatedPassword = !envPassword ? crypto.randomBytes(12).toString('base64url') : null;
  const seedPassword = envPassword || generatedPassword!;
  const adminPasswordHash = bcrypt.hashSync(seedPassword, 10);

  // Ensure only the Super Admin user is present (no demo/dummy records)
  await prisma.profile.upsert({
    where: { email: 'admin@imfex.com' },
    update: {
      passwordHash: adminPasswordHash,
      mustChangePassword: Boolean(generatedPassword),
      status: 'ACTIVE',
    },
    create: {
      id: '11111111-1111-1111-1111-111111111111',
      email: 'admin@imfex.com',
      fullName: 'Супер Администратор',
      role: 'SUPER_ADMIN',
      passwordHash: adminPasswordHash,
      mustChangePassword: Boolean(generatedPassword),
      status: 'ACTIVE',
    },
  });

  if (generatedPassword) {
    console.log('✅ Minimal seed complete for admin@imfex.com. Generated one-time password (change on first login):', generatedPassword);
  } else {
    console.log('✅ Minimal seed complete for admin@imfex.com (using ADMIN_SEED_PASSWORD).');
  }
}

if (require.main === module) {
  seedDatabase()
    .catch((e) => {
      console.error(e);
      process.exit(1);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
