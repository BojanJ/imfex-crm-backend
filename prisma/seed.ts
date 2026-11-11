import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

export async function seedDatabase() {
  console.log('🌱 Starting IMFEX CRM Minimal Database Seeding...');

  const adminPasswordHash = bcrypt.hashSync('admin123', 10);

  // Ensure only the Super Admin user is present (no demo/dummy records)
  await prisma.profile.upsert({
    where: { email: 'admin@imfex.com' },
    update: {
      passwordHash: adminPasswordHash,
      mustChangePassword: false,
      status: 'ACTIVE',
    },
    create: {
      id: '11111111-1111-1111-1111-111111111111',
      email: 'admin@imfex.com',
      fullName: 'Супер Администратор',
      role: 'SUPER_ADMIN',
      passwordHash: adminPasswordHash,
      mustChangePassword: false,
      status: 'ACTIVE',
    },
  });

  console.log('✅ Minimal seed complete: admin@imfex.com (admin123)');
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
