import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

export async function seedDatabase() {
  console.log('🌱 Starting IMFEX CRM Database Seeding (Macedonian)...');

  const adminPasswordHash = bcrypt.hashSync('admin123', 10);
  const salesPasswordHash = bcrypt.hashSync('sales123', 10);

  // 1. Seed Demo Profiles / Users
  const superAdmin = await prisma.profile.upsert({
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

  const salesUser = await prisma.profile.upsert({
    where: { email: 'sales@imfex.com' },
    update: {
      passwordHash: salesPasswordHash,
      mustChangePassword: false,
      status: 'ACTIVE',
    },
    create: {
      id: '22222222-2222-2222-2222-222222222222',
      email: 'sales@imfex.com',
      fullName: 'Менаџер за Продажба',
      role: 'USER',
      passwordHash: salesPasswordHash,
      mustChangePassword: false,
      status: 'ACTIVE',
    },
  });

  console.log('✅ Profiles seeded with bcrypt password hashes: admin@imfex.com (admin123) & sales@imfex.com (sales123)');

  // 2. Seed Products
  const garageDoor = await prisma.product.upsert({
    where: { code: 'PROD-GAR-01' },
    update: {},
    create: {
      id: 'a1111111-1111-1111-1111-111111111111',
      name: 'Сегментна Гаражна Врата',
      code: 'PROD-GAR-01',
      description: 'Двослојни топлински изолирани челични панели (40мм) со полиуретанско јадро.',
      isActive: true,
    },
  });

  const industrialWindow = await prisma.product.upsert({
    where: { code: 'PROD-WIN-02' },
    update: {},
    create: {
      id: 'a2222222-2222-2222-2222-222222222222',
      name: 'Алуминиумски Архитектонски Прозорски Систем',
      code: 'PROD-WIN-02',
      description: 'Високоперформансен термалски изолиран алуминиумски профил.',
      isActive: true,
    },
  });

  const rollerShutter = await prisma.product.upsert({
    where: { code: 'PROD-SHU-03' },
    update: {},
    create: {
      id: 'a3333333-3333-3333-3333-333333333333',
      name: 'Екструдирана Сигурносна Ролетна',
      code: 'PROD-SHU-03',
      description: 'Зајакната алуминиумска ролетна за комерцијална и станбена безбедност.',
      isActive: true,
    },
  });

  console.log('✅ Products seeded: Гаражна Врата, Прозорски Систем, Ролетна');

  // 3. Seed Models & Spec Keys for Garage Door
  const modelG1 = await prisma.productModel.create({
    data: {
      productId: garageDoor.id,
      name: 'ThermoPro 40 (40мм Изолација)',
      basePrice: 850.00,
    },
  });

  const modelG2 = await prisma.productModel.create({
    data: {
      productId: garageDoor.id,
      name: 'UltraShield 60 (60мм Изолација)',
      basePrice: 1200.00,
    },
  });

  // Specs for Garage Door
  await prisma.specificationKey.create({
    data: {
      productId: garageDoor.id,
      name: 'Површина и Завршница на Панел',
      inputType: 'SELECT',
      options: {
        create: [
          { label: 'Стуко Втиснат (Стандардна Бела)', priceModifier: 0.00 },
          { label: 'Мазна Мат - RAL 7016 Антрацит', priceModifier: 85.00 },
          { label: 'Златен Даб Дрвен Декор', priceModifier: 150.00 },
        ],
      },
    },
  });

  await prisma.specificationKey.create({
    data: {
      productId: garageDoor.id,
      name: 'Автоматизиран Мотор и Погон',
      inputType: 'SELECT',
      options: {
        create: [
          { label: 'Рачно Управување (Со синџир и брава)', priceModifier: 0.00 },
          { label: 'Somfy Dexxo Optimo Паметен Мотор (+2 далечински)', priceModifier: 240.00 },
          { label: 'Hörmann SupraMatic E Брз Погон', priceModifier: 380.00 },
        ],
      },
    },
  });

  // 4. Seed Customers
  const customerCorp = await prisma.customer.create({
    data: {
      customerType: 'COMPANY',
      name: 'Логистички Центар Скопје ДООЕЛ',
      companyName: 'Логистички Центар Скопје ДООЕЛ',
      taxId: 'MK4030012345678',
      email: 'nabavki@logistika.mk',
      phone: '+389 2 3123 456',
      address: 'Ул. Индустриска бр. 42',
      city: 'Скопје',
      notes: 'Главен комерцијален клиент. Стандардно фактурирање со 18% ДДВ.',
    },
  });

  await prisma.customer.create({
    data: {
      customerType: 'INDIVIDUAL',
      name: 'Александар Стојановски',
      email: 'alex.stojanovski@gmail.com',
      phone: '+389 70 888 999',
      address: 'Ул. Партизански Одреди 74',
      city: 'Скопје',
      notes: 'Реновирање на приватна вила.',
    },
  });

  console.log('✅ Customers seeded in Macedonian');

  // 5. Seed Sample Offer
  const sampleOffer = await prisma.offer.create({
    data: {
      offerNumber: 'OFF-2026-0001',
      customerId: customerCorp.id,
      createdByUserId: superAdmin.id,
      status: 'SENT',
      taxRate: 18.00,
      subtotal: 2540.00,
      taxAmount: 457.20,
      totalAmount: 2997.20,
      validUntil: new Date('2026-08-30'),
      items: {
        create: [
          {
            serviceTypes: ['PRODUCT', 'INSTALLATION'],
            productId: garageDoor.id,
            productModelId: modelG1.id,
            customTitle: 'Сегментна Гаражна Врата (Магацинска Врата 1)',
            widthMm: 4000,
            heightMm: 3000,
            quantity: 2,
            unitPrice: 1170.00,
            totalPrice: 2340.00,
          },
          {
            serviceTypes: ['SERVICE'],
            customTitle: 'Годишен Сервисен Преглед и Пакет за Одржување на Мотор',
            quantity: 1,
            unitPrice: 200.00,
            totalPrice: 200.00,
          },
        ],
      },
    },
  });

  console.log(`✅ Sample Offer Created: ${sampleOffer.offerNumber}`);
  console.log('🎉 Seeding finished successfully!');
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
