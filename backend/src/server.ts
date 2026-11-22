import 'dotenv/config';
import { createHash, randomBytes } from 'node:crypto';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { PrismaClient, type User } from '@prisma/client';
import argon2 from 'argon2';
import { z, ZodError } from 'zod';

const Env = z.object({
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  ACCESS_TOKEN_TTL: z.string().default('15m'),
  REFRESH_TOKEN_DAYS: z.coerce.number().int().positive().default(30),
  CORS_ORIGINS: z.string().default('http://localhost:8081')
}).parse(process.env);

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { sub: string; email: string };
    user: { sub: string; email: string };
  }
}

const prisma = new PrismaClient();
const app = Fastify({ logger: true });

await app.register(helmet);
await app.register(cors, {
  origin: Env.CORS_ORIGINS.split(',').map((v) => v.trim()).filter(Boolean),
  credentials: true
});
await app.register(rateLimit, { max: 150, timeWindow: '1 minute' });
await app.register(jwt, { secret: Env.JWT_SECRET });
await app.register(swagger, {
  openapi: {
    info: { title: 'petHelper API', version: '0.1.0' },
    servers: [{ url: 'http://localhost:3000' }]
  }
});
await app.register(swaggerUi, { routePrefix: '/docs' });

const authenticate = async (request: FastifyRequest, reply: FastifyReply) => {
  try {
    await request.jwtVerify();
  } catch {
    return reply.code(401).send({ error: 'Unauthorized' });
  }
};

const hashToken = (token: string) =>
  createHash('sha256').update(token).digest('hex');

const createSession = async (user: Pick<User, 'id' | 'email'>) => {
  const refreshToken = randomBytes(48).toString('base64url');
  const refreshExpiresAt = new Date(
    Date.now() + Env.REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000
  );

  await prisma.session.create({
    data: {
      userId: user.id,
      tokenHash: hashToken(refreshToken),
      expiresAt: refreshExpiresAt
    }
  });

  const accessToken = app.jwt.sign(
    { sub: user.id, email: user.email },
    { expiresIn: Env.ACCESS_TOKEN_TTL }
  );

  return { accessToken, refreshToken, refreshExpiresAt };
};

const ownedPet = (userId: string, petId: string) =>
  prisma.pet.findFirst({ where: { id: petId, ownerId: userId } });

const petIdParams = z.object({ petId: z.string().min(1) });
const idParams = z.object({ id: z.string().min(1) });

app.get('/health', async () => ({
  status: 'ok',
  service: 'pethelper-backend',
  timestamp: new Date().toISOString()
}));

const registerBody = z.object({
  email: z.string().email().transform((value) => value.trim().toLowerCase()),
  password: z.string().min(8).max(128),
  name: z.string().trim().min(1).max(100).optional(),
  timezone: z.string().min(1).max(100).optional()
});

app.post('/api/v1/auth/register', async (request, reply) => {
  const body = registerBody.parse(request.body);
  const existing = await prisma.user.findUnique({ where: { email: body.email } });
  if (existing) return reply.code(409).send({ error: 'Email already registered' });

  const user = await prisma.user.create({
    data: {
      email: body.email,
      passwordHash: await argon2.hash(body.password, { type: argon2.argon2id }),
      name: body.name,
      timezone: body.timezone
    },
    select: {
      id: true,
      email: true,
      name: true,
      avatarUrl: true,
      timezone: true,
      createdAt: true
    }
  });

  return reply.code(201).send({ user, ...(await createSession(user)) });
});

const loginBody = registerBody.pick({ email: true, password: true });

app.post('/api/v1/auth/login', async (request, reply) => {
  const body = loginBody.parse(request.body);
  const user = await prisma.user.findUnique({ where: { email: body.email } });

  if (!user || !(await argon2.verify(user.passwordHash, body.password))) {
    return reply.code(401).send({ error: 'Invalid email or password' });
  }

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl,
      timezone: user.timezone
    },
    ...(await createSession(user))
  };
});

const refreshBody = z.object({ refreshToken: z.string().min(20) });

app.post('/api/v1/auth/refresh', async (request, reply) => {
  const { refreshToken } = refreshBody.parse(request.body);
  const session = await prisma.session.findUnique({
    where: { tokenHash: hashToken(refreshToken) },
    include: { user: true }
  });

  if (!session || session.revokedAt || session.expiresAt <= new Date()) {
    return reply.code(401).send({ error: 'Invalid or expired refresh token' });
  }

  await prisma.session.update({
    where: { id: session.id },
    data: { revokedAt: new Date() }
  });

  return createSession(session.user);
});

app.post('/api/v1/auth/logout', async (request, reply) => {
  const { refreshToken } = refreshBody.parse(request.body);
  await prisma.session.updateMany({
    where: { tokenHash: hashToken(refreshToken), revokedAt: null },
    data: { revokedAt: new Date() }
  });
  return reply.code(204).send();
});

app.get('/api/v1/users/me', { onRequest: authenticate }, async (request) =>
  prisma.user.findUniqueOrThrow({
    where: { id: request.user.sub },
    select: {
      id: true,
      email: true,
      name: true,
      avatarUrl: true,
      timezone: true,
      createdAt: true,
      updatedAt: true
    }
  })
);

const profileBody = z.object({
  name: z.string().trim().min(1).max(100).nullable().optional(),
  avatarUrl: z.string().url().nullable().optional(),
  timezone: z.string().min(1).max(100).optional()
});

app.patch('/api/v1/users/me', { onRequest: authenticate }, async (request) =>
  prisma.user.update({
    where: { id: request.user.sub },
    data: profileBody.parse(request.body),
    select: {
      id: true,
      email: true,
      name: true,
      avatarUrl: true,
      timezone: true,
      createdAt: true,
      updatedAt: true
    }
  })
);

const petBody = z.object({
  name: z.string().trim().min(1).max(100),
  species: z.string().trim().min(1).max(60),
  breed: z.string().trim().max(100).nullable().optional(),
  sex: z.enum(['MALE', 'FEMALE', 'UNKNOWN']).optional(),
  dateOfBirth: z.coerce.date().nullable().optional(),
  color: z.string().trim().max(100).nullable().optional(),
  photoUrl: z.string().url().nullable().optional(),
  microchipId: z.string().trim().max(100).nullable().optional(),
  notes: z.string().max(5000).nullable().optional()
});

app.get('/api/v1/pets', { onRequest: authenticate }, async (request) =>
  prisma.pet.findMany({
    where: { ownerId: request.user.sub },
    orderBy: { createdAt: 'desc' },
    include: {
      _count: {
        select: {
          medicalRecords: true,
          reminders: true,
          appointments: true,
          weights: true
        }
      }
    }
  })
);

app.post('/api/v1/pets', { onRequest: authenticate }, async (request, reply) => {
  const pet = await prisma.pet.create({
    data: { ownerId: request.user.sub, ...petBody.parse(request.body) }
  });
  return reply.code(201).send(pet);
});

app.get('/api/v1/pets/:id', { onRequest: authenticate }, async (request, reply) => {
  const { id } = idParams.parse(request.params);
  const pet = await prisma.pet.findFirst({
    where: { id, ownerId: request.user.sub },
    include: {
      weights: { orderBy: { measuredAt: 'desc' }, take: 10 },
      medicalRecords: { orderBy: { occurredAt: 'desc' }, take: 10 },
      reminders: { where: { status: 'ACTIVE' }, orderBy: { scheduledAt: 'asc' }, take: 10 },
      appointments: { orderBy: { scheduledAt: 'desc' }, take: 10 }
    }
  });
  if (!pet) return reply.code(404).send({ error: 'Pet not found' });
  return pet;
});

app.patch('/api/v1/pets/:id', { onRequest: authenticate }, async (request, reply) => {
  const { id } = idParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, id))) {
    return reply.code(404).send({ error: 'Pet not found' });
  }
  return prisma.pet.update({ where: { id }, data: petBody.partial().parse(request.body) });
});

app.delete('/api/v1/pets/:id', { onRequest: authenticate }, async (request, reply) => {
  const { id } = idParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, id))) {
    return reply.code(404).send({ error: 'Pet not found' });
  }
  await prisma.pet.delete({ where: { id } });
  return reply.code(204).send();
});

const weightBody = z.object({
  weightKg: z.coerce.number().positive().max(1000),
  measuredAt: z.coerce.date().default(() => new Date()),
  notes: z.string().max(1000).nullable().optional()
});

app.get('/api/v1/pets/:petId/weights', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return prisma.weightEntry.findMany({ where: { petId }, orderBy: { measuredAt: 'desc' } });
});

app.post('/api/v1/pets/:petId/weights', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return reply.code(201).send(
    await prisma.weightEntry.create({ data: { petId, ...weightBody.parse(request.body) } })
  );
});

const medicalBody = z.object({
  type: z.enum(['VACCINATION', 'MEDICATION', 'ALLERGY', 'CONDITION', 'CHECKUP', 'SURGERY', 'LAB_RESULT', 'NOTE']),
  title: z.string().trim().min(1).max(200),
  details: z.string().max(10000).nullable().optional(),
  provider: z.string().trim().max(200).nullable().optional(),
  occurredAt: z.coerce.date(),
  nextDueAt: z.coerce.date().nullable().optional()
});
const recordParams = z.object({ petId: z.string().min(1), recordId: z.string().min(1) });

app.get('/api/v1/pets/:petId/medical-records', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return prisma.medicalRecord.findMany({ where: { petId }, orderBy: { occurredAt: 'desc' } });
});

app.post('/api/v1/pets/:petId/medical-records', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return reply.code(201).send(
    await prisma.medicalRecord.create({ data: { petId, ...medicalBody.parse(request.body) } })
  );
});

app.patch('/api/v1/pets/:petId/medical-records/:recordId', { onRequest: authenticate }, async (request, reply) => {
  const { petId, recordId } = recordParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  const record = await prisma.medicalRecord.findFirst({ where: { id: recordId, petId } });
  if (!record) return reply.code(404).send({ error: 'Medical record not found' });
  return prisma.medicalRecord.update({
    where: { id: recordId },
    data: medicalBody.partial().parse(request.body)
  });
});

app.delete('/api/v1/pets/:petId/medical-records/:recordId', { onRequest: authenticate }, async (request, reply) => {
  const { petId, recordId } = recordParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  const result = await prisma.medicalRecord.deleteMany({ where: { id: recordId, petId } });
  if (!result.count) return reply.code(404).send({ error: 'Medical record not found' });
  return reply.code(204).send();
});

const reminderBody = z.object({
  title: z.string().trim().min(1).max(200),
  description: z.string().max(5000).nullable().optional(),
  scheduledAt: z.coerce.date(),
  repeatType: z.enum(['NONE', 'DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']).optional(),
  status: z.enum(['ACTIVE', 'COMPLETED', 'CANCELLED']).optional()
});
const reminderParams = z.object({ petId: z.string().min(1), reminderId: z.string().min(1) });

app.get('/api/v1/pets/:petId/reminders', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return prisma.reminder.findMany({ where: { petId }, orderBy: { scheduledAt: 'asc' } });
});

app.post('/api/v1/pets/:petId/reminders', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return reply.code(201).send(
    await prisma.reminder.create({ data: { petId, ...reminderBody.parse(request.body) } })
  );
});

app.patch('/api/v1/pets/:petId/reminders/:reminderId', { onRequest: authenticate }, async (request, reply) => {
  const { petId, reminderId } = reminderParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  const reminder = await prisma.reminder.findFirst({ where: { id: reminderId, petId } });
  if (!reminder) return reply.code(404).send({ error: 'Reminder not found' });
  return prisma.reminder.update({
    where: { id: reminderId },
    data: reminderBody.partial().parse(request.body)
  });
});

app.delete('/api/v1/pets/:petId/reminders/:reminderId', { onRequest: authenticate }, async (request, reply) => {
  const { petId, reminderId } = reminderParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  const result = await prisma.reminder.deleteMany({ where: { id: reminderId, petId } });
  if (!result.count) return reply.code(404).send({ error: 'Reminder not found' });
  return reply.code(204).send();
});

const appointmentBody = z.object({
  clinicName: z.string().trim().max(200).nullable().optional(),
  vetName: z.string().trim().max(200).nullable().optional(),
  address: z.string().trim().max(500).nullable().optional(),
  reason: z.string().trim().min(1).max(500),
  scheduledAt: z.coerce.date(),
  status: z.enum(['SCHEDULED', 'COMPLETED', 'CANCELLED']).optional(),
  notes: z.string().max(5000).nullable().optional()
});
const appointmentParams = z.object({ petId: z.string().min(1), appointmentId: z.string().min(1) });

app.get('/api/v1/pets/:petId/appointments', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return prisma.appointment.findMany({ where: { petId }, orderBy: { scheduledAt: 'asc' } });
});

app.post('/api/v1/pets/:petId/appointments', { onRequest: authenticate }, async (request, reply) => {
  const { petId } = petIdParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  return reply.code(201).send(
    await prisma.appointment.create({ data: { petId, ...appointmentBody.parse(request.body) } })
  );
});

app.patch('/api/v1/pets/:petId/appointments/:appointmentId', { onRequest: authenticate }, async (request, reply) => {
  const { petId, appointmentId } = appointmentParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  const appointment = await prisma.appointment.findFirst({ where: { id: appointmentId, petId } });
  if (!appointment) return reply.code(404).send({ error: 'Appointment not found' });
  return prisma.appointment.update({
    where: { id: appointmentId },
    data: appointmentBody.partial().parse(request.body)
  });
});

app.delete('/api/v1/pets/:petId/appointments/:appointmentId', { onRequest: authenticate }, async (request, reply) => {
  const { petId, appointmentId } = appointmentParams.parse(request.params);
  if (!(await ownedPet(request.user.sub, petId))) return reply.code(404).send({ error: 'Pet not found' });
  const result = await prisma.appointment.deleteMany({ where: { id: appointmentId, petId } });
  if (!result.count) return reply.code(404).send({ error: 'Appointment not found' });
  return reply.code(204).send();
});

app.setErrorHandler((error, _request, reply) => {
  if (error instanceof ZodError) {
    return reply.code(400).send({ error: 'Validation error', issues: error.issues });
  }

  app.log.error(error);
  const statusCode =
    typeof (error as { statusCode?: unknown }).statusCode === 'number'
      ? (error as { statusCode: number }).statusCode
      : 500;

  return reply
    .code(statusCode)
    .send({ error: statusCode === 500 ? 'Internal server error' : error.message });
});

app.addHook('onClose', async () => prisma.$disconnect());

try {
  await prisma.$connect();
  await app.listen({ host: Env.HOST, port: Env.PORT });
} catch (error) {
  app.log.error(error);
  await prisma.$disconnect();
  process.exit(1);
}
