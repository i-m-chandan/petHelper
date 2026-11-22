# petHelper backend

REST API foundation for the petHelper mobile app.

## Stack

- Node.js 22 + TypeScript
- Fastify
- PostgreSQL
- Prisma ORM
- JWT access tokens + rotating refresh tokens
- Argon2id password hashing
- Zod validation
- Swagger/OpenAPI

## Included features

- Register, login, refresh token, and logout
- User profile
- Pet CRUD with owner isolation
- Weight history
- Medical records
- Reminders
- Vet appointments
- CORS, security headers, and rate limiting
- Health check and Swagger UI

## Run locally

```bash
cd backend
cp .env.example .env
docker compose up -d postgres
npm install
npm run prisma:generate
npm run prisma:migrate -- --name init
npm run dev
```

API: `http://localhost:3000`

Swagger UI: `http://localhost:3000/docs`

Health check: `GET /health`

## Main API routes

### Authentication

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`

### User

- `GET /api/v1/users/me`
- `PATCH /api/v1/users/me`

### Pets

- `GET /api/v1/pets`
- `POST /api/v1/pets`
- `GET /api/v1/pets/:id`
- `PATCH /api/v1/pets/:id`
- `DELETE /api/v1/pets/:id`

### Weight history

- `GET /api/v1/pets/:petId/weights`
- `POST /api/v1/pets/:petId/weights`

### Medical records

- `GET /api/v1/pets/:petId/medical-records`
- `POST /api/v1/pets/:petId/medical-records`
- `PATCH /api/v1/pets/:petId/medical-records/:recordId`
- `DELETE /api/v1/pets/:petId/medical-records/:recordId`

### Reminders

- `GET /api/v1/pets/:petId/reminders`
- `POST /api/v1/pets/:petId/reminders`
- `PATCH /api/v1/pets/:petId/reminders/:reminderId`
- `DELETE /api/v1/pets/:petId/reminders/:reminderId`

### Appointments

- `GET /api/v1/pets/:petId/appointments`
- `POST /api/v1/pets/:petId/appointments`
- `PATCH /api/v1/pets/:petId/appointments/:appointmentId`
- `DELETE /api/v1/pets/:petId/appointments/:appointmentId`

## Mobile authentication flow

Store the access token in memory and the refresh token in the platform secure credential store. Send the access token as `Authorization: Bearer <token>`. If it expires, rotate it through the refresh endpoint and retry the original request once.

## Next backend milestones

1. Email verification and password reset.
2. Device tokens and push notification delivery.
3. Pet photos and medical-document uploads.
4. Family/shared pet access.
5. Automated API integration tests.
6. Production deployment, observability, backups, and secrets management.
