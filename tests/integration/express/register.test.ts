import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../helpers/testApp.ts';
import { clearDatabase, startMemoryMongo, stopMemoryMongo } from '../../helpers/mongoMemoryServer.ts';
import { resetRateLimiters } from '../../helpers/rateLimit.ts';
import { makeRegisterData } from '../../fixtures/testUsers.ts';

describe('POST /api/auth/register', () => {
    let app: ReturnType<typeof createTestApp>;

    beforeAll(async () => {
        await startMemoryMongo();
        app = createTestApp();
    }, 180000);

    afterAll(async () => {
        await stopMemoryMongo();
    });

    beforeEach(async () => {
        await clearDatabase();
        await resetRateLimiters();
    });

    it('registers with 201 and sets both auth cookies (HttpOnly)', async () => {
        const data = makeRegisterData();

        const res = await request(app).post('/api/auth/register').send(data);

        expect(res.status).toBe(201);
        expect(res.body).toEqual({ success: true, message: 'User registered successfully' });
        const cookies = res.headers['set-cookie'] as unknown as string[];
        expect(cookies.some((c) => c.startsWith('accessToken=') && c.includes('HttpOnly'))).toBe(true);
        expect(cookies.some((c) => c.startsWith('refreshToken=') && c.includes('HttpOnly'))).toBe(true);
    });

    it('rejects a duplicate email with 409', async () => {
        const data = makeRegisterData();
        await request(app).post('/api/auth/register').send(data);

        const res = await request(app).post('/api/auth/register').send(data);

        expect(res.status).toBe(409);
        expect(res.body).toEqual({ success: false, message: 'Email already in use' });
    });

    it('rejects a weak password with the 422 validation shape', async () => {
        const res = await request(app)
            .post('/api/auth/register')
            .send({ ...makeRegisterData(), password: 'weak' });

        expect(res.status).toBe(422);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toBe('Validation failed');
        expect(Array.isArray(res.body.errors)).toBe(true);
        expect(res.body.errors.some((e: { field: string }) => e.field === 'password')).toBe(true);
    });

    it('rejects a missing name with 422', async () => {
        const data = makeRegisterData() as Record<string, unknown>;
        delete data.name;

        const res = await request(app).post('/api/auth/register').send(data);

        expect(res.status).toBe(422);
        expect(res.body.success).toBe(false);
    });
});
