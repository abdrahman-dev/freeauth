import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../helpers/testApp.ts';
import { clearDatabase, startMemoryMongo, stopMemoryMongo } from '../../helpers/mongoMemoryServer.ts';
import { resetRateLimiters } from '../../helpers/rateLimit.ts';
import { FIXED_OTP, setVerifyOtp } from '../../helpers/dbSetup.ts';
import { makeRegisterData } from '../../fixtures/testUsers.ts';

describe('POST /api/auth/login', () => {
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

    async function registerVerified(data = makeRegisterData()) {
        await request(app).post('/api/auth/register').send(data);
        await setVerifyOtp(data.email);
        await request(app).post('/api/auth/verify-email').send({ email: data.email, otp: FIXED_OTP });
        return data;
    }

    it('logs in a verified user with 200 and sets both cookies', async () => {
        const data = await registerVerified();

        const res = await request(app).post('/api/auth/login').send({ email: data.email, password: data.password });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'Login successful' });
        const cookies = res.headers['set-cookie'] as unknown as string[];
        expect(cookies.some((c) => c.startsWith('accessToken='))).toBe(true);
        expect(cookies.some((c) => c.startsWith('refreshToken='))).toBe(true);
    });

    it('rejects a wrong password with 401', async () => {
        const data = await registerVerified();

        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: data.email, password: 'Wrongpass1!' });

        expect(res.status).toBe(401);
        expect(res.body).toEqual({ success: false, message: 'Invalid email or password' });
    });

    it('rejects an unknown email with the identical 401', async () => {
        const res = await request(app)
            .post('/api/auth/login')
            .send({ email: 'nobody@example.com', password: 'Whatever1!' });

        expect(res.status).toBe(401);
        expect(res.body).toEqual({ success: false, message: 'Invalid email or password' });
    });

    it('rejects an unverified account with 403', async () => {
        const data = makeRegisterData();
        await request(app).post('/api/auth/register').send(data);

        const res = await request(app).post('/api/auth/login').send({ email: data.email, password: data.password });

        expect(res.status).toBe(403);
        expect(res.body).toEqual({ success: false, message: 'Please verify your email before logging in' });
    });

    it('runs the full register → verify → login → me flow over HTTP (same flow as manual curl testing)', async () => {
        const agent = request.agent(app);
        const data = makeRegisterData();

        const reg = await agent.post('/api/auth/register').send(data);
        expect(reg.status).toBe(201);

        await setVerifyOtp(data.email);
        const verify = await agent.post('/api/auth/verify-email').send({ email: data.email, otp: FIXED_OTP });
        expect(verify.status).toBe(200);

        const login = await agent.post('/api/auth/login').send({ email: data.email, password: data.password });
        expect(login.status).toBe(200);

        // The agent jar carries the login cookies: /me must return the safe
        // projection with no sensitive fields.
        const me = await agent.get('/api/auth/me');
        expect(me.status).toBe(200);
        expect(me.body).toEqual({
            success: true,
            data: { id: expect.any(String), email: data.email, name: data.name, isAccountVerified: true },
        });
        expect(me.body.data).not.toHaveProperty('password');
    });
});
