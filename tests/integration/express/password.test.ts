import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../helpers/testApp.ts';
import { clearDatabase, startMemoryMongo, stopMemoryMongo } from '../../helpers/mongoMemoryServer.ts';
import { resetRateLimiters } from '../../helpers/rateLimit.ts';
import { FIXED_OTP, setResetOtp, setVerifyOtp } from '../../helpers/dbSetup.ts';
import { makeRegisterData } from '../../fixtures/testUsers.ts';

const NEW_PASSWORD = 'N3w!Strong1';

describe('POST /api/auth/forgot-password + POST /api/auth/reset-password', () => {
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

    it('forgot-password returns the same generic 200 for unknown emails', async () => {
        const res = await request(app).post('/api/auth/forgot-password').send({ email: 'nobody@example.com' });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'If this email exists, an OTP has been sent' });
    });

    it('resets the password end-to-end and the new password logs in', async () => {
        const data = await registerVerified();
        await request(app).post('/api/auth/forgot-password').send({ email: data.email });
        await setResetOtp(data.email);

        const reset = await request(app)
            .post('/api/auth/reset-password')
            .send({ email: data.email, otp: FIXED_OTP, newPassword: NEW_PASSWORD });

        expect(reset.status).toBe(200);
        expect(reset.body).toEqual({ success: true, message: 'Password reset successful' });

        const login = await request(app)
            .post('/api/auth/login')
            .send({ email: data.email, password: NEW_PASSWORD });
        expect(login.status).toBe(200);
    });

    it('rejects a wrong reset OTP with 400', async () => {
        const data = await registerVerified();
        await request(app).post('/api/auth/forgot-password').send({ email: data.email });
        await setResetOtp(data.email);

        const res = await request(app)
            .post('/api/auth/reset-password')
            .send({ email: data.email, otp: '000000', newPassword: NEW_PASSWORD });

        expect(res.status).toBe(400);
        expect(res.body).toEqual({ success: false, message: 'Invalid or expired OTP' });
    });
});

describe('POST /api/auth/change-password', () => {
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

    it('rejects unauthenticated callers with 401', async () => {
        const res = await request(app)
            .post('/api/auth/change-password')
            .send({ currentPassword: 'x', newPassword: NEW_PASSWORD });

        expect(res.status).toBe(401);
        expect(res.body).toEqual({ success: false, message: 'No access token provided' });
    });

    it('changes the password and kills existing sessions (caller re-logs in)', async () => {
        const agent = request.agent(app);
        const data = makeRegisterData();
        await agent.post('/api/auth/register').send(data);
        await setVerifyOtp(data.email);
        await agent.post('/api/auth/verify-email').send({ email: data.email, otp: FIXED_OTP });
        const login = await agent.post('/api/auth/login').send({ email: data.email, password: data.password });
        expect(login.status).toBe(200);
        const cookies = login.headers['set-cookie'] as unknown as string[];
        const oldRefresh = cookies.find((c) => c.startsWith('refreshToken='))!.split(';')[0];

        const change = await agent
            .post('/api/auth/change-password')
            .send({ currentPassword: data.password, newPassword: NEW_PASSWORD });
        expect(change.status).toBe(200);
        expect(change.body).toEqual({ success: true, message: 'Password changed successfully' });

        // Pre-change session is dead…
        const stale = await request(app).post('/api/auth/refresh').set('Cookie', oldRefresh);
        expect(stale.status).toBe(401);

        // …and the new password works.
        const relogin = await request(app)
            .post('/api/auth/login')
            .send({ email: data.email, password: NEW_PASSWORD });
        expect(relogin.status).toBe(200);
    });

    it('rejects a wrong current password with 401', async () => {
        const agent = request.agent(app);
        const data = makeRegisterData();
        await agent.post('/api/auth/register').send(data);
        await setVerifyOtp(data.email);
        await agent.post('/api/auth/verify-email').send({ email: data.email, otp: FIXED_OTP });
        await agent.post('/api/auth/login').send({ email: data.email, password: data.password });

        const res = await agent
            .post('/api/auth/change-password')
            .send({ currentPassword: 'Wrongpass1!', newPassword: NEW_PASSWORD });

        expect(res.status).toBe(401);
        expect(res.body).toEqual({ success: false, message: 'Current password is incorrect' });
    });
});
