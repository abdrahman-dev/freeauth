import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../helpers/testApp.ts';
import { clearDatabase, startMemoryMongo, stopMemoryMongo } from '../../helpers/mongoMemoryServer.ts';
import { resetRateLimiters } from '../../helpers/rateLimit.ts';
import { FIXED_OTP, setVerifyOtp } from '../../helpers/dbSetup.ts';
import { makeRegisterData, sleepPastJwtSecond } from '../../fixtures/testUsers.ts';

const refreshCookieOf = (res: { headers: Record<string, unknown> }): string => {
    const cookies = res.headers['set-cookie'] as unknown as string[];
    return cookies.find((c) => c.startsWith('refreshToken='))!.split(';')[0];
};

describe('POST /api/auth/refresh + POST /api/auth/logout + GET /api/auth/me', () => {
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

    it('rotates the refresh token: old cookie rejected, new cookie accepted', async () => {
        const data = await registerVerified();
        const login = await request(app).post('/api/auth/login').send({ email: data.email, password: data.password });
        const oldCookie = refreshCookieOf(login);

        // Distinct iat seconds so old/new token strings cannot collide.
        await sleepPastJwtSecond();

        const rotated = await request(app).post('/api/auth/refresh').set('Cookie', oldCookie);
        expect(rotated.status).toBe(200);
        expect(rotated.body).toEqual({ success: true, message: 'Token refreshed successfully' });

        const replay = await request(app).post('/api/auth/refresh').set('Cookie', oldCookie);
        expect(replay.status).toBe(401);
        expect(replay.body).toEqual({ success: false, message: 'Invalid or expired refresh token' });

        const freshCookie = refreshCookieOf(rotated);
        const again = await request(app).post('/api/auth/refresh').set('Cookie', freshCookie);
        expect(again.status).toBe(200);
    });

    it('rejects refresh with no cookie at 401', async () => {
        const res = await request(app).post('/api/auth/refresh');

        expect(res.status).toBe(401);
        expect(res.body).toEqual({ success: false, message: 'No refresh token provided' });
    });

    it('logs out with 200, clears both cookies, and kills the session', async () => {
        const data = await registerVerified();
        const login = await request(app).post('/api/auth/login').send({ email: data.email, password: data.password });
        const cookie = refreshCookieOf(login);

        const logout = await request(app).post('/api/auth/logout').set('Cookie', cookie);
        expect(logout.status).toBe(200);
        expect(logout.body).toEqual({ success: true, message: 'Logout successful' });
        const cleared = logout.headers['set-cookie'] as unknown as string[];
        expect(cleared.some((c) => c.startsWith('accessToken=;'))).toBe(true);
        expect(cleared.some((c) => c.startsWith('refreshToken=;'))).toBe(true);

        const after = await request(app).post('/api/auth/refresh').set('Cookie', cookie);
        expect(after.status).toBe(401);
    });

    it('logout without a cookie still succeeds (idempotent)', async () => {
        const res = await request(app).post('/api/auth/logout');

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'Logout successful' });
    });

    it('GET /me returns the safe projection for a logged-in agent', async () => {
        const agent = request.agent(app);
        const data = makeRegisterData();
        await agent.post('/api/auth/register').send(data);
        await setVerifyOtp(data.email);
        await agent.post('/api/auth/verify-email').send({ email: data.email, otp: FIXED_OTP });
        await agent.post('/api/auth/login').send({ email: data.email, password: data.password });

        const me = await agent.get('/api/auth/me');

        expect(me.status).toBe(200);
        expect(me.body.data.email).toBe(data.email);
        expect(me.body.data).not.toHaveProperty('password');
    });

    it('GET /me rejects missing and bad tokens with 401', async () => {
        const missing = await request(app).get('/api/auth/me');
        expect(missing.status).toBe(401);
        expect(missing.body).toEqual({ success: false, message: 'No access token provided' });

        const bad = await request(app).get('/api/auth/me').set('Authorization', 'Bearer not-a-token');
        expect(bad.status).toBe(401);
        expect(bad.body).toEqual({ success: false, message: 'Invalid access token' });
    });
});
