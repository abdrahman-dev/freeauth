import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../helpers/testApp.ts';
import { clearDatabase, startMemoryMongo, stopMemoryMongo } from '../../helpers/mongoMemoryServer.ts';
import { resetRateLimiters } from '../../helpers/rateLimit.ts';
import { FIXED_OTP, markAccountVerified, setVerifyOtp } from '../../helpers/dbSetup.ts';
import { makeRegisterData } from '../../fixtures/testUsers.ts';

describe('POST /api/auth/verify-email', () => {
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

    it('verifies with 200 for the correct OTP', async () => {
        const data = makeRegisterData();
        await request(app).post('/api/auth/register').send(data);
        await setVerifyOtp(data.email);

        const res = await request(app).post('/api/auth/verify-email').send({ email: data.email, otp: FIXED_OTP });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'Email verified successfully' });
    });

    it('rejects a wrong OTP with 400', async () => {
        const data = makeRegisterData();
        await request(app).post('/api/auth/register').send(data);
        await setVerifyOtp(data.email);

        const res = await request(app).post('/api/auth/verify-email').send({ email: data.email, otp: '000000' });

        expect(res.status).toBe(400);
        expect(res.body).toEqual({ success: false, message: 'Invalid or expired OTP' });
    });

    it('rejects a malformed OTP with 422', async () => {
        const res = await request(app)
            .post('/api/auth/verify-email')
            .send({ email: 'a@example.com', otp: 'not-six-digits!!' });

        expect(res.status).toBe(422);
        expect(res.body.success).toBe(false);
    });
});

describe('POST /api/auth/resend-otp', () => {
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

    it('returns the generic 200 for an unknown email (enumeration-resistant)', async () => {
        const res = await request(app).post('/api/auth/resend-otp').send({ email: 'nobody@example.com' });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'If this email exists, a new OTP has been sent' });
    });

    it('rejects an already-verified account with 400', async () => {
        const data = makeRegisterData();
        await request(app).post('/api/auth/register').send(data);
        await markAccountVerified(data.email);

        const res = await request(app).post('/api/auth/resend-otp').send({ email: data.email });

        expect(res.status).toBe(400);
        expect(res.body).toEqual({ success: false, message: 'Account is already verified' });
    });

    it('accepts an unverified account with the generic 200', async () => {
        const data = makeRegisterData();
        await request(app).post('/api/auth/register').send(data);

        const res = await request(app).post('/api/auth/resend-otp').send({ email: data.email });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'If this email exists, a new OTP has been sent' });
    });
});
