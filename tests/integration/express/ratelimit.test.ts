import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../helpers/testApp.ts';
import { clearDatabase, startMemoryMongo, stopMemoryMongo } from '../../helpers/mongoMemoryServer.ts';
import { resetRateLimiters } from '../../helpers/rateLimit.ts';
import { makeRegisterData } from '../../fixtures/testUsers.ts';

// The real limiter instances are exercised here — no waiting is needed because
// exceeding `max` rejects immediately; the window only governs EXPIRY.
// `beforeEach(resetRateLimiters)` guarantees each test starts from an empty
// bucket, so these counts are deterministic.

describe('rate limiting', () => {
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

    it('authLimiter: the 6th login attempt in 15 minutes gets 429 (first 5 pass through)', async () => {
        const statuses: number[] = [];
        for (let i = 0; i < 6; i += 1) {
            // eslint-disable-next-line no-await-in-loop
            const res = await request(app)
                .post('/api/auth/login')
                .send({ email: 'nobody@example.com', password: 'Whatever1!' });
            statuses.push(res.status);
        }

        expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
        expect(statuses[5]).toBe(429);

        const blocked = await request(app)
            .post('/api/auth/login')
            .send({ email: 'nobody@example.com', password: 'Whatever1!' });
        expect(blocked.body).toEqual({ success: false, message: 'Too many login attempts, try again after 15 minutes' });
    });

    it('registerLimiter: the 11th registration in an hour gets 429', async () => {
        // Invalid bodies still consume budget: the limiter runs before validation.
        let lastStatus = 0;
        for (let i = 0; i < 11; i += 1) {
            // eslint-disable-next-line no-await-in-loop
            const res = await request(app)
                .post('/api/auth/register')
                .send({ ...makeRegisterData(), password: 'weak' });
            lastStatus = res.status;
        }

        expect(lastStatus).toBe(429);
        const blocked = await request(app)
            .post('/api/auth/register')
            .send({ ...makeRegisterData(), password: 'weak' });
        expect(blocked.body).toEqual({
            success: false,
            message: 'Too many accounts created, try again after an hour',
        });
    });
});
