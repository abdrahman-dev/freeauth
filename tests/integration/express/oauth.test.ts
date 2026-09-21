import { OAuth2Client } from 'google-auth-library';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { createTestApp } from '../../helpers/testApp.ts';
import { clearDatabase, startMemoryMongo, stopMemoryMongo } from '../../helpers/mongoMemoryServer.ts';
import { resetRateLimiters } from '../../helpers/rateLimit.ts';
import { makeRegisterData } from '../../fixtures/testUsers.ts';

describe('POST /api/auth/github/state + POST /api/auth/github', () => {
    let app: ReturnType<typeof createTestApp>;
    let fetchMock: ReturnType<typeof vi.fn>;

    const profile = { id: 424242, login: 'octocat', name: 'The Octocat' };
    const emails = [
        { email: 'secondary@example.com', primary: false, verified: true },
        { email: 'octocat@example.com', primary: true, verified: true },
    ];

    const mockGithub = () => {
        fetchMock = vi.fn(async (url: string) => {
            if (url.includes('/login/oauth/access_token')) {
                return { ok: true, json: async () => ({ access_token: 'gho_testtoken' }) };
            }
            if (url.includes('/user/emails')) {
                return { ok: true, json: async () => emails };
            }
            return { ok: true, json: async () => profile };
        });
        vi.stubGlobal('fetch', fetchMock);
    };

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

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    it('issues state with 200 and sets the state cookie', async () => {
        const res = await request(app).post('/api/auth/github/state').send();

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.data.state).toMatch(/^[0-9a-f]{64}$/);
        const cookies = res.headers['set-cookie'] as unknown as string[];
        expect(cookies.some((c) => c.startsWith('github_oauth_state=') && c.includes('HttpOnly'))).toBe(true);
    });

    it('completes the full state → callback flow with 200, auth cookies, and isNewUser', async () => {
        mockGithub();
        const agent = request.agent(app);

        const issued = await agent.post('/api/auth/github/state').send();
        const state = issued.body.data.state as string;

        const res = await agent.post('/api/auth/github').send({ code: 'valid-code', state });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'GitHub login successful', isNewUser: true });
        const cookies = res.headers['set-cookie'] as unknown as string[];
        expect(cookies.some((c) => c.startsWith('accessToken='))).toBe(true);
        expect(cookies.some((c) => c.startsWith('refreshToken='))).toBe(true);
        // Single-use binding: the state cookie is consumed by the callback.
        expect(cookies.some((c) => c.startsWith('github_oauth_state=;'))).toBe(true);
    });

    it('rejects a mismatched state with 401 without calling GitHub', async () => {
        mockGithub();
        const agent = request.agent(app);
        await agent.post('/api/auth/github/state').send();

        const res = await agent.post('/api/auth/github').send({ code: 'valid-code', state: 'forged-state' });

        expect(res.status).toBe(401);
        expect(res.body).toEqual({ success: false, message: 'Invalid OAuth state. Please try signing in again.' });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('rejects the callback with 401 when no state was ever issued (no cookie)', async () => {
        mockGithub();

        const res = await request(app).post('/api/auth/github').send({ code: 'valid-code', state: 'orphan-state' });

        expect(res.status).toBe(401);
        expect(res.body.success).toBe(false);
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('rejects a pre-existing email with 409 (no linking)', async () => {
        mockGithub();
        const data = makeRegisterData({ email: 'octocat@example.com' });
        await request(app).post('/api/auth/register').send(data);
        const agent = request.agent(app);
        const issued = await agent.post('/api/auth/github/state').send();

        const res = await agent.post('/api/auth/github').send({ code: 'valid-code', state: issued.body.data.state });

        expect(res.status).toBe(409);
        expect(res.body).toEqual({
            success: false,
            message: 'An account already exists with this email. Sign in with your password instead.',
        });
    });
});

describe('POST /api/auth/google', () => {
    let app: ReturnType<typeof createTestApp>;

    const payload = {
        email: 'google-user@example.com',
        name: 'Google User',
        given_name: 'Google',
        sub: 'google-sub-123',
        email_verified: true,
    };

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

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('logs in with a valid ID token: 200, auth cookies, isNewUser', async () => {
        vi.spyOn(OAuth2Client.prototype, 'verifyIdToken').mockResolvedValue({
            getPayload: () => payload,
        } as never);

        const res = await request(app).post('/api/auth/google').send({ idToken: 'valid-token' });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'Google login successful', isNewUser: true });
        const cookies = res.headers['set-cookie'] as unknown as string[];
        expect(cookies.some((c) => c.startsWith('accessToken='))).toBe(true);
        expect(cookies.some((c) => c.startsWith('refreshToken='))).toBe(true);
    });

    it('rejects an invalid ID token with 401', async () => {
        vi.spyOn(OAuth2Client.prototype, 'verifyIdToken').mockRejectedValue(new Error('bad signature'));

        const res = await request(app).post('/api/auth/google').send({ idToken: 'bogus' });

        expect(res.status).toBe(401);
        expect(res.body).toEqual({ success: false, message: 'Invalid or expired Google ID token' });
    });

    it('rejects a pre-existing email with 409 (no linking)', async () => {
        vi.spyOn(OAuth2Client.prototype, 'verifyIdToken').mockResolvedValue({
            getPayload: () => payload,
        } as never);
        const data = makeRegisterData({ email: 'google-user@example.com' });
        await request(app).post('/api/auth/register').send(data);

        const res = await request(app).post('/api/auth/google').send({ idToken: 'valid-token' });

        expect(res.status).toBe(409);
        expect(res.body.success).toBe(false);
    });
});
