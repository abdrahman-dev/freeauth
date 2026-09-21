import { beforeEach, describe, expect, it } from 'vitest';
import { createAuth } from '../../../src/core/authService.ts';
import { createFakeAdapter } from '../../fixtures/fakeAdapter.ts';
import type { FakeStore } from '../../fixtures/fakeAdapter.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { makeRegisterData, TEST_SECRETS } from '../../fixtures/testUsers.ts';

describe('loginUser', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    async function registerVerifiedUser(overrides = {}) {
        const data = makeRegisterData(overrides);
        const reg = await auth.registerUser(data);
        await auth.verifyEmail({ email: data.email, otp: reg.otp });
        return data;
    }

    it('logs in a verified user and creates a session', async () => {
        const data = await registerVerifiedUser();

        const result = await auth.loginUser({ email: data.email, password: data.password });

        expect(typeof result.accessToken).toBe('string');
        expect(typeof result.refreshToken).toBe('string');
        expect(store.sessions).toHaveLength(2); // register session + login session
        expect(store.sessions.every((s) => !s.isRevoked)).toBe(true);
    });

    it('allows multi-device login without revoking older sessions', async () => {
        const data = await registerVerifiedUser();

        const first = await auth.loginUser({ email: data.email, password: data.password });
        const second = await auth.loginUser({ email: data.email, password: data.password });

        expect(store.sessions).toHaveLength(3);
        expect(store.sessions.every((s) => !s.isRevoked)).toBe(true);
        expect(first.refreshToken).toBeDefined();
        expect(second.refreshToken).toBeDefined();
    });

    it('rejects an unknown email with 401', async () => {
        await expect(
            auth.loginUser({ email: 'nobody@example.com', password: 'Whatever1!' })
        ).rejects.toMatchObject({ message: 'Invalid email or password', statusCode: 401 });
    });

    it('rejects a wrong password with the IDENTICAL 401 (no user-enumeration oracle)', async () => {
        const data = await registerVerifiedUser();

        const attempt = auth.loginUser({ email: data.email, password: 'Wrongpass1!' });
        await expect(attempt).rejects.toMatchObject({
            message: 'Invalid email or password',
            statusCode: 401,
        });
    });

    it('rejects an unverified account with 403', async () => {
        const data = makeRegisterData();
        await auth.registerUser(data);

        await expect(auth.loginUser({ email: data.email, password: data.password })).rejects.toMatchObject({
            message: 'Please verify your email before logging in',
            statusCode: 403,
        });
    });

    it('rejects an OAuth-only account with the provider-neutral 401 (never reaches bcrypt)', async () => {
        const data = makeRegisterData();
        await adapter.users.createOAuthUser({
            email: data.email,
            name: data.name,
            provider: 'google',
            providerId: 'google-sub-123',
        });

        await expect(
            auth.loginUser({ email: data.email, password: 'Anything1!' })
        ).rejects.toMatchObject({
            message: 'This account uses social sign-in. Please sign in with the provider you originally used.',
            statusCode: 401,
        });
    });
});
