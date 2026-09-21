import jwt from 'jsonwebtoken';
import { beforeEach, describe, expect, it } from 'vitest';
import { createAuth } from '../../../src/core/authService.ts';
import { verifyPassword } from '../../../src/internal/passwordService.js';
import { createFakeAdapter } from '../../fixtures/fakeAdapter.ts';
import type { FakeStore } from '../../fixtures/fakeAdapter.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { makeRegisterData, TEST_SECRETS } from '../../fixtures/testUsers.ts';

describe('registerUser', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    it('creates an unverified local user and returns tokens plus the raw OTP', async () => {
        const data = makeRegisterData();

        const result = await auth.registerUser(data);

        expect(typeof result.accessToken).toBe('string');
        expect(typeof result.refreshToken).toBe('string');
        expect(result.otp).toMatch(/^\d{6}$/);

        const stored = [...store.users.values()].find((u) => u.email === data.email);
        expect(stored).toBeDefined();
        expect(stored!.name).toBe(data.name);
        expect(stored!.isAccountVerified).toBe(false);
        expect(stored!.provider).toBe('local');
        expect(stored!.providerId).toBeNull();
        // The OTP is stored hashed, never plaintext.
        expect(stored!.verifyOTP).not.toBe(result.otp);
        expect(stored!.verifyOTPExpire).toBeGreaterThan(Date.now());
    });

    it('hashes the password (never stores plaintext)', async () => {
        const data = makeRegisterData();

        await auth.registerUser(data);

        const stored = [...store.users.values()].find((u) => u.email === data.email)!;
        expect(stored.password).not.toBe(data.password);
        expect(await verifyPassword(data.password, stored.password!)).toBe(true);
    });

    it('creates exactly one session row for the refresh token', async () => {
        const data = makeRegisterData();

        const result = await auth.registerUser(data);

        expect(store.sessions).toHaveLength(1);
        const session = store.sessions.find((s) => s.token === result.refreshToken);
        expect(session).toBeDefined();
        expect(session!.isRevoked).toBe(false);
        expect(session!.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('issues access tokens whose userId matches the created user', async () => {
        const data = makeRegisterData();

        const result = await auth.registerUser(data);

        const stored = [...store.users.values()].find((u) => u.email === data.email)!;
        const decoded = jwt.verify(result.accessToken, TEST_SECRETS.accessTokenSecret) as { userId: string };
        expect(decoded.userId).toBe(stored.id);
    });

    it('rejects a duplicate email with 409', async () => {
        const data = makeRegisterData();
        await auth.registerUser(data);

        await expect(auth.registerUser({ ...data, name: 'Someone Else' })).rejects.toMatchObject({
            message: 'Email already in use',
            statusCode: 409,
        });
        expect(store.users.size).toBe(1);
    });
});
