import { beforeEach, describe, expect, it } from 'vitest';
import { createAuth } from '../../../src/core/authService.ts';
import { createFakeAdapter } from '../../fixtures/fakeAdapter.ts';
import type { FakeStore } from '../../fixtures/fakeAdapter.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { makeRegisterData, TEST_SECRETS, validPassword, wrongOtpFor } from '../../fixtures/testUsers.ts';

describe('forgotPassword', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    const storedByEmail = (email: string) => [...store.users.values()].find((u) => u.email === email)!;

    it('returns sent:false for an unknown email (enumeration-resistant)', async () => {
        await expect(auth.forgotPassword({ email: 'nobody@example.com' })).resolves.toEqual({ sent: false });
    });

    it('stores a hashed reset OTP with a future expiry for a known email', async () => {
        const data = makeRegisterData();
        await auth.registerUser(data);

        const result = await auth.forgotPassword({ email: data.email });

        expect(result.sent).toBe(true);
        expect(result.otp).toMatch(/^\d{6}$/);
        const stored = storedByEmail(data.email);
        expect(stored.resetOTP).not.toBe(result.otp);
        expect(stored.resetOTPExpire).toBeGreaterThan(Date.now());
    });
});

describe('resetPassword', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    const NEW_PASSWORD = 'N3w!Strong1';

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    const storedByEmail = (email: string) => [...store.users.values()].find((u) => u.email === email)!;

    async function setupWithResetOtp(overrides = {}) {
        const data = makeRegisterData(overrides);
        const reg = await auth.registerUser(data);
        await auth.verifyEmail({ email: data.email, otp: reg.otp });
        const forgot = await auth.forgotPassword({ email: data.email });
        return { data, otp: forgot.otp! };
    }

    it('resets with newPassword, clears OTP state, and revokes ALL sessions', async () => {
        const { data, otp } = await setupWithResetOtp();
        // An extra login session exists to prove revoke-all (not just current).
        await auth.loginUser({ email: data.email, password: data.password });

        const result = await auth.resetPassword({ email: data.email, otp, newPassword: NEW_PASSWORD });

        expect(result).toEqual({ reset: true });
        const stored = storedByEmail(data.email);
        expect(stored.resetOTP).toBeNull();
        expect(stored.resetOTPExpire).toBeNull();
        expect(store.sessions.every((s) => s.isRevoked)).toBe(true);

        // New password works, old one does not.
        await expect(
            auth.loginUser({ email: data.email, password: NEW_PASSWORD })
        ).resolves.toMatchObject({});
        await expect(auth.loginUser({ email: data.email, password: data.password })).rejects.toMatchObject({
            statusCode: 401,
        });
    });

    it('accepts the legacy `password` alias', async () => {
        const { data, otp } = await setupWithResetOtp();

        await expect(
            auth.resetPassword({ email: data.email, otp, password: NEW_PASSWORD })
        ).resolves.toEqual({ reset: true });
        await expect(
            auth.loginUser({ email: data.email, password: NEW_PASSWORD })
        ).resolves.toMatchObject({});
    });

    it('rejects a wrong OTP with 400', async () => {
        const { data, otp } = await setupWithResetOtp();

        await expect(
            auth.resetPassword({ email: data.email, otp: wrongOtpFor(otp), newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({ message: 'Invalid or expired OTP', statusCode: 400 });
    });

    it('rejects an unknown email with 400', async () => {
        await expect(
            auth.resetPassword({ email: 'ghost@example.com', otp: '123456', newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({ message: 'Invalid or expired OTP', statusCode: 400 });
    });

    it('rejects an expired OTP with 400 and clears it', async () => {
        const { data, otp } = await setupWithResetOtp();
        storedByEmail(data.email).resetOTPExpire = Date.now() - 1000;

        await expect(
            auth.resetPassword({ email: data.email, otp, newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({ message: 'Invalid or expired OTP', statusCode: 400 });
        expect(storedByEmail(data.email).resetOTP).toBeNull();
    });

    it('locks the reset flow at exactly 5 failed attempts (5th 400+lock, 6th 429)', async () => {
        const { data, otp } = await setupWithResetOtp();
        const wrong = wrongOtpFor(otp);

        for (let i = 0; i < 4; i += 1) {
            await expect(
                auth.resetPassword({ email: data.email, otp: wrong, newPassword: NEW_PASSWORD })
            ).rejects.toMatchObject({ statusCode: 400 });
        }
        await expect(
            auth.resetPassword({ email: data.email, otp: wrong, newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({ statusCode: 400 });
        expect(storedByEmail(data.email).resetLockUntil).not.toBeNull();

        await expect(
            auth.resetPassword({ email: data.email, otp, newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({ message: 'Too many attempts, try again later', statusCode: 429 });
    });
});

describe('changePassword', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    const NEW_PASSWORD = 'N3w!Strong1';

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    const storedByEmail = (email: string) => [...store.users.values()].find((u) => u.email === email)!;

    async function setupVerified() {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        await auth.verifyEmail({ email: data.email, otp: reg.otp });
        return { data, userId: storedByEmail(data.email).id };
    }

    it('changes the password and revokes ALL sessions (caller must re-login)', async () => {
        const { data, userId } = await setupVerified();
        await auth.loginUser({ email: data.email, password: data.password });

        const result = await auth.changePassword(userId, {
            currentPassword: data.password,
            newPassword: NEW_PASSWORD,
        });

        expect(result).toEqual({ changed: true });
        expect(store.sessions.every((s) => s.isRevoked)).toBe(true);
        await expect(
            auth.loginUser({ email: data.email, password: NEW_PASSWORD })
        ).resolves.toMatchObject({});
        expect(validPassword()).not.toBe(NEW_PASSWORD); // sanity: factory default differs
    });

    it('rejects a wrong current password with 401', async () => {
        const { data, userId } = await setupVerified();

        await expect(
            auth.changePassword(userId, { currentPassword: 'Wrongpass1!', newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({ message: 'Current password is incorrect', statusCode: 401 });
    });

    it('rejects an unknown user with 404', async () => {
        await expect(
            auth.changePassword('no-such-id', { currentPassword: 'x', newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({ message: 'User not found', statusCode: 404 });
    });

    it('rejects an OAuth-only account with the provider-neutral 401 (never reaches bcrypt)', async () => {
        const data = makeRegisterData();
        const oauthUser = await adapter.users.createOAuthUser({
            email: data.email,
            name: data.name,
            provider: 'github',
            providerId: 'github-id-999',
        });

        await expect(
            auth.changePassword(oauthUser.id, { currentPassword: 'Anything1!', newPassword: NEW_PASSWORD })
        ).rejects.toMatchObject({
            message: 'This account uses social sign-in. Please sign in with the provider you originally used.',
            statusCode: 401,
        });
    });
});
