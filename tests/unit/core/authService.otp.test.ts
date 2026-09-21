import { beforeEach, describe, expect, it } from 'vitest';
import { createAuth } from '../../../src/core/authService.ts';
import { createFakeAdapter } from '../../fixtures/fakeAdapter.ts';
import type { FakeStore } from '../../fixtures/fakeAdapter.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { makeRegisterData, TEST_SECRETS, wrongOtpFor } from '../../fixtures/testUsers.ts';

describe('verifyEmail', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    const storedByEmail = (email: string) => [...store.users.values()].find((u) => u.email === email)!;

    it('verifies with the correct OTP, marks verified, and clears OTP state', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);

        const result = await auth.verifyEmail({ email: data.email, otp: reg.otp });

        expect(result).toEqual({ verified: true });
        const stored = storedByEmail(data.email);
        expect(stored.isAccountVerified).toBe(true);
        expect(stored.verifyOTP).toBeNull();
        expect(stored.verifyOTPExpire).toBeNull();
        expect(stored.verifyAttempts).toBe(0);
        expect(stored.verifyLockUntil).toBeNull();
    });

    it('rejects an unknown email with 400', async () => {
        await expect(auth.verifyEmail({ email: 'ghost@example.com', otp: '123456' })).rejects.toMatchObject({
            message: 'Invalid or expired OTP',
            statusCode: 400,
        });
    });

    it('rejects a wrong OTP with 400 and increments the verify counter', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);

        await expect(
            auth.verifyEmail({ email: data.email, otp: wrongOtpFor(reg.otp) })
        ).rejects.toMatchObject({ message: 'Invalid or expired OTP', statusCode: 400 });

        expect(storedByEmail(data.email).verifyAttempts).toBe(1);
        expect(storedByEmail(data.email).isAccountVerified).toBe(false);
    });

    it('locks the verify flow at exactly 5 failed attempts (4x400, 5th 400+lock, 6th 429)', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        const wrong = wrongOtpFor(reg.otp);

        for (let i = 0; i < 4; i += 1) {
            await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
                statusCode: 400,
            });
        }
        expect(storedByEmail(data.email).verifyAttempts).toBe(4);
        expect(storedByEmail(data.email).verifyLockUntil).toBeNull();

        // 5th failure still reports 400, but sets the lock and resets the counter.
        await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
            statusCode: 400,
        });
        const locked = storedByEmail(data.email);
        expect(locked.verifyLockUntil).not.toBeNull();
        expect(locked.verifyLockUntil!.getTime()).toBeGreaterThan(Date.now());
        expect(locked.verifyAttempts).toBe(0);

        // While locked, even the CORRECT OTP is rejected with 429.
        await expect(auth.verifyEmail({ email: data.email, otp: reg.otp })).rejects.toMatchObject({
            message: 'Too many attempts, try again later',
            statusCode: 429,
        });
    });

    it('rejects an expired OTP with 400 and clears it', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        storedByEmail(data.email).verifyOTPExpire = Date.now() - 1000;

        await expect(auth.verifyEmail({ email: data.email, otp: reg.otp })).rejects.toMatchObject({
            message: 'Invalid or expired OTP',
            statusCode: 400,
        });
        expect(storedByEmail(data.email).verifyOTP).toBeNull();
    });

    it('recovers after partial failures: correct OTP still verifies and resets the counter', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        const wrong = wrongOtpFor(reg.otp);

        await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
            statusCode: 400,
        });
        await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
            statusCode: 400,
        });

        await expect(auth.verifyEmail({ email: data.email, otp: reg.otp })).resolves.toEqual({
            verified: true,
        });
        expect(storedByEmail(data.email).verifyAttempts).toBe(0);
    });

    it('tracks verify and reset flows with fully independent counters', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        await auth.forgotPassword({ email: data.email });
        const wrong = wrongOtpFor(reg.otp);

        await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
            statusCode: 400,
        });
        await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
            statusCode: 400,
        });

        const stored = storedByEmail(data.email);
        expect(stored.verifyAttempts).toBe(2);
        expect(stored.resetAttempts).toBe(0);
        expect(stored.resetLockUntil).toBeNull();
    });
});

describe('resendOTP', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    const storedByEmail = (email: string) => [...store.users.values()].find((u) => u.email === email)!;

    it('returns sent:false for an unknown email (enumeration-resistant)', async () => {
        await expect(auth.resendOTP({ email: 'nobody@example.com' })).resolves.toEqual({ sent: false });
    });

    it('rejects an already-verified account with 400', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        await auth.verifyEmail({ email: data.email, otp: reg.otp });

        await expect(auth.resendOTP({ email: data.email })).rejects.toMatchObject({
            message: 'Account is already verified',
            statusCode: 400,
        });
    });

    it('issues a fresh OTP that verifies, invalidating the previous one', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);

        const resend = await auth.resendOTP({ email: data.email });

        expect(resend.sent).toBe(true);
        expect(resend.otp).toMatch(/^\d{6}$/);
        // The rotated OTP no longer matches the original one.
        await expect(auth.verifyEmail({ email: data.email, otp: reg.otp })).rejects.toMatchObject({
            statusCode: 400,
        });
        await expect(auth.verifyEmail({ email: data.email, otp: resend.otp! })).resolves.toEqual({
            verified: true,
        });
        expect(storedByEmail(data.email).isAccountVerified).toBe(true);
    });
});
