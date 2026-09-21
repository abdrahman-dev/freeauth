import { beforeEach, describe, expect, it } from 'vitest';
import { createAuth } from '../../../src/core/authService.ts';
import { createFakeAdapter } from '../../fixtures/fakeAdapter.ts';
import type { FakeStore } from '../../fixtures/fakeAdapter.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { makeRegisterData, sleepPastJwtSecond, TEST_SECRETS } from '../../fixtures/testUsers.ts';

describe('refreshSession (rotation)', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    async function register() {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        return { data, reg };
    }

    it('rotates: revokes the presented token and persists a fresh session', async () => {
        const { reg } = await register();

        const rotated = await auth.refreshSession(reg.refreshToken);

        expect(typeof rotated.accessToken).toBe('string');
        expect(typeof rotated.refreshToken).toBe('string');
        expect(store.sessions).toHaveLength(2);
        expect(store.sessions.filter((s) => s.isRevoked)).toHaveLength(1);
        expect(store.sessions.filter((s) => !s.isRevoked)).toHaveLength(1);
        // The revoked row is the presented one…
        expect(store.sessions.find((s) => s.token === reg.refreshToken && s.isRevoked)).toBeDefined();
        // …and at least one live row exists afterwards.
        expect(store.sessions.some((s) => !s.isRevoked)).toBe(true);
    });

    it('rejects a missing token with 401', async () => {
        await expect(auth.refreshSession(undefined as unknown as string)).rejects.toMatchObject({
            message: 'No refresh token provided',
            statusCode: 401,
        });
        await expect(auth.refreshSession('')).rejects.toMatchObject({ statusCode: 401 });
    });

    it('rejects an unknown token with 401', async () => {
        await expect(auth.refreshSession('no-such-token')).rejects.toMatchObject({
            message: 'Invalid or expired refresh token',
            statusCode: 401,
        });
    });

    it('rejects a sequentially replayed (already-rotated) token with 401 — without wiping other sessions', async () => {
        const { reg } = await register();
        // Force distinct token strings: replaying a byte-identical token is
        // indistinguishable from using the fresh one, so the test would be
        // meaningless without crossing a JWT `iat` second boundary first.
        await sleepPastJwtSecond();
        const rotated = await auth.refreshSession(reg.refreshToken);
        expect(rotated.refreshToken).not.toBe(reg.refreshToken);

        // Second use of the OLD token: findValid still returns it (isRevoked),
        // so core rejects BEFORE the atomic revoke — no reuse nuke fires.
        await expect(auth.refreshSession(reg.refreshToken)).rejects.toMatchObject({
            message: 'Invalid or expired refresh token',
            statusCode: 401,
        });

        // The rotated session survives: no revoke-all happened.
        await expect(auth.refreshSession(rotated.refreshToken)).resolves.toMatchObject({});
    });

    it('treats a lost revoke race as reuse: wipes ALL sessions with 401', async () => {
        const { reg } = await register();
        // Simulate the concurrent-refresh race: findValid passes, then the
        // atomic revoke loses (returns false) because a rival call won it.
        const racingAdapter: AuthAdapter = {
            ...adapter,
            sessions: { ...adapter.sessions, revoke: async () => false },
        };
        const racingAuth = createAuth({ adapter: racingAdapter, secrets: TEST_SECRETS });

        await expect(racingAuth.refreshSession(reg.refreshToken)).rejects.toMatchObject({
            message: 'Session invalidated due to suspicious activity, please login again',
            statusCode: 401,
        });
        expect(store.sessions.every((s) => s.isRevoked)).toBe(true);
    });

    it('lets exactly one of two concurrent refreshes succeed (atomic revoke)', async () => {
        const { reg } = await register();
        // Distinct strings again: with a byte-identical token the loser's
        // findValid could legitimately match the winner's fresh row.
        await sleepPastJwtSecond();

        const results = await Promise.allSettled([
            auth.refreshSession(reg.refreshToken),
            auth.refreshSession(reg.refreshToken),
        ]);

        const fulfilled = results.filter((r) => r.status === 'fulfilled');
        const rejected = results.filter((r) => r.status === 'rejected');
        expect(fulfilled).toHaveLength(1);
        expect(rejected).toHaveLength(1);
        expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({ statusCode: 401 });
    });

    it('rejects refresh for a token whose user no longer exists with 401', async () => {
        const { reg } = await register();
        const session = store.sessions.find((s) => s.token === reg.refreshToken)!;
        store.users.delete(session.userId);

        await expect(auth.refreshSession(reg.refreshToken)).rejects.toMatchObject({
            message: 'User not found',
            statusCode: 401,
        });
    });
});

describe('logoutUser', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    it('revokes the presented token and reports logout', async () => {
        const reg = await auth.registerUser(makeRegisterData());

        await expect(auth.logoutUser(reg.refreshToken)).resolves.toEqual({ loggedOut: true });
        expect(store.sessions.find((s) => s.token === reg.refreshToken)?.isRevoked).toBe(true);
    });

    it('is idempotent: missing or unknown tokens still succeed', async () => {
        await expect(auth.logoutUser(undefined as unknown as string)).resolves.toEqual({ loggedOut: true });
        await expect(auth.logoutUser('')).resolves.toEqual({ loggedOut: true });
        await expect(auth.logoutUser('never-existed')).resolves.toEqual({ loggedOut: true });
    });

    it('revokes only the presented session, leaving other devices alone', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        const regOtp = reg.otp;
        await auth.verifyEmail({ email: data.email, otp: regOtp });
        await auth.loginUser({ email: data.email, password: data.password });

        // revoke() flips exactly one row however the token strings fall out —
        // whether register/login JWTs are byte-identical or distinct, one
        // device session dies and the other survives.
        await auth.logoutUser(reg.refreshToken);

        expect(store.sessions).toHaveLength(2);
        expect(store.sessions.filter((s) => s.isRevoked)).toHaveLength(1);
        expect(store.sessions.filter((s) => !s.isRevoked)).toHaveLength(1);
    });
});

describe('getMe', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS });
    });

    it('returns the safe projection (never password or OTP hashes)', async () => {
        const data = makeRegisterData();
        const reg = await auth.registerUser(data);
        await auth.verifyEmail({ email: data.email, otp: reg.otp });
        const userId = [...store.users.values()].find((u) => u.email === data.email)!.id;

        const me = await auth.getMe(userId);

        expect(me).toEqual({
            id: userId,
            email: data.email,
            name: data.name,
            isAccountVerified: true,
        });
        expect(me).not.toHaveProperty('password');
        expect(me).not.toHaveProperty('verifyOTP');
        expect(me).not.toHaveProperty('resetOTP');
    });

    it('rejects an unknown user with 404', async () => {
        await expect(auth.getMe('no-such-id')).rejects.toMatchObject({
            message: 'User not found',
            statusCode: 404,
        });
    });
});
