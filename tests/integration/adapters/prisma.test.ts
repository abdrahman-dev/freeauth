import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { prismaAdapter } from '../../../src/adapters/prisma.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { clearDatabase, startPglite, stopPglite } from '../../helpers/pgliteServer.ts';
import { makeRegisterData } from '../../fixtures/testUsers.ts';

// Direct adapter tests via pglite (real Postgres semantics, WASM).
// Mirrors mongoose.test.ts structure: same coverage goals, same file location
// pattern, but over Postgres. Uses the shared pgliteServer helper which
// replays prisma/migrations/**/migration.sql directly (fastest, offline).

describe('prismaAdapter.users', () => {
    let adapter: AuthAdapter;

    beforeAll(async () => {
        const prisma = await startPglite();
        adapter = prismaAdapter(prisma);
    }, 180000);

    afterAll(async () => {
        await stopPglite();
    });

    beforeEach(async () => {
        await clearDatabase();
    });

    it('round-trips create → findByEmail → findById with contract defaults', async () => {
        const data = makeRegisterData();

        const created = await adapter.users.create({
            name: data.name,
            email: data.email,
            password: 'hashed-pw',
            verifyOTP: 'hex',
            verifyOTPExpire: Date.now() + 60000,
        });

        expect(typeof created.id).toBe('string');
        expect(created.provider).toBe('local');
        expect(created.providerId).toBeNull();
        expect(created.isAccountVerified).toBe(false);
        // BigInt expiry round-trips via Number() in prismaAdapter
        expect(typeof created.verifyOTPExpire).toBe('number');

        const byEmail = await adapter.users.findByEmail(data.email);
        expect(byEmail?.id).toBe(created.id);
        const byId = await adapter.users.findById(created.id);
        expect(byId?.email).toBe(data.email);
    });

    it('returns null for unknown email and unknown id', async () => {
        expect(await adapter.users.findByEmail('nobody@example.com')).toBeNull();
        // cuid-like ids, not ObjectId — any random string works for "unknown"
        expect(await adapter.users.findById('cuid_unknown_123')).toBeNull();
    });

    it('createOAuthUser persists a verified, passwordless user', async () => {
        const data = makeRegisterData();

        const user = await adapter.users.createOAuthUser({
            email: data.email,
            name: data.name,
            provider: 'github',
            providerId: '424242',
        });

        expect(user.isAccountVerified).toBe(true);
        expect(user.password).toBeNull();
        expect(user.provider).toBe('github');
        expect(user.providerId).toBe('424242');
        expect(user.verifyOTP).toBeNull();
    });

    it('updatePassword replaces the hash', async () => {
        const created = await adapter.users.create({
            ...makeRegisterData(),
            password: 'old-hash',
            verifyOTP: 'hex',
            verifyOTPExpire: 1,
        });

        await adapter.users.updatePassword(created.id, 'new-hash');

        expect((await adapter.users.findById(created.id))?.password).toBe('new-hash');
    });

    it('markVerified flips the flag and OTP setters/clearers round-trip', async () => {
        const created = await adapter.users.create({
            ...makeRegisterData(),
            password: 'h',
            verifyOTP: 'hex',
            verifyOTPExpire: 1,
        });

        await adapter.users.markVerified(created.id);
        expect((await adapter.users.findById(created.id))?.isAccountVerified).toBe(true);

        await adapter.users.setVerifyOTP(created.id, 'new-hex', 12345);
        let found = (await adapter.users.findById(created.id))!;
        expect(found.verifyOTP).toBe('new-hex');
        expect(found.verifyOTPExpire).toBe(12345);

        await adapter.users.clearVerifyOTP(created.id);
        found = (await adapter.users.findById(created.id))!;
        expect(found.verifyOTP).toBeNull();
        expect(found.verifyOTPExpire).toBeNull();

        await adapter.users.setResetOTP(created.id, 'reset-hex', 67890);
        found = (await adapter.users.findById(created.id))!;
        expect(found.resetOTP).toBe('reset-hex');
        await adapter.users.clearResetOTP(created.id);
        found = (await adapter.users.findById(created.id))!;
        expect(found.resetOTP).toBeNull();
        expect(found.resetOTPExpire).toBeNull();
    });

    it('incrementOtpAttempts returns post-increment counts per independent flow', async () => {
        const created = await adapter.users.create({
            ...makeRegisterData(),
            password: 'h',
            verifyOTP: 'hex',
            verifyOTPExpire: 1,
        });

        expect(await adapter.users.incrementOtpAttempts(created.id, 'verify')).toBe(1);
        expect(await adapter.users.incrementOtpAttempts(created.id, 'verify')).toBe(2);
        expect(await adapter.users.incrementOtpAttempts(created.id, 'reset')).toBe(1);

        const lockUntil = new Date(Date.now() + 60000);
        await adapter.users.setOtpLock(created.id, 'verify', lockUntil);
        let found = (await adapter.users.findById(created.id))!;
        expect(found.verifyLockUntil?.getTime()).toBe(lockUntil.getTime());
        expect(found.resetLockUntil).toBeNull();

        await adapter.users.resetOtpAttempts(created.id, 'verify');
        found = (await adapter.users.findById(created.id))!;
        expect(found.verifyAttempts).toBe(0);
        expect(found.verifyLockUntil).toBeNull();
        expect(found.resetAttempts).toBe(1);
    });
});

describe('prismaAdapter.sessions', () => {
    let adapter: AuthAdapter;

    beforeAll(async () => {
        const prisma = await startPglite();
        adapter = prismaAdapter(prisma);
    }, 180000);

    afterAll(async () => {
        await stopPglite();
    });

    beforeEach(async () => {
        await clearDatabase();
    });

    it('creates sessions and findValid enforces expiry (not revocation)', async () => {
        const live = await adapter.sessions.create({
            userId: 'cuid_user_1',
            token: 'live-token',
            expiresAt: new Date(Date.now() + 60000),
        });
        expect(live.isRevoked).toBe(false);
        expect(live.createdAt).toBeInstanceOf(Date);

        expect((await adapter.sessions.findValid('live-token'))?.token).toBe('live-token');

        await adapter.sessions.create({
            userId: 'cuid_user_1',
            token: 'stale-token',
            expiresAt: new Date(Date.now() - 1000),
        });
        expect(await adapter.sessions.findValid('stale-token')).toBeNull();
        expect(await adapter.sessions.findValid('never-existed')).toBeNull();
    });

    it('revoke() returns true once, then false (unknown tokens: false)', async () => {
        await adapter.sessions.create({
            userId: 'cuid_user_1',
            token: 'revoke-me',
            expiresAt: new Date(Date.now() + 60000),
        });

        expect(await adapter.sessions.revoke('revoke-me')).toBe(true);
        expect(await adapter.sessions.revoke('revoke-me')).toBe(false);
        expect(await adapter.sessions.revoke('never-existed')).toBe(false);
    });

    it('concurrent revoke() calls split exactly one true / one false (atomicity proof)', async () => {
        await adapter.sessions.create({
            userId: 'cuid_user_1',
            token: 'race-token',
            expiresAt: new Date(Date.now() + 60000),
        });

        // Two genuinely concurrent revoke attempts against real Postgres (pglite):
        // single UPDATE ... WHERE token = $1 AND isRevoked = false must let
        // exactly one caller win.
        const results = await Promise.all([adapter.sessions.revoke('race-token'), adapter.sessions.revoke('race-token')]);

        expect(results.sort()).toEqual([false, true]);
    });

    it('revokeAllForUser revokes every session of that user only', async () => {
        const userA = 'cuid_user_a';
        const userB = 'cuid_user_b';
        const future = new Date(Date.now() + 60000);
        await adapter.sessions.create({ userId: userA, token: 'a1', expiresAt: future });
        await adapter.sessions.create({ userId: userA, token: 'a2', expiresAt: future });
        await adapter.sessions.create({ userId: userB, token: 'b1', expiresAt: future });

        await adapter.sessions.revokeAllForUser(userA);

        expect((await adapter.sessions.findValid('a1'))?.isRevoked).toBe(true);
        expect((await adapter.sessions.findValid('a2'))?.isRevoked).toBe(true);
        expect((await adapter.sessions.findValid('b1'))?.isRevoked).toBe(false);
    });
});
