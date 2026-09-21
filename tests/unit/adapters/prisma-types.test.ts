import { describe, expect, it } from 'vitest';
import { prismaAdapter } from '../../../src/adapters/prisma.ts';
import type { PrismaClientLike } from '../../../src/adapters/prisma.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';

// No Postgres is available in this environment, so there are no live Prisma
// integration tests. This file does two things instead:
//  1. COMPILE-TIME: `const adapter: AuthAdapter = prismaAdapter(fake)` fails
//     `tsc --noEmit` (which covers `tests/`) if the adapter ever drifts from
//     the contract — new/renamed methods or shapes break the build.
//  2. RUNTIME: exercises the adapter's translation layer (BigInt expiry
//     mapping, provider fallback, atomic-style revoke/increment semantics)
//     against a minimal in-memory stand-in for the generated client.

// Minimal structural fake of the PrismaClient surface the adapter uses.
// Deliberately untyped internally (`any` rows, like real delegate results)
// so the adapter's own mapping code is what gets verified.
function createFakePrismaClient() {
    let nextId = 1;
    const users = new Map<string, any>();
    const tokens = new Map<string, any>();

    const byEmail = (email: string) => [...users.values()].find((u) => u.email === email) ?? null;

    return {
        user: {
            async findUnique(args: any) {
                if (args.where.email) return byEmail(args.where.email);
                return users.get(args.where.id) ?? null;
            },
            async create(args: any) {
                const row = {
                    id: `cuid-${nextId++}`,
                    isAccountVerified: false,
                    provider: 'local',
                    providerId: null,
                    verifyOTP: null,
                    verifyOTPExpire: null,
                    verifyAttempts: 0,
                    verifyLockUntil: null,
                    resetOTP: null,
                    resetOTPExpire: null,
                    resetAttempts: 0,
                    resetLockUntil: null,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    ...args.data,
                };
                // A real BigInt column round-trips expiries as BigInt, not
                // number — store it that way so the adapter's Number()
                // conversion on read is genuinely exercised below.
                if (typeof row.verifyOTPExpire === 'number') row.verifyOTPExpire = BigInt(row.verifyOTPExpire);
                if (typeof row.resetOTPExpire === 'number') row.resetOTPExpire = BigInt(row.resetOTPExpire);
                users.set(row.id, row);
                return row;
            },
            async update(args: any) {
                const row = users.get(args.where.id);
                if (!row) {
                    const err: any = new Error('Record not found');
                    err.code = 'P2025';
                    throw err;
                }
                for (const [key, value] of Object.entries(args.data)) {
                    if (value && typeof value === 'object' && 'increment' in (value as object)) {
                        row[key] += (value as { increment: number }).increment;
                    } else {
                        row[key] = value;
                    }
                }
                row.updatedAt = new Date();
                return row;
            },
        },
        refreshToken: {
            async create(args: any) {
                const row = {
                    id: `tok-${nextId++}`,
                    isRevoked: false,
                    createdAt: new Date(),
                    ...args.data,
                };
                tokens.set(row.token, row);
                return row;
            },
            async findFirst(args: any) {
                const row = tokens.get(args.where.token) ?? null;
                if (!row) return null;
                if (!(row.expiresAt > args.where.expiresAt.gt)) return null;
                return row;
            },
            async updateMany(args: any) {
                // Mirror Prisma semantics: every WHERE clause must match for
                // the row to count (this is what makes revoke() atomic).
                const row = tokens.get(args.where.token);
                const matches =
                    !!row &&
                    Object.entries(args.where).every(([key, value]) => {
                        if (value !== null && typeof value === 'object' && !(value instanceof Date)) return false;
                        return row[key] === value;
                    });
                if (!matches) return { count: 0 };
                Object.assign(row, args.data);
                return { count: 1 };
            },
        },
    };
}

describe('prismaAdapter contract', () => {
    it('satisfies the AuthAdapter interface (compile-time enforced by the annotation)', () => {
        const adapter: AuthAdapter = prismaAdapter(createFakePrismaClient() as PrismaClientLike);

        expect(typeof adapter.users.findByEmail).toBe('function');
        expect(typeof adapter.users.createOAuthUser).toBe('function');
        expect(typeof adapter.sessions.revoke).toBe('function');
        expect(typeof adapter.sessions.revokeAllForUser).toBe('function');
    });

    it('round-trips a user, converting BigInt expiries to numbers', async () => {
        const adapter: AuthAdapter = prismaAdapter(createFakePrismaClient() as PrismaClientLike);

        await adapter.users.create({
            name: 'Ada Lovelace',
            email: 'ada@example.com',
            password: 'hashed',
            verifyOTP: 'hex',
            verifyOTPExpire: 1700000000000,
        });

        const found = await adapter.users.findByEmail('ada@example.com');
        expect(found?.provider).toBe('local');
        expect(found?.providerId).toBeNull();
        // The fake stores a BigInt like the real BigInt column would; the
        // adapter must surface a plain number per the contract.
        expect(typeof found?.verifyOTPExpire).toBe('number');
        expect(found?.verifyOTPExpire).toBe(1700000000000);
    });

    it('creates OAuth users verified with a null password', async () => {
        const adapter: AuthAdapter = prismaAdapter(createFakePrismaClient() as PrismaClientLike);

        const user = await adapter.users.createOAuthUser({
            email: 'gh@example.com',
            name: 'Octocat',
            provider: 'github',
            providerId: '424242',
        });

        expect(user.isAccountVerified).toBe(true);
        expect(user.password).toBeNull();
        expect(user.provider).toBe('github');
        expect(user.providerId).toBe('424242');
    });

    it('revoke() returns true once, then false (reuse signal)', async () => {
        const adapter: AuthAdapter = prismaAdapter(createFakePrismaClient() as PrismaClientLike);
        await adapter.sessions.create({
            userId: 'u1',
            token: 'tok-abc',
            expiresAt: new Date(Date.now() + 60000),
        });

        expect(await adapter.sessions.revoke('tok-abc')).toBe(true);
        expect(await adapter.sessions.revoke('tok-abc')).toBe(false);
        expect(await adapter.sessions.revoke('never-existed')).toBe(false);
    });

    it('incrementOtpAttempts returns the post-increment count per flow', async () => {
        const fake = createFakePrismaClient();
        const adapter: AuthAdapter = prismaAdapter(fake as PrismaClientLike);
        const user = await adapter.users.create({
            name: 'Ada Lovelace',
            email: 'ada@example.com',
            password: 'hashed',
            verifyOTP: 'hex',
            verifyOTPExpire: 1,
        });

        expect(await adapter.users.incrementOtpAttempts(user.id, 'verify')).toBe(1);
        expect(await adapter.users.incrementOtpAttempts(user.id, 'verify')).toBe(2);
        // The reset flow has its own counter, untouched by verify increments.
        expect(await adapter.users.incrementOtpAttempts(user.id, 'reset')).toBe(1);
    });
});
