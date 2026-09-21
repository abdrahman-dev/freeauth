// Prisma adapter — the second real implementation of the AuthAdapter contract.
// Source of truth for every shape and method name: doc/freeauth-architecture.md
// A faithful structural port of adapters/mongoose.ts onto Prisma's query API —
// same method list, same semantics, no redesign.
//
// Real differences from the Mongoose adapter (not ceremony, each is real):
//  - `id` maps directly: Prisma's cuid() is already a string, unlike Mongo's
//    ObjectId which had to be .toString()'d.
//  - OTP expiries (verifyOTPExpire/resetOTPExpire) are `BigInt` in Prisma; the
//    contract's UserRecord field is `number | null`, so this adapter converts on
//    read with Number(). Lossless here: epoch-ms (~1.7e12) is far below 2^53.
//    A 32-bit `Int` column would overflow at year 2038, so BigInt is the right type.
//  - revoke() uses refreshToken.updateMany -> a single UPDATE...WHERE statement;
//    count === 1 means this call won the revoke, count === 0 means the token was
//    already revoked (reuse). Same atomicity guarantee as findOneAndUpdate.
//  - prisma.user.update() throws P2025 if the id does not exist, where Mongoose's
//    findByIdAndUpdate returns null. core only writes to users it just fetched, so
//    this never fires in practice — noted as a behavioral divergence, not smoothed over.

import type { AuthAdapter, SessionAdapter, SessionRecord, UserAdapter, UserRecord } from '../core/types.js';

// Minimal structural type for the Prisma client surface this adapter uses.
// The consumer passes their own generated PrismaClient (which always satisfies
// this shape); the library never imports a generated client itself, so it has
// no build-time dependency on `prisma generate` output and ships no dangling
// type references. Args are intentionally `any`: every real Prisma delegate
// method accepts these call shapes, and the returns are the awaited row types.
export interface PrismaClientLike {
    user: {
        findUnique(args: any): Promise<PrismaUserShape | null>;
        create(args: any): Promise<PrismaUserShape>;
        update(args: any): Promise<PrismaUserShape>;
    };
    refreshToken: {
        create(args: any): Promise<PrismaTokenShape>;
        findFirst(args: any): Promise<PrismaTokenShape | null>;
        updateMany(args: any): Promise<{ count: number }>;
    };
}

// Structural stand-in for the generated Prisma client's query results, so the
// translator below is self-contained and checkable against the inferred query
// results once `prisma generate` has produced real types.
interface PrismaUserShape {
    id: string;
    email: string;
    name: string;
    password: string | null;
    isAccountVerified: boolean;
    provider: string;
    providerId: string | null;
    verifyOTP: string | null;
    verifyOTPExpire: bigint | null;
    verifyAttempts: number;
    verifyLockUntil: Date | null;
    resetOTP: string | null;
    resetOTPExpire: bigint | null;
    resetAttempts: number;
    resetLockUntil: Date | null;
    createdAt: Date;
    updatedAt: Date;
}

interface PrismaTokenShape {
    id: string;
    userId: string;
    token: string;
    isRevoked: boolean;
    expiresAt: Date;
    createdAt: Date;
}

export function prismaAdapter(prismaClient: PrismaClientLike): AuthAdapter {
    // Maps a Prisma User row to the contract's UserRecord. Field names match the
    // schema (which mirrors Mongoose naming), so the only real translation is
    // BigInt -> number on the OTP expiries; `id` flows through untouched.
    // provider falls back to 'local' so rows written before the column existed
    // still satisfy the contract.
    const toUserRecord = (user: PrismaUserShape): UserRecord => ({
        id: user.id,
        email: user.email,
        name: user.name,
        password: user.password ?? null,

        isAccountVerified: user.isAccountVerified ?? false,

        provider: (user.provider as UserRecord['provider']) ?? 'local',
        providerId: user.providerId ?? null,

        verifyOTP: user.verifyOTP ?? null,
        verifyOTPExpire: user.verifyOTPExpire != null ? Number(user.verifyOTPExpire) : null,
        verifyAttempts: user.verifyAttempts ?? 0,
        verifyLockUntil: user.verifyLockUntil ?? null,

        resetOTP: user.resetOTP ?? null,
        resetOTPExpire: user.resetOTPExpire != null ? Number(user.resetOTPExpire) : null,
        resetAttempts: user.resetAttempts ?? 0,
        resetLockUntil: user.resetLockUntil ?? null,
    });

    // Maps a Prisma RefreshToken row to the contract's SessionRecord.
    const toSessionRecord = (doc: PrismaTokenShape): SessionRecord => ({
        userId: doc.userId,
        token: doc.token,
        isRevoked: doc.isRevoked ?? false,
        expiresAt: doc.expiresAt,
        createdAt: doc.createdAt,
    });

    const users: UserAdapter = {
        async findByEmail(email) {
            const doc = await prismaClient.user.findUnique({ where: { email } });
            return doc ? toUserRecord(doc) : null;
        },

        async findById(id) {
            const doc = await prismaClient.user.findUnique({ where: { id } });
            return doc ? toUserRecord(doc) : null;
        },

        async create(data) {
            const doc = await prismaClient.user.create({
                data: {
                    name: data.name,
                    email: data.email,
                    password: data.password,
                    verifyOTP: data.verifyOTP,
                    verifyOTPExpire: data.verifyOTPExpire,
                },
            });
            return toUserRecord(doc);
        },

        // OAuth-only user: password null, verified immediately (Google already
        // verified the email), no OTP fields set.
        async createOAuthUser(data) {
            const doc = await prismaClient.user.create({
                data: {
                    name: data.name,
                    email: data.email,
                    password: null,
                    isAccountVerified: true,
                    provider: data.provider,
                    providerId: data.providerId,
                },
            });
            return toUserRecord(doc);
        },

        async updatePassword(id, hashedPassword) {
            await prismaClient.user.update({ where: { id }, data: { password: hashedPassword } });
        },

        async markVerified(id) {
            await prismaClient.user.update({ where: { id }, data: { isAccountVerified: true } });
        },

        async clearVerifyOTP(id) {
            await prismaClient.user.update({ where: { id }, data: { verifyOTP: null, verifyOTPExpire: null } });
        },

        async setVerifyOTP(id, otp, expiresAt) {
            await prismaClient.user.update({ where: { id }, data: { verifyOTP: otp, verifyOTPExpire: expiresAt } });
        },

        async setResetOTP(id, otp, expiresAt) {
            await prismaClient.user.update({ where: { id }, data: { resetOTP: otp, resetOTPExpire: expiresAt } });
        },

        async clearResetOTP(id) {
            await prismaClient.user.update({ where: { id }, data: { resetOTP: null, resetOTPExpire: null } });
        },

        // Atomic single-statement increment (UPDATE ... SET col = col + 1 WHERE id = ?),
        // mirroring mongooseAdapter's $inc + { new: true }. The returned value is the
        // authoritative post-increment count the core lockout logic relies on.
        async incrementOtpAttempts(id, type) {
            const updated = await prismaClient.user.update({
                where: { id },
                data: type === 'verify'
                    ? { verifyAttempts: { increment: 1 } }
                    : { resetAttempts: { increment: 1 } },
            });
            return type === 'verify' ? updated.verifyAttempts : updated.resetAttempts;
        },

        async setOtpLock(id, type, lockUntil) {
            await prismaClient.user.update({
                where: { id },
                data: type === 'verify'
                    ? { verifyLockUntil: lockUntil }
                    : { resetLockUntil: lockUntil },
            });
        },

        // Clears only the matching flow's counter/lock; the other flow stays untouched.
        async resetOtpAttempts(id, type) {
            await prismaClient.user.update({
                where: { id },
                data: type === 'verify'
                    ? { verifyAttempts: 0, verifyLockUntil: null }
                    : { resetAttempts: 0, resetLockUntil: null },
            });
        },
    };

    const sessions: SessionAdapter = {
        async create(data) {
            const doc = await prismaClient.refreshToken.create({
                data: {
                    userId: data.userId,
                    token: data.token,
                    expiresAt: data.expiresAt,
                },
            });
            return toSessionRecord(doc);
        },

        async findValid(token) {
            const doc = await prismaClient.refreshToken.findFirst({
                where: { token, expiresAt: { gt: new Date() } },
            });
            return doc ? toSessionRecord(doc) : null;
        },

        // A single UPDATE...WHERE statement: the WHERE (isRevoked: false) is evaluated
        // by the database as part of the same statement as the UPDATE. Two concurrent
        // calls can't both match: under MVCC the winner's UPDATE takes the row lock and
        // sets isRevoked=true; the loser's WHERE re-evaluates against that and matches
        // 0 rows. count===1 wins the revoke; count===0 means already revoked (reuse).
        async revoke(token) {
            const result = await prismaClient.refreshToken.updateMany({
                where: { token, isRevoked: false },
                data: { isRevoked: true },
            });
            return result.count === 1;
        },

        async revokeAllForUser(userId) {
            await prismaClient.refreshToken.updateMany({ where: { userId }, data: { isRevoked: true } });
        },
    };

    return { users, sessions };
}