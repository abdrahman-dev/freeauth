import type { AuthAdapter, SessionRecord, UserAdapter, UserRecord } from '../../src/core/types.ts';

// In-memory AuthAdapter for unit tests: plain Maps standing in for the
// database, so every core test runs in milliseconds with zero I/O.
//
// Fidelity notes (deliberate, mirroring the real adapters):
// - `revoke()` is a synchronous check-and-set, which IS atomic on the JS
//   event loop: two interleaved callers cannot both observe `isRevoked:
//   false`, exactly the guarantee the Mongo/Prisma single-statement revokes
//   provide. Returns false for unknown tokens, like the real adapters.
// - `incrementOtpAttempts()` returns the authoritative post-increment count.
// - `findValid()` enforces expiry but NOT revocation (core checks
//   `isRevoked` itself, same as the Mongoose adapter).
// - Reads return shallow copies, like `toUserRecord`/`toSessionRecord` do —
//   tests that need to simulate expiry/lockout must mutate `store` directly.
// - Missing-user writes are silent no-ops (Mongoose semantics, not Prisma's
//   P2025-throw — core only writes to users it just fetched, so this never
//   fires in practice either way).

export interface FakeStore {
    users: Map<string, UserRecord>;
    // Array, not a Map: like Mongo documents, two rows may carry the same
    // token string (jsonwebtoken `iat` has 1-second resolution, so two tokens
    // minted within the same wall-clock second are byte-identical). Lookups
    // match the FIRST unexpired row, like `findOne`, and `revoke` flips the
    // first unrevoked match — mirroring `findOneAndUpdate`.
    sessions: SessionRecord[];
}

const blankFlowState = () => ({
    attempts: 0,
    lockUntil: null as Date | null,
});

export function createFakeAdapter(): { adapter: AuthAdapter; store: FakeStore } {
    let nextId = 1;
    const users = new Map<string, UserRecord>();
    const sessions: SessionRecord[] = [];

    const findByEmail = (email: string): UserRecord | null => {
        for (const user of users.values()) {
            if (user.email === email) return { ...user };
        }
        return null;
    };

    const usersAdapter: UserAdapter = {
        async findByEmail(email) {
            return findByEmail(email);
        },

        async findById(id) {
            const user = users.get(id);
            return user ? { ...user } : null;
        },

        async create(data) {
            const verify = blankFlowState();
            const reset = blankFlowState();
            const user: UserRecord = {
                id: String(nextId++),
                email: data.email,
                name: data.name,
                password: data.password,
                isAccountVerified: false,
                provider: 'local',
                providerId: null,
                verifyOTP: data.verifyOTP,
                verifyOTPExpire: data.verifyOTPExpire,
                verifyAttempts: verify.attempts,
                verifyLockUntil: verify.lockUntil,
                resetOTP: null,
                resetOTPExpire: null,
                resetAttempts: reset.attempts,
                resetLockUntil: reset.lockUntil,
            };
            users.set(user.id, user);
            return { ...user };
        },

        async createOAuthUser(data) {
            const verify = blankFlowState();
            const reset = blankFlowState();
            const user: UserRecord = {
                id: String(nextId++),
                email: data.email,
                name: data.name,
                password: null,
                isAccountVerified: true,
                provider: data.provider,
                providerId: data.providerId,
                verifyOTP: null,
                verifyOTPExpire: null,
                verifyAttempts: verify.attempts,
                verifyLockUntil: verify.lockUntil,
                resetOTP: null,
                resetOTPExpire: null,
                resetAttempts: reset.attempts,
                resetLockUntil: reset.lockUntil,
            };
            users.set(user.id, user);
            return { ...user };
        },

        async updatePassword(id, hashedPassword) {
            const user = users.get(id);
            if (user) user.password = hashedPassword;
        },

        async markVerified(id) {
            const user = users.get(id);
            if (user) user.isAccountVerified = true;
        },

        async setVerifyOTP(id, otp, expiresAt) {
            const user = users.get(id);
            if (user) {
                user.verifyOTP = otp;
                user.verifyOTPExpire = expiresAt;
            }
        },

        async setResetOTP(id, otp, expiresAt) {
            const user = users.get(id);
            if (user) {
                user.resetOTP = otp;
                user.resetOTPExpire = expiresAt;
            }
        },

        async clearVerifyOTP(id) {
            const user = users.get(id);
            if (user) {
                user.verifyOTP = null;
                user.verifyOTPExpire = null;
            }
        },

        async clearResetOTP(id) {
            const user = users.get(id);
            if (user) {
                user.resetOTP = null;
                user.resetOTPExpire = null;
            }
        },

        async incrementOtpAttempts(id, type) {
            const user = users.get(id);
            if (!user) return 0;
            if (type === 'verify') {
                user.verifyAttempts += 1;
                return user.verifyAttempts;
            }
            user.resetAttempts += 1;
            return user.resetAttempts;
        },

        async setOtpLock(id, type, lockUntil) {
            const user = users.get(id);
            if (!user) return;
            if (type === 'verify') user.verifyLockUntil = lockUntil;
            else user.resetLockUntil = lockUntil;
        },

        async resetOtpAttempts(id, type) {
            const user = users.get(id);
            if (!user) return;
            if (type === 'verify') {
                user.verifyAttempts = 0;
                user.verifyLockUntil = null;
            } else {
                user.resetAttempts = 0;
                user.resetLockUntil = null;
            }
        },
    };

    const adapter: AuthAdapter = {
        users: usersAdapter,
        sessions: {
            async create(data) {
                const record: SessionRecord = {
                    userId: data.userId,
                    token: data.token,
                    isRevoked: false,
                    expiresAt: data.expiresAt,
                    createdAt: new Date(),
                };
                sessions.push(record);
                return { ...record };
            },

            async findValid(token) {
                const record = sessions.find((s) => s.token === token && s.expiresAt > new Date());
                return record ? { ...record } : null;
            },

            async revoke(token) {
                const record = sessions.find((s) => s.token === token && !s.isRevoked);
                if (!record) return false;
                record.isRevoked = true;
                return true;
            },

            async revokeAllForUser(userId) {
                for (const record of sessions) {
                    if (record.userId === userId) record.isRevoked = true;
                }
            },
        },
    };

    return { adapter, store: { users, sessions } };
}
