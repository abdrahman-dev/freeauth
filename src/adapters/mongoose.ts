// Mongoose adapter — the first real implementation of the AuthAdapter contract.
// Source of truth for every shape and method name: doc/freeauth-architecture.md
// This is a relocation, not a rewrite: the queries below mirror the legacy
// repositories/userRepository.js and repositories/sessionRepository.js (since
// removed) and their models.

import userModel from '../internal/models/userModel.js';
import refreshTokenModel from '../internal/models/refreshToken.js';
import type { AuthAdapter, SessionAdapter, SessionRecord, UserAdapter, UserRecord } from '../core/types.js';

// Maps a Mongoose user document to the contract's UserRecord.
// Schema fields map 1:1 to the contract's separate verify/reset pairs.
// provider/providerId fall back to 'local'/null so pre-existing documents
// written before those fields existed still satisfy the contract.
const toUserRecord = (doc: any): UserRecord => ({
    id: doc._id.toString(),
    email: doc.email,
    name: doc.name,
    password: doc.password ?? null,

    isAccountVerified: doc.isAccountVerified ?? false,

    provider: doc.provider ?? 'local',
    providerId: doc.providerId ?? null,

    verifyOTP: doc.verifyOTP ?? null,
    verifyOTPExpire: doc.verifyOTPExpire ?? null,
    verifyAttempts: doc.verifyAttempts ?? 0,
    verifyLockUntil: doc.verifyLockUntil ?? null,

    resetOTP: doc.resetOTP ?? null,
    resetOTPExpire: doc.resetOTPExpire ?? null,
    resetAttempts: doc.resetAttempts ?? 0,
    resetLockUntil: doc.resetLockUntil ?? null,
});

const toSessionRecord = (doc: any): SessionRecord => ({
    userId: doc.userId.toString(),
    token: doc.token,
    isRevoked: doc.isRevoked ?? false,
    expiresAt: doc.expiresAt,
    createdAt: doc.createdAt,
});

const users: UserAdapter = {
    async findByEmail(email) {
        const doc = await userModel.findOne({ email });
        return doc ? toUserRecord(doc) : null;
    },

    async findById(id) {
        const doc = await userModel.findById(id);
        return doc ? toUserRecord(doc) : null;
    },

    async create(data) {
        const doc = await userModel.create({
            name: data.name,
            email: data.email,
            password: data.password,
            verifyOTP: data.verifyOTP,
            verifyOTPExpire: data.verifyOTPExpire,
        });
        return toUserRecord(doc);
    },

    // OAuth-only user: no password (schema default null applies), verified
    // immediately (Google already verified the email), no OTP fields set.
    async createOAuthUser(data) {
        const doc = await userModel.create({
            name: data.name,
            email: data.email,
            provider: data.provider,
            providerId: data.providerId,
            isAccountVerified: true,
        });
        return toUserRecord(doc);
    },

    async updatePassword(id, hashedPassword) {
        await userModel.findByIdAndUpdate(id, { password: hashedPassword });
    },

    async markVerified(id) {
        await userModel.findByIdAndUpdate(id, { isAccountVerified: true });
    },

    async clearVerifyOTP(id) {
        await userModel.findByIdAndUpdate(id, { verifyOTP: null, verifyOTPExpire: null });
    },

    async setVerifyOTP(id, otp, expiresAt) {
        await userModel.findByIdAndUpdate(id, { verifyOTP: otp, verifyOTPExpire: expiresAt });
    },

    async setResetOTP(id, otp, expiresAt) {
        await userModel.findByIdAndUpdate(id, { resetOTP: otp, resetOTPExpire: expiresAt });
    },

    async clearResetOTP(id) {
        await userModel.findByIdAndUpdate(id, { resetOTP: null, resetOTPExpire: null });
    },

    // Atomic increment ($inc + { new: true }), targeting the flow's own counter.
    async incrementOtpAttempts(id, type) {
        const attemptField = type === 'verify' ? 'verifyAttempts' : 'resetAttempts';
        const doc = await userModel.findByIdAndUpdate(
            id,
            { $inc: { [attemptField]: 1 } },
            { new: true }
        );
        return doc?.[attemptField] ?? 0;
    },

    async setOtpLock(id, type, lockUntil) {
        const lockField = type === 'verify' ? 'verifyLockUntil' : 'resetLockUntil';
        await userModel.findByIdAndUpdate(id, { [lockField]: lockUntil });
    },

    // Clears only the matching flow's counter/lock; the other flow is untouched.
    async resetOtpAttempts(id, type) {
        const fields = type === 'verify'
            ? { verifyAttempts: 0, verifyLockUntil: null }
            : { resetAttempts: 0, resetLockUntil: null };
        await userModel.findByIdAndUpdate(id, fields);
    },
};

const sessions: SessionAdapter = {
    async create(data) {
        const doc = await refreshTokenModel.create({
            userId: data.userId,
            token: data.token,
            expiresAt: data.expiresAt,
        });
        return toSessionRecord(doc);
    },

    async findValid(token) {
        const doc = await refreshTokenModel.findOne({ token, expiresAt: { $gt: new Date() } });
        return doc ? toSessionRecord(doc) : null;
    },

    // Atomic single-operation revoke exactly as documented on SessionAdapter.revoke:
    // one findOneAndUpdate with isRevoked:false in the filter. Returns true only when
    // the atomic update matched; false means the token was already revoked (or never
    // existed), which core treats as a reuse attack.
    async revoke(token) {
        const doc = await refreshTokenModel.findOneAndUpdate(
            { token, isRevoked: false },
            { isRevoked: true }
        );
        return !!doc;
    },

    async revokeAllForUser(userId) {
        await refreshTokenModel.updateMany({ userId }, { isRevoked: true });
    },
};

export function mongooseAdapter(): AuthAdapter {
    return { users, sessions };
}