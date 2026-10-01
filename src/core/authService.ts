// Core auth service, rebuilt against the AuthAdapter contract.
// Source of truth for all shapes and signatures used here: doc/openauth-architecture.md
// This is a translation of services/authService.js — the business logic (password
// hashing, JWT signing, OTP generation/verification, lockout rules, session
// rotation/reuse detection) is unchanged; only the data source changed, from Mongoose
// repositories/models to adapter.* calls. No DB driver or ORM import is allowed here.

import { hashPassword, verifyPassword } from '../internal/passwordService.js';
import { issueOTP, hashOTP } from '../internal/otpService.js';
import { generateAccessToken, generateRefreshToken } from '../internal/authTokens.js';
import { AppError } from '../internal/errors.js';
import { logger } from '../internal/logger.js';
import { REFRESH_TOKEN_TTL_MS } from '../internal/constants.js';
import type { AuthAdapter, UserRecord } from './types.js';

const MAX_OTP_ATTEMPTS = 5;
const OTP_LOCKOUT_MS = 15 * 60 * 1000;

export interface AuthSecrets {
    accessTokenSecret: string;
    refreshTokenSecret: string;
}

// The library receives already-parsed inputs from the consuming application and
// makes no assumption that the consumer validated their types. Guard every string
// input that flows into an adapter query, so a non-string value (e.g. a MongoDB
// operator object like { $gt: '' }) can never reach findByEmail and be interpreted
// as a query operator — i.e. NoSQL operator injection. Returns the value narrowed
// to `string` so callers can use the result directly.
const assertString = (value: unknown, field: string): string => {
    if (typeof value !== 'string') {
        throw new AppError(`Invalid ${field}`, 400);
    }
    return value;
};

export function createAuth(config: { adapter: AuthAdapter; secrets: AuthSecrets }) {
    const { adapter, secrets } = config;

    const checkOtpLock = (user: UserRecord, type: 'verify' | 'reset') => {
        const lockUntil = type === 'verify' ? user.verifyLockUntil : user.resetLockUntil;

        if (lockUntil && lockUntil.getTime() > Date.now()) {
            throw new AppError('Too many attempts, try again later', 429);
        }
    };

    // Mirrors otpService registerOtpMismatch. The lockout decision uses the
    // authoritative post-increment count returned by the adapter, not a count
    // guessed from the record fetched at the start of the flow.
    const registerOtpMismatch = async (user: UserRecord, type: 'verify' | 'reset') => {
        const attempts = await adapter.users.incrementOtpAttempts(user.id, type);

        if (attempts >= MAX_OTP_ATTEMPTS) {
            // Order matters. resetOtpAttempts clears the counter AND the lock together
            // (its documented contract — the success path relies on that). So it must
            // run BEFORE setOtpLock, otherwise it would null the very lock we just set
            // and the lockout would never engage (checkOtpLock could never see a future
            // lockUntil). The counter is zeroed so a fresh window of attempts is granted
            // once the lock expires.
            await adapter.users.resetOtpAttempts(user.id, type);
            await adapter.users.setOtpLock(user.id, type, new Date(Date.now() + OTP_LOCKOUT_MS));
        }
    };

    // Translation of otpService verifyAndConsumeOTP, via adapter calls instead of
    // mutating a Mongoose document and calling save().
    const verifyAndConsumeOTP = async (user: UserRecord | null, otp: string, type: 'verify' | 'reset') => {
        if (type === 'reset') {
            if (!user || !user.resetOTP || !user.resetOTPExpire) {
                throw new AppError('Invalid or expired OTP', 400);
            }

            checkOtpLock(user, 'reset');

            if (Date.now() > user.resetOTPExpire) {
                await adapter.users.clearResetOTP(user.id);
                throw new AppError('Invalid or expired OTP', 400);
            }

            if (user.resetOTP !== hashOTP(otp)) {
                await registerOtpMismatch(user, 'reset');
                throw new AppError('Invalid or expired OTP', 400);
            }

            await adapter.users.clearResetOTP(user.id);
            await adapter.users.resetOtpAttempts(user.id, 'reset');

            return true;
        }

        if (!user || !user.verifyOTP || !user.verifyOTPExpire) {
            throw new AppError('Invalid or expired OTP', 400);
        }

        checkOtpLock(user, 'verify');

        if (Date.now() > user.verifyOTPExpire) {
            await adapter.users.clearVerifyOTP(user.id);
            throw new AppError('Invalid or expired OTP', 400);
        }

        if (user.verifyOTP !== hashOTP(otp)) {
            await registerOtpMismatch(user, 'verify');
            throw new AppError('Invalid or expired OTP', 400);
        }

        // Mirror of the reset flow's success path (which clears reset fields alongside
        // the password update): clear the verify fields alongside marking verified.
        await adapter.users.markVerified(user.id);
        await adapter.users.clearVerifyOTP(user.id);
        await adapter.users.resetOtpAttempts(user.id, 'verify');

        return true;
    };

    // Translation of sessionService rotateSession.
    const rotateSession = async (oldToken: string) => {
        const storedToken = await adapter.sessions.findValid(oldToken);

        if (!storedToken) {
            throw new AppError('Invalid or expired refresh token', 401);
        }

        // A refresh token that is still present (unexpired) but ALREADY revoked being
        // presented is a reuse attempt. The legitimate client discards a refresh token
        // the instant it rotates it, so the only party replaying a revoked-but-unexpired
        // token is an attacker holding a stolen copy (or a client whose rotation response
        // was lost). Both this case and the revoke()-lost-the-race case below are reuse,
        // and both must wipe every session for the user.
        //
        // Previously the revoked token was rejected with a plain 401 at this point —
        // BEFORE revoke() could ever report the collision — so the "revoke all sessions
        // on reuse" defense could only fire on a sub-second concurrency race and never on
        // real sequential theft. The attacker's rotated session survived indefinitely.
        const reuseDetected = async (): Promise<never> => {
            await adapter.sessions.revokeAllForUser(storedToken.userId);
            logger.warn(`[SECURITY] Refresh token reuse detected for userId: ${storedToken.userId}. All sessions revoked.`);
            throw new AppError('Session invalidated due to suspicious activity, please login again', 401);
        };

        if (storedToken.isRevoked) {
            await reuseDetected();
        }

        const user = await adapter.users.findById(storedToken.userId);

        if (!user) {
            throw new AppError('User not found', 401);
        }

        const revoked = await adapter.sessions.revoke(oldToken);

        if (!revoked) {
            await reuseDetected();
        }

        const accessToken = generateAccessToken({ id: storedToken.userId }, secrets.accessTokenSecret);
        const refreshToken = generateRefreshToken({ id: storedToken.userId }, secrets.refreshTokenSecret);

        await adapter.sessions.create({
            userId: storedToken.userId,
            token: refreshToken,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        });

        return { accessToken, refreshToken };
    };

    const registerUser = async (data: { name: string; email: string; password: string }) => {
        const name = assertString(data.name, 'name');
        const email = assertString(data.email, 'email');
        const password = assertString(data.password, 'password');

        const existingUser = await adapter.users.findByEmail(email);

        if (existingUser) {
            throw new AppError('Email already in use', 409);
        }

        const hashedPassword = await hashPassword(password);

        const { otp, otpExpire, otpHash } = await issueOTP(null, 'verify');

        const user = await adapter.users.create({
            name,
            email,
            password: hashedPassword,
            verifyOTP: otpHash,
            verifyOTPExpire: otpExpire,
        });

        // Registration deliberately does NOT establish a session. Email verification is
        // a gate — loginUser refuses an unverified account — and returning working
        // access/refresh tokens here would hand a full session to an account that has
        // not proven control of its email address (and may have registered against an
        // address it does not own), bypassing that gate entirely. The caller delivers
        // `otp`, the user verifies, and then logs in to obtain tokens.
        return { userId: user.id, otp };
    };

    const loginUser = async (data: { email: string; password: string }) => {
        const email = assertString(data.email, 'email');
        const password = assertString(data.password, 'password');

        const user = await adapter.users.findByEmail(email);

        if (!user) {
            throw new AppError('Invalid email or password', 401);
        }

        const isMatch = await verifyPassword(password, user.password);

        if (!isMatch) {
            throw new AppError('Invalid email or password', 401);
        }

        if (!user.isAccountVerified) {
            throw new AppError('Please verify your email before logging in', 403);
        }

        const accessToken = generateAccessToken(user, secrets.accessTokenSecret);
        const refreshToken = generateRefreshToken(user, secrets.refreshTokenSecret);

        await adapter.sessions.create({
            userId: user.id,
            token: refreshToken,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        });

        return { accessToken, refreshToken };
    };

    const verifyEmail = async (data: { email: string; otp: string }) => {
        const email = assertString(data.email, 'email');
        const otp = assertString(data.otp, 'otp');

        const user = await adapter.users.findByEmail(email);

        await verifyAndConsumeOTP(user, otp, 'verify');

        return { verified: true };
    };

    const refreshSession = async (oldRefreshToken: string) => {
        if (!oldRefreshToken) {
            throw new AppError('No refresh token provided', 401);
        }

        return rotateSession(oldRefreshToken);
    };

    const forgotPassword = async (data: { email: string }) => {
        const email = assertString(data.email, 'email');

        const user = await adapter.users.findByEmail(email);

        if (!user) {
            return { sent: false };
        }

        // Generate OTP and save to DB with expiry
        const { otp, otpExpire, otpHash } = await issueOTP(user, 'reset');

        await adapter.users.setResetOTP(user.id, otpHash, otpExpire);

        return { sent: true, otp };
    };

    const resetPassword = async (data: { email: string; otp: string; newPassword?: string; password?: string }) => {
        const email = assertString(data.email, 'email');
        const otp = assertString(data.otp, 'otp');
        // newPassword going forward, password kept as deprecated alias. Validate it is a
        // present string BEFORE consuming the OTP — otherwise a request carrying a valid
        // OTP but no new password would burn the user's one-time OTP (and only then fail)
        // without ever changing the password, needlessly invalidating a good OTP.
        const password = assertString(data.newPassword ?? data.password, 'newPassword');

        const user = await adapter.users.findByEmail(email);

        await verifyAndConsumeOTP(user, otp, 'reset');

        // verifyAndConsumeOTP throws on a null/unknown user, so on return the account exists
        const hashedPassword = await hashPassword(password);
        await adapter.users.updatePassword(user!.id, hashedPassword);

        await adapter.sessions.revokeAllForUser(user!.id);

        return { reset: true };
    };

    const resendOTP = async (data: { email: string }) => {
        const email = assertString(data.email, 'email');

        const user = await adapter.users.findByEmail(email);

        if (!user) {
            return { sent: false };
        }

        // Account already verified
        if (user.isAccountVerified) {
            throw new AppError('Account is already verified', 400);
        }

        const { otp, otpExpire, otpHash } = await issueOTP(user, 'verify');

        // Save new OTP to DB
        await adapter.users.setVerifyOTP(user.id, otpHash, otpExpire);

        return { sent: true, otp };
    };

    const changePassword = async (userId: string, data: { currentPassword: string; newPassword: string }) => {
        const currentPassword = assertString(data.currentPassword, 'currentPassword');
        const newPassword = assertString(data.newPassword, 'newPassword');

        const user = await adapter.users.findById(userId);

        if (!user) {
            throw new AppError('User not found', 404);
        }

        // Verify current password
        const isMatch = await verifyPassword(currentPassword, user.password);

        if (!isMatch) {
            throw new AppError('Current password is incorrect', 401);
        }

        await adapter.users.updatePassword(userId, await hashPassword(newPassword));

        await adapter.sessions.revokeAllForUser(userId);

        return { changed: true };
    };

    const logoutUser = async (token: string) => {
        if (!token) {
            return { loggedOut: true };
        }

        await adapter.sessions.revoke(token);

        return { loggedOut: true };
    };

    const getMe = async (userId: string) => {
        const user = await adapter.users.findById(userId);

        if (!user) {
            throw new AppError('User not found', 404);
        }

        // The adapter returns the full UserRecord (no safe/unsafe projections); core is
        // responsible for never leaking password/OTP hashes to the controller/API layer.
        return {
            id: user.id,
            email: user.email,
            name: user.name,
            isAccountVerified: user.isAccountVerified,
        };
    };

    return {
        registerUser,
        loginUser,
        verifyEmail,
        refreshSession,
        forgotPassword,
        resetPassword,
        resendOTP,
        changePassword,
        logoutUser,
        getMe,
    };
}