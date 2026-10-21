// Core auth service, rebuilt against the AuthAdapter contract.
// Source of truth for all shapes and signatures used here: doc/freeauth-architecture.md
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
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';
import type { AuthAdapter, UserRecord } from './types.js';

const MAX_OTP_ATTEMPTS = 5;
const OTP_LOCKOUT_MS = 15 * 60 * 1000;

export interface AuthSecrets {
    accessTokenSecret: string;
    refreshTokenSecret: string;
}

export function createAuth(config: { adapter: AuthAdapter; secrets: AuthSecrets; googleClientId?: string; githubClientId?: string; githubClientSecret?: string }) {
    const { adapter, secrets, googleClientId, githubClientId, githubClientSecret } = config;

    // Verifies Google ID tokens for loginWithGoogle. Constructed once; the client
    // ID doubles as the expected audience so tokens minted for another OAuth app
    // are rejected. Null when the consumer did not configure Google sign-in.
    const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

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
            // Order matters: reset the counter FIRST, then set the lock.
            // resetOtpAttempts clears the flow's counter AND lock together, so
            // setting the lock afterwards is what makes the lockout stick —
            // the reverse order (lock, then reset) silently cleared the lock
            // it just set, and sequential brute-forcing never locked out.
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

        if (storedToken.isRevoked) {
            await adapter.sessions.revokeAllForUser(storedToken.userId);

            logger.warn(`[SECURITY] Refresh token reuse detected for userId: ${storedToken.userId}. All sessions revoked.`);

            throw new AppError('Session invalidated due to suspicious activity, please login again', 401);
        }

        const user = await adapter.users.findById(storedToken.userId);

        if (!user) {
            throw new AppError('User not found', 401);
        }

        const revoked = await adapter.sessions.revoke(oldToken);

        if (!revoked) {
            await adapter.sessions.revokeAllForUser(storedToken.userId);

            logger.warn(`[SECURITY] Refresh token reuse detected for userId: ${storedToken.userId}. All sessions revoked.`);

            throw new AppError('Session invalidated due to suspicious activity, please login again', 401);
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

    // Shared session issuance: mint a fresh access/refresh pair for an already-
    // authenticated user and persist the refresh side server-side. Used by the
    // OAuth logins; existing methods keep their inline copies untouched.
    const issueSession = async (user: { id: string }) => {
        const accessToken = generateAccessToken(user, secrets.accessTokenSecret);
        const refreshToken = generateRefreshToken(user, secrets.refreshTokenSecret);

        await adapter.sessions.create({
            userId: user.id,
            token: refreshToken,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        });

        return { accessToken, refreshToken };
    };

    // OAuth `state` check (CSRF protection for the authorization-code flow).
    // Compares two opaque strings — the value GitHub echoed back vs. the value
    // stored at initiation time — so core never touches HTTP cookies directly;
    // the caller (e.g. the Express controller) owns all cookie/session I/O and
    // just passes both values in. Constant-time comparison so a mismatch leaks
    // nothing about the expected value. Missing, non-string, or mismatched
    // values all reject identically with 401, before any code exchange happens.
    const verifyOAuthState = (receivedState: unknown, expectedState: unknown) => {
        const received = typeof receivedState === 'string' ? receivedState : '';
        const expected = typeof expectedState === 'string' ? expectedState : '';
        const receivedBuf = Buffer.from(received);
        const expectedBuf = Buffer.from(expected);

        if (
            !received ||
            !expected ||
            receivedBuf.length !== expectedBuf.length ||
            !crypto.timingSafeEqual(receivedBuf, expectedBuf)
        ) {
            throw new AppError('Invalid OAuth state. Please try signing in again.', 401);
        }
    };

    // Shared OAuth tail: reject any pre-existing account with the same email
    // (no linking/merging — the explicit safety boundary of this version),
    // otherwise create an OAuth-only user and issue a session. Used by both
    // loginWithGoogle and loginWithGithub so the rejection/session logic
    // exists in exactly one place.
    const completeOAuthLogin = async (data: { email: string; name: string; provider: 'google' | 'github'; providerId: string }) => {
        const existingUser = await adapter.users.findByEmail(data.email);

        if (existingUser) {
            throw new AppError('An account already exists with this email. Sign in with your password instead.', 409);
        }

        const user = await adapter.users.createOAuthUser({
            email: data.email,
            name: data.name,
            provider: data.provider,
            providerId: data.providerId,
        });

        const { accessToken, refreshToken } = await issueSession(user);

        return { accessToken, refreshToken, isNewUser: true };
    };

    const registerUser = async (data: { name: string; email: string; password: string }) => {
        const { name, email, password } = data;

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

        const accessToken = generateAccessToken(user, secrets.accessTokenSecret);
        const refreshToken = generateRefreshToken(user, secrets.refreshTokenSecret);

        await adapter.sessions.create({
            userId: user.id,
            token: refreshToken,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        });

        return { accessToken, refreshToken, otp };
    };

    const loginUser = async (data: { email: string; password: string }) => {
        const { email, password } = data;

        const user = await adapter.users.findByEmail(email);

        if (!user) {
            throw new AppError('Invalid email or password', 401);
        }

        // OAuth-only accounts have no local password; reject before bcrypt.
        if (!user.password) {
            throw new AppError('This account uses social sign-in. Please sign in with the provider you originally used.', 401);
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

    // Google OAuth sign-in. Verifies the ID token against Google's public keys
    // (signature, expiry, and audience == our OAuth client ID) via the official
    // google-auth-library — never hand-rolled JWT verification.
    // First-time Google users get an OAuth-only account (verified, no password,
    // no OTP flow) plus a fresh session. Any pre-existing account with the same
    // email is rejected instead of linked/merged — that is the explicit safety
    // boundary of this first version; linking is a separate future task.
    const loginWithGoogle = async (idToken: string) => {
        if (!googleClient) {
            throw new AppError('Google sign-in is not configured', 500);
        }

        if (!idToken) {
            throw new AppError('No Google ID token provided', 401);
        }

        let email: string | undefined;
        let name: string | undefined;
        let providerId: string | undefined;
        let emailVerified: boolean | undefined;

        try {
            const ticket = await googleClient.verifyIdToken({
                idToken,
                audience: googleClientId,
            });
            const payload = ticket.getPayload();
            email = payload?.email;
            name = payload?.name ?? payload?.given_name;
            providerId = payload?.sub;
            emailVerified = payload?.email_verified;
        } catch {
            throw new AppError('Invalid or expired Google ID token', 401);
        }

        if (!email || !providerId) {
            throw new AppError('Invalid or expired Google ID token', 401);
        }

        if (emailVerified !== true) {
            throw new AppError('Google account email is not verified', 403);
        }

        return completeOAuthLogin({ email, name: name ?? email, provider: 'google', providerId });
    };

    // GitHub OAuth sign-in. Unlike Google's single verified JWT, GitHub's flow is
    // plain HTTP: exchange the authorization code for an access token, then fetch
    // the profile and email list with it (global fetch, no dedicated library —
    // there is no signature to verify). Mirrors loginWithGoogle's structure and
    // shares its tail (completeOAuthLogin): pre-existing emails are rejected,
    // first-time users get an OAuth-only account plus a fresh session.
    // `receivedState` is the `state` value GitHub echoed back on the callback;
    // `expectedState` is the value stored at initiation time (see
    // POST /api/auth/github/state in the reference app). They are compared
    // before the code exchange, so a forged or missing binding never reaches GitHub.
    const loginWithGithub = async (code: string, receivedState?: string, expectedState?: string) => {
        if (!githubClientId || !githubClientSecret) {
            throw new AppError('GitHub sign-in is not configured', 500);
        }

        if (!code) {
            throw new AppError('No GitHub authorization code provided', 401);
        }

        verifyOAuthState(receivedState, expectedState);

        // 1) Exchange the code for a user access token. GitHub answers 200 with
        // an { error } body (not a non-2xx status) for bad/expired codes, so the
        // presence of access_token — not the HTTP status alone — decides success.
        let tokenJson: any;
        try {
            const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    client_id: githubClientId,
                    client_secret: githubClientSecret,
                    code,
                }),
            });
            tokenJson = await tokenRes.json();
        } catch (error) {
            if (error instanceof AppError) throw error;
            throw new AppError('Invalid or expired GitHub authorization code', 401);
        }

        const githubAccessToken = tokenJson?.access_token;

        if (typeof githubAccessToken !== 'string' || !githubAccessToken) {
            throw new AppError('Invalid or expired GitHub authorization code', 401);
        }

        // 2) Fetch profile + email list with the access token.
        const githubHeaders = {
            Authorization: `Bearer ${githubAccessToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'freeauth',
        };

        let profile: any;
        let emails: any;
        try {
            const [profileRes, emailsRes] = await Promise.all([
                fetch('https://api.github.com/user', { headers: githubHeaders }),
                fetch('https://api.github.com/user/emails', { headers: githubHeaders }),
            ]);

            if (!profileRes.ok || !emailsRes.ok) {
                throw new AppError('Failed to authenticate with GitHub', 401);
            }

            profile = await profileRes.json();
            emails = await emailsRes.json();
        } catch (error) {
            if (error instanceof AppError) throw error;
            throw new AppError('Failed to authenticate with GitHub', 401);
        }

        // 3) The qualifying email is the one that is BOTH primary and verified —
        // never just the first entry, never an unverified one.
        const qualifying = Array.isArray(emails)
            ? emails.find((entry) => entry?.primary === true && entry?.verified === true)
            : undefined;

        const email: string | undefined = qualifying?.email;

        if (!email) {
            throw new AppError('GitHub account email is not verified', 403);
        }

        const providerId = profile?.id != null ? String(profile.id) : undefined;

        if (!providerId) {
            throw new AppError('Failed to authenticate with GitHub', 401);
        }

        const name: string = profile?.name ?? profile?.login ?? email;

        return completeOAuthLogin({ email, name, provider: 'github', providerId });
    };

    const verifyEmail = async (data: { email: string; otp: string }) => {
        const { email, otp } = data;

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
        const { email } = data;

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
        const { email, otp } = data;
        // newPassword going forward, password kept as deprecated alias
        const password = data.newPassword ?? data.password;

        const user = await adapter.users.findByEmail(email);

        await verifyAndConsumeOTP(user, otp, 'reset');

        // verifyAndConsumeOTP throws on a null/unknown user, so on return the account exists
        const hashedPassword = await hashPassword(password);
        await adapter.users.updatePassword(user!.id, hashedPassword);

        await adapter.sessions.revokeAllForUser(user!.id);

        return { reset: true };
    };

    const resendOTP = async (data: { email: string }) => {
        const { email } = data;

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
        const { currentPassword, newPassword } = data;

        const user = await adapter.users.findById(userId);

        if (!user) {
            throw new AppError('User not found', 404);
        }

        // OAuth-only accounts have no local password; reject before bcrypt.
        if (!user.password) {
            throw new AppError('This account uses social sign-in. Please sign in with the provider you originally used.', 401);
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
        loginWithGoogle,
        loginWithGithub,
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