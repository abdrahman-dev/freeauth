import { auth } from '../../config/auth.ts';
import { setAuthCookies, clearAuthCookies } from '../../utils/cookies.js';
import { asyncHandler } from '../../utils/asyncHandler.js';
import { logger } from '../../src/internal/logger.js';

// Returns basic API status to confirm the server is running
export const getApiStatus = (req, res) => {
    return res.status(200).json({
        success: true,
        message: "API is working"
    });
};

export const getMe = asyncHandler(async (req, res) => {
    const user = await auth.getMe(req.user.userId);
    return res.status(200).json({ success: true, data: user });
});

// Verifies refresh token and issues a new access token if valid
export const refreshTokenController = asyncHandler(async (req, res) => {
    const { accessToken, refreshToken: newRefreshToken } = await auth.refreshSession(req.cookies?.refreshToken);

    setAuthCookies(res, accessToken, newRefreshToken);

    return res.status(200).json({
        success: true,
        message: "Token refreshed successfully",
    });
});

// Registers a new user and issues a verification OTP. Note: registration does NOT
// start a session — the account must verify its email and then log in.
export const registerUser = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const { otp } = await auth.registerUser(req.body);

    // Deliver the OTP out-of-band (email). logger.debug only prints in development,
    // so the plaintext OTP never reaches production logs.
    logger.debug(`Account verification OTP for ${email}: ${otp}`);

    return res.status(201).json({
        success: true,
        message: "User registered successfully. Please verify your email."
    });
});

// Authenticates user credentials and creates session with access/refresh tokens
export const loginUser = asyncHandler(async (req, res) => {
    const { accessToken, refreshToken } = await auth.loginUser(req.body);

    setAuthCookies(res, accessToken, refreshToken);

    return res.status(200).json({
        success: true,
        message: "Login successful"
    });
});

export const forgotPassword = asyncHandler(async (req, res) => {

    // 1) check if user with email exists
    const { email } = req.body;

    const result = await auth.forgotPassword(req.body);

    if (result.sent) {
        // Deliver the OTP out-of-band (email). logger.debug is dev-only, so the
        // plaintext reset OTP never reaches production logs.
        logger.debug(`Password reset OTP for ${email}: ${result.otp}`);
    }

    return res.status(200).json({
        success: true,
        message: "If this email exists, an OTP has been sent"
    });

});

export const resetPassword = asyncHandler(async (req, res) => {
    await auth.resetPassword(req.body);

    return res.status(200).json({
        success: true,
        message: "Password reset successful"
    });
});

export const verifyEmail = asyncHandler(async (req, res) => {

    // 1) Validate email and OTP, check if OTP is correct and not expired, then mark account as verified
    await auth.verifyEmail(req.body);

    return res.status(200).json({
        success: true,
        message: "Email verified successfully"
    });
});

export const resendOTP = asyncHandler(async (req, res) => {

    // Resends verification OTP if account is not yet verified
    const { email } = req.body;

    const result = await auth.resendOTP(req.body);

    if (result.sent) {
        // Dev-only log; deliver the OTP out-of-band (email) in real deployments.
        logger.debug(`Resend verify OTP for ${email}: ${result.otp}`);
    }

    return res.status(200).json({
        success: true,
        message: "If this email exists, a new OTP has been sent"
    });
});

// Allows authenticated user to change their password
export const changePassword = asyncHandler(async (req, res) => {
    await auth.changePassword(req.user.userId, req.body);

    return res.status(200).json({
        success: true,
        message: "Password changed successfully"
    });
});

// Revokes refresh token in DB and clears auth cookies to end user session
export const logoutUser = asyncHandler(async (req, res) => {
    const token = req.cookies?.refreshToken;

    await auth.logoutUser(token);

    clearAuthCookies(res);

    return res.status(200).json({
        success: true,
        message: "Logout successful"
    });
});
