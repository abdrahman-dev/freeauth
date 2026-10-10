import express from 'express';
import { validate } from '../middleware/validate.js';
import { authMiddleware } from '../middleware/authMiddleware.js';
import { registerSchema, loginSchema, googleLoginSchema, githubLoginSchema, forgotPasswordSchema, resetPasswordSchema, verifyEmailSchema, resendOTPSchema, changePasswordSchema } from '../controllers/auth/authValidation.js'; 
import {
    getApiStatus,
    registerUser,
    loginUser,
    googleLogin,
    githubOAuthState,
    githubLogin,
    logoutUser,
    refreshTokenController,
    getMe,
    forgotPassword,
    resetPassword,
    verifyEmail,
    resendOTP,
    changePassword
} from '../controllers/auth/authController.js'; 
import { 
    authLimiter,
    registerLimiter,
    refreshLimiter,
    resetPasswordLimiter,
    verifyEmailLimiter,
    resendOtpLimiter,
} from '../middleware/rateLimiter.js';

const router = express.Router();

router.get('/', getApiStatus);
router.post('/register', registerLimiter, validate(registerSchema), registerUser);
router.post('/login', authLimiter, validate(loginSchema), loginUser);
// Social logins share the password-login limiter: all three routes exchange a
// credential for a session, so they share one abuse surface and one bucket —
// an attacker doesn't get 3x the attempts by rotating login surfaces.
router.post('/google', authLimiter, validate(googleLoginSchema), googleLogin);
// Issues the OAuth `state` that POST /github later verifies. Shares the login
// limiter bucket: initiation is part of the login surface, and an attacker
// must not get a separate budget for minting states.
router.post('/github/state', authLimiter, githubOAuthState);
router.post('/github', authLimiter, validate(githubLoginSchema), githubLogin);
router.post('/logout', logoutUser);
router.post('/refresh', refreshLimiter, refreshTokenController);
router.get('/me', authMiddleware, getMe);
router.post('/forgot-password', resetPasswordLimiter, validate(forgotPasswordSchema), forgotPassword);
router.post('/reset-password', resetPasswordLimiter, validate(resetPasswordSchema), resetPassword);
router.post('/verify-email', verifyEmailLimiter, validate(verifyEmailSchema), verifyEmail);
router.post('/resend-otp', resendOtpLimiter, validate(resendOTPSchema), resendOTP);
router.post('/change-password', authMiddleware, validate(changePasswordSchema), changePassword);

export default router;