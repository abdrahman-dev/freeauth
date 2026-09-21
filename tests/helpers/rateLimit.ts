import {
    authLimiter,
    globalLimiter,
    refreshLimiter,
    registerLimiter,
    resendOtpLimiter,
    resetPasswordLimiter,
    verifyEmailLimiter,
} from '../../middleware/rateLimiter.js';

// express-rate-limit stores buckets per limiter instance, keyed by client IP,
// and instances are module singletons — so budgets are shared by every test
// in the same FILE (vitest isolates modules per file, not per test). Call
// `resetRateLimiters()` in `beforeEach` to make each test independent.
// Supertest connects over IPv4 loopback, which Express reports as
// `::ffff:127.0.0.1`; all plausible loopback key forms are reset defensively.

const ALL_LIMITERS = [
    authLimiter,
    globalLimiter,
    refreshLimiter,
    registerLimiter,
    resendOtpLimiter,
    resetPasswordLimiter,
    verifyEmailLimiter,
];

const LOOPBACK_KEYS = ['127.0.0.1', '::ffff:127.0.0.1', '::1'];

export async function resetRateLimiters(): Promise<void> {
    for (const limiter of ALL_LIMITERS) {
        if (typeof limiter.resetKey !== 'function') continue;
        for (const key of LOOPBACK_KEYS) {
            await limiter.resetKey(key);
        }
    }
}
