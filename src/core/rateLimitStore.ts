// Rate limiting (this module) vs OTP/account lockout (authService):
// - Lockout is per-account after failed OTP attempts (verifyLockUntil / resetLockUntil).
// - Rate limiting is per opaque key (e.g. email or IP) inside a time window, and does
//   not care whether the attempt succeeded or failed. Callers pass the key; core never
//   reads IP/email from a framework request object.

/**
 * Outcome of one `hit` against a rate-limit bucket.
 * `resetAt` is epoch milliseconds when the current window ends.
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

/**
 * Pluggable store for core rate limiting. Implementations may be sync or async
 * (in-memory today; Redis or others later). Core must not import any DB driver here.
 */
export interface RateLimitStore {
  hit(
    key: string,
    windowMs: number,
    limit: number,
  ): Promise<RateLimitResult> | RateLimitResult;
}
