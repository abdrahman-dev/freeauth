import type { RateLimitResult, RateLimitStore } from './rateLimitStore.js';

interface Bucket {
  count: number;
  resetAt: number;
}

/**
 * In-memory RateLimitStore for single-process use.
 * Expired buckets are removed lazily inside `hit` — no timers that keep the process alive.
 */
export function createMemoryRateLimitStore(): RateLimitStore {
  const buckets = new Map<string, Bucket>();

  function purgeExpired(now: number): void {
    for (const [key, bucket] of buckets) {
      if (now >= bucket.resetAt) {
        buckets.delete(key);
      }
    }
  }

  return {
    hit(key: string, windowMs: number, limit: number): RateLimitResult {
      const now = Date.now();
      purgeExpired(now);

      let bucket = buckets.get(key);
      if (!bucket || now >= bucket.resetAt) {
        bucket = { count: 0, resetAt: now + windowMs };
        buckets.set(key, bucket);
      }

      if (bucket.count >= limit) {
        return { allowed: false, remaining: 0, resetAt: bucket.resetAt };
      }

      bucket.count += 1;
      return {
        allowed: true,
        remaining: limit - bucket.count,
        resetAt: bucket.resetAt,
      };
    },
  };
}
