import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMemoryRateLimitStore } from '../../../src/core/memoryRateLimitStore.ts';

describe('createMemoryRateLimitStore', () => {
  const windowMs = 60_000;
  const limit = 3;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows hits under the limit and decreases remaining', () => {
    const store = createMemoryRateLimitStore();

    const first = store.hit('login:ada@example.com', windowMs, limit);
    expect(first).toEqual({
      allowed: true,
      remaining: 2,
      resetAt: Date.now() + windowMs,
    });

    const second = store.hit('login:ada@example.com', windowMs, limit);
    expect(second.allowed).toBe(true);
    expect(second.remaining).toBe(1);

    const third = store.hit('login:ada@example.com', windowMs, limit);
    expect(third.allowed).toBe(true);
    expect(third.remaining).toBe(0);
  });

  it('rejects further hits once the limit is reached', () => {
    const store = createMemoryRateLimitStore();

    for (let i = 0; i < limit; i += 1) {
      expect(store.hit('otp:ada@example.com', windowMs, limit).allowed).toBe(true);
    }

    const blocked = store.hit('otp:ada@example.com', windowMs, limit);
    expect(blocked).toEqual({
      allowed: false,
      remaining: 0,
      resetAt: Date.now() + windowMs,
    });

    const stillBlocked = store.hit('otp:ada@example.com', windowMs, limit);
    expect(stillBlocked.allowed).toBe(false);
    expect(stillBlocked.remaining).toBe(0);
  });

  it('resets the counter after the window expires', () => {
    const store = createMemoryRateLimitStore();

    for (let i = 0; i < limit; i += 1) {
      store.hit('login:ada@example.com', windowMs, limit);
    }
    expect(store.hit('login:ada@example.com', windowMs, limit).allowed).toBe(false);

    vi.advanceTimersByTime(windowMs);

    const afterReset = store.hit('login:ada@example.com', windowMs, limit);
    expect(afterReset.allowed).toBe(true);
    expect(afterReset.remaining).toBe(limit - 1);
    expect(afterReset.resetAt).toBe(Date.now() + windowMs);
  });

  it('keeps separate keys independent', () => {
    const store = createMemoryRateLimitStore();

    for (let i = 0; i < limit; i += 1) {
      store.hit('login:ada@example.com', windowMs, limit);
    }
    expect(store.hit('login:ada@example.com', windowMs, limit).allowed).toBe(false);

    const other = store.hit('login:grace@example.com', windowMs, limit);
    expect(other.allowed).toBe(true);
    expect(other.remaining).toBe(limit - 1);
  });

  it('purges expired entries lazily so a later hit starts a fresh window', () => {
    const store = createMemoryRateLimitStore();

    store.hit('ip:1.2.3.4', windowMs, limit);
    store.hit('ip:1.2.3.4', windowMs, limit);

    vi.advanceTimersByTime(windowMs);

    // Hitting a different key still triggers purgeExpired for the whole map.
    store.hit('ip:9.9.9.9', windowMs, limit);

    const fresh = store.hit('ip:1.2.3.4', windowMs, limit);
    expect(fresh.allowed).toBe(true);
    expect(fresh.remaining).toBe(limit - 1);
  });
});
