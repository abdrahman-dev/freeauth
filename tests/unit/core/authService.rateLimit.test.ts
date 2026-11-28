import { beforeEach, describe, expect, it } from 'vitest';
import { createAuth } from '../../../src/core/authService.ts';
import { createMemoryRateLimitStore } from '../../../src/core/memoryRateLimitStore.ts';
import { createFakeAdapter } from '../../fixtures/fakeAdapter.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { makeRegisterData, TEST_SECRETS, wrongOtpFor } from '../../fixtures/testUsers.ts';

describe('createAuth rateLimit option', () => {
  let adapter: AuthAdapter;

  beforeEach(() => {
    ({ adapter } = createFakeAdapter());
  });

  async function registerVerified(auth: ReturnType<typeof createAuth>, overrides = {}) {
    const data = makeRegisterData(overrides);
    const reg = await auth.registerUser(data);
    await auth.verifyEmail({ email: data.email, otp: reg.otp });
    return data;
  }

  it('leaves login and OTP behavior unchanged when rateLimit is omitted', async () => {
    const auth = createAuth({ adapter, secrets: TEST_SECRETS });
    const data = await registerVerified(auth);

    for (let i = 0; i < 8; i += 1) {
      await expect(auth.loginUser({ email: data.email, password: data.password })).resolves.toMatchObject({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
      });
    }

    const pending = makeRegisterData();
    const reg = await auth.registerUser(pending);
    await expect(
      auth.verifyEmail({ email: pending.email, otp: wrongOtpFor(reg.otp) })
    ).rejects.toMatchObject({ statusCode: 400 });
  });

  it('blocks login after the configured limit and returns 429', async () => {
    const auth = createAuth({
      adapter,
      secrets: TEST_SECRETS,
      rateLimit: {
        store: createMemoryRateLimitStore(),
        login: { windowMs: 60_000, limit: 2 },
      },
    });
    const data = await registerVerified(auth);

    await auth.loginUser({ email: data.email, password: data.password });
    await auth.loginUser({ email: data.email, password: data.password });

    await expect(auth.loginUser({ email: data.email, password: data.password })).rejects.toMatchObject({
      message: 'Too many requests, please try again later',
      statusCode: 429,
    });
  });

  it('blocks verifyEmail after the otpVerify limit', async () => {
    const auth = createAuth({
      adapter,
      secrets: TEST_SECRETS,
      rateLimit: {
        store: createMemoryRateLimitStore(),
        otpVerify: { windowMs: 60_000, limit: 2 },
      },
    });
    const data = makeRegisterData();
    const reg = await auth.registerUser(data);
    const wrong = wrongOtpFor(reg.otp);

    await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
      statusCode: 400,
    });
    await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
      statusCode: 400,
    });
    await expect(auth.verifyEmail({ email: data.email, otp: wrong })).rejects.toMatchObject({
      message: 'Too many requests, please try again later',
      statusCode: 429,
    });
  });

  it('applies otpVerify limit to resetPassword as well', async () => {
    // Register without rateLimit so verifyEmail does not consume otpVerify budget.
    const setup = createAuth({ adapter, secrets: TEST_SECRETS });
    const data = await registerVerified(setup);
    const auth = createAuth({
      adapter,
      secrets: TEST_SECRETS,
      rateLimit: {
        store: createMemoryRateLimitStore(),
        otpVerify: { windowMs: 60_000, limit: 1 },
      },
    });
    const forgot = await auth.forgotPassword({ email: data.email });
    expect(forgot.sent).toBe(true);

    await expect(
      auth.resetPassword({
        email: data.email,
        otp: wrongOtpFor(forgot.otp!),
        newPassword: 'AnotherPass1!',
      })
    ).rejects.toMatchObject({ statusCode: 400 });

    await expect(
      auth.resetPassword({
        email: data.email,
        otp: forgot.otp!,
        newPassword: 'AnotherPass1!',
      })
    ).rejects.toMatchObject({
      message: 'Too many requests, please try again later',
      statusCode: 429,
    });
  });

  it('rate-limits by IP independently when ip is supplied', async () => {
    const setup = createAuth({ adapter, secrets: TEST_SECRETS });
    const first = await registerVerified(setup, { email: 'one@example.com' });
    const second = await registerVerified(setup, { email: 'two@example.com' });
    const auth = createAuth({
      adapter,
      secrets: TEST_SECRETS,
      rateLimit: {
        store: createMemoryRateLimitStore(),
        login: { windowMs: 60_000, limit: 1 },
      },
    });

    await auth.loginUser({ email: first.email, password: first.password, ip: '1.1.1.1' });

    await expect(
      auth.loginUser({ email: second.email, password: second.password, ip: '1.1.1.1' })
    ).rejects.toMatchObject({
      message: 'Too many requests, please try again later',
      statusCode: 429,
    });

    await expect(
      auth.loginUser({ email: second.email, password: second.password, ip: '2.2.2.2' })
    ).resolves.toMatchObject({ accessToken: expect.any(String) });
  });

  it('does not limit login when only otpVerify is configured', async () => {
    const auth = createAuth({
      adapter,
      secrets: TEST_SECRETS,
      rateLimit: {
        store: createMemoryRateLimitStore(),
        otpVerify: { windowMs: 60_000, limit: 1 },
      },
    });
    const data = await registerVerified(auth);

    await auth.loginUser({ email: data.email, password: data.password });
    await auth.loginUser({ email: data.email, password: data.password });
    await expect(auth.loginUser({ email: data.email, password: data.password })).resolves.toMatchObject({
      accessToken: expect.any(String),
    });
  });
});
