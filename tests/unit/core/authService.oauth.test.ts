import { OAuth2Client } from 'google-auth-library';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuth } from '../../../src/core/authService.ts';
import { createFakeAdapter } from '../../fixtures/fakeAdapter.ts';
import type { FakeStore } from '../../fixtures/fakeAdapter.ts';
import type { AuthAdapter } from '../../../src/core/types.ts';
import { makeRegisterData, TEST_OAUTH_CONFIG, TEST_SECRETS } from '../../fixtures/testUsers.ts';

describe('loginWithGoogle', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;

    const googlePayload = (overrides = {}) => ({
        email: 'oauth-user@example.com',
        name: 'OAuth User',
        given_name: 'OAuth',
        sub: 'google-sub-123',
        email_verified: true,
        ...overrides,
    });

    const mockVerifyIdToken = (payload: Record<string, unknown> | Error) => {
        if (payload instanceof Error) {
            vi.spyOn(OAuth2Client.prototype, 'verifyIdToken').mockRejectedValue(payload);
        } else {
            vi.spyOn(OAuth2Client.prototype, 'verifyIdToken').mockResolvedValue({
                getPayload: () => payload,
            } as never);
        }
    };

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({ adapter, secrets: TEST_SECRETS, googleClientId: TEST_OAUTH_CONFIG.googleClientId });
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('creates a verified OAuth-only user and returns isNewUser:true plus a session', async () => {
        mockVerifyIdToken(googlePayload());

        const result = await auth.loginWithGoogle('valid-id-token');

        expect(result.isNewUser).toBe(true);
        expect(typeof result.accessToken).toBe('string');
        expect(typeof result.refreshToken).toBe('string');

        const stored = [...store.users.values()].find((u) => u.email === 'oauth-user@example.com')!;
        expect(stored.isAccountVerified).toBe(true);
        expect(stored.password).toBeNull();
        expect(stored.provider).toBe('google');
        expect(stored.providerId).toBe('google-sub-123');
        expect(store.sessions).toHaveLength(1);
    });

    it('throws 500 when Google sign-in is not configured (no network touched)', async () => {
        const unconfigured = createAuth({ adapter, secrets: TEST_SECRETS });
        const spy = vi.spyOn(OAuth2Client.prototype, 'verifyIdToken');

        await expect(unconfigured.loginWithGoogle('anything')).rejects.toMatchObject({
            message: 'Google sign-in is not configured',
            statusCode: 500,
        });
        expect(spy).not.toHaveBeenCalled();
    });

    it('throws 401 when no ID token is provided', async () => {
        await expect(auth.loginWithGoogle('')).rejects.toMatchObject({
            message: 'No Google ID token provided',
            statusCode: 401,
        });
    });

    it('throws 401 when verification fails (bad signature / expired)', async () => {
        mockVerifyIdToken(new Error('Token used too late'));

        await expect(auth.loginWithGoogle('bogus-token')).rejects.toMatchObject({
            message: 'Invalid or expired Google ID token',
            statusCode: 401,
        });
        expect(store.users.size).toBe(0);
    });

    it('throws 401 when the payload lacks email or sub', async () => {
        mockVerifyIdToken(googlePayload({ email: undefined }));

        await expect(auth.loginWithGoogle('token-without-email')).rejects.toMatchObject({
            message: 'Invalid or expired Google ID token',
            statusCode: 401,
        });
    });

    it('throws 403 when email_verified is not true', async () => {
        mockVerifyIdToken(googlePayload({ email_verified: false }));

        await expect(auth.loginWithGoogle('unverified-token')).rejects.toMatchObject({
            message: 'Google account email is not verified',
            statusCode: 403,
        });
        expect(store.users.size).toBe(0);
    });

    it('rejects a pre-existing email with 409 (no linking, regardless of provider)', async () => {
        const data = makeRegisterData({ email: 'oauth-user@example.com' });
        const reg = await auth.registerUser(data);
        await auth.verifyEmail({ email: data.email, otp: reg.otp });
        mockVerifyIdToken(googlePayload());

        await expect(auth.loginWithGoogle('valid-id-token')).rejects.toMatchObject({
            message: 'An account already exists with this email. Sign in with your password instead.',
            statusCode: 409,
        });
        expect(store.users.size).toBe(1);
        expect(store.sessions).toHaveLength(1); // register session only — no OAuth session issued
    });

    it('falls back to given_name when the payload has no name', async () => {
        mockVerifyIdToken(googlePayload({ name: undefined }));

        await auth.loginWithGoogle('valid-id-token');

        const stored = [...store.users.values()].find((u) => u.email === 'oauth-user@example.com')!;
        expect(stored.name).toBe('OAuth');
    });

    it('falls back to the email when the payload has neither name nor given_name', async () => {
        mockVerifyIdToken(googlePayload({ name: undefined, given_name: undefined }));

        await auth.loginWithGoogle('valid-id-token');

        const stored = [...store.users.values()].find((u) => u.email === 'oauth-user@example.com')!;
        expect(stored.name).toBe('oauth-user@example.com');
    });
});

describe('loginWithGithub', () => {
    let adapter: AuthAdapter;
    let store: FakeStore;
    let auth: ReturnType<typeof createAuth>;
    let fetchMock: ReturnType<typeof vi.fn>;

    const profile = { id: 424242, login: 'octocat', name: 'The Octocat' };
    const primaryVerifiedEmails = [
        { email: 'secondary@example.com', primary: false, verified: true },
        { email: 'octocat@example.com', primary: true, verified: true },
    ];

    // Minimal fetch stub routing on URL, mirroring GitHub's three endpoints.
    const mockGithub = (
        overrides: {
            token?: unknown;
            profile?: unknown;
            emails?: unknown;
            failWith?: Error;
            profileOk?: boolean;
            emailsOk?: boolean;
            profileThrows?: Error;
        } = {}
    ) => {
        fetchMock = vi.fn(async (url: string) => {
            if (overrides.failWith) throw overrides.failWith;
            if (url.includes('/login/oauth/access_token')) {
                const body = overrides.token !== undefined ? overrides.token : { access_token: 'gho_testtoken' };
                return { ok: true, json: async () => body };
            }
            if (url.includes('/user/emails')) {
                if (overrides.profileThrows) throw overrides.profileThrows;
                return {
                    ok: overrides.emailsOk ?? true,
                    json: async () => overrides.emails ?? primaryVerifiedEmails,
                };
            }
            return {
                ok: overrides.profileOk ?? true,
                json: async () => overrides.profile ?? profile,
            };
        });
        vi.stubGlobal('fetch', fetchMock);
    };

    beforeEach(() => {
        ({ adapter, store } = createFakeAdapter());
        auth = createAuth({
            adapter,
            secrets: TEST_SECRETS,
            githubClientId: TEST_OAUTH_CONFIG.githubClientId,
            githubClientSecret: TEST_OAUTH_CONFIG.githubClientSecret,
        });
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    it('creates a verified OAuth-only user from the PRIMARY+verified email (not the first entry)', async () => {
        mockGithub();

        const result = await auth.loginWithGithub('valid-code', 'state-abc', 'state-abc');

        expect(result.isNewUser).toBe(true);
        const stored = [...store.users.values()].find((u) => u.email === 'octocat@example.com')!;
        expect(stored.isAccountVerified).toBe(true);
        expect(stored.password).toBeNull();
        expect(stored.provider).toBe('github');
        expect(stored.providerId).toBe('424242');
        expect(stored.name).toBe('The Octocat');
    });

    it('throws 500 when GitHub sign-in is not configured', async () => {
        const unconfigured = createAuth({ adapter, secrets: TEST_SECRETS });
        mockGithub();

        await expect(unconfigured.loginWithGithub('code', 's', 's')).rejects.toMatchObject({
            message: 'GitHub sign-in is not configured',
            statusCode: 500,
        });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('throws 401 when no code is provided', async () => {
        mockGithub();

        await expect(auth.loginWithGithub('', 's', 's')).rejects.toMatchObject({
            message: 'No GitHub authorization code provided',
            statusCode: 401,
        });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('throws 401 on state mismatch WITHOUT calling GitHub (check runs before exchange)', async () => {
        mockGithub();

        await expect(auth.loginWithGithub('valid-code', 'attacker-state', 'expected-state')).rejects.toMatchObject({
            message: 'Invalid OAuth state. Please try signing in again.',
            statusCode: 401,
        });
        expect(fetchMock).not.toHaveBeenCalled();
        expect(store.users.size).toBe(0);
    });

    it('throws 401 when state is missing on either side', async () => {
        mockGithub();

        await expect(auth.loginWithGithub('valid-code', undefined, 'expected-state')).rejects.toMatchObject({
            statusCode: 401,
        });
        await expect(auth.loginWithGithub('valid-code', 'expected-state', undefined)).rejects.toMatchObject({
            statusCode: 401,
        });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('throws 401 when GitHub reports an error body instead of an access token', async () => {
        mockGithub({ token: { error: 'bad_verification_code', error_description: 'expired' } });

        await expect(auth.loginWithGithub('stale-code', 's', 's')).rejects.toMatchObject({
            message: 'Invalid or expired GitHub authorization code',
            statusCode: 401,
        });
    });

    it('throws 401 when the token exchange request itself fails', async () => {
        mockGithub({ failWith: new Error('socket hang up') });

        await expect(auth.loginWithGithub('valid-code', 's', 's')).rejects.toMatchObject({
            message: 'Invalid or expired GitHub authorization code',
            statusCode: 401,
        });
    });

    it('throws 403 when no email is both primary AND verified', async () => {
        mockGithub({
            emails: [
                { email: 'unverified-primary@example.com', primary: true, verified: false },
                { email: 'verified-secondary@example.com', primary: false, verified: true },
            ],
        });

        await expect(auth.loginWithGithub('valid-code', 's', 's')).rejects.toMatchObject({
            message: 'GitHub account email is not verified',
            statusCode: 403,
        });
        expect(store.users.size).toBe(0);
    });

    it('throws 401 when the GitHub profile/emails endpoints answer non-OK', async () => {
        mockGithub({ profileOk: false });

        await expect(auth.loginWithGithub('valid-code', 's', 's')).rejects.toMatchObject({
            message: 'Failed to authenticate with GitHub',
            statusCode: 401,
        });
        expect(store.users.size).toBe(0);
    });

    it('throws 401 when the profile/emails fetch throws mid-flight', async () => {
        mockGithub({ profileThrows: new Error('socket hang up') });

        await expect(auth.loginWithGithub('valid-code', 's', 's')).rejects.toMatchObject({
            message: 'Failed to authenticate with GitHub',
            statusCode: 401,
        });
        expect(store.users.size).toBe(0);
    });

    it('throws 401 when the profile carries no usable user id', async () => {
        mockGithub({ profile: { login: 'octocat', name: 'The Octocat' } });

        await expect(auth.loginWithGithub('valid-code', 's', 's')).rejects.toMatchObject({
            message: 'Failed to authenticate with GitHub',
            statusCode: 401,
        });
        expect(store.users.size).toBe(0);
    });

    it('throws 403 when the emails payload is not a list at all', async () => {
        mockGithub({ emails: { message: 'unexpected shape' } });

        await expect(auth.loginWithGithub('valid-code', 's', 's')).rejects.toMatchObject({
            message: 'GitHub account email is not verified',
            statusCode: 403,
        });
        expect(store.users.size).toBe(0);
    });

    it('falls back to login, then email, when profile name fields are absent', async () => {
        mockGithub({ profile: { id: 777 } });

        await auth.loginWithGithub('valid-code', 's', 's');

        const stored = [...store.users.values()].find((u) => u.email === 'octocat@example.com')!;
        expect(stored.name).toBe('octocat@example.com');
    });

    it('rejects a pre-existing email with 409 (no linking)', async () => {
        const data = makeRegisterData({ email: 'octocat@example.com' });
        const reg = await auth.registerUser(data);
        await auth.verifyEmail({ email: data.email, otp: reg.otp });
        mockGithub();

        await expect(auth.loginWithGithub('valid-code', 's', 's')).rejects.toMatchObject({
            message: 'An account already exists with this email. Sign in with your password instead.',
            statusCode: 409,
        });
        expect(store.users.size).toBe(1);
    });
});
