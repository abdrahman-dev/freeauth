// Shared factories for valid test user data. Names stay within the
// `registerSchema` name rule (/^[a-zA-Z\s]+$/, 2-50 chars) and passwords meet
// the full `passwordSchema`, so the same factories work for core-level and
// HTTP-level tests. Emails are unique per call (counter suffix) so tests never
// collide on the unique-email constraint, even against a shared database.

let counter = 0;

const FIRST_NAMES = ['Ada', 'Grace', 'Alan', 'Katherine', 'Linus', 'Margaret'];
const LAST_NAMES = ['Lovelace', 'Hopper', 'Turing', 'Johnson', 'Torvalds', 'Hamilton'];

export const validPassword = () => 'Str0ng!Pass1';

export function makeRegisterData(overrides: { name?: string; email?: string; password?: string } = {}) {
    counter += 1;
    const first = FIRST_NAMES[counter % FIRST_NAMES.length];
    const last = LAST_NAMES[(counter * 7) % LAST_NAMES.length];
    return {
        name: `${first} ${last}`,
        email: `user${counter}-${Date.now()}@example.com`,
        password: validPassword(),
        ...overrides,
    };
}

// Derives a guaranteed-different OTP from a real one (flips the last digit).
// Core returns the raw OTP from registerUser/forgotPassword, so tests capture
// the real value and use this for deterministic "wrong OTP" cases.
export function wrongOtpFor(otp: string): string {
    const last = otp[otp.length - 1];
    return otp.slice(0, -1) + (last === '9' ? '8' : '9');
}

// jsonwebtoken's `iat` has 1-second resolution: two tokens minted within the
// same wall-clock second are byte-identical strings. Tests that need two
// DISTINGUISHABLE tokens (rotation replay, concurrent refresh) sleep past a
// second boundary first. This mirrors production reality rather than working
// around it — rapid successive logins genuinely share token strings.
export const sleepPastJwtSecond = () => new Promise((resolve) => setTimeout(resolve, 1100));

export const TEST_SECRETS = {
    accessTokenSecret: 'test-access-token-secret-0123456789abcdef',
    refreshTokenSecret: 'test-refresh-token-secret-fedcba9876543210',
};

export const TEST_OAUTH_CONFIG = {
    googleClientId: 'test-google-client-id.apps.googleusercontent.com',
    githubClientId: 'test-github-client-id',
    githubClientSecret: 'test-github-client-secret-0123456789',
};
