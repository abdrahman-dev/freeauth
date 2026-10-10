import { env } from './env.js';

export const accessCookieOptions = {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
}

export const refreshCookieOptions = {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
}

// Short-lived holder for the GitHub OAuth `state` value between initiation
// (POST /api/auth/github/state) and callback (POST /api/auth/github).
// Same flags as the auth cookies; the 10-minute lifetime bounds how long an
// issued state stays usable. SameSite=strict is sufficient: the cookie is
// only ever read on the same-origin callback POST, never on the cross-site
// GitHub redirect itself.
export const githubOAuthStateCookieOptions = {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 10 * 60 * 1000
}


