import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL_MS } from './constants.js';

// Every token carries a random `jti`. Without it the payload is only
// { userId, iat, exp }, and since `iat`/`exp` are second-granularity, two tokens
// minted for the same user in the same second are byte-identical. For refresh
// tokens that is a correctness bug: the token string is the session's identity
// and primary key (RefreshToken.token is unique in the Prisma schema), so
// identical tokens collide — rotation ends up revoking-then-recreating the same
// string, single-session revoke/logout act on an ambiguous row, and reuse
// detection cannot tell two sessions apart. The jti makes each token unique.
//
// Secrets are passed in by the caller (core threads them through from
// createAuth's `secrets` config) — this module never reads environment config
// itself, so the library has no import-time env requirements. The signing
// algorithm is pinned to HS256 to match the verifier's pinned algorithm.
export const generateAccessToken = (user, accessTokenSecret) => {
    return jwt.sign(
        { userId: user.id, jti: crypto.randomUUID() },
        accessTokenSecret,
        { expiresIn: ACCESS_TOKEN_TTL, algorithm: 'HS256' }
    );
}

export const generateRefreshToken = (user, refreshTokenSecret) => {
    return jwt.sign(
        { userId: user.id, jti: crypto.randomUUID() },
        refreshTokenSecret,
        // jsonwebtoken takes seconds for numeric expiresIn
        { expiresIn: REFRESH_TOKEN_TTL_MS / 1000, algorithm: 'HS256' }
    );
}
