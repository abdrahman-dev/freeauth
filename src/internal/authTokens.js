import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL_MS } from './constants.js';

// Every token carries a random `jti`. Without it the payload is only
// { userId, iat, exp }, and since `iat`/`exp` are second-granularity, two tokens
// minted for the same user in the same second are byte-identical. For refresh
// tokens that is a correctness bug: the token string IS the session's identity
// (and its unique key in both adapters), so identical tokens collide — rotation
// would revoke-then-recreate the same string, single-session revoke/logout would
// act on an ambiguous row, and reuse detection could not tell two sessions apart.
// The jti makes every token distinct.
//
// Secrets are passed in by the caller (core threads them through from
// createAuth's `secrets` config) — this module never reads environment
// config itself, so the library has no import-time env requirements. The signing
// algorithm is pinned to HS256 to match the pinned algorithm the verifier
// accepts (`middleware/authMiddleware.js`), so neither side can be steered into
// a different algorithm.
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
