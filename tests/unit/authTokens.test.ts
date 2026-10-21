import jwt from 'jsonwebtoken';
import { describe, expect, it } from 'vitest';
import { generateAccessToken, generateRefreshToken } from '../../src/internal/authTokens.js';
import { TEST_SECRETS } from '../fixtures/testUsers.ts';

// Token-layer guarantees that the rest of the session machinery depends on:
// every token is unique (a random `jti`, because `iat`/`exp` are second-
// granularity and the token string is a session's identity), and every token is
// signed HS256, which is also the only algorithm the verifier accepts.

describe('token uniqueness and algorithm pinning', () => {
    const user = { id: 'user-abc-123' };

    it('mints a different refresh token for the same user within the same second', () => {
        // No artificial delay: the point is that back-to-back calls — which share
        // an `iat` second and would previously produce byte-identical strings,
        // colliding on the adapters' unique token key — are already distinct.
        const first = generateRefreshToken(user, TEST_SECRETS.refreshTokenSecret);
        const second = generateRefreshToken(user, TEST_SECRETS.refreshTokenSecret);

        expect(first).not.toBe(second);
    });

    it('mints a different access token for the same user within the same second', () => {
        const first = generateAccessToken(user, TEST_SECRETS.accessTokenSecret);
        const second = generateAccessToken(user, TEST_SECRETS.accessTokenSecret);

        expect(first).not.toBe(second);
    });

    it('signs both token types with HS256 and accepts them when verified with HS256 pinned', () => {
        const access = generateAccessToken(user, TEST_SECRETS.accessTokenSecret);
        const refresh = generateRefreshToken(user, TEST_SECRETS.refreshTokenSecret);

        for (const [token, secret] of [
            [access, TEST_SECRETS.accessTokenSecret],
            [refresh, TEST_SECRETS.refreshTokenSecret],
        ] as const) {
            const header = jwt.decode(token, { complete: true })!.header;
            expect(header.alg).toBe('HS256');

            const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] }) as {
                userId: string;
                jti: string;
            };
            expect(decoded.userId).toBe(user.id);
            expect(decoded.jti).toBeTruthy();
        }
    });

    it('gives each token its own jti', () => {
        const first = generateRefreshToken(user, TEST_SECRETS.refreshTokenSecret);
        const second = generateRefreshToken(user, TEST_SECRETS.refreshTokenSecret);

        const firstJti = jwt.decode(first) as { jti: string };
        const secondJti = jwt.decode(second) as { jti: string };

        expect(firstJti.jti).not.toBe(secondJti.jti);
    });
});