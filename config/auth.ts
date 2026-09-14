import { createAuth } from 'openauth';
import { mongooseAdapter } from 'openauth/mongoose';
import { env } from './env.js';

// Composition root: the single place where the adapter and the auth instance are
// constructed. Controllers import `auth` from here, never openauth subpaths
// directly. The reference app consumes the built package exactly like an
// external consumer: `openauth` resolves via node_modules (a `file:.` install
// of this repo's packed output) to dist/, not to src/.
// Secrets come from the app's validated env and are passed explicitly — the
// library never reads environment config itself.
export const auth = createAuth({
    adapter: mongooseAdapter(),
    secrets: {
        accessTokenSecret: env.ACCESS_TOKEN_SECRET,
        refreshTokenSecret: env.REFRESH_TOKEN_SECRET,
    },
});