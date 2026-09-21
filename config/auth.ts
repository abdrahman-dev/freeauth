import { createAuth } from 'freeauth';
import { mongooseAdapter } from 'freeauth/mongoose';
import { prismaAdapter } from 'freeauth/prisma';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.ts';
import { env } from './env.js';

// Composition root: the single place where the adapter and the auth instance are
// constructed. Controllers import `auth` from here, never freeauth subpaths
// directly. The reference app consumes the built package exactly like an
// external consumer: `freeauth` resolves via node_modules (a `file:.` install
// of this repo's packed output) to dist/, not to src/.
// Adapter selection is explicit and symmetric — ADAPTER=mongoose or
// ADAPTER=prisma, both equally supported production-shaped paths. Secrets come
// from the app's validated env and are passed explicitly — the library never
// reads environment config itself. OAuth client IDs/secret are optional here
// exactly like in core: when unset, createAuth leaves that provider
// unconfigured and its login method throws at call time instead of failing app
// boot for deployments that don't use social sign-in yet.
const adapter =
    env.ADAPTER === 'prisma'
        ? prismaAdapter(
              new PrismaClient({
                  adapter: new PrismaPg({ connectionString: env.DATABASE_URL! }),
              })
          )
        : mongooseAdapter();

export const auth = createAuth({
    adapter,
    secrets: {
        accessTokenSecret: env.ACCESS_TOKEN_SECRET,
        refreshTokenSecret: env.REFRESH_TOKEN_SECRET,
    },
    googleClientId: env.GOOGLE_CLIENT_ID,
    githubClientId: env.GITHUB_CLIENT_ID,
    githubClientSecret: env.GITHUB_CLIENT_SECRET,
});