# freeauth

Drop-in authentication for Node backends — OTP email verification, JWT access/refresh sessions with rotation and reuse detection, per-flow lockouts. You bring the database; freeauth brings the opinions.

> **Status:** freeauth is not published to npm yet, so `npm install freeauth` does not work yet. Until it is published, use this repository directly (see [Running the reference app locally](#running-the-reference-app-locally)).

## Requirements

- Node.js 22. CI uses Node 22, and the reference app relies on native TypeScript type-stripping for its `.ts` imports. There is no `engines` field, so this is not enforced by npm.
- A database matching your `ADAPTER`: MongoDB for `ADAPTER=mongoose`, PostgreSQL for `ADAPTER=prisma`. The automated tests do not need a real database (MongoDB runs in memory; the Prisma tests use pglite).

## Install

```sh
npm install freeauth
```

You'll also need whichever database driver your adapter uses (each is an optional peer — install only the one you need):

```sh
npm install mongoose        # for freeauth/mongoose
npm install @prisma/client  # for freeauth/prisma
```

## Quick start

```ts
import mongoose from 'mongoose';
import { createAuth } from 'freeauth';
import { mongooseAdapter } from 'freeauth/mongoose';

await mongoose.connect(process.env.MONGODB_URL);

export const auth = createAuth({
  adapter: mongooseAdapter(),
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
  },
});

const { accessToken, refreshToken, otp } = await auth.registerUser({
  name: 'Ada',
  email: 'ada@example.com',
  password: 'correct horse battery staple',
});
// deliver `otp` to the user (see Email delivery below), then:
await auth.verifyEmail({ email: 'ada@example.com', otp });
```

Everything else follows the same shape: `loginUser`, `refreshSession`, `forgotPassword`, `resetPassword`, `resendOTP`, `changePassword`, `logoutUser`, `getMe`. Failures throw `AppError` with a `statusCode` — handle them however your framework likes.

## Available adapters

- `freeauth/mongoose` — MongoDB via Mongoose. Ships with the user/session schemas it needs.
- `freeauth/prisma` — your own Prisma schema and client. Pass your generated client in: `prismaAdapter(prisma)`.

That's all there is today. If you've written one for something else, contributions are genuinely welcome — the contract it has to satisfy lives in `src/core/types.ts` and is deliberately small.

## Secrets

Secrets are explicit parameters, not environment lookups. The library never reads `process.env` itself and has no import-time requirements, so this is the entire configuration surface:

```ts
const auth = createAuth({
  adapter: mongooseAdapter(), // or prismaAdapter(prisma)
  secrets: {
    accessTokenSecret: '...',  // signs short-lived access tokens
    refreshTokenSecret: '...', // signs long-lived refresh tokens (use a different value)
  },
});
```

## Email delivery

Plainly: **freeauth does not send email.** There is no mailer inside, no SMTP settings, no provider SDK — that is a feature, not a gap.

`registerUser`, `forgotPassword`, and `resendOTP` return the raw `otp` value to your code, and delivering it is your application's job: nodemailer, Resend, SendGrid, carrier pigeon — whatever you already use. The core hashes the OTP before storing it and enforces expiry, attempt counting, and lockouts; the last mile to the inbox is yours.

## Running the reference app locally

The Express app in the repository root is a reference consumer of the library. It imports `freeauth`, `freeauth/mongoose`, and `freeauth/prisma` from `dist/` (through a `file:.` self-install), so the library must be built before the app runs.

1. Clone the repository and install dependencies:

   ```sh
   git clone https://github.com/abdrahman-dev/freeauth.git
   cd freeauth
   npm install
   ```

   `npm install` also runs `prisma generate` (the `postinstall` script), which writes `generated/prisma/`; `config/auth.ts` imports that generated client.

2. Build the library:

   ```sh
   npm run build
   ```

   This emits `dist/`. Rebuild after changing anything in `src/`; a stale `dist/` gives confusing results because the app does not read `src/` directly.

3. Copy `.env.example` to `.env` and fill it in:

   ```sh
   cp .env.example .env
   ```

   Always required: `ADAPTER` (`mongoose` or `prisma`), `PORT`, `ACCESS_TOKEN_SECRET`, and `REFRESH_TOKEN_SECRET` (both at least 32 characters and different from each other).

   Depending on the adapter:
   - `ADAPTER=mongoose`: set `MONGODB_URL`.
   - `ADAPTER=prisma`: set `DATABASE_URL`.

   Optional: `NODE_ENV` (defaults to `development`), `FRONTEND_URL` (defaults to `http://localhost:5173` in development and is required in production), and `GOOGLE_CLIENT_ID`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` for social sign-in. `.env` is ignored by git; `.env.example` is the tracked template.

   For `ADAPTER=prisma`, also apply the schema in `prisma/migrations/` to your database with the Prisma CLI (for example `npx prisma migrate dev`); no npm script wires migrations.

4. Start the app:

   ```sh
   npm start
   # or, with auto-restart:
   npm run dev
   ```

   The API is mounted at `/api/auth` and listens on `PORT`.

## Tests

```sh
npm test              # Vitest, single run
npm run test:watch    # watch mode
npm run test:coverage # Vitest with v8 coverage
npx tsc --noEmit      # type-check (there is no type-check script)
```

The Prisma adapter integration tests run against pglite, so they do not need a real PostgreSQL server. The Mongoose tests use `mongodb-memory-server`, which downloads its `mongod` binary on first run.

## Architecture

freeauth separates authentication logic from data access. The core (`src/core/`) owns hashing, OTP rules, token issuance, session rotation, and lockouts. It never imports a database driver, ORM, or model; it only calls the `AuthAdapter` interface defined in `src/core/types.ts`.

Adapters (`src/adapters/`) translate those calls into a specific database: `freeauth/mongoose` for MongoDB and `freeauth/prisma` for PostgreSQL. The reference app selects one with the `ADAPTER` environment variable. See [doc/freeauth-architecture.md](doc/freeauth-architecture.md) for the contracts and design decisions, and [doc/backend.md](doc/backend.md) for the reference app's API and behavior.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, pull request expectations, commit style, and architecture rules.

## License

MIT. See `LICENSE`.

Source: `https://github.com/abdrahman-dev/freeauth`.

---

*Note: this repository also contains a small Express reference app (`app.js`, `controllers/`, `routes/`, …) showing one way to wire the library up. It is not part of the published package — `npm` only ships `dist/` plus the metadata files.*
