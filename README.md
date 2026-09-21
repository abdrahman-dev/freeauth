# freeauth

Drop-in authentication for Node backends — OTP email verification, JWT access/refresh sessions with rotation and reuse detection, per-flow lockouts. You bring the database; freeauth brings the opinions.

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

## License

MIT. See `LICENSE`.

Source: `https://github.com/abdrahman-dev/freeauth`.

---

*Note: this repository also contains a small Express reference app (`app.js`, `controllers/`, `routes/`, …) showing one way to wire the library up. It is not part of the published package — `npm` only ships `dist/` plus the metadata files.*
