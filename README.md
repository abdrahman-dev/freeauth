# openauth

Drop-in authentication for Node backends — OTP email verification, JWT access/refresh sessions with rotation and reuse detection, per-flow lockouts. You bring the database; openauth brings the opinions.

## Install

```sh
npm install openauth
```

You'll also need whichever database driver your adapter uses (each is an optional peer — install only the one you need):

```sh
npm install mongoose        # for openauth/mongoose
npm install @prisma/client  # for openauth/prisma
```

## Quick start

```ts
import mongoose from 'mongoose';
import { createAuth } from 'openauth';
import { mongooseAdapter } from 'openauth/mongoose';

await mongoose.connect(process.env.MONGODB_URL);

export const auth = createAuth({
  adapter: mongooseAdapter(),
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
  },
});

const { userId, otp } = await auth.registerUser({
  name: 'Ada',
  email: 'ada@example.com',
  password: 'correct horse battery staple',
});
// Registration does NOT start a session. Deliver `otp` to the user (see Email
// delivery below), have them verify, and THEN log in to get tokens:
await auth.verifyEmail({ email: 'ada@example.com', otp });
const { accessToken, refreshToken } = await auth.loginUser({
  email: 'ada@example.com',
  password: 'correct horse battery staple',
});
```

Everything else follows the same shape: `loginUser`, `refreshSession`, `forgotPassword`, `resetPassword`, `resendOTP`, `changePassword`, `logoutUser`, `getMe`. Failures throw `AppError` with a `statusCode` — handle them however your framework likes.

## Security notes

- **Registration issues no session.** `registerUser` returns `{ userId, otp }` only — not tokens. Email verification is a gate (`loginUser` refuses an unverified account), so handing a working session to an unverified registration would defeat it. The flow is register → verify → login.
- **Email verification / password-reset OTPs** are rate-limited per account: 5 wrong attempts lock that flow for 15 minutes. This bounds online guessing of the 6-digit OTP, but you should still rate-limit the HTTP layer by IP/identifier — the library cannot see your transport.
- **Refresh-token rotation + reuse detection.** Each refresh rotates to a brand-new token and revokes the old one; presenting an already-revoked (but unexpired) refresh token is treated as theft and revokes *every* session for that user. A client whose rotation response is lost will therefore have to log in again — this is intentional.
- **Access tokens are stateless.** `changePassword`, `resetPassword`, and reuse-detection revoke *refresh* tokens immediately, but an already-issued access token stays valid until it expires (default 15 minutes). Keep the access-token TTL short; it is the window in which a pre-change token still works.
- **Inputs are trusted to be the declared types but checked anyway.** The library validates that fields like `email`/`otp`/`password` are strings before they reach the database layer, so passing an unvalidated object cannot turn into a query-operator injection — but you should still validate and shape input at your edge.

## Available adapters

- `openauth/mongoose` — MongoDB via Mongoose. Ships with the user/session schemas it needs.
- `openauth/prisma` — your own Prisma schema and client. Pass your generated client in: `prismaAdapter(prisma)`.

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

Plainly: **openauth does not send email.** There is no mailer inside, no SMTP settings, no provider SDK — that is a feature, not a gap.

`registerUser`, `forgotPassword`, and `resendOTP` return the raw `otp` value to your code, and delivering it is your application's job: nodemailer, Resend, SendGrid, carrier pigeon — whatever you already use. The core hashes the OTP before storing it and enforces expiry, attempt counting, and lockouts; the last mile to the inbox is yours.

## License

MIT. See `LICENSE`.

Source (once it exists): `https://github.com/TODO/openauth` — no public repo yet; the link above is a placeholder, same as the `repository` field in `package.json`.

---

*Note: this repository also contains a small Express reference app (`app.js`, `controllers/`, `routes/`, …) showing one way to wire the library up. It is not part of the published package — `npm` only ships `dist/` plus the metadata files.*
