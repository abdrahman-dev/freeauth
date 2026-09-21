# FreeAuth — Adapter Architecture & API Reference

This document is the single source of truth for two things:

1. **Adapter architecture** — how FreeAuth separates auth logic from database logic.
   Read this before writing or modifying any code under `core/` or `adapters/`.
2. **The API surface** — every HTTP endpoint the reference app exposes, with request
   bodies, limiter/validation wiring, cookies, and status codes (§9), and the complete
   `createAuth` library API — config, method signatures, return shapes, error statuses
   (§10).

Read this before writing or modifying any code under `core/`, `adapters/`, or the
reference app's `routes/` / `controllers/`.

If anything in a prompt or a PR contradicts this document, this document wins. Update it
first, then write the code.

---

## 1. The core idea

FreeAuth is not an auth **service** (not OAuth, not a hosted identity provider). It is a
**library** developers drop into their own backend, wired to whatever database/ORM they
already use.

To make that possible, the codebase is split into two things that must never mix:

- **Core** — all auth *logic*. Hashing, OTP generation/verification, JWT issuing, session
  rotation rules, lockout rules. This code is **the same for every user of FreeAuth**,
  regardless of their database.
- **Adapter** — all *data access*. Translates the core's requests ("find this user by
  email") into whatever a specific ORM/database needs (Mongoose query, Prisma query,
  Supabase client call, etc).

**Rule: Core never imports a database driver, an ORM client, or a model. It only ever
talks to the `AuthAdapter` interface.** If you find yourself importing `mongoose`,
`@prisma/client`, or any DB client inside `core/`, stop — that logic belongs in an
adapter.

---

## 2. Why the contract is strict, not flexible

We considered letting `UserRecord`/`SessionRecord` be loosely typed (e.g.
`[key: string]: unknown`) so adapters could pass through whatever shape their own schema
has, and let the core figure it out at read time.

**We rejected this.** Reasoning:

- A flexible contract doesn't remove the need to translate one dev's schema into a
  common shape — it just moves that translation from the adapter (one place, written
  once) into the core (many places, defensive `??` fallbacks scattered through business
  logic).
- The whole point of an adapter pattern is that the core stays boring and simple. A
  flexible contract quietly reintroduces the exact "logic and data access mixed
  together" problem the original `smart-auth-system` audit flagged as the #1
  architectural issue.
- A strict contract fails fast, at the adapter boundary, usually at compile time. A
  loose contract fails late, deep inside core logic, at runtime, in a way that's hard to
  trace back to its source.

**Rule: every adapter must return data in exactly the shape defined below. Any
translation between a user's actual DB schema and this shape happens inside their
adapter, never inside core.**

---

## 3. Data shapes

```typescript
interface UserRecord {
  id: string; // always a string — adapter must convert ObjectId/number/uuid itself
  email: string;
  name: string;
  password: string | null; // hash, never plaintext; null for OAuth-only users who never set one

  isAccountVerified: boolean;

  // 'local' for users created via registerUser (the default for all pre-existing
  // records); 'google'/'github' for users created via createOAuthUser.
  provider: 'local' | 'google' | 'github';
  providerId: string | null; // provider's subject id (`sub` for Google, numeric user id for GitHub), null for local users

  verifyOTP: string | null; // hash of the OTP, never plaintext
  verifyOTPExpire: number | null; // epoch ms
  verifyAttempts: number;
  verifyLockUntil: Date | null;

  resetOTP: string | null;
  resetOTPExpire: number | null;
  resetAttempts: number;
  resetLockUntil: Date | null;
}

interface SessionRecord {
  userId: string;
  token: string;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
}
```

Notes:

- `verify*` and `reset*` OTP state are tracked **separately** (separate attempt counters
  and separate lockouts). The original backend shared one counter for both flows; we
  caught this ourselves in that project's own security audit (a reset-OTP brute-force
  attempt would lock out email verification, and vice versa) and are not repeating it
  here now that we're building the contract from scratch.
- `createdAt` on `SessionRecord` costs nothing to add now and unblocks future features
  (e.g. "show active sessions", "log out other devices") without a breaking contract
  change later. Cheap now beats a migration later.

---

## 4. The adapter interface

```typescript
interface UserAdapter {
  findByEmail(email: string): Promise<UserRecord | null>;
  findById(id: string): Promise<UserRecord | null>;

  create(data: {
    email: string;
    name: string;
    password: string; // already hashed by core before calling this
    verifyOTP: string;
    verifyOTPExpire: number;
  }): Promise<UserRecord>;

  /**
   * Create an OAuth-only user. Unlike create(), this sets no password (OAuth users
   * authenticate via their provider, never via a local password) and marks the
   * account verified immediately — the provider already verified the email, so no
   * OTP flow is needed. Called only by core's OAuth logins for first-time OAuth users.
   */
  createOAuthUser(data: {
    email: string;
    name: string;
    provider: 'google' | 'github';
    providerId: string;
  }): Promise<UserRecord>;

  updatePassword(id: string, hashedPassword: string): Promise<void>;

  markVerified(id: string): Promise<void>;

  setVerifyOTP(id: string, otp: string, expiresAt: number): Promise<void>;
  setResetOTP(id: string, otp: string, expiresAt: number): Promise<void>;
  clearVerifyOTP(id: string): Promise<void>; // clears verifyOTP/verifyOTPExpire, mirroring clearResetOTP
  clearResetOTP(id: string): Promise<void>;

  /**
   * Increment a flow's OTP attempt counter and return the authoritative
   * post-increment count. The core uses this return value to decide whether
   * the lockout threshold (currently 5) has been reached — it must never
   * guess the count from a record read at the start of the flow and assume
   * no concurrent attempts happened. Two concurrent wrong-OTP submissions
   * could both read count=4, and neither would trigger the lock. The
   * adapter's increment must be the single source of truth for the count,
   * the same way revoke() is the single source of truth for revocation state.
   */
  incrementOtpAttempts(id: string, type: 'verify' | 'reset'): Promise<number>;
  setOtpLock(id: string, type: 'verify' | 'reset', lockUntil: Date): Promise<void>;
  /**
   * Reset a flow's OTP attempt counter AND its lock in a single call — a
   * successful OTP verification always resets attempts and lock together.
   * Clears verifyLockUntil for type 'verify', resetLockUntil for type 'reset'.
   */
  resetOtpAttempts(id: string, type: 'verify' | 'reset'): Promise<void>;
}

interface SessionAdapter {
  create(data: { userId: string; token: string; expiresAt: Date }): Promise<SessionRecord>;

  findValid(token: string): Promise<SessionRecord | null>;

  /**
   * Revoke a refresh token. MUST be a single atomic operation —
   * e.g. Mongoose: findOneAndUpdate({ token, isRevoked: false }, { isRevoked: true })
   *      Prisma:   updateMany({ where: { token, isRevoked: false }, data: { isRevoked: true } })
   *                then check the affected-row count
   *
   * Returns false if the token was ALREADY revoked when this call ran. The core
   * treats a false return as a reuse attack (someone used a token that had already
   * been used) and wipes every session for that user.
   *
   * A "find, then check, then save" implementation (two separate steps) reintroduces
   * a race condition: two concurrent refresh calls with the same stolen token can
   * both read isRevoked:false before either one writes, and both succeed. This is
   * not a hypothetical — it was a real bug in the original backend (see its audit,
   * finding S10), and it must not be reintroduced by any adapter.
   */
  revoke(token: string): Promise<boolean>;

  revokeAllForUser(userId: string): Promise<void>;
}

interface AuthAdapter {
  users: UserAdapter;
  sessions: SessionAdapter;
}
```

Why specific named methods (`markVerified`, `setResetOTP`, ...) instead of one generic
`update(id, partialData)`:

- Each method has one obvious purpose and one obvious calling point in core. Anyone
  writing a new adapter can see exactly when each one fires.
- A generic `update` pushes the responsibility of "which fields does *this* action
  touch" onto whoever writes the adapter — the same flexibility-shifts-complexity
  problem from section 2, just at the method level instead of the data-shape level.

---

## 5. What "core" actually looks like after this refactor

`core/authService.ts`'s business logic (bcrypt calls, JWT signing, OTP generation, lockout
rules, rotation/reuse-detection rules) **does not change**. The only thing that changes
is where its data comes from:

```javascript
// before (current smart-auth-system)
const user = await userModel.findOne({ email });

// after (core, adapter-based)
const user = await adapter.users.findByEmail(email);
```

Everything else in the function — password verification, token issuing, error
throwing — stays exactly as-is.

Two adapters implement the interface today, both shipped via subpath exports
(`freeauth/mongoose`, `freeauth/prisma`) and both equally supported
production-shaped paths. The design stays adapter-agnostic — neither adapter is
the "primary" the project is redesigned around; selection is explicit via the
`ADAPTER` env var (see `doc/backend.md` §10 and `config/auth.ts`):

- `mongooseAdapter()` — the first adapter, historically a relocation of the legacy
  `repositories/userRepository.js` + `sessionRepository.js` (since removed) into
  `adapters/mongoose.ts`, reshaped to satisfy the interface above. No new logic — a
  relocation with a translation layer. Selected when `ADAPTER=mongoose`.
- `prismaAdapter(client)` — the second, in `adapters/prisma.ts`, sharing the exact
  same `AuthAdapter` contract against a consumer-supplied `PrismaClient`. Semantics
  differences from Mongoose (e.g. a two-row-targeted `update` on a missing row throws
  `P2025` instead of resolving `null`) are documented in its header comment
  (`prisma.ts:16-18`). Selected when `ADAPTER=prisma`. Its presence does not replace
  Mongoose and does not change the adapter-agnostic architecture.

The reference app wires one of them into core at `config/auth.ts` — `ADAPTER`
env var selects `mongooseAdapter()` (MongoDB) or `prismaAdapter(prisma)`
(PostgreSQL) symmetrically. `app.js` only contacts the selected store
(`connectDB()` gated on `ADAPTER=mongoose`; Prisma connects lazily via its
driver adapter, no boot-time step). The architecture itself remains
database-agnostic.

---

## 6. Agent rules for this project

These apply to any coding agent working on `core/` or `adapters/` in this repo:

1. **Core code never imports a DB driver, ORM client, or model.** If a prompt asks for
   something that would require this, stop and flag it instead of finding a workaround.
2. **Every adapter's `revoke()` must be a single atomic DB operation**, per the JSDoc
   comment on `SessionAdapter.revoke` above. Do not implement it as a separate
   find-then-save/find-then-update sequence, in any adapter, ever.
3. **Don't invent new `AuthAdapter` methods without discussing it first.** If a task
   seems to need a new adapter method, say so and describe what it would do — don't add
   it silently, since every adapter (including ones written by other developers later)
   would need to implement it.
4. **Match the existing shapes and method names in section 3 and 4 exactly.** Don't
   rename fields or reorganize the interface "for clarity" — if something seems
   awkward, flag it for discussion rather than changing it unilaterally.
5. **Keep testing simple.** No headless-browser tests, no smoke-test frameworks, no
   heavyweight test scaffolding for this backend work. If a test is genuinely useful,
   it should be a plain, direct unit test of one function — nothing more elaborate than
   that, and only when explicitly asked for.
6. **Stay inside the scope of the prompt.** Don't restructure files, rename things, or
   "improve" adjacent code that wasn't asked for in the current task — this applies to
   backend work specifically, where scope creep is expensive to review.
7. **The `mongooseAdapter` is a relocation, not a rewrite.** When building it, the
   expectation is that the existing repository logic moves with minimal changes beyond
   what's needed to satisfy the interface — not a chance to redesign the Mongoose
   queries themselves.

---

## 7. Status

- [x] Core vs. adapter separation agreed
- [x] Strict-contract decision agreed (over a flexible/loose contract)
- [x] `UserRecord` / `SessionRecord` shapes finalized
- [x] `UserAdapter` / `SessionAdapter` method signatures finalized
- [x] `core/types.ts` written
- [x] `authService.js` decoupled from Mongoose, rebuilt against `AuthAdapter`
- [x] `mongooseAdapter()` implemented (first real adapter, ports existing repositories)
- [x] Package structure decision (single package with subpath exports vs. monorepo) — decided: single `freeauth` package, library sources self-contained under `src/`, built with `tsc` to `dist/`
- [x] Google OAuth login (additive): `provider`/`providerId` on `UserRecord`, `UserAdapter.createOAuthUser`, `loginWithGoogle(idToken)` in core (verified via `google-auth-library`, `googleClientId` in `createAuth` config). Explicit non-goals for this version: no account linking (pre-existing email is rejected with 409, never merged), no other providers, no Express routes yet.
- [x] GitHub OAuth login (additive, mirrors Google): `provider` widened with `'github'`, `loginWithGithub(code)` in core (server-side code exchange via plain `fetch`, primary+verified email rule, `githubClientId`/`githubClientSecret` in `createAuth` config, shared `completeOAuthLogin` tail with Google). Same non-goals: no linking, no routes yet.
- [x] Express layer for OAuth: `POST /api/auth/google` (`{ idToken }`) and `POST /api/auth/github` (`{ code, state }`) plus `POST /api/auth/github/state` (state issuance) in the reference app, sharing the login rate limiter, setting the standard auth cookies, returning `isNewUser`.
- [x] `prismaAdapter(client)` implemented as the second adapter (same `AuthAdapter` contract; P2025-vs-null divergence documented at `src/adapters/prisma.ts:16-18`), shipped as `freeauth/prisma`.
- [x] Automated test suite added (Vitest + supertest + mongodb-memory-server): 120 tests across core, both adapters, and the Express boundary — `npm test` (inventory + result in `doc/backend.md §16`).
- [x] Reference-app wiring: `ADAPTER` env var (`mongoose`|`prisma`) selects the adapter symmetrically — `ADAPTER=mongoose` → `mongooseAdapter()` + `connectDB()` (MongoDB), `ADAPTER=prisma` → `prismaAdapter(prisma)` + lazy `PrismaPg` (PostgreSQL). Both paths verified end-to-end: Mongoose via in-memory Mongo (`vitest` + `mongodb-memory-server`) and Atlas manual runs; Prisma via local Postgres (manual Bruno) + unit contract tests.

---

## 8. OAuth login (Google + GitHub) — design decisions

This section records *why* the OAuth additions look the way they do, in the same spirit as sections 1–4. The contract additions are small on purpose: two fields, one method, two core functions.

### 8.1 Core/adapter additions

- **`provider` / `providerId` on `UserRecord`.** The core needs to know *how* an account authenticates so it can refuse the wrong method (see 8.4), but it must not care about provider-specific profile shapes. A closed string union (`'local' | 'google' | 'github'`) plus an opaque `providerId` string is the smallest representation that satisfies both: adapters translate their own storage into it, core branches on it exactly once (never, today — the null-password guard doesn't even look at it). `providerId` is deliberately generic: Google's `sub` claim and GitHub's numeric user id are both just "the provider's stable subject identifier", and core treats them as opaque strings it writes once and never reads back.
- **`UserAdapter.createOAuthUser` instead of reusing `create`.** `create` means "password user pending OTP verification" — its required `password`/`verifyOTP` fields encode that flow. An OAuth user is none of those things: no password exists, and the email arrives already verified, so there is nothing to verify. A separate named method keeps the one-method-one-purpose convention from section 4 and makes the call site (`completeOAuthLogin`) self-documenting. Both adapters implement it with the same semantics: `isAccountVerified: true`, no password, no OTP state.
- **Why verified immediately.** Re-running our OTP email flow on top of a provider that already verified the address adds friction with no security gain — the trust decision is delegated to the provider at the moment the user chooses that provider. If a deployment doesn't trust a provider's verification, it shouldn't offer that provider at all.

### 8.2 The no-auto-linking boundary, and why it exists

When `loginWithGoogle`/`loginWithGithub` finds a pre-existing account with the same email, it throws 409 (`An account already exists with this email. Sign in with your password instead.`) — regardless of that account's provider. It never links, merges, or silently logs in. Reasoning:

- An email string is an **address**, not an identity. The same address appearing in two trust domains (our `users` table vs. Google/GitHub) is not proof of the same human: addresses get recycled by mail providers, GitHub lets users attach addresses they haven't verified (we filter those, but the next provider might have weaker rules), and a local account created years ago has no cryptographic relationship to a provider account created today.
- Auto-linking would turn the weaker side's account-creation policy into a takeover primitive against our accounts: anyone able to present the victim's email at the provider — however the provider allowed that — would inherit the victim's local account, its data, and its sessions.
- The safe direction is explicit, user-driven linking (prove ownership of *both* sides in one authenticated ceremony), which is a separate feature with its own UX and threat model — not something to smuggle into a login path. Until it exists, a loud 409 that tells the user exactly what to do is the correct failure mode: no silent behavior, no account confusion, no way to stumble into someone else's account.

### 8.3 Email verification differs by provider, and the code shows it

- **Google** gives us a signed JWT (the ID token) whose claims already contain `email` and `email_verified`. Verification is cryptographic (`google-auth-library` checks signature, expiry, and audience) plus one boolean check. One round trip, no extra API calls — which is why Google rightfully needed a dedicated verification library rather than hand-rolled JWT parsing.
- **GitHub** has no ID token. The `code` is a single-use bearer credential that must be exchanged server-side for an access token, and *then* two API calls (`GET /user`, `GET /user/emails`) recover what Google put in one JWT. The emails endpoint returns a *list* because GitHub accounts hold many addresses in mixed states — so the rule is strict: the qualifying email must be `primary === true && verified === true`. Not the first entry (order is not meaningful), not merely verified-but-secondary (the user hasn't designated it their identity), and never unverified. Failure maps to the same 403 shape as Google's unverified case, because from the caller's perspective it is the same outcome: "this provider identity has no verified email we can trust."
- Both flows converge after that point on purpose: everything downstream (lookup, rejection, creation, session) is provider-agnostic, which is what `completeOAuthLogin` enforces structurally.

### 8.4 Shared tail and the generic guard

- **`completeOAuthLogin`** exists because the two providers' tails were about to become a copy-paste pair: same 409 rejection, same `createOAuthUser` call shape, same `issueSession`, same `{ accessToken, refreshToken, isNewUser: true }` return. Two copies would drift (a message fix applied to one and not the other is exactly the kind of bug this codebase's strictness tries to prevent). Provider-specific code stops at "produce a verified `(email, name, provider, providerId)` tuple"; everything after is shared.
- **The null-password guard** (`if (!user.password)` in `loginUser`/`changePassword`) deliberately does not inspect `provider`. The invariant it protects is about *credentials*, not provenance: "password flows require a password hash." Checking the credential's presence rather than the account's origin means the guard stays correct for every future provider with zero changes, and — equally important — it cannot misfire on a `local` account, whose password is always a non-null hash. Provider-neutral message, provider-neutral condition.
- **Config is optional per provider** (`googleClientId?`, `githubClientId?`/`githubClientSecret?`) for the same reason secrets are explicit: the library never reads env, and a deployment offering only one provider shouldn't have to fabricate credentials for the other. An unconfigured provider fails loudly at call time (500), never silently, and never at import/boot time.

### 8.5 GitHub `state` (CSRF protection for the code flow)

- **Why only GitHub.** `state` is specifically an *authorization-code-flow* mechanism (RFC 6749 §10.12): it binds the callback to the initiation so an attacker can't complete the flow with a code from an account *they* control and thereby fixate the victim's session onto the attacker's account. GitHub's flow has exactly that shape — the `code` travels through a browser redirect, which is attacker-steerable. Google's flow here does not: the frontend obtains a signed ID token directly from Google in first-party context and POSTs it; there is no redirect round trip to bind, hence no `state` to check. (The residual, generic login-CSRF class — tricking a browser into POSTing the attacker's own valid credential — applies equally to all three login endpoints and is blunted by JSON-only POSTs plus `SameSite=strict` cookies; it is not something a `state` parameter on one endpoint would address.)
- **Split across the core/HTTP boundary on purpose.** Core owns the *decision* — `loginWithGithub(code, receivedState, expectedState)` compares two opaque strings with `crypto.timingSafeEqual` and throws 401 (`Invalid OAuth state…`) before any code exchange — so every library consumer gets the check unconditionally, not just the Express app. The Express controller owns all *HTTP*: reading the stored value from the cookie, passing both values in, clearing the cookie. Core never sees a cookie jar, matching the existing "no HTTP concerns in core" boundary.
- **Why a backend-issued httpOnly cookie, not alternatives.** There is no session store in this stack (no `express-session`, no Redis), so server-side session storage would be new infrastructure for one value. The stateless alternative — HMAC-signing the state so nothing is stored — would put a small crypto protocol inside core for no real gain. The double-submit-cookie pattern needs nothing new: `POST /api/auth/github/state` mints 32 random bytes, sets them as a 10-minute httpOnly `SameSite=strict` cookie, and returns the value for the authorize URL; the callback POSTs back GitHub's echo alongside the code. Strict (not Lax) suffices because the cookie is only read on the same-origin callback POST, never on the cross-site GitHub redirect itself.
- **Single-use by consumption.** The controller clears the state cookie *before* calling core, so every callback attempt — success or failure — needs a freshly issued state. Missing, non-string, or length-mismatched values reject identically to a wrong value (no oracle, no `timingSafeEqual` length-throw leak).

---

## 9. HTTP API Reference (reference app)

All routes are under `/api/auth` (`routes/authRoutes.js`); every request goes through
`globalLimiter` first, and every response uses the shared envelope from §9.1. Bodies
are `application/json`; unknown body keys are stripped by Zod. Exact messages, schema
rules, and status-to-cause mappings for each endpoint are in `doc/backend.md §4`.

| # | Method & path | Rate limiter | Validation | Auth | Success |
|---|---------------|--------------|------------|------|---------|
| 1 | `GET /api/auth/` | — | — | — | 200 `{ success: true, message }` |
| 2 | `POST /api/auth/register` | `registerLimiter` (10/h) | `registerSchema` | — | 201 `{ success: true, message }` + both cookies |
| 3 | `POST /api/auth/login` | `authLimiter` (5/15min) | `loginSchema` | — | 200 message + both cookies |
| 4 | `POST /api/auth/logout` | — | — | refresh cookie | 200 message (idempotent) |
| 5 | `POST /api/auth/refresh` | `refreshLimiter` (20/15min) | — | refresh cookie | 200 message + rotated cookies |
| 6 | `GET /api/auth/me` | — | — | `authMiddleware` | 200 `{ success: true, data: { user: { id, email, name, isAccountVerified } } }` |
| 7 | `POST /api/auth/forgot-password` | `resetPasswordLimiter` (5/30min, shared) | `forgotPasswordSchema` | — | 200 message (enumeration-resistant) |
| 8 | `POST /api/auth/reset-password` | `resetPasswordLimiter` (shared) | `resetPasswordSchema` | — | 200 message |
| 9 | `POST /api/auth/verify-email` | `verifyEmailLimiter` (5/15min) | `verifyEmailSchema` | — | 200 message |
| 10 | `POST /api/auth/resend-otp` | `resendOtpLimiter` (5/30min) | `resendOTPSchema` | — | 200 message |
| 11 | `POST /api/auth/change-password` | — | `changePasswordSchema` | `authMiddleware` | 200 message |
| 12 | `POST /api/auth/google` | `authLimiter` (shared bucket) | `googleLoginSchema` (`{ idToken }`) | — | 200 message + both cookies |
| 13 | `POST /api/auth/github/state` | `authLimiter` (shared bucket) | — (no body) | — | 200 `{ success: true, data: { state } }` + `github_oauth_state` cookie |
| 14 | `POST /api/auth/github` | `authLimiter` (shared bucket) | `githubLoginSchema` (`{ code, state }`) | — | 200 message + both cookies |

Request bodies (all `required` unless marked optional):

- `register`: `{ name, email, password }`
- `login`: `{ email, password }`
- `forgot-password` / `resend-otp`: `{ email }`
- `reset-password`: `{ email, otp, newPassword? }` (legacy alias `password?` also
  accepted; `newPassword` wins when both are sent)
- `verify-email`: `{ email, otp }`
- `change-password`: `{ currentPassword, newPassword }` (Bearer or cookie auth)
- `google`: `{ idToken }` — signed Google ID token; verified server-side
- `github/state`: empty body
- `github`: `{ code, state }` — `state` must equal the value issued by
  `POST /github/state` and echoed back by GitHub

Cookies set/cleared by the reference app (`config/cookie.js`): `accessToken`
(15 min), `refreshToken` (7 days), `github_oauth_state` (10 min, single-use, for the
GitHub code flow). All are `httpOnly` + `SameSite=strict`, with `secure` in
production. Refresh/logout read only the cookie (no header alternative); `/me` and
`/change-password` accept `Authorization: Bearer <accessToken>` as a fallback.

### 9.1 Error envelope

All endpoints (including `authMiddleware`'s inline 401s and rate-limiter 429s) use:
`{ success: false, message: string, errors?: [{ field, message }], stack?: string }`
(`stack` only on dev 500s). Error-class → status mapping is in `doc/backend.md §8`:
400 OTP-semantic, 401 authN, 403 unverified-login, 404 unknown route/user, 409
duplicate email, 422 Zod validation, 429 limiter or OTP-lockout, 500 unexpected. The
four OAuth/login routes share one `authLimiter` bucket (§8.5's `state` issuance is
part of the login surface).

---

## 10. Library API — `createAuth`

Signature (in `src/core/index.ts` / `src/core/authService.ts`):

```typescript
createAuth(config: {
  adapter: AuthAdapter;
  secrets: { accessTokenSecret: string; refreshTokenSecret: string };
  googleClientId?: string;
  githubClientId?: string;
  githubClientSecret?: string;
}) → {
  registerUser, loginUser, loginWithGoogle, loginWithGithub, verifyEmail,
  refreshSession, forgotPassword, resetPassword, resendOTP, changePassword,
  logoutUser, getMe
}
```

- `adapter` is any `AuthAdapter` (§4); Mongoose and Prisma implementations ship as
  `freeauth/mongoose` and `freeauth/prisma`.
- Secrets are explicit (≥32 chars, must differ) — the library **never reads env**.
- OAuth config is optional per provider; an unconfigured provider fails loudly at
  call time (`500 … sign-in is not configured`), never at boot.

Methods (all `async` unless noted; core throws `AppError(message, statusCode)`):

| Method | Returns | Errors (AppError status) |
|--------|---------|--------------------------|
| `registerUser({ name, email, password })` | `{ accessToken, refreshToken, otp }` | 409 email in use |
| `loginUser({ email, password })` | `{ accessToken, refreshToken }` | 401 bad credentials; 401 social-only account; 403 not verified |
| `loginWithGoogle(idToken)` | `{ accessToken, refreshToken, isNewUser: true }` | 401 no/invalid/expired token; 403 unverified email; 409 existing email (no linking); 500 unconfigured |
| `loginWithGithub(code, receivedState, expectedState)` | `{ accessToken, refreshToken, isNewUser: true }` (primary+verified email required) | 401 invalid `state` (timing-safe compare, §8.5); 401 bad/expired code; 403 no verified email; 409 existing email; 500 unconfigured |
| `verifyEmail({ email, otp })` | `{ verified: true }` | 400 invalid/expired OTP; 400 OTP attempts exhausted (→ lockout) |
| `refreshSession(oldRefreshToken)` | `{ accessToken, refreshToken }` (atomic rotation; §4 `revoke`) | 401 no/invalid/expired token; reuse ⇒ wipe-all-sessions + 401 |
| `forgotPassword({ email })` | `{ sent: true, otp }` or `{ sent: false }` (unknown email — enumeration-resistant) | — |
| `resetPassword({ email, otp, newPassword? / password? })` | `{ reset: true }` (revokes all user sessions) | 400 invalid/expired OTP |
| `resendOTP({ email })` | `{ sent: true, otp }` or `{ sent: false }` | 400 already verified |
| `changePassword(userId, { currentPassword, newPassword })` | `{ changed: true }` (revokes all user sessions) | 404 user; 401 social-only account / wrong current password |
| `logoutUser(token)` | `{ loggedOut: true }` (idempotent — falsy token returns immediately) | — |
| `getMe(userId)` | `{ id, email, name, isAccountVerified }` — never leaks password/OTP hashes | 404 user |

Notes:

- `forgotPassword`/`resendOTP`/`registerUser` return the plaintext `otp` **to the
  caller** — the reference app prints it via `logger.info` (`[DEV] … OTP for
  <email>`) instead of sending email (`doc/backend.md §11`); a production consumer
  must deliver it itself.
- Every successful session-bearing call creates a server-side refresh row; refresh
  JWT signature/expiry are not re-verified in `rotateSession` (DB row is the check).
- OTP flows have independent per-flow lockouts (`verify` vs `reset`), enforced by
  `incrementOtpAttempts` + `setOtpLock` returning/coordinating the authoritative
  count (§4).

---
