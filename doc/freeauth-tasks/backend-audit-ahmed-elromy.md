# Backend Audit - Ahmed EL-Romy
Date: 2026-11-20
Repo: freeauth
Commit audited: `1a6dcd9` (2026-10-21, "docs: update Node version note now that engines and .nvmrc exist")

Environment of this audit: Node v24.18.0, npm 11.16.0, Windows 11 (Git Bash). Everything below marked **[live]** was executed on this machine against this commit; everything else was verified by reading the source at the paths cited.

---

## 1. Summary

FreeAuth is a database-agnostic auth toolkit for Node.js (OTP email verification, JWT access/refresh sessions with rotation + reuse detection, per-flow lockouts, Google/GitHub OAuth) built around a small, strictly-documented `AuthAdapter` contract with Mongoose and Prisma implementations. The architecture is genuinely clean: `src/core/` contains zero DB imports (verified by search), and the contract (`src/core/types.ts`) encodes the hard-won lessons (atomic revocation, authoritative attempt counters) as rules adapters must follow. I ran the full suite: build, type-check, 136/136 tests pass, 98.44% statement coverage, and the reference app end-to-end on **both** adapters (register → verify → login → refresh → reuse-detection → logout all behaved exactly as documented). The weak spots are operational, not architectural: OTPs are logged unconditionally (including production), refresh tokens are stored in plaintext, the package cannot be installed by a real consumer yet (the `postinstall` script fails outside the repo — verified), and a few consistency gaps (email case-sensitivity, adapter-specific error mapping) remain. None of these are hard to fix, and none undermine the core design.

## 2. What the project is

**Problem and audience.** Host apps (Node/Express backends) keep re-implementing the same auth plumbing: OTP verification, session refresh with rotation, brute-force lockouts, OAuth. FreeAuth packages that logic so the host brings only the database and the email provider. Target user: a Node developer adding auth to an app who wants the opinions made for them ("You bring the database; freeauth brings the opinions" — README.md:3).

**Library vs reference app.** What npm ships (verified via `npm pack`): only `dist/`, `README.md`, `LICENSE`, `package.json` (`package.json:39-43`). The Express app at the repo root (`app.js`, `config/`, `controllers/`, `middleware/`, `model/`, `routes/`, `utils/`) is a **reference consumer**, excluded from the package. Its config even consumes the library "like an external user" through a documented `file:.` self-install (`config/auth.ts:6-9`).

**Public library API** — all 12 functions returned by `createAuth(...)` (`src/core/authService.ts:561-574`):

| Function | One-line description |
|---|---|
| `registerUser({name,email,password})` | Creates user (hashed password + verify-OTP hash), issues tokens + session, returns raw OTP for the host to deliver |
| `loginUser({email,password})` | Verifies credentials (blocks unverified with 403, OAuth-only accounts with a dedicated 401), issues tokens + session |
| `loginWithGoogle(idToken)` | Verifies Google ID token (signature, audience, `email_verified`), rejects existing emails with 409, creates OAuth-only user + session |
| `loginWithGithub(code, receivedState, expectedState)` | Verifies OAuth `state` (constant-time), exchanges code, requires primary+verified email, same no-linking tail as Google |
| `verifyEmail({email,otp})` | Checks lock → expiry → hash match, marks verified, clears OTP fields and attempt counter |
| `refreshSession(oldRefreshToken)` | Validates session, atomic revoke (a failed revoke = reuse attack → revoke all), issues rotated pair |
| `forgotPassword({email})` | Issues reset-OTP hash with expiry; silently no-ops (`{sent:false}`) for unknown emails |
| `resetPassword({email,otp,newPassword})` | Consumes reset-OTP, updates password, revokes all sessions |
| `resendOTP({email})` | Re-issues verify-OTP for unverified accounts; silent for unknown emails |
| `changePassword(userId,{currentPassword,newPassword})` | Verifies current password, updates, revokes all sessions |
| `logoutUser(token)` | Revokes the refresh-token session |
| `getMe(userId)` | Returns the safe projection `{id,email,name,isAccountVerified}` — never password/OTP hashes |

**Reference app endpoints** (`routes/authRoutes.js:32-51`, all under `/api/auth`, with their limiters): `GET /` (status), `POST /register`, `/login`, `/google`, `/github/state`, `/github`, `/logout`, `/refresh`, `/forgot-password`, `/reset-password`, `/verify-email`, `/resend-otp`, `/change-password` (auth required), and `GET /me` (auth required). 14 routes total; every sensitive one carries a dedicated rate limiter.

## 3. Architecture and flows

**The core/adapter split, in my own words.** The core is a state machine over two abstractions: a `UserAdapter` (identity + per-flow OTP counters/locks) and a `SessionAdapter` (refresh-token rows). It owns every decision — hashing, expiry, thresholds, what counts as a reuse attack — and the adapters own every storage mechanic. The contract is deliberately strict where races exist: `revoke()` must be one atomic operation whose return value is authoritative (`src/core/types.ts:96-112`, with the historical race documented), and `incrementOtpAttempts()` must return the post-increment count so the lockout decision is never made from a stale read (`src/core/types.ts:71-81`). This is the strongest part of the codebase: the dangerous subtleties are written down where the next contributor will see them.

**Core purity — verified.** A search of `src/core/` finds exactly one external import: `google-auth-library` (`src/core/authService.ts:14`), used for Google ID-token verification. No mongoose, prisma, pg, or model imports anywhere in core. (Note: this does mean an HTTP-transport SDK lives in core; see §11.)

**Main flows** (as verified in code, and — where marked — live):

- **Register** [live]: check email unused (`authService.ts:220-224`) → bcrypt-hash password (`:226`) → issue 6-digit OTP, store sha256 hash + 10-min expiry (`:228-236`) → mint token pair, **create session** (`:238-245`) → return raw OTP to host. Note: a session is issued before verification (see S3).
- **Verify email** [live]: lock check → expiry check → hash compare → `markVerified` + clear OTP + reset attempts (`:431-439`, `:85-108`).
- **Login** [live]: find user → generic 401 "Invalid email or password" for both unknown user and wrong password (`:253-268`) → 403 gate on unverified (`:270-272`) → tokens + session.
- **Refresh** [live]: find session by token (expiry-filtered) → if `isRevoked`, treat as reuse: revoke **all** user's sessions + `[SECURITY]` log + 401 (`:118-124`) → atomic `revoke()`; if it loses the race, same nuke path (`:132-140`) → mint rotated pair with fresh `jti` (`src/internal/authTokens.js:20-35`).
- **Logout** [live]: revoke session, clear cookies (`authController.js:173-184`).
- **Forgot/Reset password** [live]: forgot is silent for unknown emails (`:454-456`); reset consumes OTP (lock/expiry/hash), updates password, revokes all sessions (`:466-482`).
- **Change password**: verify current, update, revoke all (`:506-532`).
- **OAuth login**: Google — `verifyIdToken` with audience = our client ID, requires `email_verified` (`:293-330`). GitHub — single-use `state` cookie compared with `crypto.timingSafeEqual` **before** code exchange (`:177-191`, `authController.js:155-161`), then code→token→profile, email must be `primary && verified` (`:410-418`). Both share one tail: existing email → 409 (no linking), new user → OAuth-only account (verified, password null) + session (`:198-215`).

## 4. Stack and how to run it

**Dependencies** (`package.json`):
- **Runtime** (shipped): `bcryptjs` ^3 (password hashing), `jsonwebtoken` ^9 (JWT sign/verify), `google-auth-library` ^11 (Google ID-token verification). Also `freeauth: "file:."` — a deliberate self-install so the reference app resolves the built package (`config/auth.ts:6-9`); documented, but see §10.
- **Peer** (optional): `mongoose` ^9.4, `@prisma/client` ^7.10 — the host installs only the one it needs.
- **Dev** (reference app + tests): express ^5, zod ^4, cors, helmet, cookie-parser, express-rate-limit, dotenv, prisma + @prisma/adapter-pg, pg, mongoose, mongodb-memory-server, @electric-sql/pglite, vitest + coverage-v8, supertest, typescript ^7, nodemon, @types/*.

**How to run (verified from this clone, Windows, no Docker needed):**
1. `npm install` — also runs `postinstall: prisma generate`, writing `generated/prisma/` (`package.json:49`, README.md:92). ✓
2. `npm run build` → emits `dist/`. ✓ (exit 0)
3. `cp .env.example .env`; set `ADAPTER`, `PORT`, both secrets (≥32 chars, different — enforced by `config/env.js:28-32`), then `MONGODB_URL` **or** `DATABASE_URL`.
4. `ADAPTER=mongoose`: any MongoDB at the URL. `ADAPTER=prisma`: Postgres + `npx prisma migrate deploy` (no npm script wires migrations — README.md:116 is accurate). ✓ both adapters ran end-to-end for me.
5. `npm start` → API at `/api/auth` on `PORT`.

**Command results [live]:**

| Command | Result |
|---|---|
| `npm run build` | ✓ exit 0 |
| `npm test` | ✓ **136/136** tests, 17 files |
| `npm run test:coverage` | ✓ 98.44% stmts / 89.30% branch / 95.94% funcs / 98.73% lines |
| `npx tsc --noEmit` | ✓ no output (clean) |

**Did anything not work or not match the README?** The README's own instructions all matched my runs. Two real-world frictions exist beyond the README: (1) installing the repo as a `file:`/path dependency alongside the host's own mongoose gives two mongoose copies and `users.findOne()` buffering timeouts (see §10); (2) a real consumer install of the packed tarball fails outright (see §10 / P1).

## 5. Security findings

Ranked, security first. Severity assumes the reference-app deployment unless stated.

**S1 — HIGH: OTPs are logged in every environment, including production.**
`controllers/auth/authController.js:40,69,107` call `logger.info("[DEV] Account verification OTP for ...")` — but `logger.info` has **no environment gate** (`src/internal/logger.js:8-10`; only `logger.debug` is dev-gated, `logger.js:17-21`). The "[DEV]" prefix is cosmetic. In production, verification/reset OTPs land in console logs and anything that ships them (aggregators, APM). Live evidence of the logging path: OTPs appeared in the app log during my runs. Fix: gate on `NODE_ENV` (or remove — the host delivers OTPs anyway); note `logger.warn` security events *should* stay.

**S2 — MEDIUM: Refresh tokens are stored in plaintext at rest.**
Both adapters persist the raw refresh-token JWT: `src/adapters/mongoose.ts:130-137` (`token: data.token`) and `src/adapters/prisma.ts:208-215`; unique index on the raw string (`src/internal/models/refreshToken.js:17-20`, `prisma/schema.prisma:47`). A database read (dump, backup leak, SSRF into DB) yields immediately usable 7-day session tokens. Inconsistent with the project's own rigor: OTPs are hashed before storage (`src/internal/otpService.js:9-11`). Fix: store `sha256(token)` and look up by hash — a small change confined to the two adapters.

**S3 — MEDIUM: Register issues a full session before email verification.**
`src/core/authService.ts:238-245` mints access+refresh and creates the session during `registerUser`, and the reference app sets both cookies (`controllers/auth/authController.js:36-38`). Meanwhile `loginUser` refuses unverified users with 403 (`authService.ts:270-272`). So an unverified account holds a live session (and my live run confirmed register returns 201 with tokens in play) — the verification gate is bypassable for the lifetime of the first refresh token (7 days). Either delay session issuance until verification, or shorten/restrict the pre-verification session.

**S4 — MEDIUM-LOW: Email addresses are case-sensitive end to end.**
No normalization anywhere: Mongoose schema has no `lowercase`/`trim` (`src/internal/models/userModel.js:5`), the Prisma column is a plain case-sensitive `@unique` (`prisma/schema.prisma:16` — Postgres default), adapters query `{ email }` verbatim (`src/adapters/mongoose.ts:46-48`, `src/adapters/prisma.ts:111-114`), and the zod schemas don't transform (`controllers/auth/authValidation.js:18-22`). Consequences: `A@x.com` and `a@x.com` become two accounts; verification/reset lookups miss on case mismatch; mild enumeration vector via case probing. Fix: normalize (`toLowerCase().trim()`) once in core at every entry point.

**S5 — LOW-MEDIUM: OTP hashing is unsalted SHA-256 over a 6-digit space.**
`src/internal/otpService.js:9-11`: `sha256(otp)` with no salt/pepper; OTP space is 900,000 values, TTL 10 min (`src/internal/constants.js:3`). Online attacks are well contained (5 attempts → 15-min lock, per flow: `authService.ts:18-19,45-57`), but a leaked DB enables offline brute force of every live OTP (and with S2, the tokens too). An HMAC with a server-side pepper would close it cheaply.

**S6 — LOW: OTP hash comparison is not constant-time.**
`src/core/authService.ts:74` and `:96` use `!==` on the stored hash vs `hashOTP(otp)`, while the OAuth state check in the same file uses `crypto.timingSafeEqual` (`:177-191`). Hashing first makes the timing channel harder to exploit, but the inconsistency is free to fix.

**S7 — LOW: The login limiter counts successful logins and is per-IP memory.**
`middleware/rateLimiter.js:39-49`: `max: 5` per IP per 15 min on `/login` — my live run tripped it with *successful* logins, and a fresh account's first wrong password returned 429 ("Too many login attempts, try again after 15 minutes"). A family/office NAT locks colleagues out; restarts reset counters (default MemoryStore); and no `trustProxy` is configured in `app.js`, so behind a reverse proxy all clients share one key. Count only failures (or raise the cap), and document the proxy story.

**S8 — LOW: Revoked sessions don't invalidate outstanding access tokens.**
After a reuse-attack nuke (all sessions revoked, verified live), `GET /me` still returned 200 with the previously issued access token — JWTs are stateless and middleware only verifies the signature (`middleware/authMiddleware.js:20-21`). Worst case is a 15-minute window (`ACCESS_TOKEN_TTL '15m'`, `constants.js:5`). A documented, defensible tradeoff — but it should be stated in the docs, since the API copy ("All sessions revoked") implies more than it delivers.

**S9 — LOW: Prisma deployments accumulate expired sessions forever.**
Mongoose has a TTL index on `expiresAt` (`src/internal/models/refreshToken.js:22-26`), so expired rows self-delete. The Prisma schema has no equivalent (`prisma/schema.prisma:44-51`) and no cleanup path exists — `RefreshToken` grows unbounded, which also degrades `revokeAllForUser` (see §6).

**S10 — INFO: bcrypt cost is 10.**
`src/internal/constants.js:1`. Not wrong; 12 is the currently common recommendation for new systems. Cheap to bump.

**S11 — LOW: The error handler is mongoose-specific and leaks a little.**
`middleware/errorHandler.js:48-51` maps only Mongo's `code === 11000` to 409; a Prisma unique-violation (`P2002`) from the same register race falls through to **500**. And `CastError` echoes the raw input value into the message (`errorHandler.js:53-55`). Map P2002, stop echoing values.

**What is done right (verified, worth keeping):** HS256 pinned on sign **and** verify (`src/internal/authTokens.js:24,33`; `middleware/authMiddleware.js:20`); per-token `jti` so sessions are distinguishable (`authTokens.js:20-35`); atomic single-op revocation with authoritative return, plus the contract documenting *why* (`types.ts:96-112`; `mongoose.ts:148-154`; `prisma.ts:231-237`); per-flow lockouts driven by an atomic increment (`types.ts:71-88`); no email enumeration on forgot/resend (identical responses — verified live); no auto-linking — OAuth on an existing email is always 409 (`authService.ts:198-215`); Google audience + `email_verified` checks; GitHub requires primary+verified email and uses a single-use, httpOnly, constant-time-compared state cookie (`authController.js:143-169`; `config/cookie.js:23-28`); helmet, single-origin CORS with credentials, zod validation with a real password policy; cookies `HttpOnly + SameSite=Strict + secure-in-prod`, short access / long refresh split (`config/cookie.js:3-15`); stack traces only in development 500s (`errorHandler.js:67-70`); reset/change-password revoke all sessions.

## 6. Database layer

**The `AuthAdapter` contract (`src/core/types.ts`)** — clear, minimal, and complete for the feature set. Its two most subtle methods carry the reasoning inline (atomic revoke; authoritative post-increment attempt count), which is exactly where adapter authors go wrong. Two adapters implement it today and the shape holds for both with no core changes — good evidence the contract is right-sized. The `UserRecord` contract keeps every field the flows need (both OTP flows' hash/expiry/attempt/lock quartets) and nothing more.

**Mongoose vs Prisma — real differences, all documented in the adapter itself** (`src/adapters/prisma.ts:1-18`): id mapping (ObjectId→string vs cuid), OTP expiries `BigInt`→`Number()` conversion (lossless below 2^53), `update()` throwing `P2025` where Mongoose returns null (acknowledged divergence, unreachable in current flows), and `updateMany`-count atomicity matching `findOneAndUpdate`. Behavior I could observe live was identical across adapters.

**Schema/migration issues:**
- **Missing index on `RefreshToken.userId`** in both stores (`src/internal/models/refreshToken.js:3-35`; `prisma/schema.prisma:44-51`). `revokeAllForUser` (`mongoose.ts:156-158`, `prisma.ts:239-241`) is a full scan on every password change/reset and every reuse attack. The `token` unique index covers `findValid`/`revoke` lookups, but userId queries are unindexed.
- **No expired-session cleanup on Prisma** (S9 above). Also nothing deletes revoked-but-unexpired rows on either store (they only age out on Mongoose once *expired*).
- Mongoose model names are inconsistent: `"user"` (`userModel.js:22`) vs `"RefreshToken"` (`refreshToken.js:37`).
- Migration history is a single `init` migration; the schema comments are genuinely useful (the BigInt rationale in `schema.prisma` is the kind of note that prevents future mistakes).
- The mongoose `token @unique` + autoIndex deployment caveat is documented in the model and referenced from `doc/backend.md` — good.

## 7. Tests and CI

**Coverage [live, `npm run test:coverage`]:** statements 98.44%, branch 89.30%, functions 95.94%, lines 98.73%. Weakest files: `src/internal/logger.js` 42.85% stmts / 20% branch (its debug gate is untested), `src/core/index.ts` and `types.ts` at 0% (type-only modules — expected). Everything security-critical sits above 99% statements.

**What is covered:** 136 tests across 17 files, layered deliberately: unit tests per core service (`tests/unit/core/authService.{login,register,session,otp,password,oauth}.test.ts`), adapter parity at the integration level (`tests/integration/adapters/{mongoose,prisma}.test.ts`), and full HTTP behavior through the Express app (`tests/integration/express/*`). The security behaviors the task asks about are all exercised: rotation + old-cookie rejection + reuse nuking sessions (`express/session.test.ts` — the "[SECURITY] ... All sessions revoked" log line appears in the test output I ran), OTP lockouts (`authService.otp.test.ts`), OAuth rules including the no-linking 409 (`authService.oauth.test.ts`, `express/oauth.test.ts`), and rate limiting (`express/ratelimit.test.ts`, 2 tests). Vitest aliases `freeauth` imports to live `src/` so tests never exercise stale `dist/` (`vitest.config.ts:8-17`) — a subtle and important choice, and CI still runs `npm run build` to keep dist honest.

**CI (`.github/workflows/test.yml`):** on push/PR: Node 22, `npm ci`, `npm run build`, `npx tsc --noEmit`, `npm test`. **Gaps:** coverage is never measured in CI (no gate, no artifact); there is **no linter at all** (no ESLint/Prettier config in the repo — style is convention-only); no dependency-audit step; the workflow file has no `permissions:` hardening (minor).

## 8. Code quality

- **TypeScript strictness:** `"strict": true` (`tsconfig.json`) with zero errors on `tsc --noEmit`. The library layer (core + adapters) is fully typed; the contract types are the spine of the codebase.
- **`any` usage:** 11 occurrences in `src/`. Six are in `src/adapters/prisma.ts:28-39` and are intentional and well-argued (structural stand-ins for any consumer's generated client). The rest are untyped GitHub API responses in `authService.ts:356,389-390` (`tokenJson`, `profile`, `emails`) — acceptable, but small interfaces would document the fields actually used.
- **JS/TS mix:** `src/internal/*.js` (tokens, otp, password, errors, logger, models) is JavaScript while core/adapters are TypeScript. Verdict: tolerable — these are small, stable wrappers — but they contribute no types, and the mix is invisible from import sites. The sharper issue is placement: `src/internal/models/` contains **Mongoose models** living inside the *library* tree, yet only the mongoose adapter uses them (the Prisma adapter uses the consumer's own schema). They belong next to the mongoose adapter.
- **Duplication:** session issuance appears three times — inline in `registerUser` (`authService.ts:238-245`), inline in `loginUser` (`:273-281`), and as the shared `issueSession` helper (`:157-168`) which only the OAuth paths use. Consolidating is trivial and removes drift risk.
- **Dead code/smells:** `issueOTP(user, type)` ignores both parameters (`src/internal/otpService.js:13-19`); `middleware/errorHandler.js:73` re-exports `AppError` from a middleware file (confusing import surface); `resetPassword` carries a deprecated `password` alias (`authService.ts:466-469`, `authValidation.js:48-50`).
- **Error handling consistency:** core is disciplined — every failure is an `AppError` with a real status code (verified across the whole service file), controllers are thin `asyncHandler` wrappers, and the app-level handler maps Zod/JWT/Mongoose errors with dev-only stacks. Gaps are S11 (P2002/CastError) and the three-call, non-atomic verify success path (`authService.ts:103-105` — a crash between `markVerified`/`clearVerifyOTP`/`resetOtpAttempts` can leave inconsistent OTP state; low impact, worth a note in the contract).
- **Naming/folders:** root-level `config/`, `controllers/`, `middleware/`, `model/`, `utils/` belong to the reference app while `src/` belongs to the library — the split is coherent once you know it, and `doc/backend.md:108` maps it explicitly.

## 9. Docs and repo health

- **Documentation matches the code.** I verified the README's claims against live behavior: install/build/test commands produce exactly the documented results; tests really need no real database (mongodb-memory-server + pglite in `package.json:96,81`); the reference-app runbook (build before start, `.env` fields, per-adapter URL, migrations via CLI only) is accurate step for step; "the library does not send email" is true (OTPs are returned raw — `authService.ts:247,463,503`). `doc/backend.md` is a real per-endpoint API reference (with a "documented inconsistencies" section — a maturity signal), and `doc/freeauth-architecture.md` is named as the source of truth that `src/core/types.ts` must not drift from (`types.ts:1-3`).
- **Root files:** `CONTRIBUTING.md` (points at the README runbook), `SECURITY.md` (private email for vulns — consistent with the task's rule 6), `.env.example` (matches `config/env.js` field-for-field, including the production `FRONTEND_URL` requirement), `.gitignore` (covers `.env`, `.env.*`, `!  .env.example`), issue templates (`bug_report.yml`, `proposal.yml`, `config.yml`), `.nvmrc`, and an `AGENTS.md` (plus `Agents/AGENTS.md` — a duplicate agent-instructions file; consolidate to one).
- **Nothing committed that shouldn't be.** I found no secrets, no build output, no coverage dirs in git. (Locally, `npm install` touched `package-lock.json` — restored; not committed.) The `coverage/` directory produced by my run is ignored.
- Minor doc gap: the rate-limit tables in `doc/backend.md` describe caps as "attempts" while the implementation counts successful requests too (S7); and nothing documents S8's "access tokens survive revocation" window.

## 10. Packaging and developer experience

- **What npm would actually ship — verified:** `npm pack` produced a tarball containing exactly `dist/**` + `package.json` + `README.md` + `LICENSE`, honoring the `files` field (`package.json:39-43`). The `exports` map (`.` / `./mongoose` / `./prisma`, types included, `package.json:22-38`) and `engines: node >=22` are correct.
- **P1 — the package is not installable by a real consumer.** `package.json:49` ships `postinstall: prisma generate`. Inside the repo it works (devDependencies provide the CLI), but installing the packed tarball in a clean folder **fails**: `'prisma' is not recognized as an internal or external command` (verified live, `npm install freeauth-0.1.0.tgz`). The moment this is published, every `npm install freeauth` breaks. Fix: remove the postinstall from the published package — `prisma generate` is the *prisma-adapter consumer's* concern (the library never imports a generated client — `prisma.ts:22-27`), so it has no business in the package lifecycle.
- **DX today (pre-publish):** the README's honest "not on npm yet — use this repository directly" path (`README.md:5`) has a sharp edge: consuming the repo by path/git while also depending on mongoose yields **two mongoose copies** (the junction keeps the repo's `node_modules` alive), and the adapter's models then bind to an unconnected mongoose instance — I reproduced the exact `Operation users.findOne() buffering timed out after 10000ms` failure in a clean consumer. Workaround exists (single mongoose copy) but nothing documents it. This disappears once published with proper peerDeps resolution — one more reason to prioritize the publish blockers.
- **Ease of adoption, otherwise — good.** The whole library surface is one `createAuth({ adapter, secrets })` call; secrets are explicit parameters, never `process.env` reads (verified: only `src/internal/logger.js:4` reads env, for a debug gate); no import-time requirements. My out-of-repo demo (clean folder, installed via the tarball's `dist/`, mongoose from the repo) executed the full lifecycle — register → verify → login → refresh (rotated) → reuse old token → `AppError` 401 → forgot → reset → re-login → logout (`{loggedOut:true}`) — on the first pass, with the only stumble being the plain-string signatures (`refreshSession(token)`, `logoutUser(token)`), which the type declarations make obvious anyway.
- A new developer's realistic path today: clone → `npm install` → build → copy `.env.example` → run with an in-memory Mongo or pglite-backed tests. That path works exactly as documented.

## 11. My opinion

**What is good and should stay:**
1. The contract-first architecture (`types.ts` ↔ `doc/freeauth-architecture.md` enforced sync) with race-condition rationale written where implementers need it. This is the project's moat.
2. The atomicity discipline: single-operation revocation, authoritative attempt counters, `jti` uniqueness. The hard bugs are prevented by design, not by vigilance.
3. The test suite's shape: unit-per-service + adapter-parity + HTTP integration, with security behaviors explicitly exercised, at 98%+ coverage.
4. Honest, deep documentation (a docs file that lists its own inconsistencies is rare).
5. Algorithm pinning and the constant-time OAuth state check — small things done exactly right.

**Weak or risky (top 5, security first):**
1. **OTP logging in production** (S1) — one env-gate away from fixed; do it before any real deployment.
2. **Plaintext refresh tokens at rest** (S2) — the project already hashes OTPs; sessions deserve the same.
3. **Publish blockers** (§10 P1 + the pre-publish path friction) — the library's promise ("drop-in") is currently unverifiable for a real consumer.
4. **Session-before-verification** (S3) — an inconsistency the docs don't own up to.
5. **Email case-sensitivity** (S4) — small, but it silently corrupts the identity key everything else depends on.

**What we can remove:**
- The `postinstall` script from the published package (P1) — removing it *fixes* installs.
- `google-auth-library` from core: move Google verification behind the same explicit-config pattern as GitHub (core keeps a `verify(provider, payload)` seam; the transport moves to an optional module). Restores full dependency purity to the published core and shrinks the shipped surface.
- The deprecated `password` alias in `resetPassword` (one contract, one name).
- The unused parameters of `issueOTP`, and the two inline session-issuance copies in favor of `issueSession`.
- One of the two `AGENTS.md` files (root vs `Agents/`).
Removing these helps because each one is either a broken install, a purity violation, or a drift trap — none is a feature.

**How to develop next (top 5, effort/impact):**
1. **Publish readiness** — remove postinstall, verify `npm pack` install in CI, set `repository`/provenance, document the pre-publish consumption path. *Effort: small / Impact: high.*
2. **Hash refresh tokens at rest** (+ optional pepper on OTP hashes). *Effort: medium / Impact: high.*
3. **Email normalization in core** + tests for the case-mismatch flows. *Effort: small / Impact: high.*
4. **Logger with env gates + remove OTP logging; document the access-token-after-revocation window.** *Effort: small / Impact: high.*
5. **DB hygiene:** `RefreshToken.userId` indexes in both adapters, a Prisma expired-session cleanup story (doc or example cron), map `P2002` in the error handler. *Effort: small / Impact: medium.*

**What is missing that a production auth library should have:** consistent enforcement of the verification gate (S3); token versioning or per-user "revoke all now" that also short-circuits access tokens (or at least documentation of the window); MFA/2FA; email-change flow with re-verification; account deletion/data-export path (GDPR-ish); a documented multi-instance story (shared rate-limit store, migration/lock story for horizontal scaling); lint/format + coverage gates in CI; and a CHANGELOG/release process (it has none — acceptable pre-publish, required after).

## 12. Questions I could not answer

1. **Real Google/GitHub OAuth end-to-end**: no provider credentials in this environment, so `loginWithGoogle`/`loginWithGithub` were verified by code reading and unit/integration tests only — never against the live providers.
2. **The GitHub `state` cookie under `SameSite=Strict` in a real browser**: the design argues it works because the callback is a same-origin POST (`config/cookie.js:17-22`); I could not confirm browser behavior (redirect round-trip) without a real OAuth app.
3. **Concurrent same-email registration on the Prisma adapter**: code reading says `P2002` → unhandled → 500 (S11), but I did not reproduce the race live on Postgres.
4. **Multi-instance deployments**: rate-limit stores are per-process memory; I could not test how badly counters diverge behind multiple replicas (no shared store exists to test).
5. **Post-publish behavior on the npm registry itself** (provenance, tarball hosting, `engines` enforcement): verified `npm pack` locally only; the package is not published.
6. **Performance characteristics**: no benchmarks were run (bcrypt cost, token throughput, session-table size effects) — the audit makes no claims about load behavior.
