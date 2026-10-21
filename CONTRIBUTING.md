# Contributing to freeauth

## Setup

Follow [Requirements](README.md#requirements) and [Running the reference app locally](README.md#running-the-reference-app-locally) in the README. In short: Node 22, `npm install`, `npm run build`, and a `.env` copied from `.env.example` for the adapter you are using.

## Before opening a pull request

Run both of these from the repository root:

```sh
npx tsc --noEmit
npm test
```

There is no type-check script, so call `tsc` directly. CI (`.github/workflows/test.yml`) runs `npm run build`, `npx tsc --noEmit`, and `npm test` on every push and pull request.

## Workflow

- Work on a branch, never directly on `main`.
- Use `feat/...`, `fix/...`, `docs/...`, or `chore/...` branch names.
- Open a pull request against `main`.

Use conventional commit messages with a short imperative subject:

```text
feat: add GitHub state cookie expiry check
fix: reject replayed refresh tokens
docs: clarify adapter setup
chore: update dev dependencies
refactor: extract OTP lockout helper
test: cover OAuth state mismatch
```

## Pull request expectations

- Keep the change small and focused on one concern.
- Describe what changed and why.
- Add or update tests when logic changes.
- Update `doc/backend.md` or `doc/freeauth-architecture.md` when behavior changes. Those documents are the project's source of truth.

## Architecture rules

- The core (`src/core/`) must never import a database driver, ORM client, or model. It talks only to the `AuthAdapter` interface.
- Database-specific code belongs in `src/adapters/` only.
- Shared security-sensitive helpers live in `src/internal/` and must not be duplicated in the app or adapters.

## Locked product decisions

Decisions recorded in `doc/freeauth-architecture.md` are not changed in a pull request without opening an issue to discuss the change first.

For example, OAuth sign-in never auto-links accounts: if Google or GitHub returns an email that already exists, the request fails with `409` and the accounts are not merged (`doc/freeauth-architecture.md` section 8.2, `src/core/authService.ts`).

For example, refresh token reuse is treated as theft: presenting an already-revoked refresh token returns `401` and revokes all of that user's sessions, including the one created by the legitimate refresh (`doc/freeauth-architecture.md` section 11).

## Security issues

Do not open a public issue for a vulnerability. Email `abdrahmanwalied11@gmail.com` instead.

## Working with coding agents

If you use a coding agent, point it at [`Agents/AGENTS.md`](Agents/AGENTS.md) before it starts work.
