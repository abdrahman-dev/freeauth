// Runs before any test module is evaluated (see `setupFiles` in
// vitest.config.ts), so these values are in place before `config/env.js`
// executes its import-time `envSchema.parse(process.env)`.
//
// MONGODB_URL is a placeholder that only needs to PASS validation here —
// integration tests connect mongoose to the mongodb-memory-server URI
// explicitly and never call `model/mongodb.js`. Test secrets mirror the
// production constraints (>= 32 chars, access !== refresh).

process.env.ADAPTER ??= 'mongoose';
process.env.MONGODB_URL ??= 'mongodb://127.0.0.1:27017/freeauth-test-placeholder';
process.env.DATABASE_URL ??= 'postgresql://127.0.0.1:5432/freeauth-test-placeholder';
process.env.PORT ??= '3000';
process.env.ACCESS_TOKEN_SECRET ??= 'test-access-token-secret-0123456789abcdef';
process.env.REFRESH_TOKEN_SECRET ??= 'test-refresh-token-secret-fedcba9876543210';
process.env.NODE_ENV ??= 'test';
process.env.FRONTEND_URL ??= 'http://localhost:5173';

// OAuth provider config is optional in `config/env.js` on purpose — but the
// OAuth endpoint tests need the providers CONFIGURED (otherwise core throws
// "not configured" 500s before any logic runs). These dummy values flow
// through the real `config/auth.ts` composition root; the provider side is
// mocked per-test (google-auth-library spy / fetch stub), so no network is
// ever touched.
process.env.GOOGLE_CLIENT_ID ??= 'test-google-client-id.apps.googleusercontent.com';
process.env.GITHUB_CLIENT_ID ??= 'test-github-client-id';
process.env.GITHUB_CLIENT_SECRET ??= 'test-github-client-secret-0123456789';
