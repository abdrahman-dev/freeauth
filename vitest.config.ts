import { defineConfig } from 'vitest/config';

// The reference app resolves `starkeep` / `starkeep/mongoose` / `starkeep/prisma`
// to `dist/` (a `file:.` self-install of the packed output). For tests that
// indirection would exercise STALE build output, so the aliases below redirect
// those imports to the live `src/` tree instead. Production builds are
// unaffected — this config only applies under `vitest`.
const root = import.meta.dirname;

export default defineConfig({
    resolve: {
        alias: [
            { find: /^starkeep\/mongoose$/, replacement: `${root}/src/adapters/mongoose.ts` },
            { find: /^starkeep\/prisma$/, replacement: `${root}/src/adapters/prisma.ts` },
            { find: /^starkeep$/, replacement: `${root}/src/core/index.ts` },
        ],
    },
    test: {
        environment: 'node',
        globals: false,
        include: ['tests/**/*.test.ts'],
        setupFiles: ['./tests/helpers/setupEnv.ts'],
        testTimeout: 30000,
        hookTimeout: 180000,
        coverage: {
            provider: 'v8',
            include: ['src/**/*.{ts,js}'],
            reporter: ['text', 'html'],
            reportsDirectory: './coverage',
        },
    },
});
