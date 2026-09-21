import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import type { PrismaClientLike } from '../../src/adapters/prisma.ts';

// Shared lifecycle for prismaAdapter integration tests via pglite.
// Mirrors `mongoMemoryServer.ts` shape: one in-memory Postgres per test file
// (beforeAll/afterAll), database wiped between tests so the unique-email index
// never collides. Uses raw SQL replay of `prisma/migrations/**/migration.sql`
// — fastest, fully offline, no Prisma CLI or external Postgres needed.
//
// Why this approach (per plan): No official `@prisma/adapter-pglite` exists
// (404 on registry 2026-09-16), so we cannot construct a real PrismaClient
// over pglite via a driver adapter. The fallback is pglite as a lightweight
// Postgres-compatible in-memory instance, but instead of trying to bridge
// Prisma's pg adapter over pglite's wire (which pglite doesn't expose as a
// pg Pool), we implement a minimal `PrismaClientLike` that delegates directly
// to pglite's SQL engine. This still gives real Postgres semantics (DDL,
// unique constraints, BIGINT handling, MVCC for concurrent updateMany) because
// pglite *is* Postgres (WASM), and it lets `prismaAdapter()` exercise its
// translation layer (BigInt expiry → Number, provider fallback) unchanged.
//
// Writing a dummy DATABASE_URL is fine here (see setupEnv pattern) — the
// helper never reads it; pglite is in-process and needs no connection string.

let pglite: PGlite | null = null;
let prismaLike: PrismaClientLike | null = null;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationSqlPath = path.resolve(__dirname, '../../prisma/migrations/20260915121515_init/migration.sql');

function toPgTimestamp(d: Date): string {
    // TIMESTAMP(3) without timezone — store as UTC wall time without Z so
    // pglite does not apply local-timezone conversion. Use ISO without Z
    // (Postgres TIMESTAMP stores without zone, so we write UTC wall time
    // and read it back as UTC by re-adding Z).
    return d.toISOString().slice(0, 23).replace('T', ' ');
}

function parseTimestamp(v: any): Date | null {
    if (v == null) return null;
    if (v instanceof Date) return v;
    if (typeof v === 'string') {
        // pglite returns TIMESTAMP(3) without timezone as "YYYY-MM-DD HH:MM:SS.sss"
        // Treat the stored UTC wall time as UTC by re-adding Z.
        const iso = v.includes('T') ? v : v.replace(' ', 'T') + 'Z';
        // Ensure Z suffix
        const withZ = iso.endsWith('Z') ? iso : iso + 'Z';
        return new Date(withZ);
    }
    return new Date(v);
}

function toUserRow(row: any) {
    if (!row) return null;
    // pglite returns BIGINT as string or number depending on range; normalize
    // to bigint for the adapter's Number() path, matching real pg behavior.
    const toBigInt = (v: any) => (v == null ? null : typeof v === 'bigint' ? v : BigInt(v));
    return {
        id: row.id,
        email: row.email,
        name: row.name,
        password: row.password,
        isAccountVerified: row.isAccountVerified ?? row.isaccountverified ?? false,
        provider: row.provider,
        providerId: row.providerId ?? row.providerid ?? null,
        verifyOTP: row.verifyOTP ?? row.verifyotp ?? null,
        verifyOTPExpire: toBigInt(row.verifyOTPExpire ?? row.verifyotpexpire),
        verifyAttempts: row.verifyAttempts ?? row.verifyattempts ?? 0,
        verifyLockUntil: parseTimestamp(row.verifyLockUntil ?? row.verifylockuntil),
        resetOTP: row.resetOTP ?? row.resetotp ?? null,
        resetOTPExpire: toBigInt(row.resetOTPExpire ?? row.resetotpexpire),
        resetAttempts: row.resetAttempts ?? row.resetattempts ?? 0,
        resetLockUntil: parseTimestamp(row.resetLockUntil ?? row.resetlockuntil),
        createdAt: parseTimestamp(row.createdAt ?? row.createdat)!,
        updatedAt: parseTimestamp(row.updatedAt ?? row.updatedat)!,
    };
}

function toTokenRow(row: any) {
    if (!row) return null;
    return {
        id: row.id,
        userId: row.userId ?? row.userid,
        token: row.token,
        isRevoked: row.isRevoked ?? row.isrevoked ?? false,
        expiresAt: parseTimestamp(row.expiresAt ?? row.expiresat)!,
        createdAt: parseTimestamp(row.createdAt ?? row.createdat)!,
    };
}

export async function startPglite(): Promise<PrismaClientLike> {
    if (pglite && prismaLike) return prismaLike;

    pglite = new PGlite();

    const rawMigrationSql = fs.readFileSync(migrationSqlPath, 'utf8');
    // pglite's TIMESTAMP(3) without timezone has a known 3-hour offset bug in
    // this environment (stores UTC as local wall time, see test_pglite_date2
    // verification: TIMESTAMP with same input gives 02:26 UTC vs 05:26 original).
    // TIMESTAMPTZ preserves UTC correctly (test 4: Date->TIMESTAMPTZ is exact).
    // Since the schema's TIMESTAMP columns are only used for lockUntil/
    // expiresAt/createdAt (all UTC instants), we replay the migration with
    // TIMESTAMPTZ to get correct UTC semantics in pglite. This is the only
    // SQL-level change; all other semantics (unique constraints, BIGINT for
    // expiries, atomic updateMany) are identical and fully Postgres-faithful.
    // If raw replay ever fails for another reason, the fallback would be
    // `prisma migrate deploy` against a real Postgres (per prompt).
    const migrationSql = rawMigrationSql.replace(/TIMESTAMP\(3\)/g, 'TIMESTAMPTZ');
    await pglite.exec(migrationSql);

    // Minimal PrismaClientLike that delegates to pglite SQL.
    // Generates cuid-like ids via crypto.randomUUID when not supplied (Prisma's
    // @default(cuid()) would do this in the query engine; we do it here).
    const genId = () => `cuid_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;

    prismaLike = {
        user: {
            async findUnique(args: any) {
                const where = args.where;
                let rows: any[];
                if (where.email) {
                    const res = await pglite!.query('SELECT * FROM "User" WHERE email = $1 LIMIT 1', [where.email]);
                    rows = res.rows;
                } else if (where.id) {
                    const res = await pglite!.query('SELECT * FROM "User" WHERE id = $1 LIMIT 1', [where.id]);
                    rows = res.rows;
                } else {
                    return null;
                }
                return rows[0] ? toUserRow(rows[0]) : null;
            },
            async create(args: any) {
                const d = args.data;
                const id = genId();
                const now = new Date();
                // Prisma create for User: allow optional fields to use DB
                // defaults (provider default 'local', verifyAttempts etc.)
                // We pass explicit values for required fields, leave others to
                // defaults where not provided.
                const res = await pglite!.query(
                    `INSERT INTO "User" (id, name, email, password, "isAccountVerified", provider, "providerId", "verifyOTP", "verifyOTPExpire", "verifyAttempts", "verifyLockUntil", "resetOTP", "resetOTPExpire", "resetAttempts", "resetLockUntil", "createdAt", "updatedAt")
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                     RETURNING *`,
                    [
                        id,
                        d.name,
                        d.email,
                        d.password ?? null,
                        d.isAccountVerified ?? false,
                        d.provider ?? 'local',
                        d.providerId ?? null,
                        d.verifyOTP ?? null,
                        d.verifyOTPExpire != null ? String(d.verifyOTPExpire) : null,
                        0,
                        null,
                        d.resetOTP ?? null,
                        d.resetOTPExpire != null ? String(d.resetOTPExpire) : null,
                        0,
                        null,
                        now,
                        now,
                    ]
                );
                return toUserRow(res.rows[0])!;
            },
            async update(args: any) {
                const whereId = args.where.id;
                const data = args.data;

                // Check existence first to mimic Prisma P2025 throw on missing row.
                const existing = await pglite!.query('SELECT id FROM "User" WHERE id = $1', [whereId]);
                if (existing.rows.length === 0) {
                    const err: any = new Error(`Record to update does not exist.`);
                    err.code = 'P2025';
                    throw err;
                }

                const sets: string[] = [];
                const vals: any[] = [];
                let idx = 1;

                const pushSet = (col: string, val: any) => {
                    sets.push(`"${col}" = $${idx++}`);
                    vals.push(val);
                };

                // Handle each possible update shape used by prismaAdapter
                if ('password' in data) pushSet('password', data.password);
                if ('isAccountVerified' in data) pushSet('isAccountVerified', data.isAccountVerified);
                if ('verifyOTP' in data) pushSet('verifyOTP', data.verifyOTP);
                if ('verifyOTPExpire' in data) {
                    // Can be BigInt, number, or null
                    pushSet('verifyOTPExpire', data.verifyOTPExpire != null ? String(data.verifyOTPExpire) : null);
                }
                if ('resetOTP' in data) pushSet('resetOTP', data.resetOTP);
                if ('resetOTPExpire' in data) {
                    pushSet('resetOTPExpire', data.resetOTPExpire != null ? String(data.resetOTPExpire) : null);
                }
                if ('verifyAttempts' in data) {
                    const v = data.verifyAttempts;
                    if (v && typeof v === 'object' && 'increment' in v) {
                        sets.push(`"verifyAttempts" = "verifyAttempts" + $${idx++}`);
                        vals.push(v.increment);
                    } else {
                        pushSet('verifyAttempts', v);
                    }
                }
                if ('resetAttempts' in data) {
                    const v = data.resetAttempts;
                    if (v && typeof v === 'object' && 'increment' in v) {
                        sets.push(`"resetAttempts" = "resetAttempts" + $${idx++}`);
                        vals.push(v.increment);
                    } else {
                        pushSet('resetAttempts', v);
                    }
                }
                if ('verifyLockUntil' in data) pushSet('verifyLockUntil', data.verifyLockUntil);
                if ('resetLockUntil' in data) pushSet('resetLockUntil', data.resetLockUntil);
                if ('provider' in data) pushSet('provider', data.provider);
                if ('providerId' in data) pushSet('providerId', data.providerId);

                // Always bump updatedAt
                pushSet('updatedAt', new Date());

                vals.push(whereId);
                const res = await pglite!.query(
                    `UPDATE "User" SET ${sets.join(', ')} WHERE id = $${idx} RETURNING *`,
                    vals
                );
                return toUserRow(res.rows[0])!;
            },
        },
        refreshToken: {
            async create(args: any) {
                const d = args.data;
                const id = genId();
                const now = new Date();
                const res = await pglite!.query(
                    `INSERT INTO "RefreshToken" (id, "userId", token, "isRevoked", "expiresAt", "createdAt")
                     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
                    [id, d.userId, d.token, false, d.expiresAt, now]
                );
                return toTokenRow(res.rows[0])!;
            },
            async findFirst(args: any) {
                const where = args.where;
                // where: { token, expiresAt: { gt: Date } }
                const token = where.token;
                const gt = where.expiresAt?.gt;
                const res = await pglite!.query(
                    'SELECT * FROM "RefreshToken" WHERE token = $1 AND "expiresAt" > $2 LIMIT 1',
                    [token, gt]
                );
                return res.rows[0] ? toTokenRow(res.rows[0]) : null;
            },
            async updateMany(args: any) {
                const where = args.where;
                const data = args.data;
                // Two shapes used by prismaAdapter:
                // 1) revoke: where { token, isRevoked: false }, data { isRevoked: true }
                // 2) revokeAllForUser: where { userId }, data { isRevoked: true }
                let res: any;
                if (where.token) {
                    // Atomic revoke: UPDATE ... WHERE token = $1 AND "isRevoked" = false
                    // Returns count 1 if won, 0 if already revoked / missing — exactly
                    // the semantics prismaAdapter relies on for reuse detection.
                    res = await pglite!.query(
                        'UPDATE "RefreshToken" SET "isRevoked" = $1 WHERE token = $2 AND "isRevoked" = false',
                        [data.isRevoked, where.token]
                    );
                    // pglite/pg returns rowCount
                    const count = (res as any).rowCount ?? (res as any).affectedRows ?? 0;
                    return { count };
                } else if (where.userId) {
                    res = await pglite!.query('UPDATE "RefreshToken" SET "isRevoked" = $1 WHERE "userId" = $2', [
                        data.isRevoked,
                        where.userId,
                    ]);
                    const count = (res as any).rowCount ?? 0;
                    return { count };
                }
                return { count: 0 };
            },
        },
    };

    return prismaLike;
}

export async function clearDatabase(): Promise<void> {
    if (!pglite) return;
    // TRUNCATE with CASCADE handles FKs if any; our schema has no FK, but safe.
    // Use DELETE as fallback if TRUNCATE not supported in pglite.
    try {
        await pglite.exec('TRUNCATE "User", "RefreshToken" CASCADE;');
    } catch {
        await pglite.exec('DELETE FROM "RefreshToken"; DELETE FROM "User";');
    }
}

export async function stopPglite(): Promise<void> {
    if (pglite) {
        await pglite.close();
        pglite = null;
        prismaLike = null;
    }
}
