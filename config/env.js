import { z } from "zod";

export const envSchema = z.object({
  PORT: z
    .string()
    .regex(/^\d+$/, "PORT must be a number")
    .transform(Number)
    .refine((port) => port > 0 && port <= 65535, {
      message: "PORT must be between 1 and 65535",
    }),

  ADAPTER: z.enum(['mongoose', 'prisma'], {
    message: "ADAPTER must be 'mongoose' or 'prisma'",
  }),

  MONGODB_URL: z
    .string()
    .min(1, "MONGODB_URL is required")
    .optional(),

  DATABASE_URL: z
    .string()
    .min(1, "DATABASE_URL is required")
    .optional(),

  ACCESS_TOKEN_SECRET: z
    .string()
    .min(32, "ACCESS_TOKEN_SECRET must be at least 32 characters"),

  REFRESH_TOKEN_SECRET: z
    .string()
    .min(32, "REFRESH_TOKEN_SECRET must be at least 32 characters"),

  GOOGLE_CLIENT_ID: z
    .string()
    .min(1, "GOOGLE_CLIENT_ID must not be empty")
    .optional(),

  GITHUB_CLIENT_ID: z
    .string()
    .min(1, "GITHUB_CLIENT_ID must not be empty")
    .optional(),

  GITHUB_CLIENT_SECRET: z
    .string()
    .min(1, "GITHUB_CLIENT_SECRET must not be empty")
    .optional(),

  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),

  FRONTEND_URL: z
    .string()
    .min(1, "FRONTEND_URL is required")
    .optional(),
}).superRefine((data, ctx) => {
  if (data.ADAPTER === 'mongoose' && !data.MONGODB_URL) {
    ctx.addIssue({
      code: 'custom',
      path: ['MONGODB_URL'],
      message: 'MONGODB_URL is required when ADAPTER=mongoose',
    });
  }
  if (data.ADAPTER === 'prisma' && !data.DATABASE_URL) {
    ctx.addIssue({
      code: 'custom',
      path: ['DATABASE_URL'],
      message: 'DATABASE_URL is required when ADAPTER=prisma',
    });
  }
  if (data.NODE_ENV === 'production' && !data.FRONTEND_URL) {
    ctx.addIssue({
      code: 'custom',
      path: ['FRONTEND_URL'],
      message: 'FRONTEND_URL is required in production',
    });
  }
}).transform((data) => ({
  ...data,
  FRONTEND_URL: data.FRONTEND_URL ?? 'http://localhost:5173',
})).refine((data) => data.ACCESS_TOKEN_SECRET !== data.REFRESH_TOKEN_SECRET, {
  message: 'ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET must be different',
  path: ['REFRESH_TOKEN_SECRET'],
});

export const env = envSchema.parse(process.env);