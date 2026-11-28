// Public entry point for the 'starkeep' subpath export.
export { createAuth } from './authService.js';
export type { AuthRateLimitConfig, AuthSecrets, RateLimitFlowConfig } from './authService.js';
export { createMemoryRateLimitStore } from './memoryRateLimitStore.js';
export type { RateLimitResult, RateLimitStore } from './rateLimitStore.js';
export type {
    AuthAdapter,
    SessionAdapter,
    SessionRecord,
    UserAdapter,
    UserRecord,
} from './types.js';
