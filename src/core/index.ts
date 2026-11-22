// Public entry point for the 'starkeep' subpath export.
export { createAuth } from './authService.js';
export type { AuthSecrets } from './authService.js';
export type {
    AuthAdapter,
    SessionAdapter,
    SessionRecord,
    UserAdapter,
    UserRecord,
} from './types.js';
