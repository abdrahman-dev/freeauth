// Public entry point for the 'freeauth' subpath export.
export { createAuth } from './authService.js';
export type { AuthSecrets } from './authService.js';
export type {
    AuthAdapter,
    SessionAdapter,
    SessionRecord,
    UserAdapter,
    UserRecord,
} from './types.js';
