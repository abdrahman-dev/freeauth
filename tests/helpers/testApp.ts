import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import authRoutes from '../../routes/authRoutes.js';
import { globalLimiter } from '../../middleware/rateLimiter.js';
import { env } from '../../config/env.js';
import errorHandler from '../../middleware/errorHandler.js';

// Test Express app: mirrors `app.js`'s middleware stack exactly (same order,
// same real routes/limiters/error handler) but does NOT connect to MongoDB or
// listen on a port — supertest drives it in-process. The caller connects
// mongoose to the mongodb-memory-server URI first (see
// `helpers/mongoMemoryServer.ts`).
//
// NOTE on `freeauth` imports: `controllers/auth/authController.js` imports the
// library via `config/auth.ts`, which resolves `freeauth*` through
// `vitest.config.ts` aliases to the live `src/` tree — so these tests always
// exercise current source, never a stale `dist/` build.

export function createTestApp() {
    const app = express();

    app.use(express.json());
    app.use(helmet());
    app.use(cors({
        origin: env.FRONTEND_URL,
        credentials: true
    }));
    app.use(cookieParser());

    app.use(globalLimiter);
    app.use('/api/auth', authRoutes);

    app.use((req, res) => res.status(404).json({ success: false, message: 'Not found' }));

    app.use(errorHandler);

    return app;
}
