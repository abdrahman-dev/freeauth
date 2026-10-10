import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import 'dotenv/config';
import connectDB from './model/mongodb.js';
import { globalLimiter } from './middleware/rateLimiter.js';
import { env } from './config/env.js';

// Import router for authentication endpoints (login, register, logout, refresh)
import authRoutes from './routes/authRoutes.js'

import errorHandler from './middleware/errorHandler.js';


const app = express();
const port = env.PORT;

// Middleware setup for JSON parsing, CORS with frontend, and cookie handling
app.use(express.json());
app.use(helmet());
app.use(cors({
  origin: env.FRONTEND_URL,
  credentials: true               
}));
app.use(cookieParser());

// Register route handlers with rate limiting and API endpoints
app.use(globalLimiter);
app.use('/api/auth', authRoutes);

// 404 JSON handler for unknown routes
app.use((req, res) => res.status(404).json({ success: false, message: 'Not found' }));

// Global error handling middleware
app.use(errorHandler);

// Establish database connection before starting the server. Only the selected
// adapter's store is contacted — the other is untouched. Prisma manages its
// own connection lazily via the driver adapter (PrismaPg) on first query, so
// no explicit connect step is needed when ADAPTER=prisma (verified against
// the generated PrismaClient — $connect is available but optional; the adapter's
// pg Pool connects on demand).
const startServer = async () => {
    if (env.ADAPTER === 'mongoose') {
        try {
            await connectDB();
        } catch (error) {
            console.error('Failed to connect to MongoDB:', error);
            process.exit(1);
        }
    }

    // Start the Express server on specified port
    app.listen(port, () => {
        console.log(`Running on PORT:${port}`);
    });
};

startServer();