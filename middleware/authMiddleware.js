import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export const authMiddleware = (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "No access token provided"
            });
        }

        // Pin the algorithm: accept only HS256 (the algorithm the tokens are signed
        // with). Without this, jwt.verify accepts any algorithm the key type allows,
        // which is the footgun behind alg-confusion attacks — defence in depth even
        // though a symmetric secret is not itself confusable with a public key.
        const decoded = jwt.verify(token, env.ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] });
        req.user = { userId: decoded.userId };

        next();

    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: "Access token expired"
            });
        }

        return res.status(401).json({
            success: false,
            message: "Invalid access token"
        });
    }
};