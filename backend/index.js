/**
 * @file index.js
 * @description IIITA-Crypt Backend Entry Point.
 * Bootstraps the Express server, connects to MongoDB Atlas,
 * applies JWT authentication middleware, and mounts API routes.
 */
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { rateLimit } from 'express-rate-limit';

import authRoutes from './routes/authRoutes.js';
import chatRoutes from './routes/chatRoutes.js';

dotenv.config({ path: '../.env' });

const app = express();
const PORT = process.env.PORT || 3000;

// ── Security: CORS ────────────────────────────────────────────────────
const allowedOrigins = [
    'http://localhost:5173',  // Vite dev server
    'http://127.0.0.1:5173',
];
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (Postman, curl, server-to-server)
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        callback(new Error(`CORS: Origin "${origin}" not allowed.`));
    },
    credentials: true,
}));

// ── Security: Rate Limiting on Login ─────────────────────────────────
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,                  // max 100 attempts per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
    skip: (req) => req.ip === '127.0.0.1' || req.ip === '::1', // skip for localhost in dev
});

app.use(express.json());

// ── Connect to MongoDB Atlas ────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URL)
    .then(() => console.log('✅ MongoDB Atlas Connected Successfully!'))
    .catch((err) => console.error('❌ MongoDB Connection Error:', err.message));

// ── JWT Auth Middleware ───────────────────────────────────────────────────
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        try {
            // JWT_SECRET must be set in .env; fallback is for local dev only
            req.user = jwt.verify(token, process.env.JWT_SECRET || 'iiita_fallback_secret');
            next();
        } catch(e) {
            res.sendStatus(403);
        }
    } else {
        res.sendStatus(401);
    }
};

// ── Routes ─────────────────────────────────────────────────────────
app.use('/api', loginLimiter, authRoutes);
app.use('/api/chat', authenticateJWT, chatRoutes);

app.listen(PORT, () => {
    console.log(`✅ Backend Server running on port ${PORT}`);
    console.log(`✅ Modular Architecture active.`);
    console.log(`✅ Phase 3 RAG Endpoint ready at POST /api/chat`);
});
