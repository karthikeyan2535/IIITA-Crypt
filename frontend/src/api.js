/**
 * @file api.js
 * @description Centralized API base URL configuration.
 * In production, set VITE_API_URL as a Vercel environment variable
 * pointing to your Render backend (e.g. https://iiita-crypt-backend.onrender.com).
 * Falls back to localhost:3000 for local development.
 */
export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3000';
