import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const router = express.Router();

// ── Staff Registry (mirrors iiita_user_profiles.json role assignments) ─────────
const STAFF_REGISTRY = {
    'dean.acad':   { role: 'Dean',    attributes: ['PUBLIC', 'DEAN', 'ADMIN', 'FACULTY', 'ADMINISTRATION'] },
    'warden.bh1':  { role: 'Warden',  attributes: ['PUBLIC', 'WARDEN', 'HOSTEL-WARDEN', 'HOSTEL-WARDEN-BH1', 'HOSTEL-BH1'] },
    'warden.bh2':  { role: 'Warden',  attributes: ['PUBLIC', 'WARDEN', 'HOSTEL-WARDEN', 'HOSTEL-WARDEN-BH2', 'HOSTEL-BH2'] },
    'warden.bh3':  { role: 'Warden',  attributes: ['PUBLIC', 'WARDEN', 'HOSTEL-WARDEN', 'HOSTEL-WARDEN-BH3', 'HOSTEL-BH3'] },
    'warden.gh1':  { role: 'Warden',  attributes: ['PUBLIC', 'WARDEN', 'HOSTEL-WARDEN', 'HOSTEL-WARDEN-GH1', 'HOSTEL-GH1'] },
    'warden.gh2':  { role: 'Warden',  attributes: ['PUBLIC', 'WARDEN', 'HOSTEL-WARDEN', 'HOSTEL-WARDEN-GH2', 'HOSTEL-GH2'] },
    // HoDs get HOD-<DEPT> attribute — allows them to see their dept's faculty salaries
    'ravi.s':      { role: 'Faculty',  attributes: ['PUBLIC', 'FACULTY', 'HOD-IT',   'IT']   },
    'preeti.r':    { role: 'Faculty',  attributes: ['PUBLIC', 'FACULTY', 'HOD-ECE',  'ECE']  },
    // Regular faculty
    'sk.singh':    { role: 'Faculty',  attributes: ['PUBLIC', 'FACULTY', 'IT']   },
    'anjali.t':    { role: 'Faculty',  attributes: ['PUBLIC', 'FACULTY', 'ECE']  },
    'manish.k':    { role: 'Faculty',  attributes: ['PUBLIC', 'FACULTY', 'MGMT'] },
    'kavita.j':    { role: 'Faculty',  attributes: ['PUBLIC', 'FACULTY', 'IT']   },
};

// ── Case 2.3: Guest Override Map ─────────────────────────────────────────────
// Handles PhD scholars, visiting faculty, office accounts, and other special
// identities that don't match the standard student/staff regex patterns.
// These accounts get a restrictive PUBLIC+GUEST attribute set by default.
const GUEST_OVERRIDE_PREFIXES = ['office.', 'lib.', 'cc.', 'hpc.', 'sports.'];

const resolveGuestIdentity = (username) => {
    // Known special prefix accounts (e.g., office.it, lib.acad)
    if (GUEST_OVERRIDE_PREFIXES.some(p => username.startsWith(p))) {
        return { role: 'Staff', attributes: ['PUBLIC', 'STAFF'] };
    }
    // PhD / research scholars: pattern phd<year><seq> or rs<year><seq>
    if (/^(phd|rs)\d{4,6}$/.test(username)) {
        return { role: 'Scholar', attributes: ['PUBLIC', 'STUDENT', 'PHD-SCHOLAR'] };
    }
    // Visiting / guest lecturers: any other unknown @iiita.ac.in pattern
    // Falls back to minimum viable access — PUBLIC only
    console.warn(`[Auth] Unknown IIITA identity pattern for username: "${username}" → GUEST fallback`);
    return { role: 'Guest', attributes: ['PUBLIC', 'GUEST'] };
};

// ── Agent Alpha: IIITA Identity Parser ───────────────────────────────────────
const parseIIITAEmail = (email) => {
    const studentRegex = /^([a-z]{3})(20\d{2})(\d{3})@iiita\.ac\.in$/;
    const staffRegex   = /^([a-z][a-z0-9.]+)@iiita\.ac\.in$/;

    const studentMatch = email.match(studentRegex);
    if (studentMatch) {
        const branchCode = studentMatch[1];
        const batchYear  = parseInt(studentMatch[2], 10);
        const currentYear = new Date().getFullYear();
        let yearOfStudy  = currentYear - batchYear + 1;
        if (yearOfStudy < 1) yearOfStudy = 1;
        if (yearOfStudy > 5) yearOfStudy = 5; // PhD can be Year-5

        const branchMap = { iit: 'IT', iec: 'ECE', itm: 'IT-BUSINESS' };
        const branch = branchMap[branchCode] || 'UNKNOWN';

        return {
            role: 'Student',
            attributes: ['PUBLIC', 'STUDENT', branch, `BATCH-${batchYear}`, `YEAR-${yearOfStudy}`]
        };
    }

    const staffMatch = email.match(staffRegex);
    if (staffMatch) {
        const username = staffMatch[1];
        const entry = STAFF_REGISTRY[username];
        if (entry) {
            return { role: entry.role, attributes: entry.attributes };
        }
        // Case 2.3: Unknown @iiita.ac.in staff pattern → Guest/Scholar/Staff fallback
        // Never throw here — always return a valid (restrictive) identity.
        return resolveGuestIdentity(username);
    }

    // If regex doesn't match at all (malformed domain bypass attempt) — hard fail
    throw new Error('Unauthorized domain. Only @iiita.ac.in addresses are permitted.');
};

// ── Login Route ───────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const identity = parseIIITAEmail(email.toLowerCase());

        const { default: User } = await import('../models/User.js');
        const userRecord = await User.findOne({ email: email.toLowerCase() });

        if (!userRecord) {
            return res.status(401).json({ error: 'User not found. Please contact IIITA CC.' });
        }

        const isValid = await bcrypt.compare(password, userRecord.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // ── Hostel Attachment: inject HOSTEL-BH1/GH1/etc. into student JWT ────────
        // Fetches the hostel sub-profile so the mess-menu access policy can be
        // enforced in chatRoutes without an extra DB round-trip per message.
        if (identity.role === 'Student') {
            try {
                const { default: UserProfile } = await import('../models/UserProfile.js');
                const userId = email.toLowerCase().split('@')[0];
                const hostelDoc = await UserProfile.findOne(
                    { id: userId, sub_type: 'hostel' },
                    { hostel: 1 }
                );
                if (hostelDoc?.hostel) {
                    // "BH-1" → "BH1", "GH-2" → "GH2"
                    const hostelCode = hostelDoc.hostel.replace('-', '').toUpperCase();
                    identity.attributes.push(`HOSTEL-${hostelCode}`);
                }
            } catch (hostelErr) {
                // Non-fatal: login still succeeds; student just won't have HOSTEL attr
                console.warn('[Auth] Hostel lookup failed (non-fatal):', hostelErr.message);
            }
        }

        const token = jwt.sign(
            { email: email.toLowerCase(), role: identity.role, attributes: identity.attributes },
            process.env.JWT_SECRET || 'iiita_fallback_secret',
            { expiresIn: '15m' }  // Agent Delta: shortened TTL — forces re-auth on attribute changes
        );

        const refreshToken = jwt.sign(
            { email: email.toLowerCase() },
            process.env.JWT_SECRET || 'iiita_fallback_secret',
            { expiresIn: '7d' } // Long-lived refresh token
        );

        res.json({
            token,
            user: { email: email.toLowerCase(), role: identity.role, attributes: identity.attributes, token, refreshToken }
        });
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

// ── Refresh Token Route ───────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: 'Refresh token required.' });

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET || 'iiita_fallback_secret');
        const email = decoded.email;

        const { default: User } = await import('../models/User.js');
        const userRecord = await User.findOne({ email });
        if (!userRecord) return res.status(401).json({ error: 'User no longer exists.' });

        const identity = parseIIITAEmail(email);

        // ── Re-fetch dynamic attributes (Hostel) ──
        if (identity.role === 'Student') {
            try {
                const { default: UserProfile } = await import('../models/UserProfile.js');
                const userId = email.split('@')[0];
                const hostelDoc = await UserProfile.findOne({ id: userId, sub_type: 'hostel' }, { hostel: 1 });
                if (hostelDoc?.hostel) {
                    const hostelCode = hostelDoc.hostel.replace('-', '').toUpperCase();
                    identity.attributes.push(`HOSTEL-${hostelCode}`);
                }
            } catch (_) {}
        }

        const token = jwt.sign(
            { email, role: identity.role, attributes: identity.attributes },
            process.env.JWT_SECRET || 'iiita_fallback_secret',
            { expiresIn: '15m' }
        );

        res.json({ token, user: { email, role: identity.role, attributes: identity.attributes, token, refreshToken } });
    } catch (error) {
        res.status(401).json({ error: 'Invalid or expired refresh token. Please log in again.' });
    }
});

// ── Guest Login Route ─────────────────────────────────────────────────────────
// Issues a short-lived, ephemeral JWT with PUBLIC-only attributes.
// isGuest: true prevents any chat history from being saved (chatRoutes.js).
router.post('/guest-login', (req, res) => {
    const guestEmail = `guest_${Date.now()}@iiita.ac.in`;
    const token = jwt.sign(
        { email: guestEmail, role: 'Guest', attributes: ['PUBLIC'], isGuest: true },
        process.env.JWT_SECRET || 'iiita_fallback_secret',
        { expiresIn: '2h' }
    );
    res.json({
        token,
        user: { email: guestEmail, role: 'Guest', attributes: ['PUBLIC'], isGuest: true, token }
    });
});

export default router;
