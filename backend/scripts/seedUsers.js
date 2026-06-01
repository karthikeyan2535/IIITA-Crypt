import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import User from '../models/User.js';

dotenv.config({ path: '../.env' });

const buildEmail = (p) => `${p.ID}@iiita.ac.in`;

// Must mirror parseIIITAEmail in authRoutes.js
const deriveRole = (p) => p.type;

const seedUsers = async () => {
    console.log('\n--- IIITA-Crypt: Seeding All User Credentials ---');
    await mongoose.connect(process.env.MONGODB_URL);
    console.log('✅ Connected to MongoDB Atlas\n');

    // Clear ALL users to avoid stale entries
    await User.deleteMany({});
    console.log('🗑️  Cleared existing users.\n');

    const profilesRaw = fs.readFileSync(path.join(process.cwd(), '../iiita_user_profiles.json'), 'utf-8');
    const profiles = JSON.parse(profilesRaw);

    for (const p of profiles) {
        const email = buildEmail(p);
        const password_hash = bcrypt.hashSync(p.password, 10);
        const role = deriveRole(p);
        await User.create({ email, password_hash, role, attributes: [] });
        console.log(`  ✅ [${role.padEnd(7)}] ${email}`);
    }

    console.log(`\n--- Seeded ${profiles.length} users ---`);
    await mongoose.disconnect();
    process.exit(0);
};

seedUsers().catch(err => { console.error('Seed failed:', err.message); process.exit(1); });
