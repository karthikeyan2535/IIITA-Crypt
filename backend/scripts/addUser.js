import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import User from '../models/User.js';

dotenv.config({ path: '../.env' });

const email = 'iit2023245@iiita.ac.in';
const password = '12345678';

// Derive attributes from email (same logic as parseIIITAEmail)
const branchCode = 'iit'; // iit -> IT
const batchYear = 2023;
const currentYear = new Date().getFullYear();
const year = Math.min(Math.max(currentYear - batchYear + 1, 1), 4);
const attributes = ['Student', 'IT', `Batch-${batchYear}`, `Year-${year}`];

const run = async () => {
    await mongoose.connect(process.env.MONGODB_URL);
    console.log('✅ Connected to MongoDB Atlas');

    const exists = await User.findOne({ email });
    if (exists) {
        console.log(`⏭  User already exists: ${email}`);
        await mongoose.disconnect();
        process.exit(0);
    }

    const password_hash = bcrypt.hashSync(password, 10);
    await User.create({ email, password_hash, role: 'Student', attributes });
    console.log(`✅ Created: ${email} [Student] attrs: ${attributes.join(', ')}`);

    await mongoose.disconnect();
    process.exit(0);
};

run().catch(err => { console.error(err.message); process.exit(1); });
