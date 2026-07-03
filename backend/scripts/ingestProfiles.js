import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import crypto from 'crypto'; // Rule 2: source_hash computation
import UserProfile from '../models/UserProfile.js';

dotenv.config({ path: '../.env' });

const PROFILE_FILE = path.join(process.cwd(), '../iiita_user_profiles.json');

// ── Embedding generation (OpenAI if available, deterministic hash fallback) ───
const generateEmbedding = async (text) => {
    try {
        const { default: OpenAI } = await import('openai');
        const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
        const r = await openai.embeddings.create({ model: 'text-embedding-3-small', input: text });
        return r.data[0].embedding;
    } catch {
        let seed = 0;
        for (let i = 0; i < text.length; i++) seed = (seed * 31 + text.charCodeAt(i)) & 0xffffffff;
        return Array(1536).fill(0).map(() => {
            seed = (seed ^ (seed << 13)) & 0xffffffff;
            seed = (seed ^ (seed >> 7))  & 0xffffffff;
            seed = (seed ^ (seed << 17)) & 0xffffffff;
            return ((seed & 0xffff) / 0x10000 - 0.5) * 0.1;
        });
    }
};

// ── Encrypt via Python Beta service ──────────────────────────────────────────
const encrypt = async (data, policy) => {
    const res = await fetch('http://localhost:8000/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plaintext: JSON.stringify(data), policy })
    });
    if (!res.ok) throw new Error(`Encryption failed: ${await res.text()}`);
    return (await res.json()).ciphertext;
};

// ── Save one sub-profile document ─────────────────────────────────────────
const saveSubProfile = async ({ type, sub_type, name, id, dept, hostel, data, policy, description, searchText }) => {
    const embedding  = await generateEmbedding(searchText);
    // Rule 2: Compute source_hash BEFORE encryption to detect tampering
    const source_hash = crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
    const ciphertext = await encrypt(data, policy);
    await new UserProfile({
        type, sub_type, name, id, dept: dept || null, hostel: hostel || null,
        source_hash,
        sensitive_data_ciphertext: ciphertext,
        embedding,
        metadata: { policy, description }
    }).save();
    console.log(`    ✅ [${sub_type}] policy="${policy}" hash=${source_hash.substring(0,8)}...`);
};

// ── STUDENT: Three sub-profiles ───────────────────────────────────────────────
// directory    → Faculty + Dean + Student can see (basic info)
// hostel_info  → Warden + Dean + Student can see
// academic     → ONLY Dean + Student can see (Warden/Faculty CANNOT)
const ingestStudent = async (p) => {
    const studentId  = p.ID.toUpperCase();
    const hostelCode = (p.Hostel || '').replace('-', '').toUpperCase(); // BH-1 → BH1
    const wardenAttr = `HOSTEL-WARDEN-${hostelCode}`;
    
    // Derive department
    let dept = "General";
    if (p.ID.startsWith('iit')) dept = "Information Technology";
    if (p.ID.startsWith('iec')) dept = "Electronics and Communication";
    if (p.ID.startsWith('itm')) dept = "IT-Management";

    // 0️⃣  DIRECTORY INFO — Faculty + Warden + Dean + Admin can see
    await saveSubProfile({
        type: 'Student', sub_type: 'directory',
        name: p.Name, id: p.ID, hostel: p.Hostel, dept,
        data: { Name: p.Name, Roll_Number: p.ID, Department: dept, Hostel: p.Hostel },
        policy: `ADMIN OR DEAN OR FACULTY OR WARDEN OR ${studentId}`,
        description: 'Student Directory',
        searchText: `${p.Name} roll number student department ${dept} ${p.ID} ${p.Hostel}`
    });

    // 1️⃣  HOSTEL INFO — Warden can see (room, phone, guardian contact)
    await saveSubProfile({
        type: 'Student', sub_type: 'hostel',
        name: p.Name, id: p.ID, hostel: p.Hostel,
        data: { Name: p.Name, ID: p.ID, Address: p.Address, Hostel: p.Hostel, Phone: p.Phone, Guardian_Phone: p.Guardian_Phone },
        policy: `ADMIN OR DEAN OR ${wardenAttr} OR ${studentId}`,
        description: 'Hostel Info',
        searchText: `${p.Name} hostel address room phone guardian ${p.Hostel} residential`
    });

    // 2️⃣  ACADEMIC INFO — Warden/Faculty CANNOT see; only Dean + Student
    await saveSubProfile({
        type: 'Student', sub_type: 'academic',
        name: p.Name, id: p.ID, hostel: p.Hostel,
        data: { Name: p.Name, ID: p.ID, CGPA: p.CGPA, Backlogs: p.Backlogs, Fee_Status: p.Fee_Status, Scholarship: p.Scholarship },
        policy: `ADMIN OR DEAN OR ${studentId}`,
        description: 'Academic Record',
        searchText: `${p.Name} CGPA grade backlogs fee status scholarship academic record personal`
    });
};

// ── FACULTY: Three sub-profiles ─────────────────────────────────────────────────
// public_directory → PUBLIC (name, designation, dept, phone — students can see)
// contact          → Faculty + HoD + Dean (professional details)
// salary           → ONLY Dean + HoD + self (other faculty CANNOT see each other's salaries)
const ingestFaculty = async (p) => {
    const facultyId = p.ID.toUpperCase().replace('.', '.');
    const dept      = (p.Dept || 'STAFF').toUpperCase().replace('MANAGEMENT', 'MGMT');
    const hodAttr   = `HOD-${dept}`;

    // 0️⃣  PUBLIC DIRECTORY — anyone (including students) can see basic info
    await saveSubProfile({
        type: 'Faculty', sub_type: 'public_directory',
        name: p.Name, id: p.ID, dept: p.Dept,
        data: { Name: p.Name, ID: p.ID, Department: p.Dept, Designation: p.Designation, Phone: p.Phone },
        policy: 'PUBLIC',
        description: 'Faculty Public Directory',
        searchText: `${p.Name} faculty professor ${p.Dept} ${p.Designation} staff directory contact`
    });

    // 1️⃣  CONTACT / PROFESSIONAL INFO — visible to same-dept faculty
    await saveSubProfile({
        type: 'Faculty', sub_type: 'contact',
        name: p.Name, id: p.ID, dept: p.Dept,
        data: { Name: p.Name, ID: p.ID, Department: p.Dept, Designation: p.Designation, Phone: p.Phone, Publications: p.Publications },
        policy: `ADMIN OR DEAN OR ${hodAttr} OR FACULTY OR ${facultyId}`,
        description: 'Professional Profile',
        searchText: `${p.Name} faculty professor ${p.Dept} designation publications contact`
    });

    // 2️⃣  SALARY INFO — ONLY Dean + HoD of their dept + self; other faculty CANNOT see
    await saveSubProfile({
        type: 'Faculty', sub_type: 'salary',
        name: p.Name, id: p.ID, dept: p.Dept,
        data: { Name: p.Name, ID: p.ID, Salary_Grade: p.Salary_Grade, Salary_Amount: p.Salary_Amount, Research_Budget: p.Research_Budget },
        policy: `ADMIN OR DEAN OR ${hodAttr} OR ${facultyId}`,
        description: 'Salary & Budget',
        searchText: `${p.Name} salary pay grade research budget compensation financial`
    });
};

// ── DEAN / WARDEN: Two sub-profiles ─────────────────────────────────────────────
// public_directory → PUBLIC (name, designation, office/hostel, phone — students can see)
// admin            → Restricted to ADMIN/DEAN or HOSTEL-WARDEN-*
const ingestAdmin = async (p) => {
    const adminId = p.ID.toUpperCase().replace('.', '.');
    const data = {
        Name: p.Name, ID: p.ID, Designation: p.Designation,
        Office: p.Office, Phone: p.Phone, Authority: p.Authority,
        Hostel: p.Hostel, Residents_Count: p.Residents_Count, Pending_Leaves: p.Pending_Leaves
    };
    const policy = p.suggested_policy;

    // 0️⃣  PUBLIC DIRECTORY — anyone (including students) can see basic contact info
    await saveSubProfile({
        type: p.type, sub_type: 'public_directory',
        name: p.Name, id: p.ID,
        hostel: p.Hostel || null,
        data: { Name: p.Name, ID: p.ID, Designation: p.Designation, Office: p.Office || p.Hostel, Phone: p.Phone },
        policy: 'PUBLIC',
        description: `${p.type} Public Directory`,
        searchText: `${p.Name} ${p.type} ${p.Designation || ''} ${p.Hostel || ''} ${p.Office || ''} administrator warden dean contact`
    });

    // 1️⃣  FULL ADMIN PROFILE — restricted
    await saveSubProfile({
        type: p.type, sub_type: 'admin',
        name: p.Name, id: p.ID,
        hostel: p.Hostel || null,
        data, policy,
        description: `${p.type} Profile`,
        searchText: `${p.Name} ${p.type} ${p.Designation || ''} ${p.Hostel || ''} administrator`
    });
};

// ── Main ingestion pipeline ───────────────────────────────────────────────────
const ingestProfiles = async () => {
    console.log('\n─────────────────────────────────────────────────');
    console.log('  IIITA-Crypt: Field-Level CP-ABE Ingestion');
    console.log('─────────────────────────────────────────────────');
    await mongoose.connect(process.env.MONGODB_URL);
    console.log('✅ Connected to MongoDB Atlas\n');

    const profiles = JSON.parse(fs.readFileSync(PROFILE_FILE, 'utf-8'));

    await UserProfile.deleteMany({});
    console.log('🗑️  Cleared existing profiles.\n');

    for (const p of profiles) {
        console.log(`\n📋 ${p.Name} (${p.ID}) [${p.type}]`);
        switch (p.type) {
            case 'Student': await ingestStudent(p); break;
            case 'Faculty': await ingestFaculty(p); break;
            default:        await ingestAdmin(p);   break;
        }
    }

    const total = await UserProfile.countDocuments();
    console.log(`\n─────────────────────────────────────────────────`);
    console.log(`✅ Done — ${total} sub-profile documents created`);
    console.log(`   (${profiles.filter(p=>p.type==='Student').length * 2} student + ${profiles.filter(p=>p.type==='Faculty').length * 2} faculty + ${profiles.filter(p=>!['Student','Faculty'].includes(p.type)).length} admin)`);
    console.log(`─────────────────────────────────────────────────\n`);
    await mongoose.disconnect();
    process.exit(0);
};

ingestProfiles().catch(err => { console.error(err); process.exit(1); });
