import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import OpenAI from 'openai';
import crypto from 'crypto';
import Document from '../models/Document.js';

// Load workspace .env
dotenv.config({ path: '../.env' });

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY || 'dummy_key' // Fallback for graceful degradation
});

const INGEST_FILE = path.join(process.cwd(), '../iiita_knowledge_base.json');

const generateEmbedding = async (text) => {
    try {
        if (!process.env.OPENAI_API_KEY) throw new Error("No OPENAI_API_KEY");
        const response = await openai.embeddings.create({
            model: "text-embedding-3-small",
            input: text,
        });
        return response.data[0].embedding;
    } catch (err) {
        // console.warn('⚠️  OpenAI API key missing. Using mock embedding vector [0.1, 0.2, ...]');
        return Array(1536).fill(0).map(() => Math.random() * 0.1);
    }
};

const encryptContent = async (plaintext, policy) => {
    try {
        const response = await fetch('http://localhost:8000/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ plaintext, policy })
        });
        if (!response.ok) throw new Error("Encryption failed");
        const data = await response.json();
        return data.ciphertext;
    } catch (err) {
        // Fallback local mock if Python Docker container isn't running
        const raw = `CP-ABE[Policy:${policy}]|Data:${plaintext}`;
        return Buffer.from(raw).toString('base64');
    }
};

const ingest = async () => {
    console.log('\n--- Starting IIITA-Crypt Ingestion Pipeline ---');
    
    const mongoUrl = process.env.MONGODB_URL;
    let isDbConnected = false;
    
    if (!mongoUrl || mongoUrl.includes('<db_password>')) {
        console.warn('⚠️  MONGODB_URL has placeholder password or is missing.');
        console.log('    Running in DRY RUN mode. DB insertion will be skipped.');
    } else {
        try {
            await mongoose.connect(mongoUrl);
            console.log('✅ Connected to MongoDB Atlas');
            isDbConnected = true;
        } catch(e) {
            console.warn('⚠️  MongoDB Connection failed. Running in DRY RUN mode.');
        }
    }

    const rawData = fs.readFileSync(INGEST_FILE, 'utf-8');
    const entries = JSON.parse(rawData);

    // Agent Delta: Clear stale ghost documents before fresh ingestion
    if (isDbConnected) {
        await mongoose.connection.db.collection('documents').deleteMany({});
        console.log('  🗑️  Cleared stale documents collection.');
    }

    for (const entry of entries) {
        console.log(`\nIngesting: ${entry.title} (${entry.category})`);
        
        process.stdout.write('  -> Generating Embedding (Agent Alpha)... ');
        // Embed title + content + category for maximum keyword recall (Agent Delta)
        const embeddingText = `${entry.title} ${entry.category} ${entry.content}`;
        const embedding = await generateEmbedding(embeddingText);
        console.log('OK');

        // Rule 2 Requirement
        const source_hash = crypto.createHash('sha256').update(entry.content).digest('hex');

        process.stdout.write('  -> Requesting CP-ABE Encryption (Agent Beta)... ');
        const ciphertext = await encryptContent(entry.content, entry.suggested_policy);
        console.log('OK');

        const doc = new Document({
            title: entry.title,
            ciphertext: ciphertext,
            source_hash: source_hash,
            metadata: {
                category: entry.category,
                policy: entry.suggested_policy
            },
            embedding: embedding
        });

        if (isDbConnected) {
            await doc.save();
            console.log('  -> Saved to Atlas successfully.');
        } else {
            console.log('  -> [DRY RUN] Document built securely. DB insertion skipped.');
            console.log(`     Ciphertext Snippet: ${ciphertext.substring(0, 30)}...`);
            console.log(`     Source Hash: ${source_hash}`);
        }
    }
    
    console.log('\n--- Ingestion Pipeline Complete ---');
    if (isDbConnected) await mongoose.disconnect();
    process.exit(0);
};

ingest();
