/**
 * IIITA-Crypt — Re-Encryption Pipeline (Case 4.2)
 *
 * Updates the CP-ABE policy on existing encrypted documents or user profiles
 * without corrupting historical data. The script:
 *   1. Connects to MongoDB Atlas
 *   2. Fetches matching document(s) by title/ID
 *   3. POSTs ciphertext to Python service /decrypt (with DEAN override attrs)
 *   4. POSTs recovered plaintext to /encrypt with the new policy
 *   5. Updates the document's ciphertext, policy metadata, and source_hash
 *
 * Usage:
 *   node scripts/reEncrypt.js --collection documents --title "Budget Allocation" --newPolicy "DEAN"
 *   node scripts/reEncrypt.js --collection userprofiles --id "dean.acad" --newPolicy "ADMIN OR DEAN"
 *
 * Options:
 *   --collection   documents | userprofiles   (required)
 *   --title        Partial title match        (for documents collection)
 *   --id           Exact user profile ID      (for userprofiles collection)
 *   --newPolicy    New CP-ABE policy string   (required)
 *   --dry-run      Preview changes without writing to DB
 */

import mongoose from 'mongoose';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config({ path: '../.env' });

const PYTHON_SERVICE = 'http://localhost:8000';

// ── CLI Argument Parser ───────────────────────────────────────────────────────
const args = process.argv.slice(2);
const getArg = (name) => {
    const idx = args.indexOf(`--${name}`);
    return idx !== -1 ? args[idx + 1] : null;
};
const hasFlag = (name) => args.includes(`--${name}`);

const collection = getArg('collection');
const titleFilter = getArg('title');
const idFilter    = getArg('id');
const newPolicy   = getArg('newPolicy');
const isDryRun    = hasFlag('dry-run');

// Validation
if (!collection || !['documents', 'userprofiles'].includes(collection)) {
    console.error('❌ --collection must be "documents" or "userprofiles"');
    process.exit(1);
}
if (!newPolicy) {
    console.error('❌ --newPolicy is required (e.g. "DEAN OR ADMIN")');
    process.exit(1);
}
if (!titleFilter && !idFilter) {
    console.error('❌ Provide --title (for documents) or --id (for userprofiles)');
    process.exit(1);
}

// ── Service Calls ─────────────────────────────────────────────────────────────
async function decryptWithDeanOverride(ciphertext) {
    // Use DEAN attribute for re-encryption authority — requires admin credentials
    const res = await fetch(`${PYTHON_SERVICE}/decrypt-batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ciphertext,
            attributes: ['ADMIN', 'DEAN'],
            policy: 'DEAN'
        }),
        signal: AbortSignal.timeout(10000)
    });
    if (!res.ok) {
        const detail = await res.text();
        throw new Error(`Decrypt failed (${res.status}): ${detail}`);
    }
    return (await res.json()).plaintext;
}

async function encryptWithNewPolicy(plaintext, policy) {
    const res = await fetch(`${PYTHON_SERVICE}/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plaintext, policy }),
        signal: AbortSignal.timeout(10000)
    });
    if (!res.ok) {
        const detail = await res.text();
        throw new Error(`Encrypt failed (${res.status}): ${detail}`);
    }
    return (await res.json()).ciphertext;
}

// ── Main Pipeline ─────────────────────────────────────────────────────────────
async function run() {
    console.log('\n─────────────────────────────────────────────────────');
    console.log('  IIITA-Crypt: Re-Encryption Pipeline (Case 4.2)');
    console.log(`  Collection : ${collection}`);
    console.log(`  Filter     : ${titleFilter ? `title ~ "${titleFilter}"` : `id = "${idFilter}"`}`);
    console.log(`  New Policy : ${newPolicy.toUpperCase()}`);
    console.log(`  Mode       : ${isDryRun ? '🔵 DRY RUN (no writes)' : '🟢 LIVE'}`);
    console.log('─────────────────────────────────────────────────────\n');

    // ── Verify Python service health ──────────────────────────────────────────
    try {
        const health = await fetch(`${PYTHON_SERVICE}/health`, { signal: AbortSignal.timeout(3000) });
        if (!health.ok) throw new Error('Unhealthy');
        console.log('✅ Python encryption service reachable\n');
    } catch {
        console.error('❌ Python service not reachable at', PYTHON_SERVICE);
        console.error('   Start it with: uvicorn main:app --host 0.0.0.0 --port 8000');
        process.exit(1);
    }

    // ── Connect to MongoDB ────────────────────────────────────────────────────
    await mongoose.connect(process.env.MONGODB_URL);
    console.log('✅ MongoDB Atlas connected\n');

    const db = mongoose.connection.db;
    const col = db.collection(collection);

    // ── Build query ───────────────────────────────────────────────────────────
    let query;
    if (collection === 'documents') {
        query = { title: { $regex: titleFilter, $options: 'i' } };
    } else {
        query = idFilter ? { id: idFilter } : { name: { $regex: titleFilter, $options: 'i' } };
    }

    const ciphertextField = collection === 'documents' ? 'ciphertext' : 'sensitive_data_ciphertext';
    const docs = await col.find(query).toArray();

    if (docs.length === 0) {
        console.warn(`⚠️  No documents matched the filter. Check --title or --id.`);
        await mongoose.disconnect();
        process.exit(0);
    }

    console.log(`📋 Found ${docs.length} document(s) to re-encrypt:\n`);

    let success = 0, failed = 0;

    for (const doc of docs) {
        const label = doc.title || `${doc.name} (${doc.id}) [${doc.sub_type}]`;
        const oldPolicy = doc.metadata?.policy || 'UNKNOWN';
        console.log(`  📄 "${label}"`);
        console.log(`     Old policy: ${oldPolicy}`);
        console.log(`     New policy: ${newPolicy.toUpperCase()}`);

        try {
            // Step 1: Decrypt with DEAN override
            const oldCiphertext = doc[ciphertextField];
            if (!oldCiphertext) {
                console.warn('     ⚠️  No ciphertext found — skipping');
                continue;
            }
            const plaintext = await decryptWithDeanOverride(oldCiphertext);
            console.log(`     ✅ Decrypted successfully`);

            // Step 2: Compute new source_hash (Rule 2)
            const newSourceHash = crypto.createHash('sha256').update(plaintext).digest('hex');

            // Step 3: Re-encrypt with new policy
            const newCiphertext = await encryptWithNewPolicy(plaintext, newPolicy.toUpperCase());
            console.log(`     ✅ Re-encrypted with new policy`);

            if (!isDryRun) {
                // Step 4: Update document in Atlas
                const updateOp = {
                    $set: {
                        [ciphertextField]: newCiphertext,
                        source_hash: newSourceHash,
                        'metadata.policy': newPolicy.toUpperCase(),
                    }
                };
                await col.updateOne({ _id: doc._id }, updateOp);
                console.log(`     ✅ Atlas document updated (hash: ${newSourceHash.substring(0, 8)}...)\n`);
            } else {
                console.log(`     🔵 [DRY RUN] Would update — new hash: ${newSourceHash.substring(0, 8)}...\n`);
            }
            success++;
        } catch (err) {
            console.error(`     ❌ Failed: ${err.message}\n`);
            failed++;
        }
    }

    console.log('─────────────────────────────────────────────────────');
    console.log(`✅ Re-encryption complete: ${success} succeeded, ${failed} failed`);
    if (isDryRun) console.log('   (DRY RUN — no changes written to database)');
    console.log('─────────────────────────────────────────────────────\n');

    await mongoose.disconnect();
    process.exit(failed > 0 ? 1 : 0);
}

run().catch(err => {
    console.error('Fatal:', err.message);
    process.exit(1);
});
