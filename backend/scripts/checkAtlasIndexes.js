import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config({ path: '../.env' });

async function checkIndexes() {
    await mongoose.connect(process.env.MONGODB_URL);
    const db = mongoose.connection.db;
    
    console.log('\n--- Checking Atlas Search Indexes ---');
    
    try {
        const docIndexes = await db.collection('documents').listSearchIndexes().toArray();
        console.log('\nDocuments collection indexes:');
        docIndexes.forEach(idx => console.log(`  ${idx.name}: ${idx.status}`));
    } catch (e) {
        console.log('Documents indexes error:', e.message);
    }

    try {
        const profIndexes = await db.collection('userprofiles').listSearchIndexes().toArray();
        console.log('\nUserProfiles collection indexes:');
        profIndexes.forEach(idx => console.log(`  ${idx.name}: ${idx.status}`));
    } catch (e) {
        console.log('UserProfiles indexes error:', e.message);
    }

    // Also check doc count
    const docCount = await db.collection('documents').countDocuments();
    const profCount = await db.collection('userprofiles').countDocuments();
    console.log(`\nDocuments: ${docCount} records`);
    console.log(`UserProfiles: ${profCount} records`);

    // Sample a document to verify embedding exists
    const sample = await db.collection('documents').findOne({}, { projection: { title: 1, 'embedding': { $slice: 3 }, 'metadata': 1 } });
    console.log('\nSample doc:', JSON.stringify(sample, null, 2));

    await mongoose.disconnect();
    process.exit(0);
}
checkIndexes().catch(e => { console.error(e); process.exit(1); });
