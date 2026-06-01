import mongoose from 'mongoose';
import dotenv from 'dotenv';
import OpenAI from 'openai';
dotenv.config({ path: '../.env' });

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

async function test() {
    await mongoose.connect(process.env.MONGODB_URL);
    const db = mongoose.connection.db;
    
    // Test 1: Mess menu
    const q1 = "What is on the BH-1 mess menu?";
    const e1 = (await openai.embeddings.create({ model: 'text-embedding-3-small', input: q1 })).data[0].embedding;
    
    const docs = await db.collection('documents').aggregate([
        { $vectorSearch: { index: 'vector_index', path: 'embedding', queryVector: e1, numCandidates: 50, limit: 5 } },
        { $project: { title: 1, 'metadata.policy': 1, score: { $meta: 'vectorSearchScore' } } }
    ]).toArray();
    
    console.log('\n=== Test 1: Mess Menu Query ===');
    docs.forEach(d => console.log(`  [${d.score.toFixed(4)}] ${d.title} — Policy: ${d.metadata?.policy}`));

    // Test 2: CGPA
    const q2 = "What is my CGPA?";
    const e2 = (await openai.embeddings.create({ model: 'text-embedding-3-small', input: q2 })).data[0].embedding;
    
    const userId = 'iit2023001';
    const profiles = await db.collection('userprofiles').aggregate([
        { $vectorSearch: { index: 'profile_vector_index', path: 'embedding', queryVector: e2, numCandidates: 20, limit: 3, filter: { id: userId } } },
        { $project: { name: 1, 'metadata.policy': 1, score: { $meta: 'vectorSearchScore' } } }
    ]).toArray();
    
    console.log('\n=== Test 2: CGPA Query (userId=iit2023001) ===');
    if (profiles.length === 0) {
        console.log('  ❌ No profiles returned — trying WITHOUT filter...');
        const profilesNoFilter = await db.collection('userprofiles').aggregate([
            { $vectorSearch: { index: 'profile_vector_index', path: 'embedding', queryVector: e2, numCandidates: 20, limit: 3 } },
            { $project: { name: 1, id: 1, 'metadata.policy': 1, score: { $meta: 'vectorSearchScore' } } }
        ]).toArray();
        console.log('  Without filter:');
        profilesNoFilter.forEach(p => console.log(`  [${p.score.toFixed(4)}] ${p.name} (id=${p.id})`));
    } else {
        profiles.forEach(p => console.log(`  [${p.score.toFixed(4)}] ${p.name}`));
    }

    // Test 3: Attendance
    const q3 = "Tell me about the attendance policy";
    const e3 = (await openai.embeddings.create({ model: 'text-embedding-3-small', input: q3 })).data[0].embedding;
    const docs3 = await db.collection('documents').aggregate([
        { $vectorSearch: { index: 'vector_index', path: 'embedding', queryVector: e3, numCandidates: 50, limit: 3 } },
        { $project: { title: 1, score: { $meta: 'vectorSearchScore' } } }
    ]).toArray();
    console.log('\n=== Test 3: Attendance Query ===');
    docs3.forEach(d => console.log(`  [${d.score.toFixed(4)}] ${d.title}`));

    await mongoose.disconnect();
    process.exit(0);
}
test().catch(e => { console.error(e); process.exit(1); });
