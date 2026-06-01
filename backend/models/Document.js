import mongoose from 'mongoose';

const documentSchema = new mongoose.Schema({
    title: String,
    ciphertext: String,
    source_hash: String,
    metadata: {
        category: String,
        policy: String, // Used for logical Vector Search filtering bounds
    },
    embedding: [Number] // Index for Atlas Vector Search
});

export default mongoose.models.Document || mongoose.model('Document', documentSchema);
