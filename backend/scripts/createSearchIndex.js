import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config({ path: '../.env' });

async function createIndex() {
    await mongoose.connect(process.env.MONGODB_URL);
    const db = mongoose.connection.db;
    try {
        await db.collection('documents').createSearchIndex({
            name: "vector_index",
            definition: {
                "mappings": {
                    "dynamic": true,
                    "fields": {
                        "embedding": {
                            "dimensions": 1536,
                            "similarity": "cosine",
                            "type": "knnVector"
                        }
                    }
                }
            }
        });
        await db.collection('userprofiles').createSearchIndex({
            name: "profile_vector_index",
            definition: {
                "mappings": {
                    "dynamic": true,
                    "fields": {
                        "embedding": {
                            "dimensions": 1536,
                            "similarity": "cosine",
                            "type": "knnVector"
                        },
                        "id": {
                            "type": "token"
                        }
                    }
                }
            }
        });
        console.log("Vector indexes created successfully.");
    } catch(e) {
        console.error("Error creating index:", e.message);
    }
    await mongoose.disconnect();
}
createIndex();
