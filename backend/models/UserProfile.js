import mongoose from 'mongoose';

const userProfileSchema = new mongoose.Schema({
    type:     String,   // Student | Faculty | Dean | Warden
    sub_type: String,   // 'academic' | 'hostel' | 'salary' | 'contact' | 'admin'
    name:     String,
    id:       String,
    dept:     String,
    hostel:   String,   // BH-1, GH-1, etc. — for hostel sub-profiles
    source_hash: String, // Rule 2: SHA-256 of plaintext data before encryption (tamper detection)
    sensitive_data_ciphertext: String,
    embedding: [Number],
    metadata: {
        policy:      String,
        description: String   // human-readable: "Academic Record" | "Hostel Info"
    }
});

export default mongoose.models.UserProfile || mongoose.model('UserProfile', userProfileSchema);
