import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    password_hash: { type: String, required: true },
    role: { type: String, required: true },
    attributes: [String],
    createdAt: { type: Date, default: Date.now }
});

// Instance method to verify password
userSchema.methods.verifyPassword = function(plaintext) {
    return bcrypt.compareSync(plaintext, this.password_hash);
};

export default mongoose.models.User || mongoose.model('User', userSchema);
