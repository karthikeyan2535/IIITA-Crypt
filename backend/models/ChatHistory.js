import mongoose from 'mongoose';

const MessageSchema = new mongoose.Schema({
    sender: { type: String, required: true, enum: ['user', 'bot'] },
    text: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const ChatHistorySchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    messages: [MessageSchema]
}, { timestamps: true });

export default mongoose.models.ChatHistory || mongoose.model('ChatHistory', ChatHistorySchema);
