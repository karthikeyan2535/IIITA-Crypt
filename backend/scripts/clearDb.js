import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config({ path: '../.env' });

async function clear() {
  await mongoose.connect(process.env.MONGODB_URL);
  await mongoose.connection.db.collection('documents').deleteMany({});
  console.log("Documents collection cleared.");
  process.exit(0);
}
clear();
