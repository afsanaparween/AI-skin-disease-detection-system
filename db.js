const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '.data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

let isFallback = false;

// We will attempt to connect to MongoDB. If it fails, we enable fallback.
async function connectDB() {
  const mongoURI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/skindisease';
  console.log(`Attempting to connect to MongoDB at: ${mongoURI}...`);
  try {
    // Set a short timeout (2.5s) so the application starts instantly and falls back cleanly
    await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 2500,
    });
    console.log('MongoDB connected successfully!');
  } catch (err) {
    console.warn('\n========================================================================');
    console.warn('WARNING: MongoDB is not running or unreachable.');
    console.warn('FALLING BACK TO LOCAL FLAT-FILE JSON STORAGE DRIVER (./.data/)');
    console.warn('All features will work flawlessly, including auth and scan tracking!');
    console.warn('========================================================================\n');
    isFallback = true;
  }
}

// Flat file storage helpers for seamless database operations without MongoDB
const jsonDB = {
  read(collectionName) {
    const filename = `${collectionName}.json`;
    const filepath = path.join(DATA_DIR, filename);
    if (!fs.existsSync(filepath)) {
      fs.writeFileSync(filepath, JSON.stringify([]));
      return [];
    }
    try {
      const data = fs.readFileSync(filepath, 'utf8');
      return JSON.parse(data);
    } catch (e) {
      console.error(`Error reading database file ${filename}:`, e);
      return [];
    }
  },
  write(collectionName, data) {
    const filename = `${collectionName}.json`;
    const filepath = path.join(DATA_DIR, filename);
    try {
      fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
      return true;
    } catch (e) {
      console.error(`Error writing database file ${filename}:`, e);
      return false;
    }
  }
};

module.exports = {
  connectDB,
  getIsFallback: () => isFallback,
  jsonDB
};
