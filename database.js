const sqlite3 = require('sqlite3').verbose();

// Connect to SQLite database
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
    
    // Users table - stores account credentials (hashed)
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        passwordHash TEXT NOT NULL
      )
    `);
    
    // Security questions for account recovery and new device verification
    db.run(`
      CREATE TABLE IF NOT EXISTS security_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        question TEXT NOT NULL,
        answerHash TEXT NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(id)
      )
    `);
    
    // Device tracking for offline/online login
    db.run(`
      CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        deviceIdentifier TEXT NOT NULL,
        isVerified BOOLEAN DEFAULT 0,
        FOREIGN KEY (userId) REFERENCES users(id)
      )
    `);
    
    // Game progress - levels unlocked and best scores
    db.run(`
      CREATE TABLE IF NOT EXISTS game_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        levelsUnlocked TEXT NOT NULL,
        bestScores TEXT NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(id)
      )
    `);
  }
});

module.exports = db; 