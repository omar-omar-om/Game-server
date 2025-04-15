const express = require('express');// Web framework for handling API requests
const bodyParser = require('body-parser'); // Parses incoming JSON requests.

const cors = require('cors'); // Allows Unity to communicate with the backend
const crypto = require('crypto'); // for hashing
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors()); // allow unity to acess API
app.use(bodyParser.json()); // parsing
// Helper function to hash passwords and answers
function hashString(string) {
  return crypto.createHash('sha256').update(string).digest('hex');
}

// --- User Authentication Routes

// Register a new user
app.post('/api/register', (req, res) => {
  const { username, email, password, securityQuestion, securityAnswer } = req.body;
  
  if (!username || !email || !password || !securityQuestion || !securityAnswer) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  const passwordHash = hashString(password);
  const answerHash = hashString(securityAnswer);
  
  // Insert user
  db.run('INSERT INTO users (username, email, passwordHash) VALUES (?, ?, ?)', 
    [username, email, passwordHash], 
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'Username or email already exists' });
      }
      
      const userId = this.lastID;
      
      // Add security question
      db.run('INSERT INTO security_questions (userId, question, answerHash) VALUES (?, ?, ?)',
        [userId, securityQuestion, answerHash],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to set security question' });
          }
          
          res.status(201).json({ 
            message: 'User registered successfully', 
            userId: userId 
          });
        }
      );
    }
  );
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password, deviceIdentifier } = req.body;
  
  if (!username || !password || !deviceIdentifier) {
    return res.status(400).json({ error: 'Username, password and device identifier required' });
  }
  
  const passwordHash = hashString(password);
  
  // Check user credentials
  db.get('SELECT id FROM users WHERE username = ? AND passwordHash = ?', 
    [username, passwordHash], 
    (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
      
      // Check if device is verified
      db.get('SELECT isVerified FROM devices WHERE userId = ? AND deviceIdentifier = ?',
        [user.id, deviceIdentifier],
        (err, device) => {
          if (err) {
            return res.status(500).json({ error: 'Database error' });
          }
          
          if (device) {
            // Device exists
            if (device.isVerified) {
              // Device is verified, login successful
              return res.json({ 
                message: 'Login successful', 
                userId: user.id,
                requiresVerification: false
              });
            } else {
              // Device exists but not verified
              return res.json({
                message: 'Device requires verification',
                userId: user.id,
                requiresVerification: true
              });
            }
          } else {
            // New device, add to database as unverified
            db.run('INSERT INTO devices (userId, deviceIdentifier, isVerified) VALUES (?, ?, 0)',
              [user.id, deviceIdentifier],
              (err) => {
                if (err) {
                  return res.status(500).json({ error: 'Failed to register device' });
                }
                
                return res.json({ 
                  message: 'New device requires verification', 
                  userId: user.id,
                  requiresVerification: true
                });
              }
            );
          }
        }
      );
    }
  );
});

// Verify security question for new device
app.post('/api/verify-device', (req, res) => {
  const { userId, deviceIdentifier, securityAnswer } = req.body;
  
  if (!userId || !deviceIdentifier || !securityAnswer) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  const answerHash = hashString(securityAnswer);
  
  // Get user's security question answer
  db.get('SELECT answerHash FROM security_questions WHERE userId = ?', 
    [userId], 
    (err, question) => {
      if (err || !question) {
        return res.status(404).json({ error: 'Security question not found' });
      }
      
      if (question.answerHash !== answerHash) {
        return res.status(401).json({ error: 'Incorrect security answer' });
      }
      
      // Answer is correct, verify the device
      db.run('UPDATE devices SET isVerified = 1 WHERE userId = ? AND deviceIdentifier = ?',
        [userId, deviceIdentifier],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to verify device' });
          }
          
          res.json({ message: 'Device verified successfully' });
        }
      );
    }
  );
});

// Get security question for a user
app.get('/api/security-question/:username', (req, res) => {
  const username = req.params.username;
  
  db.get('SELECT id FROM users WHERE username = ?', 
    [username], 
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      db.get('SELECT question FROM security_questions WHERE userId = ?', 
        [user.id], 
        (err, secQuestion) => {
          if (err || !secQuestion) {
            return res.status(404).json({ error: 'Security question not found' });
          }
          
          res.json({ question: secQuestion.question });
        }
      );
    }
  );
});

// Reset password using security question
app.post('/api/reset-password', (req, res) => {
  const { username, securityAnswer, newPassword } = req.body;
  
  if (!username || !securityAnswer || !newPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  const answerHash = hashString(securityAnswer);
  const newPasswordHash = hashString(newPassword);
  
  // Verify user and security answer
  db.get('SELECT u.id FROM users u JOIN security_questions sq ON u.id = sq.userId WHERE u.username = ? AND sq.answerHash = ?', 
    [username, answerHash], 
    (err, result) => {
      if (err || !result) {
        return res.status(401).json({ error: 'Invalid username or security answer' });
      }
      
      // Update password
      db.run('UPDATE users SET passwordHash = ? WHERE id = ?',
        [newPasswordHash, result.id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to update password' });
          }
          
          res.json({ message: 'Password reset successfully' });
        }
      );
    }
  );
});

// --- Game Progress Routes ---

// Get user's game progress
app.get('/api/progress/:userId', (req, res) => {
  const userId = req.params.userId;
  
  db.get('SELECT levelsUnlocked, bestScores FROM game_progress WHERE userId = ?', 
    [userId], 
    (err, progress) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!progress) {
        // No progress yet, return defaults
        return res.json({
          levelsUnlocked: '[1]', // Start with level 1 unlocked
          bestScores: '{}'       // No scores yet
        });
      }
      
      res.json(progress);
    }
  );
});

// Update game progress
app.post('/api/progress', (req, res) => {
  const { userId, levelsUnlocked, bestScores } = req.body;
  
  if (!userId || !levelsUnlocked || !bestScores) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  // Check if progress exists
  db.get('SELECT id FROM game_progress WHERE userId = ?', 
    [userId], 
    (err, progress) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (progress) {
        // Update existing progress
        db.run('UPDATE game_progress SET levelsUnlocked = ?, bestScores = ? WHERE userId = ?',
          [levelsUnlocked, bestScores, userId],
          (err) => {
            if (err) {
              return res.status(500).json({ error: 'Failed to update progress' });
            }
            
            res.json({ message: 'Progress updated successfully' });
          }
        );
      } else {
        // Create new progress
        db.run('INSERT INTO game_progress (userId, levelsUnlocked, bestScores) VALUES (?, ?, ?)',
          [userId, levelsUnlocked, bestScores],
          (err) => {
            if (err) {
              return res.status(500).json({ error: 'Failed to save progress' });
            }
            
            res.json({ message: 'Progress saved successfully' });
          }
        );
      }
    }
  );
});

// Server status endpoint
app.get('/', (req, res) => {
  res.json({ status: 'Game Server is running' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 