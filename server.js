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
  const { email, password, securityQuestion, securityAnswer } = req.body;
  
  if (!email || !password || !securityQuestion || !securityAnswer) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  const passwordHash = hashString(password);
  const answerHash = hashString(securityAnswer);
  
  // Insert user
  db.run('INSERT INTO users (email, passwordHash) VALUES (?, ?)', 
    [email, passwordHash], 
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'Email already exists' });
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
  const { email, password, deviceIdentifier } = req.body;
  
  if (!email || !password || !deviceIdentifier) {
    return res.status(400).json({ error: 'Email, password and device identifier required' });
  }
  
  const passwordHash = hashString(password);
  
  // Check user credentials
  db.get('SELECT id FROM users WHERE email = ? AND passwordHash = ?', 
    [email, passwordHash], 
    (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Invalid email or password' });
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
  
  console.log(`Verification request received: userId=${userId}, deviceId=${deviceIdentifier}`);
  
  if (!userId || !deviceIdentifier || !securityAnswer) {
    console.log("Missing required fields");
    return res.status(400).json({ error: 'All fields are required', success: false });
  }
  
  const answerHash = hashString(securityAnswer);
  console.log(`Answer hash: ${answerHash}`);
  
  // Handle email as userId
  const isEmail = userId.includes('@');
  console.log(`User identifier is ${isEmail ? 'an email' : 'a numeric ID'}`);
  
  // Query to get the user ID
  const userQuery = isEmail 
    ? 'SELECT id FROM users WHERE email = ?' 
    : 'SELECT id FROM users WHERE id = ?';
  
  // First get user ID from database
  db.get(userQuery, [userId], (err, user) => {
    if (err) {
      console.error("Database error finding user:", err);
      return res.status(500).json({ error: 'Database error', success: false });
    }
    
    if (!user) {
      console.log(`User not found for identifier: ${userId}`);
      return res.status(404).json({ error: 'User not found', success: false });
    }
    
    const numericUserId = user.id;
    console.log(`Found user with ID: ${numericUserId}`);
    
    // Get user's security question answer
    db.get('SELECT answerHash FROM security_questions WHERE userId = ?', 
      [numericUserId], 
      (err, question) => {
        if (err) {
          console.error("Database error finding security question:", err);
          return res.status(500).json({ error: 'Database error', success: false });
        }
        
        if (!question) {
          console.log(`No security question found for user ID: ${numericUserId}`);
          
          // DEBUG: Let's check all security questions in the database
          db.all('SELECT userId, question, answerHash FROM security_questions', [], (err, allQuestions) => {
            if (err) {
              console.error("Error retrieving all security questions:", err);
            } else {
              console.log("All security questions in database:", allQuestions);
            }
          });
          
          return res.status(404).json({ error: 'Security question not found', success: false });
        }
        
        console.log(`Found security question. Stored hash: ${question.answerHash}`);
        console.log(`Comparing with provided hash: ${answerHash}`);
        
        if (question.answerHash !== answerHash) {
          console.log("Security answer is incorrect");
          return res.status(401).json({ 
            error: 'Incorrect security answer',
            success: false
          });
        }
        
        console.log("Security answer is correct, verifying device");
        
        // Answer is correct, verify the device
        db.run('UPDATE devices SET isVerified = 1 WHERE userId = ? AND deviceIdentifier = ?',
          [numericUserId, deviceIdentifier],
          function(err) {
            if (err) {
              console.error("Error updating device verification:", err);
              return res.status(500).json({ 
                error: 'Failed to verify device',
                success: false
              });
            }
            
            // Check if any rows were affected
            if (this.changes === 0) {
              console.log("No devices were updated. Device may not exist for this user.");
              
              // Insert the device if it doesn't exist
              db.run('INSERT INTO devices (userId, deviceIdentifier, isVerified) VALUES (?, ?, 1)',
                [numericUserId, deviceIdentifier],
                (err) => {
                  if (err) {
                    console.error("Error inserting device:", err);
                    return res.status(500).json({ 
                      error: 'Failed to add device',
                      success: false
                    });
                  }
                  
                  console.log("Device added and verified successfully");
                  res.json({ 
                    message: 'Device added and verified successfully',
                    success: true 
                  });
                }
              );
            } else {
              console.log("Device verified successfully");
              res.json({ 
                message: 'Device verified successfully',
                success: true 
              });
            }
          }
        );
      }
    );
  });
});

// Get security question for a user
app.get('/api/security-question/:email', (req, res) => {
  const email = req.params.email;
  
  db.get('SELECT id FROM users WHERE email = ?', 
    [email], 
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

// --- Game Progress Routes ---

// Get user's game progress
app.get('/api/progress/:userId', (req, res) => {
  const userId = req.params.userId;
  
  db.get('SELECT bestScores FROM game_progress WHERE userId = ?', 
    [userId], 
    (err, progress) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!progress) {
        // No progress yet, return defaults
        return res.json({
          bestScores: '{}'       // No scores yet
        });
      }
      
      res.json(progress);
    }
  );
});

// Update game progress
app.post('/api/progress', (req, res) => {
  const { userId, bestScores } = req.body;
  
  if (!userId || !bestScores) {
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
        db.run('UPDATE game_progress SET bestScores = ? WHERE userId = ?',
          [bestScores, userId],
          (err) => {
            if (err) {
              return res.status(500).json({ error: 'Failed to update progress' });
            }
            
            res.json({ message: 'Progress updated successfully' });
          }
        );
      } else {
        // Create new progress
        db.run('INSERT INTO game_progress (userId, bestScores) VALUES (?, ?)',
          [userId, bestScores],
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