const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI;

// Password hashing helpers
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  if (!storedPassword || !storedPassword.includes(':')) return false;
  const [salt, hash] = storedPassword.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === verifyHash;
}

// Middleware
app.use(cors({
  origin: 'http://localhost:3000', // Allow requests from React frontend
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Support parsing text/plain beacons
app.use((req, res, next) => {
  if (req.header('content-type') === 'text/plain' && typeof req.body === 'string') {
    try {
      req.body = JSON.parse(req.body);
    } catch (e) { }
  }
  next();
});

// MongoDB connection
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Successfully connected to MongoDB.'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Schemas & Models
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String }, // not required for guest
  isGuest: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: null }
});

// TTL index to automatically delete guest sessions after 24h
UserSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', UserSchema);

const QuestionSchema = new mongoose.Schema({
  question: { type: String, required: true },
  choices: [{ type: String }],
  answer: { type: String, required: true },
  code: { type: String, default: null },
  codeLang: { type: String, default: 'python' }
}, { _id: false });

const ResultSchema = new mongoose.Schema({
  score: { type: Number, required: true },
  total: { type: Number, required: true },
  percentage: { type: Number, required: true },
  submittedAt: { type: String, required: true },
  answers: { type: Map, of: String, required: true }
}, { _id: false });

const QuizSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true }, // The UUID from client
  query: { type: String, required: true },
  questions: [QuestionSchema],
  questionMode: { type: String, default: null },
  isCoding: { type: Boolean, default: false },
  createdAt: { type: String, required: true },
  result: { type: ResultSchema, default: null },
  userId: { type: String, default: null }, // Link to User._id
  expiresAt: { type: Date, default: null } // TTL for guest quizzes
});

// TTL index to automatically delete guest quizzes
QuizSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Quiz = mongoose.model('Quiz', QuizSchema);

// Middleware to authenticate requests based on a simple Authorization header containing the user ID
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No authorization token provided' });
  }
  const token = authHeader.split(' ')[1]; // Bearer <userId>
  if (!token) {
    return res.status(401).json({ error: 'Invalid authorization token format' });
  }
  try {
    const user = await User.findById(token);
    if (!user) {
      return res.status(401).json({ error: 'User session has expired or is invalid' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
};

// Auth API Endpoints

// 1. POST /api/auth/signup - Register new user
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;
    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const emailNormalized = email.trim().toLowerCase();
    const nameTrimmed = name.trim();

    // Check if email already exists
    const existingEmail = await User.findOne({ email: emailNormalized });
    if (existingEmail) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Check if name already exists
    const existingName = await User.findOne({ name: nameTrimmed });
    if (existingName) {
      return res.status(400).json({ error: 'User with this name already exists' });
    }

    const hashedPassword = hashPassword(password);
    const newUser = new User({
      name: nameTrimmed,
      email: emailNormalized,
      password: hashedPassword,
      isGuest: false
    });

    await newUser.save();
    res.status(201).json({
      message: 'Signup successful!',
      user: {
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        isGuest: false,
        createdAt: newUser.createdAt
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to complete signup' });
  }
});

// 2. POST /api/auth/login - Log in an existing user
app.post('/api/auth/login', async (req, res) => {
  try {
    const { loginKey, password } = req.body; // loginKey is email or name
    if (!loginKey || !password) {
      return res.status(400).json({ error: 'Name/Email and password are required' });
    }

    const trimmedKey = loginKey.trim();
    // Search by email (case-insensitive) or name (exact)
    const user = await User.findOne({
      $or: [
        { email: trimmedKey.toLowerCase() },
        { name: trimmedKey }
      ]
    });

    if (!user || user.isGuest) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = verifyPassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({
      message: 'Login successful!',
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        isGuest: false,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

// 3. POST /api/auth/guest - Log in as a temporary Guest
app.post('/api/auth/guest', async (req, res) => {
  try {
    const randomSuffix = crypto.randomBytes(3).toString('hex');
    const guestName = `Guest_${randomSuffix}`;
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24-hour expiry TTL

    const newGuest = new User({
      name: guestName,
      isGuest: true,
      expiresAt
    });

    await newGuest.save();

    res.status(201).json({
      message: 'Guest session initialized',
      user: {
        _id: newGuest._id,
        name: newGuest.name,
        isGuest: true,
        createdAt: newGuest.createdAt,
        expiresAt: newGuest.expiresAt
      }
    });
  } catch (error) {
    console.error('Guest login error:', error);
    res.status(500).json({ error: 'Failed to start guest session' });
  }
});

// 4. POST /api/auth/guest-cleanup - Immediately clean up a guest session on unload
app.post('/api/auth/guest-cleanup', async (req, res) => {
  try {
    let { userId } = req.body;
    if (!userId && typeof req.body === 'string') {
      try {
        const parsed = JSON.parse(req.body);
        userId = parsed.userId;
      } catch (err) { }
    }

    if (!userId) {
      return res.status(400).json({ error: 'Missing userId for cleanup' });
    }

    // Verify and delete guest user
    const user = await User.findById(userId);
    if (user && user.isGuest) {
      await User.findByIdAndDelete(userId);
      await Quiz.deleteMany({ userId });
      return res.json({ message: `Cleaned up guest user ${userId} and associated quizzes.` });
    }

    res.json({ message: 'User not found or is not a guest.' });
  } catch (error) {
    console.error('Guest cleanup error:', error);
    res.status(500).json({ error: 'Failed to clean up guest session' });
  }
});

// REST API Quiz History Endpoints (User-Scoped)

// 1. GET /api/history - Fetch saved quizzes for the authenticated user
app.get('/api/history', authenticate, async (req, res) => {
  try {
    const quizzes = await Quiz.find({ userId: req.user._id }).sort({ createdAt: -1 });
    res.json(quizzes);
  } catch (error) {
    console.error('Error fetching history:', error);
    res.status(500).json({ error: 'Failed to fetch quiz history' });
  }
});

// 2. POST /api/history - Save a new quiz for the authenticated user
app.post('/api/history', authenticate, async (req, res) => {
  try {
    const { id, query, questions, questionMode, isCoding, createdAt, result } = req.body;
    if (!id || !query || !questions) {
      return res.status(400).json({ error: 'Missing required quiz fields' });
    }

    // Check if quiz already exists
    const existing = await Quiz.findOne({ id });
    if (existing) {
      return res.status(400).json({ error: 'Quiz with this ID already exists' });
    }

    const newQuiz = new Quiz({
      id,
      query,
      questions,
      questionMode,
      isCoding,
      createdAt,
      result,
      userId: req.user._id,
      expiresAt: req.user.isGuest ? req.user.expiresAt : null
    });

    await newQuiz.save();
    res.status(201).json(newQuiz);
  } catch (error) {
    console.error('Error saving quiz:', error);
    res.status(500).json({ error: 'Failed to save quiz to database' });
  }
});

// 3. PUT /api/history/:id - Update the results of an existing quiz (User-Scoped)
app.put('/api/history/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { result } = req.body;

    if (!result) {
      return res.status(400).json({ error: 'Missing quiz result data' });
    }

    const updatedQuiz = await Quiz.findOneAndUpdate(
      { id, userId: req.user._id },
      { $set: { result } },
      { new: true }
    );

    if (!updatedQuiz) {
      return res.status(404).json({ error: 'Quiz not found or unauthorized' });
    }

    res.json(updatedQuiz);
  } catch (error) {
    console.error('Error updating quiz result:', error);
    res.status(500).json({ error: 'Failed to update quiz result' });
  }
});

// 4. DELETE /api/history - Delete all quizzes for the authenticated user
app.delete('/api/history', authenticate, async (req, res) => {
  try {
    await Quiz.deleteMany({ userId: req.user._id });
    res.json({ message: 'All quizzes deleted successfully' });
  } catch (error) {
    console.error('Error deleting all quizzes:', error);
    res.status(500).json({ error: 'Failed to delete all quizzes' });
  }
});

// 5. DELETE /api/history/:id - Delete a specific quiz (User-Scoped)
app.delete('/api/history/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedQuiz = await Quiz.findOneAndDelete({ id, userId: req.user._id });

    if (!deletedQuiz) {
      return res.status(404).json({ error: 'Quiz not found or unauthorized' });
    }

    res.json({ message: 'Quiz deleted successfully', id });
  } catch (error) {
    console.error('Error deleting quiz:', error);
    res.status(500).json({ error: 'Failed to delete quiz' });
  }
});

// Status page for backend root
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>MCQ Studio Backend Status</title>
      <style>
        body {
          margin: 0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
          background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #312e81 100%);
          color: #f1f5f9;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
        }
        .container {
          background: rgba(30, 41, 59, 0.7);
          border: 1px solid rgba(255, 255, 255, 0.1);
          box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
          border-radius: 24px;
          padding: 40px;
          text-align: center;
          max-width: 500px;
          width: 90%;
          backdrop-filter: blur(10px);
        }
        .logo {
          font-size: 3.5rem;
          margin-bottom: 20px;
          animation: pulse 2s infinite ease-in-out;
          display: inline-block;
        }
        h1 {
          font-size: 1.8rem;
          margin: 0 0 10px 0;
          background: linear-gradient(135deg, #818cf8, #f472b6);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
        .status-badge {
          display: inline-block;
          padding: 6px 14px;
          border-radius: 20px;
          background: rgba(34, 197, 94, 0.15);
          border: 1px solid rgba(34, 197, 94, 0.3);
          color: #4ade80;
          font-size: 0.85rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-bottom: 30px;
        }
        .endpoints-list {
          text-align: left;
          background: rgba(15, 23, 42, 0.5);
          padding: 20px;
          border-radius: 14px;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }
        .endpoints-list h3 {
          margin-top: 0;
          font-size: 1rem;
          color: #94a3b8;
          border-bottom: 1px solid rgba(255, 255, 255, 0.1);
          padding-bottom: 8px;
        }
        .endpoint-item {
          display: flex;
          justify-content: space-between;
          font-family: monospace;
          font-size: 0.85rem;
          padding: 6px 0;
          border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }
        .endpoint-item:last-child {
          border-bottom: none;
        }
        .method {
          font-weight: bold;
        }
        .method.post { color: #f43f5e; }
        .method.get { color: #10b981; }
        .method.put { color: #f59e0b; }
        .method.delete { color: #ef4444; }
        .path { color: #cbd5e1; }
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.08); }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">⚡</div>
        <h1>MCQ Studio Backend</h1>
        <div class="status-badge">API Running Successfully</div>
      </div>
    </body>
    </html>
  `);
});


// <div class="endpoints-list">
//   <h3>Active API Endpoints</h3>
//   <div class="endpoint-item">
//     <span class="method post">POST</span>
//     <span class="path">/api/auth/signup</span>
//   </div>
//   <div class="endpoint-item">
//     <span class="method post">POST</span>
//     <span class="path">/api/auth/login</span>
//   </div>
//   <div class="endpoint-item">
//     <span class="method post">POST</span>
//     <span class="path">/api/auth/guest</span>
//   </div>
//   <div class="endpoint-item">
//     <span class="method post">POST</span>
//     <span class="path">/api/auth/guest-cleanup</span>
//   </div>
//   <div class="endpoint-item">
//     <span class="method get">GET</span>
//     <span class="path">/api/history</span>
//   </div>
//   <div class="endpoint-item">
//     <span class="method post">POST</span>
//     <span class="path">/api/history</span>
//   </div>
//   <div class="endpoint-item">
//     <span class="method put">PUT</span>
//     <span class="path">/api/history/:id</span>
//   </div>
//   <div class="endpoint-item">
//     <span class="method delete">DELETE</span>
//     <span class="path">/api/history</span>
//   </div>
// </div>

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
