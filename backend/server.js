import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { exec } from 'child_process';
import { promisify } from 'util';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const execAsync = promisify(exec);
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const ALLOWED_ORIGIN = process.env.API_URL || 'http://localhost:5173';

// Strict CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (origin === ALLOWED_ORIGIN) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
};

// Apply CORS with strict options
app.use(cors(corsOptions));
app.use(express.json());

// Error handling middleware for CORS errors
app.use((err, req, res, next) => {
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({
      error: 'Access denied: Origin not allowed',
      details: 'This API can only be accessed by the authorized UI component'
    });
  } else {
    next(err);
  }
});

// Rate limiting middleware
const rateLimit = new Map();
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS = 100;

app.use((req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  
  if (!rateLimit.has(ip)) {
    rateLimit.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return next();
  }

  const limit = rateLimit.get(ip);
  if (now > limit.resetAt) {
    rateLimit.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return next();
  }

  if (limit.count >= MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Too many requests',
      retryAfter: Math.ceil((limit.resetAt - now) / 1000)
    });
  }

  limit.count++;
  next();
});

// Database setup
let db;

async function initializeDatabase() {
  db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    );

    CREATE TABLE IF NOT EXISTS access_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      port INTEGER NOT NULL,
      protocol TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'inactive',
      FOREIGN KEY (user_id) REFERENCES users (id)
    );
  `);

  // Create admin user if it doesn't exist
  const adminExists = await db.get('SELECT * FROM users WHERE email = ?', ['admin@example.com']);
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await db.run(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      ['Admin', 'admin@example.com', hashedPassword, 'admin']
    );
  }
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Input validation schemas
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6)
});

const userSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  password: z.string().min(6)
});

const accessRuleSchema = z.object({
  userId: z.number(),
  port: z.number().min(1).max(65535),
  protocol: z.enum(['tcp', 'udp']),
  status: z.enum(['active', 'inactive'])
});

// IPTables management
async function updateFirewallRules(userId, port, protocol, status) {
  const action = status === 'active' ? '-A' : '-D';
  try {
    await execAsync(`sudo iptables ${action} INPUT -p ${protocol} --dport ${port} -j ACCEPT`);
    return true;
  } catch (error) {
    console.error('Error updating firewall rules:', error);
    return false;
  }
}

// Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);
    
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    const user = await db.get('SELECT id, name, email, role FROM users WHERE id = ?', [req.user.id]);
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/access-rules', authenticateToken, async (req, res) => {
  try {
    const rules = await db.all('SELECT * FROM access_rules WHERE user_id = ?', [req.user.id]);
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin routes
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await db.all('SELECT id, name, email, role FROM users');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const userData = userSchema.parse(req.body);
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    
    const result = await db.run(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [userData.name, userData.email, hashedPassword]
    );
    
    res.status(201).json({ id: result.lastID, name: userData.name, email: userData.email });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/admin/access-rules', authenticateToken, isAdmin, async (req, res) => {
  try {
    const ruleData = accessRuleSchema.parse(req.body);
    
    const result = await db.run(
      'INSERT INTO access_rules (user_id, port, protocol, status) VALUES (?, ?, ?, ?)',
      [ruleData.userId, ruleData.port, ruleData.protocol, ruleData.status]
    );
    
    if (ruleData.status === 'active') {
      await updateFirewallRules(ruleData.userId, ruleData.port, ruleData.protocol, 'active');
    }
    
    res.status(201).json({ id: result.lastID, ...ruleData });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/admin/access-rules/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const ruleData = accessRuleSchema.parse(req.body);
    
    const oldRule = await db.get('SELECT * FROM access_rules WHERE id = ?', [id]);
    if (!oldRule) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    
    await db.run(
      'UPDATE access_rules SET user_id = ?, port = ?, protocol = ?, status = ? WHERE id = ?',
      [ruleData.userId, ruleData.port, ruleData.protocol, ruleData.status, id]
    );
    
    if (oldRule.status !== ruleData.status) {
      await updateFirewallRules(
        ruleData.userId,
        ruleData.port,
        ruleData.protocol,
        ruleData.status
      );
    }
    
    res.json({ id, ...ruleData });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Initialize database and start server
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  });