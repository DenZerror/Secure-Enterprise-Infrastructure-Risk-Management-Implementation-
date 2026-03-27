const crypto = require('crypto');
const jwt    = require('jsonwebtoken');
const fs     = require('fs');
const path   = require('path');

const USERS_FILE  = path.join(__dirname, 'data', 'users.json');
const JWT_SECRET  = process.env.JWT_SECRET || 'change-this-in-production-please';

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}
function saveUsers(users) {
  const dir = path.dirname(USERS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
}

function registerUser(username, password) {
  const users = loadUsers();
  if (users[username]) return { success: false, error: 'Username already exists' };
  const salt = crypto.randomBytes(16).toString('hex');
  users[username] = { salt, hash: hashPassword(password, salt) };
  saveUsers(users);
  return { success: true };
}

function loginUser(username, password) {
  const users = loadUsers();
  const user  = users[username];
  if (!user) return { success: false, error: 'Invalid credentials' };
  const hash  = hashPassword(password, user.salt);
  const match = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.hash, 'hex'));
  if (!match) return { success: false, error: 'Invalid credentials' };
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '2h' });
  return { success: true, token };
}

function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { registerUser, loginUser, requireAuth };
