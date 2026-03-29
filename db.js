const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const DB_FILE  = path.join(__dirname, 'data', 'messages.json');
const DB_SECRET = process.env.DB_SECRET || crypto.randomBytes(32).toString('hex');
const DB_KEY    = Buffer.from(DB_SECRET.slice(0, 64), 'hex');

function encryptForStorage(plaintext) {
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', DB_KEY, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), data: enc.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
}

function decryptFromStorage({ iv, data, tag }) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', DB_KEY, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(data, 'hex')), decipher.final()]).toString('utf8');
}

function loadMessages() {
  if (!fs.existsSync(DB_FILE)) return [];
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')).map(e => ({
    sender: e.sender, timestamp: e.timestamp, message: decryptFromStorage(e.encrypted),
  }));
}

function saveMessage(sender, plaintext) {
  const dir = path.dirname(DB_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const existing = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) : [];
  existing.push({ sender, timestamp: new Date().toISOString(), encrypted: encryptForStorage(plaintext) });
  fs.writeFileSync(DB_FILE, JSON.stringify(existing, null, 2));
}

module.exports = { loadMessages, saveMessage };
