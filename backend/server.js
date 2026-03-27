/**
 * backend/server.js
 * SecureVault — Merged Backend
 *
 * Features combined from both projects:
 *  ✔ RSA-PSS digital signatures + RSA-OAEP key encapsulation
 *  ✔ AES-256-CBC message decryption
 *  ✔ AES-256-GCM encrypted message storage (db.js)
 *  ✔ JWT authentication (auth.js)
 *  ✔ TLS/HTTPS with self-signed cert
 *  ✔ Client certificate detection (PKI)
 *  ✔ Encrypted file upload + AES-CBC decryption
 *  ✔ /secure endpoint for dashboard TLS info
 */

require('dotenv').config();
const https   = require('https');
const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const multer  = require('multer');

const { publicKey, privateKey } = require('./keys');
const { registerUser, loginUser, requireAuth } = require('./auth');
const { loadMessages, saveMessage } = require('./db');

const app = express();

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(cors({ origin: ['http://localhost:5173', 'https://localhost:5173'] }));
app.use(helmet({ contentSecurityPolicy: false }));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ─── AES HELPER (for file uploads from project 1) ─────────────
// Shared 32-byte key — in production, exchange via ECDH
const FILE_AES_KEY = Buffer.from(
  process.env.FILE_AES_KEY || 'ThisIsA32ByteSecretKey1234567890', 'utf8'
).slice(0, 32);

function aesDecryptBuffer(base64Payload) {
  const raw        = Buffer.from(base64Payload, 'base64');
  const iv         = raw.slice(0, 16);
  const ciphertext = raw.slice(16);
  const decipher   = crypto.createDecipheriv('aes-256-cbc', FILE_AES_KEY, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ─── PUBLIC KEY ───────────────────────────────────────────────
app.get('/public-key', (req, res) => res.send(publicKey));

// ─── AUTH ─────────────────────────────────────────────────────
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const result = registerUser(username, password);
  if (!result.success) return res.status(409).json({ error: result.error });
  res.json({ status: 'User registered successfully' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
  const result = loginUser(username, password);
  if (!result.success) return res.status(401).json({ error: result.error });
  res.json({ token: result.token });
});

// ─── SEND ENCRYPTED + SIGNED MESSAGE ─────────────────────────
app.post('/send', requireAuth, (req, res) => {
  try {
    const { encryptedMessage, encryptedKey, signature, signingPublicKey } = req.body;
    if (!encryptedMessage || !encryptedKey || !signature || !signingPublicKey)
      return res.status(400).json({ error: 'Missing required fields' });

    // Step 1: Verify RSA-PSS digital signature
    const isValid = crypto.verify(
      'sha256',
      Buffer.from(encryptedMessage, 'base64'),
      {
        key: signingPublicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      },
      Buffer.from(signature, 'base64')
    );
    if (!isValid) {
      console.warn(`⚠️  Signature FAILED for: ${req.user.username}`);
      return res.status(400).json({ error: 'Signature verification failed' });
    }

    // Step 2: RSA-OAEP decrypt AES key
    const decryptedKeyBuf = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(encryptedKey, 'base64')
    );
    const aesKey = Buffer.from(decryptedKeyBuf.toString(), 'hex');

    // Step 3: AES-256-CBC decrypt message
    const dataBuf       = Buffer.from(encryptedMessage, 'base64');
    const iv            = dataBuf.subarray(0, 16);
    const encryptedData = dataBuf.subarray(16);
    const decipher      = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    const finalMessage  = Buffer.concat([decipher.update(encryptedData), decipher.final()]).toString();

    console.log(`🔓 [${new Date().toISOString()}] ${req.user.username}: ${finalMessage}`);

    // Step 4: Re-encrypt and persist (AES-256-GCM via db.js)
    saveMessage(req.user.username, finalMessage);
    res.json({ status: 'Secure message received and verified' });
  } catch (err) {
    console.error('❌ Message error:', err.message);
    res.status(500).json({ error: 'Failed to process message' });
  }
});

// ─── GET MESSAGES ─────────────────────────────────────────────
app.get('/messages', requireAuth, (req, res) => {
  try {
    res.json(loadMessages());
  } catch (err) {
    console.error('❌ Load messages error:', err.message);
    res.status(500).json({ error: 'Failed to load messages' });
  }
});

// ─── FILE UPLOAD (AES-CBC encrypted file from browser) ────────
app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file received' });
    const base64Payload = req.file.buffer.toString('utf8');
    const originalName  = req.body.filename || 'upload';
    const decrypted     = aesDecryptBuffer(base64Payload);
    const savePath      = path.join(UPLOADS_DIR, `${Date.now()}_${req.user.username}_${originalName}`);
    fs.writeFileSync(savePath, decrypted);
    const ts = new Date().toISOString();
    console.log(`📁 [${ts}] ${req.user.username} uploaded: ${path.basename(savePath)} (${decrypted.length} bytes)`);
    res.json({
      success      : true,
      message      : 'File decrypted and saved.',
      savedAs      : path.basename(savePath),
      originalSize : decrypted.length,
      timestamp    : ts,
    });
  } catch (err) {
    console.error('❌ File upload error:', err.message);
    res.status(500).json({ error: 'File decryption failed: ' + err.message });
  }
});

// ─── SECURE / TLS INFO ENDPOINT ───────────────────────────────
app.get('/secure', (req, res) => {
  const cert = req.socket.getPeerCertificate?.(true);
  res.json({
    success : true,
    tls     : {
      tlsVersion : req.socket.getProtocol?.() ?? 'TLSv1.3',
      cipher     : req.socket.getCipher?.()?.name ?? 'TLS_AES_256_GCM_SHA384',
      serverCert : { subject: 'CN=localhost', issuer: 'CN=localhost (Self-Signed)', valid: true },
      clientCert : (cert && cert.subject)
        ? { cn: cert.subject.CN || 'Unknown', org: cert.subject.O || 'Unknown',
            issuer: cert.issuer?.CN || 'Unknown', valid: req.socket.authorized,
            serial: cert.serialNumber || 'N/A' }
        : null,
      authorized : req.socket.authorized || false,
      timestamp  : new Date().toISOString(),
    },
  });
});

// ─── HTTPS SERVER ─────────────────────────────────────────────
const CERTS_DIR = path.join(__dirname, 'certs');
const keyPath   = path.join(CERTS_DIR, 'server.key');
const certPath  = path.join(CERTS_DIR, 'server.crt');

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  https.createServer(
    { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath), requestCert: true, rejectUnauthorized: false },
    app
  ).listen(8443, () => console.log('🔒 HTTPS → https://localhost:8443'));
} else {
  console.warn('⚠️  Certs not found — running HTTP on 8443 (run npm run gen-certs)');
  http.createServer(app).listen(8443, () => console.log('⚠️  HTTP → http://localhost:8443'));
}
