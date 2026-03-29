# 🔒 SecureVault — Merged Capstone Project

Combines both projects into one full-stack secure application.

## New Project Structure

```
merged/
├── backend/
│   ├── server.js       ← HTTPS Express (all routes)
│   ├── keys.js         ← RSA-2048 key pair persistence
│   ├── auth.js         ← PBKDF2 + JWT authentication
│   ├── db.js           ← AES-256-GCM encrypted message storage
│   ├── certs/          ← TLS + RSA keys (auto-created)
│   ├── data/           ← messages.json, users.json (auto-created)
│   └── uploads/        ← Decrypted uploaded files (auto-created)
├── frontend/
│   └── src/
│       ├── App.jsx     ← React UI (all features)
│       └── App.css     ← Light theme styles
├── package.json
└── .env                ← You create this
```

## What's merged

| Feature | Source |
|---------|--------|
| RSA+AES hybrid encryption | Project 2 |
| RSA-PSS digital signatures | Project 2 |
| JWT authentication | Project 2 |
| PBKDF2 password hashing | Project 2 |
| AES-GCM encrypted storage | Project 2 |
| Encrypted file upload | Project 1 |
| TLS dashboard + /secure endpoint | Project 1 |
| Client certificate detection | Project 1 |
| Light theme UI | New |

## Setup (Windows — Git Bash)

### 1. Install dependencies

```bash
npm install
cd frontend && npm install && cd ..
```

### 2. Create .env file

Create a file called `.env` in the project root:

```
JWT_SECRET=your-long-random-secret-here-make-it-64-chars
DB_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
FILE_AES_KEY=ThisIsA32ByteSecretKey1234567890
```

> ⚠️ DB_SECRET must be exactly 64 hex characters (32 bytes). Once set, never change it or your stored messages become unreadable.

### 3. Generate TLS certificates (Git Bash)

```bash
mkdir -p backend/certs
cd backend/certs
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
cd ../..
```

### 4. Run backend + frontend (two terminals)

**Terminal 1:**
```bash
node backend/server.js
```

**Terminal 2:**
```bash
cd frontend
npm run dev
```

### 5. Open in browser

```
http://localhost:5173
```

On first load, visit `https://localhost:8443/public-key` and click **Advanced → Proceed** to accept the self-signed cert.

## Security Architecture

```
BROWSER                              SERVER
──────────────────────────────────────────────────────
1. AES-256-CBC encrypt message       5. Verify JWT
   (CryptoJS, random key+IV)         6. Verify RSA-PSS signature
2. RSA-OAEP encrypt AES key          7. RSA-OAEP decrypt AES key
   (server's public key)             8. AES-CBC decrypt message
3. RSA-PSS sign ciphertext           9. AES-GCM re-encrypt for disk
4. Send { msg, key, sig, pubkey }
   + Bearer JWT over TLS
```

## What This Demonstrates

| Principle | Implementation |
|-----------|---------------|
| Confidentiality | AES-256-CBC + RSA-OAEP key wrap |
| Integrity | RSA-PSS digital signature |
| Authentication | JWT (PBKDF2 passwords, timing-safe compare) |
| Non-repudiation | Signed ciphertext with client's ephemeral key |
| Secure transport | TLS 1.3 HTTPS |
| Encrypted storage | AES-256-GCM with auth tag — never plaintext on disk |
| File security | AES-256-CBC browser encryption before upload |
| PKI | Client certificate detection + TLS dashboard |
