const https = require('https');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const { publicKey, privateKey } = require('./keys');

const app = express();
app.use(express.json());
app.use(cors());
app.use(helmet());

let messages = [];

// 🔑 Send public key to client
app.get('/public-key', (req, res) => {
    res.send(publicKey);
});

// 🔐 Receive encrypted message (RSA + AES)
app.post('/send', (req, res) => {
    try {
        const { encryptedMessage, encryptedKey } = req.body;

        const decryptedKeyBuffer = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",   // 🔥 REQUIRED FIX
            },
            Buffer.from(encryptedKey, 'base64')
        );

// Convert HEX string → Buffer
const aesKey = Buffer.from(decryptedKeyBuffer.toString(), 'hex');

        // 2️⃣ Extract IV + encrypted data
        const dataBuffer = Buffer.from(encryptedMessage, 'base64');
        const iv = dataBuffer.subarray(0, 16);
        const encryptedData = dataBuffer.subarray(16);

        // 3️⃣ Decrypt message using AES
        const decipher = crypto.createDecipheriv(
            'aes-256-cbc',
            aesKey,
            iv
        );

        let decrypted = decipher.update(encryptedData);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        const finalMessage = decrypted.toString();

        console.log("🔓 Decrypted message:", finalMessage);

        // Store decrypted message (for demo)
        messages.push(finalMessage);

        res.json({ status: "Secure message received" });

    } catch (err) {
        console.error("❌ Decryption failed:", err);
        res.status(500).json({ error: "Decryption failed" });
    }
});

// 📥 Get messages
app.get('/messages', (req, res) => {
    res.json(messages);
});

// 🔐 HTTPS server
https.createServer({
    key: fs.readFileSync('./certs/server.key'),
    cert: fs.readFileSync('./certs/server.crt')
}, app).listen(8443, () => {
    console.log("🔐 Server running at https://localhost:8443");
});