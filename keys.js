const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const KEYS_DIR     = path.join(__dirname, 'certs');
const PUB_KEY_PATH  = path.join(KEYS_DIR, 'rsa_public.pem');
const PRIV_KEY_PATH = path.join(KEYS_DIR, 'rsa_private.pem');

function generateAndSaveKeys() {
  console.log('🔑 Generating RSA-2048 key pair...');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pubPem  = publicKey.export({ type: 'spki', format: 'pem' });
  const privPem = privateKey.export({ type: 'pkcs1', format: 'pem' });
  if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR, { recursive: true });
  fs.writeFileSync(PUB_KEY_PATH, pubPem);
  fs.writeFileSync(PRIV_KEY_PATH, privPem);
  console.log('✅ RSA keys saved.');
  return { publicKey: pubPem, privateKey: privPem };
}

function loadOrGenerateKeys() {
  if (fs.existsSync(PUB_KEY_PATH) && fs.existsSync(PRIV_KEY_PATH)) {
    console.log('🔑 Loading existing RSA keys...');
    return { publicKey: fs.readFileSync(PUB_KEY_PATH, 'utf8'), privateKey: fs.readFileSync(PRIV_KEY_PATH, 'utf8') };
  }
  return generateAndSaveKeys();
}

module.exports = loadOrGenerateKeys();
