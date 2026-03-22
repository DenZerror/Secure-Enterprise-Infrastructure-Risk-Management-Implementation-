const crypto = require('crypto');

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Export keys
module.exports = {
  publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' })
};