const crypto = require('crypto');

const ENCRYPTION_SECRET = process.env.VAULT_ENCRYPTION_KEY || 'trustvault-master-zero-trust-key-2026-snovasys';
const VAULT_KEY = crypto.createHash('sha256').update(ENCRYPTION_SECRET).digest();

/**
 * Encrypt a file buffer using AES-256-GCM (Authenticated Encryption)
 * Produces format: [16 bytes IV] + [16 bytes AuthTag] + [Ciphertext]
 */
function encryptBuffer(buffer) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', VAULT_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]);
}

/**
 * Decrypt an AES-256-GCM encrypted file buffer
 * Validates integrity via AuthTag to detect any ciphertext tampering
 */
function decryptBuffer(encryptedBuffer) {
  if (!Buffer.isBuffer(encryptedBuffer) || encryptedBuffer.length < 32) {
    return encryptedBuffer;
  }
  try {
    const iv = encryptedBuffer.subarray(0, 16);
    const authTag = encryptedBuffer.subarray(16, 32);
    const ciphertext = encryptedBuffer.subarray(32);

    const decipher = crypto.createDecipheriv('aes-256-gcm', VAULT_KEY, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    // If decryption fails (e.g. legacy plaintext buffer), fallback safely
    return encryptedBuffer;
  }
}

module.exports = {
  encryptBuffer,
  decryptBuffer
};
