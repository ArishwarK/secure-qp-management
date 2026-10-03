import crypto from 'crypto';

const rawKey = process.env.MASTER_KEY || '01234567890123456789012345678901';
const MASTER_KEY = Buffer.from(rawKey.padEnd(32, '0').slice(0, 32), 'utf-8');

/**
 * Encrypts question paper using AES-256-GCM.
 * Matches Python cryptography AESGCM: ciphertext + 16-byte auth tag.
 */
export function encryptQuestionPaper(plainText) {
  const nonce = crypto.randomBytes(12); // Standard 96-bit nonce for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, nonce);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  const combined = Buffer.concat([encrypted, tag]);

  return {
    nonce: nonce.toString('base64'),
    ciphertext: combined.toString('base64'),
  };
}

/**
 * Decrypts AES-256-GCM encrypted payload.
 * Throws an error if ciphertext or nonce is tampered with.
 */
export function decryptQuestionPaper(ciphertextB64, nonceB64) {
  const nonce = Buffer.from(nonceB64, 'base64');
  const combined = Buffer.from(ciphertextB64, 'base64');

  if (combined.length < 16) {
    throw new Error('Ciphertext is too short for AES-GCM tag verification');
  }

  const ciphertext = combined.subarray(0, combined.length - 16);
  const tag = combined.subarray(combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, nonce);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf-8');
}

/**
 * Encrypts binary file buffer using AES-256-GCM.
 */
export function encryptBuffer(buffer) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, nonce);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([encrypted, tag]);

  return {
    nonce: nonce.toString('base64'),
    ciphertext: combined.toString('base64'),
  };
}

/**
 * Decrypts AES-256-GCM encrypted binary buffer.
 */
export function decryptBuffer(ciphertextB64, nonceB64) {
  const nonce = Buffer.from(nonceB64, 'base64');
  const combined = Buffer.from(ciphertextB64, 'base64');

  if (combined.length < 16) {
    throw new Error('Ciphertext is too short for AES-GCM tag verification');
  }

  const ciphertext = combined.subarray(0, combined.length - 16);
  const tag = combined.subarray(combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

