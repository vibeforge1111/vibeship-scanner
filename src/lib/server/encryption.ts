import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import { ENCRYPTION_KEY } from '$env/static/private';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT = 'vibeship-scanner-salt'; // Static salt is fine since key should be random

function getKey(): Buffer {
	if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length < 32) {
		throw new Error('ENCRYPTION_KEY must be set and at least 32 characters');
	}
	// Derive a 32-byte key from the encryption key
	return scryptSync(ENCRYPTION_KEY, SALT, 32);
}

export function encrypt(plaintext: string): string {
	const key = getKey();
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv(ALGORITHM, key, iv);

	let encrypted = cipher.update(plaintext, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	const authTag = cipher.getAuthTag();

	// Format: iv:authTag:encrypted (all hex encoded)
	return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

export function decrypt(encryptedData: string): string {
	const key = getKey();

	const parts = encryptedData.split(':');
	if (parts.length !== 3) {
		throw new Error('Invalid encrypted data format');
	}

	const [ivHex, authTagHex, encrypted] = parts;
	const iv = Buffer.from(ivHex, 'hex');
	const authTag = Buffer.from(authTagHex, 'hex');

	const decipher = createDecipheriv(ALGORITHM, key, iv);
	decipher.setAuthTag(authTag);

	let decrypted = decipher.update(encrypted, 'hex', 'utf8');
	decrypted += decipher.final('utf8');

	return decrypted;
}
