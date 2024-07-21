import { _ } from '@joplin/lib/locale';
import { Crypto, CryptoBuffer, EncryptionResult } from '@joplin/lib/services/e2ee/types';
import QuickCrypto from 'react-native-quick-crypto';
import { HashAlgorithm } from 'react-native-quick-crypto/lib/typescript/keys';
import type { CipherCCMOptions, CipherCCM, DecipherCCM, CipherGCMOptions, CipherGCM, DecipherGCM } from 'crypto';

const crypto: Crypto = {

	getCiphers: () => {
		return QuickCrypto.getCiphers();
	},

	getHashes: () => {
		return QuickCrypto.getHashes();
	},

	randomBytes: async (size: number) => {
		return new Promise((resolve, reject) => {
			QuickCrypto.randomBytes(size, (error, result) => {
				if (error) {
					reject(error);
				} else {
					resolve(result);
				}
			});
		});
	},

	pbkdf2Raw: async (password: string, salt: CryptoBuffer, iterations: number, keylen: number, digest: string) => {
		const digestMap: { [key: string]: HashAlgorithm } = {
			'sha1': 'SHA-1',
			'sha224': 'SHA-224',
			'sha256': 'SHA-256',
			'sha384': 'SHA-384',
			'sha512': 'SHA-512',
			'ripemd160': 'RIPEMD-160',
		};
		const digestAlgorithm: string = digestMap[digest.toLowerCase()] || digest;
		return new Promise((resolve, reject) => {
			QuickCrypto.pbkdf2(password, salt, iterations, keylen, digestAlgorithm as HashAlgorithm, (error, result) => {
				if (error) {
					reject(error);
				} else {
					resolve(result);
				}
			});
		});
	},

	encryptRaw: (data: CryptoBuffer, algorithm: string, key: CryptoBuffer, iv: CryptoBuffer | null, authTagLength: number, associatedData: Buffer | null) => {

		algorithm = algorithm.toLowerCase();
		if (iv === null) {
			iv = QuickCrypto.randomBytes(12);
		}
		if (associatedData === null) {
			associatedData = Buffer.alloc(0);
		}

		let cipher = null;
		if (algorithm.includes('gcm')) {
			cipher = QuickCrypto.createCipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherGCMOptions) as CipherGCM;
		} else if (algorithm.includes('ccm')) {
			cipher = QuickCrypto.createCipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherCCMOptions) as CipherCCM;
		} else {
			throw new Error(_('Unknown cipher algorithm: %s', algorithm));
		}

		cipher.setAAD(associatedData, { plaintextLength: Buffer.byteLength(data) });

		const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
		const authTag = cipher.getAuthTag();

		return Buffer.concat([encryptedData, authTag]);
	},

	decryptRaw: (data: CryptoBuffer, algorithm: string, key: CryptoBuffer, iv: CryptoBuffer, authTagLength: number, associatedData: Buffer | null) => {

		algorithm = algorithm.toLowerCase();
		if (associatedData === null) {
			associatedData = Buffer.alloc(0);
		}

		let decipher = null;
		if (algorithm.includes('gcm')) {
			decipher = QuickCrypto.createDecipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherGCMOptions) as DecipherGCM;
		} else if (algorithm.includes('ccm')) {
			decipher = QuickCrypto.createDecipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherCCMOptions) as DecipherCCM;
		} else {
			throw new Error(_('Unknown decipher algorithm: %s', algorithm));
		}

		const authTag = data.subarray(-authTagLength);
		const encryptedData = data.subarray(0, data.byteLength - authTag.byteLength);
		decipher.setAuthTag(authTag);
		decipher.setAAD(associatedData, { plaintextLength: Buffer.byteLength(data) });

		let decryptedData = null;
		try {
			decryptedData = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
		} catch (error) {
			throw new Error(`Authentication failed! ${error}`);
		}

		return decryptedData;
	},

	encrypt: async (password: string, iterationCount: number, salt: CryptoBuffer | null, data: CryptoBuffer) => {

		const result: EncryptionResult = {
			algo: 'aes-256-gcm', // algorithm
			ts: 16, // authTagLength: 16 bytes (128 bits)
			hash: 'SHA-512', // digestAlgorithm
			iter: iterationCount,
			salt: '',
			iv: '',
			ct: '', // cipherText
		};
		salt = salt || await crypto.randomBytes(32); // 256 bits
		const iv = await crypto.randomBytes(12); // 96 bits

		const key = await crypto.pbkdf2Raw(password, salt, iterationCount, 32, result.hash);
		const encrypted = crypto.encryptRaw(data, result.algo, key, iv, result.ts, null);

		result.salt = salt.toString('base64');
		result.iv = iv.toString('base64');
		result.ct = encrypted.toString('base64');

		return result;
	},

	decrypt: async (password: string, data: EncryptionResult) => {
		const salt = Buffer.from(data.salt, 'base64');
		const iv = Buffer.from(data.iv, 'base64');

		const key = await crypto.pbkdf2Raw(password, salt, data.iter, 32, data.hash);
		const decrypted = crypto.decryptRaw(Buffer.from(data.ct, 'base64'), data.algo, key, iv, data.ts, null);

		return decrypted;
	},

	encryptString: async (password: string, iterationCount: number, salt: CryptoBuffer | null, data: string, encoding: BufferEncoding) => {
		return crypto.encrypt(password, iterationCount, salt, Buffer.from(data, encoding));
	},
};

export default crypto;
