import { Crypto, CryptoBuffer, EncryptionResult } from './types';
import { promisify } from 'util';
import { _ } from '../../locale';
import {
	getCiphers as nodeGetCiphers, getHashes as nodeGetHashes,
	randomBytes as nodeRandomBytes,
	pbkdf2 as nodePbkdf2,
	createCipheriv, createDecipheriv,
	CipherCCMOptions, CipherCCM, DecipherCCM, CipherGCMOptions, CipherGCM, DecipherGCM,
} from 'crypto';

const crypto: Crypto = {

	getCiphers: () => {
		return nodeGetCiphers();
	},

	getHashes: () => {
		return nodeGetHashes();
	},

	randomBytes: async (size: number) => {
		const randomBytesAsync = promisify(nodeRandomBytes);
		return randomBytesAsync(size);
	},

	pbkdf2Raw: async (password: string, salt: CryptoBuffer, iterations: number, keylen: number, digest: string) => {
		const digestMap: { [key: string]: string } = {
			'sha-1': 'sha1',
			'sha-224': 'sha224',
			'sha-256': 'sha256',
			'sha-384': 'sha384',
			'sha-512': 'sha512',
			'ripemd-160': 'ripemd160',
		};
		const digestAlgorithm: string = digestMap[digest.toLowerCase()] || digest;

		const pbkdf2Async = promisify(nodePbkdf2);
		return pbkdf2Async(password, salt, iterations, keylen, digestAlgorithm);
	},

	encryptRaw: (data: CryptoBuffer, algorithm: string, key: CryptoBuffer, iv: CryptoBuffer | null, authTagLength: number, associatedData: Buffer | null) => {

		algorithm = algorithm.toLowerCase();
		if (associatedData === null) {
			associatedData = Buffer.alloc(0);
		}

		let cipher = null;
		if (algorithm.includes('gcm')) {
			cipher = createCipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherGCMOptions) as CipherGCM;
			iv = iv || nodeRandomBytes(12);
		} else if (algorithm.includes('ccm')) {
			cipher = createCipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherCCMOptions) as CipherCCM;
			iv = iv || nodeRandomBytes(13);
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
			decipher = createDecipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherGCMOptions) as DecipherGCM;
		} else if (algorithm.includes('ccm')) {
			decipher = createDecipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherCCMOptions) as DecipherCCM;
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
