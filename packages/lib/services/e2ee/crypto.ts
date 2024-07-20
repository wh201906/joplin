import { Crypto, CryptoBuffer } from './types';
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

	getCiphers: (): string[] => {
		return nodeGetCiphers();
	},

	getHashes: (): string[] => {
		return nodeGetHashes();
	},

	randomBytes: async (size: number): Promise<Buffer> => {
		const randomBytesAsync = promisify(nodeRandomBytes);
		return randomBytesAsync(size);
	},

	pbkdf2Raw: async (password: string, salt: Buffer, iterations: number, keylen: number, digest: string): Promise<Buffer> => {
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

	encryptRaw: (data: Buffer, algorithm: string, key: Buffer, iv: CryptoBuffer | null, authTagLength: number, associatedData: Buffer | null): Buffer => {

		algorithm = algorithm.toLowerCase();
		if (iv === null) {
			iv = nodeRandomBytes(12);
		}
		if (associatedData === null) {
			associatedData = Buffer.alloc(0);
		}

		let cipher = null;
		if (algorithm.includes('gcm')) {
			cipher = createCipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherGCMOptions) as CipherGCM;
		} else if (algorithm.includes('ccm')) {
			cipher = createCipheriv(algorithm, key, iv, { authTagLength: authTagLength } as CipherCCMOptions) as CipherCCM;
		} else {
			throw new Error(_('Unknown cipher algorithm: %s', algorithm));
		}

		cipher.setAAD(associatedData, { plaintextLength: Buffer.byteLength(data) });

		const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
		const authTag = cipher.getAuthTag();

		return Buffer.concat([encryptedData, authTag]);
	},

	decryptRaw: (data: Buffer, algorithm: string, key: Buffer, iv: Buffer, authTagLength: number, associatedData: Buffer | null): Buffer => {

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
};

export default crypto;
