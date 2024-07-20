import { _ } from '@joplin/lib/locale';
import { Crypto, CryptoBuffer } from '@joplin/lib/services/e2ee/types';
import QuickCrypto from 'react-native-quick-crypto';
import { HashAlgorithm } from 'react-native-quick-crypto/lib/typescript/keys';
import type { CipherCCMOptions, CipherCCM, DecipherCCM, CipherGCMOptions, CipherGCM, DecipherGCM } from 'crypto';

const crypto: Crypto = {

	getCiphers: (): string[] => {
		return QuickCrypto.getCiphers();
	},

	getHashes: (): string[] => {
		return QuickCrypto.getHashes();
	},

	randomBytes: async (size: number): Promise<CryptoBuffer> => {
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

	pbkdf2Raw: async (password: string, salt: Buffer, iterations: number, keylen: number, digest: string): Promise<CryptoBuffer> => {
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

	encryptRaw: (data: Buffer, algorithm: string, key: Buffer, iv: CryptoBuffer | null, authTagLength: number, associatedData: Buffer | null): Buffer => {

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

	decryptRaw: (data: Buffer, algorithm: string, key: Buffer, iv: Buffer, authTagLength: number, associatedData: Buffer | null): Buffer => {

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
};

export default crypto;
