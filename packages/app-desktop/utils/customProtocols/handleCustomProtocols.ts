import { net, protocol } from 'electron';
import { dirname, resolve, normalize } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { contentProtocolName } from './constants';
import resolvePathWithinDir from '@joplin/lib/utils/resolvePathWithinDir';
import { LoggerWrapper } from '@joplin/utils/Logger';
import * as fs from 'fs-extra';
import { createReadStream } from 'fs';
import { fromFilename } from '@joplin/lib/mime-utils';

export interface CustomProtocolHandler {
	allowReadAccessToDirectory(path: string): void;
	allowReadAccessToFile(path: string): { remove(): void };
}


// In some cases, the NodeJS built-in adapter (Readable.toWeb) closes its controller twice,
// leading to an error dialog. See:
// - https://github.com/nodejs/node/blob/e578c0b1e8d3dd817e692a0c5df1b97580bc7c7f/lib/internal/webstreams/adapters.js#L454
// - https://github.com/nodejs/node/issues/54205
// We work around this by creating a more-error-tolerant custom adapter.
const nodeStreamToWeb = (resultStream: fs.ReadStream) => {
	resultStream.pause();

	let closed = false;

	return new ReadableStream({
		start: (controller) => {
			resultStream.on('data', (chunk) => {
				if (closed) {
					return;
				}

				if (Buffer.isBuffer(chunk)) {
					controller.enqueue(new Uint8Array(chunk));
				} else {
					controller.enqueue(chunk);
				}

				if (controller.desiredSize <= 0) {
					resultStream.pause();
				}
			});

			resultStream.on('error', (error) => {
				controller.error(error);
			});

			resultStream.on('end', () => {
				if (!closed) {
					closed = true;
					controller.close();
				}
			});
		},
		pull: (_controller) => {
			if (closed) {
				return;
			}

			resultStream.resume();
		},
		cancel: () => {
			if (!closed) {
				closed = true;
				resultStream.close();
			}
		},
	}, { highWaterMark: resultStream.readableHighWaterMark });
};

// Allows seeking videos.
// See https://github.com/electron/electron/issues/38749 for why this is necessary.
const handleRangeRequest = async (request: Request, targetPath: string) => {
	const makeUnsupportedRangeResponse = () => {
		return new Response('unsupported range', {
			status: 416, // Range Not Satisfiable
		});
	};

	const rangeHeader = request.headers.get('Range');
	if (!rangeHeader.startsWith('bytes=')) {
		return makeUnsupportedRangeResponse();
	}

	const stat = await fs.stat(targetPath);
	// Ranges are requested using one of the following formats
	//  bytes=1234-5679
	//  bytes=-5678
	//  bytes=1234-
	// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
	const startByte = Number(rangeHeader.match(/(\d+)-/)?.[1] || '0');
	const endByte = Number(rangeHeader.match(/-(\d+)/)?.[1] || `${stat.size - 1}`);

	if (endByte > stat.size || startByte < 0) {
		return makeUnsupportedRangeResponse();
	}

	// Note: end is inclusive.
	const resultStream = createReadStream(targetPath, { start: startByte, end: endByte });

	// See the HTTP range requests guide: https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests
	const headers = new Headers([
		['Accept-Ranges', 'bytes'],
		['Content-Type', fromFilename(targetPath)],
		['Content-Length', `${endByte + 1 - startByte}`],
		['Content-Range', `bytes ${startByte}-${endByte}/${stat.size}`],
	]);


	return new Response(
		nodeStreamToWeb(resultStream),
		{ headers, status: 206 },
	);
};

// Creating a custom protocol allows us to isolate iframes by giving them
// different domain names from the main Joplin app.
//
// For example, an iframe with url joplin-content://note-viewer/path/to/iframe.html will run
// in a different process from a parent frame with url file://path/to/iframe.html.
//
// See note_viewer_isolation.md for why this is important.
//
// TODO: Use Logger.create (doesn't work for now because Logger is only initialized
// in the main process.)
const handleCustomProtocols = (logger: LoggerWrapper): CustomProtocolHandler => {
	const readableDirectories: string[] = [];
	const readableFiles = new Map<string, number>();

	// See also the protocol.handle example: https://www.electronjs.org/docs/latest/api/protocol#protocolhandlescheme-handler
	protocol.handle(contentProtocolName, async request => {
		const url = new URL(request.url);
		const host = url.host;

		let pathname = normalize(fileURLToPath(`file://${url.pathname}`));

		// See https://security.stackexchange.com/a/123723
		if (pathname.startsWith('..')) {
			throw new Error(`Invalid URL (not absolute), ${request.url}`);
		}

		pathname = resolve(appBundleDirectory, pathname);

		const allowedHosts = ['note-viewer'];

		let canRead = false;
		if (allowedHosts.includes(host)) {
			if (readableFiles.has(pathname)) {
				canRead = true;
			} else {
				for (const readableDirectory of readableDirectories) {
					if (resolvePathWithinDir(readableDirectory, pathname)) {
						canRead = true;
						break;
					}
				}
			}
		} else {
			throw new Error(`Invalid URL ${request.url}`);
		}

		if (!canRead) {
			throw new Error(`Read access not granted for URL ${request.url}`);
		}

		const asFileUrl = pathToFileURL(pathname).toString();
		logger.debug('protocol handler: Fetch file URL', asFileUrl);

		const rangeHeader = request.headers.get('Range');
		if (!rangeHeader) {
			const response = await net.fetch(asFileUrl);
			return response;
		} else {
			return handleRangeRequest(request, pathname);
		}
	});

	const appBundleDirectory = dirname(dirname(__dirname));
	return {
		allowReadAccessToDirectory: (path: string) => {
			path = resolve(appBundleDirectory, path);
			logger.debug('protocol handler: Allow read access to directory', path);

			readableDirectories.push(path);
		},
		allowReadAccessToFile: (path: string) => {
			path = resolve(appBundleDirectory, path);
			logger.debug('protocol handler: Allow read access to file', path);

			if (readableFiles.has(path)) {
				readableFiles.set(path, readableFiles.get(path) + 1);
			} else {
				readableFiles.set(path, 1);
			}

			return {
				remove: () => {
					if ((readableFiles.get(path) ?? 0) <= 1) {
						logger.debug('protocol handler: Remove read access to file', path);
						readableFiles.delete(path);
					} else {
						readableFiles.set(path, readableFiles.get(path) - 1);
					}
				},
			};
		},
	};
};

export default handleCustomProtocols;