import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import 'dotenv/config';

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const UPLOAD_DIR = path.resolve(process.cwd(), process.env.UPLOAD_DIR || './local-uploads');
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 20 * 1024 * 1024);
const UPLOAD_TOKEN = process.env.UPLOAD_TOKEN || '';
const MAX_CONCURRENT_UPLOADS = Number(process.env.MAX_CONCURRENT_UPLOADS || 8);
const MIN_FREE_DISK_BYTES = Number(process.env.MIN_FREE_DISK_BYTES || 1024 * 1024 * 1024);
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 120_000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 30);
const RATE_LIMIT_WINDOW = process.env.RATE_LIMIT_WINDOW || '1 minute';

const ALLOWED_EXTS = new Set([
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.csv', '.txt', '.png', '.jpg', '.jpeg', '.webp'
]);

const MIME_BY_EXT = {
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.csv': 'text/csv; charset=utf-8',
    '.txt': 'text/plain; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp'
};

function assertConfiguration() {
    if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
        throw new Error('PORT harus berupa angka antara 1 sampai 65535');
    }
    if (Buffer.byteLength(UPLOAD_TOKEN, 'utf8') < 32) {
        throw new Error('UPLOAD_TOKEN wajib diisi dengan token acak minimal 32 byte');
    }
    if (!Number.isSafeInteger(MAX_FILE_SIZE) || MAX_FILE_SIZE < 1) {
        throw new Error('MAX_FILE_SIZE harus berupa bilangan positif');
    }
    if (!Number.isInteger(MAX_CONCURRENT_UPLOADS) || MAX_CONCURRENT_UPLOADS < 1) {
        throw new Error('MAX_CONCURRENT_UPLOADS harus berupa bilangan bulat minimal 1');
    }
    if (!Number.isSafeInteger(MIN_FREE_DISK_BYTES) || MIN_FREE_DISK_BYTES < 0) {
        throw new Error('MIN_FREE_DISK_BYTES tidak valid');
    }
}

assertConfiguration();
await fs.promises.mkdir(UPLOAD_DIR, { recursive: true, mode: 0o750 });

const app = Fastify({
    logger: {
        level: process.env.LOG_LEVEL || 'info',
        redact: ['req.headers.x-upload-token']
    },
    requestTimeout: REQUEST_TIMEOUT_MS,
    connectionTimeout: 10_000,
    bodyLimit: MAX_FILE_SIZE + 1024 * 1024
});

await app.register(rateLimit, {
    global: false,
    hook: 'preHandler'
});

await app.register(multipart, {
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1,
        fields: 10,
        parts: 11,
        fieldNameSize: 100,
        fieldSize: 1024
    }
});

function isValidToken(providedToken) {
    if (typeof providedToken !== 'string') return false;
    const expected = Buffer.from(UPLOAD_TOKEN, 'utf8');
    const actual = Buffer.from(providedToken, 'utf8');
    if (expected.length !== actual.length) return false;
    return crypto.timingSafeEqual(expected, actual);
}

function getRequestedFolder(req) {
    const queryFolder = req.query?.folder;
    const headerFolder = req.headers['x-upload-folder'];
    if (queryFolder !== undefined && headerFolder !== undefined) {
        throw new Error('Gunakan salah satu: query folder atau header X-Upload-Folder');
    }
    const value = queryFolder ?? headerFolder ?? '';
    if (Array.isArray(value) || typeof value !== 'string') {
        throw new Error('Folder harus berupa string');
    }
    if (value === '') return '';

    const segments = value.split('/');
    if (segments.length > 4) throw new Error('Folder maksimal memiliki 4 segmen');
    for (const segment of segments) {
        if (!/^[a-zA-Z0-9_-]{1,32}$/.test(segment)) {
            throw new Error('Setiap segmen folder hanya boleh berisi huruf, angka, underscore, dan dash (maksimal 32 karakter)');
        }
    }
    return segments.join('/');
}

function sanitizeFileName(rawName, ext) {
    const basename = path.posix.basename(String(rawName || 'document').replaceAll('\\', '/'));
    const hasExpectedSuffix = basename.toLowerCase().endsWith(ext);
    const withoutExt = hasExpectedSuffix ? basename.slice(0, -ext.length) : basename;
    const cleanBase = withoutExt
        .replace(/[^a-zA-Z0-9._-]/g, '_')
        .replace(/^[._-]+|[._-]+$/g, '')
        .slice(0, 100);
    return `${cleanBase || 'document'}${ext}`;
}

function hasPrefix(buffer, hex) {
    return buffer.length >= hex.length / 2 && buffer.subarray(0, hex.length / 2).equals(Buffer.from(hex, 'hex'));
}

function isPlausibleText(buffer, final = false) {
    if (buffer.includes(0x00)) return false;
    try {
        new TextDecoder('utf-8', { fatal: true }).decode(buffer, { stream: !final });
    } catch {
        return false;
    }
    for (const byte of buffer) {
        if (byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d && byte !== 0x0c) return false;
    }
    return true;
}

function validateFileSignature(ext, sample, final = false) {
    switch (ext) {
        case '.pdf': return sample.subarray(0, 5).toString('ascii') === '%PDF-';
        case '.png': return hasPrefix(sample, '89504e470d0a1a0a');
        case '.jpg':
        case '.jpeg': return hasPrefix(sample, 'ffd8ff');
        case '.webp': return sample.length >= 12 && sample.subarray(0, 4).toString('ascii') === 'RIFF' && sample.subarray(8, 12).toString('ascii') === 'WEBP';
        case '.doc':
        case '.xls':
        case '.ppt': return hasPrefix(sample, 'd0cf11e0a1b11ae1');
        case '.docx':
        case '.xlsx':
        case '.pptx': return hasPrefix(sample, '504b0304');
        case '.csv':
        case '.txt': return isPlausibleText(sample, final);
        default: return false;
    }
}

function createSignatureValidator(ext) {
    let pending = Buffer.alloc(0);
    let validated = false;
    const sampleSize = 4100;

    function validateAndPush(stream, final = false) {
        if (!validated && (pending.length >= sampleSize || final)) {
            if (!validateFileSignature(ext, pending.subarray(0, sampleSize), final)) {
                throw new Error('Konten file tidak sesuai dengan ekstensi yang dikirim');
            }
            validated = true;
            stream.push(pending);
            pending = Buffer.alloc(0);
        }
    }

    return new Transform({
        transform(chunk, encoding, callback) {
            try {
                if (validated) {
                    callback(null, chunk);
                    return;
                }
                pending = Buffer.concat([pending, chunk]);
                validateAndPush(this);
                callback();
            } catch (error) {
                callback(error);
            }
        },
        flush(callback) {
            try {
                if (!validated) validateAndPush(this, true);
                callback();
            } catch (error) {
                callback(error);
            }
        }
    });
}

async function assertDiskCapacity() {
    const stats = await fs.promises.statfs(UPLOAD_DIR);
    const availableBytes = Number(stats.bavail) * Number(stats.bsize);
    if (availableBytes < MIN_FREE_DISK_BYTES + MAX_FILE_SIZE) {
        const error = new Error('Ruang penyimpanan NAS tidak mencukupi untuk menerima upload baru');
        error.code = 'INSUFFICIENT_STORAGE';
        throw error;
    }
}

let activeUploads = 0;

app.get('/health', async () => ({ status: 'ok' }));

app.post('/upload', {
    config: {
        rateLimit: {
            max: RATE_LIMIT_MAX,
            timeWindow: RATE_LIMIT_WINDOW
        }
    }
}, async (req, reply) => {
    const token = req.headers['x-upload-token'];
    if (!isValidToken(token)) {
        req.log.warn({ ip: req.ip }, 'Upload ditolak: token tidak valid');
        return reply.code(401).send({ ok: false, error: 'Unauthorized' });
    }

    if (activeUploads >= MAX_CONCURRENT_UPLOADS) {
        return reply.code(503).send({ ok: false, error: 'Server sedang sibuk, silakan coba kembali' });
    }
    activeUploads += 1;

    let docDir = null;
    let completed = false;
    let uploadResult = null;
    let earlyError = null;

    try {
        const cleanSubFolder = getRequestedFolder(req);
        await assertDiskCapacity();

        for await (const part of req.parts()) {
            if (earlyError) {
                if (part.type === 'file') part.file.resume();
                continue;
            }

            if (part.type === 'field') {
                if (part.fieldname === 'folder') {
                    earlyError = { code: 400, error: 'Field multipart folder tidak didukung. Gunakan query ?folder=... atau header X-Upload-Folder.' };
                }
                continue;
            }

            if (part.type !== 'file') continue;
            if (part.fieldname !== 'file' || uploadResult) {
                part.file.resume();
                earlyError = { code: 400, error: 'Hanya satu file pada field multipart bernama "file" yang diperbolehkan' };
                continue;
            }

            const originalName = path.posix.basename(String(part.filename || 'document').replaceAll('\\', '/')).slice(0, 255);
            const ext = path.extname(originalName).toLowerCase();
            if (!ALLOWED_EXTS.has(ext)) {
                part.file.resume();
                earlyError = { code: 400, error: `Ekstensi file '${ext || 'tidak diketahui'}' tidak diizinkan` };
                continue;
            }

            const docId = crypto.randomUUID();
            const safeFileName = sanitizeFileName(originalName, ext);
            const relativeDir = cleanSubFolder ? path.posix.join(cleanSubFolder, docId) : docId;
            const normalizedRoot = path.resolve(UPLOAD_DIR);
            docDir = path.resolve(normalizedRoot, ...relativeDir.split('/'));
            if (!docDir.startsWith(normalizedRoot + path.sep)) {
                part.file.resume();
                earlyError = { code: 400, error: 'Path folder tidak valid' };
                continue;
            }

            await fs.promises.mkdir(docDir, { recursive: true, mode: 0o750 });
            const targetPath = path.join(docDir, safeFileName);
            const tempPath = path.join(docDir, `.${crypto.randomUUID()}.part`);
            const relativePath = path.posix.join(relativeDir, safeFileName);

            try {
                const validator = createSignatureValidator(ext);
                await pipeline(part.file, validator, fs.createWriteStream(tempPath, { flags: 'wx', mode: 0o640 }));

                if (part.file.truncated) {
                    earlyError = { code: 413, error: `Ukuran file melebihi batas maksimal (${MAX_FILE_SIZE} bytes)` };
                    await fs.promises.rm(tempPath, { force: true });
                    continue;
                }

                await fs.promises.rename(tempPath, targetPath);
                const stat = await fs.promises.stat(targetPath);
                uploadResult = {
                    docId,
                    folder: cleanSubFolder,
                    relativeDir,
                    fileName: safeFileName,
                    originalName,
                    relativePath,
                    size: stat.size,
                    mimeType: MIME_BY_EXT[ext]
                };
                completed = true;
                req.log.info({ docId, relativePath, size: stat.size, mimeType: MIME_BY_EXT[ext] }, 'Upload berhasil');
            } catch (error) {
                await fs.promises.rm(tempPath, { force: true }).catch(() => {});
                if (error.message?.includes('Konten file tidak sesuai')) {
                    earlyError = { code: 415, error: error.message };
                } else if (error.code === 'FST_REQ_FILE_TOO_LARGE' || part.file.truncated) {
                    earlyError = { code: 413, error: `Ukuran file melebihi batas maksimal (${MAX_FILE_SIZE} bytes)` };
                } else {
                    throw error;
                }
            }
        }

        if (earlyError) {
            if (docDir) await fs.promises.rm(docDir, { recursive: true, force: true });
            return reply.code(earlyError.code).send({ ok: false, error: earlyError.error });
        }
        if (!uploadResult) {
            return reply.code(400).send({ ok: false, error: 'File wajib dikirim pada field multipart bernama "file"' });
        }
        return reply.code(201).send({ ok: true, ...uploadResult });
    } catch (error) {
        if (docDir && !completed) await fs.promises.rm(docDir, { recursive: true, force: true }).catch(() => {});
        if (error.code === 'INSUFFICIENT_STORAGE') {
            req.log.warn({ err: error }, 'Upload ditolak: ruang penyimpanan tidak mencukupi');
            return reply.code(507).send({ ok: false, error: error.message });
        }
        if (error.message?.startsWith('Folder ') || error.message?.startsWith('Setiap segmen') || error.message?.startsWith('Gunakan salah satu')) {
            return reply.code(400).send({ ok: false, error: error.message });
        }
        req.log.error({ err: error }, 'Upload gagal');
        return reply.code(500).send({ ok: false, error: 'Gagal menyimpan file' });
    } finally {
        activeUploads -= 1;
    }
});

try {
    await app.listen({ port: PORT, host: HOST });
    app.log.info({ host: HOST, port: PORT, uploadDir: UPLOAD_DIR }, 'Uploader service berjalan');
} catch (error) {
    app.log.error({ err: error }, 'Gagal menjalankan uploader service');
    process.exit(1);
}
