import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import 'dotenv/config';

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const UPLOAD_DIR = path.resolve(process.cwd(), process.env.UPLOAD_DIR || './local-uploads');
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 20 * 1024 * 1024);
const UPLOAD_TOKEN = process.env.UPLOAD_TOKEN || '';

const ALLOWED_EXTS = new Set([
    '.pdf',
    '.doc',
    '.docx',
    '.xls',
    '.xlsx',
    '.ppt',
    '.pptx',
    '.csv',
    '.txt',
    '.png',
    '.jpg',
    '.jpeg',
    '.webp'
]);

await fs.promises.mkdir(UPLOAD_DIR, { recursive: true });

const app = Fastify({
    logger: true
});

await app.register(multipart, {
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1,
        fields: 10
    }
});

function isValidToken(providedToken) {
    if (!UPLOAD_TOKEN || typeof providedToken !== 'string') {
        return false;
    }

    const expectedBuf = Buffer.from(UPLOAD_TOKEN, 'utf8');
    const actualBuf = Buffer.from(providedToken, 'utf8');

    if (expectedBuf.length !== actualBuf.length) {
        return false;
    }

    return crypto.timingSafeEqual(expectedBuf, actualBuf);
}

/**
 * Membersihkan path folder dinamis dari web agar aman dari path traversal.
 * Contoh input: "surat/2026/11" atau "/surat//2026/11/" -> "surat/2026/11"
 */
function sanitizeSubFolder(rawFolder) {
    if (!rawFolder || typeof rawFolder !== 'string') {
        return '';
    }

    const normalized = rawFolder.replaceAll('\\', '/').trim();
    const segments = normalized
        .split('/')
        .map((seg) => seg.trim())
        .filter((seg) => seg.length > 0 && seg !== '.' && seg !== '..')
        // Hanya izinkan huruf, angka, dash, dan underscore per segmen folder
        .map((seg) => seg.replace(/[^a-zA-Z0-9_-]/g, '_'))
        .filter((seg) => seg.length > 0);

    return segments.join('/');
}

/**
 * Membersihkan nama file asli agar aman dipakai di filesystem.
 */
function sanitizeFileName(rawName, ext) {
    const base = path.basename(rawName || 'document', ext);
    const cleanBase = base
        .replace(/[^a-zA-Z0-9._-]/g, '_')
        .replace(/^[._-]+|[._-]+$/g, '')
        .slice(0, 100);

    return `${cleanBase || 'document'}${ext}`;
}

app.get('/health', async () => {
    return { status: 'ok', uploadDir: UPLOAD_DIR };
});

app.post('/upload', async (req, reply) => {
    const token = req.headers['x-upload-token'];
    if (!isValidToken(token)) {
        return reply.code(401).send({
            ok: false,
            error: 'Unauthorized: token tidak valid'
        });
    }

    let filePart = null;
    let requestedFolder = '';

    // Iterasi multipart parts agar field non-file (seperti `folder`) terbaca walau dikirim sebelum/sesudah `file`
    for await (const part of req.parts()) {
        if (part.type === 'field') {
            if (part.fieldname === 'folder') {
                requestedFolder = String(part.value || '');
            }
        } else if (part.type === 'file') {
            if (part.fieldname === 'file' && !filePart) {
                filePart = part;
            } else {
                // Konsumsi file tambahan jika ada agar stream tidak menggantung
                part.file.resume();
            }
        }
    }

    if (!filePart) {
        return reply.code(400).send({
            ok: false,
            error: 'File wajib dikirim pada field multipart bernama "file"'
        });
    }

    const originalName = filePart.filename || '';
    const ext = path.extname(originalName).toLowerCase();

    if (!ALLOWED_EXTS.has(ext)) {
        filePart.file.resume();
        return reply.code(400).send({
            ok: false,
            error: `Ekstensi file '${ext || 'tidak diketahui'}' tidak diizinkan`
        });
    }

    const cleanSubFolder = sanitizeSubFolder(requestedFolder);
    const docId = crypto.randomUUID();
    const safeFileName = sanitizeFileName(originalName, ext);

    // Struktur akhir: <UPLOAD_DIR>/<cleanSubFolder>/<docId>/<safeFileName>
    const relativeDir = cleanSubFolder
        ? path.posix.join(cleanSubFolder, docId)
        : docId;

    const docDir = path.resolve(UPLOAD_DIR, ...relativeDir.split('/'));

    // Pastikan path hasil resolve benar-benar berada di dalam UPLOAD_DIR
    if (!docDir.startsWith(UPLOAD_DIR + path.sep)) {
        filePart.file.resume();
        return reply.code(400).send({
            ok: false,
            error: 'Path folder tidak valid'
        });
    }

    await fs.promises.mkdir(docDir, { recursive: true });

    const targetPath = path.join(docDir, safeFileName);
    const relativePath = path.posix.join(relativeDir, safeFileName);

    try {
        await pipeline(filePart.file, fs.createWriteStream(targetPath));

        if (filePart.file.truncated) {
            await fs.promises.rm(docDir, { recursive: true, force: true });
            return reply.code(413).send({
                ok: false,
                error: `Ukuran file melebihi batas maksimal (${MAX_FILE_SIZE} bytes)`
            });
        }

        const stat = await fs.promises.stat(targetPath);

        return reply.code(201).send({
            ok: true,
            docId,
            folder: cleanSubFolder,
            relativeDir,
            fileName: safeFileName,
            originalName,
            relativePath,
            size: stat.size,
            mimeType: filePart.mimetype
        });
    } catch (err) {
        await fs.promises.rm(docDir, { recursive: true, force: true });
        req.log.error(err);
        return reply.code(500).send({
            ok: false,
            error: 'Gagal menyimpan file'
        });
    }
});

try {
    await app.listen({ port: PORT, host: HOST });
} catch (err) {
    app.log.error(err);
    process.exit(1);
}