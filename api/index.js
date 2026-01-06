require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const multer = require('multer');
const sharp = require('sharp');
const xss = require('xss');
const { z } = require('zod');
const { createClient } = require('@supabase/supabase-js');
const { syncAllSessions, deleteSessionSheet } = require('./gsheet-sync');

const app = express();

app.set('trust proxy', 1);
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(compression());

app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    hidePoweredBy: true,
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https:"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    permittedCrossDomainPolicies: { permittedPolicies: 'none' }
}));

app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=()');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['https://sith-s25.my.id', 'https://siths25.vercel.app'];

const isOriginAllowed = (origin) => {
    const allowedPatterns = [
        /^https:\/\/.*\.sith-s25\.my\.id$/,
        /^https:\/\/sith-s25\.my\.id$/,
        /^https:\/\/.*\.vercel\.app$/
    ];
    if (!origin) return true;
    if (allowedOrigins.includes(origin)) return true;
    return allowedPatterns.some(pattern => pattern.test(origin));
};

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && isOriginAllowed(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Guest-ID');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});



const csrfCheck = (req, res, next) => {
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        const origin = req.get('origin');
        if (origin && !isOriginAllowed(origin)) {
            return res.status(403).json({ message: 'CSRF check failed (Origin mismatch)' });
        }
    }
    next();
};
app.use(csrfCheck);

const csrfHeaderCheck = (req, res, next) => {
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        const xRequestedWith = req.get('X-Requested-With');
        if (!xRequestedWith) {
            return res.status(403).json({ message: 'Missing security header' });
        }
    }
    next();
};
app.use(csrfHeaderCheck);

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
    console.error("ERROR: Supabase config missing");
    process.exit(1);
}

if (!process.env.MAIN_API_URL) {
    console.error("ERROR: MAIN_API_URL config missing");
    process.exit(1);
}

if (!process.env.JWT_SECRET) {
    console.error("ERROR: JWT_SECRET config missing - required for local token validation");
    process.exit(1);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY, {
    auth: { persistSession: false }
});

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    message: { message: "Terlalu banyak request." },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(globalLimiter);

app.use((req, res, next) => {
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('application/json')) {
        express.json({ limit: '1mb' })(req, res, next);
    } else if (contentType.includes('multipart/form-data')) {
        next();
    } else {
        express.urlencoded({ extended: true, limit: '1mb' })(req, res, next);
    }
});

const authenticateToken = (allowedRoles = []) => {
    return async (req, res, next) => {
        try {
            let token = req.signedCookies?.token;
            const rawCookies = req.headers.cookie || '';

            if (!token && !rawCookies) {
                return res.status(401).json({ message: 'Akses ditolak. silakan login.' });
            }

            if (process.env.JWT_SECRET && req.signedCookies && req.signedCookies.token) {
                try {
                    const jwt = require('jsonwebtoken');
                    const decoded = jwt.verify(req.signedCookies.token, process.env.JWT_SECRET);
                    req.user = decoded;

                    if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
                        return res.status(403).json({ message: 'Akses ditolak. Role tidak sesuai (Local).' });
                    }
                    return next();
                } catch (err) {
                    if (err.code !== 'MODULE_NOT_FOUND') {
                        return res.status(401).json({ message: 'Token tidak valid (Local verify failed).' });
                    }
                }
            }

            const upstreamHeaders = {
                'Cookie': rawCookies,
                'Content-Type': 'application/json',
                'User-Agent': req.get('User-Agent') || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', // Forward or Spoof UA
                'X-Forwarded-For': req.get('X-Forwarded-For') || req.ip, // Forward IP
                'X-Real-IP': req.get('X-Real-IP') || req.ip
            };

            const response = await fetch(`${process.env.MAIN_API_URL}/api/validate-token`, {
                method: 'GET',
                headers: upstreamHeaders
            });

            if (!response.ok) {
                const errorText = await response.text();

                if (response.status === 429 || errorText.includes("Security Checkpoint")) {
                    return res.status(429).json({ message: 'Gagal validasi: Terblokir oleh proteksi Vercel. Solusi: Tambahkan JWT_SECRET ke env variable.' });
                }

                return res.status(401).json({ message: `Token tidak valid (Upstream ${response.status})` });
            }

            const data = await response.json();
            if (!data.valid) {
                return res.status(401).json({ message: 'Token tidak valid (Invalid Data)' });
            }

            req.user = data.user;

            if (allowedRoles.length > 0 && !allowedRoles.includes(req.user.role)) {
                return res.status(403).json({ message: 'Akses ditolak. Role tidak sesuai.' });
            }

            next();
        } catch (err) {
            console.error('Token validation error:', err);
            return res.status(500).json({ message: `Gagal validasi token: ${err.message}` });
        }
    };
};

const requireEvenNIM = (req, res, next) => {
    const nim = req.user?.nim || req.body?.target_nim;
    if (!nim) {
        return res.status(400).json({ message: 'NIM tidak ditemukan.' });
    }

    const lastDigit = parseInt(nim.toString().slice(-1));
    if (lastDigit % 2 !== 0) {
        return res.status(403).json({ message: 'API ini hanya untuk NIM genap.' });
    }
    next();
};

const validate = (schema) => (req, res, next) => {
    try {
        schema.parse(req.body);
        next();
    } catch (e) {
        return res.status(400).json({ message: e.errors?.[0]?.message || 'Data tidak valid' });
    }
};

const sessionSchema = z.object({
    title: z.string().min(3).max(100),
    description: z.string().max(500).optional(),
    is_photo_required: z.boolean().optional().or(z.string())
});

const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];

const checkFileHeader = (buffer) => {
    const signatures = {
        jpeg: [0xFF, 0xD8, 0xFF],
        png: [0x89, 0x50, 0x4E, 0x47],
        webp: [0x52, 0x49, 0x46, 0x46]
    };
    for (const [, sig] of Object.entries(signatures)) {
        if (sig.every((byte, i) => buffer[i] === byte)) return true;
    }
    return false;
};

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Format tidak didukung'), false);
        }
    }
});

const handleUploadError = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File terlalu besar (max 5MB)' });
        }
        return res.status(400).json({ message: err.message });
    } else if (err) {
        return res.status(400).json({ message: err.message || 'Upload error' });
    }
    next();
};

const processUpload = async (buffer) => {
    return await sharp(buffer)
        .resize({ width: 800, fit: 'inside', withoutEnlargement: true })
        .jpeg({ quality: 70, progressive: true })
        .toBuffer();
};

const verifyFileContent = (req, res, next) => {
    const files = req.files ? Object.values(req.files).flat() : (req.file ? [req.file] : []);
    for (const file of files) {
        if (!checkFileHeader(file.buffer)) {
            return res.status(400).json({ message: 'File terdeteksi meragukan. Upload file asli.' });
        }
    }
    next();
};

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', type: 'genap' });
});

app.post('/api/attendance/sessions', authenticateToken(['admin', 'sekretaris', 'dev']), validate(sessionSchema), async (req, res) => {
    try {
        const { title, description, is_photo_required } = req.body;
        const cleanTitle = xss(title);
        const cleanDesc = description ? xss(description) : "";
        const photoReq = is_photo_required === true || is_photo_required === 'true';

        const { data, error } = await supabase.from('attendance_sessions')
            .insert([{
                title: cleanTitle,
                description: cleanDesc,
                is_photo_required: photoReq,
                created_by: req.user.nim,
                is_open: true
            }]).select();

        if (error) throw error;
        res.json({ message: 'Sesi dibuat', data });
    } catch (err) {
        console.error('Create session error:', err);
        res.status(500).json({ message: 'Gagal buat sesi' });
    }
});

app.get('/api/attendance/sessions', authenticateToken(), async (req, res) => {
    try {
        const { data, error } = await supabase.from('attendance_sessions').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.json({ data });
    } catch (err) {
        res.status(500).json({ message: 'Error server' });
    }
});

app.put('/api/attendance/close/:id', authenticateToken(['admin', 'sekretaris', 'dev']), async (req, res) => {
    try {
        const { error } = await supabase.from('attendance_sessions').update({ is_open: false }).eq('id', req.params.id);
        if (error) throw error;
        res.json({ message: 'Sesi ditutup' });
    } catch (err) {
        res.status(500).json({ message: 'Gagal menutup sesi' });
    }
});

app.delete('/api/attendance/sessions/:id', authenticateToken(['admin', 'sekretaris', 'dev']), async (req, res) => {
    try {
        const { data: session } = await supabase.from('attendance_sessions').select('title').eq('id', req.params.id).single();

        await supabase.from('attendance_records').delete().eq('session_id', req.params.id);

        const { error } = await supabase.from('attendance_sessions').delete().eq('id', req.params.id);
        if (error) throw error;

        if (session?.title) {
            deleteSessionSheet(session.title).catch(err => console.error('[GSheet] Delete tab error:', err));
        }

        res.json({ message: 'Sesi dihapus' });
    } catch (err) {
        console.error('Delete session error:', err);
        res.status(500).json({ message: 'Gagal menghapus sesi' });
    }
});

app.post('/api/gsheet/sync', authenticateToken(['admin', 'dev']), async (req, res) => {
    try {
        const result = await syncAllSessions(supabase, 'genap');
        res.json(result);
    } catch (err) {
        res.status(500).json({ message: 'Sync failed', error: err.message });
    }
});

app.get('/api/cron/sync-gsheet', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
        const isVercelCron = req.headers['x-vercel-cron'] === '1';
        if (!isVercelCron && process.env.CRON_SECRET) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
    }

    try {
        console.log('[Cron] GSheet sync triggered');
        const result = await syncAllSessions(supabase, 'genap');
        res.json({ success: true, ...result });
    } catch (err) {
        console.error('[Cron] Sync error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/attendance/submit', authenticateToken(), requireEvenNIM, upload.single('image'), handleUploadError, verifyFileContent, async (req, res) => {
    try {
        const { session_id, user_name_input, status, reason } = req.body;
        const user_nim = req.user.nim;
        const file = req.file;

        if (!session_id || !status) return res.status(400).json({ message: "Data tidak lengkap" });

        const { data: session, error: sErr } = await supabase.from('attendance_sessions').select('*').eq('id', session_id).single();
        if (sErr || !session) return res.status(404).json({ message: 'Sesi tak ditemukan' });
        if (!session.is_open) return res.status(400).json({ message: 'Sesi sudah ditutup' });

        const { data: existing } = await supabase.from('attendance_records')
            .select('id, status')
            .eq('session_id', session_id)
            .eq('user_nim', user_nim)
            .single();

        let isUpdate = false;
        if (existing) {
            if (existing.status === 'Izin' && status !== 'Izin') {
                isUpdate = true;
            } else {
                return res.status(400).json({ message: 'Sudah mengisi kehadiran/izin!' });
            }
        }

        if (status !== 'Izin' && session.is_photo_required && !file) {
            return res.status(400).json({ message: 'Wajib upload foto bukti kehadiran!' });
        }

        let photoUrl = null;
        if (file) {
            try {
                const processedBuffer = await sharp(file.buffer)
                    .resize({ width: 800, fit: 'inside', withoutEnlargement: true })
                    .jpeg({ quality: 65, progressive: true })
                    .toBuffer();

                const fileName = `att-${session_id}-${user_nim}-${Date.now()}.jpg`;
                const { error } = await supabase.storage.from('attendance-images').upload(fileName, processedBuffer, { contentType: 'image/jpeg' });
                if (error) throw error;

                photoUrl = fileName;
            } catch (err) {
                return res.status(500).json({ message: 'Gagal memproses gambar.' });
            }
        }

        let realName = req.user.name;

        if (!realName) {
            const { data: uData } = await supabase.from('users').select('name').eq('nim', user_nim).single();
            if (uData && uData.name) {
                realName = uData.name;
            } else if (user_name_input) {
                realName = xss(user_name_input);
            }
        }

        if (!realName) realName = user_nim;

        let finalStatus = 'Hadir';
        let finalReason = null;

        if (status === 'Izin') {
            finalStatus = 'Izin';
            finalReason = reason ? xss(reason) : 'Izin tanpa keterangan';
        } else if (session.is_photo_required) {
            finalStatus = 'Pending';
        }

        if (isUpdate) {
            const { error } = await supabase.from('attendance_records')
                .update({
                    status: finalStatus,
                    photo_url: photoUrl,
                    created_at: new Date().toISOString()
                })
                .eq('id', existing.id)
                .eq('status', 'Izin')
                .select();

            if (error) throw error;
        } else {
            const { error } = await supabase.from('attendance_records').insert([{
                session_id, user_nim, user_name: realName, photo_url: photoUrl, status: finalStatus, reason: finalReason
            }]);
            if (error) {
                if (error.code === '23505') {
                    return res.status(400).json({ message: 'Anda sudah absen sebelumnya.' });
                }
                throw error;
            }
        }

        let msg = 'Absen Berhasil';
        if (isUpdate) msg = 'Absen Menyusul Berhasil!';
        else if (finalStatus === 'Pending') msg = 'Terkirim (Menunggu Verifikasi)';
        else if (finalStatus === 'Izin') msg = 'Permohonan Izin Tercatat';

        res.json({ message: msg });

    } catch (err) {
        console.error("Submit Error:", err);
        res.status(500).json({ message: 'Gagal mengirim data.' });
    }
});

app.put('/api/attendance/approve/:record_id', authenticateToken(['admin', 'sekretaris', 'dev']), async (req, res) => {
    try {
        const { error } = await supabase.from('attendance_records').update({ status: 'Hadir' }).eq('id', req.params.record_id);
        if (error) throw error;
        res.json({ message: 'Diverifikasi' });
    } catch (err) {
        res.status(500).json({ message: 'Gagal verifikasi' });
    }
});

app.post('/api/attendance/manual', authenticateToken(['admin', 'sekretaris', 'dev']), async (req, res) => {
    try {
        const { session_id, target_nim, target_name, status } = req.body;

        const lastDigit = parseInt(target_nim.toString().slice(-1));
        if (lastDigit % 2 !== 0) {
            return res.status(403).json({ message: 'API ini hanya untuk NIM genap.' });
        }

        const cleanName = xss(target_name);

        const { error } = await supabase.from('attendance_records').insert([{
            session_id, user_nim: target_nim, user_name: cleanName, status: status || 'Hadir'
        }]);
        if (error && error.code === '23505') return res.status(400).json({ message: 'Sudah absen' });
        if (error) throw error;
        res.json({ message: 'Done' });
    } catch (err) {
        res.status(500).json({ message: 'Gagal input' });
    }
});

app.get('/api/attendance/stats/:session_id', authenticateToken(['admin', 'sekretaris', 'dev']), async (req, res) => {
    try {
        const { data, error } = await supabase.from('attendance_records').select('*').eq('session_id', req.params.session_id);
        if (error) throw error;

        const dataWithLinks = await Promise.all(data.map(async (record) => {
            if (record.photo_url && !record.photo_url.startsWith('http')) {
                const { data: signed } = await supabase
                    .storage
                    .from('attendance-images')
                    .createSignedUrl(record.photo_url, 3000);

                if (signed) {
                    return { ...record, photo_url: signed.signedUrl };
                }
            }
            return record;
        }));

        res.json({ data: dataWithLinks });
    } catch (err) {
        res.status(500).json({ message: 'Gagal ambil data' });
    }
});

app.get('/api/attendance/my-status/:session_id', authenticateToken(), async (req, res) => {
    try {
        const user_nim = req.user.nim;
        const { data, error } = await supabase
            .from('attendance_records')
            .select('status, reason, created_at')
            .eq('session_id', req.params.session_id)
            .eq('user_nim', user_nim)
            .single();

        if (error && error.code !== 'PGRST116') throw error;

        if (data) {
            res.json({ exists: true, status: data.status, reason: data.reason, created_at: data.created_at });
        } else {
            res.json({ exists: false });
        }
    } catch (err) {
        res.status(500).json({ message: 'Gagal ambil status' });
    }
});

app.use((err, req, res, next) => {
    console.error('Server Error:', err);
    res.status(500).json({ message: 'Internal server error' });
});

app.use((req, res) => {
    res.status(404).json({ message: 'Endpoint tidak ditemukan' });
});

const PORT = process.env.PORT || 5002;
app.listen(PORT, () => {
    console.log(`[GENAP] Server running on port ${PORT}`);
});

module.exports = app;
