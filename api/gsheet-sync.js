const { google } = require('googleapis');

const getAuth = () => {
    if (!process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || !process.env.GOOGLE_PRIVATE_KEY) {
        console.warn('[GSheet] Google credentials not configured');
        return null;
    }

    try {
        const auth = new google.auth.GoogleAuth({
            credentials: {
                client_email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
                private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
            },
            scopes: ['https://www.googleapis.com/auth/spreadsheets'],
        });
        return auth;
    } catch (error) {
        console.error('[GSheet] Failed to initialize auth:', error.message);
        return null;
    }
};

const SPREADSHEET_ID = process.env.GOOGLE_SHEETS_ID || '146MsEriqhrN2s-FzmgS9HAXZ2K5zWYYxuVLi-dcC4W8';

const sanitizeSheetName = (name) => {

    return name
        .replace(/[*?:\/\\\[\]]/g, '-')
        .substring(0, 100);
};

const getExistingSheets = async (sheets) => {
    try {
        const response = await sheets.spreadsheets.get({
            spreadsheetId: SPREADSHEET_ID,
        });
        return response.data.sheets.map(s => ({
            title: s.properties.title,
            sheetId: s.properties.sheetId
        }));
    } catch (error) {
        console.error('[GSheet] Failed to get sheets:', error.message);
        return [];
    }
};

const createSheetTab = async (sheets, title) => {
    const sanitizedTitle = sanitizeSheetName(title);

    try {
        const existing = await getExistingSheets(sheets);
        if (existing.some(s => s.title === sanitizedTitle)) {
            return { success: true, existed: true };
        }

        await sheets.spreadsheets.batchUpdate({
            spreadsheetId: SPREADSHEET_ID,
            resource: {
                requests: [{
                    addSheet: {
                        properties: { title: sanitizedTitle }
                    }
                }]
            }
        });

        return { success: true, existed: false };
    } catch (error) {
        console.error('[GSheet] Failed to create sheet:', error.message);
        return { success: false, error: error.message };
    }
};

const deleteSheetTab = async (sheets, title) => {
    const sanitizedTitle = sanitizeSheetName(title);

    try {
        const existing = await getExistingSheets(sheets);
        const sheet = existing.find(s => s.title === sanitizedTitle);

        if (!sheet) {
            return { success: true, message: 'Sheet not found (already deleted)' };
        }

        await sheets.spreadsheets.batchUpdate({
            spreadsheetId: SPREADSHEET_ID,
            resource: {
                requests: [{
                    deleteSheet: {
                        sheetId: sheet.sheetId
                    }
                }]
            }
        });

        return { success: true };
    } catch (error) {
        console.error('[GSheet] Failed to delete sheet:', error.message);
        return { success: false, error: error.message };
    }
};

const syncSessionToSheet = async (sessionTitle, records, allUsers = []) => {
    const auth = getAuth();
    if (!auth) {
        return { success: false, error: 'Google credentials not configured' };
    }

    try {
        const sheets = google.sheets({ version: 'v4', auth });
        const sanitizedTitle = sanitizeSheetName(sessionTitle);

        await createSheetTab(sheets, sanitizedTitle);

        const headers = [['No', 'NIM', 'Nama', 'Status', 'Alasan', 'Waktu Input', 'Link Foto']];

        const recordsByNim = {};
        records.forEach(r => {
            recordsByNim[r.user_nim] = r;
        });

        const allData = [];
        const recordedNims = new Set(records.map(r => r.user_nim));

        records.forEach(r => {
            allData.push({
                nim: r.user_nim,
                name: r.user_name,
                status: r.status,
                reason: r.reason || '-',
                createdAt: r.created_at ? new Date(r.created_at).toLocaleString('id-ID') : '-',
                photoUrl: r.photo_url || '-'
            });
        });

        allUsers.forEach(u => {
            if (!recordedNims.has(u.nim)) {
                allData.push({
                    nim: u.nim,
                    name: u.name,
                    status: 'Belum Absen',
                    reason: '-',
                    createdAt: '-',
                    photoUrl: '-'
                });
            }
        });

        allData.sort((a, b) => a.nim.toString().localeCompare(b.nim.toString(), undefined, { numeric: true }));

        const rows = allData.map((item, index) => [
            index + 1,
            item.nim,
            item.name,
            item.status,
            item.reason,
            item.createdAt,
            item.photoUrl
        ]);

        const values = [...headers, ...rows];

        await sheets.spreadsheets.values.clear({
            spreadsheetId: SPREADSHEET_ID,
            range: `'${sanitizedTitle}'!A:G`,
        });

        await sheets.spreadsheets.values.update({
            spreadsheetId: SPREADSHEET_ID,
            range: `'${sanitizedTitle}'!A1`,
            valueInputOption: 'RAW',
            resource: { values },
        });

        return { success: true, rowCount: rows.length };
    } catch (error) {
        console.error('[GSheet] Sync error:', error.message);
        return { success: false, error: error.message };
    }
};

const deleteSessionSheet = async (sessionTitle) => {
    const auth = getAuth();
    if (!auth) {
        return { success: false, error: 'Google credentials not configured' };
    }

    try {
        const sheets = google.sheets({ version: 'v4', auth });
        return await deleteSheetTab(sheets, sessionTitle);
    } catch (error) {
        console.error('[GSheet] Delete error:', error.message);
        return { success: false, error: error.message };
    }
};

const syncAllSessions = async (supabase, nimType = 'genap') => {
    const auth = getAuth();
    if (!auth) {
        console.log('[GSheet] Skipping sync - credentials not configured');
        return { success: false, error: 'Not configured' };
    }

    try {
        const { data: sessions, error: sessErr } = await supabase
            .from('attendance_sessions')
            .select('*')
            .order('created_at', { ascending: false });

        if (sessErr) throw sessErr;

        const { data: users } = await supabase
            .from('users')
            .select('nim, name');

        const filteredUsers = (users || []).filter(u => {
            const lastDigit = parseInt(u.nim.toString().slice(-1));
            return nimType === 'ganjil' ? lastDigit % 2 !== 0 : lastDigit % 2 === 0;
        });

        const results = [];
        for (const session of sessions) {
            const { data: records } = await supabase
                .from('attendance_records')
                .select('*')
                .eq('session_id', session.id);

            const filteredRecords = (records || []).filter(r => {
                const lastDigit = parseInt(r.user_nim.toString().slice(-1));
                return nimType === 'ganjil' ? lastDigit % 2 !== 0 : lastDigit % 2 === 0;
            });

            const result = await syncSessionToSheet(
                `${session.title} (${nimType.toUpperCase()})`,
                filteredRecords,
                filteredUsers
            );

            results.push({
                session: session.title,
                ...result
            });
        }

        console.log(`[GSheet] Sync complete for ${nimType}: ${results.length} sessions`);
        return { success: true, results };
    } catch (error) {
        console.error('[GSheet] Sync all error:', error.message);
        return { success: false, error: error.message };
    }
};

module.exports = {
    syncSessionToSheet,
    deleteSessionSheet,
    syncAllSessions,
    getExistingSheets,
    getAuth
};
