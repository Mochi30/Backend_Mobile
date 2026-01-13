require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const { supabase } = require('./db');

const app = express();

function normalizeEnvValue(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

// Disable caching/ETag to avoid 304 responses for mobile clients
app.disable('etag');
app.set('etag', false);
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

const PORT = process.env.PORT || 4000;
const JWT_SECRET = normalizeEnvValue(process.env.JWT_SECRET) || 'dev_secret';
const MIDTRANS_SERVER_KEY = normalizeEnvValue(process.env.MIDTRANS_SERVER_KEY);
const MIDTRANS_CLIENT_KEY = normalizeEnvValue(process.env.MIDTRANS_CLIENT_KEY);
const MIDTRANS_IS_PRODUCTION = normalizeEnvValue(process.env.MIDTRANS_IS_PRODUCTION).toLowerCase() === 'true';
const MIDTRANS_SNAP_BASE_URL = MIDTRANS_IS_PRODUCTION ? 'https://app.midtrans.com' : 'https://app.sandbox.midtrans.com';
const MIDTRANS_CORE_BASE_URL = MIDTRANS_IS_PRODUCTION ? 'https://api.midtrans.com' : 'https://api.sandbox.midtrans.com';
const APP_DEEP_LINK = normalizeEnvValue(process.env.APP_DEEP_LINK) || 'apptwo://payment-callback';

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

app.get('/health', (req, res) => res.json({ ok: true }));

// Root endpoint for platform health checks
app.get('/', (req, res) => {
  res.json({ ok: true, service: 'backend_kos' });
});

// Extra request log to help debug when testing from a physical phone
app.use((req, res, next) => {
  console.log(`[REQ] ${req.method} ${req.originalUrl}`);
  next();
});

function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'Missing Authorization header' });
  const token = header.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Invalid Authorization header' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

function throwSb(error, context) {
  if (!error) return;
  const err = new Error(`${context}: ${error.message}`);
  err.cause = error;
  throw err;
}

async function sbMaybeSingle(builder, context) {
  const { data, error } = await builder.maybeSingle();
  throwSb(error, context);
  return data;
}

async function sbSelect(promise, context) {
  const { data, error } = await promise;
  throwSb(error, context);
  return data || [];
}

async function sbInsertSingle(builder, context) {
  const { data, error } = await builder.select().single();
  throwSb(error, context);
  return data;
}

async function addNotification(userId, title, message) {
  try {
    if (!userId) return;
    const { error } = await supabase.from('notifications').insert({
      user_id: userId,
      title: String(title || 'Notifikasi'),
      message: String(message || ''),
      is_read: false,
    });
    if (error) console.warn('addNotification failed', error.message);
  } catch (e) {
    console.warn('addNotification failed', e?.message || e);
  }
}

function isHttpUrl(value) {
  if (!value) return false;
  try {
    const url = new URL(String(value));
    return url.protocol == 'http:' || url.protocol == 'https:';
  } catch {
    return false;
  }
}

function isMidtransReady() {
  return typeof MIDTRANS_SERVER_KEY === 'string' && MIDTRANS_SERVER_KEY.trim().length > 0;
}

function midtransBaseForPath(path) {
  return path.startsWith('/snap') ? MIDTRANS_SNAP_BASE_URL : MIDTRANS_CORE_BASE_URL;
}

function midtransAuthHeader() {
  const token = Buffer.from(`${MIDTRANS_SERVER_KEY}:`).toString('base64');
  return `Basic ${token}`;
}

async function midtransRequest(path, options = {}) {
  if (!isMidtransReady()) {
    const err = new Error('Midtrans server key belum dikonfigurasi.');
    err.code = 'MIDTRANS_NOT_CONFIGURED';
    throw err;
  }

  const res = await fetch(`${midtransBaseForPath(path)}${path}`, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: midtransAuthHeader(),
      ...(options.headers || {}),
    },
    body: options.body,
  });

  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }

  if (!res.ok) {
    const msg = data?.status_message || data?.message || 'Midtrans request failed';
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }

  return data;
}

function normalizeMidtransStatus(transactionStatus, fraudStatus) {
  const status = String(transactionStatus || '').toLowerCase();
  const fraud = String(fraudStatus || '').toLowerCase();

  if (status === 'capture') {
    return fraud === 'challenge' ? 'PENDING' : 'SUCCESS';
  }
  if (status === 'settlement') return 'SUCCESS';
  if (status === 'pending') return 'PENDING';
  if (status === 'expire') return 'EXPIRED';
  if (status === 'cancel') return 'CANCELLED';
  if (status === 'deny') return 'FAILED';
  if (status === 'refund' || status === 'partial_refund') return 'REFUNDED';
  return status ? status.toUpperCase() : 'UNKNOWN';
}

function resolveBankTransfer(methodLabel) {
  const value = String(methodLabel || '').toLowerCase();
  if (value.includes('bca')) return 'bca';
  if (value.includes('mandiri')) return 'mandiri';
  if (value.includes('bni')) return 'bni';
  if (value.includes('bri')) return 'bri';
  return null;
}

function resolveEnabledPayments(methodLabel) {
  const value = String(methodLabel || '').toLowerCase();
  if (!value) return null;
  if (value.includes('gopay')) return ['gopay'];
  if (value.includes('ovo')) return ['ovo'];
  if (value.includes('dana')) return ['dana'];
  if (value.includes('kartu') || value.includes('debit') || value.includes('credit')) return ['credit_card'];
  if (value.includes('bca') || value.includes('mandiri') || value.includes('va')) return ['bank_transfer'];
  return null;
}

function generateReferenceId() {
  return `TRX-${Date.now()}-${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`;
}

function generateTokenRaw() {
  return Array.from({ length: 20 }, () => Math.floor(Math.random() * 10)).join('');
}

function formatToken(raw) {
  return String(raw || '').replace(/(.{4})/g, '$1 ').trim();
}

async function applyMidtransStatus(tx, nextStatus, opts = {}) {
  const currentStatus = String(tx.status || '').toUpperCase();
  const requestedStatus = String(nextStatus || '').toUpperCase();
  let finalStatus = currentStatus || requestedStatus || 'UNKNOWN';
  let tokenFormatted = tx.token_formatted ? String(tx.token_formatted) : null;

  if (currentStatus === 'REDEEMED') {
    return { status: 'REDEEMED', tokenFormatted };
  }

  const updates = {};

  if (currentStatus !== 'SUCCESS' && requestedStatus === 'SUCCESS') {
    finalStatus = 'SUCCESS';
    updates.status = 'SUCCESS';
  } else if (currentStatus !== 'SUCCESS' && requestedStatus && requestedStatus !== currentStatus) {
    finalStatus = requestedStatus;
    updates.status = requestedStatus;
  }

  if (finalStatus === 'SUCCESS') {
    if (!tx.token_raw || !tokenFormatted) {
      const tokenRaw = generateTokenRaw();
      tokenFormatted = formatToken(tokenRaw);
      updates.token_raw = tokenRaw;
      updates.token_formatted = tokenFormatted;
    }
  }

  if (opts.paymentType && (!tx.method || String(tx.method).trim().length === 0)) {
    updates.method = String(opts.paymentType).trim();
  }

  if (Object.keys(updates).length > 0) {
    const { error } = await supabase.from('token_transactions').update(updates).eq('id', tx.id);
    throwSb(error, 'payments.updateTx');
  }

  if (opts.userId && finalStatus === 'SUCCESS' && currentStatus !== 'SUCCESS') {
    await addNotification(
      opts.userId,
      'Pembelian token berhasil',
      `Transaksi ${tx.reference_id} berhasil. Token listrik siap digunakan.`
    );
  }

  return { status: finalStatus, tokenFormatted };
}

function verifyMidtransSignature(payload) {
  const orderId = String(payload?.order_id || '');
  const statusCode = String(payload?.status_code || '');
  const grossAmount = String(payload?.gross_amount || '');
  const signatureKey = String(payload?.signature_key || '');
  if (!orderId || !statusCode || !grossAmount || !signatureKey) return false;

  const raw = `${orderId}${statusCode}${grossAmount}${MIDTRANS_SERVER_KEY}`;
  const expected = crypto.createHash('sha512').update(raw).digest('hex');
  return expected === signatureKey;
}

// Prefer provided roomId (room_code), otherwise fall back to the first room owned by the user.
async function resolveRoomCodeForUser(userId, providedRoomId) {
  const roomCodeRaw = providedRoomId != null ? String(providedRoomId).trim() : '';
  if (roomCodeRaw) {
    const exists = await sbMaybeSingle(
      supabase.from('rooms').select('room_code').eq('user_id', userId).eq('room_code', roomCodeRaw).limit(1),
      'resolveRoomCodeForUser.exists'
    );
    if (exists) return roomCodeRaw;
  }

  const first = await sbMaybeSingle(
    supabase.from('rooms').select('room_code').eq('user_id', userId).order('id', { ascending: true }).limit(1),
    'resolveRoomCodeForUser.first'
  );
  return first?.room_code != null ? String(first.room_code).trim() : null;
}

// health
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// DEBUG: lihat semua user yang ada di DB
app.get('/api/debug/users', async (req, res) => {
  try {
    const users = await sbSelect(
      supabase.from('users').select('id, name, email').order('id', { ascending: true }).limit(200),
      'debug.users'
    );
    res.json(users);
  } catch (e) {
    console.error('debug users error', e);
    res.status(500).json({ message: 'debug error' });
  }
});

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, roomCode } = req.body;

    if (!name || !email || !password || !roomCode) {
      return res.status(400).json({ message: 'Nama, nomor kamar, email, dan password wajib diisi.' });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ message: 'Password minimal 6 karakter.' });
    }

    const emailNorm = String(email).trim().toLowerCase();

    const existing = await sbMaybeSingle(
      supabase.from('users').select('id').eq('email', emailNorm).limit(1),
      'auth.register.existing'
    );
    if (existing) return res.status(409).json({ message: 'Email sudah terdaftar.' });

    const hash = await bcrypt.hash(password, 10);
    const user = await sbInsertSingle(
      supabase.from('users').insert({
        name: String(name).trim(),
        email: emailNorm,
        password_hash: hash,
      }),
      'auth.register.insertUser'
    );

    // Buat 1 room sesuai input pengguna
    const meterId = String(Date.now()) + String(Math.floor(Math.random() * 1000)).padStart(3, '0');
    await sbInsertSingle(
      supabase.from('rooms').insert({
        kos_name: 'Kos Anda',
        room_code: String(roomCode).trim(),
        meter_id: meterId,
        user_id: user.id,
        token_kwh: 0,
        token_estimate_days: 0,
        daily_limit_kwh: 10,
        daily_used_kwh: 0,
      }),
      'auth.register.insertRoom'
    );

    const rooms = await sbSelect(
      supabase.from('rooms').select('*').eq('user_id', user.id).order('id', { ascending: true }),
      'auth.register.fetchRooms'
    );
    const token = createToken(user);

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, rooms },
    });
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GOOGLE LOGIN (MODE TESTING)
app.post('/api/auth/google-dev', async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email wajib diisi.' });

    const emailNorm = String(email).trim().toLowerCase();
    let user = await sbMaybeSingle(
      supabase.from('users').select('*').eq('email', emailNorm).limit(1),
      'auth.googleDev.findUser'
    );

    if (!user) {
      const hash = await bcrypt.hash('google_dev_password', 10);
      user = await sbInsertSingle(
        supabase.from('users').insert({
          name: String(name || 'Google User').trim(),
          email: emailNorm,
          password_hash: hash,
        }),
        'auth.googleDev.insertUser'
      );

      const meterId = String(Date.now()) + String(Math.floor(Math.random() * 1000)).padStart(3, '0');
      await sbInsertSingle(
        supabase.from('rooms').insert({
          kos_name: 'Kos Anda',
          room_code: '203',
          meter_id: meterId,
          user_id: user.id,
          token_kwh: 0,
          token_estimate_days: 0,
          daily_limit_kwh: 10,
          daily_used_kwh: 0,
        }),
        'auth.googleDev.insertRoom'
      );
    }

    const rooms = await sbSelect(
      supabase.from('rooms').select('*').eq('user_id', user.id).order('id', { ascending: true }),
      'auth.googleDev.fetchRooms'
    );
    const token = createToken(user);

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, rooms },
    });
  } catch (err) {
    console.error('google-dev error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// FORGOT PASSWORD (MODE TESTING)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email wajib diisi.' });

    const emailNorm = String(email).trim().toLowerCase();

    const user = await sbMaybeSingle(
      supabase.from('users').select('*').eq('email', emailNorm).limit(1),
      'auth.forgot.findUser'
    );
    if (!user) return res.status(404).json({ message: 'User tidak ditemukan.' });

    const resetToken = String(Math.floor(100000 + Math.random() * 900000)); // 6 digit
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await sbInsertSingle(
      supabase.from('password_resets').insert({
        email: emailNorm,
        token: resetToken,
        expires_at: expiresAt,
      }),
      'auth.forgot.insertReset'
    );

    // Untuk testing: token dikembalikan di response
    res.json({ resetToken, expiresAt });
  } catch (err) {
    console.error('forgot-password error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// RESET PASSWORD (MODE TESTING)
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, token, password } = req.body;
    if (!email || !token || !password) {
      return res.status(400).json({ message: 'Email, token, dan password wajib diisi.' });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ message: 'Password minimal 6 karakter.' });
    }

    const emailNorm = String(email).trim().toLowerCase();

    const row = await sbMaybeSingle(
      supabase
        .from('password_resets')
        .select('*')
        .eq('email', emailNorm)
        .eq('token', String(token))
        .order('id', { ascending: false })
        .limit(1),
      'auth.reset.findReset'
    );
    if (!row) return res.status(400).json({ message: 'Token reset tidak valid.' });

    const exp = new Date(row.expires_at).getTime();
    if (Number.isFinite(exp) && Date.now() > exp) {
      return res.status(400).json({ message: 'Token reset sudah kedaluwarsa.' });
    }

    const hash = await bcrypt.hash(password, 10);
    throwSb((await supabase.from('users').update({ password_hash: hash }).eq('email', emailNorm)).error, 'auth.reset.updateUser');
    throwSb((await supabase.from('password_resets').delete().eq('email', emailNorm)).error, 'auth.reset.deleteResets');

    res.json({ ok: true });
  } catch (err) {
    console.error('reset-password error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email dan password wajib diisi.' });
    }

    const emailNorm = String(email).trim().toLowerCase();

    const user = await sbMaybeSingle(
      supabase.from('users').select('*').eq('email', emailNorm).limit(1),
      'auth.login.findUser'
    );
    if (!user) return res.status(401).json({ message: 'Email atau password salah' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Email atau password salah' });

    const rooms = await sbSelect(
      supabase.from('rooms').select('*').eq('user_id', user.id).order('id', { ascending: true }),
      'auth.login.fetchRooms'
    );
    const token = createToken(user);

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, rooms },
    });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// contoh dashboard (dummy realtime)
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const roomCode = await resolveRoomCodeForUser(req.user.id, req.query.roomId);
    if (!roomCode) return res.status(404).json({ message: 'Belum ada kamar untuk user ini.' });

    let room = await sbMaybeSingle(
      supabase.from('rooms').select('*').eq('room_code', roomCode).eq('user_id', req.user.id).limit(1),
      'dashboard.findRoom'
    );
    if (!room) return res.status(404).json({ message: 'Room tidak ditemukan' });

    const user = await sbMaybeSingle(
      supabase.from('users').select('id, name, email, language, phone').eq('id', req.user.id).limit(1),
      'dashboard.findUser'
    );

    // Daily usage reset (indikator harian) berdasarkan tanggal
    const today = new Date().toISOString().slice(0, 10);
    const lastDate = room.daily_used_date ? String(room.daily_used_date).slice(0, 10) : null;
    if (lastDate !== today) {
      throwSb(
        (await supabase.from('rooms').update({ daily_used_kwh: 0, daily_used_date: today, daily_limit_notified_date: null }).eq('id', room.id)).error,
        'dashboard.dailyReset'
      );
      room.daily_used_kwh = 0;
      room.daily_used_date = today;
      room.daily_limit_notified_date = null;
    }

    // Dummy increment pemakaian agar UI bisa testing (di produksi, nilai ini seharusnya dari IoT/telemetry)
    const nextDailyUsed = Math.max(0, Number(room.daily_used_kwh || 0)) + 0.25;
    throwSb((await supabase.from('rooms').update({ daily_used_kwh: nextDailyUsed }).eq('id', room.id)).error, 'dashboard.updateDailyUsed');
    room.daily_used_kwh = nextDailyUsed;

    // Jika melebihi batas harian, buat notif 1x per hari
    const dailyLimit = Number(room.daily_limit_kwh || 10);
    const notifiedDate = room.daily_limit_notified_date ? String(room.daily_limit_notified_date).slice(0, 10) : null;
    if (dailyLimit > 0 && nextDailyUsed > dailyLimit && notifiedDate !== today) {
      await addNotification(
        req.user.id,
        'Batas indikator harian terlampaui',
        `Pemakaian hari ini ${nextDailyUsed.toFixed(2)} kWh melebihi batas ${dailyLimit} kWh. Pertimbangkan mengurangi pemakaian atau beli token.`
      );
      throwSb((await supabase.from('rooms').update({ daily_limit_notified_date: today }).eq('id', room.id)).error, 'dashboard.setNotifiedDate');
      room.daily_limit_notified_date = today;
    }

    const realtime = {
      watt: 633,
      volt: 221,
      ampere: 2.88,
      todayKwh: Number(nextDailyUsed.toFixed(2)),
      limitKwh: room.daily_limit_kwh,
      estCostPerHour: 1500,
    };

    const currentTokenKwh = Number(room.token_kwh || 0);
    const estDays = dailyLimit > 0 ? Math.max(0, Math.round(currentTokenKwh / dailyLimit)) : 0;
    if (Number(room.token_estimate_days || 0) !== estDays) {
      throwSb((await supabase.from('rooms').update({ token_estimate_days: estDays }).eq('id', room.id)).error, 'dashboard.updateEstimateDays');
      room.token_estimate_days = estDays;
    }

    const { count: unreadCount, error: unreadErr } = await supabase
      .from('notifications')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', req.user.id)
      .eq('is_read', false);
    throwSb(unreadErr, 'dashboard.unreadCount');

    res.json({
      roomId: room.room_code,
      kosName: room.kos_name,
      meterId: room.meter_id,
      userName: (user?.name || req.user.name),
      userEmail: (user?.email || req.user.email),
      language: (user?.language || 'id'),
      phone: (user?.phone || null),
      tokenKwh: room.token_kwh,
      tokenEstimateDays: room.token_estimate_days,
      realtime,
      unreadNotifications: unreadCount || 0,
    });
  } catch (err) {
    console.error('dashboard error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ===== USAGE (untuk chart) =====
app.get('/api/usage', authMiddleware, async (req, res) => {
  try {
    const roomCode = await resolveRoomCodeForUser(req.user.id, req.query.roomId);
    if (!roomCode) return res.status(404).json({ message: 'Belum ada kamar untuk user ini.' });
    const range = (req.query.range || 'daily').toString();

    const room = await sbMaybeSingle(
      supabase.from('rooms').select('*').eq('room_code', roomCode).eq('user_id', req.user.id).limit(1),
      'usage.findRoom'
    );
    if (!room) return res.status(404).json({ message: 'Room tidak ditemukan' });

    const pointsRows = await sbSelect(
      supabase.from('usage_points').select('id,label,value').eq('room_id', room.id).eq('range', range).order('id', { ascending: true }),
      'usage.fetchPoints'
    );

    // Jika belum ada data, generate dummy agar chart bisa ditesting
    if (pointsRows.length === 0) {
      const labels =
        range === 'monthly'
          ? ['W1', 'W2', 'W3', 'W4']
          : range === 'weekly'
          ? ['Sen', 'Sel', 'Rab', 'Kam', 'Jum', 'Sab', 'Min']
          : ['00', '04', '08', '12', '16', '20'];

      const rowsToInsert = labels.map((lb) => ({
        room_id: room.id,
        range,
        label: lb,
        value: Number((Math.random() * 1.2 + 0.1).toFixed(2)),
      }));
      throwSb((await supabase.from('usage_points').insert(rowsToInsert)).error, 'usage.seedPoints');
    }

    const rows = await sbSelect(
      supabase.from('usage_points').select('label,value').eq('room_id', room.id).eq('range', range).order('id', { ascending: true }),
      'usage.fetchPoints2'
    );

    res.set('Cache-Control', 'no-store');
    res.json({
      roomId: roomCode,
      range,
      labels: rows.map((r) => r.label),
      points: rows.map((r) => r.value),
    });
  } catch (err) {
    console.error('usage error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ===== PROFILE =====
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await sbMaybeSingle(
      supabase.from('users').select('id, name, email, language, phone, created_at').eq('id', req.user.id).limit(1),
      'profile.getUser'
    );
    if (!user) return res.status(404).json({ message: 'User tidak ditemukan' });

    const rooms = await sbSelect(
      supabase.from('rooms').select('*').eq('user_id', req.user.id).order('id', { ascending: true }),
      'profile.getRooms'
    );
    res.json({ user: { ...user, rooms } });
  } catch (err) {
    console.error('profile get error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { name, email, phone, password } = req.body || {};
    const current = await sbMaybeSingle(
      supabase.from('users').select('id, name, email').eq('id', req.user.id).limit(1),
      'profile.getCurrent'
    );
    if (!current) return res.status(404).json({ message: 'User tidak ditemukan' });

    const nextName = (name ?? current.name).toString().trim();
    const nextEmail = (email ?? current.email).toString().trim().toLowerCase();
    const nextPhone = phone != null ? String(phone).trim() : null;

    if (!nextName || !nextEmail) return res.status(400).json({ message: 'Nama dan email wajib diisi.' });

    if (nextEmail !== current.email) {
      const existing = await sbMaybeSingle(
        supabase.from('users').select('id').eq('email', nextEmail).neq('id', req.user.id).limit(1),
        'profile.checkEmail'
      );
      if (existing) return res.status(400).json({ message: 'Email sudah digunakan.' });
    }

    const update = { name: nextName, email: nextEmail, phone: nextPhone };
    if (password != null && String(password).trim().length > 0) {
      if (String(password).length < 6) return res.status(400).json({ message: 'Password minimal 6 karakter.' });
      update.password_hash = await bcrypt.hash(String(password), 10);
    }

    throwSb((await supabase.from('users').update(update).eq('id', req.user.id)).error, 'profile.updateUser');

    const user = await sbMaybeSingle(
      supabase.from('users').select('id, name, email, language, phone, created_at').eq('id', req.user.id).limit(1),
      'profile.fetchUser'
    );
    const rooms = await sbSelect(
      supabase.from('rooms').select('*').eq('user_id', req.user.id).order('id', { ascending: true }),
      'profile.fetchRooms'
    );

    res.json({ user: { ...user, rooms } });
  } catch (err) {
    console.error('profile put error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ===== SETTINGS =====
app.get('/api/settings', authMiddleware, async (req, res) => {
  try {
    const user = await sbMaybeSingle(
      supabase.from('users').select('language').eq('id', req.user.id).limit(1),
      'settings.get'
    );
    res.json({ language: user?.language || 'id' });
  } catch (err) {
    console.error('settings get error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/settings/language', authMiddleware, async (req, res) => {
  try {
    const { language } = req.body || {};
    const lang = String(language || '').trim().toLowerCase();
    if (!['id', 'en'].includes(lang)) return res.status(400).json({ message: 'Language harus id atau en.' });

    throwSb((await supabase.from('users').update({ language: lang }).eq('id', req.user.id)).error, 'settings.updateLanguage');
    res.json({ language: lang });
  } catch (err) {
    console.error('settings language error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/settings/daily-limit', authMiddleware, async (req, res) => {
  try {
    const { roomId, dailyLimitKwh } = req.body || {};
    const roomCode = await resolveRoomCodeForUser(req.user.id, roomId);
    if (!roomCode) return res.status(404).json({ message: 'Belum ada kamar untuk user ini.' });

    const limit = Number(dailyLimitKwh);
    if (!isFinite(limit) || limit <= 0) return res.status(400).json({ message: 'dailyLimitKwh harus angka > 0.' });

    const room = await sbMaybeSingle(
      supabase.from('rooms').select('*').eq('room_code', roomCode).eq('user_id', req.user.id).limit(1),
      'settings.dailyLimit.findRoom'
    );
    if (!room) return res.status(404).json({ message: 'Room tidak ditemukan' });

    const tokenKwh = Number(room.token_kwh || 0);
    const estDays = limit > 0 ? Math.max(0, Math.round(tokenKwh / limit)) : 0;

    throwSb((await supabase.from('rooms').update({ daily_limit_kwh: limit, token_estimate_days: estDays }).eq('id', room.id)).error, 'settings.dailyLimit.updateRoom');
    res.json({ roomId: roomCode, dailyLimitKwh: limit, tokenEstimateDays: estDays });
  } catch (err) {
    console.error('settings daily-limit error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ===== NOTIFICATIONS =====
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const notifs = await sbSelect(
      supabase.from('notifications').select('id, title, message, is_read, created_at').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50),
      'notifications.get'
    );
    res.json({ notifications: notifs });
  } catch (err) {
    console.error('notifications get error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/notifications/:id/read', authMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!isFinite(id)) return res.status(400).json({ message: 'Invalid id' });

    throwSb((await supabase.from('notifications').update({ is_read: true }).eq('id', id).eq('user_id', req.user.id)).error, 'notifications.read');
    res.json({ ok: true });
  } catch (err) {
    console.error('notifications read error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ===== TOKEN REDEEM =====
app.post('/api/token/redeem', authMiddleware, async (req, res) => {
  try {
    const { roomId, token } = req.body || {};
    const roomCode = await resolveRoomCodeForUser(req.user.id, roomId);
    if (!roomCode) return res.status(404).json({ message: 'Belum ada kamar untuk user ini.' });

    const tokenRaw = String(token || '').replace(/\s+/g, '');
    if (!/^\d{20}$/.test(tokenRaw)) return res.status(400).json({ message: 'Kode token harus 20 digit angka.' });

    const room = await sbMaybeSingle(
      supabase.from('rooms').select('*').eq('room_code', roomCode).eq('user_id', req.user.id).limit(1),
      'token.redeem.findRoom'
    );
    if (!room) return res.status(404).json({ message: 'Room tidak ditemukan' });

    const tx = await sbMaybeSingle(
      supabase.from('token_transactions').select('id, kwh, status, token_formatted, token_raw, reference_id, total_amount, admin_fee, amount, method, created_at, redeemed_at, applied_room_id')
        .eq('room_id', room.id).eq('token_raw', tokenRaw).limit(1),
      'token.redeem.findTx'
    );

    if (!tx) return res.status(404).json({ message: 'Token tidak ditemukan.' });
    if (String(tx.status).toUpperCase() === 'REDEEMED' || tx.redeemed_at) return res.status(400).json({ message: 'Token sudah digunakan.' });
    if (String(tx.status).toUpperCase() !== 'SUCCESS') return res.status(400).json({ message: 'Token belum berstatus berhasil.' });

    const addKwh = Number(tx.kwh || 0);
    const newTokenKwh = Number(room.token_kwh || 0) + addKwh;
    const dailyLimit = Number(room.daily_limit_kwh || 10);
    const estDays = dailyLimit > 0 ? Math.max(0, Math.round(newTokenKwh / dailyLimit)) : 0;

    throwSb((await supabase.from('rooms').update({ token_kwh: newTokenKwh, token_estimate_days: estDays }).eq('id', room.id)).error, 'token.redeem.updateRoom');
    throwSb((await supabase.from('token_transactions').update({ status: 'REDEEMED', redeemed_at: new Date().toISOString(), redeemed_by_user_id: req.user.id, applied_room_id: room.id }).eq('id', tx.id)).error, 'token.redeem.updateTx');

    await addNotification(req.user.id, 'Token berhasil digunakan', `Token ${tokenRaw} sudah ditambahkan. Saldo kWh sekarang ${newTokenKwh.toFixed(2)} kWh.`);

    res.json({ roomId: roomCode, tokenKwh: newTokenKwh, tokenEstimateDays: estDays, transaction: { ...tx, status: 'REDEEMED' } });
  } catch (err) {
    console.error('token redeem error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ===== PEMBELIAN TOKEN (Midtrans) =====
app.post('/api/payments/purchase', authMiddleware, async (req, res) => {
  let referenceId = '';
  try {
    const { roomId, amount, kwh, method } = req.body || {};
    const roomCode = await resolveRoomCodeForUser(req.user.id, roomId);
    if (!roomCode) return res.status(404).json({ message: 'Belum ada kamar untuk user ini.' });

    const amountNum = Number(amount);
    const kwhNum = Number(kwh);
    if (!isFinite(amountNum) || amountNum <= 0 || !isFinite(kwhNum) || kwhNum <= 0) {
      return res.status(400).json({ message: 'amount dan kwh harus angka > 0.' });
    }

    if (!isMidtransReady()) {
      return res.status(500).json({ message: 'Midtrans belum dikonfigurasi di server.' });
    }

    const room = await sbMaybeSingle(
      supabase.from('rooms').select('*').eq('room_code', roomCode).eq('user_id', req.user.id).limit(1),
      'purchase.findRoom'
    );
    if (!room) return res.status(404).json({ message: 'Room tidak ditemukan' });

    const adminFee = 2500;
    const totalAmount = amountNum + adminFee;

    const tokenRaw = generateTokenRaw();
    const tokenFormatted = formatToken(tokenRaw);
    referenceId = generateReferenceId();

    const methodLabel = String(method || 'Midtrans').trim();
    const finishUrl = isHttpUrl(APP_DEEP_LINK)
      ? `${APP_DEEP_LINK}?referenceId=${encodeURIComponent(referenceId)}`
      : null;

    await sbInsertSingle(
      supabase.from('token_transactions').insert({
        room_id: room.id,
        amount: amountNum,
        kwh: kwhNum,
        method: methodLabel,
        status: 'PENDING',
        token_raw: tokenRaw,
        token_formatted: tokenFormatted,
        reference_id: referenceId,
        admin_fee: adminFee,
        total_amount: totalAmount,
      }),
      'purchase.insertTx'
    );

    const snapPayload = {
      transaction_details: { order_id: referenceId, gross_amount: totalAmount },
      item_details: [
        { id: 'token', price: amountNum, quantity: 1, name: `Token ${kwhNum} kWh` },
        { id: 'admin_fee', price: adminFee, quantity: 1, name: 'Admin Fee' },
      ],
      customer_details: {
        first_name: String(req.user.name || '').trim() || undefined,
        email: String(req.user.email || '').trim() || undefined,
        phone: String(room?.phone || '').trim() || undefined,
      },
    };
    if (finishUrl) {
      snapPayload.callbacks = { finish: finishUrl };
      snapPayload.gopay = { enable_callback: true, callback_url: finishUrl };
    }

    const enabledPayments = resolveEnabledPayments(methodLabel);
    if (enabledPayments) snapPayload.enabled_payments = enabledPayments;

    const bankTransfer = resolveBankTransfer(methodLabel);
    if (bankTransfer) snapPayload.bank_transfer = { bank: bankTransfer };

    const snap = await midtransRequest('/snap/v1/transactions', {
      method: 'POST',
      body: JSON.stringify(snapPayload),
    });

    res.json({
      referenceId,
      paymentUrl: snap?.redirect_url,
      snapToken: snap?.token,
      adminFee,
      totalAmount,
      status: 'PENDING',
    });
  } catch (err) {
    console.error('purchase error', err);
    if (referenceId) {
      try {
        await supabase.from('token_transactions').update({ status: 'FAILED' }).eq('reference_id', referenceId);
      } catch {}
    }
    const msg = err?.message || 'Internal server error';
    res.status(500).json({ message: msg });
  }
});

// ===== CEK STATUS PEMBAYARAN (Midtrans) =====
app.get('/api/payments/status', authMiddleware, async (req, res) => {
  try {
    const referenceId = String(req.query.referenceId || '').trim();
    if (!referenceId) return res.status(400).json({ message: 'referenceId wajib diisi.' });

    if (!isMidtransReady()) {
      return res.status(500).json({ message: 'Midtrans belum dikonfigurasi di server.' });
    }

    const tx = await sbMaybeSingle(
      supabase.from('token_transactions').select('*').eq('reference_id', referenceId).limit(1),
      'payments.status.findTx'
    );
    if (!tx) return res.status(404).json({ message: 'Transaksi tidak ditemukan.' });

    const room = await sbMaybeSingle(
      supabase.from('rooms').select('id, user_id').eq('id', tx.room_id).limit(1),
      'payments.status.findRoom'
    );
    if (!room || room.user_id !== req.user.id) return res.status(403).json({ message: 'Akses ditolak.' });

    const currentStatus = String(tx.status || '').toUpperCase();
    if (currentStatus === 'SUCCESS' || currentStatus === 'REDEEMED') {
      const applied = await applyMidtransStatus(tx, currentStatus, { userId: room.user_id });
      const token = ['SUCCESS', 'REDEEMED'].includes(applied.status) ? applied.tokenFormatted : null;
      return res.json({
        referenceId,
        status: applied.status,
        token,
        adminFee: tx.admin_fee,
        totalAmount: tx.total_amount,
        amount: tx.amount,
        kwh: tx.kwh,
        method: tx.method,
      });
    }

    const statusData = await midtransRequest(`/v2/${encodeURIComponent(referenceId)}/status`, {
      method: 'GET',
    });

    const nextStatus = normalizeMidtransStatus(statusData.transaction_status, statusData.fraud_status);
    const applied = await applyMidtransStatus(tx, nextStatus, {
      userId: room.user_id,
      paymentType: statusData.payment_type,
    });
    const token = ['SUCCESS', 'REDEEMED'].includes(applied.status) ? applied.tokenFormatted : null;

    res.json({
      referenceId,
      status: applied.status,
      token,
      adminFee: tx.admin_fee,
      totalAmount: tx.total_amount,
      amount: tx.amount,
      kwh: tx.kwh,
      method: tx.method,
    });
  } catch (err) {
    console.error('payments status error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ===== MIDTRANS NOTIFICATION WEBHOOK =====
app.post('/api/payments/notification', async (req, res) => {
  try {
    if (!isMidtransReady()) return res.status(500).json({ received: false });

    if (!verifyMidtransSignature(req.body)) {
      return res.status(401).json({ received: false });
    }

    const orderId = String(req.body?.order_id || '').trim();
    if (!orderId) return res.status(400).json({ received: false });

    const tx = await sbMaybeSingle(
      supabase.from('token_transactions').select('*').eq('reference_id', orderId).limit(1),
      'payments.webhook.findTx'
    );
    if (!tx) return res.json({ received: true });

    const room = await sbMaybeSingle(
      supabase.from('rooms').select('id, user_id').eq('id', tx.room_id).limit(1),
      'payments.webhook.findRoom'
    );

    const nextStatus = normalizeMidtransStatus(req.body.transaction_status, req.body.fraud_status);
    await applyMidtransStatus(tx, nextStatus, {
      userId: room?.user_id,
      paymentType: req.body.payment_type,
    });

    res.json({ received: true });
  } catch (err) {
    console.error('payments webhook error', err);
    res.status(500).json({ received: false });
  }
});

// ===== RIWAYAT TRANSAKSI =====
app.get('/api/transactions', authMiddleware, async (req, res) => {
  try {
    const roomCode = await resolveRoomCodeForUser(req.user.id, req.query.roomId);
    if (!roomCode) return res.status(404).json({ message: 'Belum ada kamar untuk user ini.' });

    const limit = Math.min(Number(req.query.limit || 20), 50);

    const room = await sbMaybeSingle(
      supabase.from('rooms').select('*').eq('room_code', roomCode).eq('user_id', req.user.id).limit(1),
      'transactions.findRoom'
    );
    if (!room) return res.status(404).json({ message: 'Room tidak ditemukan' });

    const txs = await sbSelect(
      supabase.from('token_transactions').select('id, reference_id, method, amount, admin_fee, total_amount, kwh, status, token_formatted, created_at, redeemed_at, applied_room_id').eq('room_id', room.id).order('created_at', { ascending: false }).limit(limit),
      'transactions.list'
    );

    const safeTxs = txs.map((tx) => {
      const status = String(tx.status || '').toUpperCase();
      return {
        ...tx,
        token: status === 'SUCCESS' || status === 'REDEEMED' ? tx.token_formatted : null,
      };
    });

    res.json({ roomId: roomCode, transactions: safeTxs });
  } catch (err) {
    console.error('transactions error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server berjalan di http://localhost:${PORT} (LAN: http://<IP_KOMPUTER>:${PORT})`);
  });
}

module.exports = app;
