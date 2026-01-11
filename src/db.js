// Supabase DB adapter (PostgreSQL)
// Use SUPABASE_SERVICE_ROLE_KEY on the server (never expose it to the mobile app!).

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error(
    'Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY. Add them to backend_kos/.env'
  );
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
});

function assertOk(res, context = 'supabase') {
  if (res.error) {
    const msg = `${context}: ${res.error.message}`;
    const err = new Error(msg);
    err.cause = res.error;
    throw err;
  }
  return res.data;
}

module.exports = { supabase, assertOk };
