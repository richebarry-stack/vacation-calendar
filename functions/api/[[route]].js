// Cloudflare Pages Function — RBAC proxy for the vacation-home booking calendar.
// Static assets (index.html) are served by Pages; all /api/* requests land here.
//
// Required env/secrets (set via Cloudflare dashboard):
//   CODA_TOKEN   — Coda API token
//   CODA_DOC_ID  — Coda document ID
//   JWT_SECRET   — random string for signing session JWTs

// ════════════════════════════════════════════
// BASE64-URL
// ════════════════════════════════════════════
function toB64(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

// ════════════════════════════════════════════
// JWT  (HS256 via Web Crypto)
// ════════════════════════════════════════════
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'],
  );
}
async function jwtSign(payload, secret) {
  const enc = new TextEncoder();
  const h = toB64(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const p = toB64(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(`${h}.${p}`));
  return `${h}.${p}.${toB64(sig)}`;
}
async function jwtVerify(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const valid = await crypto.subtle.verify(
    'HMAC', await hmacKey(secret), fromB64(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!valid) return null;
  const payload = JSON.parse(new TextDecoder().decode(fromB64(p)));
  if (payload.exp && Date.now() / 1000 > payload.exp) return null;
  return payload;
}

// ════════════════════════════════════════════
// PASSWORD  (PBKDF2-SHA256, 100 000 iterations)
// ════════════════════════════════════════════
const PW_ITER = 100_000;
async function hashPw(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PW_ITER, hash: 'SHA-256' }, km, 256);
  return `pbkdf2:${PW_ITER}:${toB64(salt)}:${toB64(bits)}`;
}
async function checkPw(password, stored) {
  if (!stored) return !password;
  if (!stored.startsWith('pbkdf2:')) return password === stored;
  const [, iterStr, saltB64, wantB64] = stored.split(':');
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromB64(saltB64), iterations: parseInt(iterStr), hash: 'SHA-256' }, km, 256,
  );
  return toB64(bits) === wantB64;
}

// ════════════════════════════════════════════
// CODA helpers
// ════════════════════════════════════════════
const CODA = 'https://coda.io/apis/v1';

async function codaFetch(env, method, path, body) {
  return fetch(`${CODA}/docs/${env.CODA_DOC_ID}${path}`, {
    method,
    headers: { Authorization: `Bearer ${env.CODA_TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

let _tbl = null, _tblAt = 0;
async function tblMap(env) {
  if (_tbl && Date.now() - _tblAt < 300_000) return _tbl;
  const r = await codaFetch(env, 'GET', '/tables');
  if (!r.ok) throw new Error('Failed to list tables');
  const d = await r.json();
  _tbl = {};
  for (const t of d.items) { _tbl[t.id] = t.name; _tbl[t.name] = t.id; }
  _tblAt = Date.now();
  return _tbl;
}

async function allUsers(env) {
  const m = await tblMap(env);
  const r = await codaFetch(env, 'GET', `/tables/${m.Users}/rows?useColumnNames=true&limit=500`);
  if (!r.ok) throw new Error('Failed to load users');
  return (await r.json()).items;
}

// ════════════════════════════════════════════
// COOKIES / SESSION
// ════════════════════════════════════════════
function getCookie(req, name) {
  const m = (req.headers.get('Cookie') || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return m ? m[1] : null;
}
function makeCookie(token, req, maxAge = 2592000) {
  const sec = new URL(req.url).protocol === 'https:';
  return `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${sec ? '; Secure' : ''}`;
}
async function getSession(req, env) {
  const t = getCookie(req, 'session');
  return t ? jwtVerify(t, env.JWT_SECRET) : null;
}

// ════════════════════════════════════════════
// JSON response helper
// ════════════════════════════════════════════
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra },
  });
}

// ════════════════════════════════════════════
// LOGIN / LOGOUT
// ════════════════════════════════════════════
async function handleLogin(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ error: 'Invalid request body.' }, 400); }
  const { name, password } = body;
  if (!name) return json({ error: 'Name is required.' }, 400);

  const rows = await allUsers(env);
  const users = rows.map(r => ({ _id: r.id, ...r.values }));
  const key = name.trim().toLowerCase();
  const matches = users.filter(u => u.Name && u.Name.trim().toLowerCase() === key);

  if (!matches.length) {
    const owners = users
      .filter(u => (u.Role || '').toLowerCase().trim() === 'owner')
      .map(u => u.Name.trim());
    const who = owners.length === 1 ? `the owner (${owners[0]})`
      : owners.length ? `an owner (${owners.join(' or ')})`
      : 'an owner';
    return json({ error: `Name not recognized. Ask ${who} to add you.` }, 401);
  }
  if (matches.length > 1) {
    return json({ error: `Multiple accounts named "${name}". Ask the owner to fix the duplicate.` }, 401);
  }

  const user = matches[0];
  const stored = (user.Password || '').trim();
  if (stored && !(await checkPw(password || '', stored))) {
    return json({ error: 'Incorrect password.' }, 401);
  }

  const role = (user.Role || 'other_family').toLowerCase().trim();
  const jwt = await jwtSign({
    sub: user.Name.trim(), role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600,
  }, env.JWT_SECRET);

  return json(
    { name: user.Name.trim(), role },
    200,
    { 'Set-Cookie': makeCookie(jwt, req) },
  );
}

function handleLogout(req) {
  return json({ ok: true }, 200, { 'Set-Cookie': makeCookie('', req, 0) });
}

// ════════════════════════════════════════════
// CHANGE PASSWORD  (any authenticated user)
// ════════════════════════════════════════════
async function handleChangePassword(req, env, session) {
  let body;
  try { body = await req.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
  const { currentPassword, newPassword } = body;
  if (!newPassword) return json({ error: 'New password is required.' }, 400);

  const rows = await allUsers(env);
  const user = rows.find(r => r.values.Name && r.values.Name.trim().toLowerCase() === session.sub.toLowerCase());
  if (!user) return json({ error: 'Account not found.' }, 404);

  const stored = (user.values.Password || '').trim();
  if (stored && !(await checkPw(currentPassword || '', stored))) {
    return json({ error: 'Current password is incorrect.' }, 403);
  }

  const hashed = await hashPw(newPassword);
  const m = await tblMap(env);
  const up = await codaFetch(env, 'PUT', `/tables/${m.Users}/rows/${user.id}`, {
    row: { cells: [{ column: 'Password', value: hashed }] },
  });
  if (!up.ok) return json({ error: 'Failed to update password.' }, 500);

  return json({ ok: true });
}

// ════════════════════════════════════════════
// RBAC — authorize write operations
// ════════════════════════════════════════════
async function denyWrite(env, session, table, method, body) {
  const role = session.role;
  if (role === 'guest') return 'Guests are view-only.';
  if (role === 'owner') return null;

  if (table === 'Config') return 'Only owners can modify configuration.';
  if (table === 'Users') return 'Only owners can manage user accounts.';

  if (table === 'Reservations') {
    if (method === 'POST' && body && body.rows) {
      for (const row of body.rows) {
        const oc = (row.cells || []).find(c => c.column === 'Owner');
        if (oc && oc.value !== session.sub) return 'You can only create reservations for yourself.';
      }
    }
    if (method === 'DELETE' && body && body.rowIds && body.rowIds.length) {
      const m = await tblMap(env);
      const r = await codaFetch(env, 'GET', `/tables/${m.Reservations}/rows?useColumnNames=true&limit=500`);
      if (!r.ok) return 'Failed to verify ownership.';
      const owners = {};
      for (const row of (await r.json()).items) owners[row.id] = row.values.Owner;
      for (const id of body.rowIds) {
        if (owners[id] && owners[id] !== session.sub) return 'You can only delete your own reservations.';
      }
    }
    if (method === 'PUT' && body && body.row) {
      const oc = (body.row.cells || []).find(c => c.column === 'Owner');
      if (oc && oc.value !== session.sub) return 'You can only modify your own reservations.';
    }
    return null;
  }

  if (table === 'QuarterState') return null;

  return 'Unknown table.';
}

// ════════════════════════════════════════════
// PROXY — forward requests to Coda API
// ════════════════════════════════════════════
async function hashPasswordCells(body, method) {
  if (method === 'POST' && body && body.rows) {
    for (const row of body.rows) {
      for (const c of (row.cells || [])) {
        if (c.column === 'Password' && c.value) c.value = await hashPw(c.value);
      }
    }
  }
  if (method === 'PUT' && body && body.row) {
    for (const c of (body.row.cells || [])) {
      if (c.column === 'Password' && c.value) c.value = await hashPw(c.value);
    }
  }
}

function stripPasswords(data) {
  if (!data || !data.items) return;
  for (const row of data.items) {
    if (row.values && 'Password' in row.values) delete row.values.Password;
  }
}

async function handleProxy(req, env, session, segments) {
  const method = req.method;
  const query = new URL(req.url).search || '';
  const codaPath = '/' + segments.join('/');

  if (['POST', 'PUT', 'DELETE'].includes(method)) {
    let body = null;
    try { body = await req.json(); } catch {}

    let tableName = null;
    if (segments[0] === 'tables' && segments[1]) {
      const m = await tblMap(env);
      tableName = m[segments[1]] || null;
    }

    if (tableName) {
      const reason = await denyWrite(env, session, tableName, method, body);
      if (reason) return json({ error: reason }, 403);
      if (tableName === 'Users') await hashPasswordCells(body, method);
    }

    const res = await codaFetch(env, method, codaPath + query, body);
    if (method === 'DELETE') return new Response(null, { status: res.status });
    const data = await res.json().catch(() => ({}));
    return json(data, res.status);
  }

  // GET — forward and optionally strip sensitive fields
  const res = await codaFetch(env, 'GET', codaPath + query);
  if (!res.ok) return new Response(await res.text(), { status: res.status, headers: { 'Content-Type': 'application/json' } });
  const data = await res.json();

  if (segments[0] === 'tables' && segments[1] && segments[2] === 'rows') {
    const m = await tblMap(env);
    if (m[segments[1]] === 'Users') stripPasswords(data);
  }

  return json(data);
}

// ════════════════════════════════════════════
// ENTRY POINT
// ════════════════════════════════════════════
export async function onRequest(context) {
  const { request: req, env, params } = context;
  const method = req.method;
  const route = params.route || [];

  if (!env.JWT_SECRET || !env.CODA_TOKEN || !env.CODA_DOC_ID) {
    return json({ error: 'Server not configured. Set JWT_SECRET, CODA_TOKEN, and CODA_DOC_ID as secrets.' }, 500);
  }

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204 });
  }

  // Public
  if (route[0] === 'login' && method === 'POST') return handleLogin(req, env);
  if (route[0] === 'logout' && method === 'POST') return handleLogout(req);

  // Authenticated
  const session = await getSession(req, env);
  if (!session) return json({ error: 'Not authenticated.' }, 401);

  if (route[0] === 'me' && method === 'GET') {
    return json({ name: session.sub, role: session.role });
  }
  if (route[0] === 'change-password' && method === 'POST') {
    return handleChangePassword(req, env, session);
  }

  return handleProxy(req, env, session, route);
}
