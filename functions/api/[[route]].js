// Cloudflare Pages Function — RBAC backend for the vacation-home booking calendar.
// Uses D1 (SQLite) for storage. Static assets (index.html) are served by Pages.
//
// Required env/secrets:
//   DB          — D1 database binding
//   JWT_SECRET  — random string for signing session JWTs

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

  const key = name.trim().toLowerCase();
  const users = await env.DB.prepare('SELECT * FROM Users').all();
  const matches = users.results.filter(u => u.Name && u.Name.trim().toLowerCase() === key);

  if (!matches.length) {
    const owners = users.results
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
// CHANGE PASSWORD
// ════════════════════════════════════════════
async function handleChangePassword(req, env, session) {
  let body;
  try { body = await req.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
  const { currentPassword, newPassword } = body;
  if (!newPassword) return json({ error: 'New password is required.' }, 400);

  const user = await env.DB.prepare('SELECT * FROM Users WHERE LOWER(TRIM(Name)) = ?')
    .bind(session.sub.toLowerCase()).first();
  if (!user) return json({ error: 'Account not found.' }, 404);

  const stored = (user.Password || '').trim();
  if (stored && !(await checkPw(currentPassword || '', stored))) {
    return json({ error: 'Current password is incorrect.' }, 403);
  }

  const hashed = await hashPw(newPassword);
  await env.DB.prepare('UPDATE Users SET Password = ? WHERE id = ?').bind(hashed, user.id).run();
  return json({ ok: true });
}

// ════════════════════════════════════════════
// TABLE ENDPOINTS  (replace Coda proxy with direct D1 queries)
// ════════════════════════════════════════════

// GET /api/tables — return table names + IDs (frontend expects this shape)
async function listTables(env) {
  const names = ['Reservations', 'QuarterState', 'Users', 'Config'];
  return json({ items: names.map(n => ({ id: n, name: n })) });
}

// GET /api/tables/:table/columns — return column names
async function listColumns(env, table) {
  const cols = {
    Reservations: ['Owner', 'Type', 'StartDate', 'EndDate', 'Status', 'Quarter', 'Note', 'Guests'],
    QuarterState: ['Quarter', 'Phase'],
    Users: ['Name', 'Password', 'Role', 'DaysPerQuarter'],
    Config: ['Key', 'Value'],
  };
  const list = cols[table];
  if (!list) return json({ error: 'Unknown table.' }, 404);
  return json({ items: list.map(name => ({ name })) });
}

// GET /api/tables/:table/rows — return all rows
async function getRows(env, table, session, url) {
  const valid = ['Reservations', 'QuarterState', 'Users', 'Config'];
  if (!valid.includes(table)) return json({ error: 'Unknown table.' }, 404);

  const rows = await env.DB.prepare(`SELECT * FROM ${table}`).all();
  const items = rows.results.map(row => {
    const values = { ...row };
    const id = String(row.id);
    delete values.id;
    if (table === 'Users') delete values.Password;
    return { id, values };
  });

  return json({ items });
}

// POST /api/tables/:table/rows — insert rows
async function addRows(env, table, session, body) {
  const valid = ['Reservations', 'QuarterState', 'Users', 'Config'];
  if (!valid.includes(table)) return json({ error: 'Unknown table.' }, 404);

  // RBAC
  if (session.role === 'guest') return json({ error: 'Guests are view-only.' }, 403);
  if (session.role !== 'owner') {
    if (table === 'Config') return json({ error: 'Only owners can modify configuration.' }, 403);
    if (table === 'Users') return json({ error: 'Only owners can manage user accounts.' }, 403);
  }

  if (!body || !body.rows) return json({ error: 'Missing rows.' }, 400);
  const addedRowIds = [];

  for (const row of body.rows) {
    const cells = {};
    for (const c of (row.cells || [])) cells[c.column] = c.value;

    // RBAC: non-owners can only create their own reservations
    if (table === 'Reservations' && session.role !== 'owner') {
      if (cells.Owner && cells.Owner !== session.sub) {
        return json({ error: 'You can only create reservations for yourself.' }, 403);
      }
    }

    // Hash passwords
    if (table === 'Users' && cells.Password) {
      cells.Password = await hashPw(cells.Password);
    }

    const colDefs = {
      Reservations: ['Owner', 'Type', 'StartDate', 'EndDate', 'Status', 'Quarter', 'Note', 'Guests'],
      QuarterState: ['Quarter', 'Phase'],
      Users: ['Name', 'Password', 'Role', 'DaysPerQuarter'],
      Config: ['Key', 'Value'],
    };

    const cols = colDefs[table].filter(c => cells[c] !== undefined);
    const vals = cols.map(c => cells[c]);
    const placeholders = cols.map(() => '?').join(', ');

    const result = await env.DB.prepare(
      `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders})`
    ).bind(...vals).run();

    addedRowIds.push(String(result.meta.last_row_id));
  }

  return json({ addedRowIds });
}

// PUT /api/tables/:table/rows/:rowId — update a row
async function updateRow(env, table, rowId, session, body) {
  const valid = ['Reservations', 'QuarterState', 'Users', 'Config'];
  if (!valid.includes(table)) return json({ error: 'Unknown table.' }, 404);

  // RBAC
  if (session.role === 'guest') return json({ error: 'Guests are view-only.' }, 403);
  if (session.role !== 'owner') {
    if (table === 'Config') return json({ error: 'Only owners can modify configuration.' }, 403);
    if (table === 'Users') return json({ error: 'Only owners can manage user accounts.' }, 403);
    if (table === 'Reservations') {
      const existing = await env.DB.prepare('SELECT Owner FROM Reservations WHERE id = ?').bind(rowId).first();
      if (existing && existing.Owner !== session.sub) {
        return json({ error: 'You can only modify your own reservations.' }, 403);
      }
    }
  }

  if (!body || !body.row || !body.row.cells) return json({ error: 'Missing row data.' }, 400);

  const cells = {};
  for (const c of body.row.cells) cells[c.column] = c.value;

  // Hash passwords
  if (table === 'Users' && cells.Password) {
    cells.Password = await hashPw(cells.Password);
  }

  // Non-owners can't change Owner on reservations
  if (table === 'Reservations' && session.role !== 'owner' && cells.Owner && cells.Owner !== session.sub) {
    return json({ error: 'You can only modify your own reservations.' }, 403);
  }

  const cols = Object.keys(cells);
  const sets = cols.map(c => `${c} = ?`).join(', ');
  const vals = cols.map(c => cells[c]);

  await env.DB.prepare(`UPDATE ${table} SET ${sets} WHERE id = ?`).bind(...vals, rowId).run();
  return json({ ok: true });
}

// DELETE /api/tables/:table/rows — delete rows
async function deleteTableRows(env, table, session, body) {
  const valid = ['Reservations', 'QuarterState', 'Users', 'Config'];
  if (!valid.includes(table)) return json({ error: 'Unknown table.' }, 404);

  // RBAC
  if (session.role === 'guest') return json({ error: 'Guests are view-only.' }, 403);
  if (session.role !== 'owner') {
    if (table === 'Config') return json({ error: 'Only owners can modify configuration.' }, 403);
    if (table === 'Users') return json({ error: 'Only owners can manage user accounts.' }, 403);
    if (table === 'Reservations' && body && body.rowIds) {
      const placeholders = body.rowIds.map(() => '?').join(', ');
      const rows = await env.DB.prepare(
        `SELECT id, Owner FROM Reservations WHERE id IN (${placeholders})`
      ).bind(...body.rowIds).all();
      for (const r of rows.results) {
        if (r.Owner !== session.sub) return json({ error: 'You can only delete your own reservations.' }, 403);
      }
    }
  }

  if (!body || !body.rowIds || !body.rowIds.length) return json({ error: 'Missing rowIds.' }, 400);

  const placeholders = body.rowIds.map(() => '?').join(', ');
  await env.DB.prepare(`DELETE FROM ${table} WHERE id IN (${placeholders})`).bind(...body.rowIds).run();
  return new Response(null, { status: 202 });
}

// ════════════════════════════════════════════
// ROUTER
// ════════════════════════════════════════════
export async function onRequest(context) {
  const { request: req, env, params } = context;
  const method = req.method;
  const route = params.route || [];

  if (!env.JWT_SECRET || !env.DB) {
    return json({ error: 'Server not configured. Set JWT_SECRET and bind D1 as DB.' }, 500);
  }

  if (method === 'OPTIONS') return new Response(null, { status: 204 });

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

  // Table operations: /api/tables, /api/tables/:table/rows, etc.
  if (route[0] === 'tables') {
    if (!route[1] && method === 'GET') return listTables(env);

    const table = route[1];
    if (route[2] === 'columns' && method === 'GET') return listColumns(env, table);

    if (route[2] === 'rows') {
      if (method === 'GET') return getRows(env, table, session, new URL(req.url));
      if (method === 'POST') {
        const body = await req.json();
        return addRows(env, table, session, body);
      }
      if (method === 'DELETE') {
        const body = await req.json();
        return deleteTableRows(env, table, session, body);
      }
      if (method === 'PUT' && route[3]) {
        const body = await req.json();
        return updateRow(env, table, route[3], session, body);
      }
    }
  }

  return json({ error: 'Not found.' }, 404);
}
