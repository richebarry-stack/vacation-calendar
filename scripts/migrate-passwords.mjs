// One-time script: hash all plaintext passwords in the Coda Users table.
//
// Usage:
//   CODA_TOKEN=<your-token> CODA_DOC_ID=<your-doc-id> node scripts/migrate-passwords.mjs
//
// Safe to re-run — already-hashed passwords are skipped.

import { pbkdf2Sync, randomBytes } from 'crypto';

const TOKEN = process.env.CODA_TOKEN;
const DOC   = process.env.CODA_DOC_ID;
const BASE  = 'https://coda.io/apis/v1';
const ITER  = 100_000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function toB64Url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = pbkdf2Sync(password, salt, ITER, 32, 'sha256');
  return `pbkdf2:${ITER}:${toB64Url(salt)}:${toB64Url(hash)}`;
}

async function req(method, path, body) {
  for (let i = 0; i < 6; i++) {
    const res = await fetch(BASE + path, {
      method,
      headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 429) {
      const w = 3000 * (i + 1);
      console.log(`  429 rate-limited — waiting ${w}ms`);
      await sleep(w);
      continue;
    }
    if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${await res.text()}`);
    return res.json();
  }
  throw new Error('Gave up (rate-limited): ' + path);
}

(async () => {
  if (!TOKEN || !DOC) {
    console.error('Set CODA_TOKEN and CODA_DOC_ID environment variables.');
    process.exit(1);
  }

  console.log('Connecting to Coda…');
  const tabs = (await req('GET', `/docs/${DOC}/tables`)).items
    .reduce((m, t) => (m[t.name] = t.id, m), {});
  const uid = tabs.Users;
  if (!uid) { console.error('Users table not found in doc.'); process.exit(1); }

  const rows = (await req('GET', `/docs/${DOC}/tables/${uid}/rows?useColumnNames=true&limit=500`)).items;
  console.log(`Found ${rows.length} user(s).\n`);

  let migrated = 0, skipped = 0;
  for (const row of rows) {
    const name = (row.values.Name || '').trim() || '(unnamed)';
    const pw   = (row.values.Password || '').trim();

    if (!pw)                    { console.log(`  ${name}: no password — skip`);      skipped++; continue; }
    if (pw.startsWith('pbkdf2:')) { console.log(`  ${name}: already hashed — skip`); skipped++; continue; }

    const hashed = hashPassword(pw);
    await req('PUT', `/docs/${DOC}/tables/${uid}/rows/${row.id}`, {
      row: { cells: [{ column: 'Password', value: hashed }] },
    });
    await sleep(800);
    console.log(`  ${name}: ✓ hashed`);
    migrated++;
  }

  console.log(`\nDone. ${migrated} password(s) hashed, ${skipped} skipped.`);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
