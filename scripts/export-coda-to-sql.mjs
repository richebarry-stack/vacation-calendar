// Export all Coda data as SQL INSERT statements for D1.
//
// Usage:
//   CODA_TOKEN=xxx CODA_DOC_ID=xxx node scripts/export-coda-to-sql.mjs > seed.sql

const TOKEN = process.env.CODA_TOKEN;
const DOC   = process.env.CODA_DOC_ID;
const BASE  = 'https://coda.io/apis/v1';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function req(method, path) {
  for (let i = 0; i < 6; i++) {
    const res = await fetch(BASE + path, {
      method,
      headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    });
    if (res.status === 429) { await sleep(3000 * (i + 1)); continue; }
    if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${await res.text()}`);
    return res.json();
  }
  throw new Error('Rate-limited: ' + path);
}

async function allRows(tableId) {
  let out = [], pt = null;
  do {
    const d = await req('GET', `/docs/${DOC}/tables/${tableId}/rows?useColumnNames=true&limit=500${pt ? '&pageToken=' + pt : ''}`);
    out.push(...d.items);
    pt = d.nextPageToken;
  } while (pt);
  return out;
}

function esc(s) { return String(s == null ? '' : s).replace(/'/g, "''"); }

(async () => {
  if (!TOKEN || !DOC) { console.error('Set CODA_TOKEN and CODA_DOC_ID.'); process.exit(1); }

  const tabs = (await req('GET', `/docs/${DOC}/tables`)).items
    .reduce((m, t) => (m[t.name] = t.id, m), {});

  // Users
  const users = await allRows(tabs.Users);
  for (const r of users) {
    const v = r.values;
    const dpq = v.DaysPerQuarter != null && v.DaysPerQuarter !== '' ? parseInt(v.DaysPerQuarter) : 'NULL';
    console.log(`INSERT INTO Users (Name, Password, Role, DaysPerQuarter) VALUES ('${esc(v.Name)}', '${esc(v.Password)}', '${esc(v.Role || 'other_family')}', ${dpq});`);
  }

  // Reservations
  const res = await allRows(tabs.Reservations);
  for (const r of res) {
    const v = r.values;
    if (!v.Owner || !v.StartDate || !v.EndDate) continue;
    const sd = String(v.StartDate).slice(0, 10);
    const ed = String(v.EndDate).slice(0, 10);
    console.log(`INSERT INTO Reservations (Owner, Type, StartDate, EndDate, Status, Quarter, Note, Guests) VALUES ('${esc(v.Owner)}', '${esc(v.Type)}', '${sd}', '${ed}', '${esc(v.Status)}', '${esc(v.Quarter)}', '${esc(v.Note)}', '${esc(v.Guests)}');`);
  }

  // QuarterState
  const qs = await allRows(tabs.QuarterState);
  for (const r of qs) {
    const v = r.values;
    if (!v.Quarter) continue;
    console.log(`INSERT INTO QuarterState (Quarter, Phase) VALUES ('${esc(v.Quarter)}', '${esc(v.Phase || 'A')}');`);
  }

  // Config
  const cfg = await allRows(tabs.Config);
  for (const r of cfg) {
    const v = r.values;
    if (!v.Key) continue;
    console.log(`INSERT INTO Config (Key, Value) VALUES ('${esc(v.Key)}', '${esc(v.Value)}');`);
  }

  console.error(`Exported: ${users.length} users, ${res.length} reservations, ${qs.length} quarter states, ${cfg.length} config rows.`);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
