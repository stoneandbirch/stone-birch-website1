// Stone + Birch Workspace — shared API (one function; vercel.json routes /api/* here)
import { q, one } from './db.js';
import { hashPw, checkPw, pwProblem, rid, startSession, endSession, endUserSessions, currentUser, cookieFor, normUser, publicUser, isAdmin, canPage, canProject, PAGES, FIN_KEYS } from './auth.js';
import { hiddenKeys, strip, restore } from './fields.js';
import { merge3 } from './merge.js';
import { createHash } from 'node:crypto';

const KEY_RE = /^(settings|library|clients|proposals|contracts|vendors|project:[A-Za-z0-9_-]{1,80})$/;
const HISTORY_KEEP = 40, MAX_FILE_PARTS = 12;

class HttpError extends Error { constructor(status, msg, extra) { super(msg); this.status = status; this.extra = extra; } }
const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const bad = (msg, status = 400) => { throw new HttpError(status, msg); };
async function body(req) { try { return await req.json(); } catch { return {}; } }
const emailOk = e => /^\S+@\S+\.\S+$/.test(e || '');
const cleanEmail = e => String(e || '').trim().toLowerCase();

async function need(req) { const u = await currentUser(req); if (!u) bad('Please sign in.', 401); return u; }
async function needAdmin(req) { const u = await need(req); if (!isAdmin(u)) bad('Only admins can do that.', 403); return u; }
const userCount = async () => Number((await one(`SELECT count(*)::int AS n FROM users`)).n);

/* ── who can see which shared document ── */
function canRead(u, key) {
  if (key.startsWith('project:')) return canProject(u, key.slice(8));
  if (key === 'proposals') return canPage(u, 'proposals');
  if (key === 'contracts') return canPage(u, 'contracts');
  return true;
}
function viewOf(u, key, data) {
  let d = strip(data, hiddenKeys(u));
  if (key === 'settings' && d && Array.isArray(d.order) && Array.isArray(u.projects) && !isAdmin(u)) d = { ...d, order: d.order.filter(id => u.projects.includes(id)) };
  return d;
}

/* ── save one shared document (with automatic merge if someone else saved first) ── */
async function saveDoc(u, ch, ctx) {
  const key = String(ch.key || ''); if (!KEY_RE.test(key)) bad('Unknown document ' + key);
  const cur = await one(`SELECT key, data, version, deleted FROM docs WHERE key=$1`, [key]);
  if (cur && !cur.deleted && !canRead(u, key)) bad('You don\'t have access to ' + key, 403);
  if (!cur && key.startsWith('project:') && !canProject(u, key.slice(8))) {
    // a team member limited to certain projects just created a new one: give them access to it
    const list = Array.isArray(u.projects) ? [...u.projects, key.slice(8)] : u.projects;
    await q(`UPDATE users SET projects=$2 WHERE id=$1`, [u.id, JSON.stringify(list)]); u.projects = list;
  }
  if ((key === 'proposals' || key === 'contracts') && !canPage(u, key)) bad('You don\'t have access to ' + key, 403);
  if (ch.deleted) {
    if (!key.startsWith('project:')) bad('Only projects can be deleted.');
    if (!cur) return { v: 0 };
    const r = await one(`UPDATE docs SET deleted=true, version=version+1, seq=nextval('doc_seq'), updated_at=now(), updated_by=$2 WHERE key=$1 RETURNING version`, [key, u.id]);
    return { v: r.version, deleted: true };
  }
  let data = ch.data; if (data === undefined) bad('Missing data for ' + key);
  const hide = hiddenKeys(u);
  if (hide.size) {
    const sources = await ctx.sources(key);
    data = restore(data, cur && !cur.deleted ? cur.data : undefined, hide, sources);
  } else restore(data, undefined, hide);
  if (key === 'settings' && Array.isArray(u.projects) && !isAdmin(u) && cur && cur.data && Array.isArray(cur.data.order) && Array.isArray(data.order)) {
    const mine = data.order.filter(id => u.projects.includes(id) || !cur.data.order.includes(id)); let i = 0;   // keep projects they can't see in their places
    const order = cur.data.order.map(id => u.projects.includes(id) ? null : id);
    data.order = order.map(id => id === null ? mine[i++] : id).filter(Boolean).concat(mine.slice(i));
  }
  for (let attempt = 0; attempt < 4; attempt++) {
    const now = attempt === 0 ? cur : await one(`SELECT key, data, version, deleted FROM docs WHERE key=$1`, [key]);
    if (!now) {
      const ins = await q(`INSERT INTO docs (key, data, version, updated_by) VALUES ($1,$2,1,$3) ON CONFLICT (key) DO NOTHING RETURNING version`, [key, JSON.stringify(data), u.id]);
      if (!ins.length) continue;
      await q(`INSERT INTO doc_history (key, version, data, updated_by) VALUES ($1,1,$2,$3) ON CONFLICT DO NOTHING`, [key, JSON.stringify(data), u.id]);
      return { v: 1 };
    }
    let next = data, merged = false;
    if (!now.deleted && Number(ch.base) !== now.version) {
      const b = ch.base ? await one(`SELECT data FROM doc_history WHERE key=$1 AND version=$2`, [key, Number(ch.base)]) : null;
      next = merge3(b ? b.data : undefined, data, now.data, key); merged = true;
    }
    const up = await q(`UPDATE docs SET data=$2, version=version+1, deleted=false, seq=nextval('doc_seq'), updated_at=now(), updated_by=$3 WHERE key=$1 AND version=$4 RETURNING version`,
      [key, JSON.stringify(next), u.id, now.version]);
    if (!up.length) continue;
    const v = up[0].version;
    await q(`INSERT INTO doc_history (key, version, data, updated_by) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, [key, v, JSON.stringify(next), u.id]);
    if (v % 10 === 0) q(`DELETE FROM doc_history WHERE key=$1 AND version < $2`, [key, v - HISTORY_KEEP]).catch(() => {});
    return merged ? { v, merged: true, data: viewOf(u, key, next) } : { v };
  }
  bad('Too many people saved at once — please try again.', 409);
}
function sourceLoader() {
  const cache = {};
  const get = async k => { if (!(k in cache)) { const r = await one(`SELECT data FROM docs WHERE key=$1 AND NOT deleted`, [k]); cache[k] = r ? r.data : null; } return cache[k]; };
  return {
    async sources(key) {
      const lib = await get('library'), proj = key.startsWith('project:') ? await get(key) : null;
      const items = new Map(); if (proj && proj.state) Object.values(proj.state).forEach(r => (r && r.items || []).forEach(it => items.set(it.id, it)));
      const prods = new Map(((lib && lib.items) || []).map(p => [p.id, p]));
      return { product: id => prods.get(id), item: id => items.get(id) };
    }
  };
}


/* ── private client link: /p/<token> shows the published portal page without a login ── */
const TOKEN_RE = /^[a-z0-9]{8,40}$/;
const htmlEsc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const page = (html, status = 200, headers = {}) => new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow', 'referrer-policy': 'same-origin', 'x-frame-options': 'DENY', ...headers } });
function shell(title, inner) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${htmlEsc(title)}</title>
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#faf8f5;color:#312e2e;font:14px/1.5 'DM Sans',system-ui,sans-serif;padding:24px;text-align:center}
.b{max-width:380px}.l{font:400 24px 'Cormorant Garamond',serif;letter-spacing:.08em}.h{font:400 28px 'Cormorant Garamond',serif;margin:14px 0 6px}.m{color:#878282;font-size:13px}
input{border:1px solid #e4dedb;border-radius:8px;padding:11px 12px;font:inherit;font-size:18px;text-align:center;letter-spacing:.4em;width:170px;margin:16px 0 6px}
button{background:#6d5e5f;color:#fff;border:none;border-radius:8px;padding:10px 18px;font:inherit;cursor:pointer}.e{color:#9a2b2b;font-size:12.5px;min-height:18px}</style></head><body><div class="b"><div class="l">STONE + BIRCH</div>${inner}</div></body></html>`;
}
const inactivePage = () => page(shell('Link not active', `<div class="h">This link is no longer active</div><div class="m">Please contact your designer for an updated link.</div>`), 404);
const pinCookie = (token, pin) => 'sbp_' + token + '=' + createHash('sha256').update(token + ':' + pin).digest('hex').slice(0, 32);
function hasPin(req, link) { if (!link.pin) return true; const c = req.headers.get('cookie') || ''; return c.split(/;\s*/).includes(pinCookie(link.token, link.pin)); }
async function linkByToken(token) { if (!TOKEN_RE.test(token)) return null; return await one(`SELECT * FROM portal_links WHERE token=$1`, [token]); }
function gatePage(err) {
  return page(shell('Enter passcode', `<div class="h">Enter your passcode</div><div class="m">Your designer sent you a 4-digit code.</div>
<form method="post"><input name="pin" inputmode="numeric" maxlength="4" autocomplete="one-time-code" autofocus aria-label="Passcode"><div class="e">${htmlEsc(err || '')}</div><button type="submit">View my project</button></form>`), err ? 403 : 200);
}
async function readForm(req) { const t = await req.text(); const p = new URLSearchParams(t); return Object.fromEntries(p.entries()); }
/* apply a client's quote decisions straight onto the project, so the studio sees them right away */
function parseCode(text) {
  const m = /BEGIN QUOTE APPROVAL-+([\s\S]*?)-+END QUOTE APPROVAL/.exec(text || '') || [null, text || ''];
  const b = m[1].replace(/[\s>]+/g, ''); const p = /SBQ1\.([a-z0-9]+)\.([adp]+)\.([A-Za-z0-9+/=]*)/.exec(b); if (!p) return null;
  let extra = {}; try { extra = JSON.parse(Buffer.from(p[3], 'base64').toString('utf8')); } catch {}
  return { token: p[1], states: p[2], by: String(extra.by || '').slice(0, 120), comment: String(extra.c || '').slice(0, 2000) };
}
async function applyReply(pid, a) {
  const key = 'project:' + pid;
  for (let attempt = 0; attempt < 4; attempt++) {
    const cur = await one(`SELECT data, version FROM docs WHERE key=$1 AND NOT deleted`, [key]); if (!cur) bad('This project is no longer available.', 404);
    const data = cur.data; let hit = null;
    for (const q of (data.quotes || [])) { const s = (q.sendLog || []).find(x => x.token === a.token); if (s) { hit = { q, s }; break; } }
    if (!hit) bad('This quote has changed since the page loaded. Please reload the page and try again.', 409);
    const at = new Date().toISOString().slice(0, 10);
    hit.s.lineIds.forEach((id, i) => { const l = (hit.q.lines || []).find(x => x.id === id), st = a.states[i]; if (!l || !st || st === 'p') return;
      l.approval = st === 'a' ? 'approved' : 'declined'; l.clientDecision = { v: l.approval, by: a.by || 'Client', at, via: 'link' }; });
    hit.q.clientResponse = { by: a.by, at, comment: a.comment, via: 'link' };
    const up = await q(`UPDATE docs SET data=$2, version=version+1, seq=nextval('doc_seq'), updated_at=now(), updated_by='client' WHERE key=$1 AND version=$3 RETURNING version`, [key, JSON.stringify(data), cur.version]);
    if (!up.length) continue;
    await q(`INSERT INTO doc_history (key, version, data, updated_by) VALUES ($1,$2,$3,'client') ON CONFLICT DO NOTHING`, [key, up[0].version, JSON.stringify(data)]);
    return hit.q.number;
  }
  bad('Please try again in a moment.', 409);
}
async function publicRoute(req, token, sub, method) {
  const link = await linkByToken(token);
  if (!link || !link.active || !link.html) return sub ? json({ error: 'This link is no longer active.' }, 404) : inactivePage();
  if (!sub && method === 'POST') {   // passcode form
    if (link.locked_until && new Date(link.locked_until) > new Date()) return gatePage('Too many tries. Please wait 15 minutes.');
    const f = await readForm(req), pin = String(f.pin || '').replace(/\D/g, '');
    if (!link.pin || pin !== link.pin) {
      await q(`UPDATE portal_links SET fails=fails+1, locked_until=CASE WHEN fails+1>=8 THEN now()+interval '15 minutes' ELSE NULL END WHERE pid=$1`, [link.pid]);
      return gatePage('That code doesn\'t match.');
    }
    await q(`UPDATE portal_links SET fails=0, locked_until=NULL WHERE pid=$1`, [link.pid]);
    const secure = new URL(req.url).protocol === 'https:' || (req.headers.get('x-forwarded-proto') || '') === 'https';
    return new Response(null, { status: 303, headers: { location: '/p/' + token, 'cache-control': 'no-store', 'set-cookie': pinCookie(link.token, link.pin) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=7776000' + (secure ? '; Secure' : '') } });
  }
  if (!hasPin(req, link)) return sub ? json({ error: 'Please enter your passcode again.' }, 403) : gatePage('');
  if (!sub && (method === 'GET' || method === 'HEAD')) {
    const views = Array.isArray(link.views) ? link.views : [], last = views[views.length - 1];
    if (!last || Date.now() - new Date(last.at).getTime() > 10 * 60 * 1000) q(`UPDATE portal_links SET views=$2 WHERE pid=$1`, [link.pid, JSON.stringify([...views, { at: new Date().toISOString() }].slice(-30))]).catch(() => {});
    return page(link.html);
  }
  if (sub === 'reply' && method === 'POST') {
    if (!link.approve) bad('Approvals are turned off for this link — please contact your designer.', 403);
    const b = await body(req), a = parseCode(String(b.code || '').slice(0, 20000)); if (!a) bad('Something was missing from your decisions — please try again.');
    const number = await applyReply(link.pid, a);
    return json({ ok: true, quote: number });
  }
  bad('Not found', 404);
}

/* ── routes ── */
async function route(req, path, method) {
  /* status & sign-in */
  if (path === 'health') return json({ ok: true, db: !!(process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.SBW_PGLITE) });
  if (path === 'me' && method === 'GET') {
    const n = await userCount(); if (!n) return json({ mode: 'shared', setup: true });
    const u = await currentUser(req); return json({ mode: 'shared', user: u ? publicUser(u) : null });
  }
  if (path === 'setup' && method === 'POST') {
    const b = await body(req); if (await userCount()) bad('Sign-in is already set up.', 409);
    const email = cleanEmail(b.email), name = String(b.name || '').trim();
    if (!name || !emailOk(email)) bad('Enter your name and a valid email.'); const p = pwProblem(b.password); if (p) bad(p);
    const { salt, hash } = await hashPw(b.password), id = rid('usr_');
    await q(`INSERT INTO users (id, email, name, role, salt, hash, last_login) VALUES ($1,$2,$3,'admin',$4,$5,now())`, [id, email, name, salt, hash]);
    const code = await newRecovery();
    const token = await startSession(id); const u = normUser(await one(`SELECT * FROM users WHERE id=$1`, [id]));
    return json({ user: publicUser(u), recoveryCode: code }, 200, { 'set-cookie': cookieFor(token, req) });
  }
  if (path === 'login' && method === 'POST') {
    const b = await body(req), email = cleanEmail(b.email);
    const row = await one(`SELECT * FROM users WHERE email=$1`, [email]);
    if (row && row.locked_until && new Date(row.locked_until) > new Date()) bad('Too many tries. Wait 15 minutes, or ask your admin to reset your password.', 429);
    const ok = await checkPw(row, b.password || '');
    if (!ok) { if (row) await q(`UPDATE users SET failed=failed+1, locked_until=CASE WHEN failed+1>=8 THEN now()+interval '15 minutes' ELSE NULL END WHERE id=$1`, [row.id]); bad('That email and password don\'t match.', 401); }
    if (!row.active) bad('This account is turned off. Ask your admin to turn it back on.', 403);
    await q(`UPDATE users SET failed=0, locked_until=NULL, last_login=now() WHERE id=$1`, [row.id]);
    const token = await startSession(row.id);
    return json({ user: publicUser(normUser(row)) }, 200, { 'set-cookie': cookieFor(token, req) });
  }
  if (path === 'logout' && method === 'POST') { await endSession(req); return json({ ok: true }, 200, { 'set-cookie': cookieFor(null, req) }); }
  if (path === 'password' && method === 'POST') {
    const u = await need(req), b = await body(req);
    if (!u.mustChange && !(await checkPw(u, b.current || ''))) bad('Your current password isn\'t right.', 403);
    const p = pwProblem(b.password); if (p) bad(p);
    const { salt, hash } = await hashPw(b.password);
    await q(`UPDATE users SET salt=$2, hash=$3, must_change=false WHERE id=$1`, [u.id, salt, hash]);
    await endUserSessions(u.id, req);
    return json({ ok: true, user: publicUser({ ...u, mustChange: false }) });
  }
  if (path === 'recover' && method === 'POST') {
    const b = await body(req), email = cleanEmail(b.email), code = String(b.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const row = await one(`SELECT * FROM users WHERE email=$1 AND role='admin'`, [email]); const rec = await one(`SELECT v FROM settings WHERE k='recovery'`);
    let ok = false; if (row && rec && rec.v) { const { hash } = await hashPw(code, rec.v.salt); ok = hash === rec.v.hash; }
    if (!ok) bad('That email and recovery code don\'t match an admin.', 403);
    const p = pwProblem(b.password); if (p) bad(p);
    const { salt, hash } = await hashPw(b.password);
    await q(`UPDATE users SET salt=$2, hash=$3, must_change=false, failed=0, locked_until=NULL, active=true, last_login=now() WHERE id=$1`, [row.id, salt, hash]);
    await endUserSessions(row.id); const token = await startSession(row.id);
    return json({ ok: true, user: publicUser(normUser(await one(`SELECT * FROM users WHERE id=$1`, [row.id]))) }, 200, { 'set-cookie': cookieFor(token, req) });
  }
  if (path === 'recovery-code' && method === 'POST') { await needAdmin(req); return json({ recoveryCode: await newRecovery() }); }


  /* private client link */
  let pm;
  if ((pm = path.match(/^p\/([A-Za-z0-9]+)(?:\/(reply))?$/))) return publicRoute(req, pm[1].toLowerCase(), pm[2] || '', method);
  if (path === 'portal-snap' && method === 'POST') {
    const u = await need(req), b = await body(req), pid = String(b.pid || '');
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(pid) || !canProject(u, pid)) bad('You don\'t have access to that project.', 403);
    const token = String(b.token || '').toLowerCase(); if (!TOKEN_RE.test(token)) bad('Bad link.');
    const html = String(b.html || ''); if (html.length > 4_000_000) bad('The portal page is too large to publish.');
    const pin = /^\d{4}$/.test(String(b.pin || '')) ? String(b.pin) : '';
    const clash = await one(`SELECT pid FROM portal_links WHERE token=$1 AND pid<>$2`, [token, pid]); if (clash) bad('Link already in use — reset it.', 409);
    const prev = await one(`SELECT token, views FROM portal_links WHERE pid=$1`, [pid]);
    const views = prev && prev.token === token ? prev.views : [];
    await q(`INSERT INTO portal_links (pid, token, active, pin, approve, html, snap_at, views, updated_by, updated_at) VALUES ($1,$2,$3,$4,$5,$6,now(),$7,$8,now())
      ON CONFLICT (pid) DO UPDATE SET token=EXCLUDED.token, active=EXCLUDED.active, pin=EXCLUDED.pin, approve=EXCLUDED.approve, html=EXCLUDED.html, snap_at=now(), views=EXCLUDED.views,
        fails=CASE WHEN portal_links.token=EXCLUDED.token THEN portal_links.fails ELSE 0 END, locked_until=CASE WHEN portal_links.token=EXCLUDED.token THEN portal_links.locked_until ELSE NULL END, updated_by=EXCLUDED.updated_by, updated_at=now()`,
      [pid, token, !!b.on && !!html, pin, b.approve !== false, b.on ? html : '', JSON.stringify(views), u.id]);
    return json({ ok: true, views });
  }
  if (path === 'portal-link' && method === 'GET') {
    const u = await need(req), pid = new URL(req.url).searchParams.get('pid') || ''; if (!canProject(u, pid)) bad('You don\'t have access to that project.', 403);
    const r = await one(`SELECT token, active, views, snap_at FROM portal_links WHERE pid=$1`, [pid]);
    return json(r ? { token: r.token, active: r.active, views: r.views, snapAt: r.snap_at } : {});
  }

  /* files (images, tear sheets, PDFs) */
  let m;
  if ((m = path.match(/^files\/([A-Za-z0-9_-]+)$/)) && method === 'GET') {
    const f = await one(`SELECT * FROM files WHERE id=$1 AND complete`, [m[1]]); if (!f) return new Response('Not found', { status: 404 });
    const parts = await q(`SELECT data FROM file_parts WHERE id=$1 ORDER BY n`, [f.id]);
    const buf = Buffer.concat(parts.map(p => Buffer.from(p.data, 'base64')));
    return new Response(buf, { headers: { 'content-type': f.type || 'application/octet-stream', 'content-length': String(buf.length), 'cache-control': 'public, max-age=31536000, immutable',
      'access-control-allow-origin': '*', 'content-disposition': `inline; filename="${String(f.name || 'file').replace(/[^\w.\- ]+/g, '_')}"` } });
  }
  if (path === 'files' && method === 'POST') {
    const u = await need(req), b = await body(req), parts = Math.max(1, Math.min(MAX_FILE_PARTS, parseInt(b.parts) || 1));
    const id = rid('f'); await q(`INSERT INTO files (id, name, type, size, parts, created_by) VALUES ($1,$2,$3,$4,$5,$6)`, [id, String(b.name || '').slice(0, 200), String(b.type || '').slice(0, 120), parseInt(b.size) || 0, parts, u.id]);
    return json({ id });
  }
  if ((m = path.match(/^files\/([A-Za-z0-9_-]+)\/(\d+)$/)) && method === 'PUT') {
    const u = await need(req), b = await body(req), n = parseInt(m[2]);
    const f = await one(`SELECT * FROM files WHERE id=$1 AND created_by=$2 AND NOT complete`, [m[1], u.id]); if (!f || n >= f.parts) bad('Upload not found.', 404);
    await q(`INSERT INTO file_parts (id, n, data) VALUES ($1,$2,$3) ON CONFLICT (id, n) DO UPDATE SET data=EXCLUDED.data`, [f.id, n, String(b.data || '')]);
    if (n === f.parts - 1) await q(`UPDATE files SET complete=true WHERE id=$1`, [f.id]);
    return json({ ok: true, url: n === f.parts - 1 ? '/api/files/' + f.id : undefined });
  }

  /* shared workspace data */
  if (path === 'bootstrap' && method === 'GET') {
    const u = await need(req);
    const rows = await q(`SELECT key, version FROM docs WHERE NOT deleted`);
    const s = await one(`SELECT COALESCE(max(seq),0)::bigint AS s FROM docs`);
    return json({ user: publicUser(u), index: rows.filter(r => canRead(u, r.key)).map(r => ({ key: r.key, v: r.version })), seq: Number(s.s) });
  }
  if (path === 'docs' && method === 'GET') {
    const u = await need(req), keys = (new URL(req.url).searchParams.get('keys') || '').split(',').filter(k => KEY_RE.test(k) && canRead(u, k)).slice(0, 40);
    if (!keys.length) return json({ docs: {} });
    const rows = await q(`SELECT key, data, version FROM docs WHERE key = ANY($1) AND NOT deleted`, [keys]);
    const docs = {}; rows.forEach(r => { docs[r.key] = { v: r.version, data: viewOf(u, r.key, r.data) }; });
    return json({ docs });
  }
  if (path === 'changes' && method === 'GET') {
    const u = await need(req), since = parseInt(new URL(req.url).searchParams.get('since')) || 0;
    const rows = await q(`SELECT key, version, deleted, seq, updated_by, (length(data::text)) AS size FROM docs WHERE seq > $1 ORDER BY seq LIMIT 200`, [since]);
    const s = rows.length ? Number(rows[rows.length - 1].seq) : since;
    const vis = rows.filter(r => canRead(u, r.key));
    const names = {}; (await q(`SELECT id, name FROM users`)).forEach(x => names[x.id] = x.name);
    return json({ seq: s, changes: vis.map(r => ({ key: r.key, v: r.version, deleted: r.deleted, by: r.updated_by, byName: names[r.updated_by] || '' })), user: publicUser(u) });
  }
  if (path === 'save' && method === 'POST') {
    const u = await need(req); if (u.mustChange) bad('Choose a new password first.', 403);
    const b = await body(req), ctx = sourceLoader(), results = {};
    for (const ch of (Array.isArray(b.changes) ? b.changes : []).slice(0, 60)) {
      try { results[ch.key] = await saveDoc(u, ch, ctx); }
      catch (e) { results[ch.key] = { error: e.message, status: e.status || 500 }; }
    }
    const s = await one(`SELECT COALESCE(max(seq),0)::bigint AS s FROM docs`);
    return json({ results, seq: Number(s.s) });
  }
  if (path === 'import' && method === 'POST') {
    const u = await needAdmin(req), b = await body(req), docs = b.docs || {};
    const keys = Object.keys(docs).filter(k => KEY_RE.test(k)); if (!keys.length) bad('Nothing to import.');
    for (const k of keys) {
      await q(`INSERT INTO docs (key, data, version, updated_by) VALUES ($1,$2,1,$3) ON CONFLICT (key) DO UPDATE SET data=EXCLUDED.data, version=docs.version+1, deleted=false, seq=nextval('doc_seq'), updated_at=now(), updated_by=EXCLUDED.updated_by`, [k, JSON.stringify(docs[k]), u.id]);
      const r = await one(`SELECT version FROM docs WHERE key=$1`, [k]);
      await q(`INSERT INTO doc_history (key, version, data, updated_by) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, [k, r.version, JSON.stringify(docs[k]), u.id]);
    }
    return json({ ok: true, imported: keys.length });
  }

  /* users (admin) */
  if (path === 'users' && method === 'GET') { await needAdmin(req); return json({ users: (await q(`SELECT * FROM users ORDER BY created_at`)).map(r => publicUser(normUser(r))) }); }
  if (path === 'users' && method === 'POST') {
    await needAdmin(req); const b = await body(req), email = cleanEmail(b.email), name = String(b.name || '').trim();
    if (!name || !emailOk(email)) bad('Enter a name and a valid email.'); if (await one(`SELECT id FROM users WHERE email=$1`, [email])) bad('Another user already has that email.');
    const p = pwProblem(b.password); if (p) bad(p);
    const { salt, hash } = await hashPw(b.password), id = rid('usr_'), f = userFields(b);
    await q(`INSERT INTO users (id, email, name, role, active, pages, projects, hide_fields, salt, hash, must_change) VALUES ($1,$2,$3,$4,true,$5,$6,$7,$8,$9,$10)`,
      [id, email, name, f.role, f.pages, f.projects, f.hide, salt, hash, b.mustChange !== false]);
    return json({ user: publicUser(normUser(await one(`SELECT * FROM users WHERE id=$1`, [id]))) });
  }
  if ((m = path.match(/^users\/([A-Za-z0-9_-]+)$/)) && method === 'PATCH') {
    const me = await needAdmin(req), b = await body(req), row = await one(`SELECT * FROM users WHERE id=$1`, [m[1]]); if (!row) bad('User not found.', 404);
    const email = b.email != null ? cleanEmail(b.email) : row.email, name = b.name != null ? String(b.name).trim() : row.name;
    if (!name || !emailOk(email)) bad('Enter a name and a valid email.');
    if (email !== row.email && await one(`SELECT id FROM users WHERE email=$1 AND id<>$2`, [email, row.id])) bad('Another user already has that email.');
    const f = userFields({ role: b.role ?? row.role, pages: b.pages !== undefined ? b.pages : row.pages, projects: b.projects !== undefined ? b.projects : row.projects, hideFields: b.hideFields ?? row.hide_fields });
    const active = b.active != null ? !!b.active : row.active;
    if (row.role === 'admin' && (f.role !== 'admin' || !active) && Number((await one(`SELECT count(*)::int n FROM users WHERE role='admin' AND active AND id<>$1`, [row.id])).n) < 1) bad('Keep at least one active admin.');
    await q(`UPDATE users SET email=$2, name=$3, role=$4, active=$5, pages=$6, projects=$7, hide_fields=$8 WHERE id=$1`, [row.id, email, name, f.role, active, f.pages, f.projects, f.hide]);
    if (!active) await endUserSessions(row.id);
    return json({ user: publicUser(normUser(await one(`SELECT * FROM users WHERE id=$1`, [row.id]))) });
  }
  if ((m = path.match(/^users\/([A-Za-z0-9_-]+)\/password$/)) && method === 'POST') {
    const me = await needAdmin(req), b = await body(req), row = await one(`SELECT * FROM users WHERE id=$1`, [m[1]]); if (!row) bad('User not found.', 404);
    const p = pwProblem(b.password); if (p) bad(p);
    const { salt, hash } = await hashPw(b.password);
    await q(`UPDATE users SET salt=$2, hash=$3, must_change=$4, failed=0, locked_until=NULL WHERE id=$1`, [row.id, salt, hash, row.id !== me.id && b.mustChange !== false]);
    if (row.id !== me.id) await endUserSessions(row.id);
    return json({ ok: true });
  }
  if ((m = path.match(/^users\/([A-Za-z0-9_-]+)$/)) && method === 'DELETE') {
    const me = await needAdmin(req), row = await one(`SELECT * FROM users WHERE id=$1`, [m[1]]); if (!row) bad('User not found.', 404);
    if (row.id === me.id) bad('You can\'t delete your own account.');
    if (row.role === 'admin' && Number((await one(`SELECT count(*)::int n FROM users WHERE role='admin' AND active AND id<>$1`, [row.id])).n) < 1) bad('Keep at least one active admin.');
    await q(`DELETE FROM sessions WHERE user_id=$1`, [row.id]); await q(`DELETE FROM users WHERE id=$1`, [row.id]);
    return json({ ok: true });
  }
  bad('Not found', 404);
}
function userFields(b) {
  const role = b.role === 'admin' ? 'admin' : 'member';
  const pages = role === 'admin' || !Array.isArray(b.pages) ? null : JSON.stringify(b.pages.filter(p => PAGES.includes(p)));
  const projects = role === 'admin' || !Array.isArray(b.projects) ? null : JSON.stringify(b.projects.map(String));
  const hide = JSON.stringify(role === 'admin' ? [] : (Array.isArray(b.hideFields) ? b.hideFields.filter(k => FIN_KEYS.includes(k)) : []));
  return { role, pages, projects, hide };
}
async function newRecovery() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', bytes = (await import('node:crypto')).randomBytes(16); let code = ''; for (const x of bytes) code += A[x % A.length];
  const { salt, hash } = await hashPw(code);
  await q(`INSERT INTO settings (k, v) VALUES ('recovery',$1) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v`, [JSON.stringify({ salt, hash })]);
  return code.match(/.{4}/g).join('-');
}

export async function handle(req) {
  const url = new URL(req.url);
  const path = (url.searchParams.get('__p') || url.pathname.replace(/^\/api\/?/, '')).replace(/^\/+|\/+$/g, '');
  const method = req.method.toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {   // basic CSRF guard: writes must come from this site
    const origin = req.headers.get('origin'); let oh = null; try { oh = origin && origin !== 'null' ? new URL(origin).host : null; } catch {}
    if (origin && oh !== url.host && !(origin === 'null' && /^p\/[A-Za-z0-9]+$/.test(path))) return json({ error: 'Blocked.' }, 403);
  }
  try { return await route(req, path, method); }
  catch (e) {
    const status = e.status || 500; if (status >= 500) console.error(e);
    return json({ error: status >= 500 && !e.code ? 'Something went wrong on the server.' : e.message, code: e.code }, status);
  }
}
export const GET = handle, POST = handle, PUT = handle, PATCH = handle, DELETE = handle;
