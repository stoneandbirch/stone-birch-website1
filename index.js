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
function gatePage(err, label) {
  return page(shell('Enter passcode', `<div class="h">Enter your passcode</div><div class="m">Your designer sent you a 4-digit code.</div>
<form method="post"><input name="pin" inputmode="numeric" maxlength="4" autocomplete="one-time-code" autofocus aria-label="Passcode"><div class="e">${htmlEsc(err || '')}</div><button type="submit">${htmlEsc(label || 'View my project')}</button></form>`), err ? 403 : 200);
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
  const qm = /^quote\/([A-Za-z0-9_-]{1,80})$/.exec(sub || ''), qid = qm ? qm[1] : '', isPage = !sub || !!qm, label = qm ? 'View my quote' : 'View my project';
  if (!link || !link.active || !link.html) return isPage ? inactivePage() : json({ error: 'This link is no longer active.' }, 404);
  if (isPage && method === 'POST') {   // passcode form
    if (link.locked_until && new Date(link.locked_until) > new Date()) return gatePage('Too many tries. Please wait 15 minutes.', label);
    const f = await readForm(req), pin = String(f.pin || '').replace(/\D/g, '');
    if (!link.pin || pin !== link.pin) {
      await q(`UPDATE portal_links SET fails=fails+1, locked_until=CASE WHEN fails+1>=8 THEN now()+interval '15 minutes' ELSE NULL END WHERE pid=$1`, [link.pid]);
      return gatePage('That code doesn\'t match.', label);
    }
    await q(`UPDATE portal_links SET fails=0, locked_until=NULL WHERE pid=$1`, [link.pid]);
    const secure = new URL(req.url).protocol === 'https:' || (req.headers.get('x-forwarded-proto') || '') === 'https';
    return new Response(null, { status: 303, headers: { location: '/p/' + token + (qid ? '/quote/' + qid : ''), 'cache-control': 'no-store', 'set-cookie': pinCookie(link.token, link.pin) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=7776000' + (secure ? '; Secure' : '') } });
  }
  if (!hasPin(req, link)) return isPage ? gatePage('', label) : json({ error: 'Please enter your passcode again.' }, 403);
  if (qm && (method === 'GET' || method === 'HEAD')) {
    const views = Array.isArray(link.views) ? link.views : [], last = views[views.length - 1];
    if (!last || Date.now() - new Date(last.at).getTime() > 10 * 60 * 1000) q(`UPDATE portal_links SET views=$2 WHERE pid=$1`, [link.pid, JSON.stringify([...views, { at: new Date().toISOString(), quote: qid }].slice(-30))]).catch(() => {});
    const r = await one(`SELECT html FROM portal_quotes WHERE pid=$1 AND qid=$2`, [link.pid, qid]);
    if (!r || !r.html) return page(shell('Quote not available', `<div class="h">This quote isn't available</div><div class="m">It may have been removed or replaced. You can still see everything on your project page.</div><p><a href="/p/${htmlEsc(token)}" style="color:#6d5e5f">Go to my project page →</a></p>`), 404);
    return page(r.html);
  }
  if (!sub && (method === 'GET' || method === 'HEAD')) {
    const views = Array.isArray(link.views) ? link.views : [], last = views[views.length - 1];
    if (!last || Date.now() - new Date(last.at).getTime() > 10 * 60 * 1000) q(`UPDATE portal_links SET views=$2 WHERE pid=$1`, [link.pid, JSON.stringify([...views, { at: new Date().toISOString() }].slice(-30))]).catch(() => {});
    return page(link.html);
  }
  const qs = /^qstate\/([A-Za-z0-9_-]{1,80})$/.exec(sub || '');
  if (qs && method === 'GET') {   // latest decisions, so a reopened quote page shows what the client already chose
    const doc = await one(`SELECT data FROM docs WHERE key=$1 AND NOT deleted`, ['project:' + link.pid]);
    const qt = doc && (doc.data.quotes || []).find(x => x.id === qs[1]); if (!qt) return json({ lines: {} });
    const lines = {}; (qt.lines || []).forEach(l => { if (l && l.id) lines[l.id] = l.approval === 'approved' ? 'a' : l.approval === 'declined' ? 'd' : 'p'; });
    return json({ lines, response: qt.clientResponse ? { by: qt.clientResponse.by || '', at: qt.clientResponse.at || '' } : null });
  }
  if (sub === 'reply' && method === 'POST') {
    if (!link.approve) bad('Approvals are turned off for this link — please contact your designer.', 403);
    const b = await body(req), a = parseCode(String(b.code || '').slice(0, 20000)); if (!a) bad('Something was missing from your decisions — please try again.');
    const number = await applyReply(link.pid, a);
    await notifyApproval(new URL(req.url).origin, link.pid, a);
    return json({ ok: true, quote: number });
  }
  bad('Not found', 404);
}

/* ── email (Resend): quotes to clients, approval alerts to the studio ── */
const EMAIL_DOMAIN = (process.env.EMAIL_DOMAIN || 'stoneandbirch.com').toLowerCase();
const emailOn = () => !!process.env.RESEND_API_KEY;
const LOGO_URL = o => o + '/api/email-logo.png';
async function settingsDoc() { const r = await one(`SELECT data FROM docs WHERE key='settings' AND NOT deleted`); return (r && r.data) || {}; }
function emailCfgOf(st) {
  const si = st.studioInfo || {}, c = si.emailCfg || {};
  let from = cleanEmail(c.fromAddr || 'studio@' + EMAIL_DOMAIN); if (!from.endsWith('@' + EMAIL_DOMAIN)) from = 'studio@' + EMAIL_DOMAIN;
  return { fromName: String(c.fromName || 'Stone + Birch').replace(/[<>"\r\n]/g, '').slice(0, 80), from, replyTo: emailOk(c.replyTo) ? cleanEmail(c.replyTo) : (emailOk(si.email) ? cleanEmail(si.email) : ''),
    alertTo: (Array.isArray(c.alertTo) ? c.alertTo : []).map(cleanEmail).filter(emailOk).slice(0, 10), alertSender: c.alertSender !== false, studio: si };
}
async function sendMail({ from, to, replyTo, subject, html, text, attachments }) {
  if (!emailOn()) bad('Email isn\'t set up yet — the RESEND_API_KEY is missing in Vercel.', 503);
  const r = await fetch(process.env.RESEND_API_URL || 'https://api.resend.com/emails', { method: 'POST', headers: { authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({ from, to, subject, html, text, ...(replyTo ? { reply_to: replyTo } : {}), ...(attachments && attachments.length ? { attachments } : {}) }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { console.error('resend', r.status, j); bad('The email service said: ' + (j.message || 'error ' + r.status), 502); }
  return j.id || '';
}
const E = htmlEsc, nl2br = s => E(s).replace(/\r?\n/g, '<br>');
const noLink = s => '<span class="nolink">' + E(s).replace(/(\d)/g, '$1&#8203;').replace(/ /g, ' &#8203;') + '</span>';
function mailFrame(o, inner, foot) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="format-detection" content="telephone=no,address=no,email=no,date=no"><style>a[x-apple-data-detectors],u+#sbm .nolink a,#sbm .nolink a{color:inherit!important;text-decoration:none!important;font-size:inherit!important;font-family:inherit!important;font-weight:inherit!important;line-height:inherit!important}</style></head><body id="sbm" style="margin:0;padding:0;background:#EFEFEB">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EFEFEB"><tr><td align="center" style="padding:28px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:4px;font-family:Helvetica,Arial,sans-serif;color:#4a4243">
<tr><td align="center" style="padding:30px 36px 18px;border-bottom:1px solid #ece8e3"><img src="${LOGO_URL(o)}" alt="STONE + BIRCH" width="190" style="display:block;width:190px;max-width:60%;height:auto;border:0"></td></tr>
${inner}
<tr><td align="center" style="padding:16px 20px 22px;font-size:11px;letter-spacing:.06em;color:#948684">${foot}</td></tr>
</table></td></tr></table></body></html>`;
}
const H1 = t => `<div style="font-family:Georgia,'Times New Roman',serif;font-size:28px;line-height:1.2;color:#39292A;margin:0 0 12px">${E(t)}</div>`;
const EYE = t => `<div style="font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:#948684;margin-bottom:6px">${E(t)}</div>`;
const sumRows = rows => `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #39292A;border-bottom:1px solid #e4dedb;margin:18px 0">${rows.filter(r => r[1]).map((r, i) =>
  `<tr><td style="padding:9px 0;${i ? 'border-top:1px solid #f0ece8;' : ''}font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#878282">${E(r[0])}</td><td align="right" style="padding:9px 0;${i ? 'border-top:1px solid #f0ece8;' : ''}font-size:14px;color:#312e2e">${E(r[1])}</td></tr>`).join('')}</table>`;
const cta = (href, t) => `<table role="presentation" align="center" cellpadding="0" cellspacing="0" style="margin:24px auto 10px"><tr><td style="background:#39292A;border-radius:2px"><a href="${E(href)}" style="display:inline-block;padding:13px 30px;font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:#FFFFFF!important;text-decoration:none;font-family:Helvetica,Arial,sans-serif;line-height:1.5"><span style="color:#FFFFFF">${E(t)}</span></a></td></tr></table>`;
const absImg = (o, s) => { s = String(s || ''); return /^https:\/\//.test(s) ? s : s.startsWith('/api/files/') ? o + s : ''; };

function quoteEmail(o, { cfg, pr, qt, link, b }) {
  const thumbs = (b.thumbs || []).map(s => absImg(o, s)).filter(Boolean).slice(0, 4);
  const si = cfg.studio, addr = String(si.address || '').toUpperCase();
  const inner = `<tr><td style="padding:28px 36px 8px">${EYE('Quote ' + qt.number)}${H1(b.headline || 'Your selections are ready to review')}
<div style="font-size:14.5px;line-height:1.6;margin:0 0 14px">${nl2br(b.message || '')}</div>
${thumbs.length ? `<table role="presentation" align="center" cellpadding="0" cellspacing="0" style="margin:18px auto 4px"><tr>${thumbs.map(s => `<td style="padding:0 4px"><img src="${E(s)}" width="76" height="76" alt="" style="display:block;width:76px;height:76px;object-fit:cover;border:1px solid #ece8e3"></td>`).join('')}</tr></table>` : ''}
${b.count ? `<div style="font-size:12px;color:#878282;text-align:center">${E(b.count + ' item' + (b.count === 1 ? '' : 's') + (b.areas ? ' · ' + b.areas : ''))}</div>` : ''}
${sumRows([['Project', pr.name || ''], ['Quote', qt.number + (qt.description ? ' · ' + qt.description : '')], ['Quote total', b.total || ''], ['Please respond by', b.respondBy || '']])}
${cta(link, 'Review & Approve')}
<div style="font-size:12px;color:#878282;text-align:center;line-height:1.5">${b.pin ? 'Your passcode is the one we shared with you. ' : ''}This link always shows your latest selections.</div></td></tr>
<tr><td style="padding:20px 36px 26px;border-top:1px solid #ece8e3;font-size:12.5px;line-height:1.55;color:#4a4243">${b.sigName ? `<div style="font-family:Georgia,serif;font-size:18px;color:#39292A">${E(b.sigName)}</div>` : ''}${b.sigTitle ? E(b.sigTitle) + '<br>' : ''}${E(si.name || 'Stone + Birch Interiors')}</td></tr>`;
  const text = `${b.message || ''}\n\nProject: ${pr.name || ''}\nQuote: ${qt.number}${qt.description ? ' · ' + qt.description : ''}${b.total ? '\nQuote total: ' + b.total : ''}${b.respondBy ? '\nPlease respond by: ' + b.respondBy : ''}\n\nReview & approve: ${link}\n\n${b.sigName || ''}\n${si.name || 'Stone + Birch Interiors'}${si.address ? '\n' + si.address : ''}`;
  return { html: mailFrame(o, inner, E(String(si.name || 'Stone + Birch Interiors').toUpperCase()) + (addr ? ' · ' + noLink(addr) : '')), text };
}
function alertEmail(o, { pr, qt, a, lines }) {
  const n = { a: 0, d: 0, p: 0 }; lines.forEach(x => n[x.st]++);
  const tag = st => st === 'a' ? ['Approved', '#3f6b4f', '#eef5f0', '#b8d1bf'] : st === 'd' ? ['Declined', '#a5554f', '#fbf2f1', '#e2bdb8'] : ['Undecided', '#7a6a50', '#f7f3ec', '#cbbfa8'];
  const box = (v, l, c) => `<td width="33%" align="center" style="border:1px solid #e4dedb;padding:10px 4px"><div style="font-family:Georgia,serif;font-size:26px;color:${c}">${v}</div><div style="font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:#878282">${l}</div></td>`;
  const shown = lines.slice(0, 12);
  const inner = `<tr><td style="padding:28px 36px 8px">${EYE('Client response')}${H1((a.by || 'Your client') + ' responded to ' + qt.number)}
<div style="font-size:14px;margin-bottom:14px">${E(pr.name || '')}${qt.description ? ' · ' + E(qt.description) : ''}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="6" style="margin:8px 0 14px"><tr>${box(n.a, 'Approved', '#3f6b4f')}${box(n.d, 'Declined', '#a5554f')}${box(n.p, 'Undecided', '#948684')}</tr></table>
${a.comment ? `<div style="border-left:2px solid #b9aeac;padding:6px 12px;margin:12px 0;color:#523e3f;font-style:italic;background:#faf8f6">“${E(a.comment)}”</div>` : ''}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${shown.map(x => { const t = tag(x.st); return `<tr><td style="padding:8px 0;border-bottom:1px solid #f0ece8;font-size:13px;color:#312e2e">${E(x.name)}${x.sub ? `<div style="font-size:11px;color:#948684">${E(x.sub)}</div>` : ''}</td><td align="right" style="padding:8px 0;border-bottom:1px solid #f0ece8"><span style="font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:2px 8px;border-radius:10px;border:1px solid ${t[3]};background:${t[2]};color:${t[1]};white-space:nowrap">${t[0]}</span></td></tr>`; }).join('')}
${lines.length > shown.length ? `<tr><td colspan="2" align="center" style="padding:8px 0;font-size:12px;color:#878282">+ ${lines.length - shown.length} more items</td></tr>` : ''}</table>
${cta(o + '/', 'Open Workspace')}
<div style="font-size:12px;color:#878282;text-align:center">The quote is already updated in the workspace.</div></td></tr>`;
  const text = `${a.by || 'Your client'} responded to ${qt.number} (${pr.name || ''})\nApproved ${n.a} · Declined ${n.d} · Undecided ${n.p}${a.comment ? '\n\n"' + a.comment + '"' : ''}\n\n${lines.map(x => (x.st === 'a' ? 'APPROVED  ' : x.st === 'd' ? 'DECLINED  ' : 'UNDECIDED ') + x.name).join('\n')}\n\n${o}/`;
  const subject = (n.a ? '✓ ' : '') + (a.by || 'Your client') + (n.a && !n.d && !n.p ? ' approved all ' + n.a + ' items' : n.a ? ' approved ' + n.a + ' of ' + lines.length + ' items' : ' responded') + ' — ' + qt.number + ', ' + (pr.name || '');
  return { html: mailFrame(o, inner, 'You get this because you\'re set to receive client approvals in Admin.'), text, subject, n };
}
async function notifyApproval(o, pid, a) {
  if (!emailOn()) return;
  try {
    const st = await settingsDoc(), cfg = emailCfgOf(st);
    const doc = await one(`SELECT data FROM docs WHERE key=$1 AND NOT deleted`, ['project:' + pid]); if (!doc) return;
    const pr = doc.data; let hit = null;
    for (const qt of (pr.quotes || [])) { const s = (qt.sendLog || []).find(x => x.token === a.token); if (s) { hit = { qt, s }; break; } }
    if (!hit) return;
    const to = new Set(cfg.alertTo);
    if (cfg.alertSender) { const e = [...(hit.qt.emailLog || [])].reverse().find(x => x.byEmail); if (e && emailOk(e.byEmail)) to.add(cleanEmail(e.byEmail)); }
    if (!to.size) return;
    const lines = hit.s.lineIds.map((id, i) => { const l = (hit.qt.lines || []).find(x => x.id === id); return l ? { name: String(l.name || 'Item'), sub: [l.specId || l.sid, l.location].filter(Boolean).join(' · '), st: a.states[i] || 'p' } : null; }).filter(Boolean);
    const m = alertEmail(o, { pr, qt: hit.qt, a, lines });
    await sendMail({ from: `Stone + Birch Workspace <workspace@${EMAIL_DOMAIN}>`, to: [...to], subject: m.subject, html: m.html, text: m.text });
  } catch (e) { console.error('approval alert failed', e && e.message); }
}
async function emailQuoteRoute(req, u) {
  const b = await body(req), pid = String(b.pid || ''), qid = String(b.qid || ''), o = new URL(req.url).origin;
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(pid) || !canProject(u, pid)) bad('You don\'t have access to that project.', 403);
  const doc = await one(`SELECT data FROM docs WHERE key=$1 AND NOT deleted`, ['project:' + pid]); if (!doc) bad('Save the project first, then try again.', 404);
  const pr = doc.data, qt = (pr.quotes || []).find(x => x.id === qid); if (!qt) bad('Save the quote first, then try again.', 409);
  const lk = await one(`SELECT token, active FROM portal_links WHERE pid=$1`, [pid]); if ((!lk || !lk.active) && !b.preview) bad('Turn on the client link for this project first.', 409);
  const qp = lk && lk.active ? await one(`SELECT 1 AS ok FROM portal_quotes WHERE pid=$1 AND qid=$2 AND html<>''`, [pid, qid]) : null;
  const link = o + '/p/' + (lk && lk.active ? lk.token + (qp ? '/quote/' + qid : '') : 'your-private-link');
  const to = [...new Set(String(b.to || '').split(/[,;\s]+/).map(cleanEmail).filter(Boolean))];
  if (!to.length || to.some(e => !emailOk(e))) bad('Check the client email address.'); if (to.length > 5) bad('Send to 5 addresses or fewer.');
  const cfg = emailCfgOf(await settingsDoc());
  const fields = { message: String(b.message || '').slice(0, 5000), headline: String(b.headline || '').slice(0, 120), total: String(b.total || '').slice(0, 40), respondBy: String(b.respondBy || '').slice(0, 60),
    count: Math.max(0, parseInt(b.count) || 0), areas: String(b.areas || '').slice(0, 120), thumbs: Array.isArray(b.thumbs) ? b.thumbs.slice(0, 4) : [], pin: !!b.pin,
    sigName: String(b.sigName || u.name || '').slice(0, 80), sigTitle: String(b.sigTitle || '').slice(0, 80) };
  const m = quoteEmail(o, { cfg, pr, qt, link, b: fields }), subject = String(b.subject || ('Your quote is ready — ' + (pr.name || ''))).replace(/[\r\n]+/g, ' ').slice(0, 200);
  if (b.preview) return json({ html: m.html, subject, from: `${cfg.fromName} <${cfg.from}>`, replyTo: cfg.replyTo || (emailOk(u.email) ? u.email : ''), on: emailOn() });
  const id = await sendMail({ from: `${cfg.fromName} <${cfg.from}>`, to, replyTo: cfg.replyTo || (emailOk(u.email) ? u.email : ''), subject, html: m.html, text: m.text });
  return json({ ok: true, id, to, link });
}
const EMAIL_LOGO = Buffer.from('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', 'base64');

/* ── proposals: published pages, acceptance, email ── */
const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,58}[a-z0-9])?$/;
async function propAlert(o, rec, a) {
  if (!emailOn()) return;
  try {
    const cfg = emailCfgOf(await settingsDoc()), to = new Set(cfg.alertTo); if (!to.size && cfg.replyTo) to.add(cfg.replyTo); if (!to.size) return;
    const inner = `<tr><td style="padding:28px 36px 8px">${EYE('Proposal accepted')}${H1((a.name || 'Your client') + ' accepted ' + (rec.title || 'the proposal'))}
${sumRows([['Proposal', rec.title || ''], ['Accepted by', a.name], ['Email', a.email], ['Phone', a.phone], ['Accepted on', new Date().toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'America/New_York' })]])}
${a.note ? `<div style="border-left:2px solid #b9aeac;padding:6px 12px;margin:12px 0;color:#523e3f;font-style:italic;background:#faf8f6">“${E(a.note)}”</div>` : ''}
${cta(o + '/', 'Open Workspace')}<div style="font-size:12px;color:#878282;text-align:center">The proposal is marked Accepted. Next: the Design Contract and retainer invoice.</div></td></tr>`;
    await sendMail({ from: `Stone + Birch Workspace <workspace@${EMAIL_DOMAIN}>`, to: [...to], subject: '✓ ' + (a.name || 'Your client') + ' accepted ' + (rec.title || 'the proposal'), html: mailFrame(o, inner, 'You get this because you\'re set to receive client approvals in Admin.'), text: (a.name || '') + ' accepted ' + (rec.title || '') + '\n' + (a.email || '') + (a.note ? '\n\n"' + a.note + '"' : '') });
    if (emailOk(a.email)) {
      const si = cfg.studio, inner2 = `<tr><td style="padding:28px 36px 8px">${EYE('Proposal accepted')}${H1('Thank you, ' + (a.name || '').split(' ')[0])}<div style="font-size:14.5px;line-height:1.6">We've received your acceptance of the ${E(rec.title || '')} proposal. Your contractual agreement and retainer invoice will follow shortly.</div>${a.link ? cta(a.link, 'View your proposal') : ''}</td></tr>`;
      await sendMail({ from: `${cfg.fromName} <${cfg.from}>`, to: [cleanEmail(a.email)], replyTo: cfg.replyTo || undefined, subject: 'Proposal accepted — ' + (rec.title || ''), html: mailFrame(o, inner2, E(String(si.name || 'Stone + Birch Interiors').toUpperCase())), text: 'Thank you. We received your acceptance of the ' + (rec.title || '') + ' proposal.' });
    }
  } catch (e) { console.error('proposal alert failed', e && e.message); }
}
async function propMarkAccepted(id, a) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const cur = await one(`SELECT data, version FROM docs WHERE key='proposals' AND NOT deleted`); if (!cur) return null;
    const data = cur.data, rec = (data.items || []).find(x => x.id === id); if (!rec) return null;
    rec.status = 'Accepted'; rec.accepted = { name: a.name, email: a.email, phone: a.phone, note: a.note, at: new Date().toISOString() };
    const up = await q(`UPDATE docs SET data=$1, version=version+1, seq=nextval('doc_seq'), updated_at=now(), updated_by='client' WHERE key='proposals' AND version=$2 RETURNING version`, [JSON.stringify(data), cur.version]);
    if (up.length) { await q(`INSERT INTO doc_history (key, version, data, updated_by) VALUES ('proposals',$1,$2,'client') ON CONFLICT DO NOTHING`, [up[0].version, JSON.stringify(data)]); return rec; }
  }
  return null;
}
const propHash = (salt, code) => createHash('sha256').update('pp:' + salt + ':' + code).digest('hex');
const propCookieName = slug => 'sbpr_' + slug.replace(/-/g, '_');
const propCookieVal = pg => createHash('sha256').update('ck:' + pg.pass_salt + ':' + pg.pass_hash).digest('hex').slice(0, 40);
function propUnlocked(req, pg) { if (!pg.pass_hash) return true; const c = req.headers.get('cookie') || ''; return c.split(/;\s*/).includes(propCookieName(pg.slug) + '=' + propCookieVal(pg)); }
function propGatePage(pg, err, kind) {
  const isCon = kind === 'contract';
  const g = pg.gate || {}, hero = /^https:\/\/[^\s"'<>()]+$/.test(g.hero || '') || /^\/api\/files\/[A-Za-z0-9_-]+$/.test(g.hero || '') ? g.hero : '';
  const studio = htmlEsc(String(g.studio || 'Stone + Birch').toUpperCase()), title = htmlEsc(isCon ? (pg.title || 'Your agreement') : (g.title || 'Your proposal'));
  const icon = /^data:image\/(png|jpeg|gif|webp|x-icon|vnd\.microsoft\.icon);base64,[A-Za-z0-9+\/=]+$/.test(g.icon || '') || /^https:\/\/[^\s"'<>()]+$/.test(g.icon || '') || /^\/api\/files\/[A-Za-z0-9_-]+$/.test(g.icon || '') ? g.icon : '';
  return page(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex, nofollow"><title>${title}${isCon ? ' · Design Agreement' : ''} · ${htmlEsc(g.studio || 'Stone + Birch')}</title>${icon ? `<link rel="icon" href="${htmlEsc(icon)}"><link rel="apple-touch-icon" href="${htmlEsc(icon)}">` : ''}
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box}html,body{margin:0;min-height:100%}body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px 22px;color:#fff;font:14px/1.5 'DM Sans',system-ui,sans-serif;
background:${hero ? `linear-gradient(rgba(57,41,42,.55),rgba(57,41,42,.72)),url("${htmlEsc(hero)}") center/cover no-repeat,#39292A` : '#39292A'}}
.lg{font-size:13px;letter-spacing:.32em;margin-bottom:34px}.ey{font-size:10.5px;letter-spacing:.24em;text-transform:uppercase;opacity:.85;margin-bottom:8px}
h1{font:400 clamp(32px,6vw,46px)/1.1 'Cormorant Garamond',Georgia,serif;margin:0 0 30px}
form{background:rgba(255,255,255,.97);color:#312e2e;border-radius:4px;padding:22px 22px 16px;width:100%;max-width:340px}
label{display:block;font-size:12.5px;color:#878282;margin-bottom:10px}
input{width:100%;height:54px;text-align:center;font:500 24px 'DM Sans',sans-serif;letter-spacing:.5em;padding-left:.5em;border:1px solid #cfc6c3;border-radius:3px;color:#39292A;margin-bottom:12px}
input:focus{outline:2px solid #39292A;outline-offset:-1px}
button{display:block;width:100%;border:none;background:#39292A;color:#fff;font:500 11.5px 'DM Sans',sans-serif;letter-spacing:.18em;text-transform:uppercase;padding:14px;border-radius:2px;cursor:pointer}
.e{color:#9b3b32;font-size:12.5px;min-height:18px;margin-top:8px}.h{font-size:11.5px;color:#878282;margin-top:2px}</style></head>
<body><div class="lg">${studio}</div><div class="ey">${isCon ? 'Design Agreement' : 'Proposal + Investment Guide'}</div><h1>${title}</h1>
<form method="post"><label for="pc">Enter the passcode from your email</label><input id="pc" name="pin" inputmode="numeric" pattern="[0-9]*" maxlength="8" autocomplete="one-time-code" autofocus required>
<button type="submit">${isCon ? 'View agreement' : 'View proposal'}</button><div class="e">${htmlEsc(err || '')}</div><div class="h">Can't find it? Reply to the email and we'll resend it.</div></form></body></html>`, err ? 403 : 200);
}
async function propPublicRoute(req, slug, sub, method) {
  const pg = SLUG_RE.test(slug) ? await one(`SELECT * FROM proposal_pages WHERE slug=$1`, [slug]) : null;
  if (!pg || !pg.active || !pg.html) return sub ? json({ error: 'This proposal is no longer available.' }, 404) : page(shell('Proposal not available', `<div class="h">This proposal isn't available</div><div class="m">Please contact your designer for an updated link.</div>`), 404);
  if (!sub && method === 'POST' && pg.pass_hash) {   // passcode form
    const ip = String(req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'local').split(',')[0].trim().slice(0, 64), tk = slug + '|' + ip;
    const tr = await one(`SELECT fails, locked_until FROM proposal_tries WHERE k=$1`, [tk]);
    if (tr && tr.locked_until && new Date(tr.locked_until) > new Date()) return propGatePage(pg, 'Too many tries. Please wait 15 minutes and try again.');
    const f = await readForm(req), pin = String(f.pin || '').replace(/\D/g, '').slice(0, 8);
    if (!pin || propHash(pg.pass_salt, pin) !== pg.pass_hash) {
      q(`DELETE FROM proposal_tries WHERE updated_at < now() - interval '2 days'`).catch(() => {});
      const r2 = await one(`INSERT INTO proposal_tries (k, fails, locked_until, updated_at) VALUES ($1, 1, NULL, now())
        ON CONFLICT (k) DO UPDATE SET fails=CASE WHEN proposal_tries.locked_until IS NOT NULL THEN 1 ELSE proposal_tries.fails+1 END, locked_until=CASE WHEN proposal_tries.locked_until IS NULL AND proposal_tries.fails+1>=5 THEN now()+interval '15 minutes' ELSE NULL END, updated_at=now() RETURNING fails, locked_until`, [tk]);
      return propGatePage(pg, r2 && r2.locked_until ? 'Too many tries. Please wait 15 minutes and try again.' : 'That code doesn\u2019t match. Please try again.');
    }
    await q(`DELETE FROM proposal_tries WHERE k=$1`, [tk]);
    const host = (req.headers.get('x-forwarded-host') || req.headers.get('host') || '').toLowerCase();
    const secure = new URL(req.url).protocol === 'https:' || (req.headers.get('x-forwarded-proto') || '') === 'https';
    return new Response(null, { status: 303, headers: { location: (host.startsWith('proposals.') ? '/' : '/proposals/') + slug, 'cache-control': 'no-store', 'set-cookie': propCookieName(slug) + '=' + propCookieVal(pg) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=15552000' + (secure ? '; Secure' : '') } });
  }
  if (!propUnlocked(req, pg)) return sub ? json({ error: 'Please enter your passcode again.' }, 403) : propGatePage(pg, '');
  if (!sub && (method === 'GET' || method === 'HEAD')) {
    const views = Array.isArray(pg.views) ? pg.views : [], last = views[views.length - 1];
    if (!last || Date.now() - new Date(last.at).getTime() > 10 * 60 * 1000) q(`UPDATE proposal_pages SET views=$2 WHERE slug=$1`, [slug, JSON.stringify([...views, { at: new Date().toISOString() }].slice(-30))]).catch(() => {});
    return page(pg.html);
  }
  if (sub === 'state' && method === 'GET') return json({ accepted: pg.accepted ? { name: pg.accepted.name, at: pg.accepted.at } : null });
  if (sub === 'accept' && method === 'POST') {
    const b = await body(req); if (b.website) return json({ ok: true });
    const a = { name: String(b.name || '').trim().slice(0, 120), email: cleanEmail(b.email).slice(0, 200), phone: String(b.phone || '').slice(0, 40), note: String(b.note || '').slice(0, 2000) };
    if (a.name.length < 2) bad('Please type your full name.'); if (!emailOk(a.email)) bad('Please enter a valid email address.'); if (!b.agreed) bad('Please check the box to accept the proposal.');
    if (pg.accepted) return json({ ok: true, already: true });
    await q(`UPDATE proposal_pages SET accepted=$2 WHERE slug=$1`, [slug, JSON.stringify({ ...a, at: new Date().toISOString() })]);
    const rec = await propMarkAccepted(pg.id, a) || { title: slug };
    a.link = String(b.link || '').slice(0, 300);
    await propAlert(new URL(req.url).origin, rec, a);
    return json({ ok: true });
  }
  bad('Not found', 404);
}
async function propStudioRoute(req, path, method) {
  const u = await need(req); if (!canPage(u, 'proposals')) bad('You don\'t have access to proposals.', 403);
  if (path === 'proposal-slug' && method === 'GET') {
    const sp = new URL(req.url).searchParams, slug = String(sp.get('slug') || ''), id = String(sp.get('id') || '');
    if (!SLUG_RE.test(slug)) return json({ ok: false, reason: 'Use lowercase letters, numbers and dashes.' });
    const r = await one(`SELECT id FROM proposal_pages WHERE slug=$1`, [slug]); return json({ ok: !r || r.id === id });
  }
  if (path === 'proposal-publish' && method === 'POST') {
    const b = await body(req), id = String(b.id || ''), slug = String(b.slug || ''), html = String(b.html || '');
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(id)) bad('Bad proposal.'); if (!SLUG_RE.test(slug)) bad('The link can only use lowercase letters, numbers and dashes.');
    if (html.length > 4_000_000) bad('This proposal page is too large to publish. Try smaller photos.');
    const code = String(b.passcode || '').trim(); if (code && !/^\d{4,8}$/.test(code)) bad('The passcode should be 4 to 8 numbers.');
    const gate = { title: String(b.gate && b.gate.title || '').slice(0, 160), studio: String(b.gate && b.gate.studio || '').slice(0, 80), hero: String(b.gate && b.gate.hero || '').slice(0, 500), icon: String(b.gate && b.gate.icon || '').slice(0, 60000) };
    const clash = await one(`SELECT id FROM proposal_pages WHERE slug=$1 AND id<>$2`, [slug, id]); if (clash) bad('That link is already used by another proposal.', 409);
    const prev = await one(`SELECT slug, accepted FROM proposal_pages WHERE id=$1 AND slug<>$2`, [id, slug]);
    const curPg = await one(`SELECT pass_hash, pass_salt FROM proposal_pages WHERE slug=$1`, [slug]);
    let salt = '', hash = '';
    if (code) { if (curPg && curPg.pass_hash && propHash(curPg.pass_salt, code) === curPg.pass_hash) { salt = curPg.pass_salt; hash = curPg.pass_hash; } else { salt = (await import('node:crypto')).randomBytes(16).toString('hex'); hash = propHash(salt, code); } }
    if (prev) await q(`DELETE FROM proposal_pages WHERE id=$1 AND slug<>$2`, [id, slug]);
    await q(`INSERT INTO proposal_pages (slug, id, html, active, accepted, updated_by, updated_at, pass_hash, pass_salt, gate) VALUES ($1,$2,$3,$4,$5,$6,now(),$7,$8,$9)
      ON CONFLICT (slug) DO UPDATE SET html=EXCLUDED.html, active=EXCLUDED.active, updated_by=EXCLUDED.updated_by, updated_at=now(), pass_hash=EXCLUDED.pass_hash, pass_salt=EXCLUDED.pass_salt, gate=EXCLUDED.gate`, [slug, id, html, b.on !== false, prev && prev.accepted ? JSON.stringify(prev.accepted) : null, u.id, hash, salt, JSON.stringify(gate)]);
    if (b.reset) await q(`UPDATE proposal_pages SET accepted_hist = COALESCE(accepted_hist,'[]'::jsonb) || CASE WHEN accepted IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(accepted) END, accepted=NULL WHERE slug=$1`, [slug]);
    const r = await one(`SELECT views, accepted FROM proposal_pages WHERE slug=$1`, [slug]);
    return json({ ok: true, views: r.views || [], accepted: r.accepted || null });
  }
  if (path === 'proposal-info' && method === 'GET') {
    const id = new URL(req.url).searchParams.get('id') || ''; const r = await one(`SELECT slug, active, views, accepted FROM proposal_pages WHERE id=$1`, [id]);
    return json(r || {});
  }
  if (path === 'email-proposal' && method === 'POST') {
    const b = await body(req), o = new URL(req.url).origin, slug = String(b.slug || '');
    const pg = SLUG_RE.test(slug) ? await one(`SELECT id, active, pass_hash, pass_salt FROM proposal_pages WHERE slug=$1`, [slug]) : null; if (!pg || !pg.active) bad('Publish the proposal first.', 409);
    const pcode = String(b.passcode || '').trim();
    if (pg.pass_hash && (!pcode || propHash(pg.pass_salt, pcode) !== pg.pass_hash)) bad('The passcode changed since the page was published. Click Update page, then send again.', 409);
    const showCode = pg.pass_hash ? pcode : '';
    let link = String(b.link || ''); if (!/^https:\/\/[^\s"<>]+$/.test(link) && !link.startsWith(o + '/')) link = o + '/proposals/' + slug; if (!link.endsWith('/' + slug)) link = o + '/proposals/' + slug;
    const to = [...new Set(String(b.to || '').split(/[,;\s]+/).map(cleanEmail).filter(Boolean))]; if (!to.length || to.some(e => !emailOk(e))) bad('Check the client email address.'); if (to.length > 5) bad('Send to 5 addresses or fewer.');
    const cfg = emailCfgOf(await settingsDoc()), si = cfg.studio;
    const label = String(b.button || 'View Your Proposal').slice(0, 120), msg = String(b.message || '').slice(0, 8000);
    let used = false, codeUsed = false;
    const PCODE = () => { codeUsed = true; return `<b style="display:inline-block;letter-spacing:.3em;font-size:17px;color:#39292A;background:#F4F1EE;padding:3px 10px 3px 13px;border-radius:2px">${E(showCode)}</b>`; };
    const codeLine = () => showCode && !/\{passcode\}/i.test(msg) ? `<div style="text-align:center;font-size:13px;color:#4a4243;margin:0 0 18px">Your passcode: ${PCODE()}</div>` : '';
    const blocks = msg.replace(/\r/g, '').split(/\n\s*\n/).map(x => x.trim()).filter(Boolean).map(bk => {
      if (/^\{button\}$/i.test(bk)) { used = true; return cta(link, label) + (codeLine() || '<div style="height:10px;line-height:10px">&nbsp;</div>'); }
      if (/^##\s+/.test(bk)) return `<div style="font-family:Georgia,'Times New Roman',serif;font-size:20px;color:#39292A;margin:22px 0 8px">${E(bk.replace(/^##\s+/, ''))}</div>`;
      return `<p style="margin:0 0 14px">${nl2br(bk).replace(/\{passcode\}/gi, () => showCode ? PCODE() : '').replace(/\{button\}/gi, () => { used = true; return `</p>${cta(link, label)}${codeLine()}<p style="margin:0 0 14px">`; })}</p>`;
    }).join('');
    const inner = `<tr><td style="padding:28px 36px 18px">${EYE('Proposal + Investment Guide')}${H1(String(b.title || 'Your proposal'))}<div style="font-size:14.5px;line-height:1.65;color:#4a4243">${blocks}</div>
${used ? '' : cta(link, label) + codeLine() + '<div style="font-size:12px;color:#878282;text-align:center">You can review everything and accept online.</div>'}</td></tr>`;
    const tCode = showCode && !/\{passcode\}/i.test(msg) ? '\nYour passcode: ' + showCode : '';
    b.message = msg.replace(/\{passcode\}/gi, showCode).replace(/\{button\}/gi, label + ': ' + link + tCode).replace(/^##\s+/gm, '');
    const subject = String(b.subject || ('Your proposal — ' + (b.title || ''))).replace(/[\r\n]+/g, ' ').slice(0, 200);
    if (b.preview) return json({ html: mailFrame(o, inner, E(String(si.name || 'Stone + Birch Interiors').toUpperCase()) + (si.address ? ' · ' + noLink(String(si.address).toUpperCase()) : '')), subject, from: `${cfg.fromName} <${cfg.from}>` });
    const id = await sendMail({ from: `${cfg.fromName} <${cfg.from}>`, to, replyTo: cfg.replyTo || (emailOk(u.email) ? u.email : ''), subject, html: mailFrame(o, inner, E(String(si.name || 'Stone + Birch Interiors').toUpperCase()) + (si.address ? ' · ' + noLink(String(si.address).toUpperCase()) : '')), text: (b.message || '') + (used ? '' : '\n\n' + label + ': ' + link + tCode) });
    return json({ ok: true, id, to, link });
  }
  bad('Not found', 404);
}

/* ── contracts: public signing pages ── */
const conUrl = (o, slug) => (/^https?:\/\/contracts\./i.test(o) ? o + '/' : o + '/contracts/') + slug;
const conCookieName = slug => 'sbct_' + slug.replace(/-/g, '_');
function conUnlocked(req, pg) { if (!pg.pass_hash) return true; const c = req.headers.get('cookie') || ''; return c.split(/;\s*/).includes(conCookieName(pg.slug) + '=' + propCookieVal(pg)); }
const reqIp = req => String(req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || 'local').split(',')[0].trim().slice(0, 64);
const reqUa = req => String(req.headers.get('user-agent') || '').slice(0, 300);
function uaShort(ua) { ua = ua || ''; const dev = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android' : /Macintosh/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : 'Browser';
  const br = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) && !/Chromium/.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : ''; return dev + (br ? ' · ' + br : ''); }
const maskIp = ip => /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip.split('.').slice(0, 2).join('.') + '.xx.xx' : ip.length > 12 ? ip.slice(0, 12) + '…' : ip;
async function conEvent(slug, ev) { await q(`UPDATE contract_pages SET events = COALESCE(events,'[]'::jsonb) || $2::jsonb WHERE slug=$1`, [slug, JSON.stringify([{ ...ev, at: ev.at || new Date().toISOString() }])]); }
function conPublicState(pg) {
  const sigs = (Array.isArray(pg.sigs) ? pg.sigs : []).map(s => ({ i: s.i, name: s.name, email: s.email || '', at: s.at, img: s.img || '' }));
  const n = (Array.isArray(pg.signers) ? pg.signers : []).length || 1, inv = pg.invoice && !pg.invoice.error ? pg.invoice : null;
  return { sigs, complete: !!pg.completed_at || sigs.length >= n, invoice: inv ? { num: inv.num || '', amount: inv.amount || 0, link: inv.sent && inv.link ? inv.link : '', paid: !!inv.paid, sent: !!inv.sent } : null };
}
async function conMarkDoc(id, fn) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const cur = await one(`SELECT data, version FROM docs WHERE key='contracts' AND NOT deleted`); if (!cur) return null;
    const data = cur.data, rec = (data.items || []).find(x => x.id === id); if (!rec) return null; fn(rec);
    const up = await q(`UPDATE docs SET data=$1, version=version+1, seq=nextval('doc_seq'), updated_at=now(), updated_by='client' WHERE key='contracts' AND version=$2 RETURNING version`, [JSON.stringify(data), cur.version]);
    if (up.length) { await q(`INSERT INTO doc_history (key, version, data, updated_by) VALUES ('contracts',$1,$2,'client') ON CONFLICT DO NOTHING`, [up[0].version, JSON.stringify(data)]); return rec; }
  }
  return null;
}
async function conRefreshPaid(pg) {
  const inv = pg.invoice; if (!inv || inv.error || inv.paid || !inv.id) return pg;
  if (inv.checkedAt && Date.now() - new Date(inv.checkedAt).getTime() < 60 * 1000) return pg;
  try { const j = await qboApi('GET', 'invoice/' + inv.id); const I = j.Invoice || {}; inv.checkedAt = new Date().toISOString();
    if (I.Balance === 0 || I.Balance === '0') { inv.paid = true; inv.paidAt = new Date().toISOString(); await conEvent(pg.slug, { t: 'paid', by: 'QuickBooks', detail: 'Invoice ' + (inv.num || '') + ' paid' });
      conMarkDoc(pg.id, r => { r.retainerPaid = new Date().toISOString().slice(0, 10); }).catch(() => {}); }
    await q(`UPDATE contract_pages SET invoice=$2 WHERE slug=$1`, [pg.slug, JSON.stringify(inv)]); pg.invoice = inv;
  } catch (e) { /* QuickBooks unreachable: keep the last known state */ }
  return pg;
}
function conCertHtml(pg) {
  // The client's certificate shows only the signing itself. Page views and retainer invoice/payment events stay in the workspace history.
  const CERT = ['studio-signed', 'sent', 'signed', 'completed'], ev = (Array.isArray(pg.events) ? pg.events : []).filter(e => CERT.includes(e.t)), fmt = t => new Date(t).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit', timeZone: 'America/New_York' });
  const lab = { 'studio-signed': 'Created and signed', sent: 'Sent for signature', opened: 'Opened', signed: 'Signed', completed: 'Completed', invoice: 'Retainer invoice', paid: 'Retainer paid' };
  const fp = String(pg.fingerprint || '').replace(/(.{4})/g, '$1 ').trim();
  return `<section class="wrap" style="padding:60px var(--gutter)"><span class="caps" style="color:var(--ink-soft)">Signing record</span><h2 style="margin:8px 0 6px">Certificate of Completion</h2>
<p style="color:var(--ink-soft);font-size:14px">This page is created automatically by Stone + Birch. It records who signed, when, and how, so there's a clear record that this exact document was agreed to.</p>
<table style="width:100%;border-collapse:collapse;font-size:13.5px;border-top:1px solid var(--plum);margin-top:14px">
<tr><td style="padding:8px 0;border-bottom:1px solid var(--rule);width:180px" class="caps">Document</td><td style="border-bottom:1px solid var(--rule)">${E(pg.title || '')} · Design Agreement</td></tr>
<tr><td style="padding:8px 0;border-bottom:1px solid var(--rule)" class="caps">Status</td><td style="border-bottom:1px solid var(--rule)">${pg.completed_at ? 'Completed · signed by all parties' : 'Signing in progress'}</td></tr>
<tr><td style="padding:8px 0;border-bottom:1px solid var(--rule)" class="caps">Document fingerprint</td><td style="border-bottom:1px solid var(--rule);font-family:Menlo,Consolas,monospace;font-size:11.5px;word-break:break-all">${fp ? 'SHA-256 ' + E(fp) : '—'}</td></tr>
</table>
<table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:22px"><thead><tr>${['Date & time (ET)', 'Event', 'By', 'Details'].map(h => `<th style="text-align:left;padding:6px 8px 6px 0;border-bottom:1px solid var(--plum)" class="caps">${h}</th>`).join('')}</tr></thead><tbody>
${ev.map(e => `<tr><td style="padding:7px 8px 7px 0;border-bottom:1px solid var(--rule);white-space:nowrap;vertical-align:top">${fmt(e.at)}</td><td style="padding:7px 8px 7px 0;border-bottom:1px solid var(--rule);vertical-align:top">${E(lab[e.t] || e.t)}</td><td style="padding:7px 8px 7px 0;border-bottom:1px solid var(--rule);vertical-align:top">${E(e.by === 'Workspace' ? 'The Studio' : (e.by || ''))}</td><td style="padding:7px 0;border-bottom:1px solid var(--rule);vertical-align:top">${E([e.email, e.detail, e.ua ? uaShort(e.ua) : '', e.ip ? 'IP ' + maskIp(e.ip) : ''].filter(Boolean).join(' · '))}</td></tr>`).join('')}
</tbody></table><p style="font-size:12px;color:var(--muted);margin-top:16px">Each party agreed that their electronic signature is the legal equivalent of their handwritten signature. Changing any part of this document after signing would change its fingerprint.</p></section>`;
}
function conGatePage(pg, err) { return propGatePage({ ...pg, gate: { ...(pg.gate || {}) } }, err, 'contract'); }
async function conPublicRoute(req, slug, sub, method) {
  let pg = SLUG_RE.test(slug) ? await one(`SELECT * FROM contract_pages WHERE slug=$1`, [slug]) : null;
  const isPage = !sub || sub === 'signed';
  if (!pg || !pg.active || !pg.html) return isPage ? page(shell('Contract not available', `<div class="h">This contract isn't available</div><div class="m">Please contact your designer for an updated link.</div>`), 404) : json({ error: 'This contract is no longer available.' }, 404);
  if (!sub && method === 'POST' && pg.pass_hash) {
    const ip = reqIp(req), tk = 'c:' + slug + '|' + ip;
    const tr = await one(`SELECT fails, locked_until FROM proposal_tries WHERE k=$1`, [tk]);
    if (tr && tr.locked_until && new Date(tr.locked_until) > new Date()) return conGatePage(pg, 'Too many tries. Please wait 15 minutes and try again.');
    const f = await readForm(req), pin = String(f.pin || '').replace(/\D/g, '').slice(0, 8);
    if (!pin || propHash(pg.pass_salt, pin) !== pg.pass_hash) {
      const r2 = await one(`INSERT INTO proposal_tries (k, fails, locked_until, updated_at) VALUES ($1, 1, NULL, now())
        ON CONFLICT (k) DO UPDATE SET fails=CASE WHEN proposal_tries.locked_until IS NOT NULL THEN 1 ELSE proposal_tries.fails+1 END, locked_until=CASE WHEN proposal_tries.locked_until IS NULL AND proposal_tries.fails+1>=5 THEN now()+interval '15 minutes' ELSE NULL END, updated_at=now() RETURNING fails, locked_until`, [tk]);
      return conGatePage(pg, r2 && r2.locked_until ? 'Too many tries. Please wait 15 minutes and try again.' : 'That code doesn’t match. Please try again.');
    }
    await q(`DELETE FROM proposal_tries WHERE k=$1`, [tk]);
    const secure = new URL(req.url).protocol === 'https:' || (req.headers.get('x-forwarded-proto') || '') === 'https';
    const chost = (req.headers.get('x-forwarded-host') || req.headers.get('host') || '').toLowerCase();
    return new Response(null, { status: 303, headers: { location: (chost.startsWith('contracts.') ? '/' : '/contracts/') + slug, 'cache-control': 'no-store', 'set-cookie': conCookieName(slug) + '=' + propCookieVal(pg) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=15552000' + (secure ? '; Secure' : '') } });
  }
  let studio = null; if (sub === 'signed') studio = await currentUser(req).catch(() => null);
  if (!conUnlocked(req, pg) && !studio) return isPage ? conGatePage(pg, '') : json({ error: 'Please enter your passcode again.' }, 403);
  if (!sub && (method === 'GET' || method === 'HEAD')) {
    const ev = Array.isArray(pg.events) ? pg.events : [], last = ev.filter(e => e.t === 'opened').slice(-1)[0];
    if (!last || Date.now() - new Date(last.at).getTime() > 10 * 60 * 1000) conEvent(slug, { t: 'opened', by: 'Client', ip: reqIp(req), ua: reqUa(req), detail: pg.pass_hash ? 'Passcode entered' : '' }).catch(() => {});
    return page(pg.html);
  }
  if (sub === 'signed' && method === 'GET') {
    pg = await conRefreshPaid(pg);
    const st = conPublicState(pg);
    let html = pg.html.replace('<script>(function(){var C=', '<script>window.__CS=' + JSON.stringify(st).replace(/</g, '\\u003c') + ';</script><script>(function(){var C=').replace('<div class="cert" id="cert"></div>', `<div class="cert" id="cert" style="display:block">${conCertHtml(pg)}</div>`);
    html = html.replace('</body>', `<style>.sline .form,.top nav a.sign{display:none!important}</style><div class="noprint" style="position:fixed;right:18px;bottom:18px;z-index:60;display:flex;gap:8px;align-items:center;background:#fff;border:1px solid #d8d6d5;padding:8px 10px;box-shadow:0 6px 20px rgba(57,41,42,.15)"><span style="font:12.5px Inter,Arial;color:#6d5e5f">${st.complete ? 'Signed copy' : 'Not fully signed yet'}</span><button onclick="print()" style="background:#39292A;color:#fff;border:none;padding:10px 16px;font:400 11px Jost,Arial;letter-spacing:.2em;text-transform:uppercase;cursor:pointer">Save as PDF</button></div></body>`);
    return page(html);
  }
  if (sub === 'state' && method === 'GET') { pg = await conRefreshPaid(pg); return json(conPublicState(pg)); }
  if (sub === 'sign' && method === 'POST') {
    const b = await body(req), signers = Array.isArray(pg.signers) ? pg.signers : [], i = +b.i;
    if (!Number.isInteger(i) || i < 0 || i >= Math.max(1, signers.length)) bad('Please reload the page and try again.');
    const name = String(b.name || '').replace(/\s+/g, ' ').trim().slice(0, 120); if (name.length < 2) bad('Please type your full name.');
    if (!b.agreed) bad('Please check the box to agree before signing.');
    const type = b.type === 'draw' ? 'draw' : 'type', img = type === 'draw' ? String(b.img || '') : '';
    if (type === 'draw' && (!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(img) || img.length > 400000)) bad('Please draw your signature again.');
    const sigs = Array.isArray(pg.sigs) ? pg.sigs : []; if (sigs.some(s => s.i === i)) return json({ ok: true, state: conPublicState(pg) });
    const fp = pg.fingerprint || createHash('sha256').update(pg.html).digest('hex');
    const sig = { i, name, email: cleanEmail((signers[i] || {}).email || ''), type, img, at: new Date().toISOString(), ip: reqIp(req), ua: reqUa(req) };
    const all = sigs.concat([sig]), complete = all.length >= Math.max(1, signers.length);
    await q(`UPDATE contract_pages SET sigs=$2, fingerprint=$3, completed_at=CASE WHEN $4 THEN now() ELSE completed_at END WHERE slug=$1`, [slug, JSON.stringify(all), fp, complete]);
    await conEvent(slug, { t: 'signed', by: name, email: sig.email, ip: sig.ip, ua: sig.ua, detail: (type === 'draw' ? 'drawn signature' : 'typed signature') + ' · agreed to sign electronically' });
    if (complete) await conEvent(slug, { t: 'completed', by: 'The Studio', detail: 'Signed copy emailed to all parties' });
    await conMarkDoc(pg.id, r => { if (complete) { r.status = 'Signed'; r.signed = new Date().toISOString().slice(0, 10); } r.signedBy = all.map(s => s.name).join(', '); }).catch(() => {});
    pg = await one(`SELECT * FROM contract_pages WHERE slug=$1`, [slug]);
    const o = new URL(req.url).origin;
    if (complete && pg.pay && pg.pay.mode === 'workspace') {
      try { let inv = await qboContractInvoice(pg); if (pg.pay.auto !== 'draft') inv = await conSendRetainer(o, pg, inv); pg.invoice = inv; await q(`UPDATE contract_pages SET invoice=$2 WHERE slug=$1`, [slug, JSON.stringify(inv)]);
        await conEvent(slug, { t: 'invoice', by: 'QuickBooks', detail: 'Invoice ' + (inv.num || '') + ' for $' + (+inv.amount || 0).toFixed(2) + (inv.sent ? ' emailed to the client' + (inv.via === 'quickbooks' ? ' from QuickBooks' : '') : ' created as a draft') }); }
      catch (e) { console.error('qbo invoice failed', e && e.message); pg.invoice = { error: String(e && e.message || e).slice(0, 300) }; await q(`UPDATE contract_pages SET invoice=$2 WHERE slug=$1`, [slug, JSON.stringify(pg.invoice)]); }
    }
    await conAlert(o, pg, sig, complete).catch(e => console.error('contract alert failed', e && e.message));
    return json({ ok: true, state: conPublicState(pg) });
  }
  bad('Not found', 404);
}
const RET_EMAIL = { subject: 'Your design retainer · {project} Design Agreement', title: 'Welcome to Stone + Birch', button: 'View & Pay Retainer',
  msg: "Dear {first_name},\n\nThank you for trusting us with your home. We're so happy to officially welcome you, and we can't wait to start bringing your vision for {project} to life.\n\nTo get started, we've included your design retainer below. It's applied toward the design services in your Scope of Work, so it goes straight into the work ahead.\n\n{invoice_details}\n\n{button}\n\n## What happens next\n\nOnce your retainer arrives, we'll reach out within 3 days to schedule your kickoff meeting. That's where we'll walk through your space, talk about how you live, and start shaping the design together.\n\nWith gratitude,\n{signature}" };
// The first version of the default retainer email, if still unedited, is swapped for the current default.
const retOldDefault = m => /Thank you for signing your \{project\} Design Agreement\. We're so excited to begin\./.test(m) && /Once your retainer is received, we'll reach out to schedule your kickoff meeting and begin measuring and planning\./.test(m) && m.split(/\n\s*\n/).length <= 10;
function retTpl(st, pg) { const d = (((st.studioInfo || {}).conCfg) || {}).invEmail || {}, c = (pg.pay && pg.pay.email) || {}, pick = k => { const v = String(c[k] || d[k] || RET_EMAIL[k]); return k === 'msg' && retOldDefault(v) ? RET_EMAIL.msg : v; };
  const z = String((((st.studioInfo || {}).conCfg) || {}).zelle || '').trim(), dg = (((st.studioInfo || {}).propBrand) || {}).designer || {}, dn = String(dg.name || '').trim();
  return { subject: pick('subject'), title: pick('title'), button: pick('button'), msg: pick('msg'), zelle: emailOk(z) ? z : '', designer: dn.split(/\s+/)[0] || 'Stone + Birch', designerName: dn || 'Stone + Birch Interiors', designerTitle: String(dg.title || '').trim() }; }
function retEmail(o, cfg, pg, inv, tpl) {
  const signers = Array.isArray(pg.signers) ? pg.signers : [], firsts = signers.map(s => String(s.name || '').trim().split(/\s+/)[0]).filter(Boolean);
  const first = firsts.length > 1 ? firsts.slice(0, -1).join(', ') + ' and ' + firsts[firsts.length - 1] : (firsts[0] || 'there');
  const money = '$' + (+inv.amount || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }), num = String(inv.num || ''), pay = pg.pay || {};
  // {zelle_email} comes from Contract templates → Letter & email. With no address set, any paragraph that uses it is left out.
  const ZE = /\{zelle[_ ]email\}/i, zelle = String(tpl.zelle || '');
  tpl = { ...tpl, msg: zelle ? String(tpl.msg || '') : String(tpl.msg || '').replace(/\r/g, '').split(/\n\s*\n/).filter(p => !ZE.test(p)).join('\n\n') };
  const fill = t => String(t || '').replace(/\{first[_ ]names?\}/gi, first).replace(/\{project\}/gi, pg.title || '').replace(/\{amount\}/gi, money).replace(/\{invoice[_ ]number\}/gi, num).replace(/\{zelle[_ ]email\}/gi, zelle).replace(/\{designer[_ ]first\}/gi, tpl.designer || 'Stone + Birch');
  const rows = [['Project', pg.title || ''], ['Invoice', num ? 'No. ' + num : ''], ['Design retainer', money], ['Due', 'Upon receipt']];
  const how = [pay.ach !== false ? 'bank transfer' : '', pay.card ? 'card' : ''].filter(Boolean).join(' or ');
  const note = `<div style="font-size:12px;color:#878282;text-align:center;line-height:1.5;margin:0 0 22px">${how ? 'Pay securely by ' + how + ' through QuickBooks.<br>' : ''}Your invoice is attached as a PDF.</div>`;
  const btn = () => cta(inv.link, fill(tpl.button)) + note;
  const sig = `<div style="font-family:Georgia,'Times New Roman',serif;font-size:22px;line-height:1.2;color:#39292A;margin:4px 0 4px">${E(tpl.designerName || 'Stone + Birch Interiors')}</div>${tpl.designerTitle ? `<div style="font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:#948684">${E(tpl.designerTitle)}</div>` : ''}`;
  const P = h => `<p style="margin:0 0 14px">${h}</p>`, SPECIAL = /\{(button|invoice[_ ]details|signature)\}/i;
  let usedB = false, usedD = false, box = null; const out = [];
  const inline = bk => P(nl2br(bk).replace(/\{button\}/gi, () => { usedB = true; return '</p>' + btn() + '<p style="margin:0 0 14px">'; }).replace(/\{invoice[_ ]details\}/gi, () => { usedD = true; return '</p>' + sumRows(rows) + '<p style="margin:0 0 14px">'; }).replace(/(<br>\s*)?\{signature\}/gi, () => '</p>' + sig + '<p style="margin:0">')).replace(/<p style="margin:0(?: 0 14px)?"><\/p>/g, '');
  const closeBox = () => { if (box) { out.push(`<div style="background:#F6F4F2;padding:22px 24px 10px;margin:6px 0 24px">${box.join('')}</div>`); box = null; } };
  fill(tpl.msg).replace(/\r/g, '').split(/\n\s*\n/).map(x => x.trim()).filter(Boolean).forEach(bk => {
    if (/^##\s+/.test(bk)) { closeBox(); box = [`<div style="font-family:Georgia,'Times New Roman',serif;font-size:20px;color:#39292A;margin:0 0 10px">${E(bk.replace(/^##\s+/, ''))}</div>`]; return; }
    if (SPECIAL.test(bk)) closeBox();
    if (/^\{button\}$/i.test(bk)) { usedB = true; out.push(btn()); return; }
    if (/^\{invoice[_ ]details\}$/i.test(bk)) { usedD = true; out.push(sumRows(rows)); return; }
    (box || out).push(inline(bk));
  });
  closeBox();
  const inner = `<tr><td style="padding:28px 36px 22px">${EYE((num ? 'Invoice ' + num + ' · ' : '') + 'Design retainer')}${H1(fill(tpl.title))}<div style="font-size:14.5px;line-height:1.65;color:#4a4243">${usedD ? '' : sumRows(rows)}${out.join('')}</div>${usedB ? '' : btn()}</td></tr>`;
  const tRows = rows.filter(r => r[1]).map(r => r[0] + ': ' + r[1]).join('\n');
  let text = fill(tpl.msg).replace(/\{invoice[_ ]details\}/gi, tRows).replace(/\{button\}/gi, fill(tpl.button) + ': ' + inv.link).replace(/\{signature\}/gi, (tpl.designerName || 'Stone + Birch Interiors') + (tpl.designerTitle ? '\n' + tpl.designerTitle : '')).replace(/^##\s+/gm, '');
  if (!usedB) text += '\n\n' + fill(tpl.button) + ': ' + inv.link;
  const si = cfg.studio;
  return { subject: fill(tpl.subject).replace(/[\r\n]+/g, ' ').slice(0, 200), html: mailFrame(o, inner, E(String(si.name || 'Stone + Birch Interiors').toUpperCase()) + (si.address ? ' · ' + noLink(String(si.address).toUpperCase()) : '')), text };
}
async function qboPdf(id) {
  const s = await qboToken(), url = QBO_API() + '/v3/company/' + encodeURIComponent(s.realm) + '/invoice/' + encodeURIComponent(id) + '/pdf?minorversion=75';
  const r = await fetch(url, { headers: { authorization: 'Bearer ' + s.tok.access, accept: 'application/pdf' } }); if (!r.ok) throw new Error('pdf ' + r.status);
  const b = Buffer.from(await r.arrayBuffer()); if (b.length < 100 || b.length > 8_000_000) throw new Error('pdf size'); return b.toString('base64');
}
// Emails the retainer invoice in the studio's own style. Falls back to QuickBooks' own email if that isn't possible.
async function conSendRetainer(o, pg, inv) {
  const to = cleanEmail(((pg.signers || [])[0] || {}).email); if (!emailOk(to)) return inv;
  const viaQbo = async () => { try { await qboApi('POST', 'invoice/' + inv.id + '/send?sendTo=' + encodeURIComponent(to), null); return { ...inv, sent: true, via: 'quickbooks' }; } catch (e) { console.error('qbo send failed', e && e.message); return inv; } };
  if (!emailOn() || !inv.link) return viaQbo();
  try {
    const st = await settingsDoc(), cfg = emailCfgOf(st), m = retEmail(o, cfg, pg, inv, retTpl(st, pg));
    let attachments = []; try { attachments = [{ filename: 'Invoice ' + (inv.num || inv.id) + ' - Stone + Birch.pdf', content: await qboPdf(inv.id) }]; } catch (e) { console.error('qbo pdf failed', e && e.message); }
    const cc = [...new Set((pg.signers || []).slice(1).map(s => cleanEmail(s.email)).filter(e => emailOk(e) && e !== to))];
    await sendMail({ from: `${cfg.fromName} <${cfg.from}>`, to: [to, ...cc], replyTo: cfg.replyTo || undefined, subject: m.subject, html: m.html, text: m.text, attachments });
    return { ...inv, sent: true, via: 'workspace' };
  } catch (e) { console.error('retainer email failed', e && e.message); return viaQbo(); }
}
async function conAlert(o, pg, sig, complete) {
  if (!emailOn()) return;
  const cfg = emailCfgOf(await settingsDoc()), to = new Set(cfg.alertTo); if (!to.size && cfg.replyTo) to.add(cfg.replyTo);
  const inv = pg.invoice, link = conUrl(o, pg.slug), money = v => '$' + (+v || 0).toLocaleString('en-US', { minimumFractionDigits: 2 });
  const payLine = !complete ? '' : inv && !inv.error ? `Retainer invoice ${inv.num || ''} for ${money(inv.amount)} ${inv.sent ? 'was emailed to the client.' : 'is waiting in QuickBooks as a draft. Send it from the contract in the workspace.'}` : inv && inv.error ? 'The QuickBooks invoice couldn\'t be created (' + inv.error + '). Please send the retainer invoice yourself.' : 'Next: send the retainer invoice.';
  if (to.size) {
    const inner = `<tr><td style="padding:28px 36px 8px">${EYE(complete ? 'Contract signed' : 'Contract signature')}${H1(sig.name + ' signed ' + (pg.title || 'the contract'))}
${sumRows([['Contract', (pg.title || '') + ' · Design Agreement'], ['Signed by', sig.name], ['Email', sig.email], ['Signed on', new Date().toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'America/New_York' })], ['Status', complete ? 'Fully signed' : 'Waiting for the other signer']])}
${payLine ? `<div style="font-size:14px;line-height:1.6;margin:12px 0">${E(payLine)}</div>` : ''}${cta(link + '/signed', 'View signed copy')}</td></tr>`;
    await sendMail({ from: `Stone + Birch Workspace <workspace@${EMAIL_DOMAIN}>`, to: [...to], subject: '✓ ' + sig.name + ' signed ' + (pg.title || 'the contract'), html: mailFrame(o, inner, 'You get this because you\'re set to receive client approvals in Admin.'), text: sig.name + ' signed ' + (pg.title || '') + '. ' + payLine + ' ' + link + '/signed' });
  }
  if (complete) {
    const sigs = Array.isArray(pg.sigs) ? pg.sigs : [], emails = [...new Set(sigs.map(s => cleanEmail(s.email)).filter(emailOk))];
    if (emails.length) { const si = cfg.studio;
      const code = pg.pass_hash && /^\d{4,8}$/.test(String(pg.pass_code || '')) && propHash(pg.pass_salt, String(pg.pass_code)) === pg.pass_hash ? String(pg.pass_code) : '';
      const codeLine = code ? `<div style="text-align:center;font-size:13px;color:#4a4243;margin:0 0 18px">Your passcode: <b style="display:inline-block;letter-spacing:.3em;font-size:17px;color:#39292A;background:#F4F1EE;padding:3px 10px 3px 13px;border-radius:2px">${E(code)}</b></div>` : '';
      const how = !pg.pass_hash ? ' below' : code ? ' and passcode below' : ' below and the same passcode as before';
      const inner2 = `<tr><td style="padding:28px 36px 8px">${EYE('Design Agreement signed')}${H1('Thank you, it\'s official')}<div style="font-size:14.5px;line-height:1.6">Your ${E(pg.title || '')} Design Agreement is fully signed. You can view or save your signed copy anytime using the button${how}.${inv && !inv.error && inv.sent ? '<br><br>Your design retainer invoice has been emailed to you separately.' : '<br><br>Your design retainer invoice will follow shortly.'}</div>${cta(link + '/signed', 'View your signed agreement')}${codeLine}</td></tr>`;
      await sendMail({ from: `${cfg.fromName} <${cfg.from}>`, to: emails, replyTo: cfg.replyTo || undefined, subject: 'Signed — ' + (pg.title || '') + ' Design Agreement', html: mailFrame(o, inner2, E(String(si.name || 'Stone + Birch Interiors').toUpperCase()) + (si.address ? ' · ' + noLink(String(si.address).toUpperCase()) : '')), text: 'Your Design Agreement is fully signed. View your signed copy: ' + link + '/signed' + (code ? '\nYour passcode: ' + code : '') });
    }
  }
}
function msgEmail(o, cfg, b, link, showCode, eyebrow) {
  const label = String(b.button || 'View').slice(0, 120), msg = String(b.message || '').slice(0, 8000); let used = false;
  const PCODE = () => `<b style="display:inline-block;letter-spacing:.3em;font-size:17px;color:#39292A;background:#F4F1EE;padding:3px 10px 3px 13px;border-radius:2px">${E(showCode)}</b>`;
  const codeLine = () => showCode && !/\{passcode\}/i.test(msg) ? `<div style="text-align:center;font-size:13px;color:#4a4243;margin:0 0 18px">Your passcode: ${PCODE()}</div>` : '';
  const blocks = msg.replace(/\r/g, '').split(/\n\s*\n/).map(x => x.trim()).filter(Boolean).map(bk => {
    if (/^\{button\}$/i.test(bk)) { used = true; return cta(link, label) + (codeLine() || '<div style="height:10px;line-height:10px">&nbsp;</div>'); }
    if (/^##\s+/.test(bk)) return `<div style="font-family:Georgia,'Times New Roman',serif;font-size:20px;color:#39292A;margin:22px 0 8px">${E(bk.replace(/^##\s+/, ''))}</div>`;
    return `<p style="margin:0 0 14px">${nl2br(bk).replace(/\{passcode\}/gi, () => showCode ? PCODE() : '').replace(/\{button\}/gi, () => { used = true; return `</p>${cta(link, label)}${codeLine()}<p style="margin:0 0 14px">`; })}</p>`;
  }).join('');
  const inner = `<tr><td style="padding:28px 36px 18px">${EYE(eyebrow)}${H1(String(b.title || ''))}<div style="font-size:14.5px;line-height:1.65;color:#4a4243">${blocks}</div>${used ? '' : cta(link, label) + codeLine()}</td></tr>`;
  const tCode = showCode && !/\{passcode\}/i.test(msg) ? '\nYour passcode: ' + showCode : '';
  const text = msg.replace(/\{passcode\}/gi, showCode).replace(/\{button\}/gi, label + ': ' + link + tCode).replace(/^##\s+/gm, '') + (used ? '' : '\n\n' + label + ': ' + link + tCode);
  const si = cfg.studio; return { html: mailFrame(o, inner, E(String(si.name || 'Stone + Birch Interiors').toUpperCase()) + (si.address ? ' · ' + noLink(String(si.address).toUpperCase()) : '')), text };
}
async function conStudioRoute(req, path, method) {
  const u = await need(req); if (!canPage(u, 'contracts')) bad('You don\'t have access to contracts.', 403);
  const o = new URL(req.url).origin;
  if (path === 'contract-slug' && method === 'GET') {
    const sp = new URL(req.url).searchParams, slug = String(sp.get('slug') || ''), id = String(sp.get('id') || '');
    if (!SLUG_RE.test(slug)) return json({ ok: false }); const r = await one(`SELECT id FROM contract_pages WHERE slug=$1`, [slug]); return json({ ok: !r || r.id === id });
  }
  if (path === 'contract-publish' && method === 'POST') {
    const b = await body(req), id = String(b.id || ''), slug = String(b.slug || ''), html = String(b.html || '');
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(id)) bad('Bad contract.'); if (!SLUG_RE.test(slug)) bad('The link can only use lowercase letters, numbers and dashes.');
    if (html.length > 4_000_000) bad('This contract page is too large to publish. Try a smaller cover photo.');
    const code = String(b.passcode || '').trim(); if (code && !/^\d{4,8}$/.test(code)) bad('The passcode should be 4 to 8 numbers.');
    const clash = await one(`SELECT id FROM contract_pages WHERE slug=$1 AND id<>$2`, [slug, id]); if (clash) bad('That link is already used by another contract.', 409);
    const mine = await q(`SELECT slug, sigs FROM contract_pages WHERE id=$1`, [id]);
    if (mine.some(r => Array.isArray(r.sigs) && r.sigs.length)) bad('This contract has been signed, so it can\'t be changed.', 409);
    await q(`DELETE FROM contract_pages WHERE id=$1 AND slug<>$2`, [id, slug]);
    const cur = await one(`SELECT pass_hash, pass_salt, events FROM contract_pages WHERE slug=$1`, [slug]);
    let salt = '', hash = '';
    if (code) { if (cur && cur.pass_hash && propHash(cur.pass_salt, code) === cur.pass_hash) { salt = cur.pass_salt; hash = cur.pass_hash; } else { salt = (await import('node:crypto')).randomBytes(16).toString('hex'); hash = propHash(salt, code); } }
    const g = b.gate || {}, gate = { title: String(g.title || '').slice(0, 160), studio: String(g.studio || '').slice(0, 80), hero: String(g.hero || '').slice(0, 500), icon: String(g.icon || '').slice(0, 60000) };
    const signers = (Array.isArray(b.signers) ? b.signers : []).slice(0, 4).map(s => ({ name: String(s.name || '').slice(0, 120), email: cleanEmail(s.email).slice(0, 200) })).filter(s => s.name);
    if (!signers.length) bad('Add the client who signs.');
    const p = b.pay || {}, pay = { mode: p.mode === 'workspace' ? 'workspace' : 'manual', popup: p.popup !== false, auto: p.auto === 'draft' ? 'draft' : 'send', ach: p.ach !== false, card: !!p.card, amount: Math.max(0, Math.round((+p.amount || 0) * 100) / 100), billAddr: String(p.billAddr || '').replace(/[\r\n]+/g, ', ').slice(0, 300) };
    if (p.email && typeof p.email === 'object') { const pe = p.email, cut = (v, n) => String(v || '').slice(0, n); pay.email = { subject: cut(pe.subject, 200), title: cut(pe.title, 160), button: cut(pe.button, 60), msg: cut(pe.msg, 8000) }; }
    // pass_code keeps the passcode so the "fully signed" email can remind the client of it.
    await q(`INSERT INTO contract_pages (slug, id, html, active, title, signers, pay, gate, pass_hash, pass_salt, pass_code, updated_by, updated_at) VALUES ($1,$2,$3,true,$4,$5,$6,$7,$8,$9,$11,$10,now())
      ON CONFLICT (slug) DO UPDATE SET html=EXCLUDED.html, active=true, title=EXCLUDED.title, signers=EXCLUDED.signers, pay=EXCLUDED.pay, gate=EXCLUDED.gate, pass_hash=EXCLUDED.pass_hash, pass_salt=EXCLUDED.pass_salt, pass_code=EXCLUDED.pass_code, updated_by=EXCLUDED.updated_by, updated_at=now()`,
      [slug, id, html, String(b.title || '').slice(0, 160), JSON.stringify(signers), JSON.stringify(pay), JSON.stringify(gate), hash, salt, u.id, code]);
    const evs = (cur && Array.isArray(cur.events)) ? cur.events : [];
    if (b.studioSig && !evs.some(e => e.t === 'studio-signed')) await conEvent(slug, { t: 'studio-signed', by: String(b.studioSig.name || u.name || '').slice(0, 120), email: u.email, detail: 'typed signature', ip: reqIp(req), ua: reqUa(req) });
    return json(await conInfo(slug));
  }
  if (path === 'retainer-preview' && method === 'POST') {
    const b = await body(req), st = await settingsDoc(), cfg = emailCfgOf(st), t = b.tpl || {};
    const pg = { title: String(b.title || 'Sample Project').slice(0, 160), signers: (Array.isArray(b.signers) && b.signers.length ? b.signers : [{ name: 'Jane Client' }]).slice(0, 4), pay: { ach: b.ach !== false, card: !!b.card, email: { subject: t.subject, title: t.title, button: t.button, msg: t.msg } } };
    const m = retEmail(o, cfg, pg, { num: '1043', amount: +b.amount || 5000, link: '#' }, retTpl(st, pg));
    return json({ html: m.html, subject: m.subject, from: `${cfg.fromName} <${cfg.from}>` });
  }
  if (path === 'contract-info' && method === 'GET') {
    const id = new URL(req.url).searchParams.get('id') || ''; const r = await one(`SELECT slug FROM contract_pages WHERE id=$1`, [id]); return json(r ? await conInfo(r.slug) : {});
  }
  if (path === 'contract-invoice-send' && method === 'POST') {
    const b = await body(req); const pg = await one(`SELECT * FROM contract_pages WHERE id=$1`, [String(b.id || '')]); if (!pg || !pg.invoice || !pg.invoice.id) bad('There\'s no invoice to send yet.', 409);
    const to = cleanEmail(((pg.signers || [])[0] || {}).email); if (!emailOk(to)) bad('Add the client\'s email to the contract first.');
    let inv = { ...pg.invoice }; try { inv.link = await qboInvoiceLink(inv.id) || inv.link; } catch (e) {}
    inv = await conSendRetainer(o, pg, inv); if (!inv.sent) bad('The invoice email didn\'t go through. Try again, or send it from QuickBooks.', 502);
    await q(`UPDATE contract_pages SET invoice=$2 WHERE slug=$1`, [pg.slug, JSON.stringify(inv)]); await conEvent(pg.slug, { t: 'invoice', by: u.name || 'Studio', detail: 'Invoice ' + (inv.num || '') + ' emailed to the client' + (inv.via === 'quickbooks' ? ' from QuickBooks' : '') });
    return json(await conInfo(pg.slug));
  }
  if (path === 'email-contract' && method === 'POST') {
    const b = await body(req), slug = String(b.slug || '');
    const pg = SLUG_RE.test(slug) ? await one(`SELECT * FROM contract_pages WHERE slug=$1`, [slug]) : null; if (!pg || !pg.active) bad('Publish the contract first.', 409);
    const pcode = String(b.passcode || '').trim(); if (pg.pass_hash && (!pcode || propHash(pg.pass_salt, pcode) !== pg.pass_hash)) bad('The passcode changed since the page was published. Click Update page, then send again.', 409);
    let link = String(b.link || ''); if (!/^https:\/\/[a-z0-9.-]+(:\d+)?\/(contracts\/)?[a-z0-9-]+$/i.test(link) || !link.endsWith('/' + slug)) link = conUrl(o, slug);
    const to = [...new Set(String(b.to || '').split(/[,;\s]+/).map(cleanEmail).filter(Boolean))]; if (!to.length || to.some(e => !emailOk(e))) bad('Check the client email address.'); if (to.length > 5) bad('Send to 5 addresses or fewer.');
    const cfg = emailCfgOf(await settingsDoc()), m = msgEmail(o, cfg, b, link, pg.pass_hash ? pcode : '', 'Design Agreement');
    const subject = String(b.subject || ('Your Design Agreement — ' + (b.title || ''))).replace(/[\r\n]+/g, ' ').slice(0, 200);
    if (b.preview) return json({ html: m.html, subject, from: `${cfg.fromName} <${cfg.from}>` });
    const mid = await sendMail({ from: `${cfg.fromName} <${cfg.from}>`, to, replyTo: cfg.replyTo || (emailOk(u.email) ? u.email : ''), subject, html: m.html, text: m.text });
    await conEvent(slug, { t: 'sent', by: u.name || 'Studio', detail: 'Emailed to ' + to.join(', ') + (pg.pass_hash ? ' with passcode' : '') });
    return json({ ok: true, id: mid, to, link });
  }
  bad('Not found', 404);
}
async function conInfo(slug) {
  let pg = await one(`SELECT * FROM contract_pages WHERE slug=$1`, [slug]); if (!pg) return {};
  pg = await conRefreshPaid(pg); const st = conPublicState(pg), inv = pg.invoice;
  return { slug: pg.slug, sigs: st.sigs.map(s => ({ name: s.name, at: s.at })), complete: st.complete, events: (pg.events || []).map(e => ({ t: e.t, at: e.at, by: e.by, detail: e.detail })),
    invoice: inv ? (inv.error ? { error: inv.error } : { id: inv.id, num: inv.num, amount: inv.amount, sent: !!inv.sent, paid: !!inv.paid, qbUrl: inv.qbUrl || '' }) : null };
}

/* ── Published links: every live proposal and contract page, and taking them offline ── */
async function linksRoute(req, path, method) {
  const u = await need(req);
  const recs = async k => { const r = await one(`SELECT data FROM docs WHERE key=$1 AND NOT deleted`, [k]); const d = r && r.data; const items = Array.isArray(d) ? d : (d && Array.isArray(d.items) ? d.items : []); return new Map(items.map(x => [x.id, x])); };
  const conSigned = r => Array.isArray(r.sigs) && r.sigs.length > 0, propSigned = r => !!r.accepted;
  if (path === 'published-links' && method === 'GET') {
    if (!isAdmin(u)) bad('Only admins can see published links.', 403);
    const pm = await recs('proposals'), cm = await recs('contracts'), out = [];
    for (const r of await q(`SELECT slug, id, accepted, views, gate, updated_at FROM proposal_pages`)) {
      const w = pm.get(r.id), views = Array.isArray(r.views) ? r.views.length : 0;
      out.push({ kind: 'proposal', slug: r.slug, id: r.id, inWorkspace: !!w, title: (w && (w.doc && w.doc.title || w.title)) || (r.gate && r.gate.title) || r.slug, client: (w && w.doc && w.doc.client) || (r.accepted && r.accepted.name) || '', status: r.accepted ? 'Accepted' : views ? 'Sent · ' + views + ' view' + (views === 1 ? '' : 's') : 'Published', signed: propSigned(r), updatedAt: r.updated_at });
    }
    for (const r of await q(`SELECT slug, id, title, signers, sigs, completed_at, events, updated_at FROM contract_pages`)) {
      const w = cm.get(r.id), n = Array.isArray(r.sigs) ? r.sigs.length : 0, sent = (Array.isArray(r.events) ? r.events : []).some(e => e.t === 'sent');
      out.push({ kind: 'contract', slug: r.slug, id: r.id, inWorkspace: !!w, title: r.title || (w && w.title) || r.slug, client: (Array.isArray(r.signers) ? r.signers : []).map(x => x.name).filter(Boolean).join(' & '), status: r.completed_at ? 'Signed' : n ? 'Partly signed' : sent ? 'Sent · not signed' : 'Published', signed: conSigned(r), updatedAt: r.updated_at });
    }
    out.sort((a, b) => (a.inWorkspace - b.inWorkspace) || (new Date(b.updatedAt) - new Date(a.updatedAt)));
    return json({ links: out });
  }
  if (path === 'link-remove' && method === 'POST') {
    const b = await body(req), kind = b.kind === 'proposal' ? 'proposal' : b.kind === 'contract' ? 'contract' : '';
    if (!kind) bad('Choose a proposal or contract link.');
    if (!canPage(u, kind + 's')) bad('You don\'t have access to ' + kind + 's.', 403);
    const table = kind === 'proposal' ? 'proposal_pages' : 'contract_pages', id = String(b.id || ''), slug = String(b.slug || '');
    let rows = [];
    if (id) { if (!/^[A-Za-z0-9_-]{1,80}$/.test(id)) bad('Bad id.'); rows = await q(`SELECT * FROM ${table} WHERE id=$1`, [id]); }
    else if (SLUG_RE.test(slug)) { rows = await q(`SELECT * FROM ${table} WHERE slug=$1`, [slug]); if (rows.length && !isAdmin(u) && (await recs(kind + 's')).has(rows[0].id) === false) bad('Only admins can remove links that aren\'t in the workspace.', 403); }
    else bad('Choose a link to remove.');
    if (!rows.length) return json({ ok: true, removed: [] });
    const locked = rows.filter(kind === 'proposal' ? propSigned : conSigned);
    if (locked.length && String(b.confirm || '').trim() !== locked[0].slug) throw Object.assign(new HttpError(409, kind === 'proposal' ? 'This proposal was accepted. Type the link name to confirm.' : 'This contract has been signed. Type the link name to confirm.'), { code: 'confirm' });
    for (const r of rows) await q(`DELETE FROM ${table} WHERE slug=$1`, [r.slug]);
    return json({ ok: true, removed: rows.map(r => r.slug) });
  }
  bad('Not found', 404);
}

/* ── QuickBooks Online ── */
const QBO_ON = () => !!(process.env.QBO_CLIENT_ID && process.env.QBO_CLIENT_SECRET);
const QBO_SANDBOX = () => /sandbox/i.test(process.env.QBO_ENV || '');
const QBO_API = () => process.env.QBO_API_BASE || (QBO_SANDBOX() ? 'https://sandbox-quickbooks.api.intuit.com' : 'https://quickbooks.api.intuit.com');
const QBO_TOKEN_URL = () => process.env.QBO_TOKEN_URL || 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
const QBO_AUTH_URL = () => process.env.QBO_AUTH_URL || 'https://appcenter.intuit.com/connect/oauth2';
const QBO_APP_URL = () => QBO_SANDBOX() ? 'https://app.sandbox.qbo.intuit.com' : 'https://app.qbo.intuit.com';
async function qboKey() { const { createHash: ch } = await import('node:crypto'); return ch('sha256').update('sbw-qbo:' + (process.env.QBO_TOKEN_KEY || '') + ':' + (process.env.QBO_CLIENT_SECRET || '')).digest(); }
async function qboSeal(obj) { const c = await import('node:crypto'), iv = c.randomBytes(12), ci = c.createCipheriv('aes-256-gcm', await qboKey(), iv); const enc = Buffer.concat([ci.update(JSON.stringify(obj), 'utf8'), ci.final()]); return [iv, ci.getAuthTag(), enc].map(x => x.toString('base64')).join('.'); }
async function qboOpen(s) { const c = await import('node:crypto'), [iv, tag, enc] = String(s || '').split('.').map(x => Buffer.from(x, 'base64')); const d = c.createDecipheriv('aes-256-gcm', await qboKey(), iv); d.setAuthTag(tag); return JSON.parse(Buffer.concat([d.update(enc), d.final()]).toString('utf8')); }
async function qboGet() { const r = await one(`SELECT v FROM settings WHERE k='qbo'`); if (!r || !r.v || !r.v.sealed) return null; try { return { ...r.v, tok: await qboOpen(r.v.sealed) }; } catch (e) { return null; } }
async function qboPut(v) { const { tok, ...rest } = v; const sealed = await qboSeal(tok); await q(`INSERT INTO settings (k, v) VALUES ('qbo', $1) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v`, [JSON.stringify({ ...rest, sealed })]); }
async function qboTokenCall(params) {
  const r = await fetch(QBO_TOKEN_URL(), { method: 'POST', headers: { authorization: 'Basic ' + Buffer.from(process.env.QBO_CLIENT_ID + ':' + process.env.QBO_CLIENT_SECRET).toString('base64'), 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: new URLSearchParams(params).toString() });
  const j = await r.json().catch(() => ({})); if (!r.ok || !j.access_token) throw new Error('QuickBooks sign-in failed' + (j.error ? ': ' + j.error : '')); return j;
}
async function qboToken() {
  const s = await qboGet(); if (!s) throw new Error('QuickBooks isn\'t connected.');
  if (Date.now() < (s.tok.exp || 0) - 120000) return s;
  const j = await qboTokenCall({ grant_type: 'refresh_token', refresh_token: s.tok.refresh });
  s.tok = { access: j.access_token, refresh: j.refresh_token || s.tok.refresh, exp: Date.now() + (+j.expires_in || 3600) * 1000 }; await qboPut(s); return s;
}
async function qboApi(method, path, payload, ctype) {
  const s = await qboToken(), url = QBO_API() + '/v3/company/' + encodeURIComponent(s.realm) + '/' + path + (path.includes('?') ? '&' : '?') + 'minorversion=75';
  const r = await fetch(url, { method, headers: { authorization: 'Bearer ' + s.tok.access, accept: 'application/json', ...(payload !== undefined ? { 'content-type': ctype || (payload === null ? 'application/octet-stream' : 'application/json') } : {}) }, body: payload === undefined ? undefined : payload === null ? '' : JSON.stringify(payload) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const f = j.Fault && j.Fault.Error && j.Fault.Error[0]; throw new Error('QuickBooks: ' + ((f && (f.Detail || f.Message)) || 'error ' + r.status)); }
  return j;
}
const qboQ = s => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
async function qboInvoiceLink(id) { const j = await qboApi('GET', 'invoice/' + id + '?include=invoiceLink'); return (j.Invoice && j.Invoice.InvoiceLink) || ''; }
// Finds the QuickBooks customer for this contract's client. Only reuses a top-level customer (never a sub-customer or project)
// whose name matches AND whose email matches or is blank. Otherwise creates a new customer, adding the project or email to the
// name if QuickBooks already has someone by that name, so one client's invoice can never land on another client's account.
// "12 Sample Lane, Westfield, NJ 07090" → QuickBooks address parts. Anything it can't split goes in Line1 as typed.
const US_ST = { 'new jersey': 'NJ', 'new york': 'NY', connecticut: 'CT', pennsylvania: 'PA', delaware: 'DE', massachusetts: 'MA', florida: 'FL', california: 'CA', maryland: 'MD', virginia: 'VA' };
function qboAddr(raw) {
  const t = String(raw || '').replace(/\s+/g, ' ').trim().slice(0, 300); if (!t) return null;
  const parts = t.split(/\s*,\s*/).filter(Boolean); if (parts.length < 2) return { Line1: t.slice(0, 500) };
  let state = '', zip = '', last = parts[parts.length - 1], m;
  if ((m = last.match(/^(.*?)\s*(\d{5}(?:-\d{4})?)$/))) { zip = m[2]; last = m[1]; }
  if (/^[A-Za-z]{2}$/.test(last)) state = last.toUpperCase(); else if (US_ST[last.toLowerCase()]) state = US_ST[last.toLowerCase()];
  if ((state || zip) && parts.length >= 3) { const city = parts[parts.length - 2]; return { Line1: parts.slice(0, -2).join(', ').slice(0, 500), City: city.slice(0, 255), ...(state ? { CountrySubDivisionCode: state } : {}), ...(zip ? { PostalCode: zip } : {}) }; }
  if (!state && !zip && parts.length >= 2) return { Line1: parts[0].slice(0, 500), City: parts.slice(1).join(', ').slice(0, 255) };
  return { Line1: t.slice(0, 500) };
}
async function qboFindOrMakeCustomer(name, email, project, addr) {
  const q1 = async dn => ((await qboApi('GET', 'query?query=' + encodeURIComponent(`select * from Customer where DisplayName = '${qboQ(dn)}'`))).QueryResponse || {}).Customer || [];
  const em = String(email || '').toLowerCase(), mails = c => String((c.PrimaryEmailAddr || {}).Address || '').toLowerCase().split(/[,;\s]+/).filter(Boolean);
  const top = c => !c.Job && !c.ParentRef && c.Active !== false;
  const ok = c => top(c) && (em ? (mails(c).length === 0 || mails(c).includes(em)) : true);
  const found = (await q1(name)).find(ok); if (found) return found;
  const names = [name, project ? `${name} – ${project}` : '', em ? `${name} (${em})` : '', `${name} (${Date.now().toString(36)})`].filter(Boolean).map(s => s.slice(0, 100));
  for (const dn of names) {
    if (dn !== name) { const hit = (await q1(dn)).find(ok); if (hit) return hit; }
    try { return (await qboApi('POST', 'customer', { DisplayName: dn, ...(emailOk(email) ? { PrimaryEmailAddr: { Address: email } } : {}), ...(addr ? { BillAddr: addr, ShipAddr: addr } : {}) })).Customer; }
    catch (e) { if (!/duplicate|6240|already (being )?used|already exists/i.test(e && e.message || '')) throw e; }
  }
  throw new Error('Couldn\'t create the QuickBooks customer.');
}
async function qboContractInvoice(pg) {
  const st = await settingsDoc(), cc = ((st.studioInfo || {}).conCfg || {}).pay || {}, pay = pg.pay || {};
  const signers = Array.isArray(pg.signers) ? pg.signers : [], name = signers.map(s => s.name).join(' & ').slice(0, 100) || 'Client', email = cleanEmail((signers[0] || {}).email);
  const amount = +pay.amount || 0; if (!(amount > 0)) throw new Error('The retainer amount is missing.');
  // Bill to / Ship to come from the contract: the billing address if one was given, otherwise the project address.
  const addr = qboAddr(pay.billAddr);
  const cust = await qboFindOrMakeCustomer(name, email, pg.title || '', addr);
  let itemId = cc.item;
  if (!itemId) { const items = ((await qboApi('GET', 'query?query=' + encodeURIComponent("select * from Item where Type = 'Service' maxresults 50"))).QueryResponse || {}).Item || []; const it = items.find(x => /design/i.test(x.Name)) || items[0]; if (!it) throw new Error('Choose a product/service in Admin → QuickBooks.'); itemId = it.Id; }
  const memo = String(cc.memo || 'Thank you for signing your {project} Design Agreement. Here is your design retainer invoice.').replace(/\{project\}/gi, pg.title || '').slice(0, 1000);
  const today = new Date().toISOString().slice(0, 10);
  // When "Custom transaction numbers" is on in QuickBooks, API invoices get no number unless we ask for the next one.
  let customNums = false; try { const pf = (await qboApi('GET', 'preferences')).Preferences || {}; customNums = !!((pf.SalesFormsPrefs || {}).CustomTxnNumbers); } catch (e) {}
  const invBody = { CustomerRef: { value: cust.Id }, TxnDate: today, DueDate: today,
    Line: [{ Amount: amount, DetailType: 'SalesItemLineDetail', Description: 'Design retainer – ' + (pg.title || ''), SalesItemLineDetail: { ItemRef: { value: itemId }, Qty: 1, UnitPrice: amount } }],
    ...(emailOk(email) ? { BillEmail: { Address: email } } : {}), AllowOnlineACHPayment: pay.ach !== false, AllowOnlineCreditCardPayment: !!pay.card, CustomerMemo: { value: memo }, ...(addr ? { BillAddr: addr, ShipAddr: addr } : {}) };
  let inv;
  if (customNums) { try { inv = (await qboApi('POST', 'invoice', { ...invBody, AutoDocNumber: true })).Invoice; } catch (e) { inv = null; } }
  if (!inv) inv = (await qboApi('POST', 'invoice', invBody)).Invoice;
  const out = { id: inv.Id, num: inv.DocNumber || '', amount: +inv.TotalAmt || amount, sent: false, paid: false, link: '', qbUrl: QBO_APP_URL() + '/app/invoice?txnId=' + inv.Id, createdAt: new Date().toISOString() };
  try { out.link = await qboInvoiceLink(inv.Id); } catch (e) {}
  return out;
}
async function qboRoute(req, path, method) {
  const o = new URL(req.url).origin, redirect = process.env.QBO_REDIRECT_URI || (o + '/api/qbo/callback');
  if (path === 'qbo-status' && method === 'GET') { await need(req); const s = QBO_ON() ? await qboGet() : null; return json({ configured: QBO_ON(), connected: !!s, company: s ? s.company || '' : '', env: QBO_SANDBOX() ? 'sandbox' : 'production' }); }
  if (path === 'qbo/connect' && method === 'GET') {
    const u = await currentUser(req); if (!u || !isAdmin(u)) return page(shell('Sign in first', `<div class="h">Only admins can connect QuickBooks</div><div class="m">Sign in to the workspace as an admin, then try again from Admin → QuickBooks.</div>`), 403);
    if (!QBO_ON()) return page(shell('Not set up', `<div class="h">QuickBooks isn't set up yet</div><div class="m">Add QBO_CLIENT_ID and QBO_CLIENT_SECRET in Vercel, then redeploy.</div>`), 503);
    const state = (await import('node:crypto')).randomBytes(18).toString('hex'), secure = o.startsWith('https:');
    const url = QBO_AUTH_URL() + '?' + new URLSearchParams({ client_id: process.env.QBO_CLIENT_ID, response_type: 'code', scope: 'com.intuit.quickbooks.accounting', redirect_uri: redirect, state }).toString();
    return new Response(null, { status: 302, headers: { location: url, 'cache-control': 'no-store', 'set-cookie': 'sbqs=' + state + '; Path=/api/qbo; HttpOnly; SameSite=Lax; Max-Age=900' + (secure ? '; Secure' : '') } });
  }
  if (path === 'qbo/callback' && method === 'GET') {
    const u = await currentUser(req); if (!u || !isAdmin(u)) return page(shell('Sign in first', `<div class="h">Please sign in as an admin and connect again</div>`), 403);
    const sp = new URL(req.url).searchParams, state = sp.get('state') || '', ck = (req.headers.get('cookie') || '').split(/;\s*/).find(x => x.startsWith('sbqs=')) || '';
    if (!state || ck.slice(5) !== state) return page(shell('Try again', `<div class="h">That connection link expired</div><div class="m">Go back to Admin → QuickBooks and click Connect again.</div>`), 400);
    if (sp.get('error')) return new Response(null, { status: 302, headers: { location: '/?qbo=cancelled', 'set-cookie': 'sbqs=; Path=/api/qbo; Max-Age=0' } });
    const j = await qboTokenCall({ grant_type: 'authorization_code', code: sp.get('code') || '', redirect_uri: redirect });
    const realm = String(sp.get('realmId') || '');
    await qboPut({ realm, by: u.email, at: new Date().toISOString(), company: '', tok: { access: j.access_token, refresh: j.refresh_token, exp: Date.now() + (+j.expires_in || 3600) * 1000 } });
    try { const ci = await qboApi('GET', 'companyinfo/' + encodeURIComponent(realm)); const s = await qboGet(); s.company = (ci.CompanyInfo && (ci.CompanyInfo.CompanyName || ci.CompanyInfo.LegalName)) || ''; await qboPut(s); } catch (e) {}
    return new Response(null, { status: 302, headers: { location: '/?qbo=connected', 'set-cookie': 'sbqs=; Path=/api/qbo; Max-Age=0' } });
  }
  if (path === 'qbo-disconnect' && method === 'POST') {
    await needAdmin(req); const s = await qboGet();
    if (s && !process.env.QBO_API_BASE) { try { await fetch('https://developer.api.intuit.com/v2/oauth2/tokens/revoke', { method: 'POST', headers: { authorization: 'Basic ' + Buffer.from(process.env.QBO_CLIENT_ID + ':' + process.env.QBO_CLIENT_SECRET).toString('base64'), 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ token: s.tok.refresh }) }); } catch (e) {} }
    await q(`DELETE FROM settings WHERE k='qbo'`); return json({ ok: true });
  }
  if (path === 'qbo-items' && method === 'GET') {
    await need(req); const j = await qboApi('GET', 'query?query=' + encodeURIComponent("select * from Item where Active = true maxresults 200"));
    return json({ items: ((j.QueryResponse || {}).Item || []).filter(i => i.Type === 'Service' || i.Type === 'NonInventory').map(i => ({ id: i.Id, name: i.FullyQualifiedName || i.Name })) });
  }
  bad('Not found', 404);
}

/* ── simple legal pages (needed for the QuickBooks app listing) ── */
function legalPage(kind) {
  const upd = 'November 20, 2026', mail = 'studio@stoneandbirch.com';
  const P = kind === 'privacy' ? {
    t: 'Privacy Policy', b: `
<p>This policy explains how Stone + Birch Interiors ("Stone + Birch", "we") handles information in the Stone + Birch Workspace, the private online tool we use to run client projects, and on the proposal, contract and client pages we share from it.</p>
<h2>Who uses the Workspace</h2><p>The Workspace is used by Stone + Birch staff. Clients only see the pages we send them, such as a proposal, a contract to sign or a project page. It is not offered to the public or to other businesses.</p>
<h2>Information we keep</h2><ul><li>Client contact details you share with us: names, email addresses, phone numbers and project addresses.</li><li>Project information: rooms, product selections, quotes, proposals, contracts and related notes and files.</li><li>When you accept a proposal or sign a contract: your name, email, signature, the date and time, and basic technical details (IP address and browser type) recorded as part of the signing record.</li><li>Staff account details: name, email and sign-in activity.</li></ul>
<h2>How we use it</h2><p>Only to provide our design services: preparing and sending proposals, contracts, quotes and invoices, keeping project records, and communicating with you about your project. We do not sell information or use it for advertising.</p>
<h2>QuickBooks</h2><p>If connected, the Workspace links to our own QuickBooks Online company to create customers and invoices for our clients (for example, a design retainer after a contract is signed) and to check whether an invoice has been paid. It does not access any other QuickBooks company. Payments made through QuickBooks are handled by Intuit; we never see or store card or bank details.</p>
<h2>Service providers</h2><p>The Workspace runs on trusted providers that process information on our behalf: Vercel (hosting), Neon (database), Resend (email delivery) and Intuit QuickBooks (invoicing and payments). They may only use it to provide their service to us.</p>
<h2>Security</h2><p>Information is sent over encrypted connections. Staff sign in with individual accounts, client pages can be protected with a passcode, and connection keys for QuickBooks are stored encrypted.</p>
<h2>Keeping and deleting information</h2><p>We keep project records for as long as needed for our work together and for our business, tax and legal records. You can ask us to see, correct or delete your information by emailing <a href="mailto:${mail}">${mail}</a>.</p>
<h2>Changes</h2><p>If we change this policy we will update the date below.</p>` } : {
    t: 'Terms of Use', b: `
<p>These terms apply to the Stone + Birch Workspace ("the Workspace"), a private online tool operated by Stone + Birch Interiors ("Stone + Birch", "we"), and to the proposal, contract and client pages we share from it.</p>
<h2>Who may use it</h2><p>The Workspace is for Stone + Birch staff and the clients we invite. Staff accounts are created by Stone + Birch and are personal; please keep your password private. Client pages are for the client they were sent to.</p>
<h2>Using it properly</h2><p>Use the Workspace only for Stone + Birch business and your own project. Do not try to access other people's information, interfere with the service, or copy our designs, documents or materials for other purposes.</p>
<h2>Agreements and signatures</h2><p>Proposals and contracts accepted or signed through the Workspace are agreements between you and Stone + Birch, governed by their own terms. Electronic acceptance and signatures are intended to have the same effect as handwritten ones.</p>
<h2>QuickBooks and payments</h2><p>Where invoices are sent through QuickBooks, payments are processed by Intuit under Intuit's own terms. Stone + Birch does not store card or bank details.</p>
<h2>Our content</h2><p>Designs, drawings, documents and other materials in the Workspace belong to Stone + Birch unless they were supplied by you, as set out in your contract.</p>
<h2>Availability</h2><p>We aim to keep the Workspace available and accurate but provide it as is, and we may update or change it at any time. To the extent allowed by law, Stone + Birch is not liable for losses arising from use of the Workspace itself, separate from our obligations under your contract.</p>
<h2>Governing law</h2><p>These terms are governed by the laws of the State of New Jersey.</p>
<h2>Contact</h2><p>Questions? Email <a href="mailto:${mail}">${mail}</a>.</p>` };
  return page(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${P.t} · Stone + Birch Interiors</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@1,400&family=Inter:wght@300;400;500&family=Jost:wght@400&display=swap" rel="stylesheet">
<style>body{margin:0;background:#fff;color:#39292A;font:300 15.5px/1.8 Inter,Arial,sans-serif}.top{border-bottom:1px solid #D8D6D5;padding:18px 24px;text-align:center;font:400 13px Jost,Arial;letter-spacing:.32em}
main{max-width:720px;margin:0 auto;padding:48px 24px 80px}.ey{font:400 11px Jost,Arial;letter-spacing:.24em;text-transform:uppercase;color:#6D5E5F}h1{font:italic 400 clamp(34px,5vw,46px)/1.1 'Playfair Display',Georgia,serif;margin:8px 0 26px}
h2{font:400 11.5px Jost,Arial;letter-spacing:.2em;text-transform:uppercase;margin:30px 0 6px}p,li{color:#4a3d3e}a{color:#39292A}footer{border-top:1px solid #D8D6D5;padding:18px 24px;text-align:center;font-size:12.5px;color:#878282}</style></head>
<body><div class="top">STONE + BIRCH INTERIORS</div><main><div class="ey">Stone + Birch Workspace</div><h1>${P.t}</h1>${P.b}<p style="margin-top:34px;font-size:13px;color:#878282">Last updated ${upd}</p></main>
<footer>Stone + Birch Interiors · 500 Central Ave, Suite 4, Westfield, NJ · <a href="/legal/privacy">Privacy</a> · <a href="/legal/terms">Terms</a></footer></body></html>`);
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


  /* email */
  if (path === 'email-logo.png' && method === 'GET') return new Response(EMAIL_LOGO, { headers: { 'content-type': 'image/png', 'cache-control': 'public, max-age=86400' } });
  if (path === 'email-status' && method === 'GET') { await need(req); return json({ on: emailOn(), domain: EMAIL_DOMAIN }); }
  if (path === 'email-quote' && method === 'POST') { const u = await need(req); if (u.mustChange) bad('Choose a new password first.', 403); return emailQuoteRoute(req, u); }

  /* proposals */
  let prm;
  if ((prm = path.match(/^prop\/([a-z0-9-]{1,60})(?:\/(state|accept))?$/))) return propPublicRoute(req, prm[1], prm[2] || '', method);
  if (/^(proposal-slug|proposal-publish|proposal-info|email-proposal)$/.test(path)) return propStudioRoute(req, path, method);
  if (/^(published-links|link-remove)$/.test(path)) return linksRoute(req, path, method);

  if (path === 'legal/privacy' || path === 'legal/terms') return legalPage(path.slice(6));
  /* contracts */
  let cm;
  if ((cm = path.match(/^con\/([a-z0-9-]{1,60})(?:\/(state|sign|signed))?$/))) return conPublicRoute(req, cm[1], cm[2] || '', method);
  if (/^(contract-slug|contract-publish|contract-info|email-contract|contract-invoice-send|retainer-preview)$/.test(path)) return conStudioRoute(req, path, method);
  if (/^(qbo-status|qbo-disconnect|qbo-items|qbo\/connect|qbo\/callback)$/.test(path)) return qboRoute(req, path, method);

  /* private client link */
  let pm;
  if ((pm = path.match(/^p\/([A-Za-z0-9]+)(?:\/(reply|(?:quote|qstate)\/[A-Za-z0-9_-]{1,80}))?$/))) return publicRoute(req, pm[1].toLowerCase(), pm[2] || '', method);
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
    if (Array.isArray(b.qids)) { const keep = b.on ? b.qids.map(String).filter(x => /^[A-Za-z0-9_-]{1,80}$/.test(x)).slice(0, 500) : []; await q(`DELETE FROM portal_quotes WHERE pid=$1 AND NOT (qid = ANY($2))`, [pid, keep]); }
    return json({ ok: true, views });
  }
  if (path === 'portal-quote' && method === 'POST') {
    const u = await need(req), b = await body(req), pid = String(b.pid || ''), qid = String(b.qid || '');
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(pid) || !canProject(u, pid)) bad('You don\'t have access to that project.', 403);
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(qid)) bad('Bad quote.');
    const lk = await one(`SELECT token FROM portal_links WHERE pid=$1`, [pid]); if (!lk || lk.token !== String(b.token || '').toLowerCase()) bad('Publish the client link first.', 409);
    const html = String(b.html || ''); if (html.length > 4_000_000) bad('This quote page is too large to publish.');
    await q(`INSERT INTO portal_quotes (pid, qid, html, updated_at) VALUES ($1,$2,$3,now()) ON CONFLICT (pid, qid) DO UPDATE SET html=EXCLUDED.html, updated_at=now()`, [pid, qid, html]);
    return json({ ok: true });
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
    if (origin && oh !== url.host && !(origin === 'null' && /^p\/[A-Za-z0-9]+(\/quote\/[A-Za-z0-9_-]+)?$/.test(path))) return json({ error: 'Blocked.' }, 403);
  }
  try { return await route(req, path, method); }
  catch (e) {
    const status = e.status || 500; if (status >= 500) console.error(e);
    return json({ error: status >= 500 && !e.code ? 'Something went wrong on the server.' : e.message, code: e.code }, status);
  }
}
export const GET = handle, POST = handle, PUT = handle, PATCH = handle, DELETE = handle;
