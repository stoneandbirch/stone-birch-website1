// Hiding financial fields: strip them before data leaves the server, and put them back when a restricted user saves.
const KEYS = { unitCost: ['unitCost', 'freight', 'deposit'], markup: ['markup'], msrp: ['msrp'], shipping: ['shipping', 'shipTotal'], budget: ['budget', 'budgetMin', 'budgetMax'], clientPrice: [] };
export function hiddenKeys(user) { const out = new Set(); (user && user.role !== 'admin' ? user.hideFields || [] : []).forEach(k => (KEYS[k] || []).forEach(x => out.add(x))); return out; }
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
const nv = v => { const n = parseFloat(String(v ?? '').replace(/[^0-9.\-]/g, '')); return isFinite(n) ? n : 0; };

/** returns a deep copy without hidden keys; objects that lose cost or markup get `_cu` (client price per unit) so prices still show */
export function strip(data, hide) {
  if (!hide.size) return data;
  const walk = v => {
    if (Array.isArray(v)) return v.map(walk);
    if (!isObj(v)) return v;
    const o = {};
    const priced = ('unitCost' in v || 'markup' in v) && (hide.has('unitCost') || hide.has('markup'));
    for (const [k, x] of Object.entries(v)) { if (hide.has(k)) continue; o[k] = walk(x); }
    if (priced) o._cu = Math.round(nv(v.unitCost) * (1 + nv(v.markup) / 100) * 100) / 100;
    return o;
  };
  return walk(data);
}

/** before saving a restricted user's doc: hidden keys always come from the stored copy (or from the product/room item it was copied from) */
export function restore(incoming, current, hide, sources = {}) {
  const dropCu = v => { if (Array.isArray(v)) v.forEach(dropCu); else if (isObj(v)) { delete v._cu; Object.values(v).forEach(dropCu); } };
  if (!hide.size) { dropCu(incoming); return incoming; }
  const fill = (o, from) => { for (const k of hide) { if (from && k in from) o[k] = from[k]; else delete o[k]; } };
  const walk = (inc, cur) => {
    if (Array.isArray(inc)) {
      const byId = new Map(); if (Array.isArray(cur)) cur.forEach(c => { if (isObj(c) && c.id != null) byId.set(c.id, c); });
      inc.forEach((el, i) => { if (!isObj(el)) return; const m = el.id != null ? byId.get(el.id) : (Array.isArray(cur) ? cur[i] : undefined); walk(el, m); });
      return;
    }
    if (!isObj(inc)) return;
    delete inc._cu;
    if (cur && isObj(cur)) fill(inc, cur);
    else {
      const src = (inc.libraryId && sources.product && sources.product(inc.libraryId)) || (inc.itemId && sources.item && sources.item(inc.itemId)) || null;
      fill(inc, src);
    }
    for (const [k, x] of Object.entries(inc)) if (x && typeof x === 'object') walk(x, isObj(cur) ? cur[k] : undefined);
  };
  walk(incoming, current);
  return incoming;
}
