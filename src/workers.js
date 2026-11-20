// parspehr gate: personal login + watermark + payroll API + employee self-service portal
import { makeEngine } from './engine.js';
import PORTAL_ADMIN_JS from './portal-admin-src.js';

const PSP_BUILD = '2026-11-18-fix-v317';

const OWNER = 'Mohamad Moradibabersad'; // <-- put your own name here (English letters)
const STATE_DOCS = ['settings', 'data', 'log'];
const MAX_DOC_BYTES = 8 * 1024 * 1024;
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_ITEMS = 5000;
const SESSION_IDLE_SECONDS = 60 * 60;
const COOKIE_NAME = 'psp_session';
const EMP_COOKIE_NAME = 'psp_emp';

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function hmacHex(key, message) {
  const k = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(message)));
  return Array.from(sig).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function zwEncode(text) {
  const bytes = new TextEncoder().encode(text);
  let out = '\u2060';
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) out += ((b >> i) & 1) ? '\u200c' : '\u200b';
  }
  return out + '\u2060';
}

function parseUsers(env) {
  const users = {};
  if (env.SITE_USERS) {
    const parsed = JSON.parse(env.SITE_USERS);
    for (const name of Object.keys(parsed)) {
      const v = parsed[name];
      if (typeof v === 'string' && v) {
        users[name] = { password: v, role: 'operator' };
      } else if (v && typeof v === 'object' && typeof v.password === 'string' && v.password) {
        users[name] = { password: v.password, role: v.role === 'admin' ? 'admin' : 'operator' };
      }
    }
  }
  if (env.SITE_USER && env.SITE_PASSWORD) users[env.SITE_USER] = { password: env.SITE_PASSWORD, role: 'admin' };
  return users;
}

async function authenticate(request, users) {
  const header = request.headers.get('Authorization') || '';
  if (!header.startsWith('Basic ')) return null;
  let decoded = '';
  try { decoded = atob(header.slice(6)); } catch (e) { return null; }
  const i = decoded.indexOf(':');
  if (i < 0) return null;
  const userHash = await sha256(decoded.slice(0, i));
  const passHash = await sha256(decoded.slice(i + 1));
  let found = null;
  for (const name of Object.keys(users)) {
    const userOk = sameBytes(userHash, await sha256(name));
    const passOk = sameBytes(passHash, await sha256(users[name].password));
    if (userOk && passOk && found === null) found = { name: name, role: users[name].role };
  }
  return found;
}





function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

async function stamp(html, user, env) {
  const key = env.WM_KEY || env.SITE_USERS || env.SITE_PASSWORD || 'parspehr';
  const tag = (await hmacHex(key, 'psp:' + user)).slice(0, 16);
  const safe = user.replace(/[^A-Za-z0-9_.@-]/g, '_') + '.' + tag;
  const top =
    '<!-- Proprietary software of ' + OWNER + '. Licensed to: ' + safe +
    '. Copying, sharing or reselling is prohibited. -->' +
    '<meta name="application-name" content="Parspehr' + zwEncode(safe) + '">' +
    '<meta name="psp-license" content="' + safe + '">' +
    '<script>window.__psp="' + safe + '";</script>';
  const bootVer = '20261110v256';
  const portalAdminScript = '<script src="/api/admin/portal-boot.js?v=' + bootVer + '" onerror="console.error(\'[psp] portal-boot LOAD FAIL\');try{var d=document.createElement(\'div\');d.style.cssText=\'padding:12px;margin:12px;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;color:#991b1b;font-family:Tahoma;direction:rtl\';d.textContent=\'Ø®Ø·Ø§ Ø¯Ø± Ø¨Ø§Ø±Ú¯Ø°Ø§Ø±ÛŒ portal-boot.js (Ø´Ø¨Ú©Ù‡ ÛŒØ§ Ø¯ÛŒÙ¾Ù„ÙˆÛŒ). Worker Ø±Ø§ Ø¯ÙˆØ¨Ø§Ø±Ù‡ Ø¯ÛŒÙ¾Ù„ÙˆÛŒ Ú©Ù†ÛŒØ¯.\';document.body&&document.body.prepend(d);}catch(e){}"><\/script>';
  const emergencyInline = '<script>(function(){function n(s){return String(s||\'\').replace(/[\\u200c\\u200d\\u200e\\u200f\\u00a0]/g,\'\').replace(/\\s+/g,\' \').trim();}function hide(el){el.setAttribute(\'data-psp-struct-hide\',\'1\');el.setAttribute(\'hidden\',\'hidden\');el.style.setProperty(\'display\',\'none\',\'important\');el.style.setProperty(\'visibility\',\'hidden\',\'important\');}function show(el){el.removeAttribute(\'data-psp-struct-hide\');el.removeAttribute(\'hidden\');el.style.removeProperty(\'display\');el.style.removeProperty(\'visibility\');}function red(t){if(!t||t.length>36)return false;if(t===\'ØºÛŒØ±ÙØ¹Ø§Ù„\'||t===\'ÙØ¹Ø§Ù„\')return false;if(t.indexOf(\'ØºÛŒØ±ÙØ¹Ø§Ù„\')>=0)return true;if(t.indexOf(\'Ø³ÙØ§Ø±Ø´\')>=0&&t.indexOf(\'Ø¢ÛŒØªÙ…\')>=0)return true;if(t.indexOf(\'Ø«Ø§Ø¨Øª\')>=0&&t.indexOf(\'Ù…Ø§Ù‡Ø§Ù†\')>=0)return true;if(t.indexOf(\'ØªØ±ØªÛŒØ¨\')>=0&&t.indexOf(\'Ø³ØªÙˆÙ†\')>=0)return true;if(t===\'Ù…Ø±Ø®ØµÛŒ\'||t===\'Ù…Ø£Ù…ÙˆØ±ÛŒØª\'||t===\'Ù…Ø§Ù…ÙˆØ±ÛŒØª\'||t===\'Ø³Ø§ÛŒØ±\')return true;if(t===\'Ù…Ø±Ø®ØµÛŒ Ùˆ Ù…Ø£Ù…ÙˆØ±ÛŒØª\'||t===\'Ù…Ø±Ø®ØµÛŒ Ùˆ Ù…Ø§Ù…ÙˆØ±ÛŒØª\')return true;return false;}function go(){try{var nodes=document.querySelectorAll(\'button,[role=tab],a,.tab-btn\');var hasPortal=!!(document.getElementById(\'pspPortalTabBtn\')||document.querySelector(\'[data-tab="portalatt"]\')||document.getElementById(\'panel-portalatt\'));for(var i=0;i<nodes.length;i++){var el=nodes[i];try{if(el.closest&&el.closest(\'table,form,.psp-subtabs,#pspSubTabs\'))continue;var t=n(el.textContent);var isPortal=el.id===\'pspPortalTabBtn\'||el.getAttribute(\'data-tab\')===\'portalatt\';var leave=t.indexOf(\'Ù…Ø±Ø®ØµÛŒ\')>=0;var mis=t.indexOf(\'Ù…Ø£Ù…ÙˆØ±ÛŒØª\')>=0||t.indexOf(\'Ù…Ø§Ù…ÙˆØ±ÛŒØª\')>=0;var oth=t.indexOf(\'Ø³Ø§ÛŒØ±\')>=0;if(isPortal||(leave&&mis)||(leave&&mis&&oth)){el.textContent=\'Ú©Ø§Ø±Ú©Ø±Ø¯\';try{el.setAttribute(\'title\',\'Ú©Ø§Ø±Ú©Ø±Ø¯\');}catch(e0){}show(el);continue;}if(hasPortal&&red(t)){var r=el.getBoundingClientRect();var cnt=0,emp=0;for(var j=0;j<nodes.length;j++){try{var r2=nodes[j].getBoundingClientRect();if(Math.abs(r2.top-r.top)<50){cnt++;var tx=n(nodes[j].textContent);if(/^Ú©Ø§Ø±Ú©Ù†Ø§Ù†\\s*ÙØ¹Ø§Ù„/.test(tx)||tx.indexOf(\'ØºÛŒØ±ÙØ¹Ø§Ù„\')>=0)emp++;}}catch(e){}}if(cnt<=3&&emp>=2)continue;hide(el);}}catch(e1){}}var pb=document.getElementById(\'pspPortalTabBtn\');if(pb){pb.textContent=\'Ú©Ø§Ø±Ú©Ø±Ø¯\';show(pb);}}catch(e){}}if(!document.getElementById(\'pspStructHideCSS\')){var st=document.createElement(\'style\');st.id=\'pspStructHideCSS\';st.textContent=\'[data-psp-struct-hide="1"]{display:none!important;visibility:hidden!important;}\';(document.head||document.documentElement).appendChild(st);}go();setInterval(go,200);})();</script>';



  const bottom = emergencyInline + portalAdminScript + '<script>/*psp:' + safe + '*/</script><!-- psp:' + safe + ' -->';
  let out = /<head(?:\s[^>]*)?>/i.test(html)
    ? html.replace(/<head(?:\s[^>]*)?>/i, function (m) { return m + top; })
    : html + top;
  const end = out.lastIndexOf('</body>');
  out = end >= 0 ? out.slice(0, end) + bottom + out.slice(end) : out + bottom;
  return out;
}

function isPlainObject(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}
function arrOf(x) { return Array.isArray(x) ? x : []; }
function objOf(x) { return isPlainObject(x) ? x : {}; }
function isInt(x, lo, hi) { return Number.isInteger(x) && x >= lo && x <= hi; }
function isNum(x) { return typeof x === 'number' && Number.isFinite(x); }

async function readBody(request) {
  const m = request.method;
  if (m !== 'POST' && m !== 'PUT' && m !== 'DELETE' && m !== 'PATCH') {
    return { error: jsonResponse({ ok: false, error: 'method_not_allowed' }, 405) };
  }
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin') return { error: jsonResponse({ ok: false, error: 'forbidden' }, 403) };
  if (Number(request.headers.get('Content-Length') || 0) > MAX_BODY_BYTES) {
    return { error: jsonResponse({ ok: false, error: 'too_large' }, 413) };
  }
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) return { error: jsonResponse({ ok: false, error: 'too_large' }, 413) };
    const body = JSON.parse(text);
    if (!isPlainObject(body)) return { error: jsonResponse({ ok: false, error: 'bad_request' }, 400) };
    return { body: body };
  } catch (e) {
    return { error: jsonResponse({ ok: false, error: 'bad_json' }, 400) };
  }
}

// ---------- Supabase helpers ----------
function storeConfig(env) {
  const url = String(env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const key = String(env.SUPABASE_SERVICE_KEY || '').trim();
  if (!/^https:\/\/[A-Za-z0-9.-]+$/.test(url) || !key) return null;
  return { url: url, key: key };
}

function storeHeaders(cfg, extra) {
  const h = { apikey: cfg.key };
  if (/^eyJ/.test(cfg.key)) h.Authorization = 'Bearer ' + cfg.key;
  return Object.assign(h, extra || {});
}

async function storeFail(r) {
  let code = '';
  try { code = String(JSON.parse((await r.text()).slice(0, 2000)).code || ''); } catch (e) {}
  let reason = 'store_error';
  if (r.status === 404 || code === 'PGRST205' || code === '42P01') reason = 'table_missing';
  else if (r.status === 401 || r.status === 403 || code === '42501') reason = 'bad_key';
  return { reason: reason, status: r.status };
}

function storeFailResponse(f) {
  return jsonResponse({ ok: false, error: 'store_error', reason: f.reason, upstream: f.status }, 502);
}

async function storeVersions(cfg) {
  const r = await fetch(cfg.url + '/rest/v1/app_docs?select=name,version', { headers: storeHeaders(cfg) });
  if (!r.ok) return { fail: await storeFail(r) };
  const rows = await r.json();
  const v = { settings: 0, data: 0, log: 0 };
  rows.forEach(function (x) { if (x && STATE_DOCS.indexOf(x.name) >= 0) v[x.name] = Number(x.version) || 0; });
  return { versions: v };
}

async function storeGetData(cfg) {
  const r = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.data&select=version,data',
    { headers: storeHeaders(cfg, { Accept: 'application/vnd.pgrst.object+json' }) });
  if (r.status === 406) return { version: 0, obj: null };
  if (!r.ok) return { fail: await storeFail(r) };
  const row = await r.json();
  let obj = null;
  if (row && row.data) {
    try { obj = JSON.parse(row.data); } catch (e) { return { fail: { reason: 'bad_json', status: 502 } }; }
  }
  if (obj) {
    try { mergeAllEmployeeExtras(obj); } catch (eMerge) { /* non-fatal */ }
    // ØªØ±Ù…ÛŒÙ… Ø´Ù†Ø§ÙˆØ±ÛŒ: portalFloatMinutes / floatMinutes Ø±Ø§ ÛŒÚ©Ø¯Ø³Øª Ú©Ù†
    try {
      if (obj.settings && typeof obj.settings === 'object') {
        var fm = null;
        if (obj.settings.portalFloatMinutes != null && obj.settings.portalFloatMinutes !== '') {
          fm = parseFloatMinutesValue(obj.settings.portalFloatMinutes, null);
        }
        if (fm == null && obj.settings.floatMinutes != null && obj.settings.floatMinutes !== '') {
          fm = parseFloatMinutesValue(obj.settings.floatMinutes, null);
        }
        if (fm == null && obj.settings.contractCalendars) {
          Object.keys(obj.settings.contractCalendars).forEach(function (id) {
            if (String(id) === 'hourly') return;
            var v = parseFloatMinutesValue(obj.settings.contractCalendars[id] && obj.settings.contractCalendars[id].floatMinutes, null);
            if (v != null && (fm == null || v > fm)) fm = v;
          });
        }
        if (fm != null && fm !== 15) {
          obj.settings.portalFloatMinutes = fm;
          obj.settings.floatMinutes = fm;
          Object.keys(obj.settings.contractCalendars || {}).forEach(function (id) {
            if (String(id) === 'hourly') return;
            var c = obj.settings.contractCalendars[id];
            if (c && typeof c === 'object') c.floatMinutes = fm;
          });
        }
      }
    } catch (eFloatHeal) {}
  }
  return { version: Number(row.version) || 0, obj: obj };
}


/** Ø³Ù†Ø¯ Â«settingsÂ» (Ø«Ø§Ø¨Øªâ€ŒÙ‡Ø§ÛŒ Ù…Ø§Ù‡Ø§Ù†Ù‡ØŒ Ù‚ÙˆØ§Ù†ÛŒÙ† Ú©Ø³Ø±ØŒ Ø¨Ø±Ú†Ø³Ø¨â€ŒÙ‡Ø§) Ø¬Ø¯Ø§ Ø§Ø² Ø³Ù†Ø¯ Â«dataÂ» Ø°Ø®ÛŒØ±Ù‡ Ù…ÛŒâ€ŒØ´ÙˆØ¯ */
async function storeGetSettingsDoc(cfg) {
  try {
    const r = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.settings&select=version,data',
      { headers: storeHeaders(cfg, { Accept: 'application/vnd.pgrst.object+json' }) });
    if (!r.ok) return null;
    const row = await r.json();
    if (!row || !row.data) return null;
    const o = (typeof row.data === 'string') ? JSON.parse(row.data) : row.data;
    return (o && typeof o === 'object') ? o : null;
  } catch (e) { return null; }
}

/** Ø«Ø§Ø¨Øªâ€ŒÙ‡Ø§ÛŒ Ù…Ø§Ù‡Ø§Ù†Ù‡ ÙÙ‚Ø· Ø¨Ø§ Ø­Ø°Ù ØµØ±ÛŒØ­ (tombstone) Ù¾Ø§Ú© Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯Ø› Ø°Ø®ÛŒØ±Ù‡Ù” Ù†Ø§Ù‚Øµ ÛŒÚ© Ú©Ù„Ø§ÛŒÙ†Øª Ù‚Ø¯ÛŒÙ…ÛŒ Ø¢Ù†â€ŒÙ‡Ø§ Ø±Ø§ Ù†Ù…ÛŒâ€ŒØ¨Ø±Ø¯ */
function protectMonthlyVarsOnPut(prev, inc) {
  if (!prev || typeof prev !== 'object' || !inc || typeof inc !== 'object') return inc;
  const tomb = {};
  [].concat(Array.isArray(prev.monthlyVarsDeleted) ? prev.monthlyVarsDeleted : [],
            Array.isArray(inc.monthlyVarsDeleted) ? inc.monthlyVarsDeleted : []).forEach(function (id) { if (id) tomb[String(id)] = true; });
  const prevList = Array.isArray(prev.monthlyVars) ? prev.monthlyVars : [];
  const curList = Array.isArray(inc.monthlyVars) ? inc.monthlyVars : [];
  const byId = {};
  const order = [];
  prevList.concat(curList).forEach(function (v) {
    if (!v || !v.id) return;
    const id = String(v.id);
    if (tomb[id]) return;
    if (!byId[id]) order.push(id);
    byId[id] = v; // Ù†Ø³Ø®Ù‡Ù” Ú©Ù„Ø§ÛŒÙ†Øª (Ø¢Ø®Ø±ÛŒÙ† ÙˆÛŒØ±Ø§ÛŒØ´) Ù…Ù‚Ø¯Ù… Ø§Ø³Øª
  });
  curList.forEach(function (v) { // Ø¢ÛŒØªÙ… Ø¨Ø¯ÙˆÙ† id Ø±Ø§ Ù‡Ù… Ù†Ú¯Ù‡ Ø¯Ø§Ø±
    if (v && !v.id) { const k = 'noid:' + String(v.name || ''); if (!byId[k]) { order.push(k); byId[k] = v; } }
  });
  if (order.length || prevList.length || curList.length) inc.monthlyVars = order.map(function (k) { return byId[k]; });
  inc.monthlyVarsDeleted = Object.keys(tomb);
  return inc;
}

function employeeFieldLabels() {
  return {
    fullName: 'Ù†Ø§Ù… Ùˆ Ù†Ø§Ù… Ø®Ø§Ù†ÙˆØ§Ø¯Ú¯ÛŒ',
    firstName: 'Ù†Ø§Ù…',
    lastName: 'Ù†Ø§Ù… Ø®Ø§Ù†ÙˆØ§Ø¯Ú¯ÛŒ',
    birthDate: 'ØªØ§Ø±ÛŒØ® ØªÙˆÙ„Ø¯',
    management: 'Ù…Ø¯ÛŒØ±ÛŒØª',
    deputy: 'Ù…Ø¹Ø§ÙˆÙ†Øª',
    unit: 'ÙˆØ§Ø­Ø¯',
    group: 'Ú¯Ø±ÙˆÙ‡',
    jobGrade: 'Ø±Ø¯Ù‡ Ø´ØºÙ„ÛŒ',
    workplace: 'Ù…Ø­Ù„ Ú©Ø§Ø±',
    city: 'Ø´Ù‡Ø± Ù…Ø­Ù„ Ø³Ú©ÙˆÙ†Øª',
    province: 'Ø§Ø³ØªØ§Ù† Ù…Ø­Ù„ Ø³Ú©ÙˆÙ†Øª',
    gender: 'Ø¬Ù†Ø³ÛŒØª',
    militaryStatus: 'ÙˆØ¶Ø¹ÛŒØª Ù†Ø¸Ø§Ù… ÙˆØ¸ÛŒÙÙ‡',
    militaryExemptType: 'Ù†ÙˆØ¹ Ù…Ø¹Ø§ÙÛŒØª Ù†Ø¸Ø§Ù… ÙˆØ¸ÛŒÙÙ‡',
    educationLevel: 'Ù…Ù‚Ø·Ø¹ ØªØ­ØµÛŒÙ„ÛŒ',
    educationField: 'Ø±Ø´ØªÙ‡ ØªØ­ØµÛŒÙ„ÛŒ',
    hireDate: 'ØªØ§Ø±ÛŒØ® Ø§Ø³ØªØ®Ø¯Ø§Ù…',
    endDate: 'ØªØ§Ø±ÛŒØ® Ù¾Ø§ÛŒØ§Ù† Ù‡Ù…Ú©Ø§Ø±ÛŒ',
    position: 'Ø³Ù…Øª',
    basicSalary: 'Ø­Ù‚ÙˆÙ‚ Ù¾Ø§ÛŒÙ‡',
    status: 'ÙˆØ¶Ø¹ÛŒØª',
    contractType: 'Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯',
    bankName: 'Ù†Ø§Ù… Ø¨Ø§Ù†Ú©',
    accountNumber: 'Ø´Ù…Ø§Ø±Ù‡ Ø­Ø³Ø§Ø¨',
    insuranceNo: 'Ø´Ù…Ø§Ø±Ù‡ Ø¨ÛŒÙ…Ù‡',
    nationalId: 'Ú©Ø¯ Ù…Ù„ÛŒ',
    mobile: 'Ø´Ù…Ø§Ø±Ù‡ Ù‡Ù…Ø±Ø§Ù‡',
    fatherName: 'Ù†Ø§Ù… Ù¾Ø¯Ø±',
    address: 'Ø¢Ø¯Ø±Ø³',
    marital: 'ÙˆØ¶Ø¹ÛŒØª ØªØ£Ù‡Ù„',
    childrenCount: 'ØªØ¹Ø¯Ø§Ø¯ Ø§ÙˆÙ„Ø§Ø¯',
    taxPercent: 'Ø¯Ø±ØµØ¯ Ù…Ø§Ù„ÛŒØ§Øª',
    exemption: 'Ù…Ø¹Ø§ÙÛŒØª',
    seniorityBase: 'Ù¾Ø§ÛŒÙ‡ Ø³Ù†ÙˆØ§Øª'
  };
}

function normEmpVal(v) {
  if (v == null || v === undefined) return '';
  if (typeof v === 'number') return String(v);
  return String(v).trim();
}

function diffEmployeeChanges(prev, next) {
  if (!prev || !next) return [];
  const labels = employeeFieldLabels();
  const keys = Object.keys(labels);
  const out = [];
  keys.forEach(function (k) {
    const a = normEmpVal(prev[k]);
    const b = normEmpVal(next[k]);
    // fullName: also compose from first/last if needed
    if (k === 'fullName') {
      const fa = a || (normEmpVal(prev.firstName) + ' ' + normEmpVal(prev.lastName)).trim();
      const fb = b || (normEmpVal(next.firstName) + ' ' + normEmpVal(next.lastName)).trim();
      if (fa !== fb && (fa || fb)) {
        out.push({ field: k, label: labels[k], from: fa || 'â€”', to: fb || 'â€”' });
      }
      return;
    }
    if (a !== b && (a || b)) {
      out.push({ field: k, label: labels[k], from: a || 'â€”', to: b || 'â€”' });
    }
  });
  // customItems by name â€” ÙÙ‚Ø· ØªØºÛŒÛŒØ± ÙˆØ§Ù‚Ø¹ÛŒ Ù…Ø¨Ù„Øº/ÙØ¹Ø§Ù„ Ø¨ÙˆØ¯Ù† (Ù†Ù‡ 0 Ø¯Ø± Ø¨Ø±Ø§Ø¨Ø± ØºÛŒØ±ÙØ¹Ø§Ù„)
  function itemSig(emp) {
    const m = {};
    (emp.customItems || emp.customs || emp.items || []).forEach(function (ci) {
      if (!ci || !ci.name) return;
      const name = String(ci.name).trim();
      if (!name) return;
      const amount = Number(ci.amount);
      const amt = isFinite(amount) ? amount : 0;
      // ÙØ¹Ø§Ù„ Ø¨ÙˆØ¯Ù†: ØµØ±ÛŒØ­ false/0 = Ø®Ø§Ù…ÙˆØ´Ø› Ø¯Ø± ØºÛŒØ± Ø§ÛŒÙ† ØµÙˆØ±Øª Ø§Ú¯Ø± Ù…Ø¨Ù„Øº > 0 ÛŒØ§ enabled true
      let en = true;
      if (ci.enabled === false || ci.enabled === 0 || ci.enabled === '0') en = false;
      if (ci.active === false || ci.active === 0) en = false;
      // Ù…Ø¨Ù„Øº ØµÙØ± Ùˆ Ø¨Ø¯ÙˆÙ† ÙÙ„Ú¯ ÙØ¹Ø§Ù„ = Ù…Ø¹Ø§Ø¯Ù„ ØºÛŒØ±ÙØ¹Ø§Ù„/Ø®Ø§Ù„ÛŒ
      if (!en || !(amt > 0)) {
        m[name] = { key: 'off', label: 'ØºÛŒØ±ÙØ¹Ø§Ù„' };
      } else {
        m[name] = { key: 'on:' + amt, label: String(amt) };
      }
    });
    return m;
  }
  const pm = itemSig(prev);
  const nm = itemSig(next);
  const names = {};
  Object.keys(pm).forEach(function (n) { names[n] = true; });
  Object.keys(nm).forEach(function (n) { names[n] = true; });
  function isOffState(x) {
    if (!x || x.key === 'off') return true;
    var s = String(x.label || '').trim();
    if (!s || s === 'â€”' || s === 'ØºÛŒØ±ÙØ¹Ø§Ù„' || s === 'Ø­Ø°Ù Ø´Ø¯') return true;
    var n = Number(String(s).replace(/,/g, ''));
    if (isFinite(n) && n === 0) return true;
    return false;
  }
  Object.keys(names).forEach(function (n) {
    const a = pm[n] || { key: 'off', label: 'â€”' };
    const b = nm[n] || { key: 'off', label: 'â€”' };
    if (a.key === b.key) return;
    // 0 / ØºÛŒØ±ÙØ¹Ø§Ù„ / Ù†Ø¨ÙˆØ¯Ù† = Ù…Ø¹Ø§Ø¯Ù„ Ù‡Ù… â€” Ø«Ø¨Øª Ù†Ø´ÙˆØ¯
    if (isOffState(a) && isOffState(b)) return;
    out.push({ field: 'custom:' + n, label: 'Ø¢ÛŒØªÙ… Â«' + n + 'Â»', from: a.label, to: b.label });
  });
  return out;
}

function appendEmployeeChangeLog(obj, code, changes, updatedBy) {
  if (!obj || !code || !changes || !changes.length) return;
  if (!obj.employeeChangeLog || typeof obj.employeeChangeLog !== 'object') obj.employeeChangeLog = {};
  const key = String(code);
  if (!Array.isArray(obj.employeeChangeLog[key])) obj.employeeChangeLog[key] = [];
  const at = new Date().toISOString();
  const by = String(updatedBy || 'system');
  changes.forEach(function (c) {
    obj.employeeChangeLog[key].push({
      at: at,
      by: by,
      field: c.field,
      label: c.label,
      from: c.from,
      to: c.to,
      text: (c.label || c.field) + ' Ø§Ø² Â«' + c.from + 'Â» Ø¨Ù‡ Â«' + c.to + 'Â» ØªØºÛŒÛŒØ± Ú©Ø±Ø¯'
    });
  });
  // keep last 300
  if (obj.employeeChangeLog[key].length > 300) {
    obj.employeeChangeLog[key] = obj.employeeChangeLog[key].slice(-300);
  }
}

async function storePutData(cfg, baseVersion, obj, updatedBy) {
  // Preserve portal fields the main app form does not know about (managerCode, portal password, requestsâ€¦)
  try {
    if (obj && Array.isArray(obj.employees) && baseVersion > 0) {
      const prev = await storeGetData(cfg);
      if (!prev.fail && prev.obj && Array.isArray(prev.obj.employees)) {
        const map = {};
        prev.obj.employees.forEach(function (e) { map[String(e.code)] = e; });
        if (!obj.employeeChangeLog || typeof obj.employeeChangeLog !== 'object') {
          obj.employeeChangeLog = (prev.obj.employeeChangeLog && typeof prev.obj.employeeChangeLog === 'object')
            ? JSON.parse(JSON.stringify(prev.obj.employeeChangeLog))
            : {};
        }

        // Managers stored in portalMeta so main-app saves cannot wipe them.
        var allowMgrWrite = String(updatedBy || '').indexOf('mgr-set:') === 0;
        var prevMeta = prev.obj.portalMeta && typeof prev.obj.portalMeta === 'object' ? prev.obj.portalMeta : {};
        if (!obj.portalMeta || typeof obj.portalMeta !== 'object') obj.portalMeta = {};
        obj.portalMeta = Object.assign({}, prevMeta, obj.portalMeta);
        obj.employees.forEach(function (e) {
          const p = map[String(e.code)];
          const codeKey = String(e.code);
          const m = obj.portalMeta[codeKey] || prevMeta[codeKey];
          if (!allowMgrWrite && m) {
            e.managerCode = m.managerCode || '';
            e.managerCode2 = m.managerCode2 || '';
          } else if (!allowMgrWrite && p) {
            if (p.managerCode) e.managerCode = p.managerCode;
            if (p.managerCode2) e.managerCode2 = p.managerCode2;
          }
          if (allowMgrWrite) {
            obj.portalMeta[codeKey] = {
              managerCode: e.managerCode || '',
              managerCode2: e.managerCode2 || ''
            };
          }
          if (p) {
            if (e.portalPassHash === undefined || e.portalPassHash === null) {
              if (p.portalPassHash) e.portalPassHash = p.portalPassHash;
            }
            if (e.portalEnabled === undefined || e.portalEnabled === null) {
              if (p.portalEnabled != null) e.portalEnabled = p.portalEnabled;
            }
            if (!e.portalPassChangedAt && p.portalPassChangedAt) e.portalPassChangedAt = p.portalPassChangedAt;
            // Ø§Ú¯Ø± Ú©Ù„Ø§ÛŒÙ†Øª family Ù†ÙØ±Ø³ØªØ§Ø¯ØŒ Ø§Ø² Ù‚Ø¨Ù„ÛŒ Ù†Ú¯Ù‡ Ø¯Ø§Ø± (ØªØ§ F5 Ù¾Ø§Ú© Ù†Ú©Ù†Ø¯)
            if (e.family === undefined && p.family) e.family = p.family;
            if (e.suppInsurance === undefined && p.suppInsurance) e.suppInsurance = p.suppInsurance;
            if (e.systemMessages === undefined && p.systemMessages) e.systemMessages = p.systemMessages;
            ['fatherName','mobile','address','phone','birthDate','militaryStatus','militaryExemptType','jobGrade','educationLevel','educationField','city'].forEach(function (k) {
              var inc = e[k];
              var prev = p[k];
              var incEmpty = (inc === undefined || inc === null || String(inc).trim() === '');
              var prevHas = (prev !== undefined && prev !== null && String(prev).trim() !== '');
              if (incEmpty && prevHas) e[k] = prev;
            });
            if ((!e.mobile || String(e.mobile).trim() === '') && e.phone) e.mobile = e.phone;
            if ((!e.phone || String(e.phone).trim() === '') && e.mobile) e.phone = e.mobile;
            if (e.childrenEligibleCount === undefined && p.childrenEligibleCount != null) e.childrenEligibleCount = p.childrenEligibleCount;

            try {
              var ex = (obj.employeeExtras && obj.employeeExtras[codeKey]) || (prev.obj.employeeExtras && prev.obj.employeeExtras[codeKey]) || {};
              var per = (ex && ex.personal) || {};
              if ((!e.fatherName || String(e.fatherName).trim() === '') && per.fatherName) e.fatherName = per.fatherName;
              if ((!e.mobile || String(e.mobile).trim() === '') && (per.mobile || per.phone)) e.mobile = per.mobile || per.phone;
              if ((!e.address || String(e.address).trim() === '') && per.address) e.address = per.address;
              ['birthDate','militaryStatus','militaryExemptType','jobGrade','educationLevel','educationField','city'].forEach(function(pk){
                if ((!e[pk] || String(e[pk]).trim() === '') && per[pk]) e[pk] = per[pk];
              });
              if (!obj.employeeExtras) obj.employeeExtras = {};
              if (!obj.employeeExtras[codeKey] || typeof obj.employeeExtras[codeKey] !== 'object') obj.employeeExtras[codeKey] = Object.assign({}, (prev.obj.employeeExtras && prev.obj.employeeExtras[codeKey]) || {});
              obj.employeeExtras[codeKey].personal = {
                fatherName: e.fatherName || '',
                mobile: e.mobile || e.phone || '',
                address: e.address || '',
                birthDate: e.birthDate || '',
                militaryStatus: e.militaryStatus || '',
                militaryExemptType: e.militaryExemptType || '',
                jobGrade: e.jobGrade || '',
                educationLevel: e.educationLevel || '',
                educationField: e.educationField || '',
                city: e.city || ''
              };
            } catch (ePer) {}

            if ((e.photo === undefined || e.photo === null || e.photo === '') && p.photo) e.photo = p.photo;
            // ØªØ§Ø±ÛŒØ®Ú†Ù‡ ØªØºÛŒÛŒØ±Ø§Øª Ú©Ø§Ø±Øª Ú©Ø§Ø±Ù…Ù†Ø¯
            try {
              const ch = diffEmployeeChanges(p, e);
              if (ch.length) appendEmployeeChangeLog(obj, e.code, ch, updatedBy);
            } catch (eLog) {}
          }
        });
        // Ø­ÙØ¸ ØªØ§Ø±ÛŒØ®Ú†Ù‡ Ù‚Ø¨Ù„ÛŒ Ø§Ú¯Ø± Ú©Ù„Ø§ÛŒÙ†Øª Ù†ÙØ±Ø³ØªØ§Ø¯Ù‡
        if (prev.obj.employeeChangeLog && typeof prev.obj.employeeChangeLog === 'object') {
          if (!obj.employeeChangeLog || typeof obj.employeeChangeLog !== 'object') {
            obj.employeeChangeLog = prev.obj.employeeChangeLog;
          } else {
            Object.keys(prev.obj.employeeChangeLog).forEach(function (k) {
              if (!obj.employeeChangeLog[k]) obj.employeeChangeLog[k] = prev.obj.employeeChangeLog[k];
            });
          }
        }
        if (obj.attendanceTypes === undefined && prev.obj.attendanceTypes) obj.attendanceTypes = prev.obj.attendanceTypes;
        if (obj.attendanceRequests === undefined && prev.obj.attendanceRequests) obj.attendanceRequests = prev.obj.attendanceRequests;
        if (obj.attendanceGrants === undefined && prev.obj.attendanceGrants) obj.attendanceGrants = prev.obj.attendanceGrants;
        if (obj.contracts === undefined && prev.obj.contracts) obj.contracts = prev.obj.contracts;
        if (obj.employeeChangeLog === undefined && prev.obj.employeeChangeLog) obj.employeeChangeLog = prev.obj.employeeChangeLog;
        // ØªÙ†Ø¸ÛŒÙ…Ø§Øª Ù†Ù…Ø§ÛŒØ´ Ø­Ú©Ù…/Ù…Ø´Ø®ØµØ§Øª ÙÙ‚Ø· ØªÙˆØ³Ø· Ø®ÙˆØ¯ Ø°Ø®ÛŒØ±Ù‡â€ŒÛŒ Ù¾ÙˆØ±ØªØ§Ù„â€ŒÙˆÛŒÙˆ (updatedBy = 'portal-view:...') Ù‚Ø§Ø¨Ù„ ØªØºÛŒÛŒØ± Ø§Ø³ØªØ›
        // Ø°Ø®ÛŒØ±Ù‡â€ŒÙ‡Ø§ÛŒ Ø¯ÛŒÚ¯Ø± (ÙØ±Ù… Ø§ØµÙ„ÛŒ) Ù†Ø³Ø®Ù‡â€ŒÛŒ Ù‚Ø¨Ù„ÛŒ Ø±Ø§ Ø­ÙØ¸ Ù…ÛŒâ€ŒÚ©Ù†Ù†Ø¯. (Ù‚Ø¨Ù„Ø§Ù‹ Ø§ÛŒÙ† Ø®Ø· Ø°Ø®ÛŒØ±Ù‡â€ŒÛŒ Ø®ÙˆØ¯ Ù¾ÙˆØ±ØªØ§Ù„â€ŒÙˆÛŒÙˆ Ø±Ø§ Ù‡Ù… Ø¨Ø±Ù…ÛŒâ€ŒÚ¯Ø±Ø¯Ø§Ù†Ø¯!)
        if (String(updatedBy || '').indexOf('portal-view:') !== 0) {
          if (prev.obj.portalViewConfig) obj.portalViewConfig = prev.obj.portalViewConfig;
        }
        // Ù¾ÛŒØ§Ù…â€ŒÙ‡Ø§ÛŒ Ù‡Ù…Ú¯Ø§Ù†ÛŒ Ø§Ø¯Ù…ÛŒÙ†: ÙÙ‚Ø· Ø°Ø®ÛŒØ±Ù‡â€ŒÙ‡Ø§ÛŒ Ø®ÙˆØ¯ Ù¾ÛŒØ§Ù…â€ŒØ±Ø³Ø§Ù† (updatedBy = 'bcast:...') Ù…ÛŒâ€ŒØªÙˆØ§Ù†Ù†Ø¯ ØªØºÛŒÛŒØ±Ø´Ø§Ù† Ø¯Ù‡Ù†Ø¯
        if (String(updatedBy || '').indexOf('bcast:') !== 0) {
          if (Array.isArray(prev.obj.broadcastMessages)) obj.broadcastMessages = prev.obj.broadcastMessages;
        }
        // Ø®Ø§Ù†ÙˆØ§Ø¯Ù‡ / Ø¨ÛŒÙ…Ù‡ ØªÚ©Ù…ÛŒÙ„ÛŒ / Ø¹Ú©Ø³ â€” Ù‡Ø±Ú¯Ø² Ø¨Ø§ Ø°Ø®ÛŒØ±Ù‡ ÙØ±Ù… Ø§ØµÙ„ÛŒ Ù¾Ø§Ú© Ù†Ø´ÙˆÙ†Ø¯
        if (prev.obj.employeeExtras && typeof prev.obj.employeeExtras === 'object') {
          obj.employeeExtras = Object.assign({}, prev.obj.employeeExtras, obj.employeeExtras || {});
        }
        if (prev.obj.employeePhotos && typeof prev.obj.employeePhotos === 'object') {
          obj.employeePhotos = Object.assign({}, prev.obj.employeePhotos, obj.employeePhotos || {});
        }
        // Ø´Ø±Ø­ ÙˆØ¸Ø§ÛŒÙ â€” ÙÙ‚Ø· Ø¨Ø§ updatedBy jobdesc: ØªØºÛŒÛŒØ± Ú©Ù†Ø¯
        if (String(updatedBy || '').indexOf('jobdesc:') !== 0) {
          if (prev.obj.jobDescriptions && typeof prev.obj.jobDescriptions === 'object') {
            obj.jobDescriptions = prev.obj.jobDescriptions;
          }
          if (prev.obj.settings && prev.obj.settings.jobDescTemplate != null) {
            if (!obj.settings || typeof obj.settings !== 'object') obj.settings = {};
            if (obj.settings.jobDescTemplate == null) obj.settings.jobDescTemplate = prev.obj.settings.jobDescTemplate;
            if (obj.settings.jobDescShow == null && prev.obj.settings.jobDescShow != null) obj.settings.jobDescShow = prev.obj.settings.jobDescShow;
            if (obj.settings.jobDescCustomFields == null && prev.obj.settings.jobDescCustomFields != null) obj.settings.jobDescCustomFields = prev.obj.settings.jobDescCustomFields;
          }
        }
        // Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ùˆ ØªÙ‚ÙˆÛŒÙ… Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯: Ø§Ú¯Ø± Ú©Ù„Ø§ÛŒÙ†Øª (ÙØ±Ù… Ø§ØµÙ„ÛŒ) Ù„ÛŒØ³Øª Ù†Ø§Ù‚Øµ ÙØ±Ø³ØªØ§Ø¯ØŒ Ù„ÛŒØ³Øª Ú©Ø§Ù…Ù„ Ø³Ø±ÙˆØ± Ø­ÙØ¸ Ø´ÙˆØ¯
        try {
          if (prev.obj.settings && typeof prev.obj.settings === 'object') {
            if (!obj.settings || typeof obj.settings !== 'object') obj.settings = {};
            var prevList = Array.isArray(prev.obj.settings.contractTypesList) ? prev.obj.settings.contractTypesList : [];
            var curList = Array.isArray(obj.settings.contractTypesList) ? obj.settings.contractTypesList : [];
            if (prevList.length > curList.length) {
              // Ø§Ø¯ØºØ§Ù…: Ù‡Ù…Ù‡Ù” Ù‚Ø¨Ù„ÛŒ + Ø¬Ø¯ÛŒØ¯Ù‡Ø§ÛŒ Ú©Ù„Ø§ÛŒÙ†Øª
              var byId = {};
              prevList.forEach(function (t) { if (t && t.id) byId[t.id] = t; });
              curList.forEach(function (t) { if (t && t.id) byId[t.id] = t; });
              obj.settings.contractTypesList = Object.keys(byId).map(function (k) { return byId[k]; });
            } else if (!curList.length && prevList.length) {
              obj.settings.contractTypesList = prevList;
            }
            if ((obj.settings.floatMinutes == null || obj.settings.floatMinutes === '') && prev.obj.settings.floatMinutes != null && prev.obj.settings.floatMinutes !== '') {
              obj.settings.floatMinutes = prev.obj.settings.floatMinutes;
            }
            if (prev.obj.settings.contractCalendars && typeof prev.obj.settings.contractCalendars === 'object') {
              if (!obj.settings.contractCalendars || typeof obj.settings.contractCalendars !== 'object') {
                obj.settings.contractCalendars = prev.obj.settings.contractCalendars;
              } else {
                var SCHED_KEEP = ['floatMinutes','floatCompensate','workStart','workEnd','dayEnd','hasBreak','breakStart','breakEnd','breakCountsAsWork','workWeekDays','countNonWorkDaysAsLeave','nonWorkLeaveTypeIds','holidaysByYear','daySchedules'];
                Object.keys(prev.obj.settings.contractCalendars).forEach(function (ctId) {
                  var prevCal = prev.obj.settings.contractCalendars[ctId];
                  if (!prevCal || typeof prevCal !== 'object') return;
                  if (!obj.settings.contractCalendars[ctId]) {
                    obj.settings.contractCalendars[ctId] = prevCal;
                    return;
                  }
                  var curCal = obj.settings.contractCalendars[ctId];
                  if (!curCal || typeof curCal !== 'object') {
                    obj.settings.contractCalendars[ctId] = prevCal;
                    return;
                  }
                  SCHED_KEEP.forEach(function (k) {
                    if (k === 'floatMinutes') return; // Ø¬Ø¯Ø§Ú¯Ø§Ù†Ù‡
                    if ((curCal[k] == null || curCal[k] === '') && prevCal[k] != null && prevCal[k] !== '') curCal[k] = prevCal[k];
                  });
                  // Ø´Ù†Ø§ÙˆØ±ÛŒ Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯: ÙÙ‚Ø· Ø§Ú¯Ø± Ø®Ø§Ù„ÛŒ Ø§Ø³Øª Ø§Ø² Ù‚Ø¨Ù„ÛŒ Ù¾Ø± Ú©Ù† â€” Ù‡Ø± Ø¹Ø¯Ø¯ ØµØ±ÛŒØ­ (Ø§Ø² Ø¬Ù…Ù„Ù‡ Û±Ûµ) Ù…Ø­ØªØ±Ù… Ø§Ø³Øª
                  var prevFm = parseFloatMinutesValue(prevCal.floatMinutes, null);
                  var curFm = parseFloatMinutesValue(curCal.floatMinutes, null);
                  if (curFm == null && prevFm != null) {
                    curCal.floatMinutes = prevFm;
                  }
                });
                // Ø´Ù†Ø§ÙˆØ±ÛŒ Ø³Ø±Ø§Ø³Ø±ÛŒ: Ù…Ù‚Ø¯Ø§Ø± Ø¬Ø¯ÛŒØ¯ Ø°Ø®ÛŒØ±Ù‡â€ŒØ´Ø¯Ù‡ Ø±Ø§ Ù‡Ø±Ú¯Ø² Ø¨Ù‡â€ŒØ®Ø§Ø·Ø± Â«Ù‚Ø¨Ù„ÛŒ Û¹Û°Â» Ø¨Ø±Ù†Ú¯Ø±Ø¯Ø§Ù†
                (function () {
                  var prevSF = parseFloatMinutesValue(prev.obj.settings && prev.obj.settings.floatMinutes, null);
                  var curSF = parseFloatMinutesValue(obj.settings && obj.settings.floatMinutes, null);
                  var fromFloatSet = String(updatedBy || '').indexOf('float-set:') === 0;
                  var prevPfm = parseFloatMinutesValue(prev.obj.settings && prev.obj.settings.portalFloatMinutes, null);
                  var curPfm = parseFloatMinutesValue(obj.settings && obj.settings.portalFloatMinutes, null);
                  var finalFm = null;
                  if (fromFloatSet && curSF != null) {
                    finalFm = curSF;
                  } else if (curPfm != null) {
                    finalFm = curPfm;
                  } else if (curSF != null) {
                    finalFm = curSF;
                  } else if (prevPfm != null) {
                    finalFm = prevPfm;
                  } else if (prevSF != null) {
                    finalFm = prevSF;
                  }
                  if (finalFm != null) {
                    obj.settings.floatMinutes = finalFm;
                    obj.settings.portalFloatMinutes = finalFm;
                    Object.keys(obj.settings.contractCalendars || {}).forEach(function (cid) {
                      if (String(cid) === 'hourly') return;
                      var cx = obj.settings.contractCalendars[cid];
                      if (cx && typeof cx === 'object') cx.floatMinutes = finalFm;
                    });
                  }
                })();
              }
            }
            if (prev.obj.settings.requestWindows != null && obj.settings.requestWindows == null) obj.settings.requestWindows = prev.obj.settings.requestWindows;
            if (prev.obj.settings.leavePolicy && prev.obj.settings.leavePolicy.byContractType) {
              if (!obj.settings.leavePolicy) obj.settings.leavePolicy = {};
              if (!obj.settings.leavePolicy.byContractType) obj.settings.leavePolicy.byContractType = {};
              Object.keys(prev.obj.settings.leavePolicy.byContractType).forEach(function (ctId) {
                if (obj.settings.leavePolicy.byContractType[ctId] == null) {
                  obj.settings.leavePolicy.byContractType[ctId] = prev.obj.settings.leavePolicy.byContractType[ctId];
                }
              });
            }
          }
        } catch (eCt) { /* non-fatal */ }
        try { mergeAllEmployeeExtras(obj); } catch (e2) { /* non-fatal */ }
      }
    }
  } catch (e) { /* non-fatal */ }

  // Ø³Ø¨Ú©â€ŒØ³Ø§Ø²ÛŒ Ù‚Ø¨Ù„ Ø§Ø² Ø°Ø®ÛŒØ±Ù‡: Ø¹Ú©Ø³ ØªÚ©Ø±Ø§Ø±ÛŒ Ø¯Ø§Ø®Ù„ extras Ùˆ Ø±ÙˆÛŒ emp Ø§Ú¯Ø± Ø¯Ø± employeePhotos Ù‡Ø³Øª
  try {
    if (obj.employeeExtras && typeof obj.employeeExtras === 'object') {
      Object.keys(obj.employeeExtras).forEach(function (k) {
        if (obj.employeeExtras[k] && obj.employeeExtras[k].photo) delete obj.employeeExtras[k].photo;
      });
    }
  } catch (eStrip) {}
  const text = JSON.stringify(obj);
  if (text.length > MAX_DOC_BYTES) return { fail: { reason: 'too_large', status: 413 } };
  if (baseVersion === 0) {
    await fetch(cfg.url + '/rest/v1/app_docs?on_conflict=name', {
      method: 'POST',
      headers: storeHeaders(cfg, { 'Content-Type': 'application/json', Prefer: 'resolution=ignore-duplicates,return=minimal' }),
      body: JSON.stringify([{ name: 'data', version: 0 }])
    });
  }
  const payload = JSON.stringify({
    version: baseVersion + 1,
    updated_by: updatedBy || 'system',
    updated_at: new Date().toISOString(),
    data: text
  });
  const r = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.data&version=eq.' + baseVersion + '&select=version', {
    method: 'PATCH',
    headers: storeHeaders(cfg, { 'Content-Type': 'application/json', Prefer: 'return=representation' }),
    body: payload
  });
  if (!r.ok) return { fail: await storeFail(r) };
  const rows = await r.json();
  if (Array.isArray(rows) && rows.length === 1) return { version: baseVersion + 1 };
  return { conflict: true };
}

// ---------- Password helpers (SHA-256 hex, same style as existing auth) ----------
async function hashPassword(pass) {
  const bytes = await sha256(String(pass || ''));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkPassword(plain, storedHash) {
  if (!storedHash || !plain) return false;
  const h = await hashPassword(plain);
  const a = new TextEncoder().encode(h);
  const b = new TextEncoder().encode(String(storedHash));
  return sameBytes(a, b);
}

// ---------- Session (admin/operator) ----------
function b64urlEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  let s = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const b = atob(s);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}

async function sessionKey(env) {
  const material = 'psp-session|' + String(env.SESSION_SECRET || '') + '|' + String(env.SITE_USERS || '') + '|' +
    String(env.SITE_USER || '') + '|' + String(env.SITE_PASSWORD || '');
  return crypto.subtle.importKey('raw', new TextEncoder().encode(material), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function makeToken(env, name, exp) {
  const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify({ u: name, e: exp })));
  const sig = await crypto.subtle.sign('HMAC', await sessionKey(env), new TextEncoder().encode(payload));
  return payload + '.' + b64urlEncode(new Uint8Array(sig));
}

function sessionCookie(token) {
  return COOKIE_NAME + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax';
}

const CLEAR_COOKIE = COOKIE_NAME + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

async function readSession(request, env, users) {
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)psp_session=([^;]+)/);
  if (!m) return null;
  const parts = m[1].split('.');
  if (parts.length !== 2) return null;
  try {
    const good = await crypto.subtle.verify('HMAC', await sessionKey(env), b64urlDecode(parts[1]), new TextEncoder().encode(parts[0]));
    if (!good) return null;
    const p = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    if (!p || typeof p.u !== 'string' || !Number.isFinite(p.e)) return null;
    if (p.e < Math.floor(Date.now() / 1000)) return null;
    if (!Object.prototype.hasOwnProperty.call(users, p.u)) return null;
    return { name: p.u, role: users[p.u].role, exp: p.e };
  } catch (e) {
    return null;
  }
}

// ---------- Employee session (separate cookie) ----------
async function empSessionKey(env) {
  const material = 'psp-emp|' + String(env.SESSION_SECRET || '') + '|' + String(env.SITE_USERS || '') + '|emp-portal';
  return crypto.subtle.importKey('raw', new TextEncoder().encode(material), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function makeEmpToken(env, code, fullName, exp) {
  const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify({ c: String(code), n: fullName || '', e: exp })));
  const sig = await crypto.subtle.sign('HMAC', await empSessionKey(env), new TextEncoder().encode(payload));
  return payload + '.' + b64urlEncode(new Uint8Array(sig));
}

function empCookie(token) {
  return EMP_COOKIE_NAME + '=' + token + '; Path=/; HttpOnly; Secure; SameSite=Lax';
}

const CLEAR_EMP_COOKIE = EMP_COOKIE_NAME + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';

async function readEmpSession(request, env) {
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)psp_emp=([^;]+)/);
  if (!m) return null;
  const parts = m[1].split('.');
  if (parts.length !== 2) return null;
  try {
    const good = await crypto.subtle.verify('HMAC', await empSessionKey(env), b64urlDecode(parts[1]), new TextEncoder().encode(parts[0]));
    if (!good) return null;
    const p = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    if (!p || typeof p.c !== 'string' || !Number.isFinite(p.e)) return null;
    if (p.e < Math.floor(Date.now() / 1000)) return null;
    return { code: p.c, fullName: p.n || '', exp: p.e };
  } catch (e) {
    return null;
  }
}


/** Ù‚Ø¨Ù„ Ø§Ø² Ù…Ø­Ø§Ø³Ø¨Ù‡: family/suppInsurance/Ù…Ø¨Ù„Øº ÙˆØ§Ø­Ø¯ Ø±Ø§ Ø§Ø² Ø°Ø®ÛŒØ±Ù‡ Ø³Ø±ÙˆØ± Ø±ÙˆÛŒ payload Ú©Ù„Ø§ÛŒÙ†Øª Ø¨Ù†Ø´Ø§Ù† */
async function enrichCalcDataFromStore(env, data) {
  try {
    const cfg = storeConfig(env);
    if (!cfg || !data) return data;
    const gd = await storeGetData(cfg);
    if (gd.fail || !gd.obj) return data;
    const byCode = {};
    (gd.obj.employees || []).forEach(function (e) {
      if (e && e.code != null) byCode[String(e.code)] = e;
    });
    (data.employees || []).forEach(function (e) {
      if (!e || e.code == null) return;
      const s = byCode[String(e.code)];
      if (!s) return;
      if (s.family) e.family = s.family;
      if (s.suppInsurance) e.suppInsurance = s.suppInsurance;
      if (s.childrenEligibleCount != null) e.childrenEligibleCount = s.childrenEligibleCount;
      if (s.children != null && (e.children == null || e.children === '')) e.children = s.children;
      if (s.suppInsuranceDeductCount != null) e.suppInsuranceDeductCount = s.suppInsuranceDeductCount;
      if (s.suppInsuranceDeduct != null) e.suppInsuranceDeduct = s.suppInsuranceDeduct;
      // Ø¢ÛŒØªÙ… Ú©Ø³Ø± Ø¨ÛŒÙ…Ù‡ ØªÚ©Ù…ÛŒÙ„ÛŒ
      if (Array.isArray(s.customItems) && s.customItems.length) {
        if (!Array.isArray(e.customItems)) e.customItems = e.customItems || [];
        var hasSupp = (e.customItems || []).some(function (ci) { return ci && /Ø¨ÛŒÙ…Ù‡\s*ØªÚ©Ù…ÛŒÙ„ÛŒ/.test(String(ci.name || '')); });
        if (!hasSupp) {
          s.customItems.forEach(function (ci) {
            if (ci && /Ø¨ÛŒÙ…Ù‡\s*ØªÚ©Ù…ÛŒÙ„ÛŒ/.test(String(ci.name || ''))) e.customItems.push(JSON.parse(JSON.stringify(ci)));
          });
        } else {
          // Ù…Ø¨Ù„Øº/ØªØ¹Ø¯Ø§Ø¯ Ø±Ø§ Ø§Ø² Ø³Ø±ÙˆØ± Ø¨Ù‡â€ŒØ±ÙˆØ² Ú©Ù†
          e.customItems.forEach(function (ci) {
            if (!ci || !/Ø¨ÛŒÙ…Ù‡\s*ØªÚ©Ù…ÛŒÙ„ÛŒ/.test(String(ci.name || ''))) return;
            var src = s.customItems.find(function (x) { return x && /Ø¨ÛŒÙ…Ù‡\s*ØªÚ©Ù…ÛŒÙ„ÛŒ/.test(String(x.name || '')); });
            if (src) {
              if (Number(src.amount) > 0) ci.amount = src.amount;
              if (src.qtyDefault != null) ci.qtyDefault = src.qtyDefault;
              ci.isDeduction = true;
              ci.entryType = 'quantity';
              ci.enabled = src.enabled !== false;
            }
          });
        }
      }
    });
    if (gd.obj.settings) {
      if (!data.settings || typeof data.settings !== 'object') data.settings = {};
      var sk = ['suppInsurancePerPerson', 'supplementaryInsurancePerPerson', 'suppInsPerPerson', 'suppInsuranceAmount', 'bimeTakmiliPerPerson'];
      sk.forEach(function (k) {
        if (Number(gd.obj.settings[k]) > 0) data.settings[k] = gd.obj.settings[k];
      });
    }
    // qty Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒ
    if (gd.obj.monthlyData && data.monthlyData) {
      Object.keys(gd.obj.monthlyData).forEach(function (mk) {
        if (!data.monthlyData[mk]) data.monthlyData[mk] = gd.obj.monthlyData[mk];
        else {
          Object.keys(gd.obj.monthlyData[mk] || {}).forEach(function (ck) {
            if (!data.monthlyData[mk][ck]) data.monthlyData[mk][ck] = gd.obj.monthlyData[mk][ck];
            else if (gd.obj.monthlyData[mk][ck] && gd.obj.monthlyData[mk][ck].qty) {
              if (!data.monthlyData[mk][ck].qty) data.monthlyData[mk][ck].qty = {};
              Object.keys(gd.obj.monthlyData[mk][ck].qty).forEach(function (qn) {
                if (data.monthlyData[mk][ck].qty[qn] == null || data.monthlyData[mk][ck].qty[qn] === '') {
                  data.monthlyData[mk][ck].qty[qn] = gd.obj.monthlyData[mk][ck].qty[qn];
                }
              });
            }
          });
        }
      });
    }
  } catch (eEn) {
    console.log(JSON.stringify({ event: 'enrich_calc_error', message: String(eEn && eEn.message) }));
  }
  return data;
}

// ---------- Payroll calculation ----------

function listEmployeesMissingContract(obj) {
  const emps = (obj && obj.employees) || [];
  const contracts = (obj && obj.contracts) || [];
  const out = [];
  function isApprovedContract(c) {
    if (!c) return false;
    const st = String(c.status || '').toLowerCase();
    if (st === 'terminated' || st === 'expired' || st === 'revoked') return false;
    // accepted: explicit adminApproved OR legacy status active/approved
    if (c.adminApproved === true || c.adminApproved === 1 || c.adminApproved === 'true') return true;
    if (st === 'active' || st === 'approved' || st === 'signed') return true;
    return false;
  }
  emps.forEach(function (e) {
    if (!e || e.status === 'inactive') return;
    const mine = contracts.filter(function (c) { return String(c.empCode) === String(e.code); });
    const ok = mine.some(isApprovedContract);
    if (!ok) {
      out.push({
        code: e.code,
        fullName: e.fullName || '',
        reason: mine.length ? 'Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ø¨Ø¯ÙˆÙ† ØªØ£ÛŒÛŒØ¯ Ø§Ø¯Ù…ÛŒÙ†' : 'Ø¨Ø¯ÙˆÙ† Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯'
      });
    }
  });
  return out;
}

const DECREE_ARREARS_ITEM = 'Ù…Ø¹ÙˆÙ‚Ù‡ Ø­Ú©Ù…';
const DECREE_ARREARS_VAR_ITEM = 'Ù…Ø¹ÙˆÙ‚Ù‡ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ùˆ Ù†ÙˆØ¨Øªâ€ŒÚ©Ø§Ø±ÛŒ Ø­Ú©Ù…';

function faDigitsToLatin(s) {
  return String(s == null ? '' : s)
    .replace(/[Û°-Û¹]/g, function (c) { return String(c.charCodeAt(0) - 1776); })
    .replace(/[Ù -Ù©]/g, function (c) { return String(c.charCodeAt(0) - 1632); });
}

// Ø§Ù†Ø¯ÛŒØ³ Ù…Ø§Ù‡Ù ØªØ§Ø±ÛŒØ® Ø§Ø¬Ø±Ø§ÛŒ Ø­Ú©Ù… (Ø³Ø§Ù„*12 + Ù…Ø§Ù‡-1)
function decreeEffIndex(dec) {
  const p = parseJalaliYMD(faDigitsToLatin(dec && dec.effectiveDate));
  return p ? (p.y * 12 + (p.m - 1)) : null;
}

function decreeNumDiff(newV, oldV) {
  newV = newV || {}; oldV = oldV || {};
  const keys = {};
  Object.keys(newV).forEach(function (k) { keys[k] = 1; });
  Object.keys(oldV).forEach(function (k) { keys[k] = 1; });
  let s = 0;
  // ÙÙ‚Ø· Ø¢ÛŒØªÙ…â€ŒÙ‡Ø§ÛŒ Ù…Ø´ØªØ±Ú©: Ø¯Ø± Ø­Ú©Ù… Ù‚Ø¨Ù„ÛŒ Ùˆ Ø¬Ø¯ÛŒØ¯ Ù‡Ø± Ø¯Ùˆ Ù…Ù‚Ø¯Ø§Ø± ØºÛŒØ±ØµÙØ± Ø¯Ø§Ø±Ù†Ø¯
  // (Ø¢ÛŒØªÙ…ÛŒ Ú©Ù‡ Ù‚Ø¨Ù„Ø§Ù‹ Ù†Ø¨ÙˆØ¯Ù‡ØŒ Ù…Ø«Ù„ Ø­Ù‚ Ø§ÙˆÙ„Ø§Ø¯ Ø¬Ø¯ÛŒØ¯ØŒ ÛŒØ§ Ø­Ø°Ù Ø´Ø¯Ù‡ØŒ Ø¯Ø± Ù…Ø§Ø¨Ù‡â€ŒØ§Ù„ØªÙØ§ÙˆØª Ù†Ù…ÛŒâ€ŒØ¢ÛŒØ¯)
  Object.keys(keys).forEach(function (k) {
    const a = Number(oldV[k]) || 0, b = Number(newV[k]) || 0;
    if (a !== 0 && b !== 0) s += b - a;
  });
  return s;
}

// Ù…Ù‚Ø§Ø¯ÛŒØ± Ø­Ú©Ù…Ù Ù…Ø¹ØªØ¨Ø± Ø¯Ø± Ù…Ø§Ù‡Ù idxØŒ Ø¨Ø¯ÙˆÙ† Ø­Ú©Ù… dec (Ø§Ú¯Ø± Ø­Ú©Ù… Ù‚Ø¨Ù„ÛŒ Ù†Ø¨ÙˆØ¯: Ù…Ù‚Ø§Ø¯ÛŒØ± Ù‚Ø¨Ù„ Ø§Ø² Ù‡Ù…ÛŒÙ† Ø­Ú©Ù…)

/** Ù‚Ø¨Ù„ Ø§Ø² Ù…Ø­Ø§Ø³Ø¨Ù‡: Ø­Ù‚ÙˆÙ‚ Ù¾Ø§ÛŒÙ‡ Ùˆ Ù¾Ø§ÛŒÙ‡ Ø³Ù†ÙˆØ§Øª Ø§Ø² Ú©Ø§Ø±Øª Ú©Ø§Ø±Ù…Ù†Ø¯ Ø±ÙˆÛŒ decreeValues */
function syncCardSalaryIntoDecreeData(data) {
  if (!data || !Array.isArray(data.employees)) return data;
  if (!data.decreeValues || typeof data.decreeValues !== 'object') data.decreeValues = {};
  var headers = Array.isArray(data.decreeHeaders) ? data.decreeHeaders : [];
  function isBas(h) {
    if (!h) return false;
    if (String(h.id) === 'basic' || String(h.id) === 'basicSalary') return true;
    var n = String(h.name || '').replace(/[\u200c\u200d]/g, ' ').replace(/\s+/g, ' ').trim();
    return n === 'Ø­Ù‚ÙˆÙ‚ Ù¾Ø§ÛŒÙ‡' || n.indexOf('Ø­Ù‚ÙˆÙ‚ Ù¾Ø§ÛŒÙ‡') === 0 || /^Ø­Ù‚ÙˆÙ‚ (Ùˆ Ù…Ø²Ø¯ )?Ù¾Ø§ÛŒÙ‡/.test(n);
  }
  function isSen(h) {
    if (!h) return false;
    if (String(h.id) === 'seniorityBase' || String(h.id) === 'seniority') return true;
    var n = String(h.name || '').replace(/[\u200c\u200d]/g, ' ').replace(/\s+/g, ' ').trim();
    return n === 'Ù¾Ø§ÛŒÙ‡ Ø³Ù†ÙˆØ§Øª' || n.indexOf('Ù¾Ø§ÛŒÙ‡ Ø³Ù†ÙˆØ§Øª') === 0;
  }
  data.employees.forEach(function (emp) {
    if (!emp || emp.code == null) return;
    var code = String(emp.code);
    if (!data.decreeValues[code]) data.decreeValues[code] = {};
    headers.forEach(function (h) {
      if (isBas(h) && emp.basicSalary != null && emp.basicSalary !== '') {
        data.decreeValues[code][h.id] = Number(emp.basicSalary) || 0;
      }
      if (isSen(h) && emp.seniorityBase != null && emp.seniorityBase !== '') {
        data.decreeValues[code][h.id] = Number(emp.seniorityBase) || 0;
      }
    });
  });
  return data;
}

function decreeValuesBefore(hist, dec, idx) {
  let best = null, bestIdx = -1, bestAt = '';
  hist.forEach(function (h) {
    if (!h || h === dec || !h.values) return;
    const ei = decreeEffIndex(h);
    if (ei == null || ei > idx) return;
    const at = String(h.at || '');
    if (ei > bestIdx || (ei === bestIdx && at > bestAt)) { best = h; bestIdx = ei; bestAt = at; }
  });
  return best ? best.values : (dec.prevValues || {});
}

// Ú©Ù„ÛŒØ¯Ù‡Ø§ÛŒ Â«Ø­Ù‚ÙˆÙ‚ Ù¾Ø§ÛŒÙ‡Â» Ø¯Ø± Ù…Ù‚Ø§Ø¯ÛŒØ± Ø­Ú©Ù… (Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±/Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ/Ù†ÙˆØ¨Øªâ€ŒÚ©Ø§Ø±ÛŒ Ø¨Ø± Ù¾Ø§ÛŒÙ‡ Ù‡Ù…ÛŒÙ† Ù…Ø¨Ù„Øº Ù…Ø­Ø§Ø³Ø¨Ù‡ Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯)
function decreeBasicKeys(headers) {
  const keys = ['basic'];
  (headers || []).forEach(function (h) {
    if (!h) return;
    const nm = String(h.name || '').replace(/[\u200c\u200f\u200e]/g, ' ').replace(/ÙŠ/g, 'ÛŒ').replace(/Ùƒ/g, 'Ú©').replace(/\s+/g, ' ').trim();
    if (/^Ø­Ù‚ÙˆÙ‚ (Ùˆ Ù…Ø²Ø¯ )?Ù¾Ø§ÛŒÙ‡( Ù…Ø§Ù‡Ø§Ù†Ù‡)?$/.test(nm) || String(h.id) === 'basic') {
      const id = String(h.id == null ? h.name : h.id);
      if (keys.indexOf(id) < 0) keys.push(id);
    }
  });
  return keys;
}

// Ú©Ù„ÛŒØ¯Ù‡Ø§ÛŒ Â«Ù¾Ø§ÛŒÙ‡ Ø³Ù†ÙˆØ§ØªÂ» Ø¯Ø± Ù…Ù‚Ø§Ø¯ÛŒØ± Ø­Ú©Ù…
function decreeSeniorityKeys(headers) {
  const keys = ['seniorityBase'];
  (headers || []).forEach(function (h) {
    if (!h) return;
    const nm = String(h.name || '').replace(/[\u200c\u200f\u200e]/g, ' ').replace(/ÙŠ/g, 'ÛŒ').replace(/Ùƒ/g, 'Ú©').replace(/\s+/g, ' ').trim();
    if (/^Ù¾Ø§ÛŒÙ‡ Ø³Ù†ÙˆØ§Øª( Ù…Ø§Ù‡Ø§Ù†Ù‡)?$/.test(nm) || String(h.id) === 'seniorityBase') {
      const id = String(h.id == null ? h.name : h.id);
      if (keys.indexOf(id) < 0) keys.push(id);
    }
  });
  return keys;
}

function decreeBasicOf(values, basicKeys) {
  values = values || {};
  let s = 0;
  basicKeys.forEach(function (k) { s += Number(values[k]) || 0; });
  return s;
}

// Ù…Ø¹ÙˆÙ‚Ù‡â€ŒØ§ÛŒ Ú©Ù‡ Ø¨Ø§ÛŒØ¯ Ø¯Ø± Ø­Ù‚ÙˆÙ‚ (year, month) Ù¾Ø±Ø¯Ø§Ø®Øª Ø´ÙˆØ¯: Ø§Ø­Ú©Ø§Ù…ÛŒ Ú©Ù‡ ØªØ§Ø±ÛŒØ® Ø§Ø¬Ø±Ø§ÛŒØ´Ø§Ù† Ø¯Ø± Ù‡Ù…ÛŒÙ† Ù…Ø§Ù‡ Ø§Ø³Øª Ùˆ Â«Ø¨Ø§ Ù…Ø¹ÙˆÙ‚Ù‡ N Ù…Ø§Ù‡Â» Ø¯Ø§Ø±Ù†Ø¯
// ctx (Ø§Ø®ØªÛŒØ§Ø±ÛŒ): { eng, emp, basicKeys } â€” Ø¨Ø±Ø§ÛŒ Ù…Ø­Ø§Ø³Ø¨Ù‡ Ù…Ø¬Ø¯Ø¯ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±/Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ/Ù†ÙˆØ¨Øªâ€ŒÚ©Ø§Ø±ÛŒ Ù…Ø§Ù‡â€ŒÙ‡Ø§ÛŒ Ù…Ø¹ÙˆÙ‚Ù‡ Ø¨Ø§ Ù¾Ø§ÛŒÙ‡ Ø¬Ø¯ÛŒØ¯
function computeDecreeArrears(hist, year, month, ctx) {
  let total = 0, varTotal = 0;
  const items = [];
  const varItems = [];
  const target = year * 12 + (month - 1);
  (hist || []).forEach(function (dec) {
    if (!dec || !dec.values) return;
    const n = Math.min(12, Math.floor(Number(dec.arrearsMonths) || 0));
    if (n < 1) return;
    if (decreeEffIndex(dec) !== target) return;
    let sub = 0, subVar = 0;
    const detail = [];
    if (dec.arrearsMode === 'items' && Array.isArray(dec.arrearsItems)) {
      // Â«Ù…Ø­Ø§Ø³Ø¨Ù‡ Ø§Ø² Ø¢ÛŒØªÙ…â€ŒÙ‡Ø§Â»: Ù…Ø¨Ù„Øº Ø¬Ø¯ÛŒØ¯ âˆ’ Ù…Ø¨Ù„Øº ÙÛŒØ´ Ù‡Ø± Ù…Ø§Ù‡ Ù…Ø¹ÙˆÙ‚Ù‡ (Ø¹Ú©Ø³ Ù„Ø­Ø¸Ù‡ ØµØ¯ÙˆØ± Ø­Ú©Ù…)
      // Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±ÛŒ/Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ/Ù†ÙˆØ¨Øªâ€ŒÚ©Ø§Ø±ÛŒ (auto): Ø¨Ø§ Ø³Ø§Ø¹Ø§Øª Ù‡Ø± Ù…Ø§Ù‡ Ù…Ø¹ÙˆÙ‚Ù‡ Ùˆ Ø­Ù‚ÙˆÙ‚ Ù¾Ø§ÛŒÙ‡ Ø¬Ø¯ÛŒØ¯ ØªÙˆØ³Ø· Ù…ÙˆØªÙˆØ± Ù…Ø­Ø§Ø³Ø¨Ù‡ Ù…ÛŒâ€ŒØ´ÙˆØ¯
      const newB = ctx ? decreeBasicOf(dec.values, ctx.basicKeys) : 0;
      dec.arrearsItems.forEach(function (it) {
        if (!it) return;
        if (it.auto) {
          if (!(ctx && ctx.eng && ctx.emp) || !(newB > 0)) return;
          (it.olds || []).forEach(function (o) {
            if (!o || o.amount == null) return; // Ù…Ø§Ù‡ÛŒ Ú©Ù‡ ÙÛŒØ´ Ù†Ø¯Ø§Ø´ØªÙ‡
            const pm = String(o.k || '').split('-');
            const py = Number(pm[0]), mm = Number(pm[1]);
            if (!py || !mm) return;
            const oldB = decreeBasicOf(decreeValuesBefore(hist, dec, py * 12 + (mm - 1)), ctx.basicKeys);
            if (!(oldB > 0) || oldB === newB) return;
            const vd = ctx.eng.calcVariablePayDiff(ctx.emp, oldB, newB, py, mm);
            if (!vd || !vd.found) return;
            const part = it.auto === 'ot' ? vd.ot : (it.auto === 'night' ? vd.night : vd.shift);
            if (part) { subVar += part; detail.push({ year: py, month: mm, item: it.name, amount: part }); }
          });
          return;
        }
        const nv = Number(it.newAmount) || 0;
        (it.olds || []).forEach(function (o) {
          if (!o || o.amount == null) return;
          sub += nv - (Number(o.amount) || 0);
        });
      });
    } else {
      // Â«Ù…Ø­Ø§Ø³Ø¨Ù‡ Ø§Ø² Ø­Ú©Ù…Â»: ÙÙ‚Ø· ØªÙØ§ÙˆØª Ø¢ÛŒØªÙ…â€ŒÙ‡Ø§ÛŒ Ù…Ø´ØªØ±Ú© Ù…Ø¨Ø§Ù„Øº Ø­Ú©Ù… (Ø¨Ø¯ÙˆÙ† Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±/Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ/Ù†ÙˆØ¨Øªâ€ŒÚ©Ø§Ø±ÛŒ)
      for (let k = 1; k <= n; k++) {
        sub += decreeNumDiff(dec.values, decreeValuesBefore(hist, dec, target - k));
      }
    }
    sub = Math.round(sub);
    subVar = Math.round(subVar);
    if (sub) { total += sub; items.push({ id: dec.id || '', title: dec.title || '', months: n, amount: sub }); }
    if (subVar) { varTotal += subVar; varItems.push({ id: dec.id || '', title: dec.title || '', months: n, amount: subVar, detail: detail }); }
  });
  return { total: total, items: items, varTotal: varTotal, varItems: varItems };
}

async function applyDecreeArrears(env, data, year, month) {
  const cfg = storeConfig(env);
  if (!cfg) return [];
  const gd = await storeGetData(cfg);
  if (gd.fail || !gd.obj || !gd.obj.employeeExtras) return [];
  const extras = gd.obj.employeeExtras;
  const basicKeys = decreeBasicKeys(gd.obj.decreeHeaders || data.decreeHeaders);
  const senKeys = decreeSeniorityKeys(gd.obj.decreeHeaders || data.decreeHeaders);
  let eng = null;
  try { eng = makeEngine(data); } catch (eEng) { eng = null; }
  const applied = [];
  (data.employees || []).forEach(function (emp) {
    if (!emp || emp.code == null) return;
    const ex = extras[String(emp.code)];
    const hist = ex && Array.isArray(ex.decreeHistory) ? ex.decreeHistory : null;
    if (!hist || !hist.length) return;
    // Ø­Ù‚ÙˆÙ‚ Ù¾Ø§ÛŒÙ‡ / Ù¾Ø§ÛŒÙ‡ Ø³Ù†ÙˆØ§Øª Ú©Ø§Ø±Øª Ø¨Ø§ Ø­Ú©Ù… Ù‡Ù…Ú¯Ø§Ù… Ø´Ø¯Ù‡ Ø§Ø³ØªØ› Ø¨Ø±Ø§ÛŒ Ù…Ø§Ù‡â€ŒÙ‡Ø§ÛŒ Ù‚Ø¨Ù„ Ø§Ø² Ø§Ø¬Ø±Ø§ÛŒ Ø­Ú©Ù…ØŒ Ù…Ù‚Ø§Ø¯ÛŒØ± Â«Ù‚Ø¨Ù„ Ø§Ø² Ø­Ú©Ù…Â» Ù‡Ù…Ø§Ù† Ø­Ú©Ù… Ø§Ø³ØªÙØ§Ø¯Ù‡ Ù…ÛŒâ€ŒØ´ÙˆØ¯
    // (ÙÙ‚Ø· Ø§Ø­Ú©Ø§Ù… ØµØ§Ø¯Ø±Ø´Ø¯Ù‡ Ø¨Ø§ Ù‡Ù…Ú¯Ø§Ù…â€ŒØ³Ø§Ø²ÛŒ Ú©Ø§Ø±Øª: cardSynced)
    try {
      const tgt = year * 12 + (month - 1);
      const synced = hist.filter(function (d) { return d && d.cardSynced && d.values && d.prevValues && typeof d.prevValues === 'object'; })
        .map(function (d) { return { d: d, eff: decreeEffIndex(d) }; })
        .filter(function (x) { return x.eff != null; })
        .sort(function (a, b) { return a.eff - b.eff; });
      const nxt = synced.find(function (x) { return x.eff > tgt; });
      if (nxt) {
        const pb = decreeBasicOf(nxt.d.prevValues, basicKeys);
        if (pb > 0) emp.basicSalary = pb;
        let hasSen = false, ps = 0;
        senKeys.forEach(function (k) { if (nxt.d.prevValues[k] != null && nxt.d.prevValues[k] !== '') { hasSen = true; ps += Number(nxt.d.prevValues[k]) || 0; } });
        if (hasSen) emp.seniorityBase = ps;
      }
    } catch (eSyn) {}
    const res = computeDecreeArrears(hist, year, month, { eng: eng, emp: emp, basicKeys: basicKeys });
    const code = String(emp.code);
    if (!Array.isArray(emp.customItems)) emp.customItems = [];
    if (!res.total && !res.varTotal) return;
    // Ø§Ø¬Ø±Ø§ÛŒ Ù…Ø¬Ø¯Ø¯ Ù…Ø­Ø§Ø³Ø¨Ù‡ØŒ Ø¢ÛŒØªÙ…â€ŒÙ‡Ø§ÛŒ Ø®ÙˆØ¯Ú©Ø§Ø± Ù‚Ø¨Ù„ÛŒ Ø±Ø§ Ø¬Ø§ÛŒÚ¯Ø²ÛŒÙ† Ù…ÛŒâ€ŒÚ©Ù†Ø¯
    emp.customItems = emp.customItems.filter(function (ci) { return !(ci && (ci.name === DECREE_ARREARS_ITEM || ci.name === DECREE_ARREARS_VAR_ITEM)); });
    const row = ensureEmpMonthRow(data, year, month, code);
    if (!row.qty || typeof row.qty !== 'object') row.qty = {};
    function pushItem(name, amount, note) {
      emp.customItems.push({
        name: name,
        amount: Math.abs(amount),
        isDeduction: amount < 0,
        entryType: 'quantity',
        enabled: true,
        active: true,
        value: true,
        flag: 'Ø¨Ù„ÛŒ',
        qtyDefault: 1,
        duration: 'always',
        note: note
      });
      row.qty[name] = 1;
    }
    if (res.total) pushItem(DECREE_ARREARS_ITEM, res.total, 'Ø®ÙˆØ¯Ú©Ø§Ø± Ø§Ø² Ø§Ø­Ú©Ø§Ù…: ' + res.items.map(function (x) { return x.months + ' Ù…Ø§Ù‡'; }).join('ØŒ '));
    if (res.varTotal) pushItem(DECREE_ARREARS_VAR_ITEM, res.varTotal, 'Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±ÛŒ/Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ/Ù†ÙˆØ¨Øªâ€ŒÚ©Ø§Ø±ÛŒ Ù…Ø§Ù‡â€ŒÙ‡Ø§ÛŒ Ù…Ø¹ÙˆÙ‚Ù‡ Ø¨Ø§ Ù¾Ø§ÛŒÙ‡ Ø¬Ø¯ÛŒØ¯: ' + res.varItems.map(function (x) { return x.months + ' Ù…Ø§Ù‡'; }).join('ØŒ '));
    applied.push({ code: code, total: res.total, items: res.items, varTotal: res.varTotal, varItems: res.varItems });
  });
  return applied;
}

async function handlePayroll(request, user, env) {
  const r = await readBody(request);
  if (r.error) return r.error;
  const body = r.body;
  const year = Number(body.year);
  const month = Number(body.month);
  if (!Number.isInteger(year) || year < 1300 || year > 1600 ||
      !Number.isInteger(month) || month < 1 || month > 12 ||
      !isPlainObject(body.settings) || !Array.isArray(body.employees) || !Array.isArray(body.allowances) ||
      !isPlainObject(body.monthlyData) || !isPlainObject(body.payrolls)) {
    return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  }
  let data = {
    settings: body.settings,
    allowances: body.allowances,
    employees: body.employees,
    monthlyData: body.monthlyData,
    payrolls: body.payrolls,
    loanDeductedMonths: isPlainObject(body.loanDeductedMonths) ? body.loanDeductedMonths : {},
    transferredAdjustments: isPlainObject(body.transferredAdjustments) ? body.transferredAdjustments : {}
  };
  data = await enrichCalcDataFromStore(env, data);
  let decreeArrears = [];
  try { decreeArrears = await applyDecreeArrears(env, data, year, month); } catch (eDa) { decreeArrears = []; }
  let contractWarnings = [];
  try {
    const cfg = storeConfig(env);
    if (cfg) {
      const gd = await storeGetData(cfg);
      if (!gd.fail && gd.obj) {
        const full = Object.assign({}, gd.obj, { employees: data.employees });
        contractWarnings = listEmployeesMissingContract(full);
      }
    }
  } catch (eCw) {}
  let out;
  try {
    try { data = syncCardSalaryIntoDecreeData(data) || data; } catch (eS2) {}
    // punchDaysØ› workDays Ø§Ø² Ú©Ù„Ø§ÛŒÙ†Øª (ÙˆØ±ÙˆØ¯ Ø¯Ø§Ø¯Ù‡/ØªØ§ÛŒÙ…â€ŒØ´ÛŒØª) Ø­ÙØ¸ Ù…ÛŒâ€ŒØ´ÙˆØ¯ â€” Ø¯ÙˆØ¨Ø§Ø±Ù‡ Ú©Ù… Ù†Ø´ÙˆØ¯
    try {
      const key = year + '-' + month;
      if (!data.monthlyData) data.monthlyData = {};
      if (!data.monthlyData[key]) data.monthlyData[key] = {};
      // Ú©Ù„ÛŒØ¯Ù‡Ø§ÛŒ Ø¬Ø§ÛŒÚ¯Ø²ÛŒÙ† 1405-8 Ùˆ 1405-08
      const altKey = year + '-' + String(month).padStart(2, '0');
      if (altKey !== key && data.monthlyData[altKey]) {
        Object.keys(data.monthlyData[altKey]).forEach(function (code) {
          if (!data.monthlyData[key][code]) data.monthlyData[key][code] = data.monthlyData[altKey][code];
        });
      }
      Object.keys(data.monthlyData[key]).forEach(function (code) {
        if (code === '_meta') return;
        const row = data.monthlyData[key][code];
        if (!row) return;
        // Ø§Ú¯Ø± workDays ØµÙØ±/Ø®Ø§Ù„ÛŒ Ø§Ø³Øª Ø§Ø² Ú©Ù„ÛŒØ¯ Ø¬Ø§ÛŒÚ¯Ø²ÛŒÙ† Ø¨Ø®ÙˆØ§Ù†
        if (!(Number(row.workDays) > 0) && data.monthlyData[altKey] && data.monthlyData[altKey][code]) {
          const r2 = data.monthlyData[altKey][code];
          if (Number(r2.workDays) > 0) row.workDays = r2.workDays;
        }
        try {
          if (typeof countEmpMonthPunchDays === 'function') {
            row.punchDays = countEmpMonthPunchDays(data, year, month, code);
            try { applyAbsenceToQtyFlatItems(data, year, month, code, row); } catch (eAbs) {}
          }
        } catch (eP) {}
      });
    } catch (ePD) {}
    out = makeEngine(data).runMonth(year, month, { skipLoanSE: !!body.skipLoanSE });
  } catch (e) {
    console.log(JSON.stringify({ event: 'payroll_error', user: user, message: String(e && e.message) }));
    return jsonResponse({ ok: false, error: 'calculation_failed' }, 500);
  }
  if (out && typeof out === 'object') {
    out.contractWarnings = contractWarnings;
    out.decreeArrears = decreeArrears;
    if (contractWarnings.length) {
      out.contractWarningMessage = contractWarnings.length + ' Ù†ÙØ± ÙØ§Ù‚Ø¯ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ ØªØ£ÛŒÛŒØ¯Ø´Ø¯Ù‡ Ù‡Ø³ØªÙ†Ø¯. Ù…Ø­Ø§Ø³Ø¨Ù‡ Ø­Ù‚ÙˆÙ‚ ÙÙ‚Ø· Ø¨Ø±Ø§ÛŒ Ø§ÙØ±Ø§Ø¯ Ø¯Ø§Ø±Ø§ÛŒ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ ØªØ£ÛŒÛŒØ¯Ø´Ø¯Ù‡ Ù…Ø¹ØªØ¨Ø± Ø§Ø³Øª.';
    }
  }
  console.log(JSON.stringify({ event: 'payroll', user: user, year: year, month: month, employees: data.employees.length, contractWarnings: contractWarnings.length }));
  return jsonResponse(out, out.ok ? 200 : 400);
}

async function handleCalc(request, user, env) {
  const r = await readBody(request);
  if (r.error) return r.error;
  const body = r.body;
  const op = body.op;
  let data = {
    settings: objOf(body.settings),
    allowances: arrOf(body.allowances),
    employees: arrOf(body.employees),
    monthlyData: objOf(body.monthlyData),
    payrolls: objOf(body.payrolls),
    decreeHeaders: arrOf(body.decreeHeaders),
    decreeValues: objOf(body.decreeValues),
    eidTaxAdjustments: objOf(body.eidTaxAdjustments)
  };
  if (data.employees.length > MAX_ITEMS || data.allowances.length > MAX_ITEMS) {
    return jsonResponse({ ok: false, error: 'too_many_items' }, 413);
  }
  data = await enrichCalcDataFromStore(env, data);
  try { data = syncCardSalaryIntoDecreeData(data) || data; } catch (eSyncD) {}
  const bad = function () { return jsonResponse({ ok: false, error: 'bad_request' }, 400); };
  let result;
  try {
    const eng = makeEngine(data);
    if (op === 'eid') {
      const year = Number(body.year);
      if (!isInt(year, 1300, 1600) || !isNum(body.minDaily) || body.minDaily <= 0 ||
          !isNum(body.leaveCeilingVal) || body.leaveCeilingVal < 0 || typeof body.includeSpecialDays !== 'boolean') return bad();
      result = { ok: true, results: eng.runEid(year, body.minDaily, body.leaveCeilingVal, body.includeSpecialDays) };
    } else if (op === 'annualTax') {
      const year = Number(body.year);
      const until = Number(body.until);
      if (!isInt(year, 1300, 1600) || !isInt(until, 1, 12) || !Array.isArray(body.selected) || body.selected.length > MAX_ITEMS) return bad();
      const bracketsBefore = JSON.stringify(data.settings.taxBrackets);
      result = { ok: true, results: eng.runAnnualTax(year, until, body.selected) };
      result.filledTaxBrackets = JSON.stringify(data.settings.taxBrackets) !== bracketsBefore;
    } else if (op === 'bonusBases') {
      if (typeof body.baseType !== 'string' || !Array.isArray(body.names)) return bad();
      result = { ok: true, bases: eng.bonusBases(data.employees, body.baseType, body.names) };
    } else if (op === 'bonusRows') {
      if (!Array.isArray(body.rows) || body.rows.length > MAX_ITEMS) return bad();
      const bracketsBefore = JSON.stringify(data.settings.taxBrackets);
      result = { ok: true, rows: eng.bonusRows(body.rows) };
      result.filledTaxBrackets = JSON.stringify(data.settings.taxBrackets) !== bracketsBefore;
    } else if (op === 'decreeAmounts') {
      const year = Number(body.year);
      if (!isInt(year, 1300, 1600) || !Array.isArray(body.selectedNames) || body.selectedNames.length > MAX_ITEMS) return bad();
      result = { ok: true, entries: eng.decreeAmounts(year, body.selectedNames) };
    } else {
      return jsonResponse({ ok: false, error: 'unknown_op' }, 400);
    }
  } catch (e) {
    console.log(JSON.stringify({ event: 'calc_error', user: user, op: String(op), message: String(e && e.message) }));
    return jsonResponse({ ok: false, error: 'calculation_failed' }, 500);
  }
  console.log(JSON.stringify({ event: 'calc', user: user, op: op, employees: data.employees.length }));
  return jsonResponse(result);
}

function handleWhoami(request, who, adminConfigured, env) {
  if (request.method !== 'GET') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  return jsonResponse({ ok: true, user: who.name, role: who.role, adminConfigured: adminConfigured, syncConfigured: !!storeConfig(env) });
}


async function handleState(request, who, env, path) {
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin' && !(site === 'none' && request.method === 'GET')) return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured', reason: 'not_configured' }, 503);
  const rest = path.slice('/api/state/'.length);
  const url = new URL(request.url);
  try {
    if (rest === 'version') {
      if (request.method !== 'GET') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
      const vr = await storeVersions(cfg);
      if (vr.fail) return storeFailResponse(vr.fail);
      return jsonResponse({ ok: true, versions: vr.versions });
    }
    if (STATE_DOCS.indexOf(rest) < 0) return jsonResponse({ ok: false, error: 'unknown_document' }, 404);

    if (request.method === 'GET') {
      const r = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.' + rest + '&select=version,updated_by,updated_at,data',
        { headers: storeHeaders(cfg, { Accept: 'application/vnd.pgrst.object+json' }) });
      if (r.status === 406) return jsonResponse({ ok: true, version: 0, data: null });
      if (!r.ok) return storeFailResponse(await storeFail(r));
      const text = (await r.text()).trim();
      if (text.charAt(0) !== '{') return jsonResponse({ ok: false, error: 'store_error' }, 502);
      // Ø¨Ø±Ø§ÛŒ Ø³Ù†Ø¯ data: Ø®Ø§Ù†ÙˆØ§Ø¯Ù‡ Ø±Ø§ Ø§Ø² employeeExtras Ø§Ø¯ØºØ§Ù… Ú©Ù† â€” data Ø¨Ø§ÛŒØ¯ STRING Ø¨Ù…Ø§Ù†Ø¯ (Ú©Ù„Ø§ÛŒÙ†Øª JSON.parse Ù…ÛŒâ€ŒÚ©Ù†Ø¯)
      if (rest === 'data') {
        try {
          const row = JSON.parse(text);
          if (row && row.data) {
            let parsed = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
            if (parsed && typeof parsed === 'object') {
              try { mergeAllEmployeeExtras(parsed); } catch (eM) {}
              // Ø­ØªÙ…Ø§Ù‹ Ø¯ÙˆØ¨Ø§Ø±Ù‡ Ø±Ø´ØªÙ‡ Ø´ÙˆØ¯ ØªØ§ Ù‡Ù…Ú¯Ø§Ù…â€ŒØ³Ø§Ø²ÛŒ Ú©Ù„Ø§ÛŒÙ†Øª Ù†Ø´Ú©Ù†Ø¯
              row.data = JSON.stringify(parsed);
              const out = JSON.stringify(Object.assign({ ok: true }, row));
              return new Response(out, {
                status: 200,
                headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
              });
            }
          }
        } catch (eGet) { /* fallback raw */ }
      }
      return new Response('{"ok":true,' + text.slice(1), {
        status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }

    if (request.method === 'PUT') {
      if (rest === 'settings' && who.role !== 'admin') return jsonResponse({ ok: false, error: 'admin_only' }, 403);
      const baseRaw = url.searchParams.get('base');
      const base = Number(baseRaw);
      if (baseRaw === null || baseRaw === '' || !Number.isInteger(base) || base < 0) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
      if (Number(request.headers.get('Content-Length') || 0) > MAX_DOC_BYTES) return jsonResponse({ ok: false, error: 'too_large' }, 413);
      let text = (await request.text()).trim();
      if (text.length > MAX_DOC_BYTES) return jsonResponse({ ok: false, error: 'too_large' }, 413);
      if (text.charAt(0) !== '{' || text.charAt(text.length - 1) !== '}') return jsonResponse({ ok: false, error: 'bad_body' }, 400);

      // Ø³Ù†Ø¯ data: Ø­ÙØ¸/Ø§Ø¯ØºØ§Ù… Ù†ÙˆØ¹â€ŒÙ‚Ø±Ø§Ø±Ø¯Ø§Ø¯ + Ø­Ø°Ù ØªÚ©Ø±Ø§Ø±ÛŒ Ù‡Ù†Ú¯Ø§Ù… Ù‡Ù…Ú¯Ø§Ù…â€ŒØ³Ø§Ø²ÛŒ ÙØ±Ù… Ø§ØµÙ„ÛŒ
      if (rest === 'data' && base > 0) {
        try {
          const incoming = JSON.parse(text);
          if (incoming && typeof incoming === 'object') {
            const prev = await storeGetData(cfg);
            if (!prev.fail && prev.obj && prev.obj.settings) {
              if (!incoming.settings || typeof incoming.settings !== 'object') incoming.settings = {};
              const prevList = Array.isArray(prev.obj.settings.contractTypesList) ? prev.obj.settings.contractTypesList : [];
              const curList = Array.isArray(incoming.settings.contractTypesList) ? incoming.settings.contractTypesList : [];
              // Ø§ÙˆÙ„ Ù„ÛŒØ³Øª Ù‚Ø¨Ù„ÛŒ Ø±Ø§ Ø¨Ú¯Ø°Ø§Ø± ØªØ§ Ø­Ø°Ù Ù†Ø´ÙˆÙ†Ø¯ØŒ Ø¨Ø¹Ø¯ Ù„ÛŒØ³Øª Ú©Ù„Ø§ÛŒÙ†Øª
              incoming.settings.contractTypesList = prevList.concat(curList);
              if ((incoming.settings.floatMinutes == null || incoming.settings.floatMinutes === '') && prev.obj.settings.floatMinutes != null && prev.obj.settings.floatMinutes !== '') {
                incoming.settings.floatMinutes = prev.obj.settings.floatMinutes;
              }
              if (prev.obj.settings.contractCalendars && typeof prev.obj.settings.contractCalendars === 'object') {
                if (!incoming.settings.contractCalendars || typeof incoming.settings.contractCalendars !== 'object') {
                  incoming.settings.contractCalendars = prev.obj.settings.contractCalendars;
                } else {
                  var SCHED_KEEP2 = ['floatMinutes','floatCompensate','workStart','workEnd','dayEnd','hasBreak','breakStart','breakEnd','breakCountsAsWork','workWeekDays','countNonWorkDaysAsLeave','nonWorkLeaveTypeIds','holidaysByYear','daySchedules'];
                  Object.keys(prev.obj.settings.contractCalendars).forEach(function (ctId) {
                    var prevCal = prev.obj.settings.contractCalendars[ctId];
                    if (!prevCal || typeof prevCal !== 'object') return;
                    if (!incoming.settings.contractCalendars[ctId]) {
                      incoming.settings.contractCalendars[ctId] = prevCal;
                      return;
                    }
                    var curCal = incoming.settings.contractCalendars[ctId];
                    if (!curCal || typeof curCal !== 'object') {
                      incoming.settings.contractCalendars[ctId] = prevCal;
                      return;
                    }
                    SCHED_KEEP2.forEach(function (k) {
                      if (k === 'floatMinutes') return;
                      if ((curCal[k] == null || curCal[k] === '') && prevCal[k] != null && prevCal[k] !== '') curCal[k] = prevCal[k];
                    });
                    var prevFm2 = parseFloatMinutesValue(prevCal.floatMinutes, null);
                    var curFm2 = parseFloatMinutesValue(curCal.floatMinutes, null);
                    if (prevFm2 != null && (curFm2 == null || (curFm2 === 15 && prevFm2 !== 15))) {
                      curCal.floatMinutes = prevFm2;
                    } else if (curFm2 == null && prevFm2 != null) {
                      curCal.floatMinutes = prevFm2;
                    }
                  });
                  (function () {
                    var prevSF = parseFloatMinutesValue(prev.obj.settings && prev.obj.settings.floatMinutes, null);
                    var curSF = parseFloatMinutesValue(incoming.settings && incoming.settings.floatMinutes, null);
                    var finalFm = curSF;
                    if (curSF == null && prevSF != null) finalFm = prevSF;
                    else if (curSF === 15 && prevSF != null && prevSF !== 15) finalFm = prevSF;
                    else if (curSF != null) finalFm = curSF;
                    else finalFm = prevSF;
                    if (finalFm != null) {
                      incoming.settings.floatMinutes = finalFm;
                      Object.keys(incoming.settings.contractCalendars || {}).forEach(function (cid) {
                        if (String(cid) === 'hourly') return;
                        var cx = incoming.settings.contractCalendars[cid];
                        if (cx && typeof cx === 'object') cx.floatMinutes = finalFm;
                      });
                    }
                  })();
                }
              }
              if (prev.obj.settings.requestWindows != null && incoming.settings.requestWindows == null) incoming.settings.requestWindows = prev.obj.settings.requestWindows;
              if (prev.obj.settings.leavePolicy && prev.obj.settings.leavePolicy.byContractType) {
                if (!incoming.settings.leavePolicy) incoming.settings.leavePolicy = {};
                if (!incoming.settings.leavePolicy.byContractType) incoming.settings.leavePolicy.byContractType = {};
                Object.keys(prev.obj.settings.leavePolicy.byContractType).forEach(function (ctId) {
                  if (incoming.settings.leavePolicy.byContractType[ctId] == null) {
                    incoming.settings.leavePolicy.byContractType[ctId] = prev.obj.settings.leavePolicy.byContractType[ctId];
                  }
                });
              }
            }
            // Ø­Ø°Ù ØªÚ©Ø±Ø§Ø±ÛŒ + Ø¨Ø±Ø¯Ø§Ø´Øª Ø§Ø² Ú©Ø§Ø±Ú©Ù†Ø§Ù†
            try { mergeDedupeContractTypes(incoming); } catch (eDd) {}
            text = JSON.stringify(incoming);
          }
        } catch (eMergeCt) { /* non-fatal â€” keep original text */ }
      }

      if (rest === 'settings' && base > 0) {
        try {
          const incS = JSON.parse(text);
          const prevS = await storeGetSettingsDoc(cfg);
          if (incS && typeof incS === 'object' && prevS) {
            protectMonthlyVarsOnPut(prevS, incS);
            text = JSON.stringify(incS);
          }
        } catch (eMvp) { /* non-fatal â€” keep original text */ }
      }

      if (base === 0) {
        await fetch(cfg.url + '/rest/v1/app_docs?on_conflict=name', {
          method: 'POST',
          headers: storeHeaders(cfg, { 'Content-Type': 'application/json', Prefer: 'resolution=ignore-duplicates,return=minimal' }),
          body: JSON.stringify([{ name: rest, version: 0 }])
        });
      }
      const payload = '{"version":' + (base + 1) + ',"updated_by":' + JSON.stringify(who.name) +
        ',"updated_at":' + JSON.stringify(new Date().toISOString()) + ',"data":' + JSON.stringify(text) + '}';
      const r = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.' + rest + '&version=eq.' + base + '&select=version', {
        method: 'PATCH',
        headers: storeHeaders(cfg, { 'Content-Type': 'application/json', Prefer: 'return=representation' }),
        body: payload
      });
      if (!r.ok) return storeFailResponse(await storeFail(r));
      const rows = await r.json();
      if (Array.isArray(rows) && rows.length === 1) {
        console.log(JSON.stringify({ event: 'state_put', user: who.name, doc: rest, version: base + 1, bytes: text.length }));
        return jsonResponse({ ok: true, version: base + 1 });
      }
      const vs = await storeVersions(cfg);
      return jsonResponse({ ok: false, error: 'conflict', currentVersion: vs.versions ? vs.versions[rest] : null }, 409);
    }
    return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  } catch (e) {
    console.log(JSON.stringify({ event: 'state_error', user: who.name, message: String(e && e.message) }));
    return jsonResponse({ ok: false, error: 'store_unreachable', reason: 'unreachable' }, 502);
  }
}

// ---------- Employee portal APIs ----------

function normalizeDigits(s) {
  // Persian Û°-Û¹ and Arabic Ù -Ù© â†’ 0-9
  return String(s || '')
    .replace(/[Û°-Û¹]/g, function (d) { return String(d.charCodeAt(0) - 1776); })
    .replace(/[Ù -Ù©]/g, function (d) { return String(d.charCodeAt(0) - 1632); });
}

async function handleEmpLogin(request, env) {
  if (request.method !== 'POST') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin') return jsonResponse({ ok: false, error: 'forbidden' }, 403);

  let code = '', password = '';
  try {
    const body = await request.json();
    code = normalizeDigits(body.code || '').trim();
    password = normalizeDigits(body.password || '').trim();
  } catch (e) {
    return jsonResponse({ ok: false, error: 'bad_json' }, 400);
  }
  if (!code || !password) return jsonResponse({ ok: false, error: 'empty' }, 400);

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj || !Array.isArray(gd.obj.employees)) {
    await new Promise(r => setTimeout(r, 500));
    return jsonResponse({ ok: false, error: 'invalid', message: 'Ø¯Ø§Ø¯Ù‡ Ú©Ø§Ø±Ú©Ù†Ø§Ù† Ø±ÙˆÛŒ Ø³Ø±ÙˆØ± Ù†ÛŒØ³Øª. ÛŒÚ©â€ŒØ¨Ø§Ø± Ø§Ø² Ø³ÛŒØ³ØªÙ… Ø§ØµÙ„ÛŒ Â«Ù‡Ù…Ú¯Ø§Ù…â€ŒØ³Ø§Ø²ÛŒÂ» Ø¨Ø²Ù†ÛŒØ¯.' }, 401);
  }

  // match code as string (handles number/string storage)
  const emp = gd.obj.employees.find(function (e) {
    return normalizeDigits(e.code).trim() === code;
  });
  if (!emp) {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid', message: 'Ú©Ø¯ Ù¾Ø±Ø³Ù†Ù„ÛŒ Ø¯Ø± Ø³ÛŒØ³ØªÙ… ÛŒØ§ÙØª Ù†Ø´Ø¯.' }, 401);
  }
  if (emp.status === 'inactive') {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid', message: 'ÙˆØ¶Ø¹ÛŒØª Ø§ÛŒÙ† Ú©Ø§Ø±Ù…Ù†Ø¯ ØºÛŒØ±ÙØ¹Ø§Ù„ Ø§Ø³Øª.' }, 401);
  }
  if (emp.portalEnabled === false) {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid', message: 'Ø¯Ø³ØªØ±Ø³ÛŒ Ù¾Ø±ØªØ§Ù„ Ø¨Ø±Ø§ÛŒ Ø§ÛŒÙ† Ú©Ø§Ø±Ù…Ù†Ø¯ ØºÛŒØ±ÙØ¹Ø§Ù„ Ø§Ø³Øª.' }, 401);
  }

  const empCodeStr = normalizeDigits(emp.code).trim();
  // Always accept password === employee code (default / after reset)
  // OR matching stored hash
  let ok = false;
  let usedDefault = false;
  if (password === empCodeStr || password === code) {
    ok = true;
    usedDefault = true;
  } else if (emp.portalPassHash) {
    ok = await checkPassword(password, emp.portalPassHash);
  }
  if (!ok) {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid', message: 'Ø±Ù…Ø² Ø§Ø´ØªØ¨Ø§Ù‡ Ø§Ø³Øª. Ø¨Ø¹Ø¯ Ø§Ø² Ø±ÛŒØ³ØªØŒ Ø±Ù…Ø² = Ù‡Ù…Ø§Ù† Ú©Ø¯ Ù¾Ø±Ø³Ù†Ù„ÛŒ Ø§Ø³Øª.' }, 401);
  }

  // If logged in with code-as-password, clear any old custom hash so state stays consistent
  if (usedDefault) {
    try {
      emp.portalEnabled = true;
      emp.portalPassHash = null; // stay on default until they change password
      emp.portalPassChangedAt = new Date().toISOString();
      await storePutData(cfg, gd.version, gd.obj, 'emp-auto:' + empCodeStr);
    } catch (e) { /* non-fatal */ }
  }

  const exp = Math.floor(Date.now() / 1000) + SESSION_IDLE_SECONDS;
  const token = await makeEmpToken(env, empCodeStr, emp.fullName || '', exp);
  console.log(JSON.stringify({ event: 'emp_login', code: empCodeStr, defaultPass: usedDefault }));
  return new Response(JSON.stringify({
    ok: true,
    code: empCodeStr,
    fullName: emp.fullName || '',
    position: emp.position || '',
    mustChangePassword: usedDefault
  }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Set-Cookie': empCookie(token)
    }
  });
}

async function handleEmpLogout() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Set-Cookie': CLEAR_EMP_COOKIE
    }
  });
}

async function handleEmpWhoami(request, env) {
  if (request.method !== 'GET') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  // extend session
  const now = Math.floor(Date.now() / 1000);
  const renew = (sess.exp - now < SESSION_IDLE_SECONDS / 2)
    ? empCookie(await makeEmpToken(env, sess.code, sess.fullName, now + SESSION_IDLE_SECONDS)) : null;
  let userAccess = defaultUserAccess();
  try {
    const cfg = storeConfig(env);
    if (cfg) {
      const gd = await storeGetData(cfg);
      if (gd && gd.obj && gd.obj.settings) {
        userAccess = normalizeUserAccess(gd.obj.settings.userAccess);
      }
    }
  } catch (eUa) {}
  let personal = { nationalId: '', fatherName: '', mobile: '', address: '', birthDate: '', militaryStatus: '', militaryExemptType: '', jobGrade: '', educationLevel: '', educationField: '', city: '', management: '', deputy: '', group: '', managementDeputy: '', unit: '', workplace: '', position: '' };
  try {
    const cfg2 = storeConfig(env);
    if (cfg2) {
      const gd2 = await storeGetData(cfg2);
      if (gd2 && gd2.obj && Array.isArray(gd2.obj.employees)) {
        const emp = gd2.obj.employees.find(function (x) { return String(x.code) === String(sess.code); });
        const ex = gd2.obj.employeeExtras && gd2.obj.employeeExtras[String(sess.code)];
        const per = (ex && ex.personal) || {};
        if (emp) {
          personal.nationalId = emp.nationalId || emp.national_id || '';
          personal.fatherName = emp.fatherName || per.fatherName || '';
          personal.mobile = emp.mobile || emp.phone || per.mobile || '';
          personal.address = emp.address || per.address || '';
          personal.birthDate = emp.birthDate || per.birthDate || '';
          personal.militaryStatus = emp.militaryStatus || per.militaryStatus || '';
          personal.militaryExemptType = emp.militaryExemptType || per.militaryExemptType || '';
          personal.jobGrade = emp.jobGrade || per.jobGrade || '';
          personal.educationLevel = emp.educationLevel || per.educationLevel || '';
          personal.educationField = emp.educationField || per.educationField || '';
          personal.city = emp.city || per.city || '';
          personal.province = emp.province || emp.state || per.province || '';
          personal.gender = emp.gender || emp.sex || per.gender || '';
          personal.management = emp.management || '';
          personal.deputy = emp.deputy || '';
          personal.group = emp.group || '';
          personal.unit = emp.unit || '';
          personal.workplace = emp.workplace || '';
          personal.position = emp.position || '';
          personal.managementDeputy = emp.managementDeputy || emp.management || emp.deputy || '';
          if (!personal.managementDeputy && emp.management && emp.deputy)
            personal.managementDeputy = String(emp.management) + ' / ' + String(emp.deputy);
          else if (!personal.managementDeputy)
            personal.managementDeputy = emp.management || emp.deputy || '';
        }
      }
    }
  } catch (eP) {}
  let realJalaliYear = 1405, realJalaliMonth = 1, realJalaliDay = 1;
  let requestYear = 1405, requestMonth = 1, requestGraceDays = 0;
  let adminYear = 1405, adminMonth = 1;
  try {
    const cfgS = storeConfig(env);
    if (cfgS) {
      const gdS = await storeGetData(cfgS);
      const st = (gdS && gdS.obj && gdS.obj.settings) || {};
      adminYear = Number(st.currentYear) || 1405;
      adminMonth = Number(st.currentMonth) || Number(st.activeMonth) || 0;
      const pc = getPortalRequestMonth(st);
      realJalaliYear = pc.realYear; realJalaliMonth = pc.realMonth; realJalaliDay = pc.realDay;
      requestYear = pc.requestYear; requestMonth = pc.requestMonth; requestGraceDays = pc.graceDays;
    }
  } catch (eS) {}
  if (!adminMonth || adminMonth < 1) adminMonth = realJalaliMonth;
    let portalView = { showDecree: true, showProfile: true, decreeMode: 'self', profileMode: 'self' };
  try {
    const cfgPv2 = storeConfig(env);
    if (cfgPv2) {
      const gdPv2 = await storeGetData(cfgPv2);
      if (gdPv2 && gdPv2.obj) {
        const pvc2 = getPortalViewConfig(gdPv2.obj);
        portalView = {
          showDecree: !!pvc2.showDecree,
          showProfile: !!pvc2.showProfile,
          decreeMode: pvc2.decreeMode || 'self',
          profileMode: pvc2.profileMode || 'self'
        };
      }
    }
  } catch (ePv2) {}
const body = Object.assign({
    ok: true, code: sess.code, fullName: sess.fullName, userAccess: userAccess,
    realJalaliYear: realJalaliYear, realJalaliMonth: realJalaliMonth, realJalaliDay: realJalaliDay,
    requestYear: requestYear, requestMonth: requestMonth, requestGraceDays: requestGraceDays,
    currentYear: adminYear, currentMonth: adminMonth,
    portalView: portalView
    }, personal);
  if (renew) {
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Set-Cookie': renew }
    });
  }
  return jsonResponse(body);
}


async function handleEmpFeatures(request, env) {
  // public to logged-in employees; returns feature flags for portal UI
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  let userAccess = defaultUserAccess();
  try {
    const cfg = storeConfig(env);
    if (cfg) {
      const gd = await storeGetData(cfg);
      if (gd && !gd.fail && gd.obj && gd.obj.settings) {
        userAccess = normalizeUserAccess(gd.obj.settings.userAccess);
      }
    }
  } catch (e) {}
  let realJalaliYear = 1405, realJalaliMonth = 1, realJalaliDay = 1;
  let requestYear = 1405, requestMonth = 1, requestGraceDays = 0;
  let adminYear = 1405, adminMonth = 1;
  try {
    const cfg2 = storeConfig(env);
    if (cfg2) {
      const gd2 = await storeGetData(cfg2);
      const st = (gd2 && !gd2.fail && gd2.obj && gd2.obj.settings) ? gd2.obj.settings : {};
      adminYear = Number(st.currentYear) || 1405;
      adminMonth = Number(st.currentMonth) || Number(st.activeMonth) || 0;
      const pc = getPortalRequestMonth(st);
      realJalaliYear = pc.realYear; realJalaliMonth = pc.realMonth; realJalaliDay = pc.realDay;
      requestYear = pc.requestYear; requestMonth = pc.requestMonth; requestGraceDays = pc.graceDays;
    }
  } catch (e2) {}
  if (!adminMonth || adminMonth < 1) adminMonth = realJalaliMonth;
  return jsonResponse({
    ok: true, userAccess: userAccess,
    realJalaliYear: realJalaliYear, realJalaliMonth: realJalaliMonth, realJalaliDay: realJalaliDay,
    requestYear: requestYear, requestMonth: requestMonth, requestGraceDays: requestGraceDays,
    currentYear: adminYear, currentMonth: adminMonth
  });
}

async function handleMyPayslip(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);

  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  const month = Number(r.body.month);
  if (!isInt(year, 1300, 1600) || !isInt(month, 1, 12)) {
    return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  }

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);

  let payCode = String((r.body && r.body.code) || sess.code).trim() || String(sess.code);
  const allEmpsP = gd.obj.employees || [];
  if (payCode !== String(sess.code)) {
    const targetP = allEmpsP.find(function (e) { return String(e.code) === payCode; });
    if (!targetP || typeof isManagerOf !== 'function' || !isManagerOf(sess.code, targetP, gd.obj)) {
      return jsonResponse({ ok: false, error: 'forbidden', message: 'Ù…Ø´Ø§Ù‡Ø¯Ù‡ ÙÛŒØ´ Ø§ÛŒÙ† ÙØ±Ø¯ Ø¨Ø±Ø§ÛŒ Ø´Ù…Ø§ Ù…Ø¬Ø§Ø² Ù†ÛŒØ³Øª.' }, 403);
    }
  }
  const viewableP = allEmpsP.filter(function (e) {
    return String(e.code) === String(sess.code) || (typeof isManagerOf === 'function' && isManagerOf(sess.code, e, gd.obj));
  }).map(function (e) { return { code: String(e.code), fullName: e.fullName || '' }; });
  const key = year + '-' + month;
  const rows = (gd.obj.payrolls && gd.obj.payrolls[key]) || [];
  const rec = Array.isArray(rows)
    ? rows.find(function (x) { return String(x.code) === payCode; })
    : (rows && (rows[payCode] || rows[String(payCode)])) || null;
  if (!rec) {
    return jsonResponse({ ok: false, error: 'not_found', message: 'Ø¨Ø±Ø§ÛŒ Ø§ÛŒÙ† Ù…Ø§Ù‡ ÙÛŒØ´ÛŒ Ø«Ø¨Øª Ù†Ø´Ø¯Ù‡ Ø§Ø³Øª.', viewable: viewableP, code: payCode }, 404);
  }

  // company info (from settings if available)
  let company = {};
  try {
    const sr = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.settings&select=data',
      { headers: storeHeaders(cfg, { Accept: 'application/vnd.pgrst.object+json' }) });
    if (sr.ok) {
      const srow = await sr.json();
      if (srow && srow.data) {
        const sobj = JSON.parse(srow.data);
        company = sobj.company || {};
      }
    }
  } catch (e) {}

  // only return safe fields
  const safe = {
    code: rec.code,
    fullName: rec.fullName,
    position: rec.position || '',
    unit: rec.unit || '',
    workplace: rec.workplace || '',
    workDays: rec.workDays,
    leaveDays: rec.leaveDays || 0,
    basicAmount: rec.basicAmount,
    otAmount: rec.otAmount || 0,
    nightAmount: rec.nightAmount || 0,
    shiftAmount: rec.shiftAmount || 0,
    totalAllow: rec.totalAllow || 0,
    totalDeductions: rec.totalDeductions || 0,
    itemDetails: (rec.itemDetails || []).map(it => ({
      name: it.name,
      amount: it.amount,
      isDeduction: !!it.isDeduction,
      qty: it.qty
    })),
    gross: rec.gross,
    insurance: rec.insurance,
    tax: rec.tax,
    loanDeduction: rec.loanDeduction || 0,
    net: rec.net,
    bankName: rec.bankName || '',
    accountNumber: rec.accountNumber || '',
    contractType: rec.contractType || 'normal',
    hideOtNight: !!rec.hideOtNight
  };

  console.log(JSON.stringify({ event: 'emp_payslip', code: sess.code, year: year, month: month }));
  return jsonResponse({
    ok: true,
    year: year,
    month: month,
    code: payCode,
    viewable: typeof viewableP !== 'undefined' ? viewableP : [],
    company: {
      name: company.name || company.companyName || '',
      address: company.address || '',
      economicCode: company.economicCode || ''
    },
    payslip: safe
  });
}

async function handleEmpChangePassword(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);

  const r = await readBody(request);
  if (r.error) return r.error;
  const oldPass = String(r.body.oldPassword || '');
  const newPass = String(r.body.newPassword || '');
  if (!oldPass || !newPass || newPass.length < 6) {
    return jsonResponse({ ok: false, error: 'weak_password', message: 'Ø±Ù…Ø² Ø¬Ø¯ÛŒØ¯ Ø­Ø¯Ø§Ù‚Ù„ Û¶ Ú©Ø§Ø±Ø§Ú©ØªØ± Ø¨Ø§Ø´Ø¯.' }, 400);
  }

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  // retry a few times on version conflict
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);

    const emp = gd.obj.employees.find(e => String(e.code) === String(sess.code));
    if (!emp || emp.status === 'inactive' || emp.portalEnabled === false) {
      return jsonResponse({ ok: false, error: 'disabled' }, 403);
    }

    // accept either stored hash OR default (code as password)
    let oldOk = false;
    if (emp.portalPassHash) {
      oldOk = await checkPassword(oldPass, emp.portalPassHash);
    } else {
      oldOk = (oldPass === String(emp.code));
    }
    if (!oldOk) {
      await new Promise(r => setTimeout(r, 400));
      return jsonResponse({ ok: false, error: 'wrong_old', message: 'Ø±Ù…Ø² ÙØ¹Ù„ÛŒ Ø§Ø´ØªØ¨Ø§Ù‡ Ø§Ø³Øª.' }, 401);
    }

    emp.portalEnabled = true;
    emp.portalPassHash = await hashPassword(newPass);
    emp.portalPassChangedAt = new Date().toISOString();

    const put = await storePutData(cfg, gd.version, gd.obj, 'emp:' + sess.code);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue; // retry

    console.log(JSON.stringify({ event: 'emp_password_change', code: sess.code }));
    return jsonResponse({ ok: true, message: 'Ø±Ù…Ø² Ø¨Ø§ Ù…ÙˆÙÙ‚ÛŒØª ØªØºÛŒÛŒØ± Ú©Ø±Ø¯.' });
  }
  return jsonResponse({ ok: false, error: 'conflict', message: 'Ù„Ø·ÙØ§Ù‹ Ø¯ÙˆØ¨Ø§Ø±Ù‡ ØªÙ„Ø§Ø´ Ú©Ù†ÛŒØ¯.' }, 409);
}

// Admin helper: set / reset employee portal password (called from main app while admin is logged in)
async function handleAdminSetEmpPassword(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const code = String(r.body.code || '').trim();
  const newPass = String(r.body.password || '');
  const enabled = r.body.enabled !== false;
  if (!code) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  if (enabled && newPass && newPass.length < 6) {
    return jsonResponse({ ok: false, error: 'weak_password' }, 400);
  }

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);

    const emp = gd.obj.employees.find(e => String(e.code) === code);
    if (!emp) return jsonResponse({ ok: false, error: 'not_found' }, 404);

    emp.portalEnabled = !!enabled;
    if (!enabled) {
      // disabled â€” keep hash in case re-enabled later
    } else if (newPass === '' || newPass == null) {
      // empty password = reset to default (employee code as password)
      emp.portalPassHash = null;
      emp.portalPassChangedAt = new Date().toISOString();
    } else {
      emp.portalPassHash = await hashPassword(newPass);
      emp.portalPassChangedAt = new Date().toISOString();
    }

    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;

    console.log(JSON.stringify({ event: 'admin_set_emp_portal', by: who.name, code: code, enabled: enabled, resetDefault: !newPass }));
    return jsonResponse({
      ok: true,
      enabled: emp.portalEnabled,
      hasPassword: !!emp.portalPassHash,
      defaultPassword: !emp.portalPassHash
    });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

// ---------- Attendance requests (leave / mission) ----------
function newRequestId() {
  return 'r_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10) + '_' + Math.random().toString(36).slice(2, 6);
}

function faDigitsToEn(str) {
  return String(str || '').replace(/[Û°-Û¹]/g, function (c) { return String(c.charCodeAt(0) - 1776); })
    .replace(/[Ù -Ù©]/g, function (c) { return String(c.charCodeAt(0) - 1632); });
}
function parseJalaliYMD(str) {
  if (!str) return null;
  const m = faDigitsToEn(str).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
  if (!m) return null;
  return { y: Number(m[1]), m: Number(m[2]), d: Number(m[3]) };
}

function hoursBetween(fromT, toT) {
  const p = function (t) {
    const x = String(t || '').split(':');
    return (Number(x[0]) || 0) + (Number(x[1]) || 0) / 60;
  };
  const h = p(toT) - p(fromT);
  return h > 0 ? Math.round(h * 100) / 100 : 0;
}

function daysInJalaliMonth(y, m) {
  if (m >= 1 && m <= 6) return 31;
  if (m >= 7 && m <= 11) return 30;
  return 29;
}

// returns [{year, month, days}] covered by inclusive start..end
function splitDaysByMonth(startStr, endStr) {
  const a = parseJalaliYMD(startStr);
  const b = parseJalaliYMD(endStr) || a;
  if (!a) return [];
  const out = [];
  let y = a.y, m = a.m, d = a.d;
  const endY = b.y, endM = b.m, endD = b.d;
  // safety cap
  for (let guard = 0; guard < 400; guard++) {
    if (y > endY || (y === endY && m > endM)) break;
    const dim = daysInJalaliMonth(y, m);
    let from = (y === a.y && m === a.m) ? a.d : 1;
    let to = (y === endY && m === endM) ? endD : dim;
    from = Math.max(1, Math.min(dim, from));
    to = Math.max(1, Math.min(dim, to));
    if (to >= from) out.push({ year: y, month: m, days: to - from + 1 });
    m++;
    if (m > 12) { m = 1; y++; }
  }
  return out;
}

function ensureEmpMonthRow(data, year, month, code) {
  const key = year + '-' + month;
  if (!data.monthlyData) data.monthlyData = {};
  if (!data.monthlyData[key]) data.monthlyData[key] = {};
  if (!data.monthlyData[key][code]) {
    data.monthlyData[key][code] = {
      workDays: 0, leaveDays: 0, hourlyLeave: 0, otHours: 0, nightHours: 0,
      shiftType: 'none', shiftDays: 0, missionDays: 0, missionHours: 0, vars: {}, qty: {}
    };
  }
  const row0 = data.monthlyData[key][code];
  if (row0.missionDays == null) row0.missionDays = 0;
  if (row0.missionHours == null) row0.missionHours = 0;
  return data.monthlyData[key][code];
}


function reverseApprovedRequestFromTimesheet(data, req) {
  if (!req) return;
  const code = String(req.empCode);
  if (req.kind === 'leave' && req.mode === 'daily') {
    if (!(typeof shouldSkipLeaveDaysColumn === 'function' && shouldSkipLeaveDaysColumn(data, req))) {
      splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
        const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
        const days = leaveDaysForMonthChunk(data, req, chunk);
        row.leaveDays = Math.round(Math.max(0, (Number(row.leaveDays) || 0) - days) * 100) / 100;
      });
    } else {
      // Ø§Ø²Ø¯ÙˆØ§Ø¬/ØªÙˆÙ„Ø¯/â€¦ Ø±Ø§ Ø§Ø² qty Ø¨Ø§Ø²Ø³Ø§Ø²ÛŒ Ú©Ù† (Ù†Ù‡ Ú©Ù…â€ŒÚ©Ø±Ø¯Ù† Ø¯Ø³ØªÛŒ Ú©Ù‡ Ø¯ÙˆØ¨Ù„ Ù…ÛŒâ€ŒØ´ÙˆØ¯)
      splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
        const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
        try { rebuildLeaveTypeQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eLtR) {}
        try { rebuildRestQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eRR) {}
      });
    }
  } else if (req.kind === 'leave' && req.mode === 'hourly') {
    const p = parseJalaliYMD(req.startDate);
    if (!p) return;
    const hrs = hoursBetween(req.fromTime, req.toTime);
    const row = ensureEmpMonthRow(data, p.y, p.m, code);
    row.hourlyLeave = Math.round(Math.max(0, (Number(row.hourlyLeave) || 0) - hrs) * 100) / 100;
  } else if (req.kind === 'mission' && req.mode === 'daily') {
    splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
      const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
      try { rebuildMissionAndQtyFromRequests(data, chunk.year, chunk.month, code, row); try { rebuildRestQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eRestRb) {} } catch (eRb) {
        if (!row.qty) row.qty = {};
        Object.keys(row.qty).forEach(function (nm) { if (/Ø¬Ø§Ø¨/.test(String(nm))) row.qty[nm] = 0; });
        row.missionDays = 0;
      }
    });
  } else if (req.kind === 'mission' && req.mode === 'hourly') {
    const p = parseJalaliYMD(req.startDate);
    if (!p) return;
    const hrs = hoursBetween(req.fromTime, req.toTime);
    const row = ensureEmpMonthRow(data, p.y, p.m, code);
    row.missionHours = Math.round(Math.max(0, (Number(row.missionHours) || 0) - hrs) * 100) / 100;
  }
}

function leaveDaysForMonthChunk(data, req, chunk) {
  /* Ú©Ø³Ø± Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ ÙÙ‚Ø· Ø±ÙˆØ²Ù‡Ø§ÛŒ Ú©Ø§Ø±ÛŒ â€” Ù¾Ù†Ø¬Ø´Ù†Ø¨Ù‡/Ø¬Ù…Ø¹Ù‡ Ùˆ ØªØ¹Ø·ÛŒÙ„ Ø±Ø³Ù…ÛŒ Ø´Ù…Ø±Ø¯Ù‡ Ù†Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯
     Ù…Ú¯Ø± countNonWorkDaysAsLeave ÛŒØ§ Ù†ÙˆØ¹ Ù…Ø¬Ø§Ø² Ø±ÙˆÛŒ ØºÛŒØ±Ú©Ø§Ø±ÛŒ */
  try {
    const emp = ((data.employees || []).find(function (e) { return String(e.code) === String(req.empCode); })) || null;
    const ct = (emp && emp.contractType) || 'normal';
    const ws = typeof getWorkWeekSettings === 'function' ? getWorkWeekSettings(data, ct) : { countNonWorkDaysAsLeave: false };
    const allowNw = !!(ws.countNonWorkDaysAsLeave || req.allowNonWorkLeave ||
      (typeof isLeaveTypeAllowedOnNonWork === 'function' && isLeaveTypeAllowedOnNonWork(data, ct, req.typeId, req.typeName)));
    if (allowNw) return Number(chunk.days) || 0;
    if (typeof countWorkingDaysInMonth === 'function') {
      return countWorkingDaysInMonth(req.startDate, req.endDate || req.startDate, chunk.year, chunk.month, data, ct);
    }
  } catch (e) {}
  return Number(chunk.days) || 0;
}

function applyApprovedRequestToTimesheet(data, req) {
  if (!req || req.status !== 'approved') return;
  const code = String(req.empCode);
  if (req.kind === 'leave' && req.mode === 'daily') {
    if (typeof shouldSkipLeaveDaysColumn === 'function' && shouldSkipLeaveDaysColumn(data, req)) {
      let tname = req.typeName || req.type || '';
      if (!tname && req.typeId) {
        try {
          const types = (data.attendanceTypes || []).concat(((data.settings || {}).attendanceTypes) || []);
          const td = types.find(function (t) { return t && String(t.id) === String(req.typeId); });
          if (td) tname = td.name || '';
        } catch (eT) {}
      }
      function _isRestNameOnly(s) {
        s = String(s || '').replace(/\u200c/g, ' ').replace(/\s+/g, ' ').trim();
        if (!s) return false;
        if (/Ù…Ø±Ø®Øµ|Ø§Ø³ØªØ­Ù‚Ø§Ù‚|Ø§Ø³ØªØ¹Ù„Ø§Ø¬|Ø¨Ø¯ÙˆÙ†\s*Ø­Ù‚ÙˆÙ‚|ØºÛŒØ¨Øª|ØºØ§ÛŒØ¨|Ù…Ø£Ù…ÙˆØ±|Ù…Ø§Ù…ÙˆØ±|mission|leave/i.test(s)) return false;
        return (s.indexOf('Ø±Ø³Øª') >= 0) || /\brest\b/i.test(s);
      }
      if (_isRestNameOnly(tname) || _isRestNameOnly(req.typeId) || _isRestNameOnly(req.kind)) {
        const qtyName = matchQtyItemName(data, code, tname) || 'Ø±Ø³Øª Ú©Ø§Ø±ÛŒ';
        splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
          const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
          const days = leaveDaysForMonthChunk(data, req, chunk);
          addQtyDaysToMonthRow(row, qtyName, days);
          try { rebuildRestQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eRR) {}
        });
      } else if (tname) {
        // Ø´Ù…Ø§Ø±Ø´ Ù…Ø·Ù„Ù‚ Ø§Ø² Ù‡Ù…Ù‡ Ø¯Ø±Ø®ÙˆØ§Ø³Øªâ€ŒÙ‡Ø§ â€” Ø¬Ù„ÙˆÚ¯ÛŒØ±ÛŒ Ø§Ø² Ø¯Ùˆ Ø¨Ø±Ø§Ø¨Ø± Ø´Ø¯Ù†
        splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
          const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
          try { rebuildLeaveTypeQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eLt) {
            const days = leaveDaysForMonthChunk(data, req, chunk);
            const qtyName = matchQtyItemName(data, code, tname) || tname;
            if (!row.qty) row.qty = {};
            row.qty[qtyName] = days;
            if (/Ø§Ø²Ø¯ÙˆØ§Ø¬/.test(tname)) {
              row.qty['Ù…Ø±Ø®ØµÛŒ Ø§Ø²Ø¯ÙˆØ§Ø¬'] = days;
              row.qty['ØªØ¹Ø¯Ø§Ø¯ Ù…Ø±Ø®ØµÛŒ Ø§Ø²Ø¯ÙˆØ§Ø¬'] = days;
            }
          }
        });
      }
    } else {
      splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
        const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
        const days = leaveDaysForMonthChunk(data, req, chunk);
        row.leaveDays = Math.round(((Number(row.leaveDays) || 0) + days) * 100) / 100;
      });
    }
    // Ú©Ø§Ø±Ú©Ø±Ø¯ Ø±Ø§ Ù…Ø«Ù„ Ù¾Ø±ØªØ§Ù„ Ø§Ø² Ù†Ùˆ Ø­Ø³Ø§Ø¨ Ú©Ù†
    try {
      const p0 = parseJalaliYMD(req.startDate);
      if (p0 && typeof recountEmpMonthWorkDays === 'function') {
        const months = splitDaysByMonth(req.startDate, req.endDate || req.startDate);
        months.forEach(function (ch) {
          const r = ensureEmpMonthRow(data, ch.year, ch.month, code);
          try {
            var _pw = Number(r.workDays) || 0;
            var _rw = Math.round(recountEmpMonthWorkDays(data, ch.year, ch.month, code)) || 0;
            if (!(_pw > 0)) r.workDays = _rw;
          } catch (eRw) { r.workDays = Math.round(recountEmpMonthWorkDays(data, ch.year, ch.month, code)) || 0; }
          try { r.absenceDays = (typeof countEmpMonthAbsenceDays === 'function') ? countEmpMonthAbsenceDays(data, ch.year, ch.month, code) : 0; } catch (eAbsR) { r.absenceDays = 0; }
        });
      }
    } catch (eRc) {}
  } else if (req.kind === 'leave' && req.mode === 'hourly') {
    const p = parseJalaliYMD(req.startDate);
    if (!p) return;
    const hrs = hoursBetween(req.fromTime, req.toTime);
    const row = ensureEmpMonthRow(data, p.y, p.m, code);
    row.hourlyLeave = Math.round(((Number(row.hourlyLeave) || 0) + hrs) * 100) / 100;
  } else if (req.kind === 'mission' && req.mode === 'daily') {
    splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
      const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
      try { rebuildMissionAndQtyFromRequests(data, chunk.year, chunk.month, code, row); try { rebuildRestQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eRestRb) {} } catch (eRb) {}
    });
  } else if (req.kind === 'mission' && req.mode === 'hourly') {
    const p = parseJalaliYMD(req.startDate);
    if (!p) return;
    const hrs = hoursBetween(req.fromTime, req.toTime);
    const row = ensureEmpMonthRow(data, p.y, p.m, code);
    row.missionHours = Math.round(((Number(row.missionHours) || 0) + hrs) * 100) / 100;
  }
}

async function handleEmpCreateRequest(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const r = await readBody(request);
  if (r.error) return r.error;
  const b = r.body;
  let kind = b.kind === 'mission' ? 'mission' : 'leave';
  let mode = b.mode === 'hourly' ? 'hourly' : 'daily';
  let typeId = String(b.typeId || '').trim();
  let typeName = '';
  let deductFromEntitlement = false;
  let fixedDays = null;
  const startDate = String(b.startDate || '').trim();
  let endDate = String(b.endDate || b.startDate || '').trim();
  const fromTime = String(b.fromTime || '').trim();
  const toTime = String(b.toTime || '').trim();
  const place = String(b.place || '').trim();
  const reason = String(b.reason || '').trim();
  if (!startDate) return jsonResponse({ ok: false, error: 'bad_request', message: 'ØªØ§Ø±ÛŒØ® Ø´Ø±ÙˆØ¹ Ø§Ù„Ø²Ø§Ù…ÛŒ Ø§Ø³Øª.' }, 400);

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);

    // only current month (from settings) is allowed
    const settings = gd.obj.settings || {};
    const portalCal = getPortalRequestMonth(settings);
    const pStart = parseJalaliYMD(startDate);
    if (!pStart) return jsonResponse({ ok: false, error: 'bad_request', message: 'ÙØ±Ù…Øª ØªØ§Ø±ÛŒØ® Ù†Ø§Ù…Ø¹ØªØ¨Ø± Ø§Ø³Øª.' }, 400);
    let okMonth = (pStart.y === portalCal.realYear && pStart.m === portalCal.realMonth);
    if (!okMonth && portalCal.graceDays > 0 && portalCal.realDay <= portalCal.graceDays) {
      let py = portalCal.realYear, pm = portalCal.realMonth - 1;
      if (pm < 1) { pm = 12; py -= 1; }
      okMonth = (pStart.y === py && pStart.m === pm);
    }
    // Ù…Ù‡Ù„Øª Ø«Ø¨Øª Ø¨Ø± Ø§Ø³Ø§Ø³ Ø¨Ø§Ø²Ù‡â€ŒÙ‡Ø§ÛŒ ØªØ¹Ø±ÛŒÙâ€ŒØ´Ø¯Ù‡ ØªÙˆØ³Ø· Ø§Ø¯Ù…ÛŒÙ† (settings.requestWindows)
    const reqWins = normalizeRequestWindows(settings.requestWindows, false);
    if (reqWins.length) {
      const nowJ = jalaliNowTehran();
      const wcS = checkRequestWindow(reqWins, pStart, nowJ);
      if (wcS.handled && !wcS.ok) return jsonResponse({ ok: false, error: 'window_closed', message: wcS.message }, 400);
      if (wcS.handled && wcS.ok) okMonth = true;
      const pEnd0 = parseJalaliYMD(endDate);
      if (pEnd0) {
        const wcE = checkRequestWindow(reqWins, pEnd0, nowJ);
        if (wcE.handled && !wcE.ok) return jsonResponse({ ok: false, error: 'window_closed', message: wcE.message }, 400);
      }
    }
    if (!okMonth) {
      let msg = 'ÙÙ‚Ø· Ø¯Ø±Ø®ÙˆØ§Ø³Øª Ø¯Ø± Ù…Ø§Ù‡ Ø´Ù…Ø³ÛŒ Ø¬Ø§Ø±ÛŒ (' + portalCal.realYear + '/' + portalCal.realMonth + ') Ù…Ø¬Ø§Ø² Ø§Ø³Øª.';
      if (portalCal.graceDays > 0) msg += ' ØªØ§ ' + portalCal.graceDays + ' Ø±ÙˆØ² Ø§ÙˆÙ„ Ù…Ø§Ù‡ØŒ Ù…Ø§Ù‡ Ù‚Ø¨Ù„ Ù‡Ù… Ù…Ø¬Ø§Ø² Ø§Ø³Øª.';
      return jsonResponse({ ok: false, error: 'wrong_month', message: msg }, 400);
    }
    const cy = portalCal.realYear;
    const cm = portalCal.realMonth;
    // Ù…Ø§Ù‡ Ù‡Ø¯Ù = Ù…Ø§Ù‡ÛŒ Ú©Ù‡ ØªØ§Ø±ÛŒØ® Ø´Ø±ÙˆØ¹ Ø¯Ø± Ø¢Ù† Ù…Ø¬Ø§Ø² Ø´Ù†Ø§Ø®ØªÙ‡ Ø´Ø¯ (Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒØŒ ÛŒØ§ Ù…Ø§Ù‡ Ù‚Ø¨Ù„ Ø¯Ø± Ø±ÙˆØ²Ù‡Ø§ÛŒ Ù…Ù‡Ù„Øª)
    const targetY = pStart.y;
    const targetM = pStart.m;

    // resolve type from admin-defined list
    let types = gd.obj.attendanceTypes || [];
    if (!types.length) types = defaultAttendanceTypes();
    let tdef = typeId ? types.find(function (t) { return String(t.id) === typeId; }) : null;
    let frequency = 'throughout_year';
    let requiresAdminGrant = false;
    let grantId = '';
    if (tdef) {
      kind = tdef.kind === 'mission' ? 'mission' : 'leave';
      mode = tdef.mode === 'hourly' ? 'hourly' : 'daily';
      typeName = tdef.name || '';
      deductFromEntitlement = kind === 'leave' && !!tdef.deductFromEntitlement;
      fixedDays = tdef.fixedDays != null && tdef.fixedDays !== '' ? Number(tdef.fixedDays) : null;
      frequency = normalizeFreq(tdef.frequency);
      requiresAdminGrant = !!tdef.requiresAdminGrant;
      if (fixedDays && mode === 'daily' && startDate) {
        // ÙÙ‚Ø· Ø§Ú¯Ø± Ù¾Ø§ÛŒØ§Ù† Ø§ØµÙ„Ø§Ù‹ Ù†ÛŒØ§Ù…Ø¯Ù‡ â€” Ø«Ø¨Øª ÛŒÚ©â€ŒØ±ÙˆØ²Ù‡ (Ø§Ø²=ØªØ§) Ø±Ø§ Û³Ø±ÙˆØ²Ù‡ Ù†Ú©Ù†
        var endWasSentEmp = (typeof endDate === 'string' && endDate && endDate !== startDate);
        // Ø§Ú¯Ø± endDate Ø§Ø² body Ø¢Ù…Ø¯Ù‡ Ùˆ Ù¾Ø± Ø§Ø³ØªØŒ Ø­ØªÛŒ Ø§Ú¯Ø± = start Ø¨Ø§Ø´Ø¯ØŒ Ú¯Ø³ØªØ±Ø´ Ù†Ø¯Ù‡
        // Ø¯Ø± Ù¾Ø±ØªØ§Ù„ Ú©Ø§Ø±Ù…Ù†Ø¯: endDate Ù…Ø¹Ù…ÙˆÙ„Ø§Ù‹ Ø¨Ø¹Ø¯ Ø§Ø² Ù†Ø±Ù…Ø§Ù„â€ŒØ³Ø§Ø²ÛŒ = start Ù…ÛŒâ€ŒØ´ÙˆØ¯Ø› ÙÙ‚Ø· ÙˆÙ‚ØªÛŒ ÙˆØ§Ù‚Ø¹Ø§Ù‹ Ø®Ø§Ù„ÛŒ Ø¨ÙˆØ¯ Ú¯Ø³ØªØ±Ø´ Ø¨Ø¯Ù‡
        if (!endDate) {
          const p = parseJalaliYMD(startDate);
          if (p && fixedDays > 1) {
            let d = p.d + fixedDays - 1;
            let m = p.m, y = p.y;
            while (d > daysInJalaliMonth(y, m)) {
              d -= daysInJalaliMonth(y, m);
              m++;
              if (m > 12) { m = 1; y++; }
            }
            endDate = y + '/' + String(m).padStart(2, '0') + '/' + String(d).padStart(2, '0');
          }
        }
      }
    }

    const emp = gd.obj.employees.find(e => String(e.code) === String(sess.code));
    if (!emp || emp.status === 'inactive') return jsonResponse({ ok: false, error: 'disabled' }, 403);

    if (mode === 'hourly' && (!fromTime || !toTime)) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'Ø³Ø§Ø¹Øª Ø´Ø±ÙˆØ¹ Ùˆ Ù¾Ø§ÛŒØ§Ù† Ø§Ù„Ø²Ø§Ù…ÛŒ Ø§Ø³Øª.' }, 400);
    }
    if (mode === 'hourly') {
      try {
        const sh = assertHourlyWithinShift(gd.obj, emp, fromTime, toTime);
        if (!sh.ok) return jsonResponse({ ok: false, error: 'outside_shift', message: sh.message }, 400);
      } catch (e) {
        return jsonResponse({ ok: false, error: 'shift_check', message: 'Ø¨Ø±Ø±Ø³ÛŒ Ø³Ø§Ø¹Øª Ù…ÙˆØ¸ÙÛŒ Ù†Ø§Ù…ÙˆÙÙ‚: ' + (e && e.message ? e.message : e) }, 400);
      }
    }
    if (kind === 'mission' && !place) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'Ù…Ø­Ù„ Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø§Ù„Ø²Ø§Ù…ÛŒ Ø§Ø³Øª.' }, 400);
    }
    // reason/description required only for mission
    if (kind === 'mission' && !reason) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'ØªÙˆØ¶ÛŒØ­ / Ø¯Ù„ÛŒÙ„ Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø§Ù„Ø²Ø§Ù…ÛŒ Ø§Ø³Øª.' }, 400);
    }
    const pmeta = (gd.obj.portalMeta && gd.obj.portalMeta[String(emp.code)]) || {};
    const mgrCode1 = pmeta.managerCode || emp.managerCode || '';
    const mgrCode2 = pmeta.managerCode2 || emp.managerCode2 || '';
    if (!mgrCode1) {
      return jsonResponse({ ok: false, error: 'no_manager', message: 'Ø¨Ø±Ø§ÛŒ Ø´Ù…Ø§ Ù…Ø¯ÛŒØ± Ù…Ø³ØªÙ‚ÛŒÙ… ØªØ¹Ø±ÛŒÙ Ù†Ø´Ø¯Ù‡ Ø§Ø³Øª. Ø¨Ø§ Ù…Ù†Ø§Ø¨Ø¹ Ø§Ù†Ø³Ø§Ù†ÛŒ ØªÙ…Ø§Ø³ Ø¨Ú¯ÛŒØ±ÛŒØ¯.' }, 400);
    }
    const mgr = gd.obj.employees.find(e => String(e.code) === String(mgrCode1));
    const mgr2 = mgrCode2
      ? gd.obj.employees.find(e => String(e.code) === String(mgrCode2))
      : null;
    if (!Array.isArray(gd.obj.attendanceRequests)) gd.obj.attendanceRequests = [];
    if (!Array.isArray(gd.obj.attendanceGrants)) gd.obj.attendanceGrants = [];

    // frequency limits
    if (typeId && frequency === 'once_employment') {
      const used = countTypeUsage(gd.obj.attendanceRequests, emp.code, typeId, null);
      if (used > 0) {
        return jsonResponse({ ok: false, error: 'frequency_limit', message: 'Ø§ÛŒÙ† Ù†ÙˆØ¹ Ù…Ø±Ø®ØµÛŒ ÙÙ‚Ø· ÛŒÚ©â€ŒØ¨Ø§Ø± Ø¯Ø± Ø·ÙˆÙ„ Ø§Ø³ØªØ®Ø¯Ø§Ù… Ù‚Ø§Ø¨Ù„ Ø§Ø³ØªÙØ§Ø¯Ù‡ Ø§Ø³Øª Ùˆ Ù‚Ø¨Ù„Ø§Ù‹ Ø§Ø³ØªÙØ§Ø¯Ù‡ Ø´Ø¯Ù‡.' }, 400);
      }
    }
    if (typeId && frequency === 'once_year') {
      const py = parseJalaliYMD(startDate);
      const used = countTypeUsage(gd.obj.attendanceRequests, emp.code, typeId, py ? py.y : null);
      if (used > 0) {
        return jsonResponse({ ok: false, error: 'frequency_limit', message: 'Ø§ÛŒÙ† Ù†ÙˆØ¹ Ù…Ø±Ø®ØµÛŒ ÙÙ‚Ø· ÛŒÚ©â€ŒØ¨Ø§Ø± Ø¯Ø± Ø·ÙˆÙ„ Ø³Ø§Ù„ Ù‚Ø§Ø¨Ù„ Ø§Ø³ØªÙØ§Ø¯Ù‡ Ø§Ø³Øª Ùˆ Ø¯Ø± Ø§ÛŒÙ† Ø³Ø§Ù„ Ù‚Ø¨Ù„Ø§Ù‹ Ø«Ø¨Øª Ø´Ø¯Ù‡.' }, 400);
      }
    }

    // admin grant required â€” grant may have dateFrom..dateTo (or legacy date)
    if (requiresAdminGrant) {
      const g = gd.obj.attendanceGrants.find(function (x) {
        if (String(x.empCode) !== String(emp.code)) return false;
        if (String(x.typeId) !== String(typeId)) return false;
        if (x.revoked || x.revokedAt) return false;
        if (x.usedRequestId || x.consumed) return false;
        const from = x.dateFrom || x.date || '';
        const to = x.dateTo || x.dateFrom || x.date || '';
        if (!from && !to) return true; // unrestricted dates
        const days = listDayKeys(startDate, mode === 'hourly' ? startDate : (endDate || startDate));
        if (!days.length) return false;
        if (from && to) {
          const allowed = {};
          listDayKeys(from, to).forEach(function (k) { allowed[k] = true; });
          return days.every(function (k) { return allowed[k]; });
        }
        if (from) return days.every(function (k) { return k === dateKey(from); });
        return true;
      });
      if (!g) {
        return jsonResponse({ ok: false, error: 'no_grant', message: 'Ø§ÛŒÙ† Ù†ÙˆØ¹ Ù…Ø±Ø®ØµÛŒ ÙÙ‚Ø· Ø¨Ø§ Ù…Ø¬ÙˆØ² Ø§Ø¯Ù…ÛŒÙ† Ø¨Ø±Ø§ÛŒ Ø¨Ø§Ø²Ù‡ ØªØ§Ø±ÛŒØ® Ù…Ø´Ø®Øµ Ù‚Ø§Ø¨Ù„ Ø¯Ø±Ø®ÙˆØ§Ø³Øª Ø§Ø³Øª. Ø¨Ø§ Ù…Ù†Ø§Ø¨Ø¹ Ø§Ù†Ø³Ø§Ù†ÛŒ Ù‡Ù…Ø§Ù‡Ù†Ú¯ Ú©Ù†ÛŒØ¯.' }, 400);
      }
      grantId = g.id;
    }

    // fixed-day types: endDate already forced above â€” do not reject; user only picks start date
    if (fixedDays && mode === 'daily' && startDate && !endDate) {
      endDate = startDate;
    }
    // force entire request inside same month (current month)
    {
      const pe = parseJalaliYMD(mode === 'hourly' ? startDate : (endDate || startDate));
      if (pe && (pe.y !== targetY || pe.m !== targetM)) {
        return jsonResponse({ ok: false, error: 'wrong_month', message: 'Ø¨Ø§Ø²Ù‡ Ø¯Ø±Ø®ÙˆØ§Ø³Øª Ø¨Ø§ÛŒØ¯ Ø¯Ø§Ø®Ù„ Ù‡Ù…Ø§Ù† Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒ (' + targetY + '/' + targetM + ') Ø¨Ø§Ø´Ø¯.' }, 400);
      }
      if (pStart.y !== targetY || pStart.m !== targetM) {
        return jsonResponse({ ok: false, error: 'wrong_month', message: 'ÙÙ‚Ø· Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒ (' + targetY + '/' + targetM + ') Ù‚Ø§Ø¨Ù„ Ø¯Ø±Ø®ÙˆØ§Ø³Øª Ø§Ø³Øª.' }, 400);
      }
    }

    // overlap with existing pending/approved (and approved_l1)
    const candidate = {
      mode: mode,
      startDate: startDate,
      endDate: mode === 'hourly' ? startDate : endDate,
      fromTime: mode === 'hourly' ? fromTime : '',
      toTime: mode === 'hourly' ? toTime : ''
    };
    const conflict = gd.obj.attendanceRequests.find(function (x) {
      if (String(x.empCode) !== String(emp.code)) return false;
      if (x.status === 'rejected') return false;
      return requestsOverlap(candidate, x);
    });
    if (conflict) {
      const cname = conflict.typeName || (conflict.kind === 'mission' ? 'Ù…Ø£Ù…ÙˆØ±ÛŒØª' : 'Ù…Ø±Ø®ØµÛŒ');
      const when = conflict.mode === 'hourly'
        ? (conflict.startDate + ' ' + (conflict.fromTime || '') + '-' + (conflict.toTime || ''))
        : (conflict.startDate + (conflict.endDate && conflict.endDate !== conflict.startDate ? ' ØªØ§ ' + conflict.endDate : ''));
      return jsonResponse({
        ok: false,
        error: 'overlap',
        message: 'ØªØ¯Ø§Ø®Ù„ Ø¨Ø§ Ø¯Ø±Ø®ÙˆØ§Ø³Øª Ù‚Ø¨Ù„ÛŒ: Â«' + cname + 'Â» Ø¯Ø± ' + when + '. Ø¯Ø± ÛŒÚ© Ø±ÙˆØ²/Ø³Ø§Ø¹Øª Ù†Ù…ÛŒâ€ŒØªÙˆØ§Ù† Ú†Ù†Ø¯ Ù…Ø±Ø®ØµÛŒ ÛŒØ§ Ù…Ø£Ù…ÙˆØ±ÛŒØª Ù‡Ù…â€ŒØ²Ù…Ø§Ù† Ø¯Ø§Ø´Øª.'
      }, 400);
    }


    // Ù‚ÙˆØ§Ù†ÛŒÙ† Ù…Ø±Ø®ØµÛŒ Ø±ÙˆØ²Ø§Ù†Ù‡ Ùˆ ØªØ¹Ø·ÛŒÙ„ (ØªÙ‚ÙˆÛŒÙ… Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ú©Ø§Ø±Ù…Ù†Ø¯):
    // - Ú©Ù„ Ø¨Ø§Ø²Ù‡ ØªØ¹Ø·ÛŒÙ„ â†’ Ø±Ø¯
    // - Ø±ÙˆØ² Ø´Ø±ÙˆØ¹ ØªØ¹Ø·ÛŒÙ„ â†’ Ø±Ø¯
    // - Ø±ÙˆØ² Ù¾Ø§ÛŒØ§Ù† ØªØ¹Ø·ÛŒÙ„ â†’ Ø±Ø¯
    // - Ø´Ø±ÙˆØ¹ Ùˆ Ù¾Ø§ÛŒØ§Ù† Ø¹Ø§Ø¯ÛŒØŒ ØªØ¹Ø·ÛŒÙ„ Ù…ÛŒØ§Ù†ÛŒ â†’ Ù‚Ø¨ÙˆÙ„Ø› ÙÙ‚Ø· Ø±ÙˆØ²Ù‡Ø§ÛŒ Ú©Ø§Ø±ÛŒ Ø´Ù…Ø±Ø¯Ù‡ Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯
    if (kind === 'leave' && mode === 'daily' && startDate && !fixedDays) {
      const empCt = emp.contractType || 'normal';
      const ws = getWorkWeekSettings(gd.obj, empCt);
      const typeAllowedNw = isLeaveTypeAllowedOnNonWork(gd.obj, empCt, typeId, typeName);
      if (!ws.countNonWorkDaysAsLeave && !typeAllowedNw) {
        const endD = endDate || startDate;
        const sp = parseJalaliYMD(startDate);
        const ep = parseJalaliYMD(endD);
        if (sp && isHolidayOrNonWork(gd.obj, sp.y, sp.m, sp.d, empCt)) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'Ø±ÙˆØ² Ø´Ø±ÙˆØ¹ (' + startDate + ') ØªØ¹Ø·ÛŒÙ„/ØºÛŒØ±Ú©Ø§Ø±ÛŒ Ø§Ø³Øª Ùˆ Ø¨Ù‡â€ŒØ¹Ù†ÙˆØ§Ù† Ù…Ø±Ø®ØµÛŒ Ù…Ø­Ø³ÙˆØ¨ Ù†Ù…ÛŒâ€ŒØ´ÙˆØ¯. ØªØ§Ø±ÛŒØ® Ø´Ø±ÙˆØ¹ Ø±Ø§ Ø±ÙˆÛŒ ÛŒÚ© Ø±ÙˆØ² Ú©Ø§Ø±ÛŒ Ø¨Ú¯Ø°Ø§Ø±ÛŒØ¯ (ÛŒØ§ Ø§ÛŒÙ† Ù†ÙˆØ¹ Ù…Ø±Ø®ØµÛŒ Ø±Ø§ Ø¯Ø± ØªÙ†Ø¸ÛŒÙ…Ø§Øª ØªØ§ÛŒÙ…â€ŒØ´ÛŒØª Ø¨Ø±Ø§ÛŒ ØºÛŒØ±Ú©Ø§Ø±ÛŒ Ù…Ø¬Ø§Ø² Ú©Ù†ÛŒØ¯).'
          }, 400);
        }
        if (ep && isHolidayOrNonWork(gd.obj, ep.y, ep.m, ep.d, empCt)) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'Ø±ÙˆØ² Ù¾Ø§ÛŒØ§Ù† (' + endD + ') ØªØ¹Ø·ÛŒÙ„/ØºÛŒØ±Ú©Ø§Ø±ÛŒ Ø§Ø³Øª Ùˆ Ø¨Ù‡â€ŒØ¹Ù†ÙˆØ§Ù† Ù…Ø±Ø®ØµÛŒ Ù…Ø­Ø³ÙˆØ¨ Ù†Ù…ÛŒâ€ŒØ´ÙˆØ¯. ØªØ§Ø±ÛŒØ® Ù¾Ø§ÛŒØ§Ù† Ø±Ø§ Ø±ÙˆÛŒ ÛŒÚ© Ø±ÙˆØ² Ú©Ø§Ø±ÛŒ Ø¨Ú¯Ø°Ø§Ø±ÛŒØ¯.'
          }, 400);
        }
        const daysNeeded0 = countLeaveDays({ mode: 'daily', startDate: startDate, endDate: endD, typeId: typeId, typeName: typeName }, gd.obj, empCt);
        if (daysNeeded0 <= 0) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'Ø¯Ø± Ø¨Ø§Ø²Ù‡ Ø§Ù†ØªØ®Ø§Ø¨â€ŒØ´Ø¯Ù‡ Ù‡ÛŒÚ† Ø±ÙˆØ² Ú©Ø§Ø±ÛŒ ÙˆØ¬ÙˆØ¯ Ù†Ø¯Ø§Ø±Ø¯Ø› Ù…Ø±Ø®ØµÛŒ ÙÙ‚Ø· Ø±ÙˆÛŒ Ø±ÙˆØ²Ù‡Ø§ÛŒ Ú©Ø§Ø±ÛŒ Ø«Ø¨Øª Ù…ÛŒâ€ŒØ´ÙˆØ¯.'
          }, 400);
        }
      }
    }

    // Ø¨Ø±Ø±Ø³ÛŒ Ù…Ø§Ù†Ø¯Ù‡ Ù…Ø±Ø®ØµÛŒ Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ (Ø³Ø§Ù„ Ø¬Ø§Ø±ÛŒ / Ø°Ø®ÛŒØ±Ù‡ Ø³Ø§Ù„â€ŒÙ‡Ø§ÛŒ Ù‚Ø¨Ù„)
    let usePriorYears = !!b.usePriorYears;
    if (kind === 'leave' && deductFromEntitlement) {
      const fakeReq = { mode: mode, startDate: startDate, endDate: endDate, fromTime: fromTime, toTime: toTime, fixedDays: fixedDays, typeId: typeId, typeName: typeName };
      const daysNeeded = countLeaveDays(fakeReq, gd.obj, emp.contractType);
      const avail = leaveAvailabilityForEmp(gd.obj, emp, daysNeeded);
      const tAllowAdv = !!(tdef && tdef.allowAdvance);
      let grantAllowAdv = false;
      if (grantId) {
        const gg = (gd.obj.attendanceGrants || []).find(function (x) { return x && String(x.id) === String(grantId); });
        if (gg && gg.allowAdvance) grantAllowAdv = true;
      }
      const allowAdvance = tAllowAdv || grantAllowAdv || !!b.allowAdvance;
      if (avail.insufficient && !allowAdvance) {
        return jsonResponse({
          ok: false,
          error: 'no_leave_balance',
          message: 'Ø¨ÛŒØ´ Ø§Ø² Ø³Ù‚Ù Ø³Ø§Ù„Ø§Ù†Ù‡. Ø³Ù‚Ù: ' + (avail.annualDays||'') + 'ØŒ Ø§Ø³ØªÙØ§Ø¯Ù‡â€ŒØ´Ø¯Ù‡: ' + (avail.usedYear||0) + 'ØŒ Ø¨Ø§Ù‚ÛŒ ØªØ§ Ø³Ù‚Ù: ' + avail.currentRemaining + 'ØŒ Ø°Ø®ÛŒØ±Ù‡ Ù‚Ø¨Ù„: ' + avail.priorRemaining + 'ØŒ Ø¯Ø±Ø®ÙˆØ§Ø³Øª: ' + daysNeeded + ' Ø±ÙˆØ². Ø¨Ø±Ø§ÛŒ Ø¨ÛŒØ´ Ø§Ø² Ø³Ù‚Ù Ø§Ø² ØªØ¹Ø¯ÛŒÙ„ (+) Ø§Ø³ØªÙØ§Ø¯Ù‡ Ú©Ù†ÛŒØ¯.',
          availability: avail
        }, 400);
      }
      if (avail.insufficient && allowAdvance) {
        usePriorYears = true; // Ú©Ø³Ø± Ù…ÛŒâ€ŒØªÙˆØ§Ù†Ø¯ Ù…Ù†ÙÛŒ Ø´ÙˆØ¯
        // flag on request
      }
      if (avail.needPriorYears && !usePriorYears) {
        return jsonResponse({
          ok: false,
          error: 'need_prior_years_confirm',
          message: 'Ù…Ø§Ù†Ø¯Ù‡ Ù…Ø±Ø®ØµÛŒ Ø§Ù…Ø³Ø§Ù„ (' + avail.currentRemaining + ' Ø±ÙˆØ²) Ø¨Ø±Ø§ÛŒ Ø§ÛŒÙ† Ø¯Ø±Ø®ÙˆØ§Ø³Øª Ú©Ø§ÙÛŒ Ù†ÛŒØ³Øª. Ø§Ø² Ø°Ø®ÛŒØ±Ù‡ Ø³Ø§Ù„â€ŒÙ‡Ø§ÛŒ Ù‚Ø¨Ù„ (' + avail.priorRemaining + ' Ø±ÙˆØ²) Ø§Ø³ØªÙØ§Ø¯Ù‡ Ø´ÙˆØ¯ØŸ',
          availability: avail
        }, 409);
      }
      if (avail.needPriorYears) usePriorYears = true;
    }

    const req = {
      id: newRequestId(),
      empCode: String(emp.code),
      empName: emp.fullName || '',
      managerCode: String(mgrCode1),
      managerName: mgr ? (mgr.fullName || '') : '',
      managerCode2: mgrCode2 ? String(mgrCode2) : '',
      managerName2: mgr2 ? (mgr2.fullName || '') : '',
      typeId: typeId || '',
      typeName: typeName,
      deductFromEntitlement: deductFromEntitlement,
      usePriorYears: !!usePriorYears,
      fixedDays: fixedDays,
      frequency: frequency,
      grantId: grantId || '',
      kind, mode,
      startDate, endDate: mode === 'hourly' ? startDate : endDate,
      fromTime: mode === 'hourly' ? fromTime : '',
      toTime: mode === 'hourly' ? toTime : '',
      place: kind === 'mission' ? place : '',
      reason: reason,
      status: 'pending',
      rejectReason: '',
      createdAt: new Date().toISOString(),
      decidedAt: '',
      decidedBy: '',
      decidedAt1: '',
      decidedBy1: '',
      decidedAt2: '',
      decidedBy2: ''
    };
    if (grantId) {
      const g = gd.obj.attendanceGrants.find(function (x) { return x.id === grantId; });
      if (g) {
        g.usedRequestId = req.id; // hide from list while pending approval
        g.reservedRequestId = req.id;
        g.consumed = false;
      }
      req.grantId = grantId;
    }
    gd.obj.attendanceRequests.unshift(req);
    // keep last 2000
    if (gd.obj.attendanceRequests.length > 2000) gd.obj.attendanceRequests.length = 2000;
    const put = await storePutData(cfg, gd.version, gd.obj, 'emp:' + sess.code);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    console.log(JSON.stringify({ event: 'att_request', code: sess.code, kind, mode, id: req.id }));
    return jsonResponse({ ok: true, request: req });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleEmpListRequests(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  const all = (gd.obj && gd.obj.attendanceRequests) || [];
  const mine = all.filter(x => String(x.empCode) === String(sess.code)).slice(0, 100);
  const code = String(sess.code);
  // L1 sees pending; L2 sees approved_l1 waiting for them
  const pendingForMe = all.filter(function (x) {
    if (String(x.managerCode) === code && x.status === 'pending') return true;
    if (String(x.managerCode2) === code && x.status === 'approved_l1') return true;
    return false;
  }).slice(0, 100);
  const managedForMe = all.filter(function (x) {
    return String(x.managerCode) === code || String(x.managerCode2) === code;
  }).slice(0, 150);
  const meta = gd.obj.portalMeta || {};
  const isManager = (gd.obj.employees || []).some(function (e) {
    if (e.status === 'inactive') return false;
    const m = meta[String(e.code)] || {};
    const m1 = m.managerCode || e.managerCode || '';
    const m2 = m.managerCode2 || e.managerCode2 || '';
    return String(m1) === code || String(m2) === code;
  });
  return jsonResponse({ ok: true, mine, pendingForMe, managedForMe, isManager: isManager });
}


// ---------- Leave balance & safe extensions (non-breaking) ----------
function getLeavePolicy(obj) {
  const s = (obj && obj.settings) || {};
  const p = s.leavePolicy || {};
  var annual = Number(p.annualDays);
  if (isNaN(annual) || annual < 0) annual = 26;
  return {
    annualDays: annual,
    carryMax: Number(p.carryMax) >= 0 ? Number(p.carryMax) : 9,
    byContractType: (p.byContractType && typeof p.byContractType === 'object') ? p.byContractType : {},
    byGroup: (p.byGroup && typeof p.byGroup === 'object') ? p.byGroup : {}
  };
}

/** Ø³Ù‚Ù Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ: Ú¯Ø±ÙˆÙ‡ Ú©Ø§Ø±ÛŒ > Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ > Ù¾ÛŒØ´â€ŒÙØ±Ø¶ Ø³ÛŒØ§Ø³Øª (Ø¨Ø¯ÙˆÙ† Ù…Ù‡Ø§Ø¬Ø±Øª Ø§Ø¹Ø¯Ø§Ø¯ Ù‚Ø¯ÛŒÙ…ÛŒ) */
function getAnnualLeaveDaysForEmp(obj, emp) {
  const pol = getLeavePolicy(obj);
  if (!emp) return pol.annualDays;
  const grp = String(emp.group || '').trim();
  if (grp && pol.byGroup && pol.byGroup[grp] != null && pol.byGroup[grp] !== '') {
    const n = Number(pol.byGroup[grp]);
    if (!isNaN(n) && n >= 0) return n;
  }
  const ct = String(emp.contractType || 'normal').trim() || 'normal';
  if (pol.byContractType && pol.byContractType[ct] != null && pol.byContractType[ct] !== '') {
    const n = Number(pol.byContractType[ct]);
    if (!isNaN(n) && n >= 0) return n;
  }
  return pol.annualDays;
}

function jalaliDaysInYearW(y) {
  y = Number(y);
  const cy = y - 979;
  const breaks = [1, 5, 9, 13, 17, 22, 26, 30];
  const k = cy % 33;
  return breaks.indexOf(k) >= 0 ? 366 : 365;
}
function jalaliDayOfYearW(y, m, d) {
  const md = [0, 31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29];
  if (jalaliDaysInYearW(y) === 366) md[12] = 30;
  let n = 0;
  for (let i = 1; i < m; i++) n += md[i];
  return n + d;
}

/** Ø§Ø³ØªØ­Ù‚Ø§Ù‚ ØªÙ†Ø§Ø³Ø¨ÛŒ ØªØ§ Ù¾Ø§ÛŒØ§Ù† Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒ: (ØªØ¹Ø¯Ø§Ø¯ Ù…Ø§Ù‡ Ú©Ø§Ø±Ú©Ø±Ø¯ Ø¯Ø± Ø³Ø§Ù„ Ø´Ø§Ù…Ù„ Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒ) / 12 Ã— Ø³Ù‚Ù Ø³Ø§Ù„Ø§Ù†Ù‡ */
function computeAccruedLeaveDaysW(obj, emp, year, month) {
  const annual = getAnnualLeaveDaysForEmp(obj, emp);
  const cy = Number(year) || Number((obj.settings || {}).currentYear) || 1405;
  let cm = Number(month);
  if (!cm) cm = Number((obj.settings || {}).currentMonth) || Number((obj.settings || {}).activeMonth) || 0;
  if (!cm) { try { var _pc = (typeof getPortalCalendarNow === 'function') ? getPortalCalendarNow(obj) : null; cm = (_pc && _pc.realMonth) || 0; } catch(eCm){} }
  if (!cm) cm = 1;
  if (cm < 1) cm = 1;
  if (cm > 12) cm = 12;
  const p = parseJalaliYMD(emp && emp.hireDate);
  if (!p) {
    // Ø¨Ø¯ÙˆÙ† ØªØ§Ø±ÛŒØ® Ø§Ø³ØªØ®Ø¯Ø§Ù…: ØªÙ†Ø§Ø³Ø¨ Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒ
    return Math.round(annual * (cm / 12) * 100) / 100;
  }
  if (p.y > cy) return 0;
  let months = 0;
  if (p.y < cy) {
    months = cm; // Ø§Ø² Ø§ÙˆÙ„ Ø³Ø§Ù„ ØªØ§ Ù…Ø§Ù‡ Ø¬Ø§Ø±ÛŒ
  } else {
    // Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø¯Ø± Ù‡Ù…ÛŒÙ† Ø³Ø§Ù„
    if (p.m > cm) return 0;
    months = cm - p.m + 1;
  }
  if (months < 0) months = 0;
  if (months > 12) months = 12;
  return Math.round(annual * (months / 12) * 100) / 100;
}

function computeProratedLeaveDaysW(obj, emp, year) {
  year = Number(year) || Number((obj.settings || {}).currentYear) || 1405;
  const annual = getAnnualLeaveDaysForEmp(obj, emp);
  const hireStr = emp && emp.hireDate;
  const m = String(hireStr || '').trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
  if (!m) return annual;
  const hy = Number(m[1]), hm = Number(m[2]), hd = Number(m[3]);
  if (hy < year) return annual;
  if (hy > year) return 0;
  const diy = jalaliDaysInYearW(year);
  const doy = jalaliDayOfYearW(hy, hm, hd);
  let remaining = diy - doy + 1;
  if (remaining < 0) remaining = 0;
  if (remaining > diy) remaining = diy;
  return Math.round(annual * (remaining / diy) * 100) / 100;
}
function ensureEmpLeaveFields(emp, obj) {
  if (!emp) return;
  ensureEmpLeaveYears(emp, obj);
}

/** Ø¯ÙØªØ± Ø³Ø§Ù„Ø§Ù†Ù‡ Ù…Ø±Ø®ØµÛŒ: Ù‡Ø± Ø³Ø§Ù„ ÛŒÚ© Ø±Ø¯ÛŒÙ (Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ / Ø§Ø³ØªÙØ§Ø¯Ù‡â€ŒØ´Ø¯Ù‡ / Ù…Ø§Ù†Ø¯Ù‡ / ØªØ³ÙˆÛŒÙ‡â€ŒØ´Ø¯Ù‡) */

/** Ø¬Ù…Ø¹ Ù…Ø±Ø®ØµÛŒ Ø§Ø³ØªÙØ§Ø¯Ù‡â€ŒØ´Ø¯Ù‡ Ø³Ø§Ù„ Ø§Ø² Ø¯Ø±Ø®ÙˆØ§Ø³Øªâ€ŒÙ‡Ø§ÛŒ ØªØ£ÛŒÛŒØ¯Ø´Ø¯Ù‡ + ÙˆØ±ÙˆØ¯ Ø¯Ø§Ø¯Ù‡ Ù…Ø§Ù‡Ø§Ù†Ù‡ */
function sumUsedLeaveDaysForYear(obj, empCode, year) {
  year = Number(year) || 0;
  var code = String(empCode || '');
  var daily = 0, hourly = 0;
  // Ø§Ø² Ø¯Ø±Ø®ÙˆØ§Ø³Øªâ€ŒÙ‡Ø§ÛŒ ØªØ£ÛŒÛŒØ¯Ø´Ø¯Ù‡ Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ
  (obj.attendanceRequests || []).forEach(function (x) {
    if (!x || String(x.empCode) !== code) return;
    if (x.status !== 'approved') return;
    if (x.kind !== 'leave') return;
    // ÙÙ‚Ø· Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ (Ú©Ø³Ø± Ø§Ø² Ù…Ø§Ù†Ø¯Ù‡) â€” Ø§Ú¯Ø± ÙÙ„Ú¯ Ù†Ø¨ÙˆØ¯ Ùˆ Ù†ÙˆØ¹ Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ Ø§Ø³Øª Ù‡Ù… Ø­Ø³Ø§Ø¨ Ú©Ù†
    var deduct = x.deductFromEntitlement;
    if (deduct === false) return;
    if (x.mode === 'daily') {
      var p1 = parseJalaliYMD(x.startDate);
      var p2 = parseJalaliYMD(x.endDate || x.startDate);
      if (!p1) return;
      // Ø±ÙˆØ²Ù‡Ø§ÛŒ Ù…ØªØ¹Ù„Ù‚ Ø¨Ù‡ Ø§ÛŒÙ† Ø³Ø§Ù„
      if (p1.y === year || (p2 && p2.y === year)) {
        try {
          daily += countLeaveDays(x, obj, null);
        } catch (e) {
          // fallback: Ø§Ø®ØªÙ„Ø§Ù Ø³Ø§Ø¯Ù‡
          if (p1.y === year && (!p2 || p2.y === year)) {
            var a = p1.d || 1, b = (p2 && p2.d) || a;
            if (p1.m === (p2 && p2.m) && p1.y === (p2 && p2.y)) daily += Math.max(1, b - a + 1);
            else daily += 1;
          }
        }
      }
    } else if (x.mode === 'hourly') {
      var ph = parseJalaliYMD(x.startDate);
      if (ph && ph.y === year) {
        try { hourly += hoursBetween(x.fromTime, x.toTime); } catch (e2) {}
      }
    }
  });
  // Ø§Ø² ÙˆØ±ÙˆØ¯ Ø¯Ø§Ø¯Ù‡ Ù…Ø§Ù‡Ø§Ù†Ù‡ (Ø§Ú¯Ø± Ø¨ÛŒØ´ØªØ± Ø¨Ø§Ø´Ø¯)
  var mdDaily = 0, mdHourly = 0;
  var md = (obj && obj.monthlyData) || {};
  for (var m = 1; m <= 12; m++) {
    var key = year + '-' + m;
    var row = md[key] && md[key][code];
    if (!row) continue;
    mdDaily += Number(row.leaveDays) || 0;
    mdHourly += Number(row.hourlyLeave) || 0;
  }
  // Ø³Ø§Ø¹ØªÛŒ â†’ Ø±ÙˆØ² (ØªÙ‚Ø±ÛŒØ¨ÛŒ Û¸ Ø³Ø§Ø¹Øª Ú©Ø§Ø±ÛŒ)
  var fromReq = Math.round((daily + hourly / 8) * 100) / 100;
  var fromMd = Math.round((mdDaily + mdHourly / 8) * 100) / 100;
  return Math.max(fromReq, fromMd);
}

function ensureEmpLeaveYears(emp, obj) {
  if (!emp) return;
  const cy = Number((obj && obj.settings && obj.settings.currentYear) || 1405);
  if (!emp.leaveYears || typeof emp.leaveYears !== 'object') emp.leaveYears = {};
  // Ù…Ù‡Ø§Ø¬Ø±Øª Ø§Ø² ÙÛŒÙ„Ø¯Ù‡Ø§ÛŒ Ù‚Ø¯ÛŒÙ…ÛŒ
  if (!emp.leaveYears[String(cy)]) {
    let entitled = getAnnualLeaveDaysForEmp(obj, emp);
    let used = Number(emp.leaveUsedYear) || 0;
    let accrued = computeAccruedLeaveDaysW(obj, emp, cy);
    let remaining = Math.round((accrued - used) * 100) / 100;
    emp.leaveYears[String(cy)] = {
      year: cy,
      entitled: Math.round(entitled * 100) / 100,
      accrued: accrued,
      used: Math.round(used * 100) / 100,
      remaining: remaining,
      settled: false,
      settledAt: null,
      settledMode: null
    };
  }
  // Ø§Ø·Ù…ÛŒÙ†Ø§Ù† Ø§Ø² Ø³Ø§Ù„ Ø¬Ø§Ø±ÛŒ
  // - Ø§Ø³ØªØ®Ø¯Ø§Ù… Ù‚Ø¨Ù„ Ø§Ø² Ø§Ù…Ø³Ø§Ù„: Ø³Ù‚Ù Ú©Ø§Ù…Ù„ Ø³Ø§Ù„Ø§Ù†Ù‡ Ø¨Ø±Ø§ÛŒ Ø¯Ø±Ø®ÙˆØ§Ø³Øª Ø¯Ø± Ø·ÙˆÙ„ Ø³Ø§Ù„ (Ù…Ø§Ù†Ø¯Ù‡ = Ø³Ù‚Ù âˆ’ Ù…ØµØ±Ù)
  // - Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø§Ù…Ø³Ø§Ù„: ØªÙ†Ø§Ø³Ø¨ Ø§Ø² ØªØ§Ø±ÛŒØ® Ø§Ø³ØªØ®Ø¯Ø§Ù… (computeAccruedLeaveDaysW)
  const row = emp.leaveYears[String(cy)];
  row.entitled = getAnnualLeaveDaysForEmp(obj, emp);
  const accrued = computeAccruedLeaveDaysW(obj, emp, cy);
  row.accrued = accrued;
  // Ù‡Ù…Ú¯Ø§Ù…â€ŒØ³Ø§Ø²ÛŒ used Ø¨Ø§ Ù…Ø±Ø®ØµÛŒ ÙˆØ§Ù‚Ø¹ÛŒ (ØªØ§ÛŒÙ…â€ŒØ´ÛŒØª / Ø¯Ø±Ø®ÙˆØ§Ø³Øª ØªØ£ÛŒÛŒØ¯Ø´Ø¯Ù‡)
  try {
    var usedActual = sumUsedLeaveDaysForYear(obj, emp.code, cy);
    var usedStored = Number(row.used) || 0;
    if (usedActual > usedStored) {
      row.used = Math.round(usedActual * 100) / 100;
    }
  } catch (eUsed) {}
  if (row.settled) {
    row.remaining = 0;
  } else {
    let adjPos = 0;
    (emp.leaveAdjustments || []).forEach(function (a) {
      if (String(a.year) !== String(cy)) return;
      const d = Number(a.delta) || 0;
      if (d > 0) adjPos += d;
    });
    // Ù…Ø§Ù†Ø¯Ù‡ = Ø³Ù‚Ù Ù‚Ø§Ø¨Ù„ Ø§Ø³ØªÙØ§Ø¯Ù‡ âˆ’ Ù…ØµØ±Ù
    // Ø§Ø³ØªØ®Ø¯Ø§Ù… Ù‚Ø¨Ù„ Ø§Ø² Ø§Ù…Ø³Ø§Ù„ / Ø¨Ø¯ÙˆÙ† ØªØ§Ø±ÛŒØ®: Ø³Ù‚Ù Ú©Ø§Ù…Ù„ Ø³Ø§Ù„Ø§Ù†Ù‡
    // Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø¯Ø± Ù‡Ù…ÛŒÙ† Ø³Ø§Ù„: ØªÙ†Ø§Ø³Ø¨ Ø§Ø² ØªØ§Ø±ÛŒØ® Ø§Ø³ØªØ®Ø¯Ø§Ù… ØªØ§ Ù¾Ø§ÛŒØ§Ù† Ø³Ø§Ù„
    var baseForRemain = Number(row.entitled) || accrued;
    try {
      var hireP = parseJalaliYMD(emp && emp.hireDate);
      if (hireP && hireP.y > cy) baseForRemain = 0;
      else if (hireP && hireP.y === cy) baseForRemain = computeProratedLeaveDaysW(obj, emp, cy);
      else baseForRemain = Number(row.entitled) || getAnnualLeaveDaysForEmp(obj, emp);
    } catch (eBase) {
      baseForRemain = Number(row.entitled) || accrued;
    }
    row.remaining = Math.round((baseForRemain - Number(row.used || 0) + adjPos) * 100) / 100;
  }
  // ÙÛŒÙ„Ø¯ Ø³Ø§Ø²Ú¯Ø§Ø±ÛŒ: ÙÙ‚Ø· Ù…Ø§Ù†Ø¯Ù‡ Ø³Ø§Ù„ Ø¬Ø§Ø±ÛŒ (Ù†Ù‡ ØªØ¬Ù…ÛŒØ¹ Ø³Ø§Ù„â€ŒÙ‡Ø§ÛŒ Ù‚Ø¨Ù„)
  emp.leaveBalance = Number((emp.leaveYears[String(cy)] || {}).remaining) || 0;
  emp.leaveUsedYear = Number((emp.leaveYears[String(cy)] || {}).used) || 0;
  emp.leaveBalanceYear = cy;
}

function sumUnsettledLeaveRemaining(emp) {
  if (!emp || !emp.leaveYears) return Number(emp.leaveBalance) || 0;
  let s = 0;
  Object.keys(emp.leaveYears).forEach(function (yk) {
    const r = emp.leaveYears[yk];
    if (!r || r.settled) return;
    s += Number(r.remaining) || 0;
  });
  return Math.round(s * 100) / 100;
}

function getLeaveYearRow(emp, year) {
  if (!emp.leaveYears) emp.leaveYears = {};
  const k = String(year);
  if (!emp.leaveYears[k]) {
    emp.leaveYears[k] = {
      year: Number(year),
      entitled: 0,
      used: 0,
      remaining: 0,
      settled: false,
      settledAt: null,
      settledMode: null
    };
  }
  return emp.leaveYears[k];
}

function listLeaveYearsSorted(emp) {
  if (!emp || !emp.leaveYears) return [];
  return Object.keys(emp.leaveYears).map(Number).filter(function (y) { return !isNaN(y); }).sort(function (a, b) { return a - b; })
    .map(function (y) { return emp.leaveYears[String(y)]; });
}


/** Ø±ÙˆØ² Ù‡ÙØªÙ‡ Ø¬Ù„Ø§Ù„ÛŒ â†’ 0=ÛŒÚ©Ø´Ù†Ø¨Ù‡ â€¦ 6=Ø´Ù†Ø¨Ù‡ (Ù…Ø·Ø§Ø¨Ù‚ Date.getUTCDay) */
function jalaliWeekday(jy, jm, jd) {
  // ØªØ¨Ø¯ÛŒÙ„ ØªÙ‚Ø±ÛŒØ¨ÛŒ Ø¬Ù„Ø§Ù„ÛŒ Ø¨Ù‡ Ù…ÛŒÙ„Ø§Ø¯ÛŒ (Ø§Ù„Ú¯ÙˆØ±ÛŒØªÙ… Ø±Ø§ÛŒØ¬)
  jy = Number(jy); jm = Number(jm); jd = Number(jd);
  var gy, gm, gd;
  var jy2 = jy - 979;
  var days = 365 * jy2 + Math.floor(jy2 / 33) * 8 + Math.floor(((jy2 % 33) + 3) / 4) + 78 + jd + (jm < 7 ? (jm - 1) * 31 : ((jm - 7) * 30 + 186));
  var gy2 = 1600 + 400 * Math.floor(days / 146097);
  days = days % 146097;
  var leap = true;
  if (days >= 36525) { days--; gy2 += 100 * Math.floor(days / 36524); days = days % 36524; if (days >= 365) days++; else leap = false; }
  gy2 += 4 * Math.floor(days / 1461); days %= 1461;
  if (days >= 366) { leap = false; gy2 += Math.floor((days - 1) / 365); days = (days - 1) % 365; }
  gy = gy2;
  var sal_a = [0, 31, (leap ? 29 : 28), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  gm = 0;
  for (gm = 0; gm < 13; gm++) {
    var v = sal_a[gm];
    if (days < v) break;
    days -= v;
  }
  gd = days + 1;
  var dt = new Date(Date.UTC(gy, gm - 1, gd));
  return dt.getUTCDay();
}


function defaultContractTypesList() {
  return [
    { id: 'normal', name: 'Ø¹Ø§Ø¯ÛŒ' },
    { id: 'daily', name: 'Ø±ÙˆØ²Ù…Ø²Ø¯' },
    { id: 'hourly', name: 'Ø³Ø§Ø¹ØªÛŒ' }
  ];
}

/** Ú©Ù„ÛŒØ¯ ÛŒÚ©Ø³Ø§Ù†â€ŒØ³Ø§Ø²ÛŒ Ø¨Ø±Ø§ÛŒ Ø­Ø°Ù ØªÚ©Ø±Ø§Ø±ÛŒ Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ (ÙØ§ØµÙ„Ù‡/Ø®Ø· ØªÛŒØ±Ù‡/Ù†ÛŒÙ…â€ŒÙØ§ØµÙ„Ù‡ Ù†Ø§Ø¯ÛŒØ¯Ù‡) */
function normContractKey(s) {
  return String(s || '')
    .replace(/[\u200c\u200d\u200e\u200f\u00a0]/g, '')
    .replace(/[\s\-_]+/g, '')
    .toLowerCase();
}

/** Ù†Ø§Ù… ÙØ§Ø±Ø³ÛŒ Ø§Ø³ØªØ§Ù†Ø¯Ø§Ø±Ø¯ Ø¨Ø±Ø§ÛŒ Ø´Ù†Ø§Ø³Ù‡â€ŒÙ‡Ø§ÛŒ Ø±Ø§ÛŒØ¬ Ø§Ù†Ú¯Ù„ÛŒØ³ÛŒ */
var CONTRACT_TYPE_FA = {
  normal: 'Ø¹Ø§Ø¯ÛŒ',
  daily: 'Ø±ÙˆØ²Ù…Ø²Ø¯',
  hourly: 'Ø³Ø§Ø¹ØªÛŒ',
  fixed: 'Ø¯Ø§Ø¦Ù…',
  permanent: 'Ø¯Ø§Ø¦Ù…',
  temporary: 'Ù…ÙˆÙ‚Øª',
  temp: 'Ù…ÙˆÙ‚Øª',
  contract: 'Ù¾ÛŒÙ…Ø§Ù†ÛŒ',
  shift: 'Ø´ÛŒÙØªÛŒ',
  parttime: 'Ù¾Ø§Ø±Ù‡â€ŒÙˆÙ‚Øª',
  'part-time': 'Ù¾Ø§Ø±Ù‡â€ŒÙˆÙ‚Øª',
  fulltime: 'ØªÙ…Ø§Ù…â€ŒÙˆÙ‚Øª',
  'full-time': 'ØªÙ…Ø§Ù…â€ŒÙˆÙ‚Øª',
  intern: 'Ú©Ø§Ø±Ø¢Ù…ÙˆØ²ÛŒ',
  seasonal: 'ÙØµÙ„ÛŒ'
};

function isMostlyLatin(s) {
  var t = String(s || '');
  if (!t) return true;
  var latin = (t.match(/[A-Za-z]/g) || []).length;
  var fa = (t.match(/[\u0600-\u06FF]/g) || []).length;
  return latin > 0 && fa === 0;
}

function persianContractName(id, name) {
  var i = String(id || '').trim();
  var n = String(name || '').trim();
  var key = i.toLowerCase();
  if (CONTRACT_TYPE_FA[key]) return CONTRACT_TYPE_FA[key];
  if (n && CONTRACT_TYPE_FA[n.toLowerCase()]) return CONTRACT_TYPE_FA[n.toLowerCase()];
  if (n && !isMostlyLatin(n)) return n;
  return n || i;
}

/** Ø§Ø¯ØºØ§Ù… Ùˆ Ø­Ø°Ù ØªÚ©Ø±Ø§Ø±ÛŒ Ù„ÛŒØ³Øª Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ + Ø¨Ø±Ø¯Ø§Ø´Øª Ø§Ø² Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ú©Ø§Ø±Ú©Ù†Ø§Ù† */
function mergeDedupeContractTypes(obj) {
  if (!obj) return;
  if (!obj.settings || typeof obj.settings !== 'object') obj.settings = {};
  var s = obj.settings;
  var byId = {};
  var byNameKey = {};
  function add(t) {
    if (!t) return;
    var id = String(t.id || '').trim();
    var name = persianContractName(id, t.name || t.id || '');
    if (!id && name) {
      id = name.replace(/[^\w\u0600-\u06FF]+/g, '_').replace(/^_+|_+$/g, '') || ('ct_' + Math.random().toString(36).slice(2, 8));
    }
    if (!id) return;
    if (CONTRACT_TYPE_FA[id.toLowerCase()]) name = CONTRACT_TYPE_FA[id.toLowerCase()];
    else if (!name) name = persianContractName(id, id);
    var nk = normContractKey(name);
    if (byNameKey[nk] && byNameKey[nk] !== id) {
      var keepId = byNameKey[nk];
      if (!byId[keepId]) byId[keepId] = { id: keepId, name: name };
      if (CONTRACT_TYPE_FA[keepId.toLowerCase()]) byId[keepId].name = CONTRACT_TYPE_FA[keepId.toLowerCase()];
      else if (!isMostlyLatin(name)) byId[keepId].name = name;
      return;
    }
    if (byId[id]) {
      var cur = byId[id].name || '';
      if (CONTRACT_TYPE_FA[id.toLowerCase()]) byId[id].name = CONTRACT_TYPE_FA[id.toLowerCase()];
      else if (isMostlyLatin(cur) && !isMostlyLatin(name)) byId[id].name = name;
      else if (!isMostlyLatin(name) && name.length >= cur.length) byId[id].name = name;
    } else {
      byId[id] = { id: id, name: name };
      if (nk) byNameKey[nk] = id;
    }
  }
  (Array.isArray(s.contractTypesList) ? s.contractTypesList : []).forEach(add);
  defaultContractTypesList().forEach(add);
  (Array.isArray(obj.employees) ? obj.employees : []).forEach(function (e) {
    if (!e) return;
    var ct = e.contractType || e.contract_type || '';
    if (!ct) return;
    var id = String(ct).trim();
    add({ id: id, name: persianContractName(id, id) });
  });
  (Array.isArray(obj.contracts) ? obj.contracts : []).forEach(function (c) {
    if (!c) return;
    var ct = c.contractType || c.type || '';
    if (ct) {
      var id = String(ct).trim();
      add({ id: id, name: persianContractName(id, id) });
    }
  });
  var order = { normal: 0, daily: 1, hourly: 2, fixed: 3, permanent: 3, temporary: 4, temp: 4 };
  var list = Object.keys(byId).map(function (k) { return byId[k]; });
  list.sort(function (a, b) {
    var oa = order[String(a.id).toLowerCase()] != null ? order[String(a.id).toLowerCase()] : 50;
    var ob = order[String(b.id).toLowerCase()] != null ? order[String(b.id).toLowerCase()] : 50;
    if (oa !== ob) return oa - ob;
    return String(a.name || a.id).localeCompare(String(b.name || b.id), 'fa');
  });
  s.contractTypesList = list;
  return list;
}

/** ØªØ¹Ø·ÛŒÙ„Ø§Øª Ø±Ø³Ù…ÛŒ Ø´Ù…Ø³ÛŒ Ø«Ø§Ø¨Øª (Ø¨Ø¯ÙˆÙ† Ù…Ù†Ø§Ø³Ø¨Øªâ€ŒÙ‡Ø§ÛŒ Ù‚Ù…Ø±ÛŒ Ú©Ù‡ Ù‡Ø± Ø³Ø§Ù„ Ø¬Ø§Ø¨Ù‡â€ŒØ¬Ø§ Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯) */
function defaultIranHolidaysForYear(year) {
  year = Number(year);
  function d(m, day) {
    return year + '/' + String(m).padStart(2, '0') + '/' + String(day).padStart(2, '0');
  }
  return [
    d(1, 1), d(1, 2), d(1, 3), d(1, 4), // Ù†ÙˆØ±ÙˆØ²
    d(1, 12), // Ø±ÙˆØ² Ø¬Ù…Ù‡ÙˆØ±ÛŒ Ø§Ø³Ù„Ø§Ù…ÛŒ
    d(1, 13), // Ø±ÙˆØ² Ø·Ø¨ÛŒØ¹Øª
    d(3, 14), // Ø±Ø­Ù„Øª Ø§Ù…Ø§Ù… Ø®Ù…ÛŒÙ†ÛŒ
    d(3, 15), // Ù‚ÛŒØ§Ù… Û±Ûµ Ø®Ø±Ø¯Ø§Ø¯
    d(11, 22), // Ù¾ÛŒØ±ÙˆØ²ÛŒ Ø§Ù†Ù‚Ù„Ø§Ø¨
    d(12, 29) // Ù…Ù„ÛŒ Ø´Ø¯Ù† ØµÙ†Ø¹Øª Ù†ÙØª
  ];
}

function cloneHolidaysByYear(src) {
  const out = {};
  if (!src || typeof src !== 'object') return out;
  Object.keys(src).forEach(function (y) {
    out[y] = Array.isArray(src[y]) ? src[y].slice() : [];
  });
  return out;
}

function ensureContractCalendars(obj) {
  if (!obj.settings) obj.settings = {};
  const s = obj.settings;
  try { mergeDedupeContractTypes(obj); } catch (eMd) {
    if (!Array.isArray(s.contractTypesList) || !s.contractTypesList.length) {
      s.contractTypesList = defaultContractTypesList();
    }
  }
  if (!s.contractCalendars || typeof s.contractCalendars !== 'object') s.contractCalendars = {};
  const cy = Number(s.currentYear) || 1405;

  // Ù…Ù‡Ø§Ø¬Ø±Øª ÛŒÚ©â€ŒØ¨Ø§Ø±Ù‡ Ø§Ø² ØªÙ†Ø¸ÛŒÙ…Ø§Øª Ø³Ø±Ø§Ø³Ø±ÛŒ â€” Ú©Ù¾ÛŒ Ø¹Ù…ÛŒÙ‚ ØªØ§ Ø§Ø´ØªØ±Ø§Ú© Ù…Ø±Ø¬Ø¹ Ù†Ø¨Ø§Ø´Ø¯
  if (!s.contractCalendars.normal) {
    const migrated = (s.holidaysByYear && typeof s.holidaysByYear === 'object')
      ? cloneHolidaysByYear(s.holidaysByYear)
      : {};
    if (!migrated[String(cy)] || !migrated[String(cy)].length) {
      migrated[String(cy)] = defaultIranHolidaysForYear(cy);
    }
    s.contractCalendars.normal = {
      workWeekDays: Array.isArray(s.workWeekDays) && s.workWeekDays.length ? s.workWeekDays.slice() : [6, 0, 1, 2, 3],
      countNonWorkDaysAsLeave: false,
      holidaysByYear: migrated
    };
  }

  s.contractTypesList.forEach(function (t) {
    if (!t || !t.id) return;
    if (!s.contractCalendars[t.id]) {
      // ØªÙ‚ÙˆÛŒÙ… Ø¬Ø¯ÛŒØ¯: Ù¾ÛŒØ´â€ŒÙØ±Ø¶ Ø§ÛŒØ±Ø§Ù†ØŒ Ù…Ø³ØªÙ‚Ù„ Ø§Ø² Ø§Ù†ÙˆØ§Ø¹ Ø¯ÛŒÚ¯Ø± (Ú©Ù¾ÛŒ Ø§Ø² Ù„ÛŒØ³Øª Ù¾ÛŒØ´â€ŒÙØ±Ø¶ Ù†Ù‡ Ø§Ø² Ù†ÙˆØ¹ Ø¯ÛŒÚ¯Ø±)
      const hy = {};
      hy[String(cy)] = defaultIranHolidaysForYear(cy);
      s.contractCalendars[t.id] = Object.assign({
        workWeekDays: [6, 0, 1, 2, 3], // Ø´Ù†Ø¨Ù‡ ØªØ§ Ú†Ù‡Ø§Ø±Ø´Ù†Ø¨Ù‡Ø› Ù¾Ù†Ø¬Ø´Ù†Ø¨Ù‡ Ùˆ Ø¬Ù…Ø¹Ù‡ ØªØ¹Ø·ÛŒÙ„
        countNonWorkDaysAsLeave: false,
        holidaysByYear: hy
      }, defaultWorkSchedule());
    } else {
      // Ø§Ø·Ù…ÛŒÙ†Ø§Ù† Ø§Ø² ÙˆØ¬ÙˆØ¯ Ø¢Ø±Ø§ÛŒÙ‡ ØªØ¹Ø·ÛŒÙ„Ø§Øª Ø³Ø§Ù„ Ø¬Ø§Ø±ÛŒ Ø¨Ø¯ÙˆÙ† Ù¾Ø§Ú© Ú©Ø±Ø¯Ù† Ø³Ø§Ù„â€ŒÙ‡Ø§ÛŒ Ø¯ÛŒÚ¯Ø±
      const cal = s.contractCalendars[t.id];
      if (!cal.holidaysByYear || typeof cal.holidaysByYear !== 'object') cal.holidaysByYear = {};
      if (!Array.isArray(cal.workWeekDays) || !cal.workWeekDays.length) {
        cal.workWeekDays = [6, 0, 1, 2, 3];
      }
      // ØªØ±Ù…ÛŒÙ…: Ù…Ù‚Ø§Ø¯ÛŒØ± Ù†ÙˆØ¹ Â«Ø³Ø§Ø¹ØªÛŒÂ» (Û°Û°:Û°Û° ØªØ§ Û²Û³:ÛµÛ¹ØŒ Ø´Ù†Ø§ÙˆØ±ÛŒ Û°ØŒ Ù‡Ø± Û· Ø±ÙˆØ² Ù‡ÙØªÙ‡) Ø¨Ù‡â€ŒØ§Ø´ØªØ¨Ø§Ù‡ Ø±ÙˆÛŒ Ù†ÙˆØ¹ Ø¯ÛŒÚ¯Ø±ÛŒ Ø°Ø®ÛŒØ±Ù‡ Ø´Ø¯Ù‡ Ø¨ÙˆØ¯
      if (t.id !== 'hourly'
        && cal.workStart === '00:00' && cal.workEnd === '23:59'
        && Number(cal.floatMinutes) === 0 && !cal.hasBreak
        && cal.workWeekDays.length >= 7) {
        const dws = defaultWorkSchedule();
        cal.workWeekDays = [6, 0, 1, 2, 3];
        Object.keys(dws).forEach(function (k) { cal[k] = dws[k]; });
      }
      // ÙÙ‚Ø· Ø§Ú¯Ø± Ú©Ù„ÛŒØ¯ Ø³Ø§Ù„ Ø§ØµÙ„Ø§Ù‹ ÙˆØ¬ÙˆØ¯ Ù†Ø¯Ø§Ø±Ø¯ Ù¾ÛŒØ´â€ŒÙØ±Ø¶ Ø¨Ú¯Ø°Ø§Ø±Ø› Ø¢Ø±Ø§ÛŒÙ‡ Ø®Ø§Ù„ÛŒ = Ø§Ø¯Ù…ÛŒÙ† Ø¹Ù…Ø¯Ø§Ù‹ Ù¾Ø§Ú© Ú©Ø±Ø¯Ù‡
      if (!Array.isArray(cal.holidaysByYear[String(cy)])) {
        cal.holidaysByYear[String(cy)] = defaultIranHolidaysForYear(cy);
      }
    }
  });
  return s;
}

function defaultWorkSchedule() {
  return {
    workStart: '06:45',
    workEnd: '15:30',
    hasBreak: false,
    breakStart: '12:00',
    breakEnd: '13:00',
    breakCountsAsWork: false,
    dayEnd: '23:59',
    floatMinutes: 15,
    floatCompensate: false
  };
}

function parseFloatMinutesValue(v, fallback) {
  if (v == null || v === '') return fallback;
  var s = String(v).replace(/[Û°-Û¹]/g, function (d) {
    return '0123456789'['Û°Û±Û²Û³Û´ÛµÛ¶Û·Û¸Û¹'.indexOf(d)];
  }).replace(/[^\d.]/g, '');
  var n = parseInt(s, 10);
  if (!isFinite(n) || n < 0) return fallback;
  if (n > 480) n = 480;
  return n;
}

function normalizeWorkSchedule(cal, globalFloat) {
  const d = defaultWorkSchedule();
  const c = cal || {};
  const hasBreak = c.hasBreak != null ? !!c.hasBreak : !!(c.breakStart && c.breakEnd && c._breakExplicit);
  const hb = c.hasBreak != null ? !!c.hasBreak : false;
  // Ø§ÙˆÙ„ÙˆÛŒØª: Ø´Ù†Ø§ÙˆØ±ÛŒ Ø³Ø±Ø§Ø³Ø±ÛŒ settings â†’ ØªÙ‚ÙˆÛŒÙ… Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ â†’ Ù¾ÛŒØ´â€ŒÙØ±Ø¶ Û±Ûµ
  var fm = parseFloatMinutesValue(globalFloat, null);
  if (fm == null) fm = parseFloatMinutesValue(c.floatMinutes, null);
  if (fm == null) fm = d.floatMinutes;
  return {
    workStart: c.workStart || d.workStart,
    workEnd: c.workEnd || d.workEnd,
    hasBreak: hb,
    breakStart: c.breakStart != null ? c.breakStart : d.breakStart,
    breakEnd: c.breakEnd != null ? c.breakEnd : d.breakEnd,
    breakCountsAsWork: hb && !!c.breakCountsAsWork,
    dayEnd: c.dayEnd || d.dayEnd,
    floatMinutes: fm,
    floatCompensate: c.floatCompensate != null ? !!c.floatCompensate : !!d.floatCompensate
  };
}

function resolveCompanyFloatMinutes(obj, calHint) {
  const s = (obj && obj.settings) || {};
  // Ø§ÙˆÙ„ÙˆÛŒØª Ù…Ø·Ù„Ù‚: Ø¢Ø®Ø±ÛŒÙ† Ù…Ù‚Ø¯Ø§Ø± Ø°Ø®ÛŒØ±Ù‡â€ŒØ´Ø¯Ù‡ Ø³Ø±Ø§Ø³Ø±ÛŒ (portal Ø³Ù¾Ø³ settings)
  var fm = parseFloatMinutesValue(s.portalFloatMinutes, null);
  if (fm != null) return fm;
  fm = parseFloatMinutesValue(s.floatMinutes, null);
  if (fm != null) return fm;
  if (calHint) {
    fm = parseFloatMinutesValue(calHint.floatMinutes, null);
    if (fm != null) return fm;
  }
  var normalCal = (s.contractCalendars && s.contractCalendars.normal) || null;
  var nv = parseFloatMinutesValue(normalCal && normalCal.floatMinutes, null);
  if (nv != null) return nv;
  return 15;
}

function getContractCalendar(obj, contractType) {
  ensureContractCalendars(obj || {});
  const s = (obj && obj.settings) || {};
  const ct = String(contractType || 'normal').trim() || 'normal';
  const cal = (s.contractCalendars && s.contractCalendars[ct]) || (s.contractCalendars && s.contractCalendars.normal) || {};
  // Ø´Ù†Ø§ÙˆØ±ÛŒ Ø´Ø±Ú©Øªâ€ŒÙ…Ø­ÙˆØ± â€” Ù†Ù‡ Ù‚ÙÙ„â€ŒØ´Ø¯Ù‡ Ø±ÙˆÛŒ Û±Ûµ Ø¯Ø§Ø®Ù„ ÛŒÚ© Ù†ÙˆØ¹ Ù‚Ø¯ÛŒÙ…ÛŒ
  const companyFloat = resolveCompanyFloatMinutes(obj, cal);
  const sched = normalizeWorkSchedule(cal, companyFloat);
  // Ø³Ø§Ø¹ØªÛŒ: Ø¨Ø§Ø²Ù‡ Ú©Ø§Ø±ÛŒ Ú©Ù„ Ø´Ø¨Ø§Ù†Ù‡â€ŒØ±ÙˆØ² (Ø­Ø¶ÙˆØ± Ù‡Ø± Ø³Ø§Ø¹ØªÛŒ Ù…Ø¹ØªØ¨Ø± Ø§Ø³Øª)
  const hourlyAllDay = (ct === 'hourly');
  return {
    _contractType: ct,
    workWeekDays: hourlyAllDay
      ? [0, 1, 2, 3, 4, 5, 6]
      : (Array.isArray(cal.workWeekDays) ? cal.workWeekDays.map(Number) : [6, 0, 1, 2, 3]),
    countNonWorkDaysAsLeave: !!cal.countNonWorkDaysAsLeave,
    nonWorkLeaveTypeIds: Array.isArray(cal.nonWorkLeaveTypeIds) ? cal.nonWorkLeaveTypeIds.map(String) : [],
    holidaysByYear: (cal.holidaysByYear && typeof cal.holidaysByYear === 'object') ? cal.holidaysByYear : {},
    workStart: hourlyAllDay ? '00:00' : sched.workStart,
    workEnd: hourlyAllDay ? '23:59' : sched.workEnd,
    hasBreak: hourlyAllDay ? false : sched.hasBreak,
    breakStart: sched.breakStart,
    breakEnd: sched.breakEnd,
    breakCountsAsWork: hourlyAllDay ? false : sched.breakCountsAsWork,
    dayEnd: hourlyAllDay ? '23:59' : sched.dayEnd,
    floatMinutes: hourlyAllDay ? 0 : companyFloat,
    floatCompensate: hourlyAllDay ? false : sched.floatCompensate,
    daySchedules: (cal.daySchedules && typeof cal.daySchedules === 'object') ? cal.daySchedules : {},
    _globalFloatMinutes: companyFloat
  };
}

/** Ø¨Ø±Ù†Ø§Ù…Ù‡ Ù…ÙˆØ¸ÙÛŒ ÛŒÚ© Ø±ÙˆØ² Ø®Ø§Øµ â€” Ø¯Ø± ØµÙˆØ±Øª Ù†Ø¨ÙˆØ¯ØŒ Ø¨Ø±Ù†Ø§Ù…Ù‡ Ù¾ÛŒØ´â€ŒÙØ±Ø¶ Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ */
function getDayWorkSchedule(cal, y, m, d) {
  // cal Ù…Ù…Ú©Ù† Ø§Ø³Øª Ø®Ø±ÙˆØ¬ÛŒ getContractCalendar Ø¨Ø§Ø´Ø¯ (floatMinutes Ø§Ø² Ù‚Ø¨Ù„ Ø³Øª Ø´Ø¯Ù‡)
  const globalF = (cal && cal._globalFloatMinutes != null) ? cal._globalFloatMinutes : (cal && cal.floatMinutes);
  const base = normalizeWorkSchedule(cal, globalF);
  if (!cal || !cal.daySchedules) return base;
  const keySlash = y + '/' + String(m).padStart(2, '0') + '/' + String(d).padStart(2, '0');
  const keyDash = y + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
  const over = cal.daySchedules[keySlash] || cal.daySchedules[keyDash] || null;
  if (!over || typeof over !== 'object') return base;
  const out = Object.assign({}, base);
  if (over.workStart) out.workStart = String(over.workStart).trim();
  if (over.workEnd) out.workEnd = String(over.workEnd).trim();
  if (over.dayEnd) out.dayEnd = String(over.dayEnd).trim();
  // Ø´Ù†Ø§ÙˆØ±ÛŒ Ø±ÙˆØ²Ø§Ù†Ù‡ Ø±Ø§ Ù†Ø§Ø¯ÛŒØ¯Ù‡ Ø¨Ú¯ÛŒØ± â€” Ù‡Ù…ÛŒØ´Ù‡ Ø´Ù†Ø§ÙˆØ±ÛŒ Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ / Ø³Ø±Ø§Ø³Ø±ÛŒ (ØªØ§ Û±Ûµ Ù‚ÙÙ„ Ù†Ù…Ø§Ù†Ø¯)
  // if (over.floatMinutes != null && over.floatMinutes !== '') out.floatMinutes = ...
  if (over.hasBreak != null) out.hasBreak = !!over.hasBreak;
  if (over.breakStart) out.breakStart = String(over.breakStart).trim();
  if (over.breakEnd) out.breakEnd = String(over.breakEnd).trim();
  if (over.breakCountsAsWork != null) out.breakCountsAsWork = !!over.breakCountsAsWork;
  out._fromDaySchedule = true;
  out._dayKey = keySlash;
  return out;
}

/** HH:MM ÛŒØ§ HH:MM:SS â†’ Ø¯Ù‚ÛŒÙ‚Ù‡ Ø§Ø² Ù†ÛŒÙ…Ù‡â€ŒØ´Ø¨ (Û°..Û±Û´Û³Û¹+) */
function timeToMinutes(t) {
  if (t == null || t === '') return null;
  const s = String(t).trim().replace('.', ':');
  const p = s.split(':');
  if (p.length < 2) return null;
  const h = Number(p[0]), m = Number(p[1]);
  if (isNaN(h) || isNaN(m)) return null;
  return h * 60 + m;
}
function minutesToTime(mins) {
  if (mins == null || isNaN(mins)) return '';
  let m = Math.round(Number(mins)) % (24 * 60);
  if (m < 0) m += 24 * 60;
  const h = Math.floor(m / 60), mm = m % 60;
  return String(h).padStart(2, '0') + ':' + String(mm).padStart(2, '0');
}

/** Ù…Ø¯Øª Ø´ÛŒÙØª Ø±Ø³Ù…ÛŒ (Ø¯Ù‚ÛŒÙ‚Ù‡) Ø¨Ø§ Ø§Ø­ØªØ³Ø§Ø¨ ÙˆÙ‚ÙÙ‡ */
function officialWorkMinutes(cal) {
  const sched = normalizeWorkSchedule(cal);
  const a = timeToMinutes(sched.workStart);
  const b = timeToMinutes(sched.workEnd);
  if (a == null || b == null) return 0;
  let total = b - a;
  if (total < 0) total += 24 * 60; // Ø´Ø¨â€ŒÚ©Ø§Ø±
  if (sched.hasBreak && !sched.breakCountsAsWork) {
    const bs = timeToMinutes(sched.breakStart);
    const be = timeToMinutes(sched.breakEnd);
    if (bs != null && be != null) {
      let br = be - bs;
      if (br < 0) br += 24 * 60;
      total = Math.max(0, total - br);
    }
  }
  return total;
}

/**
 * Ù…Ø­Ø§Ø³Ø¨Ù‡ ÛŒÚ© Ø±ÙˆØ² Ú©Ø§Ø±Ú©Ø±Ø¯ Ø§Ø² ÙˆØ±ÙˆØ¯/Ø®Ø±ÙˆØ¬â€ŒÙ‡Ø§
 * punches: [{in:'08:05', out:'12:00'}, {in:'13:00', out:'17:10'}] ÛŒØ§ in1,out1,in2,out2
 * Ù†ØªÛŒØ¬Ù‡: Ø¯Ù‚ÛŒÙ‚Ù‡ Ú©Ø§Ø± Ø®Ø§Ù„ØµØŒ ØªØ£Ø®ÛŒØ±ØŒ ØªØ¹Ø¬ÛŒÙ„ Ø®Ø±ÙˆØ¬ØŒ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±ØŒ Ø´Ù†Ø§ÙˆØ±ÛŒ Ø¬Ø¨Ø±Ø§Ù†â€ŒØ´Ø¯Ù‡
 */

/** Ù‡Ù…Ù¾ÙˆØ´Ø§Ù†ÛŒ Ø¯Ùˆ Ø¨Ø§Ø²Ù‡ Ø¨Ù‡ Ø¯Ù‚ÛŒÙ‚Ù‡ */
function overlapMinutes(a0, a1, b0, b1) {
  const s = Math.max(a0, b0);
  const e = Math.min(a1, b1);
  return Math.max(0, e - s);
}
/** Ø¯Ù‚ÛŒÙ‚Ù‡ Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ Ø¯Ø± Ø¨Ø§Ø²Ù‡ Ø­Ø¶ÙˆØ±: Û²Û²:Û°Û° ØªØ§ Û°Û¶:Û°Û° (Ø±ÙˆØ² Ø¨Ø¹Ø¯) */
function nightMinutesInPair(inn, out) {
  if (inn == null || out == null) return 0;
  let a = inn, b = out;
  if (b < a) b += 24 * 60;
  // Ø´Ø¨: 22:00 (1320) ØªØ§ 24:00 Ùˆ 0 ØªØ§ 6:00 (360) â€” Ø¨Ø±Ø§ÛŒ Ø¨Ø§Ø²Ù‡â€ŒØ§ÛŒ Ú©Ù‡ Ø§Ø² Ù†ÛŒÙ…Ù‡â€ŒØ´Ø¨ Ø±Ø¯ Ù…ÛŒâ€ŒØ´ÙˆØ¯
  let n = 0;
  // Ù‚Ø³Ù…Øª Ø§ÙˆÙ„ Ø±ÙˆØ²: 0..1440
  n += overlapMinutes(a, Math.min(b, 1440), 22 * 60, 24 * 60);
  n += overlapMinutes(a, Math.min(b, 1440), 0, 6 * 60);
  if (b > 1440) {
    const a2 = 0, b2 = b - 1440;
    n += overlapMinutes(a2, b2, 22 * 60, 24 * 60);
    n += overlapMinutes(a2, b2, 0, 6 * 60);
  }
  return n;
}

/**
 * Ù…ØªØ§Ø¯ÛŒØªØ§ÛŒ Ø±ÙˆØ² Ø§Ø² ØªÙ‚ÙˆÛŒÙ…: ØªØ¹Ø·ÛŒÙ„ Ø±Ø³Ù…ÛŒ / ØªØ¹Ø·ÛŒÙ„ Ø´Ø±Ø§ÛŒØ·ÛŒ / Ù†ÛŒÙ…Ù‡â€ŒØ±ÙˆØ²
 * holidaysByYear[year] Ù…ÛŒâ€ŒØªÙˆØ§Ù†Ø¯ Ø±Ø´ØªÙ‡ ØªØ§Ø±ÛŒØ® ÛŒØ§ Ø¢Ø¨Ø¬Ú©Øª Ø¨Ø§Ø´Ø¯
 */

function normalizeHolidayDateStr(s) {
  s = String(s || '').trim().replace(/\//g, '-');
  const m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (!m) return s;
  return m[1] + '-' + String(Number(m[2])).padStart(2,'0') + '-' + String(Number(m[3])).padStart(2,'0');
}
function holidayItemMatchesDay(item, y, m, d) {
  const keyDash = y + '-' + String(m).padStart(2,'0') + '-' + String(d).padStart(2,'0');
  const keySlash = y + '/' + String(m).padStart(2,'0') + '/' + String(d).padStart(2,'0');
  if (item == null) return false;
  if (typeof item === 'string' || typeof item === 'number') {
    const s = normalizeHolidayDateStr(item);
    return s === keyDash || String(item) === keySlash || String(item) === keyDash;
  }
  if (typeof item === 'object') {
    const raw = item.date || item.day || item.d || '';
    const s = normalizeHolidayDateStr(raw);
    return s === keyDash || String(raw).replace(/-/g,'/') === keySlash || String(raw) === keySlash;
  }
  return false;
}

function getDayMeta(obj, y, m, d, contractType) {
  const keyDash = y + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
  const keySlash = y + '/' + String(m).padStart(2, '0') + '/' + String(d).padStart(2, '0');
  const ct = String(contractType || 'normal').trim() || 'normal';
  const cal = getContractCalendar(obj, ct);
  // ÙÙ‚Ø· ØªØ¹Ø·ÛŒÙ„Ø§Øª ØªÙ‚ÙˆÛŒÙ… Ù‡Ù…Ø§Ù† Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ â€” Ù†Ù‡ ØªØ¹Ø·ÛŒÙ„Ø§Øª Ø³Ø±Ø§Ø³Ø±ÛŒ Ù…Ø´ØªØ±Ú©
  const list = (cal.holidaysByYear && (cal.holidaysByYear[String(y)] || cal.holidaysByYear[y])) || [];
  let meta = null;
  (list || []).forEach(function (item) {
    if (!holidayItemMatchesDay(item, y, m, d)) return;
    if (typeof item === 'string' || typeof item === 'number') {
      meta = { date: keySlash, type: 'official', fullDay: true, conditional: false,
        otDuringOfficial: true, otAfterOfficial: true, applyFloat: false };
    } else if (typeof item === 'object') {
      const isCond = !!(item.conditional || item.type === 'conditional');
      const hasHalf = !!(item.closeFrom);
      meta = {
        date: keySlash,
        type: item.type || (isCond ? 'conditional' : 'official'),
        conditional: isCond,
        fullDay: hasHalf ? false : (item.fullDay !== false),
        closeFrom: item.closeFrom || null,
        closeTo: item.closeTo || null,
        otDuringOfficial: item.otDuringOfficial != null ? !!item.otDuringOfficial : true,
        otAfterOfficial: item.otAfterOfficial != null ? !!item.otAfterOfficial : true,
        applyFloat: item.applyFloat != null ? !!item.applyFloat : false,
        reason: item.reason ? String(item.reason).trim() : ''
      };
    }
  });
  // Ø³Ø§Ø¹ØªÛŒ: ÙÙ‚Ø· ØªØ¹Ø·ÛŒÙ„Ø§Øª Ø«Ø¨Øªâ€ŒØ´Ø¯Ù‡ Ø¯Ø± ØªÙ‚ÙˆÛŒÙ… Ø®ÙˆØ¯Ø´ â€” Ø¢Ø®Ø± Ù‡ÙØªÙ‡ Ø¨Ù‡â€ŒØ¹Ù†ÙˆØ§Ù† ØªØ¹Ø·ÛŒÙ„ Ø±Ù†Ú¯ Ù†Ù…ÛŒâ€ŒØ´ÙˆØ¯
  // (Ø­Ø¶ÙˆØ± Ø¯Ø± Ù‡Ø± Ø±ÙˆØ²/Ø³Ø§Ø¹Øª Ù…Ù…Ú©Ù† Ø§Ø³Øª)
  if (ct === 'hourly') {
    return meta;
  }
  const wd = jalaliWeekday(y, m, d);
  const isWeekend = (cal.workWeekDays || []).indexOf(wd) < 0;
  if (!meta && isWeekend) {
    meta = { date: keySlash, type: 'weekend', fullDay: true, conditional: false,
      otDuringOfficial: true, otAfterOfficial: true, applyFloat: false };
  }
  return meta;
}

/** Ù‡Ù…ÛŒØ´Ù‡ HH:MM â€” Ù…Ø«Ù„Ø§Ù‹ 00:00 ÛŒØ§ 08:45 ÛŒØ§ 32:20 */
function formatHoursHM(mins) {
  mins = Math.round(Number(mins) || 0);
  if (mins < 0) mins = 0;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0');
}
function formatHoursHMFromHours(hours) {
  return formatHoursHM(Math.round((Number(hours) || 0) * 60));
}

function computeDayTimesheet(cal, punches, opts) {
  opts = opts || {};
  const isHoliday = !!opts.isHoliday;
  const isHourly = !!(opts.isHourly || opts.contractType === 'hourly' || (cal && cal._contractType === 'hourly'));
  let sched;
  const _gFloat = (cal && cal._globalFloatMinutes != null) ? cal._globalFloatMinutes : (cal && cal.floatMinutes);
  if (opts.daySchedule && typeof opts.daySchedule === 'object') {
    sched = Object.assign({}, normalizeWorkSchedule(cal, _gFloat), opts.daySchedule);
    // Ø´Ù†Ø§ÙˆØ±ÛŒ Ø±ÙˆØ² Ø±Ø§ Ø§Ø² daySchedule Ù†Ù¾Ø°ÛŒØ± (Ù‚ÙÙ„ Û±Ûµ)
    sched.floatMinutes = normalizeWorkSchedule(cal, _gFloat).floatMinutes;
  } else if (opts.year != null && opts.month != null && opts.day != null) {
    sched = getDayWorkSchedule(cal, opts.year, opts.month, opts.day);
  } else if (opts.dateKey) {
    const pp = String(opts.dateKey).replace(/-/g, '/').split('/');
    if (pp.length >= 3) sched = getDayWorkSchedule(cal, Number(pp[0]), Number(pp[1]), Number(pp[2]));
    else sched = normalizeWorkSchedule(cal, _gFloat);
  } else {
    sched = normalizeWorkSchedule(cal, _gFloat);
  }
  const start = timeToMinutes(sched.workStart);
  const end = timeToMinutes(sched.workEnd);
  const dayEnd = timeToMinutes(sched.dayEnd);
  // Ø´Ù†Ø§ÙˆØ±ÛŒ: Ø¨Ø±Ù†Ø§Ù…Ù‡ Ø±ÙˆØ² â†’ ØªÙ‚ÙˆÛŒÙ… Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ â†’ Ø³Ø±Ø§Ø³Ø±ÛŒ (Ù‡Ø±Ú¯Ø² Ø¨Ù‡â€ŒØ®Ø§Ø·Ø± daySchedule Ø±ÙˆÛŒ Û±Ûµ Ù‚ÙÙ„ Ù†Ø´ÙˆØ¯)
  const floatM = isHourly ? 0 : Math.max(0,
    parseFloatMinutesValue(sched.floatMinutes, null) != null ? parseFloatMinutesValue(sched.floatMinutes, null)
      : (parseFloatMinutesValue(cal && cal.floatMinutes, null) != null ? parseFloatMinutesValue(cal && cal.floatMinutes, null)
        : (parseFloatMinutesValue(cal && cal._globalFloatMinutes, null) != null ? parseFloatMinutesValue(cal && cal._globalFloatMinutes, null) : 0))
  );
  const compensate = isHourly ? false : (!!sched.floatCompensate || !!opts.floatCompensate || !!(cal && cal.floatCompensate));
  const official = isHourly ? 0 : officialWorkMinutes(sched);

  // Ù†Ø±Ù…Ø§Ù„â€ŒØ³Ø§Ø²ÛŒ Ù¾Ø§Ù†Ú†â€ŒÙ‡Ø§
  let pairs = [];
  if (Array.isArray(punches)) {
    punches.forEach(function (p) {
      if (!p) return;
      if (p.in != null || p.out != null) {
        pairs.push({ inn: timeToMinutes(p.in), out: timeToMinutes(p.out) });
      }
    });
  } else if (punches && typeof punches === 'object') {
    for (let i = 1; i <= 4; i++) {
      const inn = punches['in' + i], out = punches['out' + i];
      if (inn || out) pairs.push({ inn: timeToMinutes(inn), out: timeToMinutes(out) });
    }
  }
  pairs = pairs.filter(function (p) { return p.inn != null || p.out != null; });
  // ÙÙ‚Ø· Ø¬ÙØª Ú©Ø§Ù…Ù„ (ÙˆØ±ÙˆØ¯+Ø®Ø±ÙˆØ¬) Ø¯Ø± Ú©Ø§Ø±Ú©Ø±Ø¯ Ø´Ù…Ø±Ø¯Ù‡ Ù…ÛŒâ€ŒØ´ÙˆØ¯
  const completePairs = pairs.filter(function (p) { return p.inn != null && p.out != null; });
  const incompletePairs = pairs.filter(function (p) { return p.inn == null || p.out == null; });

  let present = 0;
  completePairs.forEach(function (p) {
    let a = p.inn, b = p.out;
    if (b < a) b += 24 * 60;
    present += Math.max(0, b - a);
  });

  // Ú©Ø³Ø± ÙˆÙ‚ÙÙ‡ ÙÙ‚Ø· Ø§Ú¯Ø± ÙˆÙ‚ÙÙ‡ ÙØ¹Ø§Ù„ Ùˆ Ø¬Ø²Ùˆ Ú©Ø§Ø± Ù†Ø¨Ø§Ø´Ø¯ (Ø¨Ø±Ø§ÛŒ Ø³Ø§Ø¹ØªÛŒ Ø§Ø¹Ù…Ø§Ù„ Ù†Ù…ÛŒâ€ŒØ´ÙˆØ¯)
  if (!isHourly && sched.hasBreak && !sched.breakCountsAsWork) {
    const bs = timeToMinutes(sched.breakStart);
    const be = timeToMinutes(sched.breakEnd);
    if (bs != null && be != null && completePairs.length) {
      let br = be - bs;
      if (br < 0) br += 24 * 60;
      let covers = false;
      completePairs.forEach(function (p) {
        let a = p.inn, b = p.out;
        if (b < a) b += 24 * 60;
        if (a <= bs && b >= be) covers = true;
      });
      if (covers) present = Math.max(0, present - br);
    }
  }

  // â€”â€” Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ø³Ø§Ø¹ØªÛŒ: ÙÙ‚Ø· Ù…Ø¬Ù…ÙˆØ¹ Ø­Ø¶ÙˆØ± Ø¬ÙØªâ€ŒÙ‡Ø§ÛŒ Ú©Ø§Ù…Ù„Ø› Ø¨Ø¯ÙˆÙ† Ù…ÙˆØ¸ÙÛŒ/ØºÛŒØ¨Øª/Ø´Ù†Ø§ÙˆØ±ÛŒ/Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±/Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ â€”â€”
  if (isHourly) {
    function fmtHM_h(mins) { return formatHoursHM(mins); }
    const hasCompleteH = completePairs.length > 0;
    return {
      officialMinutes: 0,
      presentMinutes: Math.round(present),
      delayMinutes: 0,
      earlyLeaveMinutes: 0,
      compensatedMinutes: 0,
      otMinutes: 0,
      shortfallMinutes: 0,
      hourlyAbsenceMinutes: 0,
      hourlyAbsenceHours: 0,
      hourlyAbsenceHM: fmtHM_h(0),
      workHoursHM: fmtHM_h(present),
      floatMinutes: 0,
      floatCompensate: false,
      isHoliday: false,
      hasCompletePair: hasCompleteH,
      withinFloat: true,
      incompletePunch: incompletePairs.length > 0,
      firstIn: null,
      lastOut: null,
      requiredEnd: null,
      workHours: Math.round((present / 60) * 100) / 100,
      otHours: 0,
      otHoursHM: fmtHM_h(0),
      nightMinutes: 0,
      nightHours: 0,
      nightHoursHM: fmtHM_h(0),
      earlyOtMinutes: 0,
      earlyOtHours: 0,
      earlyOtHoursHM: fmtHM_h(0),
      isHourly: true
    };
  }

  const firstIn = completePairs.length
    ? completePairs.map(function (p) { return p.inn; }).sort(function (a, b) { return a - b; })[0]
    : (pairs.map(function (p) { return p.inn; }).filter(function (x) { return x != null; }).sort(function (a, b) { return a - b; })[0] || null);
  const lastOut = completePairs.length
    ? completePairs.map(function (p) { return p.out; }).sort(function (a, b) { return b - a; })[0]
    : null;
  const hasAnyPunch = pairs.length > 0;
  const hasComplete = completePairs.length > 0;

  /**
   * Ø´Ù†Ø§ÙˆØ±ÛŒ (Ø´Ø±ÙˆØ¹ 06:45ØŒ Ù¾Ø§ÛŒØ§Ù† 15:30ØŒ float Ù…Ø«Ù„Ø§Ù‹ Û±ÛµØ¯):
   * 1) ÙˆØ±ÙˆØ¯ 06:48 / Ø®Ø±ÙˆØ¬ 15:30 â†’ Ú©Ø³Ø±ÛŒ ØµØ¨Ø­ 3Ø¯ (Ø¯Ø§Ø®Ù„ Ø´Ù†Ø§ÙˆØ±ÛŒØ› Ø¨Ø¯ÙˆÙ† Ù…Ø§Ù†Ø¯Ù† = Ø¨Ø¯ÙˆÙ† Ø¬Ø¨Ø±Ø§Ù†)
   * 2) ÙˆØ±ÙˆØ¯ 06:45 / Ø®Ø±ÙˆØ¬ 15:20 â†’ Ú©Ø³Ø±ÛŒ Ø¹ØµØ± 10Ø¯
   * 3) ÙˆØ±ÙˆØ¯ 06:50 / Ø®Ø±ÙˆØ¬ 15:20 â†’ Ú©Ø³Ø±ÛŒ ØµØ¨Ø­ 5Ø¯ + Ø¹ØµØ± 10Ø¯
   * 4) ÙˆØ±ÙˆØ¯ 07:01 / Ø®Ø±ÙˆØ¬ 15:30 â†’ Ø®Ø§Ø±Ø¬ Ø´Ù†Ø§ÙˆØ±ÛŒØ› Ú©Ø³Ø±ÛŒ ØµØ¨Ø­ Ú©Ø§Ù…Ù„ 16Ø¯ (Ø¨Ø¯ÙˆÙ† Ø¬Ø¨Ø±Ø§Ù†)
   * 5) ÙˆØ±ÙˆØ¯ 07:01 / Ø®Ø±ÙˆØ¬ 15:20 â†’ Ú©Ø³Ø±ÛŒ ØµØ¨Ø­ 16Ø¯ + Ø¹ØµØ± 10Ø¯
   * 6) ÙˆØ±ÙˆØ¯ 07:08 / Ø®Ø±ÙˆØ¬ 15:40 â†’ Ù…Ø§Ù†Ø¯Ù† Ø¨Ø¹Ø¯ Ø§Ø² Ù¾Ø§ÛŒØ§Ù† ØªØ§ Ø³Ù‚Ù float Ø±ÙˆÛŒ Ú©Ø³Ø±ÛŒ ØµØ¨Ø­ Ù…ÛŒâ€ŒÙ†Ø´ÛŒÙ†Ø¯Ø›
   *    Ù…Ø«Ø§Ù„: Ù…Ø§Ù†Ø¯Ù† 10Ø¯ â†’ 10Ø¯ Ø¬Ø¨Ø±Ø§Ù†ØŒ Ø¨Ø§Ù‚ÛŒ 13Ø¯ Ù…Ø±Ø®ØµÛŒØ› Ù…Ø§Ù†Ø¯Ù† 20Ø¯ â†’ 15Ø¯ Ø¬Ø¨Ø±Ø§Ù† + 5Ø¯ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±ØŒ Ø¨Ø§Ù‚ÛŒ 8Ø¯ Ù…Ø±Ø®ØµÛŒ
   *    ØªÛŒÚ© floatCompensate: Ø¬Ø¨Ø±Ø§Ù† Ø¨Ø¯ÙˆÙ† Ø³Ù‚Ù float (Ú©Ù„ ØªØ£Ø®ÛŒØ± Ø¯Ø± Ø­Ø¯ Ù…Ø§Ù†Ø¯Ù†)
   */
  let delay = 0;          // ØªØ£Ø®ÛŒØ± ÙˆØ±ÙˆØ¯ Ù†Ø³Ø¨Øª Ø¨Ù‡ start (Ù‚Ø¨Ù„ Ø§Ø² Ø¬Ø¨Ø±Ø§Ù†)
  let earlyLeave = 0;     // ØªØ¹Ø¬ÛŒÙ„ Ø®Ø±ÙˆØ¬ Ù†Ø³Ø¨Øª Ø¨Ù‡ end (Ù‚Ø¨Ù„ Ø§Ø² Ø¬Ø¨Ø±Ø§Ù†)
  let compensated = 0;    // Ø¯Ù‚Ø§ÛŒÙ‚ Ø¬Ø¨Ø±Ø§Ù†â€ŒØ´Ø¯Ù‡ Ø¨Ø§ Ù…Ø§Ù†Ø¯Ù† Ø¨Ø¹Ø¯ Ø§Ø² end
  let ot = 0;
  let withinFloat = false;
  let requiredEnd = end;

  if (hasComplete && firstIn != null && start != null) {
    delay = Math.max(0, firstIn - start);
    withinFloat = delay > 0 && delay <= (floatM || 0);
  }
  if (hasComplete && lastOut != null && end != null) {
    earlyLeave = Math.max(0, end - lastOut);
  }

  // Ø¬Ø¨Ø±Ø§Ù† Ø¨Ø§ Ù…Ø§Ù†Ø¯Ù† Ø¨Ø¹Ø¯ Ø§Ø² end:
  // - Ù‡Ù…ÛŒØ´Ù‡ ØªØ§ Ø³Ù‚Ù float Ø¯Ù‚ÛŒÙ‚Ù‡ (Ø­ØªÛŒ Ø§Ú¯Ø± ÙˆØ±ÙˆØ¯ Ø¨Ø¹Ø¯ Ø§Ø² Ù…Ø±Ø² Ø´Ù†Ø§ÙˆØ±ÛŒ Ø¨Ø§Ø´Ø¯) â€” Ù…ÙˆØ±Ø¯ 6
  // - Ø¨Ø§ ØªÛŒÚ© floatCompensate: ØªØ§ Ú©Ù„ ØªØ£Ø®ÛŒØ± (Ø¨Ø¯ÙˆÙ† Ø³Ù‚Ù float)
  if (hasComplete && delay > 0 && lastOut != null && end != null && lastOut > end) {
    const stayedPast = Math.max(0, lastOut - end);
    let maxComp;
    if (compensate) {
      maxComp = delay;
    } else {
      maxComp = Math.min(delay, floatM || 0);
    }
    compensated = Math.min(maxComp, stayedPast);
    delay = Math.max(0, delay - compensated);
    ot = Math.max(0, stayedPast - compensated);
    earlyLeave = 0;
  } else if (hasComplete && lastOut != null && end != null) {
    if (lastOut > end) {
      ot = lastOut - end;
      earlyLeave = 0;
    } else {
      earlyLeave = end - lastOut;
      ot = 0;
    }
  }
  // ØªØ±Ø¯Ø¯ Ù†Ø§Ù‚Øµ Ø¨Ø¯ÙˆÙ† Ø¬ÙØª Ú©Ø§Ù…Ù„: Ú©Ø§Ø±Ú©Ø±Ø¯ ØµÙØ± â€” delay/early Ø¬Ø¯Ø§Ú¯Ø§Ù†Ù‡ Ù…Ø¹Ù†Ø§ Ù†Ø¯Ø§Ø±Ø¯

  // Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ: ÙÙ‚Ø· Û²Û²:Û°Û°â€“Û°Û¶:Û°Û° (Ø¬Ø²Ùˆ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ø¹Ø§Ø¯ÛŒ Ù†ÛŒØ³Øª)
  let nightMin = 0;
  completePairs.forEach(function (p) {
    nightMin += nightMinutesInPair(p.inn, p.out);
  });

  // Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ù‚Ø¨Ù„ Ø§Ø² Ø´Ø±ÙˆØ¹ (Ø§Ø®ØªÛŒØ§Ø±ÛŒ per opts.earlyOtEnabled)
  let earlyOtMin = 0;
  const earlyOtOn = !!opts.earlyOtEnabled;
  if (earlyOtOn && start != null) {
    // Ù¾ÛŒØ´â€ŒÙØ±Ø¶: Ø§Ø² (Ø´Ø±ÙˆØ¹ âˆ’ Û´Û´ Ø¯Ù‚ÛŒÙ‚Ù‡) Ù…Ø«Ù„Ø§Ù‹ Û°Û¶:Û°Û± ØªØ§ Û°Û¶:Û´Ûµ â€” Ù‚Ø§Ø¨Ù„ ØªÙ†Ø¸ÛŒÙ… Ø¨Ø§ earlyOtFrom
    const earlyFrom = (opts.earlyOtFrom != null && !isNaN(Number(opts.earlyOtFrom)))
      ? Number(opts.earlyOtFrom)
      : Math.max(0, start - 44);
    earlyOtMin = 0;
    completePairs.forEach(function (p) {
      let a = p.inn, b = p.out;
      if (a == null || b == null) return;
      if (b < a) b += 24 * 60;
      earlyOtMin += overlapMinutes(a, b, earlyFrom, start);
    });
  }

  // Ø±ÙˆØ² ØªØ¹Ø·ÛŒÙ„/ØºÛŒØ±Ú©Ø§Ø±ÛŒ ÛŒØ§ ØªØ¹Ø·ÛŒÙ„ Ø´Ø±Ø§ÛŒØ·ÛŒ
  let workPresent = present;
  const dayMeta = opts.dayMeta || null;
  const isCondMeta = !!(dayMeta && (dayMeta.conditional || dayMeta.type === 'conditional'));
  // ØªÙ…Ø§Ù…â€ŒØ±ÙˆØ²: Ø´Ø±Ø§ÛŒØ·ÛŒ Ø¨Ø¯ÙˆÙ† closeFrom (ÛŒØ§ fullDay ØµØ±ÛŒØ­)
  const condFull = isCondMeta && !dayMeta.closeFrom && (dayMeta.fullDay !== false);
  const condHalf = isCondMeta && !!dayMeta.closeFrom;
  const forceNoFloat = dayMeta && dayMeta.applyFloat === false;

  // Ø­Ø¶ÙˆØ± ÙÙ‚Ø· Ø¯Ø§Ø®Ù„ Ø¨Ø§Ø²Ù‡ Ù…ÙˆØ¸ÙÛŒ [start, end] â€” Ù…Ø¨Ù†Ø§ÛŒ Ú©Ø§Ø±Ú©Ø±Ø¯ Ùˆ Ú©Ø³Ø±ÛŒ
  // Ø¬Ø¨Ø±Ø§Ù† Ø´Ù†Ø§ÙˆØ±ÛŒ/ØªÛŒÚ© Ø¬Ø¨Ø±Ø§Ù†: Ø¯Ù‚Ø§ÛŒÙ‚ compensated Ø¨Ù‡ Ú©Ø§Ø±Ú©Ø±Ø¯ Ø§Ø¶Ø§ÙÙ‡ Ùˆ Ø§Ø² Ú©Ø³Ø±ÛŒ Ú©Ù… Ù…ÛŒâ€ŒØ´ÙˆØ¯
  // Ø®Ø§Ø±Ø¬ Ø´Ù†Ø§ÙˆØ±ÛŒ Ø¨Ø¯ÙˆÙ† ØªÛŒÚ© Ø¬Ø¨Ø±Ø§Ù†: compensated=0 â†’ Ø´Ú©Ø§Ù ØµØ¨Ø­ + Ø´Ú©Ø§Ù Ø¹ØµØ± Ù‡Ø± Ø¯Ùˆ Ú©Ø³Ø±ÛŒâ€ŒØ§Ù†Ø¯ (Ø¯Ùˆ Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª)
  let presenceInWindow = 0;
  if (start != null && end != null) {
    completePairs.forEach(function (p) {
      let a = p.inn, b = p.out;
      if (a == null || b == null) return;
      if (b < a) b += 24 * 60;
      presenceInWindow += overlapMinutes(a, b, start, end);
    });
    if (sched.hasBreak && !sched.breakCountsAsWork) {
      const bs2 = timeToMinutes(sched.breakStart);
      const be2 = timeToMinutes(sched.breakEnd);
      if (bs2 != null && be2 != null) {
        let br2 = be2 - bs2; if (br2 < 0) br2 += 24 * 60;
        let covers2 = false;
        completePairs.forEach(function (p) {
          let a = p.inn, b = p.out;
          if (a == null || b == null) return;
          if (b < a) b += 24 * 60;
          if (a <= bs2 && b >= be2) covers2 = true;
        });
        if (covers2) presenceInWindow = Math.max(0, presenceInWindow - br2);
      }
    }
  } else {
    presenceInWindow = present;
  }
  // Ú©Ø§Ø±Ú©Ø±Ø¯ Ù…Ø¤Ø«Ø± = Ø­Ø¶ÙˆØ± Ø¯Ø± Ù¾Ù†Ø¬Ø±Ù‡ + Ø¬Ø¨Ø±Ø§Ù† Ù…Ø¹ØªØ¨Ø± (Ù…Ø§Ù†Ø¯Ù† Ø¨Ø¹Ø¯ Ø§Ø² Ù¾Ø§ÛŒØ§Ù† Ú©Ù‡ ØªØ£Ø®ÛŒØ± ØµØ¨Ø­ Ø±Ø§ Ù¾ÙˆØ´Ø§Ù†Ø¯)
  const creditComp = (!isHoliday && !condFull && !opts.unpaidLeave && !opts.fullDayLeaveOrMission)
    ? (compensated || 0) : 0;
  let presentForShort = Math.min(present, presenceInWindow + creditComp);
  // workPresent Ø¨Ø±Ø§ÛŒ Ø±ÙˆØ² Ø¹Ø§Ø¯ÛŒ Ø§Ø² Ù‡Ù…ÛŒÙ† Ù…Ø¨Ù†Ø§ (ØªØ¹Ø·ÛŒÙ„/Ø´Ø±Ø§ÛŒØ·ÛŒ Ù¾Ø§ÛŒÛŒÙ†â€ŒØªØ± Ù…Ù…Ú©Ù† Ø§Ø³Øª Ø¨Ø§Ø²Ù†ÙˆÛŒØ³ÛŒ Ú©Ù†Ù†Ø¯)
  if (!isHoliday && !condFull && !condHalf) {
    workPresent = presentForShort;
  }
  const beyondFloat = hasComplete && firstIn != null && start != null &&
    (firstIn - start) > (floatM || 0) && !compensate;

  // Ø§Ù‚Ù…Ø§Ø±ÛŒ / Ù‡Ù…Ù‡ Ø±ÙˆØ²Ù‡Ø§ÛŒ Ù‡ÙØªÙ‡ Ú©Ø§Ø±ÛŒ: Ø¯Ø± ØªØ¹Ø·ÛŒÙ„ Ø±Ø³Ù…ÛŒ ØªØ§ Ø³Ù‚Ù Ù…ÙˆØ¸ÙÛŒ = Ú©Ø§Ø±Ú©Ø±Ø¯ØŒ ÙÙ‚Ø· Ù…Ø§Ø²Ø§Ø¯ = Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±
  const allWeekWork = Array.isArray(cal && cal.workWeekDays) && cal.workWeekDays.length >= 7;
  if (isHoliday && present > 0 && !(dayMeta && dayMeta.conditional)) {
    if (allWeekWork && official > 0) {
      // Ù…Ø«Ù„ Ø±ÙˆØ² Ø¹Ø§Ø¯ÛŒ: Ú©Ø§Ø±Ú©Ø±Ø¯ ØªØ§ Ù…ÙˆØ¸ÙÛŒØŒ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± ÙÙ‚Ø· Ø¨Ø¹Ø¯ Ø§Ø² Ù¾Ø§ÛŒØ§Ù† Ø´ÛŒÙØª (Ù…Ù†Ù‡Ø§ÛŒ Ø´Ø¨)
      workPresent = Math.min(present, official);
      delay = 0;
      earlyLeave = 0;
      compensated = 0;
      ot = 0;
      if (hasComplete && lastOut != null && end != null && lastOut > end) {
        let stayedH = Math.max(0, lastOut - end);
        const nightInAfterH = nightMinutesInPair(end, lastOut);
        ot = Math.max(0, stayedH - nightInAfterH);
      }
    } else {
      // ØªØ¹Ø·ÛŒÙ„ Ø±Ø³Ù…ÛŒ/Ù‡ÙØªÙ‡ (Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ø¹Ø§Ø¯ÛŒ): ØªÙ…Ø§Ù… Ø­Ø¶ÙˆØ± = Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± (Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ Ø¬Ø¯Ø§)
      ot = Math.max(0, present - nightMin);
      workPresent = 0;
      delay = 0;
      earlyLeave = 0;
      compensated = 0;
    }
  } else if (condFull && present > 0) {
    // ØªØ¹Ø·ÛŒÙ„ Ø´Ø±Ø§ÛŒØ·ÛŒ ØªÙ…Ø§Ù…â€ŒØ±ÙˆØ²
    if (dayMeta.otDuringOfficial) {
      ot = Math.max(0, present - nightMin);
      workPresent = 0;
    } else {
      // ÙÙ‚Ø· Ø¨Ø¹Ø¯ Ø§Ø² Ù…ÙˆØ¸ÙÛŒ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±
      ot = 0;
      workPresent = Math.min(present, official);
      if (dayMeta.otAfterOfficial && lastOut != null && end != null && lastOut > end) {
        ot = Math.max(0, lastOut - end - nightMin); // ØªÙ‚Ø±ÛŒØ¨ÛŒ
      }
    }
    delay = 0;
    earlyLeave = 0;
    compensated = 0;
  } else if (condHalf) {
    // ØªØ¹Ø·ÛŒÙ„ Ø´Ø±Ø§ÛŒØ·ÛŒ Ø§Ø² Ø³Ø§Ø¹Øª closeFrom
    const cf = timeToMinutes(dayMeta.closeFrom);
    if (cf != null) {
      // Ú©Ø§Ø±Ú©Ø±Ø¯ ÙÙ‚Ø· ØªØ§ closeFrom
      let presentUntil = 0;
      completePairs.forEach(function (p) {
        let a = p.inn, b = p.out;
        if (b < a) b += 24 * 60;
        presentUntil += overlapMinutes(a, b, start != null ? start : 0, cf);
      });
      if (sched.hasBreak && !sched.breakCountsAsWork) {
        const bs = timeToMinutes(sched.breakStart);
        const be = timeToMinutes(sched.breakEnd);
        if (bs != null && be != null && bs < cf) {
          presentUntil = Math.max(0, presentUntil - overlapMinutes(bs, be, start, cf));
        }
      }
      workPresent = presentUntil;
      // Ø¨Ø¹Ø¯ Ø§Ø² closeFrom ØªØ§ end (ÛŒØ§ Ø¨Ø¹Ø¯) = Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ø¯Ø± ØµÙˆØ±Øª otAfterOfficial
      let afterClose = 0;
      completePairs.forEach(function (p) {
        let a = p.inn, b = p.out;
        if (b < a) b += 24 * 60;
        afterClose += overlapMinutes(a, b, cf, dayMeta.otAfterOfficial ? (lastOut != null ? Math.max(lastOut, end || cf) : (end || cf + 60)) : cf);
      });
      if (dayMeta.otAfterOfficial) ot = Math.max(0, afterClose - nightMin);
      else ot = 0;
      // Ø¨Ø¯ÙˆÙ† Ø´Ù†Ø§ÙˆØ±ÛŒ
      if (forceNoFloat) {
        delay = 0;
        compensated = 0;
        // ØªØ£Ø®ÛŒØ± ÙˆØ§Ù‚Ø¹ÛŒ Ø§Ú¯Ø± Ø¨Ø¹Ø¯ Ø§Ø² start Ø¢Ù…Ø¯Ù‡ ØªØ§ closeFrom
        if (firstIn != null && start != null && firstIn > start && firstIn < cf) {
          delay = firstIn - start;
        }
        earlyLeave = 0;
      }
    }
  }

  // â”€â”€ Ø¬Ø¯Ø§Ø³Ø§Ø²ÛŒ Ù‚Ø·Ø¹ÛŒ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ùˆ Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ â”€â”€
  // Ù‡Ø± Ø¯Ù‚ÛŒÙ‚Ù‡ Ø­Ø¶ÙˆØ± Ø¯Ø± Û²Û²:Û°Û°â€“Û°Û¶:Û°Û° = Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ (Ù†Ù‡ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±)
  // Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± = Ø­Ø¶ÙˆØ± Ø¨Ø¹Ø¯ Ø§Ø² Ù¾Ø§ÛŒØ§Ù† Ø´ÛŒÙØª Ú©Ù‡ Ø¯Ø§Ø®Ù„ Ø¨Ø§Ø²Ù‡ Ø´Ø¨ Ù†Ø¨Ø§Ø´Ø¯
  nightMin = 0;
  completePairs.forEach(function (p) {
    nightMin += nightMinutesInPair(p.inn, p.out);
  });

  if (hasComplete && lastOut != null && end != null && lastOut > end && !isHoliday && !condFull && !condHalf) {
    // Ø±ÙˆØ² Ø¹Ø§Ø¯ÛŒ: Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± ÙÙ‚Ø· Ø¨Ø¹Ø¯ Ø§Ø² Ù¾Ø§ÛŒØ§Ù† Ø´ÛŒÙØª (Ù…Ù†Ù‡Ø§ÛŒ Ø´Ø¨â€ŒÚ©Ø§Ø±ÛŒ Ùˆ Ø¬Ø¨Ø±Ø§Ù† Ø´Ù†Ø§ÙˆØ±ÛŒ)
    let stayed = Math.max(0, lastOut - end);
    stayed = Math.max(0, stayed - (compensated || 0));
    const nightInAfter = nightMinutesInPair(end, lastOut);
    ot = Math.max(0, stayed - nightInAfter);
  } else if (isHoliday && !condFull && !condHalf && present > 0) {
    // ØªØ¹Ø·ÛŒÙ„ Ø±Ø³Ù…ÛŒ/Ù‡ÙØªÙ‡ (Ù†Ù‡ Ø´Ø±Ø§ÛŒØ·ÛŒ)
    // Ø§Ù‚Ù…Ø§Ø±ÛŒ (Ù‡Ù…Ù‡ Ø±ÙˆØ² Ú©Ø§Ø±ÛŒ): Ú©Ø§Ø±Ú©Ø±Ø¯ ØªØ§ Ù…ÙˆØ¸ÙÛŒ Ø­ÙØ¸ Ø´ÙˆØ¯Ø› ot ÙÙ‚Ø· Ø¨Ø¹Ø¯ Ø§Ø² Ù¾Ø§ÛŒØ§Ù† Ø´ÛŒÙØª (Ø¨Ø§Ù„Ø§ Ù…Ø­Ø§Ø³Ø¨Ù‡ Ø´Ø¯Ù‡)
    if (allWeekWork && official > 0) {
      // ot Ùˆ workPresent Ø§Ø² Ø¨Ù„ÙˆÚ© Ø§ÙˆÙ„ Ø­ÙØ¸ Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯Ø› Ø¨Ø§Ø²Ù†ÙˆÛŒØ³ÛŒ Ù†Ø´ÙˆØ¯
    } else {
      // Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ø¹Ø§Ø¯ÛŒ: Ú©Ù„ Ø­Ø¶ÙˆØ± ØºÛŒØ±Ø´Ø¨ = Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±
      ot = Math.max(0, present - nightMin);
      workPresent = 0;
    }
  }
  // condFull / condHalf: Ù…Ù‚Ø¯Ø§Ø± ot Ø§Ø² Ø¨Ù„ÙˆÚ© Ø¨Ø§Ù„Ø§ØªØ± Ø­ÙØ¸ Ù…ÛŒâ€ŒØ´ÙˆØ¯
  ot = Math.max(0, ot || 0);

  // Ø¯Ø± ØªØ¹Ø·ÛŒÙ„ Ø´Ø±Ø§ÛŒØ·ÛŒ Ø§Ú¯Ø± Â«Ø­Ø¶ÙˆØ± Ø¯Ø± Ù…ÙˆØ¸ÙÛŒ = Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±Â» Ø®Ø§Ù…ÙˆØ´ Ø¨Ø§Ø´Ø¯ØŒ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ù‚Ø¨Ù„ Ø§Ø² Ø´Ø±ÙˆØ¹ Ù‡Ù… ØµÙØ±
  if (condFull && dayMeta && dayMeta.otDuringOfficial === false) {
    earlyOtMin = 0;
  }
  if (condHalf && dayMeta && dayMeta.otAfterOfficial === false && dayMeta.otDuringOfficial === false) {
    earlyOtMin = 0;
  }
  // early OT Ø¬Ø¯Ø§ Ø§Ø² ot Ù†Ú¯Ù‡ Ø¯Ø§Ø´ØªÙ‡ Ù…ÛŒâ€ŒØ´ÙˆØ¯ (earlyOtMin)


  // ØºÛŒØ¨Øª Ø³Ø§Ø¹ØªÛŒ:
  // - Ø±ÙˆØ² Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø±ÙˆØ²Ø§Ù†Ù‡ (ØºÛŒØ± Ø¨Ø¯ÙˆÙ†â€ŒØ­Ù‚ÙˆÙ‚) â†’ ØµÙØ±
  // - Ù…Ø±Ø®ØµÛŒ Ø¨Ø¯ÙˆÙ† Ø­Ù‚ÙˆÙ‚ â†’ Ú©Ù„ Ù…ÙˆØ¸ÙÛŒ
  // - Ø±ÙˆØ² Ø¹Ø§Ø¯ÛŒ â†’ Ú©Ù…Ø¨ÙˆØ¯ Ù¾Ø³ Ø§Ø² Ø­Ø¶ÙˆØ± + Ù¾ÙˆØ´Ø´ Ø³Ø§Ø¹ØªÛŒ
  let covered = Number(opts.coveredMinutes) || 0;
  // ÙÙ‚Ø· Ø¨Ø®Ø´ÛŒ Ø§Ø² Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø³Ø§Ø¹ØªÛŒ Ú©Ù‡ Ø±ÙˆÛŒ Â«ØºÛŒØ¨Øª ÙˆØ§Ù‚Ø¹ÛŒÂ» Ø¯Ø§Ø®Ù„ [Ø´Ø±ÙˆØ¹ØŒ Ù¾Ø§ÛŒØ§Ù†] Ù…ÛŒâ€ŒØ§ÙØªØ¯ Ù¾ÙˆØ´Ø´ Ø­Ø³Ø§Ø¨ Ù…ÛŒâ€ŒØ´ÙˆØ¯
  // (Ø¨Ø§Ø²Ù‡ ØªÚ©Ø±Ø§Ø±ÛŒ/Ù‡Ù…â€ŒÙ¾ÙˆØ´Ø§Ù† ÛŒØ§ Ø¨Ø§Ø²Ù‡â€ŒØ§ÛŒ Ú©Ù‡ ÙØ±Ø¯ Ø­Ø§Ø¶Ø± Ø¨ÙˆØ¯Ù‡ØŒ Ú©Ø³Ø±ÛŒ Ø±Ø§ Ù¾Ø± Ù†Ù…ÛŒâ€ŒÚ©Ù†Ø¯)
  if (Array.isArray(opts.coveredIntervals) && !isHoliday && !(dayMeta && dayMeta.closeFrom) && start != null && end != null) {
    const presMerged = [];
    completePairs.map(function (p) { let a0 = p.inn, b0 = p.out; if (b0 < a0) b0 += 24 * 60; return [a0, b0]; })
      .sort(function (x, y) { return x[0] - y[0]; })
      .forEach(function (p) {
        if (presMerged.length && p[0] <= presMerged[presMerged.length - 1][1]) presMerged[presMerged.length - 1][1] = Math.max(presMerged[presMerged.length - 1][1], p[1]);
        else presMerged.push([p[0], p[1]]);
      });
    let eff = 0;
    const mergedCov = [];
    opts.coveredIntervals.slice().sort(function (x, y) { return x[0] - y[0]; }).forEach(function (iv) {
      if (mergedCov.length && iv[0] <= mergedCov[mergedCov.length - 1][1]) mergedCov[mergedCov.length - 1][1] = Math.max(mergedCov[mergedCov.length - 1][1], iv[1]);
      else mergedCov.push([iv[0], iv[1]]);
    });
    mergedCov.forEach(function (iv) {
      const c0 = Math.max(iv[0], start), c1 = Math.min(iv[1], end);
      if (c1 <= c0) return;
      let m = c1 - c0;
      presMerged.forEach(function (p) { m -= overlapMinutes(c0, c1, p[0], p[1]); });
      eff += Math.max(0, m);
    });
    covered = eff;
  }
  let shortfall = 0;
  const holidayFull = isHoliday || (dayMeta && dayMeta.fullDay && (dayMeta.conditional || dayMeta.type === 'conditional' || dayMeta.type === 'official' || dayMeta.type === 'weekend'));
  // Ø§Ù‚Ù…Ø§Ø±ÛŒ (Ù‡Ù…Ù‡ Ø±ÙˆØ² Ú©Ø§Ø±ÛŒ): ØªØ¹Ø·ÛŒÙ„ Ø±Ø³Ù…ÛŒ Ù‡Ù… Ø±ÙˆØ² Ù…ÙˆØ¸ÙÛŒ Ø§Ø³Øª â†’ Ø¨Ø¯ÙˆÙ† Ø­Ø¶ÙˆØ±/Ù¾ÙˆØ´Ø´ = ØºÛŒØ¨Øª
  // ÙÙ‚Ø· ØªØ¹Ø·ÛŒÙ„ Ø´Ø±Ø§ÛŒØ·ÛŒ (ÛŒØ§ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ ØºÛŒØ± Ø§Ù‚Ù…Ø§Ø±ÛŒ) shortfall Ø±Ø§ ØµÙØ± Ù…ÛŒâ€ŒÚ©Ù†Ø¯
  const aqmariDutyHoliday = allWeekWork && official > 0 && isHoliday
    && !(dayMeta && (dayMeta.conditional || dayMeta.type === 'conditional'));
  if (holidayFull && !aqmariDutyHoliday) {
    shortfall = 0;
  } else if (condHalf && dayMeta && dayMeta.closeFrom) {
    // Ù…ÙˆØ¸ÙÛŒ ÙÙ‚Ø· ØªØ§ Ø³Ø§Ø¹Øª ØªØ¹Ø·ÛŒÙ„ Ø´Ø±Ø§ÛŒØ·ÛŒ
    const cf = timeToMinutes(dayMeta.closeFrom);
    let officialHalf = (cf != null && start != null && cf > start) ? (cf - start) : official;
    if (sched.hasBreak && !sched.breakCountsAsWork) {
      const bs = timeToMinutes(sched.breakStart);
      const be = timeToMinutes(sched.breakEnd);
      if (bs != null && be != null && cf != null && bs < cf) {
        officialHalf = Math.max(0, officialHalf - Math.max(0, Math.min(be, cf) - bs));
      }
    }
    shortfall = Math.max(0, officialHalf - workPresent - covered);
  } else if (opts.unpaidLeave) {
    shortfall = official;
  } else if (opts.fullDayLeaveOrMission) {
    shortfall = 0;
  } else {
    // Ú©Ø³Ø±ÛŒ = Ù…ÙˆØ¸ÙÛŒ âˆ’ (Ø­Ø¶ÙˆØ± Ø¯Ø± Ù¾Ù†Ø¬Ø±Ù‡ + Ø¬Ø¨Ø±Ø§Ù† Ù…Ø¹ØªØ¨Ø±) âˆ’ Ù¾ÙˆØ´Ø´ Ø³Ø§Ø¹ØªÛŒ
    // Ù…Ø«Ø§Ù„ Ø¨Ø¯ÙˆÙ† Ø¬Ø¨Ø±Ø§Ù†: ÙˆØ±ÙˆØ¯ Û°Û·:Û°Û± Ø®Ø±ÙˆØ¬ Û±Ûµ:Û²Ûµ â†’ Ø­Ø¶ÙˆØ±â€ŒÙ¾Ù†Ø¬Ø±Ù‡ ÛµÛ°Û´ØŒ Ú©Ø³Ø±ÛŒ Û²Û± (Û±Û¶ ØµØ¨Ø­ + Ûµ Ø¹ØµØ±)
    // Ù…Ø«Ø§Ù„ Ø¨Ø§ Ø¬Ø¨Ø±Ø§Ù†: ÙˆØ±ÙˆØ¯ Û°Û·:Û±Ûµ Ø®Ø±ÙˆØ¬ Û±Û¶:Û°Û° â†’ Ø­Ø¶ÙˆØ±â€ŒÙ¾Ù†Ø¬Ø±Ù‡ Û´Û¹Ûµ + Ø¬Ø¨Ø±Ø§Ù† Û³Û° = ÛµÛ²ÛµØŒ Ú©Ø³Ø±ÛŒ Û°
    shortfall = Math.max(0, official - presentForShort - covered);
  }

  // Ú©Ø§Ø±Ú©Ø±Ø¯ Ù†Ù…Ø§ÛŒØ´ÛŒ: Ø­Ø¶ÙˆØ± + Ù¾ÙˆØ´Ø´ Ø³Ø§Ø¹ØªÛŒ (ØªØ§ Ø³Ù‚Ù Ù…ÙˆØ¸ÙÛŒ) â€” ÙˆÙ‚ØªÛŒ Ú©Ø³Ø±ÛŒ Ù¾Ø± Ø´Ø¯ = Ù…ÙˆØ¸ÙÛŒ Ú©Ø§Ù…Ù„
  // Ø§Ù‚Ù…Ø§Ø±ÛŒ Ø¯Ø± ØªØ¹Ø·ÛŒÙ„: workPresent Ø§Ø² Ù‚Ø¨Ù„ ØªØ§ Ù…ÙˆØ¸ÙÛŒ Ù¾Ø± Ø´Ø¯Ù‡ â€” Ù†Ù…Ø§ÛŒØ´ Ø´ÙˆØ¯
  let displayWorkMin = workPresent + ((isHoliday && !(allWeekWork && official > 0)) ? 0 : covered);
  if ((!isHoliday || (allWeekWork && official > 0)) && !opts.unpaidLeave) {
    if (opts.fullDayLeaveOrMission) displayWorkMin = official;
    else displayWorkMin = Math.min(official, displayWorkMin);
  }
  // ÙØ±Ù…Øª Ø³Ø§Ø¹Øª: Ø¯Ù‚ÛŒÙ‚Ù‡ â†’ Â«Ø³Ø§Ø¹Øª:Ø¯Ù‚ÛŒÙ‚Ù‡Â» Ù…Ø«Ù„Ø§Ù‹ 8:45
  function fmtHM(mins) {
    return formatHoursHM(mins);
  }

  // ØªØ¬Ù…ÛŒØ¹ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ù‚Ø¨Ù„ Ø¨Ø§ Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø± Ù…Ø¹Ù…ÙˆÙ„
  const otTotal = Math.round((ot || 0) + (earlyOtMin || 0));
  return {
    officialMinutes: official,
    presentMinutes: Math.round(present),
    delayMinutes: Math.round(delay),
    earlyLeaveMinutes: Math.round(earlyLeave),
    compensatedMinutes: Math.round(compensated),
    otMinutes: otTotal,
    shortfallMinutes: Math.round(shortfall),
    hourlyAbsenceMinutes: Math.round(shortfall),
    hourlyAbsenceHours: Math.round((shortfall / 60) * 100) / 100,
    hourlyAbsenceHM: fmtHM(shortfall),
    workHoursHM: fmtHM(displayWorkMin),
    floatMinutes: floatM,
    floatCompensate: compensate,
    isHoliday: isHoliday,
    hasCompletePair: hasComplete,
    withinFloat: withinFloat,
    incompletePunch: incompletePairs.length > 0,
    firstIn: firstIn != null ? minutesToTime(firstIn) : null,
    lastOut: lastOut != null ? minutesToTime(lastOut) : null,
    requiredEnd: requiredEnd != null ? minutesToTime(requiredEnd) : null,
    workHours: Math.round((displayWorkMin / 60) * 100) / 100,
    otHours: Math.round((otTotal / 60) * 100) / 100,
    otHoursHM: fmtHM(otTotal),
    nightMinutes: Math.round(nightMin || 0),
    nightHours: Math.round(((nightMin || 0) / 60) * 100) / 100,
    nightHoursHM: fmtHM(nightMin || 0),
    earlyOtMinutes: Math.round(earlyOtMin || 0),
    earlyOtHours: Math.round(((earlyOtMin || 0) / 60) * 100) / 100,
    earlyOtHoursHM: fmtHM(earlyOtMin || 0)
  };
}


function getHolidaySet(obj, year, contractType) {
  const cal = getContractCalendar(obj, contractType);
  const list = cal.holidaysByYear[String(year)] || cal.holidaysByYear[year] || [];
  const set = {};
  (list || []).forEach(function (d) {
    if (d && typeof d === 'object') {
      const k = String(d.date || d.day || '').replace(/\//g, '-');
      if (k) { set[k] = true; set[String(d.date || d.day)] = true; }
    } else {
      const k = String(d).replace(/\//g, '-');
      set[k] = true;
      set[String(d)] = true;
    }
  });
  return set;
}

function isHolidayOrNonWork(obj, y, m, d, contractType) {
  // ÙÙ‚Ø· ØªÙ‚ÙˆÛŒÙ… Ù‡Ù…Ø§Ù† Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ Ú©Ø§Ø±Ù…Ù†Ø¯ â€” Ù†Ù‡ ØªÙ‚ÙˆÛŒÙ… Ø§Ù†ÙˆØ§Ø¹ Ø¯ÛŒÚ¯Ø±
  // (Ù‚Ø¨Ù„Ø§Ù‹ Ø§Ú¯Ø± Ù‡Ø± Ù†ÙˆØ¹ÛŒ Ù¾Ù†Ø¬Ø´Ù†Ø¨Ù‡/Ø¬Ù…Ø¹Ù‡ ØªØ¹Ø·ÛŒÙ„ Ø¨ÙˆØ¯ØŒ Ø¨Ø±Ø§ÛŒ Ù‡Ù…Ù‡ ØºÛŒØ¨Øª ØµÙØ± Ù…ÛŒâ€ŒØ´Ø¯)
  function metaIsFullHoliday(meta) {
    if (!meta) return false;
    if (meta.conditional && meta.fullDay === false) return false;
    return true;
  }
  return metaIsFullHoliday(getDayMeta(obj, y, m, d, contractType));
}

function getWorkWeekSettings(obj, contractType) {
  const cal = getContractCalendar(obj, contractType);
  return {
    workWeekDays: cal.workWeekDays,
    countNonWorkDaysAsLeave: cal.countNonWorkDaysAsLeave,
    nonWorkLeaveTypeIds: Array.isArray(cal.nonWorkLeaveTypeIds) ? cal.nonWorkLeaveTypeIds.map(String) : []
  };
}
function isLeaveTypeAllowedOnNonWork(obj, contractType, typeId, typeName) {
  const ws = getWorkWeekSettings(obj, contractType);
  if (ws.countNonWorkDaysAsLeave) return true;
  const ids = ws.nonWorkLeaveTypeIds || [];
  if (!ids.length) return false;
  const id = String(typeId || '').trim();
  const nm = String(typeName || '').trim();
  for (let i = 0; i < ids.length; i++) {
    const a = String(ids[i] || '').trim();
    if (!a) continue;
    if (a === id || (nm && a === nm)) return true;
  }
  return false;
}

function listNonWorkDaysInRange(obj, startStr, endStr, contractType) {
  if (typeof listDayKeys !== 'function') return [];
  const keys = listDayKeys(startStr, endStr || startStr);
  const out = [];
  keys.forEach(function (k) {
    const parts = String(k).split(/[-\/]/);
    if (parts.length < 3) return;
    const yy = Number(parts[0]), mm = Number(parts[1]), dd = Number(parts[2]);
    if (isHolidayOrNonWork(obj, yy, mm, dd, contractType)) {
      out.push(yy + '/' + String(mm).padStart(2, '0') + '/' + String(dd).padStart(2, '0'));
    }
  });
  return out;
}


/** ØªØ¹Ø¯Ø§Ø¯ Ø±ÙˆØ²Ù‡Ø§ÛŒ Ú©Ø§Ø±ÛŒ (ØºÛŒØ±ØªØ¹Ø·ÛŒÙ„) Ø¯Ø± Ø¨Ø§Ø²Ù‡ØŒ Ù…Ø­Ø¯ÙˆØ¯ Ø¨Ù‡ ÛŒÚ© Ù…Ø§Ù‡ */
function countWorkingDaysInMonth(startStr, endStr, year, month, obj, contractType) {
  if (typeof listDayKeys !== 'function') return 0;
  const keys = listDayKeys(startStr, endStr || startStr);
  const ct = contractType || 'normal';
  let n = 0;
  keys.forEach(function (k) {
    const parts = String(k).split(/[-\/]/);
    if (parts.length < 3) return;
    const yy = Number(parts[0]), mm = Number(parts[1]), dd = Number(parts[2]);
    if (year != null && yy !== Number(year)) return;
    if (month != null && mm !== Number(month)) return;
    if (isHolidayOrNonWork(obj, yy, mm, dd, ct)) return;
    n++;
  });
  return n;
}

/** Ù‡Ù…Ù‡ Ø±ÙˆØ²Ù‡Ø§ÛŒ ØªÙ‚ÙˆÛŒÙ…ÛŒ Ø¯Ø± Ø¨Ø§Ø²Ù‡ (Ø¨Ø§ ØªØ¹Ø·ÛŒÙ„) â€” Ø¨Ø±Ø§ÛŒ Ù…Ø£Ù…ÙˆØ±ÛŒØª */
function countAllDaysInMonth(startStr, endStr, year, month) {
  if (typeof listDayKeys !== 'function') return 0;
  const keys = listDayKeys(startStr, endStr || startStr);
  let n = 0;
  keys.forEach(function (k) {
    const parts = String(k).split(/[-\/]/);
    if (parts.length < 3) return;
    const yy = Number(parts[0]), mm = Number(parts[1]);
    if (year != null && yy !== Number(year)) return;
    if (month != null && mm !== Number(month)) return;
    n++;
  });
  return n;
}

function lastActivityDayInMonth(dayMap) {
  let last = 0;
  Object.keys(dayMap || {}).forEach(function (k) {
    const c = dayMap[k];
    if (!c) return;
    const has = !!(c.in1 || c.out1 || c.in2 || c.out2 || c.in3 || c.out3 || c.in4 || c.out4 || c.leaveDaily || c.missionDaily || c.leaveHourly || c.missionHourly);
    if (has && Number(c.day) > last) last = Number(c.day);
  });
  return last;
}

function computeWorkDaysFromMap(dayMap) {
  const last = lastActivityDayInMonth(dayMap);
  if (!last) return 0;
  let n = 0;
  Object.keys(dayMap).forEach(function (k) {
    const c = dayMap[k];
    if (!c || Number(c.day) > last) return;
    if (c.isNonWork) return;
    const hasPunch = !!(c.in1 || c.out1 || c.in2 || c.out2 || c.in3 || c.out3 || c.in4 || c.out4);
    const hasLeaveMis = !!(c.leaveDaily || c.missionDaily || c.leaveHourly || c.missionHourly);
    if (hasPunch || hasLeaveMis) n++;
  });
  return n;
}

/** Ú©Ø§Ø±Ú©Ø±Ø¯ Ù…Ø§Ù‡ = Ø±ÙˆØ²Ù‡Ø§ÛŒ Ø¹Ø§Ø¯ÛŒ ØªØ§ Ø¢Ø®Ø±ÛŒÙ† Ù¾Ø§Ù†Ú†/Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª */
/** ØªØ´Ø®ÛŒØµ Ù…Ø±Ø®ØµÛŒ Ø¨Ø¯ÙˆÙ† Ø­Ù‚ÙˆÙ‚ Ø§Ø² Ø±ÙˆÛŒ Ù†ÙˆØ¹/Ù†Ø§Ù… */

/** Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø³Ø§Ø¹ØªÛŒ ÙÙ‚Ø· Ø¯Ø§Ø®Ù„ Ø¨Ø§Ø²Ù‡ Ù…ÙˆØ¸ÙÛŒ (Ù…Ø«Ù„Ø§Ù‹ 06:45â€“15:30) */

/** ÙˆØ±ÙˆØ¯/Ø®Ø±ÙˆØ¬ Ù†Ø§Ù‚Øµ: ÙˆØ±ÙˆØ¯ Ø¨Ø¯ÙˆÙ† Ø®Ø±ÙˆØ¬ ÛŒØ§ Ø®Ø±ÙˆØ¬ Ø¨Ø¯ÙˆÙ† ÙˆØ±ÙˆØ¯ */
function punchPairIncomplete(inn, out) {
  const a = String(inn || '').trim();
  const b = String(out || '').trim();
  if (!a && !b) return false;
  if (a && !b) return true;
  if (!a && b) return true;
  return false;
}
function punchIncompleteFlags(p) {
  p = p || {};
  const o = {};
  for (let i = 1; i <= 4; i++) {
    const bad = punchPairIncomplete(p['in' + i], p['out' + i]);
    o['in' + i] = bad;
    o['out' + i] = bad;
  }
  return o;
}
function minutesToHHMM(m) {
  if (m == null || isNaN(m)) return '';
  m = Math.round(m);
  if (m < 0) m = 0;
  const h = Math.floor(m / 60) % 24;
  const mm = m % 60;
  return String(h).padStart(2, '0') + ':' + String(mm).padStart(2, '0');
}

function assertHourlyWithinShift(obj, emp, fromTime, toTime) {
  const cal = getContractCalendar(obj, (emp && emp.contractType) || 'normal');
  const sched = normalizeWorkSchedule(cal);
  const start = timeToMinutes(sched.workStart);
  const end = timeToMinutes(sched.workEnd);
  const a = timeToMinutes(fromTime);
  const b = timeToMinutes(toTime);
  if (start == null || end == null) {
    return { ok: false, message: 'Ø³Ø§Ø¹Øª Ù…ÙˆØ¸ÙÛŒ Ø¨Ø±Ø§ÛŒ Ù†ÙˆØ¹ Ù‚Ø±Ø§Ø±Ø¯Ø§Ø¯ ØªØ¹Ø±ÛŒÙ Ù†Ø´Ø¯Ù‡ Ø§Ø³Øª.' };
  }
  if (a == null || b == null) {
    return { ok: false, message: 'Ø³Ø§Ø¹Øª Ø´Ø±ÙˆØ¹/Ù¾Ø§ÛŒØ§Ù† Ù†Ø§Ù…Ø¹ØªØ¨Ø± Ø§Ø³Øª.' };
  }
  if (b <= a) {
    return { ok: false, message: 'Ø³Ø§Ø¹Øª Ù¾Ø§ÛŒØ§Ù† Ø¨Ø§ÛŒØ¯ Ø¨Ø¹Ø¯ Ø§Ø² Ø³Ø§Ø¹Øª Ø´Ø±ÙˆØ¹ Ø¨Ø§Ø´Ø¯.' };
  }
  if (a < start || b > end) {
    return {
      ok: false,
      message: 'Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø³Ø§Ø¹ØªÛŒ ÙÙ‚Ø· Ø¯Ø§Ø®Ù„ Ø³Ø§Ø¹Øª Ù…ÙˆØ¸ÙÛŒ (' + (sched.workStart || '') + ' ØªØ§ ' + (sched.workEnd || '') + ') Ù…Ø¬Ø§Ø² Ø§Ø³Øª Ùˆ Ù†Ù…ÛŒâ€ŒØªÙˆØ§Ù†Ø¯ Ù‚Ø¨Ù„ ÛŒØ§ Ø¨Ø¹Ø¯ Ø§Ø² Ø¢Ù† Ø¨Ø§Ø´Ø¯.'
    };
  }
  return { ok: true, workStart: sched.workStart, workEnd: sched.workEnd };
}

function isUnpaidLeaveRequest(obj, req) {
  if (!req || req.kind !== 'leave') return false;
  if (req.unpaid === true || req.isUnpaid === true) return true;
  const id = String(req.typeId || '').toLowerCase();
  const name = String(req.typeName || '');
  if (id.indexOf('unpaid') >= 0 || id.indexOf('without_pay') >= 0 || id.indexOf('no_pay') >= 0) return true;
  if (name.indexOf('Ø¨Ø¯ÙˆÙ† Ø­Ù‚ÙˆÙ‚') >= 0 || name.indexOf('Ø¨Ø¯ÙˆÙ†â€ŒØ­Ù‚ÙˆÙ‚') >= 0) return true;
  // Ø§Ø² ØªØ¹Ø±ÛŒÙ Ø§Ù†ÙˆØ§Ø¹ Ø¯Ø± settings
  try {
    const types = (obj && obj.settings && obj.settings.attendanceTypes) || [];
    const t = types.find(function (x) { return String(x.id) === String(req.typeId); });
    if (t && (t.unpaid === true || t.isUnpaid === true || String(t.name || '').indexOf('Ø¨Ø¯ÙˆÙ† Ø­Ù‚ÙˆÙ‚') >= 0)) return true;
  } catch (e) {}
  return false;
}

function isRestOrNonLeaveColumnType(obj, req) {
  if (!req) return false;
  function hasRestWord(s) {
    s = String(s || '');
    // Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ / Ø§Ø³ØªØ¹Ù„Ø§Ø¬ÛŒ / Ø¨Ø¯ÙˆÙ†â€ŒØ­Ù‚ÙˆÙ‚ Ù‡Ø±Ú¯Ø² Â«Ø±Ø³ØªÂ» Ù†ÛŒØ³Øª
    if (s.indexOf('Ø§Ø³ØªØ­Ù‚Ø§Ù‚') >= 0) return false;
    if (s.indexOf('Ø§Ø³ØªØ¹Ù„Ø§Ø¬') >= 0) return false;
    if (s.indexOf('Ø¨Ø¯ÙˆÙ† Ø­Ù‚ÙˆÙ‚') >= 0 || s.indexOf('Ø¨Ø¯ÙˆÙ†â€ŒØ­Ù‚ÙˆÙ‚') >= 0) return false;
    return s.indexOf('Ø±Ø³Øª') >= 0 || /\brest\b/i.test(s);
  }
  // Ú©Ø³Ø± Ø§Ø² Ø§Ø³ØªØ­Ù‚Ø§Ù‚ â†’ Ø³ØªÙˆÙ† Ù…Ø±Ø®ØµÛŒ
  if (req.deductFromEntitlement === true) return false;
  const name = String(req.typeName || req.type || req.name || '');
  const id = String(req.typeId || '').toLowerCase();
  if (name.indexOf('Ø§Ø³ØªØ­Ù‚Ø§Ù‚') >= 0 || id.indexOf('leave_annual') >= 0 || id === 'annual') return false;
  if (hasRestWord(name) || hasRestWord(id)) return true;
  try {
    const types = [].concat((obj && obj.settings && obj.settings.attendanceTypes) || [], (obj && obj.attendanceTypes) || []);
    // ÙÙ‚Ø· ØªØ·Ø¨ÛŒÙ‚ id ÛŒØ§ Ù†Ø§Ù… Ø¯Ù‚ÛŒÙ‚ â€” Ù†Ø¨Ø§ÛŒØ¯ Â«Ù‡Ø± Ù†ÙˆØ¹ Ø±Ø³ØªÂ» Ø¯Ø± Ù„ÛŒØ³Øª Ø¨Ø§Ø¹Ø« match Ø´ÙˆØ¯
    const t = types.find(function (x) {
      if (!x) return false;
      if (req.typeId && String(x.id) === String(req.typeId)) return true;
      if (name && String(x.name || '') === name) return true;
      return false;
    });
    if (t) {
      const tn = String(t.name || '');
      // Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ / Ú©Ø³Ø± Ø§Ø² Ù…Ø§Ù†Ø¯Ù‡ Ù‡Ø±Ú¯Ø² Ø±Ø³Øª Ù†ÛŒØ³Øª
      if (tn.indexOf('Ø§Ø³ØªØ­Ù‚Ø§Ù‚') >= 0 || tn.indexOf('Ù…Ø±Ø®Øµ') >= 0 || t.deductFromEntitlement === true) return false;
      // ÙÙ‚Ø· Ù†Ø§Ù…/Ø´Ù†Ø§Ø³Ù‡ Ú©Ù‡ ØµØ±ÛŒØ­Ø§Ù‹ Â«Ø±Ø³ØªÂ» Ø¯Ø§Ø±Ø¯
      if (hasRestWord(t.name) || hasRestWord(t.id)) return true;
      // excludeFromLeaveDays Ø¨Ù‡â€ŒØªÙ†Ù‡Ø§ÛŒÛŒ ÛŒØ¹Ù†ÛŒ Â«Ø±Ø³ØªÂ» Ù†ÛŒØ³Øª â€” Ø¯ÛŒÚ¯Ø± Ø±Ø³Øª Ø­Ø³Ø§Ø¨ Ù†Ú©Ù†
    }
  } catch (e) {}
  return false;
}


function enrichLeaveRequestFromTypes(obj, x) {
  if (!x) return x;
  try {
    var types = [].concat((obj && obj.attendanceTypes) || [], (obj && obj.settings && obj.settings.attendanceTypes) || []);
    var td = null;
    if (x.typeId) td = types.find(function (t) { return t && String(t.id) === String(x.typeId); });
    if (!td && (x.typeName || x.type || x.name)) {
      var nm0 = String(x.typeName || x.type || x.name || '');
      td = types.find(function (t) { return t && String(t.name || '') === nm0; });
    }
    if (!td) return x;
    var out = Object.assign({}, x);
    if (!out.typeName) out.typeName = td.name || '';
    if (out.deductFromEntitlement == null && td.deductFromEntitlement != null) out.deductFromEntitlement = td.deductFromEntitlement;
    return out;
  } catch (e) { return x; }
}

function shouldSkipLeaveDaysColumn(obj, req) {
  if (!req || req.kind !== 'leave') return false;
  var nm = String(req.typeName || req.type || req.name || '');
  var tid = String(req.typeId || '').toLowerCase();
  var tdef = null;
  try {
    var types = [].concat((obj && obj.attendanceTypes) || [], (obj && obj.settings && obj.settings.attendanceTypes) || []);
    tdef = types.find(function (x) { return x && (String(x.id) === String(req.typeId) || (nm && String(x.name || '') === nm)); }) || null;
  } catch (eT) {}
  if (tdef && !nm) nm = String(tdef.name || '');
  // Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ â†’ Ø³ØªÙˆÙ† leaveDays
  if (nm.indexOf('Ø§Ø³ØªØ­Ù‚Ø§Ù‚') >= 0) return false;
  if (req.deductFromEntitlement === true) return false;
  if (tdef && tdef.deductFromEntitlement === true) return false;
  if (tid.indexOf('leave_annual') >= 0 || tid === 'annual') return false;
  if (tdef && /leave_annual|annual/i.test(String(tdef.id || ''))) return false;
  // ØºÛŒØ± Ø§Ø³ØªØ­Ù‚Ø§Ù‚ÛŒ â†’ Ø³ØªÙˆÙ† qty Ø¬Ø¯Ø§ (Ø§Ø²Ø¯ÙˆØ§Ø¬ØŒ ØªÙˆÙ„Ø¯ØŒ ÙÙˆØªØŒ â€¦)
  if (req.deductFromEntitlement === false) return true;
  if (tdef && tdef.deductFromEntitlement === false) return true;
  if (/Ø§Ø²Ø¯ÙˆØ§Ø¬|ØªÙˆÙ„Ø¯|ÙÙˆØª|Ø¨Ø¯ÙˆÙ†\s*Ø­Ù‚ÙˆÙ‚|Ø§Ø³ØªØ¹Ù„Ø§Ø¬|Ø®Ø§Øµ|marriage|birth|death|unpaid|sick/i.test(nm)) return true;
  if (/leave_marriage|leave_birth|leave_death|leave_unpaid|leave_special|leave_sick/i.test(tid)) return true;
  if (isUnpaidLeaveRequest(obj, req)) return true;
  if (typeof isRestOrNonLeaveColumnType === 'function' && isRestOrNonLeaveColumnType(obj, req)) return true;
  return false;
}
function isLongTermSickLeaveRequest(obj, req) {
  if (!req) return false;
  if (req.longTermSick === true || req.isLongTermSick === true) return true;
  const name = String(req.typeName || req.name || '').trim();
  if (/Ø§Ø³ØªØ¹Ù„Ø§Ø¬ÛŒ\s*Ø¨Ù„Ù†Ø¯\s*Ù…Ø¯Øª|Ø§Ø³ØªØ¹Ù„Ø§Ø¬ÛŒ\s*Ø¨Ù„Ù†Ø¯Ù…Ø¯Øª|Ù…Ø±Ø®ØµÛŒ\s*Ø§Ø³ØªØ¹Ù„Ø§Ø¬ÛŒ\s*Ø¨Ù„Ù†Ø¯/.test(name)) return true;
  try {
    const typesA = (obj && obj.attendanceTypes) || [];
    const typesB = (obj && obj.settings && obj.settings.attendanceTypes) || [];
    const types = typesA.concat(typesB);
    const t = types.find(function (x) { return String(x.id) === String(req.typeId); });
    if (t) {
      if (t.longTermSick === true || t.isLongTermSick === true) return true;
      if (/Ø§Ø³ØªØ¹Ù„Ø§Ø¬ÛŒ\s*Ø¨Ù„Ù†Ø¯\s*Ù…Ø¯Øª|Ø§Ø³ØªØ¹Ù„Ø§Ø¬ÛŒ\s*Ø¨Ù„Ù†Ø¯Ù…Ø¯Øª/.test(String(t.name || ''))) return true;
    }
  } catch (e) {}
  return false;
}


function dailyLeaveMissionFlags(obj, code, year, month, day) {
  const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(day).padStart(2, '0');
  const dateDash = year + '-' + String(month).padStart(2, '0') + '-' + String(day).padStart(2, '0');
  let fullDay = false, unpaid = false;
  (obj.attendanceRequests || []).forEach(function (x) {
    if (String(x.empCode) !== String(code) || x.status !== 'approved') return;
    if (x.mode !== 'daily') return;
    if (x.kind !== 'leave' && x.kind !== 'mission') return;
    const keys = (typeof listDayKeys === 'function') ? listDayKeys(x.startDate, x.endDate || x.startDate) : [];
    let hit = false;
    keys.forEach(function (k) {
      const parts = String(k).split(/[-\/]/);
      if (parts.length < 3) return;
      if (Number(parts[0]) === Number(year) && Number(parts[1]) === Number(month) && Number(parts[2]) === Number(day)) hit = true;
    });
    if (!hit) {
      const sk = String(x.startDate || '').replace(/-/g, '/');
      if (sk === dateFa || dateKey(x.startDate) === dateDash) hit = true;
    }
    if (!hit) return;
    fullDay = true;
    if (x.kind === 'leave' && isUnpaidLeaveRequest(obj, x)) unpaid = true;
  });
  return { fullDayLeaveOrMission: fullDay, unpaidLeave: unpaid };
}

function hourlyCoverMinutesOnDay(obj, code, year, month, day) {
  const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(day).padStart(2, '0');
  const dateDash = year + '-' + String(month).padStart(2, '0') + '-' + String(day).padStart(2, '0');
  let mins = 0;
  const iv = [];
  (obj.attendanceRequests || []).forEach(function (x) {
    if (String(x.empCode) !== String(code) || x.status !== 'approved') return;
    if (x.mode !== 'hourly') return;
    if (x.kind !== 'leave' && x.kind !== 'mission') return;
    const sk = String(x.startDate || '').replace(/-/g, '/');
    const k = (typeof dateKey === 'function') ? dateKey(x.startDate) : '';
    if (k !== dateDash && sk !== dateFa) return;
    const a = timeToMinutes(x.fromTime);
    const b = timeToMinutes(x.toTime);
    if (a == null || b == null || b <= a) return;
    iv.push([a, b]);
  });
  // Ø§Ø¬ØªÙ…Ø§Ø¹ Ø¨Ø§Ø²Ù‡â€ŒÙ‡Ø§: Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø³Ø§Ø¹ØªÛŒ ØªÚ©Ø±Ø§Ø±ÛŒ ÛŒØ§ Ù‡Ù…â€ŒÙ¾ÙˆØ´Ø§Ù† ÙÙ‚Ø· ÛŒÚ©â€ŒØ¨Ø§Ø± Ø´Ù…Ø±Ø¯Ù‡ Ø´ÙˆØ¯
  iv.sort(function (p, q) { return p[0] - q[0]; });
  let curA = null, curB = null;
  iv.forEach(function (p) {
    if (curA == null) { curA = p[0]; curB = p[1]; return; }
    if (p[0] <= curB) { if (p[1] > curB) curB = p[1]; return; }
    mins += (curB - curA); curA = p[0]; curB = p[1];
  });
  if (curA != null) mins += (curB - curA);
  return mins;
}


/** Ø§Ø¬ØªÙ…Ø§Ø¹ Ø¨Ø§Ø²Ù‡â€ŒÙ‡Ø§ÛŒ Ù…Ø±Ø®ØµÛŒ/Ù…Ø£Ù…ÙˆØ±ÛŒØª Ø³Ø§Ø¹ØªÛŒ Ø±ÙˆØ² (Ø¨Ø±Ø§ÛŒ Ù¾ÙˆØ´Ø´ Ø¯Ù‚ÛŒÙ‚ ØºÛŒØ¨Øª) */
function hourlyCoverIntervalsOnDay(obj, code, year, month, day) {
  const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(day).padStart(2, '0');
  const dateDash = year + '-' + String(month).padStart(2, '0') + '-' + String(day).padStart(2, '0');
  const iv = [];
  (obj.attendanceRequests || []).forEach(function (x) {
    if (String(x.empCode) !== String(code) || x.status !== 'approved') return;
    if (x.mode !== 'hourly') return;
    if (x.kind !== 'leave' && x.kind !== 'mission') return;
    const sk = String(x.startDate || '').replace(/-/g, '/');
    const k = (typeof dateKey === 'function') ? dateKey(x.startDate) : '';
    if (k !== dateDash && sk !== dateFa) return;
    const a = timeToMinutes(x.fromTime);
    const b = timeToMinutes(x.toTime);
    if (a == null || b == null || b <= a) return;
    iv.push([a, b]);
  });
  return iv;
}

/** Ù¾Ø§Ú©â€ŒØ³Ø§Ø²ÛŒ ØªÙˆØ¶ÛŒØ­ Ø§Ø² Ù…ØªÙ†â€ŒÙ‡Ø§ÛŒ Ø®ÙˆØ¯Ú©Ø§Ø± Ù¾ÙˆØ´Ø´ Ú©Ø³Ø± Ùˆ ØªÚ©Ø±Ø§Ø±ÛŒâ€ŒÙ‡Ø§ */
function cleanTimesheetNote(note) {
  if (!note) return '';
  const seen = {};
  return String(note).split(/[Ø›;]+/).map(function (s) { return s.trim(); }).filter(function (s) {
    if (!s) return false;
    if (s.indexOf('Ø«Ø¨Øª Ø®ÙˆØ¯Ú©Ø§Ø±') >= 0 || s.indexOf('Ù¾ÙˆØ´Ø´ Ú©Ø³Ø±') >= 0) return false;
    const k = s.replace(/\s+/g, ' ');
    if (seen[k]) return false;
    seen[k] = true;
    return true;
  }).join('Ø› ');
}

function empOtCeilingHours(emp, settings) {
  // Ø³Ù‚Ù ÙØ±Ø¯ÛŒ > Ù¾ÛŒØ´â€ŒÙØ±Ø¶ ØªÙ†Ø¸ÛŒÙ…Ø§Øª > Û°
  // Û° ÛŒØ¹Ù†ÛŒ Ù‡ÛŒÚ† Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±ÛŒ ØªØ£ÛŒÛŒØ¯ Ù†Ù…ÛŒâ€ŒØ´ÙˆØ¯ (Ù†Ù‡ Â«Ø¨Ø¯ÙˆÙ† Ø³Ù‚ÙÂ»)
  if (emp) {
    const v = emp.otCeilingHours != null ? emp.otCeilingHours
      : (emp.maxOtHours != null ? emp.maxOtHours
      : (emp.otLimit != null ? emp.otLimit
      : (emp.otCeiling != null ? emp.otCeiling : null)));
    if (v !== '' && v != null) {
      const n = Number(v);
      if (isFinite(n) && n >= 0) return n;
    }
  }
  const def = settings && settings.maxOtHours;
  if (def !== '' && def != null) {
    const n = Number(def);
    if (isFinite(n) && n >= 0) return n;
  }
  return 0; // Ù¾ÛŒØ´â€ŒÙØ±Ø¶: Ø¨Ø¯ÙˆÙ† Ø§Ø¶Ø§ÙÙ‡â€ŒÚ©Ø§Ø±
}



/** Ù†Ø±Ù…Ø§Ù„â€ŒØ³Ø§Ø²ÛŒ Ø§Ø±Ù‚Ø§Ù… Ùˆ ÛŒØ§ÙØªÙ† Ø³Ù„ÙˆÙ„ ØªØ±Ø¯Ø¯ ÛŒÚ© Ø±ÙˆØ² â€” ÛŒÚ©Ø³Ø§Ù† Ø¨Ø±Ø§ÛŒ Ù¾Ø§Ù†Ú†/Ú©Ø§Ø±Ú©Ø±Ø¯/ØºÛŒØ¨Øª */
function toEnDigitsPsp(s) {
  return String(s || '').replace(/[\u06f0-\u06f9]/g, function (ch) {
    return String(ch.charCodeAt(0) - 0x06f0);
  }).replace(/[\u0660-\u0669]/g, function (ch) {
    return String(ch.charCodeAt(0) - 0x0660);
  });
}
function lookupPunchCell(punchStore, year, month, d) {
  if (!punchStore) return null;
  year = Number(year); month = Number(month); d = Number(d);
  const pad = String(d).padStart(2, '0');
  const mpad = String(month).padStart(2, '0');
  const keys = [
    year + '-' + mpad + '-' + pad,
    year + '/' + mpad + '/' + pad,
    year + '-' + month + '-' + d,
    year + '/' + month + '/' + d,
    year + '-' + mpad + '-' + d,
    year + '/' + mpad + '/' + d,
    year + '/' + month + '/' + pad,
    year + '-' + month + '-' + pad
  ];
  for (let i = 0; i < keys.length; i++) {
    if (punchStore[keys[i]]) return punchStore[keys[i]];
  }
  try {
    var ks = Object.keys(punchStore || {});
    for (var ki = 0; ki < ks.length; ki++) {
      var parts = toEnDigitsPsp(ks[ki]).split(/[-\/.]/);
      if (parts.length < 3) continue;
      if (Number(parts[0]) === year && Number(parts[1]) === month && Number(parts[2]) === d) {
        return punchStore[ks[ki]];
      }
    }
  } catch (e) {}
  return null;
}
function cellHasAnyPunch(punch) {
  if (!punch) return false;
  for (let pi = 1; pi <= 4; pi++) {
    if (String(punch['in' + pi] || '').trim() || String(punch['out' + pi] || '').trim()) return true;
  }
  return false;
}

function countEmpMonthPunchDays(obj, year, month, code) {
  year = Number(year); month = Number(month);
  const dim = daysInJalaliMonth(year, month);
  const punchStore = ((obj.dailyAttendance || {})[String(code)]) ||
    ((obj.dailyAttendance || {})[code]) || {};
  let n = 0;
  for (let d = 1; d <= dim; d++) {
    if (cellHasAnyPunch(lookupPunchCell(punchStore, year, month, d))) n++;
  }
  return n;
}


/** ØªØ¹Ø¯Ø§Ø¯ Ø±ÙˆØ²Ù‡Ø§ÛŒ Ú©Ø§Ø±ÛŒ ØªÙ‚ÙˆÛŒÙ… Ù…Ø§Ù‡: Ù…ÙˆØ¸ÙÛŒ Ù…Ù†Ù‡Ø§ÛŒ Ù¾Ù†Ø¬Ø´Ù†Ø¨Ù‡/Ø¬Ù…Ø¹Ù‡ Ùˆ ØªØ¹Ø·ÛŒÙ„ Ø±Ø³Ù…ÛŒ/Ø´Ø±Ø§ÛŒØ·ÛŒ Ú©Ø§Ù…Ù„ */
function countFunctionalDaysInMonth(obj, year, month, contractType) {
  year = Number(year); month = Number(month);
  const dim = daysInJalaliMonth(year, month);
  const ct = contractType || 'normal';
  let n = 0;
  for (let d = 1; d <= dim; d++) {
    try {
      if (!isHolidayOrNonWork(obj, year, month, d, ct)) n++;
    } catch (e) {
      // Ø¯Ø± Ø®Ø·Ø§ Ø±ÙˆØ² Ø±Ø§ Ù…ÙˆØ¸ÙÛŒ ÙØ±Ø¶ Ù†Ú©Ù†
    }
  }
  return n > 0 ? n : 0;
}

function recountEmpMonthWorkDays(obj, year, month, code) {
  /* Ú©Ø§Ø±Ú©Ø±Ø¯ Ù…Ø§Ù‡:
     Ù¾Ø§ÛŒÙ‡ = Ø±ÙˆØ²Ù‡Ø§ÛŒ ØªÙ‚ÙˆÛŒÙ…ÛŒ Ø¨Ø§Ø²Ù‡ Ø§Ø³ØªØ®Ø¯Ø§Ù… Ø¯Ø± Ù…Ø§Ù‡.
     Ù‡Ø± Ø±ÙˆØ² Ú©Ø§Ø±ÛŒ Ø¨Ø§ Ø­Ø¶ÙˆØ± ÛŒØ§ Ù…Ø±Ø®ØµÛŒ ÛŒØ§ Ù…Ø£Ù…ÙˆØ±ÛŒØª â†’ Ú©Ø§Ø±Ú©Ø±Ø¯ (Ø­ØªÛŒ Ø¨Ø¯ÙˆÙ† ØªØ±Ø¯Ø¯).
     ÙÙ‚Ø· Ø±ÙˆØ² Ú©Ø§Ø±ÛŒ Ú©Ø§Ù…Ù„Ø§Ù‹ Ø®Ø§Ù„ÛŒ â†’ ØºÛŒØ¨Øª.
     Ù…Ø±Ø®ØµÛŒ Ø¨Ø¯ÙˆÙ† Ø­Ù‚ÙˆÙ‚ â†’ Ú©Ø§Ø±Ú©Ø±Ø¯ Ù†ÛŒØ³Øª.
  */
  year = Number(year); month = Number(month);
  const dim = daysInJalaliMonth(year, month);
  const emp = ((obj.employees || []).find(function (e) { return String(e.code) === String(code); })) || null;
  const ct = (emp && emp.contractType) || 'normal';

  let fromD = 1, toD = dim;
  try {
    const hire = parseJalaliYMD(emp && emp.hireDate);
    if (hire) {
      if (hire.y > year || (hire.y === year && hire.m > month)) return 0;
      if (hire.y === year && hire.m === month) fromD = Math.max(1, Math.min(dim, hire.d || 1));
    }
    const end = parseJalaliYMD(emp && emp.endDate);
    if (end) {
      if (end.y < year || (end.y === year && end.m < month)) return 0;
      if (end.y === year && end.m === month) toD = Math.max(1, Math.min(dim, end.d || dim));
    }
  } catch (eH) {}
  if (toD < fromD) return 0;

  const punchStore = ((obj.dailyAttendance || {})[String(code)]) ||
    ((obj.dailyAttendance || {})[code]) || {};
  const calR = getContractCalendar(obj, ct);
  const allWeekWorkR = Array.isArray(calR.workWeekDays) && calR.workWeekDays.length >= 7;

  const dayActivity = {};
  for (let d = fromD; d <= toD; d++) dayActivity[d] = false;
  function markDay(d) {
    d = Number(d);
    if (d >= fromD && d <= toD) dayActivity[d] = true;
  }
  for (let d = fromD; d <= toD; d++) {
    const punch = lookupPunchCell(punchStore, year, month, d) || {};
    if (cellHasAnyPunch(punch)) markDay(d);
    if (punch.leaveDaily || punch.missionDaily || punch.leaveHourly || punch.missionHourly) markDay(d);
    if (punch.leave || punch.mission) markDay(d);
    try {
      const note = String(punch.note || '') + ' ' + String(punch.status || '') + ' ' + String(punch.type || '');
      if (/Ù…Ø±Ø®Øµ|Ù…Ø£Ù…ÙˆØ±|Ù…Ø§Ù…ÙˆØ±|leave|mission/i.test(note) && !/Ø¨Ø¯ÙˆÙ†\s*Ø­Ù‚ÙˆÙ‚|unpaid/i.test(note)) markDay(d);
    } catch (eN) {}
  }

  let leaveDaysFromReq = 0;
  let missionDaysFromReq = 0;
  (obj.attendanceRequests || []).forEach(function (req) {
    if (!req) return;
    if (String(req.empCode) !== String(code)) return;
    const st = String(req.status || '').toLowerCase();
    // ØªØ£ÛŒÛŒØ¯ Ø´Ø¯Ù‡ / Ø³Ø·Ø­ Û± / Ù†Ù‡Ø§ÛŒÛŒ
    if (!(st === 'approved' || st === 'approved_l1' || st === 'final' || st === 'ØªØ§ÛŒÛŒØ¯' || st === 'ØªØ£ÛŒÛŒØ¯' || st === 'ØªØ§ÛŒÛŒØ¯ Ø´Ø¯Ù‡' || st === 'ØªØ£ÛŒÛŒØ¯ Ø´Ø¯Ù‡')) return;
    try {
      // ÙÙ‚Ø· Ù…Ø±Ø®ØµÛŒ Ø¨Ø¯ÙˆÙ† Ø­Ù‚ÙˆÙ‚ Ø§Ø² Ú©Ù„ Ø­Ù„Ù‚Ù‡ Ø­Ø°Ù Ù…ÛŒâ€ŒØ´ÙˆØ¯Ø› Ø±Ø³Øª ÙÙ‚Ø· Ø§Ø² Ø³ØªÙˆÙ† Ø±ÙˆØ² Ù…Ø±Ø®ØµÛŒ Ø­Ø°Ù Ù…ÛŒâ€ŒØ´ÙˆØ¯
      if (typeof isUnpaidLeaveRequest === 'function' && isUn
