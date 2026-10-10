// parspehr gate: personal login + watermark + payroll API + employee self-service portal
import { makeEngine } from './engine.js';
import PORTAL_ADMIN_JS from './portal-admin-src.js';
const OWNER = 'Mohamad Moradibabersad'; // <-- put your own name here (English letters)

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
    // اسکریپت پنل فقط از Worker (فایل جدا) — جلوگیری از SyntaxError داخل HTML
  const portalAdminScript = '<script src="/api/admin/portal-boot.js?v=20261010v37" defer><\/script>';
  const bottom = portalAdminScript + '<script>/*psp:' + safe + '*/</script><!-- psp:' + safe + ' -->';
  let out = /<head(?:\s[^>]*)?>/i.test(html)
    ? html.replace(/<head(?:\s[^>]*)?>/i, function (m) { return m + top; })
    : html + top;
  const end = out.lastIndexOf('</body>');
  out = end >= 0 ? out.slice(0, end) + bottom + out.slice(end) : out + bottom;
  return out;
}

const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_ITEMS = 5000;
const MAX_DOC_BYTES = 8 * 1024 * 1024;
const STATE_DOCS = ['settings', 'data', 'log'];
const SESSION_IDLE_SECONDS = 60 * 60;
const COOKIE_NAME = 'psp_session';
const EMP_COOKIE_NAME = 'psp_emp';

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
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
  }
  return { version: Number(row.version) || 0, obj: obj };
}

async function storePutData(cfg, baseVersion, obj, updatedBy) {
  // Preserve portal fields the main app form does not know about (managerCode, portal password, requests…)
  try {
    if (obj && Array.isArray(obj.employees) && baseVersion > 0) {
      const prev = await storeGetData(cfg);
      if (!prev.fail && prev.obj && Array.isArray(prev.obj.employees)) {
        const map = {};
        prev.obj.employees.forEach(function (e) { map[String(e.code)] = e; });
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
            // اگر کلاینت family نفرستاد، از قبلی نگه دار (تا F5 پاک نکند)
            if (e.family === undefined && p.family) e.family = p.family;
            if (e.suppInsurance === undefined && p.suppInsurance) e.suppInsurance = p.suppInsurance;
            if (e.systemMessages === undefined && p.systemMessages) e.systemMessages = p.systemMessages;
            if (e.childrenEligibleCount === undefined && p.childrenEligibleCount != null) e.childrenEligibleCount = p.childrenEligibleCount;
            if ((e.photo === undefined || e.photo === null || e.photo === '') && p.photo) e.photo = p.photo;
          }
        });
        if (obj.attendanceTypes === undefined && prev.obj.attendanceTypes) obj.attendanceTypes = prev.obj.attendanceTypes;
        if (obj.attendanceRequests === undefined && prev.obj.attendanceRequests) obj.attendanceRequests = prev.obj.attendanceRequests;
        if (obj.attendanceGrants === undefined && prev.obj.attendanceGrants) obj.attendanceGrants = prev.obj.attendanceGrants;
        if (obj.contracts === undefined && prev.obj.contracts) obj.contracts = prev.obj.contracts;
        if (obj.portalViewConfig === undefined && prev.obj.portalViewConfig) obj.portalViewConfig = prev.obj.portalViewConfig;
        // خانواده / بیمه تکمیلی / عکس — هرگز با ذخیره فرم اصلی پاک نشوند
        if (prev.obj.employeeExtras && typeof prev.obj.employeeExtras === 'object') {
          obj.employeeExtras = Object.assign({}, prev.obj.employeeExtras, obj.employeeExtras || {});
        }
        if (prev.obj.employeePhotos && typeof prev.obj.employeePhotos === 'object') {
          obj.employeePhotos = Object.assign({}, prev.obj.employeePhotos, obj.employeePhotos || {});
        }
        try { mergeAllEmployeeExtras(obj); } catch (e2) { /* non-fatal */ }
      }
    }
  } catch (e) { /* non-fatal */ }

  // سبک‌سازی قبل از ذخیره: عکس تکراری داخل extras و روی emp اگر در employeePhotos هست
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
  const b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
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


/** قبل از محاسبه: family/suppInsurance/مبلغ واحد را از ذخیره سرور روی payload کلاینت بنشان */
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
      // آیتم کسر بیمه تکمیلی
      if (Array.isArray(s.customItems) && s.customItems.length) {
        if (!Array.isArray(e.customItems)) e.customItems = e.customItems || [];
        var hasSupp = (e.customItems || []).some(function (ci) { return ci && /بیمه\s*تکمیلی/.test(String(ci.name || '')); });
        if (!hasSupp) {
          s.customItems.forEach(function (ci) {
            if (ci && /بیمه\s*تکمیلی/.test(String(ci.name || ''))) e.customItems.push(JSON.parse(JSON.stringify(ci)));
          });
        } else {
          // مبلغ/تعداد را از سرور به‌روز کن
          e.customItems.forEach(function (ci) {
            if (!ci || !/بیمه\s*تکمیلی/.test(String(ci.name || ''))) return;
            var src = s.customItems.find(function (x) { return x && /بیمه\s*تکمیلی/.test(String(x.name || '')); });
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
    // qty ماه جاری
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
        reason: mine.length ? 'قرارداد بدون تأیید ادمین' : 'بدون قرارداد'
      });
    }
  });
  return out;
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
    out = makeEngine(data).runMonth(year, month, { skipLoanSE: !!body.skipLoanSE });
  } catch (e) {
    console.log(JSON.stringify({ event: 'payroll_error', user: user, message: String(e && e.message) }));
    return jsonResponse({ ok: false, error: 'calculation_failed' }, 500);
  }
  if (out && typeof out === 'object') {
    out.contractWarnings = contractWarnings;
    if (contractWarnings.length) {
      out.contractWarningMessage = contractWarnings.length + ' نفر فاقد قرارداد تأییدشده هستند. محاسبه حقوق فقط برای افراد دارای قرارداد تأییدشده معتبر است.';
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
      // برای سند data: خانواده را از employeeExtras ادغام کن — data باید STRING بماند (کلاینت JSON.parse می‌کند)
      if (rest === 'data') {
        try {
          const row = JSON.parse(text);
          if (row && row.data) {
            let parsed = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
            if (parsed && typeof parsed === 'object') {
              try { mergeAllEmployeeExtras(parsed); } catch (eM) {}
              // حتماً دوباره رشته شود تا همگام‌سازی کلاینت نشکند
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
      const text = (await request.text()).trim();
      if (text.length > MAX_DOC_BYTES) return jsonResponse({ ok: false, error: 'too_large' }, 413);
      if (text.charAt(0) !== '{' || text.charAt(text.length - 1) !== '}') return jsonResponse({ ok: false, error: 'bad_body' }, 400);
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
  // Persian ۰-۹ and Arabic ٠-٩ → 0-9
  return String(s || '')
    .replace(/[۰-۹]/g, function (d) { return String(d.charCodeAt(0) - 1776); })
    .replace(/[٠-٩]/g, function (d) { return String(d.charCodeAt(0) - 1632); });
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
    return jsonResponse({ ok: false, error: 'invalid', message: 'داده کارکنان روی سرور نیست. یک‌بار از سیستم اصلی «همگام‌سازی» بزنید.' }, 401);
  }

  // match code as string (handles number/string storage)
  const emp = gd.obj.employees.find(function (e) {
    return normalizeDigits(e.code).trim() === code;
  });
  if (!emp) {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid', message: 'کد پرسنلی در سیستم یافت نشد.' }, 401);
  }
  if (emp.status === 'inactive') {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid', message: 'وضعیت این کارمند غیرفعال است.' }, 401);
  }
  if (emp.portalEnabled === false) {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid', message: 'دسترسی پرتال برای این کارمند غیرفعال است.' }, 401);
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
    return jsonResponse({ ok: false, error: 'invalid', message: 'رمز اشتباه است. بعد از ریست، رمز = همان کد پرسنلی است.' }, 401);
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
  const body = { ok: true, code: sess.code, fullName: sess.fullName };
  if (renew) {
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Set-Cookie': renew }
    });
  }
  return jsonResponse(body);
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

  const key = year + '-' + month;
  const rows = (gd.obj.payrolls && gd.obj.payrolls[key]) || [];
  const rec = rows.find(x => String(x.code) === String(sess.code));
  if (!rec) {
    return jsonResponse({ ok: false, error: 'not_found', message: 'برای این ماه فیشی ثبت نشده است.' }, 404);
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
    return jsonResponse({ ok: false, error: 'weak_password', message: 'رمز جدید حداقل ۶ کاراکتر باشد.' }, 400);
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
      return jsonResponse({ ok: false, error: 'wrong_old', message: 'رمز فعلی اشتباه است.' }, 401);
    }

    emp.portalEnabled = true;
    emp.portalPassHash = await hashPassword(newPass);
    emp.portalPassChangedAt = new Date().toISOString();

    const put = await storePutData(cfg, gd.version, gd.obj, 'emp:' + sess.code);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue; // retry

    console.log(JSON.stringify({ event: 'emp_password_change', code: sess.code }));
    return jsonResponse({ ok: true, message: 'رمز با موفقیت تغییر کرد.' });
  }
  return jsonResponse({ ok: false, error: 'conflict', message: 'لطفاً دوباره تلاش کنید.' }, 409);
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
      // disabled — keep hash in case re-enabled later
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

function parseJalaliYMD(str) {
  if (!str) return null;
  const m = String(str).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
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
    splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
      const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
      row.leaveDays = Math.round(Math.max(0, (Number(row.leaveDays) || 0) - chunk.days) * 100) / 100;
    });
  } else if (req.kind === 'leave' && req.mode === 'hourly') {
    const p = parseJalaliYMD(req.startDate);
    if (!p) return;
    const hrs = hoursBetween(req.fromTime, req.toTime);
    const row = ensureEmpMonthRow(data, p.y, p.m, code);
    row.hourlyLeave = Math.round(Math.max(0, (Number(row.hourlyLeave) || 0) - hrs) * 100) / 100;
  } else if (req.kind === 'mission' && req.mode === 'daily') {
    splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
      const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
      row.missionDays = Math.round(Math.max(0, (Number(row.missionDays) || 0) - chunk.days) * 100) / 100;
    });
  } else if (req.kind === 'mission' && req.mode === 'hourly') {
    const p = parseJalaliYMD(req.startDate);
    if (!p) return;
    const hrs = hoursBetween(req.fromTime, req.toTime);
    const row = ensureEmpMonthRow(data, p.y, p.m, code);
    row.missionHours = Math.round(Math.max(0, (Number(row.missionHours) || 0) - hrs) * 100) / 100;
  }
}

function applyApprovedRequestToTimesheet(data, req) {
  if (!req || req.status !== 'approved') return;
  const code = String(req.empCode);
  if (req.kind === 'leave' && req.mode === 'daily') {
    splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
      const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
      row.leaveDays = Math.round(((Number(row.leaveDays) || 0) + chunk.days) * 100) / 100;
    });
  } else if (req.kind === 'leave' && req.mode === 'hourly') {
    const p = parseJalaliYMD(req.startDate);
    if (!p) return;
    const hrs = hoursBetween(req.fromTime, req.toTime);
    const row = ensureEmpMonthRow(data, p.y, p.m, code);
    row.hourlyLeave = Math.round(((Number(row.hourlyLeave) || 0) + hrs) * 100) / 100;
  } else if (req.kind === 'mission' && req.mode === 'daily') {
    splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
      const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
      row.missionDays = Math.round(((Number(row.missionDays) || 0) + chunk.days) * 100) / 100;
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
  if (!startDate) return jsonResponse({ ok: false, error: 'bad_request', message: 'تاریخ شروع الزامی است.' }, 400);

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);

    // only current month (from settings) is allowed
    const settings = gd.obj.settings || {};
    const cy = Number(settings.currentYear) || 1405;
    let cm = Number(settings.currentMonth) || Number(settings.activeMonth) || 0;
    const pStart = parseJalaliYMD(startDate);
    if (!pStart) return jsonResponse({ ok: false, error: 'bad_request', message: 'فرمت تاریخ نامعتبر است.' }, 400);
    if (!cm) {
      return jsonResponse({ ok: false, error: 'no_current_month', message: 'ماه جاری درخواست‌ها در سیستم تنظیم نشده. ادمین از تب «مأموریت/مرخصی و سایر» ماه جاری را ثبت کند.' }, 400);
    }
    const targetY = cy;
    const targetM = cm;
    if (pStart.y !== cy || pStart.m !== cm) {
      return jsonResponse({ ok: false, error: 'wrong_month', message: 'فقط درخواست در ماه جاری سیستم (' + cy + '/' + cm + ') مجاز است.' }, 400);
    }

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
        const p = parseJalaliYMD(startDate);
        if (p) {
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

    const emp = gd.obj.employees.find(e => String(e.code) === String(sess.code));
    if (!emp || emp.status === 'inactive') return jsonResponse({ ok: false, error: 'disabled' }, 403);

    if (mode === 'hourly' && (!fromTime || !toTime)) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'ساعت شروع و پایان الزامی است.' }, 400);
    }
    if (mode === 'hourly') {
      try {
        const sh = assertHourlyWithinShift(gd.obj, emp, fromTime, toTime);
        if (!sh.ok) return jsonResponse({ ok: false, error: 'outside_shift', message: sh.message }, 400);
      } catch (e) {
        return jsonResponse({ ok: false, error: 'shift_check', message: 'بررسی ساعت موظفی ناموفق: ' + (e && e.message ? e.message : e) }, 400);
      }
    }
    if (kind === 'mission' && !place) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'محل مأموریت الزامی است.' }, 400);
    }
    // reason/description required only for mission
    if (kind === 'mission' && !reason) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'توضیح / دلیل مأموریت الزامی است.' }, 400);
    }
    const pmeta = (gd.obj.portalMeta && gd.obj.portalMeta[String(emp.code)]) || {};
    const mgrCode1 = pmeta.managerCode || emp.managerCode || '';
    const mgrCode2 = pmeta.managerCode2 || emp.managerCode2 || '';
    if (!mgrCode1) {
      return jsonResponse({ ok: false, error: 'no_manager', message: 'برای شما مدیر مستقیم تعریف نشده است. با منابع انسانی تماس بگیرید.' }, 400);
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
        return jsonResponse({ ok: false, error: 'frequency_limit', message: 'این نوع مرخصی فقط یک‌بار در طول استخدام قابل استفاده است و قبلاً استفاده شده.' }, 400);
      }
    }
    if (typeId && frequency === 'once_year') {
      const py = parseJalaliYMD(startDate);
      const used = countTypeUsage(gd.obj.attendanceRequests, emp.code, typeId, py ? py.y : null);
      if (used > 0) {
        return jsonResponse({ ok: false, error: 'frequency_limit', message: 'این نوع مرخصی فقط یک‌بار در طول سال قابل استفاده است و در این سال قبلاً ثبت شده.' }, 400);
      }
    }

    // admin grant required — grant may have dateFrom..dateTo (or legacy date)
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
        return jsonResponse({ ok: false, error: 'no_grant', message: 'این نوع مرخصی فقط با مجوز ادمین برای بازه تاریخ مشخص قابل درخواست است. با منابع انسانی هماهنگ کنید.' }, 400);
      }
      grantId = g.id;
    }

    // fixed-day types: endDate already forced above — do not reject; user only picks start date
    if (fixedDays && mode === 'daily' && startDate && !endDate) {
      endDate = startDate;
    }
    // force entire request inside same month (current month)
    {
      const pe = parseJalaliYMD(mode === 'hourly' ? startDate : (endDate || startDate));
      if (pe && (pe.y !== targetY || pe.m !== targetM)) {
        return jsonResponse({ ok: false, error: 'wrong_month', message: 'بازه درخواست باید داخل همان ماه جاری (' + targetY + '/' + targetM + ') باشد.' }, 400);
      }
      if (pStart.y !== targetY || pStart.m !== targetM) {
        return jsonResponse({ ok: false, error: 'wrong_month', message: 'فقط ماه جاری (' + targetY + '/' + targetM + ') قابل درخواست است.' }, 400);
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
      const cname = conflict.typeName || (conflict.kind === 'mission' ? 'مأموریت' : 'مرخصی');
      const when = conflict.mode === 'hourly'
        ? (conflict.startDate + ' ' + (conflict.fromTime || '') + '-' + (conflict.toTime || ''))
        : (conflict.startDate + (conflict.endDate && conflict.endDate !== conflict.startDate ? ' تا ' + conflict.endDate : ''));
      return jsonResponse({
        ok: false,
        error: 'overlap',
        message: 'تداخل با درخواست قبلی: «' + cname + '» در ' + when + '. در یک روز/ساعت نمی‌توان چند مرخصی یا مأموریت هم‌زمان داشت.'
      }, 400);
    }


    // قوانین مرخصی روزانه و تعطیل (تقویم نوع قرارداد کارمند):
    // - کل بازه تعطیل → رد
    // - روز شروع تعطیل → رد
    // - روز پایان تعطیل → رد
    // - شروع و پایان عادی، تعطیل میانی → قبول؛ فقط روزهای کاری شمرده می‌شوند
    if (kind === 'leave' && mode === 'daily' && startDate && !fixedDays) {
      const empCt = emp.contractType || 'normal';
      const ws = getWorkWeekSettings(gd.obj, empCt);
      if (!ws.countNonWorkDaysAsLeave) {
        const endD = endDate || startDate;
        const sp = parseJalaliYMD(startDate);
        const ep = parseJalaliYMD(endD);
        if (sp && isHolidayOrNonWork(gd.obj, sp.y, sp.m, sp.d, empCt)) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'روز شروع (' + startDate + ') تعطیل/غیرکاری است و به‌عنوان مرخصی محسوب نمی‌شود. تاریخ شروع را روی یک روز کاری بگذارید.'
          }, 400);
        }
        if (ep && isHolidayOrNonWork(gd.obj, ep.y, ep.m, ep.d, empCt)) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'روز پایان (' + endD + ') تعطیل/غیرکاری است و به‌عنوان مرخصی محسوب نمی‌شود. تاریخ پایان را روی یک روز کاری بگذارید.'
          }, 400);
        }
        const daysNeeded0 = countLeaveDays({ mode: 'daily', startDate: startDate, endDate: endD }, gd.obj, empCt);
        if (daysNeeded0 <= 0) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'در بازه انتخاب‌شده هیچ روز کاری وجود ندارد؛ مرخصی فقط روی روزهای کاری ثبت می‌شود.'
          }, 400);
        }
        // تعطیلات میانی فقط از شمارش کسر می‌شوند (در countLeaveDays) — درخواست پذیرفته می‌شود
      }
    }

    // بررسی مانده مرخصی استحقاقی (سال جاری / ذخیره سال‌های قبل)
    let usePriorYears = !!b.usePriorYears;
    if (kind === 'leave' && deductFromEntitlement) {
      const fakeReq = { mode: mode, startDate: startDate, endDate: endDate, fromTime: fromTime, toTime: toTime, fixedDays: fixedDays };
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
          message: 'بیش از سقف سالانه. سقف: ' + (avail.annualDays||'') + '، استفاده‌شده: ' + (avail.usedYear||0) + '، باقی تا سقف: ' + avail.currentRemaining + '، ذخیره قبل: ' + avail.priorRemaining + '، درخواست: ' + daysNeeded + ' روز. برای بیش از سقف از تعدیل (+) استفاده کنید.',
          availability: avail
        }, 400);
      }
      if (avail.insufficient && allowAdvance) {
        usePriorYears = true; // کسر می‌تواند منفی شود
        // flag on request
      }
      if (avail.needPriorYears && !usePriorYears) {
        return jsonResponse({
          ok: false,
          error: 'need_prior_years_confirm',
          message: 'مانده مرخصی امسال (' + avail.currentRemaining + ' روز) برای این درخواست کافی نیست. از ذخیره سال‌های قبل (' + avail.priorRemaining + ' روز) استفاده شود؟',
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

/** سقف استحقاقی: گروه کاری > نوع قرارداد > پیش‌فرض سیاست (بدون مهاجرت اعداد قدیمی) */
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

/** استحقاق تناسبی تا پایان ماه جاری: (تعداد ماه کارکرد در سال شامل ماه جاری) / 12 × سقف سالانه */
function computeAccruedLeaveDaysW(obj, emp, year, month) {
  const annual = getAnnualLeaveDaysForEmp(obj, emp);
  const cy = Number(year) || Number((obj.settings || {}).currentYear) || 1405;
  let cm = Number(month);
  if (!cm) cm = Number((obj.settings || {}).currentMonth) || Number((obj.settings || {}).activeMonth) || 1;
  if (cm < 1) cm = 1;
  if (cm > 12) cm = 12;
  const p = parseJalaliYMD(emp && emp.hireDate);
  if (!p) {
    // بدون تاریخ استخدام: تناسب ماه جاری
    return Math.round(annual * (cm / 12) * 100) / 100;
  }
  if (p.y > cy) return 0;
  let months = 0;
  if (p.y < cy) {
    months = cm; // از اول سال تا ماه جاری
  } else {
    // استخدام در همین سال
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

/** دفتر سالانه مرخصی: هر سال یک ردیف (استحقاقی / استفاده‌شده / مانده / تسویه‌شده) */
function ensureEmpLeaveYears(emp, obj) {
  if (!emp) return;
  const cy = Number((obj && obj.settings && obj.settings.currentYear) || 1405);
  if (!emp.leaveYears || typeof emp.leaveYears !== 'object') emp.leaveYears = {};
  // مهاجرت از فیلدهای قدیمی
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
  // اطمینان از سال جاری
  // - استخدام قبل از امسال: سقف کامل سالانه برای درخواست در طول سال (مانده = سقف − مصرف)
  // - استخدام امسال: تناسب از تاریخ استخدام (computeAccruedLeaveDaysW)
  const row = emp.leaveYears[String(cy)];
  row.entitled = getAnnualLeaveDaysForEmp(obj, emp);
  const accrued = computeAccruedLeaveDaysW(obj, emp, cy);
  row.accrued = accrued;
  if (row.settled) {
    row.remaining = 0;
  } else {
    let adjPos = 0;
    (emp.leaveAdjustments || []).forEach(function (a) {
      if (String(a.year) !== String(cy)) return;
      const d = Number(a.delta) || 0;
      if (d > 0) adjPos += d;
    });
    const baseForRemain = accrued;
    row.remaining = Math.round((baseForRemain - Number(row.used || 0) + adjPos) * 100) / 100;
  }
  // فیلد سازگاری: فقط مانده سال جاری (نه تجمیع سال‌های قبل)
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


/** روز هفته جلالی → 0=یکشنبه … 6=شنبه (مطابق Date.getUTCDay) */
function jalaliWeekday(jy, jm, jd) {
  // تبدیل تقریبی جلالی به میلادی (الگوریتم رایج)
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
    { id: 'normal', name: 'عادی' },
    { id: 'daily', name: 'روزمزد' },
    { id: 'hourly', name: 'ساعتی' }
  ];
}

/** تعطیلات رسمی شمسی ثابت (بدون مناسبت‌های قمری که هر سال جابه‌جا می‌شوند) */
function defaultIranHolidaysForYear(year) {
  year = Number(year);
  function d(m, day) {
    return year + '/' + String(m).padStart(2, '0') + '/' + String(day).padStart(2, '0');
  }
  return [
    d(1, 1), d(1, 2), d(1, 3), d(1, 4), // نوروز
    d(1, 12), // روز جمهوری اسلامی
    d(1, 13), // روز طبیعت
    d(3, 14), // رحلت امام خمینی
    d(3, 15), // قیام ۱۵ خرداد
    d(11, 22), // پیروزی انقلاب
    d(12, 29) // ملی شدن صنعت نفت
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
  if (!Array.isArray(s.contractTypesList) || !s.contractTypesList.length) {
    s.contractTypesList = defaultContractTypesList();
  }
  if (!s.contractCalendars || typeof s.contractCalendars !== 'object') s.contractCalendars = {};
  const cy = Number(s.currentYear) || 1405;

  // مهاجرت یک‌باره از تنظیمات سراسری — کپی عمیق تا اشتراک مرجع نباشد
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
      // تقویم جدید: پیش‌فرض ایران، مستقل از انواع دیگر (کپی از لیست پیش‌فرض نه از نوع دیگر)
      const hy = {};
      hy[String(cy)] = defaultIranHolidaysForYear(cy);
      s.contractCalendars[t.id] = Object.assign({
        workWeekDays: [6, 0, 1, 2, 3], // شنبه تا چهارشنبه؛ پنجشنبه و جمعه تعطیل
        countNonWorkDaysAsLeave: false,
        holidaysByYear: hy
      }, defaultWorkSchedule());
    } else {
      // اطمینان از وجود آرایه تعطیلات سال جاری بدون پاک کردن سال‌های دیگر
      const cal = s.contractCalendars[t.id];
      if (!cal.holidaysByYear || typeof cal.holidaysByYear !== 'object') cal.holidaysByYear = {};
      if (!Array.isArray(cal.workWeekDays) || !cal.workWeekDays.length) {
        cal.workWeekDays = [6, 0, 1, 2, 3];
      }
      // ترمیم: مقادیر نوع «ساعتی» (۰۰:۰۰ تا ۲۳:۵۹، شناوری ۰، هر ۷ روز هفته) به‌اشتباه روی نوع دیگری ذخیره شده بود
      if (t.id !== 'hourly'
        && cal.workStart === '00:00' && cal.workEnd === '23:59'
        && Number(cal.floatMinutes) === 0 && !cal.hasBreak
        && cal.workWeekDays.length >= 7) {
        const dws = defaultWorkSchedule();
        cal.workWeekDays = [6, 0, 1, 2, 3];
        Object.keys(dws).forEach(function (k) { cal[k] = dws[k]; });
      }
      // فقط اگر کلید سال اصلاً وجود ندارد پیش‌فرض بگذار؛ آرایه خالی = ادمین عمداً پاک کرده
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

function normalizeWorkSchedule(cal) {
  const d = defaultWorkSchedule();
  const c = cal || {};
  const hasBreak = c.hasBreak != null ? !!c.hasBreak : !!(c.breakStart && c.breakEnd && c._breakExplicit);
  // اگر hasBreak صریح نباشد ولی breakStart/End ذخیره شده و قبلاً استفاده شده
  const hb = c.hasBreak != null ? !!c.hasBreak : false;
  return {
    workStart: c.workStart || d.workStart,
    workEnd: c.workEnd || d.workEnd,
    hasBreak: hb,
    breakStart: c.breakStart != null ? c.breakStart : d.breakStart,
    breakEnd: c.breakEnd != null ? c.breakEnd : d.breakEnd,
    breakCountsAsWork: hb && !!c.breakCountsAsWork,
    dayEnd: c.dayEnd || d.dayEnd,
    floatMinutes: Math.max(0, (c.floatMinutes != null && c.floatMinutes !== '') ? Number(c.floatMinutes) : d.floatMinutes),
    floatCompensate: c.floatCompensate != null ? !!c.floatCompensate : !!d.floatCompensate
  };
}

function getContractCalendar(obj, contractType) {
  ensureContractCalendars(obj || {});
  const s = (obj && obj.settings) || {};
  const ct = String(contractType || 'normal').trim() || 'normal';
  const cal = (s.contractCalendars && s.contractCalendars[ct]) || (s.contractCalendars && s.contractCalendars.normal) || {};
  const sched = normalizeWorkSchedule(cal);
  // ساعتی: بازه کاری کل شبانه‌روز (حضور هر ساعتی معتبر است)
  const hourlyAllDay = (ct === 'hourly');
  return {
    _contractType: ct,
    workWeekDays: hourlyAllDay
      ? [0, 1, 2, 3, 4, 5, 6]
      : (Array.isArray(cal.workWeekDays) ? cal.workWeekDays.map(Number) : [6, 0, 1, 2, 3]),
    countNonWorkDaysAsLeave: !!cal.countNonWorkDaysAsLeave,
    holidaysByYear: (cal.holidaysByYear && typeof cal.holidaysByYear === 'object') ? cal.holidaysByYear : {},
    workStart: hourlyAllDay ? '00:00' : sched.workStart,
    workEnd: hourlyAllDay ? '23:59' : sched.workEnd,
    hasBreak: hourlyAllDay ? false : sched.hasBreak,
    breakStart: sched.breakStart,
    breakEnd: sched.breakEnd,
    breakCountsAsWork: hourlyAllDay ? false : sched.breakCountsAsWork,
    dayEnd: hourlyAllDay ? '23:59' : sched.dayEnd,
    floatMinutes: hourlyAllDay ? 0 : sched.floatMinutes,
    floatCompensate: hourlyAllDay ? false : sched.floatCompensate,
    daySchedules: (cal.daySchedules && typeof cal.daySchedules === 'object') ? cal.daySchedules : {}
  };
}

/** برنامه موظفی یک روز خاص — در صورت نبود، برنامه پیش‌فرض نوع قرارداد */
function getDayWorkSchedule(cal, y, m, d) {
  const base = normalizeWorkSchedule(cal);
  if (!cal || !cal.daySchedules) return base;
  const keySlash = y + '/' + String(m).padStart(2, '0') + '/' + String(d).padStart(2, '0');
  const keyDash = y + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
  const over = cal.daySchedules[keySlash] || cal.daySchedules[keyDash] || null;
  if (!over || typeof over !== 'object') return base;
  const out = Object.assign({}, base);
  if (over.workStart) out.workStart = String(over.workStart).trim();
  if (over.workEnd) out.workEnd = String(over.workEnd).trim();
  if (over.dayEnd) out.dayEnd = String(over.dayEnd).trim();
  if (over.floatMinutes != null && over.floatMinutes !== '') out.floatMinutes = Math.max(0, Number(over.floatMinutes) || 0);
  if (over.hasBreak != null) out.hasBreak = !!over.hasBreak;
  if (over.breakStart) out.breakStart = String(over.breakStart).trim();
  if (over.breakEnd) out.breakEnd = String(over.breakEnd).trim();
  if (over.breakCountsAsWork != null) out.breakCountsAsWork = !!over.breakCountsAsWork;
  out._fromDaySchedule = true;
  out._dayKey = keySlash;
  return out;
}

/** HH:MM یا HH:MM:SS → دقیقه از نیمه‌شب (۰..۱۴۳۹+) */
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

/** مدت شیفت رسمی (دقیقه) با احتساب وقفه */
function officialWorkMinutes(cal) {
  const sched = normalizeWorkSchedule(cal);
  const a = timeToMinutes(sched.workStart);
  const b = timeToMinutes(sched.workEnd);
  if (a == null || b == null) return 0;
  let total = b - a;
  if (total < 0) total += 24 * 60; // شب‌کار
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
 * محاسبه یک روز کارکرد از ورود/خروج‌ها
 * punches: [{in:'08:05', out:'12:00'}, {in:'13:00', out:'17:10'}] یا in1,out1,in2,out2
 * نتیجه: دقیقه کار خالص، تأخیر، تعجیل خروج، اضافه‌کار، شناوری جبران‌شده
 */

/** همپوشانی دو بازه به دقیقه */
function overlapMinutes(a0, a1, b0, b1) {
  const s = Math.max(a0, b0);
  const e = Math.min(a1, b1);
  return Math.max(0, e - s);
}
/** دقیقه شب‌کاری در بازه حضور: ۲۲:۰۰ تا ۰۶:۰۰ (روز بعد) */
function nightMinutesInPair(inn, out) {
  if (inn == null || out == null) return 0;
  let a = inn, b = out;
  if (b < a) b += 24 * 60;
  // شب: 22:00 (1320) تا 24:00 و 0 تا 6:00 (360) — برای بازه‌ای که از نیمه‌شب رد می‌شود
  let n = 0;
  // قسمت اول روز: 0..1440
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
 * متادیتای روز از تقویم: تعطیل رسمی / تعطیل شرایطی / نیمه‌روز
 * holidaysByYear[year] می‌تواند رشته تاریخ یا آبجکت باشد
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
  // فقط تعطیلات تقویم همان نوع قرارداد — نه تعطیلات سراسری مشترک
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
  // ساعتی: فقط تعطیلات ثبت‌شده در تقویم خودش — آخر هفته به‌عنوان تعطیل رنگ نمی‌شود
  // (حضور در هر روز/ساعت ممکن است)
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

/** همیشه HH:MM — مثلاً 00:00 یا 08:45 یا 32:20 */
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
  if (opts.daySchedule && typeof opts.daySchedule === 'object') {
    sched = Object.assign({}, normalizeWorkSchedule(cal), opts.daySchedule);
  } else if (opts.year != null && opts.month != null && opts.day != null) {
    sched = getDayWorkSchedule(cal, opts.year, opts.month, opts.day);
  } else if (opts.dateKey) {
    const pp = String(opts.dateKey).replace(/-/g, '/').split('/');
    if (pp.length >= 3) sched = getDayWorkSchedule(cal, Number(pp[0]), Number(pp[1]), Number(pp[2]));
    else sched = normalizeWorkSchedule(cal);
  } else {
    sched = normalizeWorkSchedule(cal);
  }
  const start = timeToMinutes(sched.workStart);
  const end = timeToMinutes(sched.workEnd);
  const dayEnd = timeToMinutes(sched.dayEnd);
  const floatM = isHourly ? 0 : sched.floatMinutes;
  const compensate = isHourly ? false : (!!sched.floatCompensate || !!opts.floatCompensate);
  const official = isHourly ? 0 : officialWorkMinutes(sched);

  // نرمال‌سازی پانچ‌ها
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
  // فقط جفت کامل (ورود+خروج) در کارکرد شمرده می‌شود
  const completePairs = pairs.filter(function (p) { return p.inn != null && p.out != null; });
  const incompletePairs = pairs.filter(function (p) { return p.inn == null || p.out == null; });

  let present = 0;
  completePairs.forEach(function (p) {
    let a = p.inn, b = p.out;
    if (b < a) b += 24 * 60;
    present += Math.max(0, b - a);
  });

  // کسر وقفه فقط اگر وقفه فعال و جزو کار نباشد (برای ساعتی اعمال نمی‌شود)
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

  // —— قرارداد ساعتی: فقط مجموع حضور جفت‌های کامل؛ بدون موظفی/غیبت/شناوری/اضافه‌کار/شب‌کاری ——
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
   * شناوری:
   * - اگر ورود در بازه [start, start+float] باشد → می‌تواند همان میزان تأخیر را با ماندن بعد از end جبران کند (حداکثر float)
   * - اگر ورود بعد از start+float باشد → شناوری اعمال نمی‌شود؛ جبران فقط اگر تیک floatCompensate زده شده باشد
   * - ماندن بعد از end بدون حق جبران = اضافه‌کار
   */
  let delay = 0;          // تأخیر ورود نسبت به start (قبل از جبران)
  let earlyLeave = 0;     // تعجیل خروج نسبت به end (قبل از جبران)
  let compensated = 0;    // دقایق جبران‌شده با ماندن بعد از end
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

  // جبران: فقط داخل شناوری (خودکار) یا با تیک floatCompensate
  const canCompensate = withinFloat || !!compensate;
  if (hasComplete && canCompensate && delay > 0 && lastOut != null && end != null) {
    const stayedPast = Math.max(0, lastOut - end);
    // حداکثر جبران = min(تأخیر، ماندن بعد از پایان، و اگر فقط شناوری باشد سقف float)
    let maxComp = delay;
    if (withinFloat && !compensate) {
      maxComp = Math.min(delay, floatM || 0);
    }
    compensated = Math.min(maxComp, stayedPast);
    delay = Math.max(0, delay - compensated);
    // اضافه‌کار = ماندن بعد از end فراتر از جبران
    ot = Math.max(0, stayedPast - compensated);
    // تعجیل فقط اگر زودتر از end رفته (و جبران صبح از end جداست)
    if (lastOut < end) {
      earlyLeave = end - lastOut;
    } else {
      earlyLeave = 0;
    }
  } else if (hasComplete && lastOut != null && end != null) {
    // بدون حق جبران: ماندن بعد از end = OT؛ تأخیر کامل می‌ماند
    if (lastOut > end) {
      ot = lastOut - end;
      earlyLeave = 0;
    } else {
      earlyLeave = end - lastOut;
      ot = 0;
    }
  }
  // تردد ناقص بدون جفت کامل: کارکرد صفر — delay/early جداگانه معنا ندارد

  // شب‌کاری: فقط ۲۲:۰۰–۰۶:۰۰ (جزو اضافه‌کار عادی نیست)
  let nightMin = 0;
  completePairs.forEach(function (p) {
    nightMin += nightMinutesInPair(p.inn, p.out);
  });

  // اضافه‌کار قبل از شروع (اختیاری per opts.earlyOtEnabled)
  let earlyOtMin = 0;
  const earlyOtOn = !!opts.earlyOtEnabled;
  if (earlyOtOn && start != null) {
    // پیش‌فرض: از (شروع − ۴۴ دقیقه) مثلاً ۰۶:۰۱ تا ۰۶:۴۵ — قابل تنظیم با earlyOtFrom
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

  // روز تعطیل/غیرکاری یا تعطیل شرایطی
  let workPresent = present;
  const dayMeta = opts.dayMeta || null;
  const isCondMeta = !!(dayMeta && (dayMeta.conditional || dayMeta.type === 'conditional'));
  // تمام‌روز: شرایطی بدون closeFrom (یا fullDay صریح)
  const condFull = isCondMeta && !dayMeta.closeFrom && (dayMeta.fullDay !== false);
  const condHalf = isCondMeta && !!dayMeta.closeFrom;
  const forceNoFloat = dayMeta && dayMeta.applyFloat === false;

  // حضور فقط داخل بازه موظفی [start, end] — مبنای کارکرد و کسری
  // جبران شناوری/تیک جبران: دقایق compensated به کارکرد اضافه و از کسری کم می‌شود
  // خارج شناوری بدون تیک جبران: compensated=0 → شکاف صبح + شکاف عصر هر دو کسری‌اند (دو مرخصی/مأموریت)
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
  // کارکرد مؤثر = حضور در پنجره + جبران معتبر (ماندن بعد از پایان که تأخیر صبح را پوشاند)
  const creditComp = (!isHoliday && !condFull && !opts.unpaidLeave && !opts.fullDayLeaveOrMission)
    ? (compensated || 0) : 0;
  let presentForShort = Math.min(present, presenceInWindow + creditComp);
  // workPresent برای روز عادی از همین مبنا (تعطیل/شرایطی پایین‌تر ممکن است بازنویسی کنند)
  if (!isHoliday && !condFull && !condHalf) {
    workPresent = presentForShort;
  }
  const beyondFloat = hasComplete && firstIn != null && start != null &&
    (firstIn - start) > (floatM || 0) && !compensate;

  if (isHoliday && present > 0 && !(dayMeta && dayMeta.conditional)) {
    // تعطیل رسمی/هفته: تمام حضور = اضافه‌کار (شب‌کاری جدا)
    ot = Math.max(0, present - nightMin);
    workPresent = 0;
    delay = 0;
    earlyLeave = 0;
    compensated = 0;
  } else if (condFull && present > 0) {
    // تعطیل شرایطی تمام‌روز
    if (dayMeta.otDuringOfficial) {
      ot = Math.max(0, present - nightMin);
      workPresent = 0;
    } else {
      // فقط بعد از موظفی اضافه‌کار
      ot = 0;
      workPresent = Math.min(present, official);
      if (dayMeta.otAfterOfficial && lastOut != null && end != null && lastOut > end) {
        ot = Math.max(0, lastOut - end - nightMin); // تقریبی
      }
    }
    delay = 0;
    earlyLeave = 0;
    compensated = 0;
  } else if (condHalf) {
    // تعطیل شرایطی از ساعت closeFrom
    const cf = timeToMinutes(dayMeta.closeFrom);
    if (cf != null) {
      // کارکرد فقط تا closeFrom
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
      // بعد از closeFrom تا end (یا بعد) = اضافه‌کار در صورت otAfterOfficial
      let afterClose = 0;
      completePairs.forEach(function (p) {
        let a = p.inn, b = p.out;
        if (b < a) b += 24 * 60;
        afterClose += overlapMinutes(a, b, cf, dayMeta.otAfterOfficial ? (lastOut != null ? Math.max(lastOut, end || cf) : (end || cf + 60)) : cf);
      });
      if (dayMeta.otAfterOfficial) ot = Math.max(0, afterClose - nightMin);
      else ot = 0;
      // بدون شناوری
      if (forceNoFloat) {
        delay = 0;
        compensated = 0;
        // تأخیر واقعی اگر بعد از start آمده تا closeFrom
        if (firstIn != null && start != null && firstIn > start && firstIn < cf) {
          delay = firstIn - start;
        }
        earlyLeave = 0;
      }
    }
  }

  // ── جداسازی قطعی اضافه‌کار و شب‌کاری ──
  // هر دقیقه حضور در ۲۲:۰۰–۰۶:۰۰ = شب‌کاری (نه اضافه‌کار)
  // اضافه‌کار = حضور بعد از پایان شیفت که داخل بازه شب نباشد
  nightMin = 0;
  completePairs.forEach(function (p) {
    nightMin += nightMinutesInPair(p.inn, p.out);
  });

  if (hasComplete && lastOut != null && end != null && lastOut > end && !isHoliday && !condFull && !condHalf) {
    // روز عادی: اضافه‌کار فقط بعد از پایان شیفت (منهای شب‌کاری و جبران شناوری)
    let stayed = Math.max(0, lastOut - end);
    stayed = Math.max(0, stayed - (compensated || 0));
    const nightInAfter = nightMinutesInPair(end, lastOut);
    ot = Math.max(0, stayed - nightInAfter);
  } else if (isHoliday && !condFull && !condHalf && present > 0) {
    // تعطیل رسمی/هفته (نه شرایطی): کل حضور غیرشب = اضافه‌کار
    // تعطیل شرایطی قبلاً با فلگ otDuringOfficial / otAfterOfficial محاسبه شده — اینجا بازنویسی نشود
    ot = Math.max(0, present - nightMin);
    workPresent = 0;
  }
  // condFull / condHalf: مقدار ot از بلوک بالاتر حفظ می‌شود
  ot = Math.max(0, ot || 0);

  // در تعطیل شرایطی اگر «حضور در موظفی = اضافه‌کار» خاموش باشد، اضافه‌کار قبل از شروع هم صفر
  if (condFull && dayMeta && dayMeta.otDuringOfficial === false) {
    earlyOtMin = 0;
  }
  if (condHalf && dayMeta && dayMeta.otAfterOfficial === false && dayMeta.otDuringOfficial === false) {
    earlyOtMin = 0;
  }
  // early OT جدا از ot نگه داشته می‌شود (earlyOtMin)


  // غیبت ساعتی:
  // - روز مرخصی/مأموریت روزانه (غیر بدون‌حقوق) → صفر
  // - مرخصی بدون حقوق → کل موظفی
  // - روز عادی → کمبود پس از حضور + پوشش ساعتی
  let covered = Number(opts.coveredMinutes) || 0;
  // فقط بخشی از مرخصی/مأموریت ساعتی که روی «غیبت واقعی» داخل [شروع، پایان] می‌افتد پوشش حساب می‌شود
  // (بازه تکراری/هم‌پوشان یا بازه‌ای که فرد حاضر بوده، کسری را پر نمی‌کند)
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
  if (holidayFull) {
    shortfall = 0;
  } else if (condHalf && dayMeta && dayMeta.closeFrom) {
    // موظفی فقط تا ساعت تعطیل شرایطی
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
    // کسری = موظفی − (حضور در پنجره + جبران معتبر) − پوشش ساعتی
    // مثال بدون جبران: ورود ۰۷:۰۱ خروج ۱۵:۲۵ → حضور‌پنجره ۵۰۴، کسری ۲۱ (۱۶ صبح + ۵ عصر)
    // مثال با جبران: ورود ۰۷:۱۵ خروج ۱۶:۰۰ → حضور‌پنجره ۴۹۵ + جبران ۳۰ = ۵۲۵، کسری ۰
    shortfall = Math.max(0, official - presentForShort - covered);
  }

  // کارکرد نمایشی: حضور + پوشش ساعتی (تا سقف موظفی) — وقتی کسری پر شد = موظفی کامل
  let displayWorkMin = workPresent + (isHoliday ? 0 : covered);
  if (!isHoliday && !opts.unpaidLeave) {
    if (opts.fullDayLeaveOrMission) displayWorkMin = official;
    else displayWorkMin = Math.min(official, displayWorkMin);
  }
  // فرمت ساعت: دقیقه → «ساعت:دقیقه» مثلاً 8:45
  function fmtHM(mins) {
    return formatHoursHM(mins);
  }

  // تجمیع اضافه‌کار قبل با اضافه‌کار معمول
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
  function metaIsFullHoliday(meta) {
    if (!meta) return false;
    if (meta.conditional && meta.fullDay === false) return false;
    return true;
  }
  if (metaIsFullHoliday(getDayMeta(obj, y, m, d, contractType))) return true;
  // جستجو در همه تقویم‌های قرارداد (اگر نوع قرارداد کارمند با تقویم ذخیره‌شده فرق داشت)
  try {
    const cals = (obj && obj.settings && obj.settings.contractCalendars) || {};
    const keys = Object.keys(cals);
    for (let i = 0; i < keys.length; i++) {
      if (String(keys[i]) === String(contractType || 'normal')) continue;
      if (metaIsFullHoliday(getDayMeta(obj, y, m, d, keys[i]))) return true;
    }
  } catch (e) {}
  return false;
}

function getWorkWeekSettings(obj, contractType) {
  const cal = getContractCalendar(obj, contractType);
  return {
    workWeekDays: cal.workWeekDays,
    countNonWorkDaysAsLeave: cal.countNonWorkDaysAsLeave
  };
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


/** تعداد روزهای کاری (غیرتعطیل) در بازه، محدود به یک ماه */
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

/** همه روزهای تقویمی در بازه (با تعطیل) — برای مأموریت */
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
    const has = !!(c.in1 || c.out1 || c.in2 || c.out2 || c.leaveDaily || c.missionDaily || c.leaveHourly || c.missionHourly);
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
    const hasPunch = !!(c.in1 || c.out1 || c.in2 || c.out2);
    const hasLeaveMis = !!(c.leaveDaily || c.missionDaily);
    if (hasPunch || hasLeaveMis) n++;
  });
  return n;
}

/** کارکرد ماه = روزهای عادی تا آخرین پانچ/مرخصی/مأموریت */
/** تشخیص مرخصی بدون حقوق از روی نوع/نام */

/** مرخصی/مأموریت ساعتی فقط داخل بازه موظفی (مثلاً 06:45–15:30) */

/** ورود/خروج ناقص: ورود بدون خروج یا خروج بدون ورود */
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
    return { ok: false, message: 'ساعت موظفی برای نوع قرارداد تعریف نشده است.' };
  }
  if (a == null || b == null) {
    return { ok: false, message: 'ساعت شروع/پایان نامعتبر است.' };
  }
  if (b <= a) {
    return { ok: false, message: 'ساعت پایان باید بعد از ساعت شروع باشد.' };
  }
  if (a < start || b > end) {
    return {
      ok: false,
      message: 'مرخصی/مأموریت ساعتی فقط داخل ساعت موظفی (' + (sched.workStart || '') + ' تا ' + (sched.workEnd || '') + ') مجاز است و نمی‌تواند قبل یا بعد از آن باشد.'
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
  if (name.indexOf('بدون حقوق') >= 0 || name.indexOf('بدون‌حقوق') >= 0) return true;
  // از تعریف انواع در settings
  try {
    const types = (obj && obj.settings && obj.settings.attendanceTypes) || [];
    const t = types.find(function (x) { return String(x.id) === String(req.typeId); });
    if (t && (t.unpaid === true || t.isUnpaid === true || String(t.name || '').indexOf('بدون حقوق') >= 0)) return true;
  } catch (e) {}
  return false;
}

/** مرخصی استعلاجی بلندمدت — در کارکرد شمرده نمی‌شود */
function isLongTermSickLeaveRequest(obj, req) {
  if (!req) return false;
  if (req.longTermSick === true || req.isLongTermSick === true) return true;
  const name = String(req.typeName || req.name || '').trim();
  if (/استعلاجی\s*بلند\s*مدت|استعلاجی\s*بلندمدت|مرخصی\s*استعلاجی\s*بلند/.test(name)) return true;
  try {
    const typesA = (obj && obj.attendanceTypes) || [];
    const typesB = (obj && obj.settings && obj.settings.attendanceTypes) || [];
    const types = typesA.concat(typesB);
    const t = types.find(function (x) { return String(x.id) === String(req.typeId); });
    if (t) {
      if (t.longTermSick === true || t.isLongTermSick === true) return true;
      if (/استعلاجی\s*بلند\s*مدت|استعلاجی\s*بلندمدت/.test(String(t.name || ''))) return true;
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
  // اجتماع بازه‌ها: مرخصی/مأموریت ساعتی تکراری یا هم‌پوشان فقط یک‌بار شمرده شود
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


/** اجتماع بازه‌های مرخصی/مأموریت ساعتی روز (برای پوشش دقیق غیبت) */
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

/** پاک‌سازی توضیح از متن‌های خودکار پوشش کسر و تکراری‌ها */
function cleanTimesheetNote(note) {
  if (!note) return '';
  const seen = {};
  return String(note).split(/[؛;]+/).map(function (s) { return s.trim(); }).filter(function (s) {
    if (!s) return false;
    if (s.indexOf('ثبت خودکار') >= 0 || s.indexOf('پوشش کسر') >= 0) return false;
    const k = s.replace(/\s+/g, ' ');
    if (seen[k]) return false;
    seen[k] = true;
    return true;
  }).join('؛ ');
}

function empOtCeilingHours(emp) {
  if (!emp) return null;
  const v = emp.otCeilingHours != null ? emp.otCeilingHours
    : (emp.maxOtHours != null ? emp.maxOtHours
    : (emp.otLimit != null ? emp.otLimit
    : (emp.otCeiling != null ? emp.otCeiling : null)));
  if (v === '' || v == null) return null;
  const n = Number(v);
  return isFinite(n) && n >= 0 ? n : null;
}

function recountEmpMonthWorkDays(obj, year, month, code) {
  /* کارکرد ماه:
     - تعطیلات اول ماه (قبل از اولین حضور، اگر بعداً حضور باشد) جزو کارکرد
     - تعطیلات آخر ماه (بعد از آخرین حضور، اگر قبلاً حضور باشد) جزو کارکرد
     - تعطیلات فی‌مابین و پایان‌هفته در طول ماه جزو کارکرد
     - تردد کامل / مرخصی / مأموریت (جز بدون‌حقوق و استعلاجی بلندمدت) = روز کارکرد
     - روز کاری کاملاً خالی از کارکرد کسر می‌شود
     - محدوده استخدام/پایان همکاری در همان ماه رعایت می‌شود
  */
  year = Number(year); month = Number(month);
  const dim = daysInJalaliMonth(year, month);
  const emp = ((obj.employees || []).find(function (e) { return String(e.code) === String(code); })) || null;
  const ct = (emp && emp.contractType) || 'normal';

  // محدوده استخدام / خاتمه در این ماه
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

  const punchStore = ((obj.dailyAttendance || {})[String(code)]) || {};
  const dayInfo = {};
  for (let d = fromD; d <= toD; d++) {
    const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
    const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0');
    const punch = punchStore[dk] || punchStore[dateFa] || {};
    let hasCompletePunch = false;
    for (let pi = 1; pi <= 4; pi++) {
      if (String(punch['in' + pi] || '').trim() && String(punch['out' + pi] || '').trim()) {
        hasCompletePunch = true;
        break;
      }
    }
    const nonWork = isHolidayOrNonWork(obj, year, month, d, ct);
    dayInfo[d] = {
      nonWork: nonWork,
      activity: hasCompletePunch,
      punch: hasCompletePunch
    };
  }

  // مرخصی / مأموریت تأییدشده
  (obj.attendanceRequests || []).forEach(function (x) {
    if (String(x.empCode) !== String(code) || x.status !== 'approved') return;
    if (x.kind !== 'leave' && x.kind !== 'mission') return;
    if (x.kind === 'leave' && isUnpaidLeaveRequest(obj, x)) return;
    if (x.kind === 'leave' && typeof isLongTermSickLeaveRequest === 'function' && isLongTermSickLeaveRequest(obj, x)) return;

    if (x.mode === 'hourly') {
      const p = parseJalaliYMD(x.startDate);
      if (!p || p.y !== year || p.m !== month) return;
      if (p.d < fromD || p.d > toD) return;
      if (!dayInfo[p.d]) return;
      dayInfo[p.d].activity = true;
      return;
    }
    // روزانه
    const keys = (typeof listDayKeys === 'function') ? listDayKeys(x.startDate, x.endDate || x.startDate) : [];
    keys.forEach(function (k) {
      const parts = String(k).split(/[-\/]/);
      if (parts.length < 3) return;
      const yy = Number(parts[0]), mm = Number(parts[1]), dd = Number(parts[2]);
      if (yy !== year || mm !== month) return;
      if (dd < fromD || dd > toD) return;
      if (!dayInfo[dd]) return;
      dayInfo[dd].activity = true;
    });
  });

  // وضعیت استعلاجی/تعلیق بلندمدت کارت: روزهای بازه special را فعالیت نکن (کارکرد نیست)
  try {
    if (emp && (emp.status === 'sick' || emp.status === 'suspend')) {
      // اگر تابع شمارش موجود باشد از همان منطق بازه استفاده می‌کنیم
      for (let d = fromD; d <= toD; d++) {
        if (typeof countSpecialDaysInMonth === 'function') {
          // تقریبی: اگر کل ماه special است و تاریخ‌ها کل ماه را پوشش می‌دهد
        }
      }
    }
  } catch (eS) {}

  // اولین و آخرین روز دارای حضور/فعالیت
  let firstAct = 0, lastAct = 0;
  for (let d = fromD; d <= toD; d++) {
    if (dayInfo[d] && dayInfo[d].activity) {
      if (!firstAct) firstAct = d;
      lastAct = d;
    }
  }
  if (!firstAct || !lastAct) return 0;

  /* کارکرد:
     ۱) تعطیلات اول ماه (از fromD تا قبل از اولین حضور) — چون بعداً کارکرد دارد
     ۲) تعطیلات فی‌مابین اولین تا آخرین حضور
     ۳) تعطیلات آخر ماه (بعد از آخرین حضور تا toD) — چون قبلش کارکرد داشته
     ۴) روزهای دارای تردد / مرخصی / مأموریت
     ۵) روز کاری کاملاً خالی → شمرده نمی‌شود (کسر کارکرد)
  */
  let n = 0;
  for (let d = fromD; d <= toD; d++) {
    const info = dayInfo[d];
    if (!info) continue;
    if (info.nonWork) {
      // تعطیل اول / وسط / آخر ماه — همگی با وجود حداقل یک روز حضور در ماه
      n++;
    } else if (info.activity) {
      n++;
    }
    // روز کاری خالی: هیچ
  }
  return n;
}


function countLeaveDays(req, obj, contractType) {
  if (!req) return 0;
  if (req.mode === 'hourly') {
    const ft = String(req.fromTime || '00:00').split(':');
    const tt = String(req.toTime || '00:00').split(':');
    const h1 = Number(ft[0]) + Number(ft[1] || 0) / 60;
    const h2 = Number(tt[0]) + Number(tt[1] || 0) / 60;
    let hrs = h2 - h1;
    if (hrs < 0) hrs = 0;
    return Math.round((hrs / 8) * 100) / 100;
  }
  if (req.fixedDays) return Number(req.fixedDays) || 1;
  const ct = contractType || (req && req.contractType) || 'normal';
  if (typeof listDayKeys === 'function' && req.startDate) {
    try {
      const keys = listDayKeys(req.startDate, req.endDate || req.startDate);
      const ws = getWorkWeekSettings(obj || {}, ct);
      if (ws.countNonWorkDaysAsLeave) return keys.length || 1;
      let n = 0;
      keys.forEach(function (k) {
        const parts = String(k).split(/[-\/]/);
        if (parts.length < 3) { n++; return; }
        const yy = Number(parts[0]), mm = Number(parts[1]), dd = Number(parts[2]);
        if (isHolidayOrNonWork(obj, yy, mm, dd, ct)) return;
        n++;
      });
      return n || 0;
    } catch (e) {}
  }
  return 1;
}


/** کسر از سال جاری؛ در صورت نیاز و موافقت، از سال‌های قبلِ تسویه‌نشده */
function applyLeaveDeduction(obj, req) {
  if (!req || req.status !== 'approved') return;
  if (!req.deductFromEntitlement) return;
  if (req.kind !== 'leave') return;
  if (req._leaveDeducted) return;
  const emp = (obj.employees || []).find(function (e) { return String(e.code) === String(req.empCode); });
  if (!emp) return;
  ensureEmpLeaveYears(emp, obj);
  const cy = Number((obj.settings || {}).currentYear) || 1405;
  const days = countLeaveDays(req, obj, emp.contractType);
  let left = days;
  const detail = [];
  const annual = getAnnualLeaveDaysForEmp(obj, emp);
  const cur = getLeaveYearRow(emp, cy);
  if (!cur.settled) {
    const used = Number(cur.used) || 0;
    const room = Math.max(0, annual - used);
    const take = Math.min(room > 0 ? room : left, left); // تا سقف سالانه از سال جاری
    // اگر room=0 ولی left>0، به prior می‌رود؛ اگر prior هم نبود در ادامه overdraft
    const takeCur = Math.min(left, Math.max(room, 0));
    // اجازه استفاده تا سقف: اگر room >= left همه از جاری
    if (left > 0) {
      const t = (room >= left) ? left : Math.max(room, 0);
      if (t > 0) {
        cur.used = Math.round((used + t) * 100) / 100;
        left = Math.round((left - t) * 100) / 100;
        detail.push({ year: cy, days: t });
      }
    }
  }
  // سپس سال‌های قبل (قدیمی‌تر اول) اگر usePriorYears
  if (left > 0 && req.usePriorYears) {
    const years = listLeaveYearsSorted(emp).map(function (r) { return r.year; }).filter(function (y) { return y < cy; });
    for (let i = 0; i < years.length && left > 0; i++) {
      const row = getLeaveYearRow(emp, years[i]);
      if (row.settled) continue;
      const take = Math.min(Math.max(0, Number(row.remaining) || 0), left);
      if (take <= 0) continue;
      row.remaining = Math.round((Number(row.remaining) - take) * 100) / 100;
      row.used = Math.round((Number(row.used || 0) + take) * 100) / 100;
      left = Math.round((left - take) * 100) / 100;
      detail.push({ year: years[i], days: take });
      req.usedPriorYears = true;
    }
  }
  // اگر هنوز مانده (بیش‌تر از موجودی) از سال جاری منفی کن تا بدهی مشخص شود
  if (left > 0) {
    cur.remaining = Math.round((Number(cur.remaining) - left) * 100) / 100;
    cur.used = Math.round((Number(cur.used || 0) + left) * 100) / 100;
    detail.push({ year: cy, days: left, overdraft: true });
    left = 0;
  }
  // به‌روزمانده نمایشی = استحقاق تناسبی − used
  const accrued = computeAccruedLeaveDaysW(obj, emp, cy);
  cur.accrued = accrued;
  cur.remaining = Math.round((accrued - Number(cur.used || 0)) * 100) / 100;
  emp.leaveBalance = Number(cur.remaining) || 0;
  emp.leaveUsedYear = Number(cur.used) || 0;
  emp.leaveBalanceYear = cy;
  req._leaveDeducted = true;
  req.leaveDaysDeducted = days;
  req.leaveDeductDetail = detail;
  if (req.usedPriorYears) {
    req.managerNote = 'کارمند سقف/مانده مرخصی امسال را کامل استفاده کرده و از ذخیره سال‌های قبل استفاده می‌کند: ' +
      detail.filter(function (d) { return d.year < cy; }).map(function (d) { return d.year + '(' + d.days + ' روز)'; }).join('، ');
  }
}

function restoreLeaveDeduction(obj, req) {
  if (!req || !req._leaveDeducted) return;
  const emp = (obj.employees || []).find(function (e) { return String(e.code) === String(req.empCode); });
  if (!emp) return;
  ensureEmpLeaveYears(emp, obj);
  const detail = Array.isArray(req.leaveDeductDetail) ? req.leaveDeductDetail : null;
  if (detail && detail.length) {
    detail.forEach(function (d) {
      const row = getLeaveYearRow(emp, d.year);
      const days = Number(d.days) || 0;
      row.remaining = Math.round((Number(row.remaining || 0) + days) * 100) / 100;
      row.used = Math.round(Math.max(0, (Number(row.used || 0) - days)) * 100) / 100;
    });
  } else {
    const days = Number(req.leaveDaysDeducted) || countLeaveDays(req, obj);
    const cy = Number((obj.settings || {}).currentYear) || 1405;
    const cur = getLeaveYearRow(emp, cy);
    cur.remaining = Math.round((Number(cur.remaining || 0) + days) * 100) / 100;
    cur.used = Math.round(Math.max(0, (Number(cur.used || 0) - days)) * 100) / 100;
  }
  emp.leaveBalance = sumUnsettledLeaveRemaining(emp);
  const cy = Number((obj.settings || {}).currentYear) || 1405;
  emp.leaveUsedYear = Number((emp.leaveYears[String(cy)] || {}).used) || 0;
  req._leaveDeducted = false;
  req.usedPriorYears = false;
}

/** خلاصه موجودی برای ثبت درخواست */

function rebuildEmpLeaveUsedFromRequests(obj, empCode) {
  const emp = (obj.employees || []).find(function (e) { return String(e.code) === String(empCode); });
  if (!emp) return;
  ensureEmpLeaveYears(emp, obj);
  const cy = Number((obj.settings || {}).currentYear) || 1405;
  // reset used for all unsettled years then re-apply from approved leave requests
  Object.keys(emp.leaveYears || {}).forEach(function (yk) {
    const row = emp.leaveYears[yk];
    if (!row || row.settled) return;
    // keep entitled; recompute used from requests in that year
    let used = 0;
    (obj.attendanceRequests || []).forEach(function (req) {
      if (String(req.empCode) !== String(empCode)) return;
      if (req.status !== 'approved') return;
      if (!req.deductFromEntitlement) return;
      if (req.kind !== 'leave') return;
      const detail = req.leaveDeductDetail;
      if (Array.isArray(detail) && detail.length) {
        detail.forEach(function (d) {
          if (String(d.year) === String(yk)) used += Number(d.days) || 0;
        });
      } else {
        const p = parseJalaliYMD(req.startDate);
        const y = p ? p.y : cy;
        if (String(y) === String(yk)) used += countLeaveDays(req, obj);
      }
    });
    // adjustments negative contribute to used
    (emp.leaveAdjustments || []).forEach(function (a) {
      if (String(a.year) !== String(yk)) return;
      if (Number(a.delta) < 0) used += Math.abs(Number(a.delta));
    });
    row.used = Math.round(used * 100) / 100;
    const baseRem = Math.round((Number(row.entitled) - row.used) * 100) / 100;
    // apply positive adjustments to remaining
    let adjPos = 0;
    (emp.leaveAdjustments || []).forEach(function (a) {
      if (String(a.year) !== String(yk)) return;
      if (Number(a.delta) > 0) adjPos += Number(a.delta);
    });
    row.remaining = Math.round((baseRem + adjPos) * 100) / 100;
  });
  emp.leaveBalance = sumUnsettledLeaveRemaining(emp);
  emp.leaveUsedYear = Number((emp.leaveYears[String(cy)] || {}).used) || 0;
}

function leaveAvailabilityForEmp(obj, emp, daysNeeded) {
  ensureEmpLeaveYears(emp, obj);
  const cy = Number((obj.settings || {}).currentYear) || 1405;
  const cur = getLeaveYearRow(emp, cy);
  const annual = getAnnualLeaveDaysForEmp(obj, emp);
  const used = Number(cur.used) || 0;
  // تا سقف سالانه (۳۰/۲۶/…) می‌تواند استفاده کند؛ تناسب ماه مانع ثبت نیست
  let ceilingLeft = cur.settled ? 0 : Math.round((annual - used) * 100) / 100;
  let adjPos = 0;
  (emp.leaveAdjustments || []).forEach(function (a) {
    if (String(a.year) !== String(cy)) return;
    const d = Number(a.delta) || 0;
    if (d > 0) adjPos += d;
  });
  ceilingLeft = Math.round((ceilingLeft + adjPos) * 100) / 100;
  let priorRem = 0;
  const priorRows = [];
  listLeaveYearsSorted(emp).forEach(function (r) {
    if (r.year >= cy || r.settled) return;
    const rem = Number(r.remaining) || 0;
    if (rem > 0) {
      priorRem += rem;
      priorRows.push({ year: r.year, remaining: rem });
    }
  });
  priorRem = Math.round(priorRem * 100) / 100;
  const need = Number(daysNeeded) || 0;
  return {
    currentYear: cy,
    annualDays: annual,
    usedYear: used,
    currentRemaining: ceilingLeft,
    accruedRemaining: cur.settled ? 0 : (Number(cur.remaining) || 0),
    priorRemaining: priorRem,
    priorRows: priorRows,
    totalUnsettled: Math.round((ceilingLeft + priorRem) * 100) / 100,
    needPriorYears: need > ceilingLeft && priorRem > 0,
    insufficient: need > ceilingLeft + priorRem
  };
}



async function handleEmpDecideRequest(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const r = await readBody(request);
  if (r.error) return r.error;
  const id = String(r.body.id || '');
  const decision = r.body.decision === 'approved' ? 'approved' : (r.body.decision === 'rejected' ? 'rejected' : '');
  const rejectReason = String(r.body.rejectReason || '').trim();
  if (!id || !decision) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  if (decision === 'rejected' && !rejectReason) {
    return jsonResponse({ ok: false, error: 'bad_request', message: 'دلیل رد الزامی است.' }, 400);
  }

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!Array.isArray(gd.obj.attendanceRequests)) gd.obj.attendanceRequests = [];
    const req = gd.obj.attendanceRequests.find(x => x.id === id);
    if (!req) return jsonResponse({ ok: false, error: 'not_found' }, 404);
    const isL1 = String(req.managerCode) === String(sess.code);
    const isL2 = req.managerCode2 && String(req.managerCode2) === String(sess.code);
    if (!isL1 && !isL2) {
      return jsonResponse({ ok: false, error: 'forbidden', message: 'فقط مدیر سطح ۱ یا ۲ می‌تواند تصمیم بگیرد.' }, 403);
    }
    // Level 1 acts on pending; Level 2 acts on approved_l1
    if (isL1 && req.status === 'pending') {
      if (decision === 'rejected') {
        req.status = 'rejected';
        req.rejectReason = rejectReason;
        req.decidedAt1 = new Date().toISOString();
        req.decidedBy1 = sess.code;
        req.decidedAt = req.decidedAt1;
        req.decidedBy = sess.code;
      } else if (req.managerCode2) {
        // needs second approval
        req.status = 'approved_l1';
        req.decidedAt1 = new Date().toISOString();
        req.decidedBy1 = sess.code;
      } else {
        // single manager = final
        req.status = 'approved';
        req.decidedAt1 = new Date().toISOString();
        req.decidedBy1 = sess.code;
        req.decidedAt = req.decidedAt1;
        req.decidedBy = sess.code;
      }
    } else if (isL2 && req.status === 'approved_l1') {
      if (decision === 'rejected') {
        req.status = 'rejected';
        req.rejectReason = rejectReason;
      } else {
        req.status = 'approved';
      }
      req.decidedAt2 = new Date().toISOString();
      req.decidedBy2 = sess.code;
      req.decidedAt = req.decidedAt2;
      req.decidedBy = sess.code;
    } else {
      return jsonResponse({ ok: false, error: 'already_decided', message: 'این درخواست در وضعیت فعلی برای شما قابل تصمیم‌گیری نیست.' }, 400);
    }
    
    // consume / restore admin grant linked to this request
    if (!Array.isArray(gd.obj.attendanceGrants)) gd.obj.attendanceGrants = [];
    const linkedGrant = gd.obj.attendanceGrants.find(function (g) {
      return g && (String(g.usedRequestId) === String(req.id) || (req.grantId && String(g.id) === String(req.grantId)));
    });
    if (linkedGrant) {
      if (req.status === 'approved') {
        linkedGrant.usedRequestId = req.id;
        linkedGrant.consumed = true;
        linkedGrant.consumedAt = new Date().toISOString();
        linkedGrant.consumedBy = sess.code;
      } else if (req.status === 'rejected') {
        // return grant to employee so they can use it again
        linkedGrant.usedRequestId = null;
        linkedGrant.consumed = false;
        linkedGrant.consumedAt = '';
        linkedGrant.reservedRequestId = null;
      }
    }
    // leave balance + monthly timesheet integration (idempotent flags on request)
    if (req.status === 'approved') {
      applyLeaveDeduction(gd.obj, req);
      if (!req._timesheetApplied) {
        applyApprovedRequestToTimesheet(gd.obj, req);
        req._timesheetApplied = true;
      }
    } else if (req.status === 'rejected') {
      restoreLeaveDeduction(gd.obj, req);
      if (req._timesheetApplied) {
        reverseApprovedRequestFromTimesheet(gd.obj, req);
        req._timesheetApplied = false;
      }
    }

    const put = await storePutData(cfg, gd.version, gd.obj, 'mgr:' + sess.code);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    console.log(JSON.stringify({ event: 'att_decide', id, decision, by: sess.code }));
    return jsonResponse({ ok: true, request: req });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleEmpTimesheet(request, env) {
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

  // employee sees only self; if they manage people they can request other codes
  let code = String(r.body.code || sess.code);
  if (code !== String(sess.code)) {
    // allow if manager of that person OR we could restrict to self only
    const target = (gd.obj.employees || []).find(e => String(e.code) === code);
    if (!target || String(target.managerCode) !== String(sess.code)) {
      code = String(sess.code);
    }
  }
  const key = year + '-' + month;
  const row = ((gd.obj.monthlyData || {})[key] || {})[code] || {};
  const reqs = ((gd.obj.attendanceRequests || []).filter(function (x) {
    if (String(x.empCode) !== code || x.status !== 'approved') return false;
    const p = parseJalaliYMD(x.startDate);
    if (!p) return false;
    if (p.y === year && p.m === month) return true;
    if (x.mode === 'daily' && x.endDate) {
      const chunks = splitDaysByMonth(x.startDate, x.endDate);
      return chunks.some(c => c.year === year && c.month === month);
    }
    return false;
  }));
  // بازمحاسبه: فقط روزهای کاری (تعطیل در جمع مرخصی/مأموریت نیست؛ در جدول روزبه‌روز نمایش داده می‌شود)
  const empRow = (gd.obj.employees || []).find(function (e) { return String(e.code) === code; });
  const empCt0 = (empRow && empRow.contractType) || 'normal';
  let reLeaveDays = 0, reHourlyLeave = 0, reMissionDays = 0, reMissionHours = 0;
  reqs.forEach(function (x) {
    if (x.kind === 'leave' && x.mode === 'daily') {
      reLeaveDays += countWorkingDaysInMonth(x.startDate, x.endDate || x.startDate, year, month, gd.obj, empCt0);
    } else if (x.kind === 'leave' && x.mode === 'hourly') {
      const p = parseJalaliYMD(x.startDate);
      if (p && p.y === year && p.m === month) reHourlyLeave += hoursBetween(x.fromTime, x.toTime);
    } else if (x.kind === 'mission' && x.mode === 'daily') {
      reMissionDays += countAllDaysInMonth(x.startDate, x.endDate || x.startDate, year, month);
    } else if (x.kind === 'mission' && x.mode === 'hourly') {
      const p = parseJalaliYMD(x.startDate);
      if (p && p.y === year && p.m === month) reMissionHours += hoursBetween(x.fromTime, x.toTime);
    }
  });
  reLeaveDays = Math.round(reLeaveDays * 100) / 100;
  reHourlyLeave = Math.round(reHourlyLeave * 100) / 100;
  reMissionDays = Math.round(reMissionDays * 100) / 100;
  reMissionHours = Math.round(reMissionHours * 100) / 100;
  const emp = (gd.obj.employees || []).find(e => String(e.code) === code);
  // day-by-day sheet (same shape as admin Excel-like timesheet)
    const dim = daysInJalaliMonth(year, month);
  if (!gd.obj.dailyAttendance) gd.obj.dailyAttendance = {};
  const punchStore = gd.obj.dailyAttendance[String(code)] || {};
  const empCt = (emp && emp.contractType) || 'normal';
  const cal = getContractCalendar(gd.obj, empCt);
  const dayMap = {};
  for (let d = 1; d <= dim; d++) {
    const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
    const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0');
    const punch = punchStore[dk] || punchStore[dateFa] || {};
    const nonWork = isHolidayOrNonWork(gd.obj, year, month, d, empCt);
    const coveredMin = hourlyCoverMinutesOnDay(gd.obj, code, year, month, d);
    const coveredIv = hourlyCoverIntervalsOnDay(gd.obj, code, year, month, d);
    const dlm = dailyLeaveMissionFlags(gd.obj, code, year, month, d);
    const dayMeta = getDayMeta(gd.obj, year, month, d, empCt);
    const calc = computeDayTimesheet(cal, {
      in1: punch.in1 || '', out1: punch.out1 || '',
      in2: punch.in2 || '', out2: punch.out2 || '',
      in3: punch.in3 || '', out3: punch.out3 || '',
      in4: punch.in4 || '', out4: punch.out4 || ''
    }, { year: year, month: month, day: d, isHoliday: nonWork, isHourly: String(empCt) === 'hourly', contractType: empCt, coveredMinutes: coveredMin, coveredIntervals: coveredIv, floatCompensate: !!(punch && punch.floatCompensate) || !!cal.floatCompensate, fullDayLeaveOrMission: dlm.fullDayLeaveOrMission, unpaidLeave: dlm.unpaidLeave, dayMeta: dayMeta, earlyOtEnabled: !!(emp && (emp.earlyOtEnabled || emp.earlyOt)), earlyOtFrom: (emp && emp.earlyOtFrom != null) ? timeToMinutes(emp.earlyOtFrom) : null });
    dayMap[dk] = {
      day: d,
      date: dateFa,
      in1: punch.in1 || '', out1: punch.out1 || '',
      in2: punch.in2 || '', out2: punch.out2 || '',
      in3: punch.in3 || '', out3: punch.out3 || '',
      in4: punch.in4 || '', out4: punch.out4 || '',
      workHours: calc.workHours,
      otHours: calc.otHours,
      otHoursHM: calc.otHoursHM,
      nightHours: calc.nightHours,
      nightHoursHM: calc.nightHoursHM,
      earlyOtHours: calc.earlyOtHours,
      earlyOtHoursHM: calc.earlyOtHoursHM,
      delayMin: calc.delayMinutes,
      earlyMin: calc.earlyLeaveMinutes,
      hourlyAbsenceMin: calc.hourlyAbsenceMinutes,
      hourlyAbsenceHours: calc.hourlyAbsenceHours,
      hourlyAbsenceHM: calc.hourlyAbsenceHM,
      workHoursHM: calc.workHoursHM,
      incomplete: punchIncompleteFlags(punch),
      manualEdit: !!punch.manualEdit,
      editedBy: punch.editedBy || '',
      editedAt: punch.editedAt || '',
      editedFields: punch.editedFields || {},
      leaveDaily: '',
      leaveHourly: '',
      missionDaily: '',
      missionHourly: '',
      note: '',
      isNonWork: nonWork
    };
  }
  reqs.forEach(function (x) {
    const days = x.mode === 'hourly'
      ? [dateKey(x.startDate)]
      : listDayKeys(x.startDate, x.endDate || x.startDate);
    days.forEach(function (dk) {
      const parts = dk.split('-');
      if (Number(parts[0]) !== year || Number(parts[1]) !== month) return;
      const cell = dayMap[dk];
      if (!cell) return;
      let label = x.typeName || (x.kind === 'mission' ? 'روزانه' : 'روزانه');
        label = String(label).replace(/^\s*مأموریت\s*/,'').replace(/^\s*ماموریت\s*/,'').replace(/^\s*مرخصی\s*/,'').replace(/\s*\(پوشش کسر کار\)\s*/g,'').trim() || label;
        // ساعتی: فقط بازه
        const shortLabel = label.replace(/\s*ساعتی\s*/g,'').trim() || label;
      if (x.kind === 'leave' && x.mode === 'daily') { cell.leaveDaily = (cell.leaveDaily ? cell.leaveDaily + '؛ ' : '') + shortLabel; if (cell.in1||cell.out1||cell.in2||cell.out2||cell.in3||cell.out3||cell.in4||cell.out4) cell.leaveConflict = true; }
      if (x.kind === 'leave' && x.mode === 'hourly') { var tr = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (tr) cell.leaveHourly = (cell.leaveHourly ? cell.leaveHourly + '؛ ' : '') + tr; if (hourlyOverlapsPresence(x.fromTime, x.toTime, cell)) cell.leaveConflict = true; }
      if (x.kind === 'mission' && x.mode === 'daily') { cell.missionDaily = (cell.missionDaily ? cell.missionDaily + '؛ ' : '') + shortLabel; if (cell.in1||cell.out1||cell.in2||cell.out2||cell.in3||cell.out3||cell.in4||cell.out4) cell.missionConflict = true; }
      if (x.kind === 'mission' && x.mode === 'hourly') { var trm = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (trm) cell.missionHourly = (cell.missionHourly ? cell.missionHourly + '؛ ' : '') + trm; if (hourlyOverlapsPresence(x.fromTime, x.toTime, cell)) cell.missionConflict = true; }
      
        if (!x.bulkCover) {
          var bits = [];
          if (x.place) bits.push(String(x.place).trim());
          if (x.reason && String(x.reason).indexOf('ثبت خودکار') < 0) bits.push(String(x.reason).trim());
          bits.forEach(function(b){
            if (!b) return;
            if (!cell.note) cell.note = b;
            else if (cell.note.indexOf(b) < 0) cell.note += '؛ ' + b;
          });
        }
    });
  });
  const dailyDays = Object.keys(dayMap).sort().map(function (k) { return dayMap[k]; });

  // جمع اضافه‌کار و شب‌کاری از همان روزبه‌روز (مثل ادمین)
  let punchOt = 0, punchNight = 0, punchAbsMin = 0;
  Object.keys(dayMap).forEach(function (k) {
    const cell = dayMap[k];
    if (!cell) return;
    punchOt += Number(cell.otHours) || 0;
    punchNight += Number(cell.nightHours) || 0;
    punchAbsMin += Number(cell.hourlyAbsenceMin) || 0;
  });
  punchOt = Math.round(punchOt * 100) / 100;
  punchNight = Math.round(punchNight * 100) / 100;
  const otCap = empOtCeilingHours(emp);
  const approvedOt = (otCap != null) ? Math.min(punchOt, otCap) : punchOt;
  const unapprovedOt = (otCap != null) ? Math.max(0, Math.round((punchOt - otCap) * 100) / 100) : 0;
  const workWithAtt = recountEmpMonthWorkDays(gd.obj, year, month, code);
  // همگام‌سازی با monthlyData تا ورود داده ماهانه و ادمین یکسان باشند
  try {
    if (!gd.obj.monthlyData) gd.obj.monthlyData = {};
    if (!gd.obj.monthlyData[key]) gd.obj.monthlyData[key] = {};
    if (!gd.obj.monthlyData[key][code]) gd.obj.monthlyData[key][code] = {};
    const mdE = gd.obj.monthlyData[key][code];
    mdE.workDays = Math.round(workWithAtt) || 0;
    mdE.leaveDays = reLeaveDays;
    mdE.hourlyLeave = reHourlyLeave;
    mdE.missionDays = reMissionDays;
    mdE.missionHours = reMissionHours;
    mdE.otHours = approvedOt || 0;
    mdE.otHoursTotal = punchOt || 0;
    mdE.otHoursUnapproved = unapprovedOt;
    mdE.nightHours = punchNight;
    mdE.hourlyAbsenceHours = Math.round((punchAbsMin / 60) * 100) / 100;
    mdE._fromTimesheet = true;
    mdE._timesheetSyncedAt = new Date().toISOString();
  } catch (eMdE) { console.error('emp md sync', eMdE); }
  const userAccess = normalizeUserAccess((gd.obj.settings || {}).userAccess);
  return jsonResponse({
    ok: true,
    code,
    fullName: emp ? emp.fullName : '',
    userAccess: userAccess,
    year, month,
    workDays: workWithAtt,
    leaveDays: reLeaveDays,
    hourlyLeave: reHourlyLeave,
    missionDays: reMissionDays,
    missionHours: reMissionHours,
    otHours: approvedOt || 0,
    otHoursTotal: punchOt || 0,
    otHoursUnapproved: unapprovedOt,
    otCeilingHours: otCap,
    otHoursHM: (typeof formatHoursHMFromHours === 'function') ? formatHoursHMFromHours(approvedOt || 0) : undefined,
    otHoursTotalHM: (typeof formatHoursHMFromHours === 'function') ? formatHoursHMFromHours(punchOt || 0) : undefined,
    otHoursUnapprovedHM: (typeof formatHoursHMFromHours === 'function') ? formatHoursHMFromHours(unapprovedOt || 0) : undefined,
    nightHours: punchNight,
    nightHoursHM: (typeof formatHoursHMFromHours === 'function') ? formatHoursHMFromHours(punchNight) : undefined,
    hourlyAbsenceHours: Math.round((punchAbsMin / 60) * 100) / 100,
    hourlyAbsenceHM: (typeof formatHoursHM === 'function') ? formatHoursHM(punchAbsMin) : undefined,
    requests: reqs,
    daily: { code: code, fullName: emp ? emp.fullName : '', days: dailyDays }
  });
}

async function handleAdminSetManager(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const code = String(r.body.code || '').trim();
  const managerCode = String(r.body.managerCode || '').trim();
  const managerCode2 = String(r.body.managerCode2 != null ? r.body.managerCode2 : (r.body.manager2 || '')).trim();
  if (!code) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    const emp = gd.obj.employees.find(e => String(e.code) === code);
    if (!emp) return jsonResponse({ ok: false, error: 'not_found' }, 404);
    function checkMgr(mc, label) {
      if (!mc) return null;
      const mgr = gd.obj.employees.find(e => String(e.code) === mc);
      if (!mgr) return label + ' یافت نشد.';
      if (mc === code) return label + ' نمی‌تواند خودش باشد.';
      return null;
    }
    const e1 = checkMgr(managerCode, 'مدیر سطح ۱');
    if (e1) return jsonResponse({ ok: false, error: 'manager_not_found', message: e1 }, 404);
    const e2 = checkMgr(managerCode2, 'مدیر سطح ۲');
    if (e2) return jsonResponse({ ok: false, error: 'manager_not_found', message: e2 }, 404);
    if (managerCode && managerCode2 && managerCode === managerCode2) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'مدیر سطح ۱ و ۲ نباید یک نفر باشند.' }, 400);
    }
    emp.managerCode = managerCode || '';
    emp.managerCode2 = managerCode2 || '';
    if (!gd.obj.portalMeta || typeof gd.obj.portalMeta !== 'object') gd.obj.portalMeta = {};
    gd.obj.portalMeta[code] = { managerCode: emp.managerCode, managerCode2: emp.managerCode2 };
    // special tag so storePutData allows writing manager fields
    const put = await storePutData(cfg, gd.version, gd.obj, 'mgr-set:' + who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, code, managerCode: emp.managerCode, managerCode2: emp.managerCode2 });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminGetManager(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const url = new URL(request.url);
  const code = String(url.searchParams.get('code') || '').trim();
  if (!code) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
  const meta = (gd.obj.portalMeta && gd.obj.portalMeta[code]) || {};
  const emp = (gd.obj.employees || []).find(function (e) { return String(e.code) === code; });
  return jsonResponse({
    ok: true,
    code: code,
    managerCode: meta.managerCode || (emp && emp.managerCode) || '',
    managerCode2: meta.managerCode2 || (emp && emp.managerCode2) || ''
  });
}


/** پیشنهاد بازه ساعتی برای پوشش کسری: تعجیل → تا پایان شیفت؛ تأخیر → از شروع شیفت */
/**
 * شکاف‌های عدم حضور داخل بازه موظفی (با کسر وقفه اگر جزو کار نباشد)
 * punches: {in1,out1,in2,out2} یا آرایه
 * خروجی: [{ fromMin, toMin, minutes }] — فقط جایی که فرد حضور نداشته
 */

/** آیا بازه ساعتی با جفت‌های کامل تردد تداخل دارد؟ */
function hourlyOverlapsPresence(fromTime, toTime, punch) {
  const a = timeToMinutes(fromTime);
  const b = timeToMinutes(toTime);
  if (a == null || b == null || b <= a) return false;
  const pairs = [];
  if (punch) {
    punchPairsFromObj(punch).forEach(function (p) {
      if (!p.incomplete && p.a != null && p.b != null) pairs.push([p.a, p.b]);
    });
  }
  for (let i = 0; i < pairs.length; i++) {
    const p = pairs[i];
    if (p[0] == null || p[1] == null) continue;
    if (a < p[1] && b > p[0]) return true;
  }
  return false;
}


function punchPairsFromObj(punches) {
  const pairs = [];
  if (!punches) return pairs;
  if (Array.isArray(punches)) {
    punches.forEach(function (p) {
      if (!p) return;
      const a = timeToMinutes(p.in != null ? p.in : p.inn);
      const b = timeToMinutes(p.out);
      if (a != null && b != null) pairs.push({ a: a, b: b < a ? b + 24 * 60 : b });
      else if (a != null || b != null) pairs.push({ a: a, b: b, incomplete: true });
    });
    return pairs;
  }
  for (let i = 1; i <= 4; i++) {
    const inn = punches['in' + i];
    const out = punches['out' + i];
    if (inn || out) {
      const a = timeToMinutes(inn);
      const b = timeToMinutes(out);
      if (a != null && b != null) pairs.push({ a: a, b: b < a ? b + 24 * 60 : b });
      else pairs.push({ a: a, b: b, incomplete: true });
    }
  }
  return pairs;
}
function findOfficialAbsenceGaps(cal, punches) {
  const sched = normalizeWorkSchedule(cal);
  const start = timeToMinutes(sched.workStart);
  const end = timeToMinutes(sched.workEnd);
  if (start == null || end == null || end <= start) return [];

  let pairs = [];
  if (Array.isArray(punches)) {
    punches.forEach(function (p) {
      if (!p) return;
      const a = timeToMinutes(p.in != null ? p.in : p.inn);
      const b = timeToMinutes(p.out);
      if (a != null && b != null) pairs.push({ a: a, b: b < a ? b + 24 * 60 : b });
    });
  } else if (punches && typeof punches === 'object') {
    punchPairsFromObj(punches).forEach(function (p) {
      if (p.incomplete) return;
      if (p.a != null && p.b != null) pairs.push({ a: p.a, b: p.b });
    });
  }

  // حضور را به بازه موظفی محدود کن
  const presence = [];
  pairs.forEach(function (p) {
    const a = Math.max(p.a, start);
    const b = Math.min(p.b, end);
    if (b > a) presence.push({ a: a, b: b });
  });
  presence.sort(function (x, y) { return x.a - y.a; });
  // ادغام
  const merged = [];
  presence.forEach(function (p) {
    if (!merged.length || p.a > merged[merged.length - 1].b) merged.push({ a: p.a, b: p.b });
    else merged[merged.length - 1].b = Math.max(merged[merged.length - 1].b, p.b);
  });

  // شکاف‌های [start,end] منهای حضور
  const gaps = [];
  let cursor = start;
  merged.forEach(function (p) {
    if (p.a > cursor) gaps.push({ fromMin: cursor, toMin: p.a, minutes: p.a - cursor });
    cursor = Math.max(cursor, p.b);
  });
  if (cursor < end) gaps.push({ fromMin: cursor, toMin: end, minutes: end - cursor });

  // اگر وقفه جزو کار نباشد، از شکاف‌ها کم کن (وقفه غیبت نیست)
  if (sched.hasBreak && !sched.breakCountsAsWork) {
    const bs = timeToMinutes(sched.breakStart);
    const be = timeToMinutes(sched.breakEnd);
    if (bs != null && be != null && be > bs) {
      const trimmed = [];
      gaps.forEach(function (g) {
        // شکاف را نسبت به [bs,be] بشکن
        if (g.toMin <= bs || g.fromMin >= be) {
          trimmed.push(g);
          return;
        }
        if (g.fromMin < bs) trimmed.push({ fromMin: g.fromMin, toMin: Math.min(g.toMin, bs), minutes: Math.min(g.toMin, bs) - g.fromMin });
        if (g.toMin > be) trimmed.push({ fromMin: Math.max(g.fromMin, be), toMin: g.toMin, minutes: g.toMin - Math.max(g.fromMin, be) });
      });
      return trimmed.filter(function (g) { return g.minutes > 0; });
    }
  }
  return gaps.filter(function (g) { return g.minutes > 0; });
}

/**
 * اعمال جبران شناوری روی شکاف صبح: ماندن بعد از end، از ابتدای شکاف صبح کم می‌کند
 */
function applyFloatToMorningGaps(gaps, cal, punches, forceCompOpt) {
  const sched = normalizeWorkSchedule(cal);
  const start = timeToMinutes(sched.workStart);
  const end = timeToMinutes(sched.workEnd);
  const floatM = Number(sched.floatMinutes) || 0;
  const forceComp = forceCompOpt != null ? !!forceCompOpt : !!sched.floatCompensate;
  if (start == null || end == null || !gaps || !gaps.length) return { gaps: gaps || [], compensated: 0 };

  let lastOut = null, firstIn = null;
  const list = [];
  if (punches && typeof punches === 'object' && !Array.isArray(punches)) {
    punchPairsFromObj(punches).forEach(function (p) {
      if (p.incomplete) return;
      if (p.a != null && p.b != null) list.push({ a: p.a, b: p.b });
    });
  } else if (Array.isArray(punches)) {
    punches.forEach(function (p) {
      const a = timeToMinutes(p.in != null ? p.in : p.inn);
      const b = timeToMinutes(p.out);
      if (a != null && b != null) list.push({ a: a, b: b < a ? b + 24 * 60 : b });
    });
  }
  list.forEach(function (p) {
    if (firstIn == null || p.a < firstIn) firstIn = p.a;
    if (lastOut == null || p.b > lastOut) lastOut = p.b;
  });
  if (firstIn == null || lastOut == null) return { gaps: gaps, compensated: 0 };

  const morningDelay = Math.max(0, firstIn - start);
  // شناوری فقط وقتی تأخیر ≤ سقف شناوری (مثلاً ۱۵د). ورود ۰۷:۰۱ با شروع ۰۶:۴۵ = ۱۶د → بدون شناوری
  const withinFloat = morningDelay > 0 && morningDelay <= floatM;
  // جبران فقط: داخل شناوری (خودکار) یا با تیک floatCompensate
  if (!withinFloat && !forceComp) return { gaps: gaps, compensated: 0 };
  if (morningDelay <= 0) return { gaps: gaps, compensated: 0 };

  const stayedPast = Math.max(0, lastOut - end);
  // داخل شناوری: سقف جبران = min(تأخیر، float، ماندن بعد از end)
  // خارج شناوری با تیک جبران: min(تأخیر، ماندن بعد از end) — بدون سقف float
  let maxComp;
  if (withinFloat) maxComp = Math.min(morningDelay, floatM, stayedPast);
  else maxComp = Math.min(morningDelay, stayedPast);
  const compensated = Math.max(0, maxComp);
  if (compensated <= 0) return { gaps: gaps, compensated: 0 };

  // جبران فقط از ابتدای شکاف صبح (از start تا firstIn) کم می‌شود
  let left = compensated;
  const out = [];
  gaps.forEach(function (g) {
    if (left <= 0) { out.push(g); return; }
    // فقط شکاف‌هایی که به بازه تأخیر صبح مربوط‌اند
    if (g.toMin <= start || g.fromMin >= firstIn) { out.push(g); return; }
    if (g.fromMin < firstIn && g.toMin > start) {
      const skip = Math.min(left, g.minutes);
      left -= skip;
      const nf = g.fromMin + skip;
      if (nf < g.toMin) out.push({ fromMin: nf, toMin: g.toMin, minutes: g.toMin - nf });
    } else {
      out.push(g);
    }
  });
  return { gaps: out, compensated: compensated };
}

/**
 * بازه‌های پوشش کسر کار = فقط شکاف‌های واقعی عدم حضور (پس از جبران شناوری)
 */
function suggestHourlyCoverRanges(cal, calc, maxCoverMinutes, punches) {
  const sched = normalizeWorkSchedule(cal);
  const start = timeToMinutes(sched.workStart);
  const end = timeToMinutes(sched.workEnd);
  if (start == null || end == null) return [];

  const hasComplete = calc && calc.hasCompletePair;
  // بدون تردد کامل
  if (!hasComplete) {
    let budget = Math.max(0, Number(maxCoverMinutes) || 0);
    const shortfall = Number(calc && calc.hourlyAbsenceMinutes) || Math.max(0, end - start);
    if (!budget) budget = shortfall;
    const need = Math.min(budget, shortfall);
    if (need > 0) return [{ fromTime: minutesToHHMM(start), toTime: minutesToHHMM(Math.min(end, start + need)), minutes: need }];
    return [];
  }

  // شکاف واقعی + جبران شناوری (ماندن بعد از پایان روی صبح)
  let gaps = findOfficialAbsenceGaps(cal, punches || {});
  const schedSug = normalizeWorkSchedule(cal);
  const applied = applyFloatToMorningGaps(gaps, cal, punches || {}, !!schedSug.floatCompensate);
  gaps = applied.gaps;

  // بودجه: اگر maxCoverMinutes داده شده از آن استفاده؛ وگرنه همه شکاف‌های باقی‌مانده
  let budget = Number(maxCoverMinutes);
  if (!isFinite(budget) || budget <= 0) {
    budget = gaps.reduce(function (s, g) { return s + g.minutes; }, 0);
  }

  const ranges = [];
  gaps.forEach(function (g) {
    if (budget <= 0) return;
    const need = Math.min(g.minutes, budget);
    if (need <= 0) return;
    ranges.push({
      fromTime: minutesToHHMM(g.fromMin),
      toTime: minutesToHHMM(g.fromMin + need),
      minutes: need
    });
    budget -= need;
  });
  return ranges;
}
function suggestHourlyCoverRange(cal, calc, coverMinutes, punches) {
  const arr = suggestHourlyCoverRanges(cal, calc, coverMinutes, punches);
  return arr.length ? arr[0] : null;
}


async function handleAdminBulkHourlyCover(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  const month = Number(r.body.month);
  const kind = r.body.kind === 'mission' ? 'mission' : 'leave';
  const codes = Array.isArray(r.body.codes) ? r.body.codes.map(function (c) { return String(c).trim(); }).filter(Boolean) : [];
  const onlyDate = String(r.body.date || '').trim(); // optional YYYY/MM/DD
  const dryRun = !!r.body.dryRun;
  const compFlag = !!r.body.compensate; // جبران تأخیر با ماندن در پایان
  if (!isInt(year, 1300, 1600) || !isInt(month, 1, 12) || !codes.length) {
    return jsonResponse({ ok: false, error: 'bad_request', message: 'سال، ماه و حداقل یک کد پرسنلی لازم است.' }, 400);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!Array.isArray(gd.obj.attendanceRequests)) gd.obj.attendanceRequests = [];
    if (!gd.obj.settings || typeof gd.obj.settings !== 'object') gd.obj.settings = {};

    const allowanceH = Number(gd.obj.settings.monthlyShortfallAllowanceHours);
    const allowanceMin = (isFinite(allowanceH) && allowanceH > 0) ? Math.round(allowanceH * 60) : 0;

    let types = gd.obj.attendanceTypes || [];
    if (!types.length) types = defaultAttendanceTypes();
    const typeLeave = types.find(function (t) { return t.kind === 'leave' && t.mode === 'hourly'; }) || { id: 'leave_hourly', name: 'مرخصی ساعتی' };
    const typeMission = types.find(function (t) { return t.kind === 'mission' && t.mode === 'hourly'; }) || { id: 'mission_hourly', name: 'مأموریت ساعتی' };
    const tdef = kind === 'mission' ? typeMission : typeLeave;

    const results = [];
    let created = 0;

    for (let ci = 0; ci < codes.length; ci++) {
      const code = codes[ci];
      const emp = (gd.obj.employees || []).find(function (e) { return String(e.code) === code; });
      if (!emp || emp.status === 'inactive') {
        results.push({ code: code, ok: false, message: 'یافت نشد' });
        continue;
      }
      const ct = emp.contractType || 'normal';
      const cal = getContractCalendar(gd.obj, ct);
      const dim = daysInJalaliMonth(year, month);
      const punchStore = ((gd.obj.dailyAttendance || {})[String(code)]) || {};

      // جمع کسری ماه (قبل از پوشش جدید)
      let totalShortMin = 0;
      const dayShorts = [];
      for (let d = 1; d <= dim; d++) {
        if (onlyDate) {
          const p = parseJalaliYMD(onlyDate);
          if (!p || p.y !== year || p.m !== month || p.d !== d) continue;
        }
        const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
        const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0');
        const punch = punchStore[dk] || punchStore[dateFa] || {};
        const nonWork = isHolidayOrNonWork(gd.obj, year, month, d, ct);
        if (nonWork) continue;
        const coveredMin = hourlyCoverMinutesOnDay(gd.obj, code, year, month, d);
        const coveredIv = hourlyCoverIntervalsOnDay(gd.obj, code, year, month, d);
        const dlm = dailyLeaveMissionFlags(gd.obj, code, year, month, d);
        if (dlm.fullDayLeaveOrMission && !dlm.unpaidLeave) continue;
        const calc = computeDayTimesheet(cal, {
          in1: punch.in1 || '', out1: punch.out1 || '',
          in2: punch.in2 || '', out2: punch.out2 || '',
          in3: punch.in3 || '', out3: punch.out3 || '',
          in4: punch.in4 || '', out4: punch.out4 || ''
        }, { year: year, month: month, day: d, isHoliday: nonWork, coveredMinutes: coveredMin, coveredIntervals: coveredIv, floatCompensate: compFlag || !!(punch && punch.floatCompensate) || !!cal.floatCompensate, fullDayLeaveOrMission: dlm.fullDayLeaveOrMission, unpaidLeave: dlm.unpaidLeave });
        // تیک «جبران تأخیر با ماندن در پایان»: روزهایی که دیر آمده و بعد از پایان مانده‌اند علامت می‌خورند
        // تا در تایم‌شیت هم همین جبران اعمال شود
        if (compFlag && calc.hasCompletePair && calc.compensatedMinutes > 0 && punchStore[dk] && !dryRun) punchStore[dk].floatCompensate = true;
        else if (compFlag && calc.hasCompletePair && calc.compensatedMinutes > 0 && punchStore[dateFa] && !dryRun) punchStore[dateFa].floatCompensate = true;
        const sm = Number(calc.hourlyAbsenceMinutes) || 0;
        if (sm > 0) {
          totalShortMin += sm;
          dayShorts.push({ d: d, dateFa: dateFa, shortMin: sm, calc: calc, comp: compFlag || !!(punch && punch.floatCompensate), punch: { in1: punch.in1||'', out1: punch.out1||'', in2: punch.in2||'', out2: punch.out2||'', in3: punch.in3||'', out3: punch.out3||'', in4: punch.in4||'', out4: punch.out4||'' } });
        }
      }

      // تا allowanceMin دقیقه کسر مجاز ماهانه باقی بماند
      let remainAllow = allowanceMin;
      let toCoverTotal = Math.max(0, totalShortMin - remainAllow);
      // توزیع از روزها: اول از هر روز به اندازه ممکن با حفظ باقی‌مانده مجاز
      const planned = [];
      let leftToCover = toCoverTotal;
      // اگر فقط یک تاریخ و toCover با allowance: برای همان روز
      for (let i = 0; i < dayShorts.length && leftToCover > 0; i++) {
        const ds = dayShorts[i];
        // شکاف‌های واقعی + جبران شناوری
        let ranges = suggestHourlyCoverRanges(ds.comp ? Object.assign({}, cal, { floatCompensate: true }) : cal, ds.calc, 0, ds.punch || {});
        if (!ranges.length) continue;
        // اعمال سقف کسر مجاز و leftToCover
        const out = [];
        ranges.forEach(function (range) {
          if (leftToCover <= 0) return;
          let m = range.minutes;
          // از اولین دقیقه‌های روز می‌توان با remainAllow رد کرد
          if (remainAllow > 0) {
            const sk2 = Math.min(m, remainAllow);
            remainAllow -= sk2;
            m -= sk2;
            // جابه‌جایی fromTime
            if (sk2 > 0 && m > 0) {
              const fm = timeToMinutes(range.fromTime);
              if (fm != null) {
                range = { fromTime: minutesToHHMM(fm + sk2), toTime: range.toTime, minutes: m };
              }
            } else if (m <= 0) {
              return;
            }
          }
          if (m > leftToCover) {
            const fm = timeToMinutes(range.fromTime);
            m = leftToCover;
            if (fm != null) range = { fromTime: range.fromTime, toTime: minutesToHHMM(fm + m), minutes: m };
          }
          if (m <= 0) return;
          out.push({ dateFa: ds.dateFa, fromTime: range.fromTime, toTime: range.toTime, minutes: m });
          leftToCover -= m;
        });
        out.forEach(function (range) { planned.push(range); });
      }

      if (!planned.length) {
        results.push({ code: code, fullName: emp.fullName || '', ok: true, created: 0, message: totalShortMin ? 'کسری در سقف مجاز ماهانه است یا پوشش لازم نیست' : 'کسری ندارد', shortHours: Math.round(totalShortMin / 60 * 100) / 100 });
        continue;
      }

      if (dryRun) {
        results.push({ code: code, fullName: emp.fullName || '', ok: true, created: planned.length, planned: planned, shortHours: Math.round(totalShortMin / 60 * 100) / 100 });
        continue;
      }

      // حذف پوشش‌های خودکار قبلی همان روز تا بازه اشتباه نماند
      const planDates = {};
      planned.forEach(function (pl) { planDates[pl.dateFa] = true; });
      gd.obj.attendanceRequests = (gd.obj.attendanceRequests || []).filter(function (x) {
        if (String(x.empCode) !== String(emp.code)) return true;
        if (!x.bulkCover) return true;
        const sd = String(x.startDate || '').replace(/-/g, '/');
        if (planDates[sd]) return false;
        return true;
      });

      let n = 0;
      planned.forEach(function (pl) {
        const req = {
          id: newRequestId(),
          empCode: String(emp.code),
          empName: emp.fullName || '',
          managerCode: String(emp.managerCode || ''),
          managerName: '',
          typeId: tdef.id || '',
          typeName: (tdef.name || (kind === 'mission' ? 'مأموریت ساعتی' : 'مرخصی ساعتی')) + ' (پوشش کسر کار)',
          deductFromEntitlement: kind === 'leave' && !!(tdef.deductFromEntitlement),
          kind: kind,
          mode: 'hourly',
          startDate: pl.dateFa,
          endDate: pl.dateFa,
          fromTime: pl.fromTime,
          toTime: pl.toTime,
          place: kind === 'mission' ? 'پوشش کسر کار (گروهی)' : '',
          reason: 'ثبت خودکار پوشش کسر کار',
          status: 'approved',
          rejectReason: '',
          createdAt: new Date().toISOString(),
          decidedAt: new Date().toISOString(),
          decidedBy: 'admin:' + who.name,
          adminOverride: true,
          bulkCover: true
        };
        // overlap skip
        const conflict = gd.obj.attendanceRequests.find(function (x) {
          if (String(x.empCode) !== String(emp.code) || x.status === 'rejected') return false;
          return requestsOverlap(req, x);
        });
        if (conflict) return;
        gd.obj.attendanceRequests.unshift(req);
        applyApprovedRequestToTimesheet(gd.obj, req);
        n++;
        created++;
      });
      results.push({ code: code, fullName: emp.fullName || '', ok: true, created: n, planned: planned, shortHours: Math.round(totalShortMin / 60 * 100) / 100 });
    }

    if (dryRun) {
      return jsonResponse({ ok: true, dryRun: true, allowanceHours: allowanceH || 0, results: results, created: 0 });
    }
    if (gd.obj.attendanceRequests.length > 5000) gd.obj.attendanceRequests.length = 5000;
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, created: created, allowanceHours: allowanceH || 0, results: results });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminShortfallSettings(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  if (request.method === 'GET') {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    const h = (gd.obj && gd.obj.settings && gd.obj.settings.monthlyShortfallAllowanceHours);
    return jsonResponse({ ok: true, monthlyShortfallAllowanceHours: h != null ? h : '' });
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj.settings) gd.obj.settings = {};
    const v = r.body.monthlyShortfallAllowanceHours;
    if (v === '' || v == null) {
      delete gd.obj.settings.monthlyShortfallAllowanceHours;
    } else {
      const n = Number(v);
      if (!isFinite(n) || n < 0) return jsonResponse({ ok: false, error: 'bad_request', message: 'مقدار نامعتبر' }, 400);
      gd.obj.settings.monthlyShortfallAllowanceHours = n;
    }
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, monthlyShortfallAllowanceHours: gd.obj.settings.monthlyShortfallAllowanceHours });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}


/** جمع کارکرد ماه از تردد + درخواست‌ها → monthlyData */
function fillEmployeeMonthFromAttendance(obj, year, month, emp) {
  if (!obj || !emp) return null;
  const code = String(emp.code);
  const ct = emp.contractType || 'normal';
  const cal = getContractCalendar(obj, ct);
  const dim = daysInJalaliMonth(year, month);
  const punchStore = ((obj.dailyAttendance || {})[code]) || {};
  let sumOt = 0, sumNight = 0, sumEarly = 0, sumAbsMin = 0;
  for (let d = 1; d <= dim; d++) {
    const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
    const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0');
    const punch = punchStore[dk] || punchStore[dateFa] || {};
    const nonWork = isHolidayOrNonWork(obj, year, month, d, ct);
    const coveredMin = hourlyCoverMinutesOnDay(obj, code, year, month, d);
    const coveredIv = hourlyCoverIntervalsOnDay(obj, code, year, month, d);
    const dlm = dailyLeaveMissionFlags(obj, code, year, month, d);
    const dayMeta = getDayMeta(obj, year, month, d, ct);
    const calc = computeDayTimesheet(cal, {
      in1: punch.in1 || '', out1: punch.out1 || '',
      in2: punch.in2 || '', out2: punch.out2 || '',
      in3: punch.in3 || '', out3: punch.out3 || '',
      in4: punch.in4 || '', out4: punch.out4 || ''
    }, {
      isHoliday: nonWork,
      coveredMinutes: coveredMin, coveredIntervals: coveredIv, floatCompensate: !!(punch && punch.floatCompensate) || !!cal.floatCompensate,
      fullDayLeaveOrMission: dlm.fullDayLeaveOrMission,
      unpaidLeave: dlm.unpaidLeave,
      dayMeta: dayMeta,
      earlyOtEnabled: !!(emp.earlyOtEnabled || emp.earlyOt)
    });
    const hasPunch = !!(punch.in1 || punch.out1 || punch.in2 || punch.out2 || punch.in3 || punch.out3 || punch.in4 || punch.out4);
    if (!nonWork) {
      sumOt += Number(calc.otHours) || 0;
      sumNight += Number(calc.nightHours) || 0;
      sumEarly += Number(calc.earlyOtHours) || 0;
      // فقط روزهایی که تردد دارند در جمع کسری می‌آیند (روز بدون تردد = عدم کارکرد، نه کسری تمام‌روز)
      if (hasPunch) sumAbsMin += Number(calc.hourlyAbsenceMinutes) || 0;
    }
  }
  sumOt = Math.round(sumOt * 100) / 100;
  sumNight = Math.round(sumNight * 100) / 100;
  const allowH = Number((obj.settings && obj.settings.monthlyShortfallAllowanceHours) || 0);
  const allowMin = Math.round(allowH * 60);
  const excessMin = Math.max(0, sumAbsMin - allowMin);
  const otCap = empOtCeilingHours(emp);
  const approvedOt = (otCap != null) ? Math.min(sumOt, otCap) : sumOt;
  const unapprovedOt = (otCap != null) ? Math.max(0, Math.round((sumOt - otCap) * 100) / 100) : 0;

  let aHourly = 0, aMissionH = 0;
  (obj.attendanceRequests || []).forEach(function (x) {
    if (String(x.empCode) !== code || x.status !== 'approved') return;
    const p = parseJalaliYMD(x.startDate);
    if (!p || p.y !== year || p.m !== month) return;
    if (x.kind === 'leave' && x.mode === 'hourly') aHourly += hoursBetween(x.fromTime, x.toTime);
    else if (x.kind === 'mission' && x.mode === 'hourly') aMissionH += hoursBetween(x.fromTime, x.toTime);
  });

  // مرخصی/مأموریت روزانه از درخواست‌های تأییدشده
  let aLeave = 0, aMission = 0;
  (obj.attendanceRequests || []).forEach(function (x) {
    if (String(x.empCode) !== code || x.status !== 'approved') return;
    if (x.kind === 'leave' && x.mode === 'daily') {
      aLeave += countWorkingDaysInMonth(x.startDate, x.endDate || x.startDate, year, month, obj, ct);
    } else if (x.kind === 'mission' && x.mode === 'daily') {
      aMission += countAllDaysInMonth(x.startDate, x.endDate || x.startDate, year, month);
    }
  });
  const workDaysTs = recountEmpMonthWorkDays(obj, year, month, code);

  const key = year + '-' + month;
  if (!obj.monthlyData) obj.monthlyData = {};
  if (!obj.monthlyData[key]) obj.monthlyData[key] = {};
  if (!obj.monthlyData[key][code]) obj.monthlyData[key][code] = {};
  const md = obj.monthlyData[key][code];
  // انتقال کامل تایم‌شیت → ورود داده ماهانه
  md.workDays = Math.round(workDaysTs) || 0;
  md.leaveDays = Math.round(aLeave * 100) / 100;
  md.missionDays = Math.round(aMission * 100) / 100;
  md.hourlyLeave = Math.round(aHourly * 100) / 100;
  md.missionHours = Math.round(aMissionH * 100) / 100;
  md.otHours = approvedOt;
  md.otHoursTotal = sumOt;
  md.otHoursUnapproved = unapprovedOt;
  md.nightHours = sumNight;
  md.hourlyAbsenceHours = Math.round((sumAbsMin / 60) * 100) / 100;
  md.excessAbsenceHours = Math.round((excessMin / 60) * 100) / 100;
  md._fromTimesheet = true;
  md._timesheetSyncedAt = new Date().toISOString();
  return md;
}

function fillAllEmployeesMonthFromAttendance(obj, year, month) {
  const out = {};
  (obj.employees || []).forEach(function (emp) {
    if (emp.status === 'inactive') return;
    try {
      out[String(emp.code)] = fillEmployeeMonthFromAttendance(obj, year, month, emp);
    } catch (e) { console.error('fillMonth', emp.code, e); }
  });
  return out;
}


async function handleAdminTimesheet(request, who, env) {
  try {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  const month = Number(r.body.month);
  if (!isInt(year, 1300, 1600) || !isInt(month, 1, 12)) {
    return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  }
  const filterCode = String(r.body.code || '').trim();
  const filterUnit = String(r.body.unit || '').trim();
  const filterManager = String(r.body.managerCode || '').trim();
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
  const key = year + '-' + month;
  const md = (gd.obj.monthlyData || {})[key] || {};
  const reqs = gd.obj.attendanceRequests || [];
  const rows = [];
  (gd.obj.employees || []).forEach(function (emp) {
    if (emp.status === 'inactive') return;
    if (filterCode && String(emp.code) !== filterCode) return;
    if (filterUnit && String(emp.unit || '') !== filterUnit) return;
    if (filterManager && String(emp.managerCode || '') !== filterManager) return;
    const row = md[emp.code] || {};
    const empReqs = reqs.filter(function (x) {
      if (String(x.empCode) !== String(emp.code) || x.status !== 'approved') return false;
      const p = parseJalaliYMD(x.startDate);
      if (!p) return false;
      if (p.y === year && p.m === month) return true;
      if (x.mode === 'daily' && x.endDate) {
        return splitDaysByMonth(x.startDate, x.endDate).some(c => c.year === year && c.month === month);
      }
      return false;
    });
    const ct = emp.contractType || 'normal';
    let aLeave = 0, aHourly = 0, aMission = 0, aMissionH = 0;
    empReqs.forEach(function (x) {
      if (x.kind === 'leave' && x.mode === 'daily') aLeave += countWorkingDaysInMonth(x.startDate, x.endDate || x.startDate, year, month, gd.obj, ct);
      else if (x.kind === 'leave' && x.mode === 'hourly') {
        const p = parseJalaliYMD(x.startDate);
        if (p && p.y === year && p.m === month) aHourly += hoursBetween(x.fromTime, x.toTime);
      } else if (x.kind === 'mission' && x.mode === 'daily') aMission += countAllDaysInMonth(x.startDate, x.endDate || x.startDate, year, month);
      else if (x.kind === 'mission' && x.mode === 'hourly') {
        const p = parseJalaliYMD(x.startDate);
        if (p && p.y === year && p.m === month) aMissionH += hoursBetween(x.fromTime, x.toTime);
      }
    });
    let filled = null;
    try { filled = fillEmployeeMonthFromAttendance(gd.obj, year, month, emp); } catch (eF) {}
    const mdRow = filled || row || {};
    rows.push({
      code: emp.code,
      fullName: emp.fullName || '',
      unit: emp.unit || '',
      managerCode: emp.managerCode || '',
      childrenEligibleCount: (emp.childrenEligibleCount != null ? Number(emp.childrenEligibleCount) : (Number(emp.children) || 0)),
      workDays: (function(){ var r = recountEmpMonthWorkDays(gd.obj, year, month, emp.code); return Math.round(r) || 0; })(),
      leaveDays: Math.round(aLeave * 100) / 100,
      hourlyLeave: Number(mdRow.hourlyLeave) != null ? Number(mdRow.hourlyLeave) : Math.round(aHourly * 100) / 100,
      missionDays: Math.round(aMission * 100) / 100,
      missionHours: Number(mdRow.missionHours) != null ? Number(mdRow.missionHours) : Math.round(aMissionH * 100) / 100,
      otHours: Number(mdRow.otHours) || 0,
      otHoursTotal: Number(mdRow.otHoursTotal) || 0,
      otHoursUnapproved: Number(mdRow.otHoursUnapproved) || 0,
      nightHours: Number(mdRow.nightHours) || 0,
      hourlyAbsenceHours: Number(mdRow.hourlyAbsenceHours) || 0,
      excessAbsenceHours: Number(mdRow.excessAbsenceHours) || 0,
      missions: Math.round(aMission * 100) / 100,
      leaves: Math.round(aLeave * 100) / 100,
      requests: empReqs
    });
  });
  rows.sort(function (a, b) { return String(a.code).localeCompare(String(b.code), 'fa'); });

  // همگام‌سازی همه ردیف‌ها با monthlyData و ذخیره پایدار برای ورود داده ماهانه
  try {
    const mdKeyAll = year + '-' + month;
    if (!gd.obj.monthlyData) gd.obj.monthlyData = {};
    if (!gd.obj.monthlyData[mdKeyAll]) gd.obj.monthlyData[mdKeyAll] = {};
    rows.forEach(function (rr) {
      if (!rr || !rr.code) return;
      const ck = String(rr.code);
      if (!gd.obj.monthlyData[mdKeyAll][ck]) gd.obj.monthlyData[mdKeyAll][ck] = {};
      const mdA = gd.obj.monthlyData[mdKeyAll][ck];
      if (rr.workDays != null) mdA.workDays = Math.round(Number(rr.workDays) || 0);
      if (rr.leaveDays != null) mdA.leaveDays = Number(rr.leaveDays) || 0;
      if (rr.missionDays != null) mdA.missionDays = Number(rr.missionDays) || 0;
      else if (rr.missions != null) mdA.missionDays = Number(rr.missions) || 0;
      if (rr.hourlyLeave != null) mdA.hourlyLeave = Number(rr.hourlyLeave) || 0;
      if (rr.missionHours != null) mdA.missionHours = Number(rr.missionHours) || 0;
      if (rr.otHours != null) mdA.otHours = Number(rr.otHours) || 0;
      if (rr.otHoursTotal != null) mdA.otHoursTotal = Number(rr.otHoursTotal) || 0;
      if (rr.otHoursUnapproved != null) mdA.otHoursUnapproved = Number(rr.otHoursUnapproved) || 0;
      if (rr.nightHours != null) mdA.nightHours = Number(rr.nightHours) || 0;
      if (rr.excessAbsenceHours != null) mdA.excessAbsenceHours = Number(rr.excessAbsenceHours) || 0;
      if (rr.hourlyAbsenceHours != null) mdA.hourlyAbsenceHours = Number(rr.hourlyAbsenceHours) || 0;
      mdA._fromTimesheet = true;
      mdA._timesheetSyncedAt = new Date().toISOString();
    });
    // فقط در حافظه پاسخ API — ذخیره سرور با «ذخیره داده‌ها» تا conflict/پرش UI نشود
  } catch (eSyncAll) { console.error('monthlyData sync all', eSyncAll); }

  // Day-by-day sheet when a single employee code is selected (Excel-like)
  let daily = null;
  if (filterCode && rows.length === 1) {
    const emp0 = (gd.obj.employees || []).find(function (e) { return String(e.code) === String(filterCode); });
    const cal = getContractCalendar(gd.obj, (emp0 && emp0.contractType) || 'normal');
    const dim = daysInJalaliMonth(year, month);
    if (!gd.obj.dailyAttendance) gd.obj.dailyAttendance = {};
    const punchStore = gd.obj.dailyAttendance[String(filterCode)] || {};


    // پاک‌سازی توضیح ذخیره‌شده (دلیل‌ها فقط از درخواست‌های جاری می‌آیند)
    try {
      const store = gd.obj.dailyAttendance && gd.obj.dailyAttendance[String(filterCode)];
      if (store) {
        Object.keys(store).forEach(function (k) {
          if (store[k] && store[k].note) store[k].note = '';
        });
      }
    } catch (e) {}
    const dayMap = {};
    for (let d = 1; d <= dim; d++) {
      const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
      const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0');
      const punch = punchStore[dk] || punchStore[dateFa] || {};
      const nonWork = isHolidayOrNonWork(gd.obj, year, month, d, (emp0 && emp0.contractType) || 'normal');
      const coveredMin = hourlyCoverMinutesOnDay(gd.obj, filterCode, year, month, d);
      const coveredIv = hourlyCoverIntervalsOnDay(gd.obj, filterCode, year, month, d);
      const dlm = dailyLeaveMissionFlags(gd.obj, filterCode, year, month, d);
      const dayMeta = getDayMeta(gd.obj, year, month, d, (emp0 && emp0.contractType) || 'normal');
      const calc = computeDayTimesheet(cal, {
        in1: punch.in1 || '', out1: punch.out1 || '',
        in2: punch.in2 || '', out2: punch.out2 || '',
        in3: punch.in3 || '', out3: punch.out3 || '',
        in4: punch.in4 || '', out4: punch.out4 || ''
      }, { year: year, month: month, day: d, isHoliday: nonWork, coveredMinutes: coveredMin, coveredIntervals: coveredIv, floatCompensate: !!(punch && punch.floatCompensate) || !!cal.floatCompensate, fullDayLeaveOrMission: dlm.fullDayLeaveOrMission, unpaidLeave: dlm.unpaidLeave, dayMeta: dayMeta, earlyOtEnabled: !!(emp0 && (emp0.earlyOtEnabled || emp0.earlyOt)), earlyOtFrom: (emp0 && emp0.earlyOtFrom != null) ? timeToMinutes(emp0.earlyOtFrom) : null });
      let wd = '';
      try { wd = ['یکشنبه','دوشنبه','سه‌شنبه','چهارشنبه','پنجشنبه','جمعه','شنبه'][jalaliWeekday(year, month, d)] || ''; } catch (e) {}
      dayMap[dk] = {
        day: d,
        date: dateFa,
        weekday: wd,
        in1: punch.in1 || '', out1: punch.out1 || '',
        in2: punch.in2 || '', out2: punch.out2 || '',
        in3: punch.in3 || '', out3: punch.out3 || '',
        in4: punch.in4 || '', out4: punch.out4 || '',
        workHours: calc.workHours,
        delayMin: calc.delayMinutes,
        earlyMin: calc.earlyLeaveMinutes,
        otHours: calc.otHours,
        otHoursHM: calc.otHoursHM,
        nightHours: calc.nightHours,
        nightHoursHM: calc.nightHoursHM,
        earlyOtHours: calc.earlyOtHours,
        earlyOtHoursHM: calc.earlyOtHoursHM,
        hourlyAbsenceMin: nonWork ? 0 : calc.hourlyAbsenceMinutes,
        hourlyAbsenceHours: nonWork ? 0 : calc.hourlyAbsenceHours,
        hourlyAbsenceHM: nonWork ? '' : calc.hourlyAbsenceHM,
        workHoursHM: nonWork && !(punch.in1||punch.out1||punch.in2||punch.out2) ? '' : calc.workHoursHM,
        incomplete: punchIncompleteFlags(punch),
        manualEdit: !!punch.manualEdit,
        editedBy: punch.editedBy || '',
        editedAt: punch.editedAt || '',
        editedFields: punch.editedFields || {},
        compensatedMin: calc.compensatedMinutes,
        leaveDaily: '',
        leaveHourly: '',
        missionDaily: '',
        missionHourly: '',
        note: (function(){
          if (!dayMeta) return '';
          if (dayMeta.conditional || dayMeta.type === 'conditional') {
            var t = 'تعطیل شرایطی';
            if (dayMeta.closeFrom) t += ' از ' + dayMeta.closeFrom;
            if (dayMeta.reason) t += ' — ' + dayMeta.reason;
            return t;
          }
          return '';
        })(),
        isNonWork: nonWork,
        dayMeta: dayMeta || null
      };
    }

    // اصلاح مرخصی‌های پوشش خودکار با بازه اشتباه (مثلاً ۰۶:۴۵-۰۶:۴۹ به‌جای ۰۶:۴۵-۰۷:۰۱)
    try {
      const reqsAll = gd.obj.attendanceRequests || [];
      for (let ri = 0; ri < reqsAll.length; ri++) {
        const x = reqsAll[ri];
        if (!x || !x.bulkCover || x.mode !== 'hourly') continue;
        if (String(x.empCode) !== String(filterCode)) continue;
        const p = parseJalaliYMD(x.startDate);
        if (!p || p.y !== year || p.m !== month) continue;
        const dk = year + '-' + String(month).padStart(2,'0') + '-' + String(p.d).padStart(2,'0');
        const cell = dayMap[dk];
        if (!cell) continue;
        if (cell.isNonWork) { x._dropBulk = true; continue; }
        const punch = { in1: cell.in1, out1: cell.out1, in2: cell.in2, out2: cell.out2, in3: cell.in3, out3: cell.out3, in4: cell.in4, out4: cell.out4 };
        const fakeCalc = { hasCompletePair: !!(cell.in1 && cell.out1) || !!(cell.in2 && cell.out2), hourlyAbsenceMinutes: cell.hourlyAbsenceMin };
        const ranges = suggestHourlyCoverRanges(cal, fakeCalc, 0, punch);
        if (!ranges.length) { x._dropBulk = true; continue; }
        // هم‌تراز کردن با شکاف‌های واقعی: اگر چند شکاف (صبح+عصر) هست، همه پوشش داده شوند
        // درخواست فعلی با نزدیک‌ترین شکاف هم‌تراز می‌شود؛ شکاف‌های بدون درخواست بعداً در bulk ساخته می‌شوند
        let best = ranges[0], bestScore = Infinity;
        const xf = timeToMinutes(x.fromTime), xt = timeToMinutes(x.toTime);
        ranges.forEach(function (r) {
          const rf = timeToMinutes(r.fromTime), rt = timeToMinutes(r.toTime);
          if (rf == null || rt == null) return;
          let score = 0;
          if (xf != null) score += Math.abs(rf - xf);
          if (xt != null) score += Math.abs(rt - xt);
          if (score < bestScore) { bestScore = score; best = r; }
        });
        if (best && (best.fromTime !== x.fromTime || best.toTime !== x.toTime)) {
          x.fromTime = best.fromTime;
          x.toTime = best.toTime;
        }
      }
      gd.obj.attendanceRequests = reqsAll.filter(function (x) { return !x._dropBulk; });
    } catch (eFix) { console.error('bulk fix', eFix); }

    (rows[0].requests || []).forEach(function (x) {
      const days = x.mode === 'hourly'
        ? [dateKey(x.startDate)]
        : listDayKeys(x.startDate, x.endDate || x.startDate);
      days.forEach(function (dk) {
        const parts = dk.split('-');
        if (Number(parts[0]) !== year || Number(parts[1]) !== month) return;
        const cell = dayMap[dk];
        if (!cell) return;
        let label = x.typeName || (x.kind === 'mission' ? 'روزانه' : 'روزانه');
        label = String(label).replace(/^\s*مأموریت\s*/,'').replace(/^\s*ماموریت\s*/,'').replace(/^\s*مرخصی\s*/,'').replace(/\s*\(پوشش کسر کار\)\s*/g,'').trim() || label;
        // ساعتی: فقط بازه
        const shortLabel = label.replace(/\s*ساعتی\s*/g,'').trim() || label;
        if (x.kind === 'leave' && x.mode === 'daily') { cell.leaveDaily = (cell.leaveDaily ? cell.leaveDaily + '؛ ' : '') + shortLabel; if (cell.in1||cell.out1||cell.in2||cell.out2||cell.in3||cell.out3||cell.in4||cell.out4) cell.leaveConflict = true; }
        if (x.kind === 'leave' && x.mode === 'hourly') { var tr = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (tr) cell.leaveHourly = (cell.leaveHourly ? cell.leaveHourly + '؛ ' : '') + tr; if (hourlyOverlapsPresence(x.fromTime, x.toTime, { in1: cell.in1, out1: cell.out1, in2: cell.in2, out2: cell.out2 })) cell.leaveConflict = true; }
        if (x.kind === 'mission' && x.mode === 'daily') { cell.missionDaily = (cell.missionDaily ? cell.missionDaily + '؛ ' : '') + shortLabel; if (cell.in1||cell.out1||cell.in2||cell.out2||cell.in3||cell.out3||cell.in4||cell.out4) cell.missionConflict = true; }
        if (x.kind === 'mission' && x.mode === 'hourly') { var trm = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (trm) cell.missionHourly = (cell.missionHourly ? cell.missionHourly + '؛ ' : '') + trm; if (hourlyOverlapsPresence(x.fromTime, x.toTime, { in1: cell.in1, out1: cell.out1, in2: cell.in2, out2: cell.out2 })) cell.missionConflict = true; }
        
        if (!x.bulkCover) {
          var bits = [];
          if (x.place) bits.push(String(x.place).trim());
          if (x.reason && String(x.reason).indexOf('ثبت خودکار') < 0) bits.push(String(x.reason).trim());
          bits.forEach(function(b){
            if (!b) return;
            if (!cell.note) cell.note = b;
            else if (cell.note.indexOf(b) < 0) cell.note += '؛ ' + b;
          });
        }
      });
    });
    const daysArr = Object.keys(dayMap).sort().map(function (k) { return dayMap[k]; });
    
    // صفر کردن غیبت در روز مرخصی/مأموریت روزانه (بدون تداخل) و روز تعطیل
    Object.keys(dayMap).forEach(function (dk) {
      const cell = dayMap[dk];
      if (!cell) return;
      if (cell.isNonWork) {
        cell.hourlyAbsenceMin = 0;
        cell.hourlyAbsenceHours = 0;
        cell.hourlyAbsenceHM = '';
        if (!cell.in1 && !cell.out1 && !cell.in2 && !cell.out2) {
          cell.workHours = 0;
          cell.workHoursHM = '';
          cell.otHours = 0;
          cell.otHoursHM = '';
        }
      }
      if ((cell.leaveDaily || cell.missionDaily) && !cell.leaveConflict && !cell.missionConflict) {
        cell.hourlyAbsenceMin = 0;
        cell.hourlyAbsenceHours = 0;
        cell.hourlyAbsenceHM = '';
      }
    });

    let computedWork = recountEmpMonthWorkDays(gd.obj, year, month, filterCode);
    let sumOtH = 0, sumNightH = 0, sumEarlyOtH = 0, sumAbsMin = 0;
    daysArr.forEach(function (d) {
      sumOtH += Number(d.otHours) || 0; // شامل اضافه‌کار قبل
      sumEarlyOtH += Number(d.earlyOtHours) || 0;
      sumNightH += Number(d.nightHours) || 0;
      sumAbsMin += Number(d.hourlyAbsenceMin) || 0;
    });
    sumOtH = Math.round(sumOtH * 100) / 100;
    sumNightH = Math.round(sumNightH * 100) / 100;
    // غیبت ساعتی مازاد روی کارکرد (روز) اثر نمی‌گذارد — کارکرد عدد صحیح روزهای حضور است.
    // کسر ریالی از excessAbsenceHours در موتور حقوق انجام می‌شود.
    const allowH = Number((gd.obj.settings && gd.obj.settings.monthlyShortfallAllowanceHours) || 0);
    const allowMin = Math.round(allowH * 60);
    const excessMin = Math.max(0, sumAbsMin - allowMin);
    computedWork = Math.max(0, Math.round(Number(computedWork) || 0));
    const otCapA = empOtCeilingHours(emp0);
    const approvedOtA = (otCapA != null) ? Math.min(sumOtH, otCapA) : sumOtH;
    const unapprovedOtA = (otCapA != null) ? Math.max(0, Math.round((sumOtH - otCapA) * 100) / 100) : 0;
    const reqList = rows[0].requests || [];
    const ct0 = (emp0 && emp0.contractType) || 'normal';
    rows[0].workDays = computedWork;
    rows[0].otHours = approvedOtA;
    rows[0].otHoursTotal = sumOtH;
    rows[0].otHoursUnapproved = unapprovedOtA;
    rows[0].otCeilingHours = otCapA;
    rows[0].nightHours = sumNightH;
    rows[0].earlyOtHours = Math.round(sumEarlyOtH * 100) / 100;
    rows[0].hourlyAbsenceHours = Math.round((sumAbsMin / 60) * 100) / 100;
    rows[0].hourlyAbsenceHM = formatHoursHM(sumAbsMin);
    rows[0].otHoursHM = formatHoursHMFromHours(approvedOtA);
    rows[0].otHoursTotalHM = formatHoursHMFromHours(sumOtH);
    rows[0].otHoursUnapprovedHM = formatHoursHMFromHours(unapprovedOtA);
    rows[0].nightHoursHM = formatHoursHMFromHours(sumNightH);
    rows[0].excessAbsenceMin = excessMin;
    rows[0].excessAbsenceHours = Math.round((excessMin / 60) * 100) / 100;
    rows[0].shortfallAllowanceMin = allowMin;
    rows[0].leaveDays = Math.round((function(){
      let n=0; reqList.forEach(function(x){ if(x.kind==='leave'&&x.mode==='daily') n+=countWorkingDaysInMonth(x.startDate,x.endDate||x.startDate,year,month,gd.obj,ct0); }); return n;
    })()*100)/100;
    rows[0].hourlyLeave = Math.round((function(){
      let n=0; reqList.forEach(function(x){ if(x.kind==='leave'&&x.mode==='hourly'){ const p=parseJalaliYMD(x.startDate); if(p&&p.y===year&&p.m===month) n+=hoursBetween(x.fromTime,x.toTime);} }); return n;
    })()*100)/100;
    rows[0].missions = Math.round((function(){
      let n=0; reqList.forEach(function(x){ if(x.kind==='mission'&&x.mode==='daily') n+=countAllDaysInMonth(x.startDate,x.endDate||x.startDate,year,month); }); return n;
    })()*100)/100;
    rows[0].leaves = rows[0].leaveDays;
    // همگام‌سازی با monthlyData برای شیت محاسبه حقوق
    try {
      const mdKey = year + '-' + month;
      if (!gd.obj.monthlyData) gd.obj.monthlyData = {};
      if (!gd.obj.monthlyData[mdKey]) gd.obj.monthlyData[mdKey] = {};
      const codeKey = String(filterCode);
      if (!gd.obj.monthlyData[mdKey][codeKey]) gd.obj.monthlyData[mdKey][codeKey] = {};
      const md = gd.obj.monthlyData[mdKey][codeKey];
      md.workDays = computedWork;
      md.otHours = approvedOtA;
      md.otHoursTotal = sumOtH;
      md.otHoursUnapproved = unapprovedOtA;
      md.nightHours = sumNightH;
      md.leaveDays = rows[0].leaveDays;
      md.hourlyLeave = rows[0].hourlyLeave;
      md.missionDays = rows[0].missions;
      md.missionHours = Math.round((function(){
        let n=0; reqList.forEach(function(x){ if(x.kind==='mission'&&x.mode==='hourly'){ const p=parseJalaliYMD(x.startDate); if(p&&p.y===year&&p.m===month) n+=hoursBetween(x.fromTime,x.toTime);} }); return n;
      })()*100)/100;
      md.hourlyAbsenceHours = rows[0].hourlyAbsenceHours;
      md.excessAbsenceMin = excessMin;
      md.excessAbsenceHours = Math.round((excessMin / 60) * 100) / 100;
      md._timesheetSyncedAt = new Date().toISOString();
      // ذخیره پایدار با یک‌بار تلاش مجدد در conflict
      try {
        let putR = await storePutData(cfg, gd.version, gd.obj, (who && who.name) || 'admin');
        if (putR && putR.conflict) {
          const gd2 = await storeGetData(cfg);
          if (!gd2.fail && gd2.obj) {
            // فقط monthlyData این ماه را روی نسخه جدید بنویس
            const mk = year + '-' + month;
            if (!gd2.obj.monthlyData) gd2.obj.monthlyData = {};
            if (gd.obj.monthlyData && gd.obj.monthlyData[mk]) {
              gd2.obj.monthlyData[mk] = gd.obj.monthlyData[mk];
            }
            putR = await storePutData(cfg, gd2.version, gd2.obj, (who && who.name) || 'admin');
          }
        }
        if (putR && putR.fail) console.error('md put fail', putR.fail);
      } catch (ePut) { console.error('md put', ePut); }
    } catch (eMd) { console.error('monthlyData sync', eMd); }
    daily = {
      code: rows[0].code,
      fullName: rows[0].fullName,
      contractType: (emp0 && emp0.contractType) || 'normal',
      schedule: {
        workStart: cal.workStart, workEnd: cal.workEnd,
        hasBreak: cal.hasBreak, breakStart: cal.breakStart, breakEnd: cal.breakEnd,
        floatMinutes: cal.floatMinutes, floatCompensate: cal.floatCompensate,
        officialMinutes: officialWorkMinutes(cal)
      },
      days: daysArr, earlyOtEnabled: !!(emp0 && (emp0.earlyOtEnabled || emp0.earlyOt))
    };
  }

  return jsonResponse({ ok: true, year, month, rows, daily: daily });
  } catch (e) {
    console.error('handleAdminTimesheet', e && e.stack ? e.stack : e);
    return jsonResponse({ ok: false, error: 'server_error', message: String(e && e.message ? e.message : e) }, 500);
  }
}

/** ذخیره ورود/خروج روزانه یک کارمند (یک روز یا چند روز ماه) */

function gregorianToJalali(gy, gm, gd) {
  gy = Number(gy); gm = Number(gm); gd = Number(gd);
  if (!gy || !gm || !gd) return null;
  var g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
  var gy2 = (gm > 2) ? (gy + 1) : gy;
  var days = 355666 + (365 * gy) + Math.floor((gy2 + 3) / 4) - Math.floor((gy2 + 99) / 100) + Math.floor((gy2 + 399) / 400) + gd + g_d_m[gm - 1];
  var jy = -1595 + (33 * Math.floor(days / 12053));
  days %= 12053;
  jy += 4 * Math.floor(days / 1461);
  days %= 1461;
  if (days > 365) { jy += Math.floor((days - 1) / 365); days = (days - 1) % 365; }
  var jm, jd;
  if (days < 186) { jm = 1 + Math.floor(days / 31); jd = 1 + (days % 31); }
  else { jm = 7 + Math.floor((days - 186) / 30); jd = 1 + ((days - 186) % 30); }
  return { y: jy, m: jm, d: jd };
}
function parseImportDateToJalali(raw) {
  raw = String(raw || '').trim();
  if (!raw) return null;
  var m = raw.match(/^(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
  if (m) {
    var y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
    if (y >= 1300 && y <= 1600) return { y: y, m: mo, d: d };
    if (y >= 1900 && y <= 2100) return gregorianToJalali(y, mo, d);
  }
  return null;
}
function normalizePunchTime(t) {
  t = String(t || '').trim();
  if (!t) return '';
  var m = t.match(/^(\d{1,2}):(\d{2})(?::\d{2})?$/);
  if (m) {
    var h = Math.min(23, Math.max(0, parseInt(m[1], 10)));
    var mi = Math.min(59, Math.max(0, parseInt(m[2], 10)));
    return (h < 10 ? '0' : '') + h + ':' + (mi < 10 ? '0' : '') + mi;
  }
  m = t.match(/^(\d{3,4})$/);
  if (m) { var s = m[1]; if (s.length === 3) s = '0' + s; return s.slice(0, 2) + ':' + s.slice(2, 4); }
  return '';
}
async function handleAdminImportPunches(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  const r = await readBody(request);
  if (r.error) return r.error;
  const rows = Array.isArray(r.body.rows) ? r.body.rows : [];
  const mode = String(r.body.mode || 'merge') === 'replace' ? 'replace' : 'merge';
  if (!rows.length) return jsonResponse({ ok: false, error: 'bad_request', message: 'هیچ ردیفی ارسال نشده است.' }, 400);
  if (rows.length > 20000) return jsonResponse({ ok: false, error: 'bad_request', message: 'حداکثر ۲۰۰۰۰ ردیف.' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const groups = {};
  let skipped = 0;
  rows.forEach(function (row) {
    if (!row) { skipped++; return; }
    const code = String(row.code || '').trim();
    if (!code) { skipped++; return; }
    const jp = parseImportDateToJalali(row.date);
    if (!jp) { skipped++; return; }
    const inT = normalizePunchTime(row.inTime || row.in || '');
    const outT = normalizePunchTime(row.outTime || row.out || '');
    if (!inT && !outT) { skipped++; return; }
    const dk = jp.y + '-' + String(jp.m).padStart(2, '0') + '-' + String(jp.d).padStart(2, '0');
    const key = code + '|' + dk;
    if (!groups[key]) groups[key] = { code: code, dk: dk, pairs: [] };
    groups[key].pairs.push({ in: inT, out: outT });
  });
  const keys = Object.keys(groups);
  if (!keys.length) return jsonResponse({ ok: false, error: 'bad_request', message: 'هیچ ردیف معتبری یافت نشد.', skipped: skipped }, 400);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!gd.obj.dailyAttendance) gd.obj.dailyAttendance = {};
    let savedDays = 0, savedPairs = 0;
    const unknownCodes = {};
    const empCodes = {};
    (gd.obj.employees || []).forEach(function (e) { if (e && e.code != null) empCodes[String(e.code).trim()] = true; });
    keys.forEach(function (k) {
      const g = groups[k];
      if (!empCodes[g.code]) unknownCodes[g.code] = true;
      if (!gd.obj.dailyAttendance[g.code]) gd.obj.dailyAttendance[g.code] = {};
      const store = gd.obj.dailyAttendance[g.code];
      const prev = store[g.dk] || {};
      let pairs = [];
      if (mode === 'merge') {
        for (let i = 1; i <= 4; i++) {
          const inn = String(prev['in' + i] || '').trim();
          const out = String(prev['out' + i] || '').trim();
          if (inn || out) pairs.push({ in: inn, out: out });
        }
      }
      g.pairs.forEach(function (p) {
        if (!pairs.some(function (x) { return x.in === p.in && x.out === p.out; })) pairs.push(p);
      });
      pairs = pairs.slice(0, 4);
      const rec = { in1: '', out1: '', in2: '', out2: '', in3: '', out3: '', in4: '', out4: '', note: prev.note || '' };
      pairs.forEach(function (p, idx) { rec['in' + (idx + 1)] = p.in || ''; rec['out' + (idx + 1)] = p.out || ''; });
      rec.importedAt = new Date().toISOString();
      rec.importedBy = who.name || who.role || 'admin';
      store[g.dk] = rec;
      savedDays++;
      savedPairs += pairs.length;
    });
    const put = await storePutData(cfg, gd.version, gd.obj, who.name || 'admin');
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, savedDays: savedDays, savedPairs: savedPairs, skipped: skipped, unknownCodes: Object.keys(unknownCodes).slice(0, 50), mode: mode, message: savedDays + ' روز ذخیره شد (' + savedPairs + ' جفت).' });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

function calcAgeYM(birthRaw, nowDate) {
  var p = parseImportDateToJalali(birthRaw);
  var by, bm, bd;
  if (p) { by = p.y; bm = p.m; bd = p.d; }
  else {
    var j = parseJalaliYMD(String(birthRaw || '').replace(/-/g, '/'));
    if (!j) return null;
    by = j.y; bm = j.m; bd = j.d;
  }
  var cy = Number((nowDate && nowDate.y) || 1405);
  var cm = Number((nowDate && nowDate.m) || 1);
  var cd = Number((nowDate && nowDate.d) || 1);
  var years = cy - by, months = cm - bm;
  if (cd < bd) months -= 1;
  if (months < 0) { years -= 1; months += 12; }
  if (years < 0) return { years: 0, months: 0, text: '0 سال' };
  return { years: years, months: Math.max(0, months), text: years + ' سال و ' + Math.max(0, months) + ' ماه' };
}
function ensureFamilySettings(obj) {
  if (!obj.settings) obj.settings = {};
  if (obj.settings.sonAlertAge == null || obj.settings.sonAlertAge === '') obj.settings.sonAlertAge = 18;
  if (!Array.isArray(obj.settings.childStatusOptions) || !obj.settings.childStatusOptions.length) {
    obj.settings.childStatusOptions = ['دانشجو', 'معلول', 'فرجه تا خدمت سربازی'];
  }
  if (obj.settings.suppInsurancePerPerson == null) obj.settings.suppInsurancePerPerson = 0;
}
function ensureEmpFamily(emp) {
  if (!emp.family || typeof emp.family !== 'object') emp.family = {};
  if (!Array.isArray(emp.family.members)) emp.family.members = [];
  // مهاجرت از مدل قدیمی
  if (!emp.family.members.length) {
    if (Array.isArray(emp.family.children)) {
      emp.family.children.forEach(function (ch, i) {
        if (!ch) return;
        emp.family.members.push({
          id: 'ch_' + i + '_' + Date.now(),
          relation: 'فرزند',
          name: ch.name || '',
          gender: ch.gender || '',
          birthDate: ch.birthDate || '',
          nationalId: ch.nationalId || '',
          idNumber: ch.idNumber || '',
          birthPlace: ch.birthPlace || '',
          issuePlace: ch.issuePlace || '',
          status: ch.status || '',
          eligibleChildAllowance: ch.eligibleChildAllowance !== false
        });
      });
    }
    function pushOne(rel, obj, prefix) {
      if (!obj || typeof obj !== 'object') return;
      var nm = obj.name || obj.fullName || '';
      if (!nm && !obj.nationalId && !obj.birthDate) return;
      emp.family.members.push({
        id: prefix + '_' + Date.now(),
        relation: rel,
        name: nm,
        gender: obj.gender || '',
        birthDate: obj.birthDate || '',
        nationalId: obj.nationalId || '',
        idNumber: obj.idNumber || '',
        birthPlace: obj.birthPlace || '',
        issuePlace: obj.issuePlace || '',
        status: '',
        eligibleChildAllowance: false
      });
    }
    pushOne('همسر', emp.family.spouse, 'sp');
    pushOne('پدر', emp.family.father, 'fa');
    pushOne('مادر', emp.family.mother, 'mo');
  }
  if (!Array.isArray(emp.family.children)) emp.family.children = [];
  if (!emp.family.spouse || typeof emp.family.spouse !== 'object') emp.family.spouse = {};
  if (!emp.family.father || typeof emp.family.father !== 'object') emp.family.father = {};
  if (!emp.family.mother || typeof emp.family.mother !== 'object') emp.family.mother = {};
  if (!emp.suppInsurance || typeof emp.suppInsurance !== 'object') emp.suppInsurance = { covered: [], deducted: [], deductCount: 0 };
  if (!Array.isArray(emp.suppInsurance.covered)) emp.suppInsurance.covered = [];
  if (!Array.isArray(emp.suppInsurance.deducted)) emp.suppInsurance.deducted = [];
  if (!Array.isArray(emp.systemMessages)) emp.systemMessages = [];
}
function syncChildrenCountsFromMembers(emp) {
  ensureEmpFamily(emp);
  var total = 0, eligible = 0;
  (emp.family.members || []).forEach(function (m) {
    if (!m) return;
    if (String(m.relation || '') === 'فرزند') {
      total++;
      if (m.eligibleChildAllowance === true) eligible++;
    }
  });
  // تعداد اولاد روی کارت = فقط مشمولان حق اولاد (برای نمایش؛ محاسبه هم از لیست اعضا است)
  emp.children = eligible;
  emp.childrenEligibleCount = eligible;
  // آینه قدیمی children برای سازگاری
  emp.family.children = (emp.family.members || []).filter(function (m) { return m && m.relation === 'فرزند'; }).map(function (m) {
    return {
      name: m.name, gender: m.gender, birthDate: m.birthDate, nationalId: m.nationalId,
      idNumber: m.idNumber, birthPlace: m.birthPlace, issuePlace: m.issuePlace,
      status: m.status, eligibleChildAllowance: !!m.eligibleChildAllowance
    };
  });
}
function refreshSonAgeMessages(obj, emp) {
  ensureFamilySettings(obj);
  ensureEmpFamily(emp);
  var alertAge = Number(obj.settings.sonAlertAge) || 18;
  var cy = Number((obj.settings || {}).currentYear) || 1405;
  var cm = Number((obj.settings || {}).currentMonth) || 1;
  var cd = Number((obj.settings || {}).currentDay) || 1;
  var now = { y: cy, m: cm, d: cd };
  (emp.family.members || []).forEach(function (ch, idx) {
    if (!ch || String(ch.relation || '') !== 'فرزند') return;
    var gender = String(ch.gender || '').trim();
    var isBoy = gender === 'پسر' || gender === 'مرد' || gender === 'male' || gender === 'M' || gender === 'پسر ';
    if (!isBoy) return;
    var age = calcAgeYM(ch.birthDate, now);
    if (!age || age.years < alertAge) return;
    var bp = parseImportDateToJalali(ch.birthDate) || parseJalaliYMD(String(ch.birthDate || '').replace(/-/g, '/'));
    // پیام سالانه: در ماه تولد، یا اگر سن >= آستانه و هنوز امسال پیام/حل نشده
    var inBirthMonth = bp ? (Number(bp.m) === cm) : true;
    if (!inBirthMonth) {
      // خارج از ماه تولد فقط اگر قبلاً هرگز برای این سن پیام نداده
      var anyPrev = (emp.systemMessages || []).some(function (m) {
        return m && m.type === 'son_age' && (m.memberId === ch.id || m.childName === ch.name);
      });
      if (anyPrev) return;
    } else if (bp && cd < Number(bp.d) && age.years === alertAge) {
      // هنوز به روز تولد نرسیده در سال آستانه
      return;
    }
    var msgKey = 'son_age_' + (ch.id || idx) + '_' + cy;
    var existing = (emp.systemMessages || []).find(function (m) { return m && m.key === msgKey; });
    if (existing) {
      if (existing.resolvedYear === cy || existing.resolvedAt) return;
      return; // باز است — دوباره نساز
    }
    if (!Array.isArray(emp.systemMessages)) emp.systemMessages = [];
    emp.systemMessages.push({
      id: 'msg_' + Date.now() + '_' + idx + '_' + Math.floor(Math.random() * 1000),
      key: msgKey,
      type: 'son_age',
      childIndex: idx,
      memberId: ch.id || null,
      childName: ch.name || ('فرزند ' + (idx + 1)),
      text: 'فرزند پسر «' + (ch.name || (idx + 1)) + '» ' + age.years + ' ساله شد (آستانه ' + alertAge + '، ماه جاری ' + cm + '). اگر همچنان مشمول حق اولاد است علت را بنویسید؛ وگرنه از حق اولاد خارج شود.',
      createdAt: new Date().toISOString(),
      year: cy,
      resolvedAt: null,
      resolution: null,
      resolvedYear: null,
      keepEligible: null,
      eligibleReason: null
    });
  });
}

/** همگام‌سازی آیتم کسر بیمه تکمیلی روی کارت کارمند */
function resolveSuppUnitAmount(obj) {
  var s = obj.settings || {};
  var keys = ['suppInsurancePerPerson', 'supplementaryInsurancePerPerson', 'suppInsPerPerson', 'suppInsuranceAmount', 'bimeTakmiliPerPerson'];
  for (var i = 0; i < keys.length; i++) {
    var v = Number(s[keys[i]]);
    if (v > 0) return Math.round(v);
  }
  var allows = obj.allowances || [];
  for (var j = 0; j < allows.length; j++) {
    var a = allows[j];
    if (!a || !a.name) continue;
    if (/بیمه\s*تکمیلی/.test(String(a.name))) {
      var av = Number(a.amount) || 0;
      if (av > 0) return Math.round(av);
    }
  }
  return 0;
}
function syncSuppInsuranceEmpItem(obj, emp) {
  ensureEmpFamily(emp);
  ensureFamilySettings(obj);
  var count = 0;
  if (emp.suppInsurance && Array.isArray(emp.suppInsurance.deducted)) count = emp.suppInsurance.deducted.length;
  else count = Number(emp.suppInsuranceDeductCount) || 0;
  emp.suppInsuranceDeduct = count > 0;
  emp.suppInsuranceDeductCount = count;
  if (emp.suppInsurance) emp.suppInsurance.deductCount = count;

  var unit = resolveSuppUnitAmount(obj);
  // اگر مبلغ در تنظیمات بود، در settings.suppInsurancePerPerson هم بنویس تا موتور یک منبع داشته باشد
  if (unit > 0) obj.settings.suppInsurancePerPerson = unit;

  var itemName = 'کسر بیمه تکمیلی';
  if (!Array.isArray(emp.customItems)) emp.customItems = [];
  var idx = -1;
  emp.customItems.forEach(function (ci, i) {
    if (ci && /بیمه\s*تکمیلی/.test(String(ci.name || ''))) idx = i;
  });
  if (count > 0) {
    var rec = {
      name: itemName,
      amount: unit > 0 ? unit : (idx >= 0 ? (Number(emp.customItems[idx].amount) || 0) : 0),
      isDeduction: true,
      entryType: 'quantity',
      enabled: true,
      active: true,
      value: true,
      flag: 'بلی',
      qtyDefault: count,
      duration: 'always',
      note: 'خودکار از اعضای خانواده — ' + count + ' نفر × ' + (unit || 0)
    };
    if (idx >= 0) {
      emp.customItems[idx] = Object.assign({}, emp.customItems[idx], rec);
    } else {
      emp.customItems.push(rec);
    }
    // فیلدهای کمکی که بعضی UIها می‌خوانند
    emp.suppInsuranceItem = { name: itemName, amount: rec.amount, qty: count, enabled: true };
    var cy = Number((obj.settings || {}).currentYear) || 0;
    var cm = Number((obj.settings || {}).currentMonth) || 0;
    if (cy && cm && obj.monthlyData) {
      var key = cy + '-' + cm;
      if (!obj.monthlyData[key]) obj.monthlyData[key] = {};
      if (!obj.monthlyData[key][String(emp.code)]) obj.monthlyData[key][String(emp.code)] = {};
      var row = obj.monthlyData[key][String(emp.code)];
      if (!row.qty || typeof row.qty !== 'object') row.qty = {};
      row.qty[itemName] = count;
    }
  } else if (idx >= 0) {
    emp.customItems[idx].enabled = false;
    emp.customItems[idx].flag = 'خیر';
    emp.customItems[idx].qtyDefault = 0;
    emp.customItems[idx].amount = unit || emp.customItems[idx].amount || 0;
    emp.suppInsuranceItem = { name: itemName, amount: unit, qty: 0, enabled: false };
  }
}

function syncFamilyQtyToMonthly(obj, emp) {
  var cy = Number((obj.settings || {}).currentYear) || 0;
  var cm = Number((obj.settings || {}).currentMonth) || 0;
  if (!cy || !cm || !obj.monthlyData) return;
  var key = cy + '-' + cm;
  if (!obj.monthlyData[key]) obj.monthlyData[key] = {};
  if (!obj.monthlyData[key][String(emp.code)]) obj.monthlyData[key][String(emp.code)] = {};
  var row = obj.monthlyData[key][String(emp.code)];
  if (!row.qty || typeof row.qty !== 'object') row.qty = {};
  var elig = Number(emp.childrenEligibleCount) || 0;
  row.qty['تعداد اولاد'] = elig;
  row.qty['اولاد'] = elig;
  row.qty['حق اولاد'] = elig;
  var supp = 0;
  if (emp.suppInsurance && Array.isArray(emp.suppInsurance.deducted)) supp = emp.suppInsurance.deducted.length;
  else supp = Number(emp.suppInsuranceDeductCount) || 0;
  row.qty['کسر بیمه تکمیلی'] = supp;
  row.qty['تعداد کسر بیمه تکمیلی'] = supp;
  row.qty['بیمه تکمیلی'] = supp;
}
function resyncAllSuppInsuranceItems(obj) {
  (obj.employees || []).forEach(function (emp) {
    if (!emp) return;
    ensureEmpFamily(emp);
    if ((emp.suppInsurance && emp.suppInsurance.deducted && emp.suppInsurance.deducted.length) || emp.suppInsuranceDeduct) {
      syncSuppInsuranceEmpItem(obj, emp);
    }
  });
}



/** ذخیره پایدار خانواده/بیمه/پیام — مستقل از فرم اصلی کارمند */
function ensureEmployeeExtras(obj) {
  if (!obj.employeeExtras || typeof obj.employeeExtras !== 'object') obj.employeeExtras = {};
  if (!obj.employeePhotos || typeof obj.employeePhotos !== 'object') obj.employeePhotos = {};
}
function snapshotEmpExtra(obj, emp) {
  if (!obj || !emp || emp.code == null) return;
  ensureEmployeeExtras(obj);
  var code = String(emp.code);
  // عکس فقط در employeePhotos — داخل extras نگذار (حجم همگام‌سازی)
  obj.employeeExtras[code] = {
    family: emp.family || { members: [] },
    suppInsurance: emp.suppInsurance || { covered: [], deducted: [], deductCount: 0 },
    systemMessages: Array.isArray(emp.systemMessages) ? emp.systemMessages : [],
    childrenEligibleCount: Number(emp.childrenEligibleCount) || 0,
    children: Number(emp.children) || 0,
    suppInsuranceDeduct: !!emp.suppInsuranceDeduct,
    suppInsuranceDeductCount: Number(emp.suppInsuranceDeductCount) || 0,
    hasPhoto: !!(obj.employeePhotos && obj.employeePhotos[code]) || !!emp.photo,
    updatedAt: new Date().toISOString()
  };
  // customItems مربوط به بیمه تکمیلی را هم نگه دار
  var suppItems = (emp.customItems || []).filter(function (ci) {
    return ci && /بیمه\s*تکمیلی/.test(String(ci.name || ''));
  });
  if (suppItems.length) obj.employeeExtras[code].suppCustomItems = suppItems;
}
function applyEmpExtra(obj, emp) {
  if (!obj || !emp || emp.code == null) return;
  ensureEmployeeExtras(obj);
  var code = String(emp.code);
  var ex = obj.employeeExtras[code];
  if (ex) {
    if (ex.family) emp.family = ex.family;
    if (ex.suppInsurance) emp.suppInsurance = ex.suppInsurance;
    if (Array.isArray(ex.systemMessages)) emp.systemMessages = ex.systemMessages;
    if (ex.childrenEligibleCount != null) emp.childrenEligibleCount = ex.childrenEligibleCount;
    if (ex.children != null) emp.children = ex.children;
    emp.suppInsuranceDeduct = !!ex.suppInsuranceDeduct;
    emp.suppInsuranceDeductCount = Number(ex.suppInsuranceDeductCount) || 0;
    if (Array.isArray(ex.suppCustomItems) && ex.suppCustomItems.length) {
      if (!Array.isArray(emp.customItems)) emp.customItems = [];
      // حذف قبلی‌های تکمیلی و جایگزینی
      emp.customItems = emp.customItems.filter(function (ci) {
        return !(ci && /بیمه\s*تکمیلی/.test(String(ci.name || '')));
      });
      ex.suppCustomItems.forEach(function (ci) { emp.customItems.push(ci); });
    }
  }
  var ph = (obj.employeePhotos && obj.employeePhotos[code]) || (ex && ex.photo) || null;
  if (ph) emp.photo = ph;
  else if (ex && !ex.hasPhoto && emp.photo && String(emp.photo).length > 5000) {
    // عکس یتیم/حجیم بدون ثبت در employeePhotos — برای سبک شدن نگه ندار
  }
}
function mergeAllEmployeeExtras(obj) {
  if (!obj || !Array.isArray(obj.employees)) return;
  ensureEmployeeExtras(obj);
  obj.employees.forEach(function (emp) {
    if (emp) applyEmpExtra(obj, emp);
  });
}

function storeEmpPhoto(obj, empCode, dataUrl) {
  if (!obj.employeePhotos || typeof obj.employeePhotos !== 'object') obj.employeePhotos = {};
  var code = String(empCode);
  if (dataUrl == null || dataUrl === '') {
    delete obj.employeePhotos[code];
    return null;
  }
  if (typeof dataUrl === 'string' && dataUrl.length < 250000 && /^data:image\//.test(dataUrl)) {
    obj.employeePhotos[code] = dataUrl;
    return dataUrl;
  }
  return null;
}
function getEmpPhoto(obj, emp) {
  if (!emp) return null;
  var code = String(emp.code);
  if (obj.employeePhotos && obj.employeePhotos[code]) return obj.employeePhotos[code];
  return emp.photo || null;
}

async function handleAdminEmployeeExtra(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  if (request.method === 'GET') {
    const url = new URL(request.url);
    const empCode = String(url.searchParams.get('empCode') || '').trim();
    if (!empCode) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    const emp = ((gd.obj && gd.obj.employees) || []).find(function (e) { return String(e.code) === empCode; });
    if (!emp) return jsonResponse({ ok: false, error: 'not_found' }, 404);
    ensureFamilySettings(gd.obj); ensureEmpFamily(emp); refreshSonAgeMessages(gd.obj, emp);
    const cy = Number((gd.obj.settings || {}).currentYear) || 1405;
    const cm = Number((gd.obj.settings || {}).currentMonth) || 1;
    const now = { y: cy, m: cm, d: 1 };
    const members = (emp.family.members || []).map(function (m, idx) {
      const age = calcAgeYM(m && m.birthDate, now);
      return Object.assign({}, m, { ageText: age ? age.text : '', ageYears: age ? age.years : null, ageMonths: age ? age.months : null, _idx: idx });
    });
    syncChildrenCountsFromMembers(emp);
    return jsonResponse({ ok: true, empCode: empCode, fullName: emp.fullName || '',
      childrenCount: Number(emp.children) || 0,
      childrenEligibleCount: Number(emp.childrenEligibleCount) || 0,
      family: { members: members, children: emp.family.children || [], spouse: emp.family.spouse || {}, father: emp.family.father || {}, mother: emp.family.mother || {} },
      photo: getEmpPhoto(gd.obj, emp), suppInsurance: emp.suppInsurance || { covered: [], deducted: [], deductCount: 0 },
      systemMessages: emp.systemMessages || [],
      settings: { sonAlertAge: Number(gd.obj.settings.sonAlertAge) || 18, childStatusOptions: gd.obj.settings.childStatusOptions || [], suppInsurancePerPerson: Number(gd.obj.settings.suppInsurancePerPerson) || 0 }
    });
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const body = r.body || {};
  const empCode = String(body.empCode || '').trim();
  const settingsOnly = !!(body.settings && who.role === 'admin' && !body.family && !body.suppInsurance && !body.resolveMessage && body.photo === undefined);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    ensureFamilySettings(gd.obj);
    if (body.settings && who.role === 'admin') {
      if (body.settings.sonAlertAge != null) gd.obj.settings.sonAlertAge = Math.max(1, Math.min(30, Number(body.settings.sonAlertAge) || 18));
      if (Array.isArray(body.settings.childStatusOptions)) gd.obj.settings.childStatusOptions = body.settings.childStatusOptions.map(function (x) { return String(x || '').trim(); }).filter(Boolean).slice(0, 30);
      if (body.settings.suppInsurancePerPerson != null) gd.obj.settings.suppInsurancePerPerson = Math.max(0, Math.round(Number(body.settings.suppInsurancePerPerson) || 0));
    }
    if (settingsOnly) {
      const putS = await storePutData(cfg, gd.version, gd.obj, who.name || 'admin');
      if (putS.fail) return storeFailResponse(putS.fail);
      if (putS.conflict) continue;
      resyncAllSuppInsuranceItems(gd.obj);
      return jsonResponse({ ok: true, message: 'تنظیمات ذخیره شد', settings: { sonAlertAge: gd.obj.settings.sonAlertAge, childStatusOptions: gd.obj.settings.childStatusOptions, suppInsurancePerPerson: gd.obj.settings.suppInsurancePerPerson } });
    }
    if (!empCode) return jsonResponse({ ok: false, error: 'bad_request', message: 'کد کارمند لازم است.' }, 400);
    const emp = ((gd.obj.employees) || []).find(function (e) { return String(e.code) === empCode; });
    if (!emp) return jsonResponse({ ok: false, error: 'not_found' }, 404);
    ensureEmpFamily(emp);
    if (body.family) {
      if (Array.isArray(body.family.members)) {
        emp.family.members = body.family.members.slice(0, 40).map(function (m, i) {
          var rel = String((m && m.relation) || '').trim().slice(0, 30);
          var isChild = rel === 'فرزند';
          return {
            id: String((m && m.id) || ('m_' + Date.now() + '_' + i)).slice(0, 40),
            relation: rel,
            name: String((m && m.name) || '').trim().slice(0, 80),
            gender: String((m && m.gender) || '').trim().slice(0, 20),
            birthDate: String((m && m.birthDate) || '').trim().slice(0, 20),
            nationalId: String((m && m.nationalId) || '').trim().slice(0, 20),
            idNumber: String((m && m.idNumber) || '').trim().slice(0, 20),
            birthPlace: String((m && m.birthPlace) || '').trim().slice(0, 60),
            issuePlace: String((m && m.issuePlace) || '').trim().slice(0, 60),
            status: String((m && m.status) || '').trim().slice(0, 40),
            eligibleChildAllowance: isChild ? !!(m && m.eligibleChildAllowance) : false
          };
        });
        syncChildrenCountsFromMembers(emp);
        syncSuppInsuranceEmpItem(gd.obj, emp);
      } else if (Array.isArray(body.family.children)) {
        // سازگاری قدیمی
        emp.family.children = body.family.children.slice(0, 20).map(function (ch) {
          return { name: String((ch && ch.name) || '').trim().slice(0, 80), gender: String((ch && ch.gender) || '').trim().slice(0, 20), birthDate: String((ch && ch.birthDate) || '').trim().slice(0, 20), nationalId: String((ch && ch.nationalId) || '').trim().slice(0, 20), idNumber: String((ch && ch.idNumber) || '').trim().slice(0, 20), birthPlace: String((ch && ch.birthPlace) || '').trim().slice(0, 60), issuePlace: String((ch && ch.issuePlace) || '').trim().slice(0, 60), status: String((ch && ch.status) || '').trim().slice(0, 40), eligibleChildAllowance: !!(ch && ch.eligibleChildAllowance) };
        });
        emp.family.members = emp.family.children.map(function (ch, i) {
          return Object.assign({ id: 'ch_' + i, relation: 'فرزند' }, ch);
        });
        syncChildrenCountsFromMembers(emp);
      }
    }
    if (body.photo !== undefined) {
      const ph = body.photo;
      if (ph == null || ph === '') {
        emp.photo = null;
        storeEmpPhoto(gd.obj, empCode, null);
      } else {
        const saved = storeEmpPhoto(gd.obj, empCode, ph);
        if (saved) emp.photo = saved;
      }
    }
    if (body.suppInsurance && typeof body.suppInsurance === 'object') {
      emp.suppInsurance.covered = Array.isArray(body.suppInsurance.covered) ? body.suppInsurance.covered.map(String).slice(0, 30) : [];
      emp.suppInsurance.deducted = Array.isArray(body.suppInsurance.deducted) ? body.suppInsurance.deducted.map(String).slice(0, 30) : [];
      emp.suppInsurance.deductCount = emp.suppInsurance.deducted.length;
      emp.suppInsuranceDeductCount = emp.suppInsurance.deductCount;
      emp.suppInsuranceDeduct = emp.suppInsurance.deductCount > 0;
      syncSuppInsuranceEmpItem(gd.obj, emp);
    }
    if (body.resolveMessage && body.resolveMessage.id) {
      const msg = (emp.systemMessages || []).find(function (m) { return m && m.id === body.resolveMessage.id; });
      if (msg) {
        msg.resolvedAt = new Date().toISOString();
        msg.resolution = String(body.resolveMessage.resolution || '').trim().slice(0, 80);
        msg.resolvedYear = Number((gd.obj.settings || {}).currentYear) || 1405;
        msg.keepEligible = body.resolveMessage.keepEligible === true || body.resolveMessage.keepEligible === 'true';
        msg.eligibleReason = String(body.resolveMessage.eligibleReason || '').trim().slice(0, 200);
        if (msg.type === 'son_age') {
          var mm = null;
          if (msg.memberId) mm = (emp.family.members || []).find(function (x) { return x && x.id === msg.memberId; });
          else if (msg.childIndex != null) mm = emp.family.members[msg.childIndex];
          if (mm) {
            mm.status = msg.resolution;
            if (msg.keepEligible) {
              mm.eligibleChildAllowance = true;
              mm.eligibleReason = msg.eligibleReason || msg.resolution;
            } else {
              mm.eligibleChildAllowance = false;
              mm.eligibleReason = '';
            }
          }
          syncChildrenCountsFromMembers(emp);
        }
      }
    }
    refreshSonAgeMessages(gd.obj, emp);
    snapshotEmpExtra(gd.obj, emp);
    try { syncFamilyQtyToMonthly(gd.obj, emp); } catch (eQ) {}
    const put = await storePutData(cfg, gd.version, gd.obj, who.name || 'admin');
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, message: 'ذخیره شد', childrenCount: Number(emp.children) || 0, childrenEligibleCount: Number(emp.childrenEligibleCount) || 0, deductCount: (emp.suppInsurance && emp.suppInsurance.deductCount) || 0, openMessages: (emp.systemMessages || []).filter(function (m) { return m && !m.resolvedAt; }).length });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}
/** افزونه: نمای کلی فقط‌خواندنی (تعداد اولاد/کسر بیمه هر کارمند + وضعیت هشدارها). هیچ چیزی ذخیره نمی‌کند. */
async function handleAdminFamilyOverview(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  const obj = gd.obj || {};
  ensureFamilySettings(obj);
  const st = obj.settings || {};
  const now = { y: Number(st.currentYear) || 1405, m: Number(st.currentMonth) || 1, d: Number(st.currentDay) || 1 };
  const qty = {};
  const alerts = {};
  (obj.employees || []).forEach(function (emp) {
    if (!emp || emp.code == null) return;
    ensureEmpFamily(emp);
    const members = emp.family.members || [];
    var kids = 0, elig = 0;
    members.forEach(function (m) {
      if (m && String(m.relation || '') === 'فرزند') { kids++; if (m.eligibleChildAllowance === true) elig++; }
    });
    if (!kids) elig = Number(emp.childrenEligibleCount != null ? emp.childrenEligibleCount : emp.children) || 0;
    var supp = 0;
    if (emp.suppInsurance && Array.isArray(emp.suppInsurance.deducted)) supp = emp.suppInsurance.deducted.length;
    else supp = Number(emp.suppInsuranceDeductCount) || 0;
    qty[String(emp.code)] = { children: elig, supp: supp };
    (emp.systemMessages || []).forEach(function (m) {
      if (!m || m.type !== 'son_age' || m.resolvedAt) return;
      var mem = null;
      if (m.memberId) mem = members.find(function (x) { return x && x.id === m.memberId; }) || null;
      if (!mem && m.childIndex != null) mem = members[m.childIndex] || null;
      const age = mem ? calcAgeYM(mem.birthDate, now) : null;
      alerts[String(emp.code) + '|' + m.id] = {
        childName: mem ? String(mem.name || '') : String(m.childName || ''),
        ageYears: age ? age.years : null,
        eligible: !!(mem && mem.eligibleChildAllowance === true),
        status: mem ? String(mem.status || '') : ''
      };
    });
  });
  return jsonResponse({ ok: true, year: now.y, month: now.m, alertAge: Number(st.sonAlertAge) || 18, qty: qty, alerts: alerts });
}

async function handleAdminSystemMessages(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  ensureFamilySettings(gd.obj);
  const all = [];
  var changed = false;
  (gd.obj.employees || []).forEach(function (emp) {
    ensureEmpFamily(emp);
    var before = (emp.systemMessages || []).length;
    refreshSonAgeMessages(gd.obj, emp);
    if ((emp.systemMessages || []).length !== before) {
      changed = true;
      snapshotEmpExtra(gd.obj, emp);
    }
    (emp.systemMessages || []).forEach(function (m) {
      if (!m) return;
      all.push({ empCode: emp.code, fullName: emp.fullName || '', id: m.id, type: m.type, text: m.text, createdAt: m.createdAt, resolvedAt: m.resolvedAt, resolution: m.resolution, eligibleReason: m.eligibleReason, year: m.year });
    });
  });
  if (changed) {
    try { await storePutData(cfg, gd.version, gd.obj, who.name || 'admin'); } catch (eSave) {}
  }
  all.sort(function (a, b) {
    if (!!a.resolvedAt !== !!b.resolvedAt) return a.resolvedAt ? 1 : -1;
    return String(b.createdAt || '').localeCompare(String(a.createdAt || ''));
  });
  return jsonResponse({ ok: true, messages: all.slice(0, 200), childStatusOptions: gd.obj.settings.childStatusOptions || [], sonAlertAge: Number(gd.obj.settings.sonAlertAge) || 18, suppInsurancePerPerson: Number(gd.obj.settings.suppInsurancePerPerson) || 0 });
}

async function handleAdminSaveTimesheetDays(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const empCode = String(r.body.code || r.body.empCode || '').trim();
  const days = Array.isArray(r.body.days) ? r.body.days : [];
  if (!empCode) {
    return jsonResponse({ ok: false, error: 'bad_request', message: 'کد پرسنلی الزامی است.' }, 400);
  }
  // فقط تنظیم earlyOt بدون روز
  if (!days.length && r.body.earlyOtEnabled != null) {
    // handled below after load
  } else if (!days.length) {
    return jsonResponse({ ok: false, error: 'bad_request', message: 'کد پرسنلی و حداقل یک روز الزامی است.' }, 400);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!gd.obj.dailyAttendance) gd.obj.dailyAttendance = {};
    if (!gd.obj.dailyAttendance[empCode]) gd.obj.dailyAttendance[empCode] = {};
    const store = gd.obj.dailyAttendance[empCode];
    const emp = (gd.obj.employees || []).find(function (e) { return String(e.code) === empCode; });
    if (r.body.earlyOtEnabled != null && emp) {
      emp.earlyOtEnabled = !!r.body.earlyOtEnabled;
    }
    if (!days.length && r.body.earlyOtEnabled != null) {
      const putEo = await storePutData(cfg, gd.version, gd.obj, who.name || 'admin');
      if (putEo && putEo.fail) return storeFailResponse(putEo.fail);
      if (putEo && putEo.conflict) continue;
      return jsonResponse({ ok: true, earlyOtEnabled: !!(emp && emp.earlyOtEnabled) });
    }
    const cal = getContractCalendar(gd.obj, (emp && emp.contractType) || 'normal');
    let saved = 0;
    days.forEach(function (d) {
      if (!d || !d.date) return;
      const p = parseJalaliYMD(d.date);
      if (!p) return;
      const dk = p.y + '-' + String(p.m).padStart(2, '0') + '-' + String(p.d).padStart(2, '0');
      const prev = store[dk] || {};
      const rec = {
        in1: String(d.in1 || '').trim(), out1: String(d.out1 || '').trim(),
        in2: String(d.in2 || '').trim(), out2: String(d.out2 || '').trim(),
        in3: String(d.in3 || '').trim(), out3: String(d.out3 || '').trim(),
        in4: String(d.in4 || '').trim(), out4: String(d.out4 || '').trim(),
        note: cleanTimesheetNote(d.note)
      };
      // علامت ویرایش دستی per-field
      const fields = ['in1','out1','in2','out2','in3','out3','in4','out4'];
      const editedFields = Object.assign({}, prev.editedFields || {});
      let any = false;
      fields.forEach(function(k){
        if (String(prev[k]||'') !== String(rec[k]||'')) {
          editedFields[k] = true;
          any = true;
        }
      });
      if (any) {
        rec.manualEdit = true;
        rec.editedBy = who.name || who.role || 'admin';
        rec.editedAt = new Date().toISOString();
        rec.editedFields = editedFields;
      } else if (prev.manualEdit) {
        rec.manualEdit = prev.manualEdit;
        rec.editedBy = prev.editedBy;
        rec.editedAt = prev.editedAt;
        rec.editedFields = prev.editedFields || {};
      }
      // اگر همه خالی → حذف
      if (!rec.in1 && !rec.out1 && !rec.in2 && !rec.out2 && !rec.in3 && !rec.out3 && !rec.in4 && !rec.out4 && !rec.note) {
        delete store[dk];
      } else {
        store[dk] = rec;
        saved++;
      }
    });
    // جمع ماه برای monthlyData (اختیاری)
    const year = Number(r.body.year);
    const month = Number(r.body.month);
    if (isInt(year, 1300, 1600) && isInt(month, 1, 12) && emp) {
      const key = year + '-' + month;
      if (!gd.obj.monthlyData) gd.obj.monthlyData = {};
      if (!gd.obj.monthlyData[key]) gd.obj.monthlyData[key] = {};
      if (!gd.obj.monthlyData[key][empCode]) gd.obj.monthlyData[key][empCode] = {};
      let sumOt = 0, sumWorkMin = 0, workDays = 0, sumDelay = 0, sumNight = 0, sumEarly = 0;
      const dim = daysInJalaliMonth(year, month);
      for (let d = 1; d <= dim; d++) {
        const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
        const punch = store[dk];
        if (!punch) continue;
        if (!punch.in1 && !punch.out1 && !punch.in2 && !punch.out2 && !punch.in3 && !punch.out3) continue;
        const p = parseJalaliYMD(dk.replace(/-/g, '/'));
        const nonWork = p ? isHolidayOrNonWork(gd.obj, p.y, p.m, p.d, (emp && emp.contractType) || 'normal') : false;
        const calc = computeDayTimesheet(cal, punch, {
          year: (p && p.y) || year, month: (p && p.m) || month, day: (p && p.d) || d,
          isHoliday: nonWork,
          floatCompensate: !!(punch && punch.floatCompensate) || !!cal.floatCompensate,
          earlyOtEnabled: !!(emp && (emp.earlyOtEnabled || emp.earlyOt))
        });
        if (calc.presentMinutes > 0 || calc.otMinutes > 0 || calc.nightMinutes > 0) {
          if (!nonWork && calc.workHours > 0) workDays++;
          sumWorkMin += calc.presentMinutes;
          sumOt += (calc.otMinutes || 0); // otMinutes already includes earlyOt
          sumNight += calc.nightMinutes || 0;
          sumEarly += calc.earlyOtMinutes || 0;
          sumDelay += calc.delayMinutes;
        }
      }
      const md = gd.obj.monthlyData[key][empCode];
      let otH = Math.round((sumOt / 60) * 100) / 100;
      const nightH = Math.round((sumNight / 60) * 100) / 100;
      const empOt = (gd.obj.employees || []).find(function (e) { return String(e.code) === String(empCode); });
      const cap = empOtCeilingHours(empOt);
      md.nightHours = nightH;
      md.earlyOtHours = Math.round((sumEarly / 60) * 100) / 100;
      if (cap != null) {
        md.otHoursTotal = otH;
        md.otHoursUnapproved = Math.max(0, Math.round((otH - cap) * 100) / 100);
        md.otHours = Math.min(otH, cap);
        md.otCeilingHours = cap;
      } else {
        md.otHours = otH;
        md.otHoursTotal = otH;
        md.otHoursUnapproved = 0;
      }
      md.workMinutes = sumWorkMin;
      md.delayMinutes = sumDelay;
      // کارکرد = پانچ‌های روز عادی + مرخصی/مأموریت روزانه تأییدشده همان ماه (فقط روز کاری)
      if (!md.workDays || r.body.updateWorkDays) {
        let leaveMis = 0;
        const ct = (emp && emp.contractType) || 'normal';
        (gd.obj.attendanceRequests || []).forEach(function (x) {
          if (String(x.empCode) !== empCode || x.status !== 'approved') return;
          if (x.mode !== 'daily') return;
          if (x.kind !== 'leave' && x.kind !== 'mission') return;
          leaveMis += countWorkingDaysInMonth(x.startDate, x.endDate || x.startDate, year, month, gd.obj, ct);
        });
        // جلوگیری از دوبارشماری: روزهایی که هم پانچ هم مرخصی دارند فقط یک‌بار
        // تقریبی: max(panches, leaveMis) if overlap unknown — بهتر: از day map
        md.workDays = recountEmpMonthWorkDays(gd.obj, year, month, empCode);
        // مرخصی/مأموریت بدون پانچ جداگانه در نمایش از درخواست‌ها محاسبه می‌شود
        md.leaveDays = 0;
        md.hourlyLeave = 0;
        md.missionDays = 0;
        (gd.obj.attendanceRequests || []).forEach(function (x) {
          if (String(x.empCode) !== empCode || x.status !== 'approved') return;
          if (x.kind === 'leave' && x.mode === 'daily')
            md.leaveDays += countWorkingDaysInMonth(x.startDate, x.endDate || x.startDate, year, month, gd.obj, ct);
          if (x.kind === 'leave' && x.mode === 'hourly') {
            const p = parseJalaliYMD(x.startDate);
            if (p && p.y === year && p.m === month) md.hourlyLeave += hoursBetween(x.fromTime, x.toTime);
          }
          if (x.kind === 'mission' && x.mode === 'daily')
            md.missionDays += countAllDaysInMonth(x.startDate, x.endDate || x.startDate, year, month);
        });
        md.leaveDays = Math.round(md.leaveDays * 100) / 100;
        md.hourlyLeave = Math.round(md.hourlyLeave * 100) / 100;
        md.missionDays = Math.round(md.missionDays * 100) / 100;
      }
    }
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, saved: saved, code: empCode });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}


function defaultAttendanceTypes() {
  return [
    { id: 'leave_annual', name: 'مرخصی استحقاقی', kind: 'leave', mode: 'daily', deductFromEntitlement: true, fixedDays: null, frequency: 'throughout_year', requiresAdminGrant: false },
    { id: 'leave_hourly', name: 'مرخصی ساعتی', kind: 'leave', mode: 'hourly', deductFromEntitlement: true, fixedDays: null, frequency: 'throughout_year', requiresAdminGrant: false },
    { id: 'leave_marriage', name: 'مرخصی ازدواج', kind: 'leave', mode: 'daily', deductFromEntitlement: false, fixedDays: 3, frequency: 'once_employment', requiresAdminGrant: false },
    { id: 'leave_birth', name: 'مرخصی تولد فرزند', kind: 'leave', mode: 'daily', deductFromEntitlement: false, fixedDays: 3, frequency: 'once_year', requiresAdminGrant: false },
    { id: 'leave_death', name: 'مرخصی فوت بستگان', kind: 'leave', mode: 'daily', deductFromEntitlement: false, fixedDays: 3, frequency: 'throughout_year', requiresAdminGrant: false },
    { id: 'leave_special', name: 'مرخصی خاص (با مجوز ادمین)', kind: 'leave', mode: 'daily', deductFromEntitlement: false, fixedDays: null, frequency: 'throughout_year', requiresAdminGrant: true },
    { id: 'leave_unpaid', name: 'مرخصی بدون حقوق', kind: 'leave', mode: 'daily', deductFromEntitlement: false, unpaid: true, fixedDays: null, frequency: 'throughout_year', requiresAdminGrant: false },
    { id: 'mission_daily', name: 'مأموریت روزانه', kind: 'mission', mode: 'daily', deductFromEntitlement: false, fixedDays: null, frequency: 'throughout_year', requiresAdminGrant: false },
    { id: 'mission_hourly', name: 'مأموریت ساعتی', kind: 'mission', mode: 'hourly', deductFromEntitlement: false, fixedDays: null, frequency: 'throughout_year', requiresAdminGrant: false }
  ];
}

function normalizeFreq(f) {
  if (f === 'once_employment' || f === 'once_year' || f === 'throughout_year') return f;
  return 'throughout_year';
}

function timeToMin(t) {
  const x = String(t || '').split(':');
  return (Number(x[0]) || 0) * 60 + (Number(x[1]) || 0);
}

function dateKey(str) {
  const p = parseJalaliYMD(str);
  if (!p) return '';
  return p.y + '-' + String(p.m).padStart(2, '0') + '-' + String(p.d).padStart(2, '0');
}

function expandRequestDays(req) {
  if (!req) return [];
  if (req.mode === 'hourly') {
    const k = dateKey(req.startDate);
    return k ? [k] : [];
  }
  return splitDaysByMonth(req.startDate, req.endDate || req.startDate).reduce(function (acc, chunk) {
    // expand each day key in chunk
    let d = 1;
    // approximate: we only have day counts per month; rebuild from start/end
    return acc;
  }, []);
}

function listDayKeys(startStr, endStr) {
  const a = parseJalaliYMD(startStr);
  const b = parseJalaliYMD(endStr) || a;
  if (!a) return [];
  const out = [];
  let y = a.y, m = a.m, d = a.d;
  for (let guard = 0; guard < 400; guard++) {
    if (y > b.y || (y === b.y && m > b.m) || (y === b.y && m === b.m && d > b.d)) break;
    out.push(y + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0'));
    d++;
    const dim = daysInJalaliMonth(y, m);
    if (d > dim) { d = 1; m++; if (m > 12) { m = 1; y++; } }
  }
  return out;
}

function requestsOverlap(a, b) {
  // ignore rejected
  if (!a || !b) return false;
  const daysA = a.mode === 'hourly' ? [dateKey(a.startDate)] : listDayKeys(a.startDate, a.endDate || a.startDate);
  const daysB = b.mode === 'hourly' ? [dateKey(b.startDate)] : listDayKeys(b.startDate, b.endDate || b.startDate);
  const setB = {};
  daysB.forEach(function (k) { setB[k] = true; });
  const shared = daysA.filter(function (k) { return setB[k]; });
  if (!shared.length) return false;
  // if either is daily, any shared day = conflict
  if (a.mode === 'daily' || b.mode === 'daily') return true;
  // both hourly on same day: check time overlap
  const a0 = timeToMin(a.fromTime), a1 = timeToMin(a.toTime);
  const b0 = timeToMin(b.fromTime), b1 = timeToMin(b.toTime);
  return a0 < b1 && b0 < a1;
}

function countTypeUsage(requests, empCode, typeId, year) {
  return (requests || []).filter(function (x) {
    if (String(x.empCode) !== String(empCode)) return false;
    if (String(x.typeId) !== String(typeId)) return false;
    if (x.status === 'rejected') return false;
    if (year != null) {
      const p = parseJalaliYMD(x.startDate);
      if (!p || p.y !== year) return false;
    }
    return true;
  }).length;
}

async function handleAdminGetAttendanceTypes(env) {
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  let types = (gd.obj && gd.obj.attendanceTypes) || [];
  if (!types.length) types = defaultAttendanceTypes();
  return jsonResponse({ ok: true, types: types });
}

async function handleAdminSaveAttendanceTypes(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  let types = Array.isArray(r.body.types) ? r.body.types : [];
  types = types.map(function (t, i) {
    const kind = t.kind === 'mission' ? 'mission' : 'leave';
    const mode = t.mode === 'hourly' ? 'hourly' : 'daily';
    let fixedDays = t.fixedDays;
    if (fixedDays === '' || fixedDays == null) fixedDays = null;
    else fixedDays = Number(fixedDays);
    if (fixedDays != null && (!isFinite(fixedDays) || fixedDays < 1)) fixedDays = null;
    return {
      id: String(t.id || ('t_' + i + '_' + Date.now().toString(36))),
      name: String(t.name || '').trim() || ('نوع ' + (i + 1)),
      kind: kind,
      mode: mode,
      deductFromEntitlement: kind === 'leave' ? !!t.deductFromEntitlement : false,
      fixedDays: fixedDays,
      frequency: normalizeFreq(t.frequency),
      requiresAdminGrant: !!t.requiresAdminGrant,
      unpaid: !!(t.unpaid || t.isUnpaid || (String(t.name||'').indexOf('بدون حقوق') >= 0))
    };
  }).filter(function (t) { return t.name; });

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    gd.obj.attendanceTypes = types;
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, types: types });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleEmpAttendanceTypes(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  let types = (gd.obj && gd.obj.attendanceTypes) || [];
  if (!types.length) types = defaultAttendanceTypes();
  const allReqs = (gd.obj && gd.obj.attendanceRequests) || [];
  const grants = ((gd.obj && gd.obj.attendanceGrants) || []).filter(function (g) {
    return String(g.empCode) === String(sess.code) && !g.consumed && !g.usedRequestId && !g.revoked && !g.revokedAt;
  });
  const settings = (gd.obj && gd.obj.settings) || {};
  const cy = Number(settings.currentYear) || 1405;

  function hasApprovedOrPending(typeId, yearOnly) {
    return allReqs.some(function (r) {
      if (String(r.empCode) !== String(sess.code)) return false;
      if (String(r.typeId) !== String(typeId)) return false;
      if (r.status === 'rejected') return false;
      // pending or approved counts as used for once_* limits
      if (yearOnly != null) {
        const p = parseJalaliYMD(r.startDate);
        if (!p || p.y !== yearOnly) return false;
      }
      return true;
    });
  }

  const visible = types.filter(function (t) {
    if (!t) return false;
    // admin-grant types: only if open unused grant
    if (t.requiresAdminGrant) {
      return grants.some(function (g) { return String(g.typeId) === String(t.id); });
    }
    // once_employment: hide after any non-rejected use
    if (t.frequency === 'once_employment') {
      if (hasApprovedOrPending(t.id, null)) return false;
    }
    // once_year: hide after use in current year
    if (t.frequency === 'once_year') {
      if (hasApprovedOrPending(t.id, cy)) return false;
    }
    return true;
  });
  return jsonResponse({ ok: true, types: visible, grants: grants });
}


/** تعدیل مانده مرخصی توسط ادمین: علامت + (بستانکار/پیش‌خور مجاز) یا − (بدهکار) */
async function handleAdminLeaveAdjust(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const empCode = String(r.body.empCode || '').trim();
  const sign = String(r.body.sign || r.body.type || '+').trim(); // + or -
  const days = Math.abs(Number(r.body.days) || 0);
  const year = Number(r.body.year) || 0;
  const reason = String(r.body.reason || '').trim();
  const mode = String(r.body.mode || 'daily'); // daily | hourly (hourly as fraction of day if hours given)
  let hours = Number(r.body.hours) || 0;
  if (!empCode || days <= 0 && hours <= 0) {
    return jsonResponse({ ok: false, error: 'bad_request', message: 'کد کارمند و مقدار روز/ساعت الزامی است.' }, 400);
  }
  let delta = days;
  if (hours > 0 && !(days > 0)) delta = Math.round((hours / 8) * 100) / 100;
  if (sign === '-' || sign === 'minus' || sign === 'بدهکار') delta = -Math.abs(delta);
  else delta = Math.abs(delta);

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    const emp = gd.obj.employees.find(function (e) { return String(e.code) === empCode; });
    if (!emp) return jsonResponse({ ok: false, error: 'not_found', message: 'کارمند یافت نشد.' }, 404);
    ensureEmpLeaveYears(emp, gd.obj);
    const settingsYear = Number((gd.obj.settings || {}).currentYear) || 1405;
    const cy = year || settingsYear;
    const source = String(r.body.source || 'current'); // current | prior
    if (!Array.isArray(emp.leaveAdjustments)) emp.leaveAdjustments = [];
    const detailYears = [];
    if (source === 'prior' && delta < 0) {
      // کسر از ذخیره سال‌های قبل (قدیمی‌تر اول)
      let left = Math.abs(delta);
      const years = listLeaveYearsSorted(emp).map(function (r) { return r.year; }).filter(function (y) { return y < cy; });
      for (let i = 0; i < years.length && left > 0; i++) {
        const row = getLeaveYearRow(emp, years[i]);
        if (row.settled) continue;
        const take = Math.min(Math.max(0, Number(row.remaining) || 0), left);
        if (take <= 0) continue;
        row.remaining = Math.round((Number(row.remaining) - take) * 100) / 100;
        row.used = Math.round((Number(row.used || 0) + take) * 100) / 100;
        left = Math.round((left - take) * 100) / 100;
        detailYears.push({ year: years[i], days: take });
      }
      if (left > 0) {
        return jsonResponse({ ok: false, error: 'no_prior', message: 'ذخیره سال‌های قبل کافی نیست. کمبود: ' + left + ' روز.' }, 400);
      }
      // ثبت در سال جاری که از ذخیره استفاده شده
      if (!emp.leaveUsedFromPrior) emp.leaveUsedFromPrior = {};
      if (!emp.leaveUsedFromPrior[String(settingsYear)]) emp.leaveUsedFromPrior[String(settingsYear)] = [];
      emp.leaveUsedFromPrior[String(settingsYear)].push({
        at: new Date().toISOString(), days: Math.abs(delta), fromYears: detailYears, by: who.name, reason: reason
      });
    } else {
      const row = getLeaveYearRow(emp, cy);
      if (row.settled) {
        return jsonResponse({ ok: false, error: 'settled', message: 'سال ' + cy + ' تسویه شده و قابل تعدیل نیست.' }, 400);
      }
      if (delta < 0) {
        row.used = Math.round((Number(row.used || 0) + Math.abs(delta)) * 100) / 100;
      } else {
        // بستانکار: به عنوان تعدیل مثبت روی سال جاری
      }
      // remaining از نو با accrued محاسبه می‌شود در ensure
      ensureEmpLeaveYears(emp, gd.obj);
      // اعمال مستقیم delta روی remaining پس از ensure
      const row2 = getLeaveYearRow(emp, cy);
      if (!row2.settled) {
        row2.remaining = Math.round((Number(row2.remaining || 0) + delta) * 100) / 100;
      }
      detailYears.push({ year: cy, days: Math.abs(delta) });
    }
    ensureEmpLeaveYears(emp, gd.obj);
    emp.leaveBalance = Number((emp.leaveYears[String(settingsYear)] || {}).remaining) || 0;
    emp.leaveUsedYear = Number((emp.leaveYears[String(settingsYear)] || {}).used) || 0;
    emp.leaveAdjustments.unshift({
      at: new Date().toISOString(),
      by: who.name,
      year: cy,
      source: source,
      delta: delta,
      sign: delta >= 0 ? '+' : '-',
      days: Math.abs(delta),
      detailYears: detailYears,
      reason: reason || (source === 'prior' ? 'استفاده از ذخیره سال‌های قبل' : (delta >= 0 ? 'بستانکار سال جاری' : 'بدهکار سال جاری')),
      mode: mode
    });
    if (emp.leaveAdjustments.length > 200) emp.leaveAdjustments.length = 200;
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({
      ok: true,
      message: 'تعدیل ثبت شد: ' + (delta >= 0 ? '+' : '') + delta + ' روز برای سال ' + cy,
      remaining: row.remaining,
      leaveBalance: emp.leaveBalance,
      yearRow: row
    });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminGrantAttendance(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  function grantStatus(g) {
    if (!g) return 'unknown';
    if (g.revoked || g.revokedAt) return 'revoked';
    if (g.consumed || g.usedRequestId) return 'used';
    // تاریخ پایان گذشته؟
    try {
      const to = g.dateTo || g.dateFrom || g.date || '';
      if (to) {
        const p = parseJalaliYMD(to);
        const cy = Number(((arguments[0] && arguments[0].settings) || {}).currentYear);
        // فقط با مقایسه رشته yyyy-mm-dd
        const key = dateKey(to);
        const today = (function () {
          // از تنظیمات سیستم اگر موجود
          return null;
        })();
        // بدون تقویم میلادی دقیق: فقط اگر dateTo با start درخواست بعدتر باشد در درخواست چک می‌شود
      }
    } catch (e0) {}
    return 'open';
  }

  // GET: فهرست همه مجوزها
  if (request.method === 'GET') {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    const list = ((gd.obj && gd.obj.attendanceGrants) || []).map(function (g) {
      const st = (g.revoked || g.revokedAt) ? 'revoked' : ((g.consumed || g.usedRequestId) ? 'used' : 'open');
      return {
        id: g.id,
        empCode: g.empCode,
        empName: g.empName || '',
        typeId: g.typeId,
        typeName: g.typeName || '',
        dateFrom: g.dateFrom || g.date || '',
        dateTo: g.dateTo || g.dateFrom || g.date || '',
        grantedBy: g.grantedBy || '',
        grantedAt: g.grantedAt || '',
        usedRequestId: g.usedRequestId || null,
        consumed: !!g.consumed,
        revoked: !!(g.revoked || g.revokedAt),
        revokedAt: g.revokedAt || null,
        revokedBy: g.revokedBy || null,
        status: st
      };
    });
    return jsonResponse({ ok: true, grants: list });
  }

  const r = await readBody(request);
  if (r.error) return r.error;
  const action = String(r.body.action || 'create').trim();

  // لغو زودهنگام / حذف
  if (action === 'revoke' || action === 'delete') {
    const id = String(r.body.id || r.body.grantId || '').trim();
    if (!id) return jsonResponse({ ok: false, error: 'bad_request', message: 'شناسه مجوز الزامی است.' }, 400);
    for (let attempt = 0; attempt < 4; attempt++) {
      const gd = await storeGetData(cfg);
      if (gd.fail) return storeFailResponse(gd.fail);
      if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
      if (!Array.isArray(gd.obj.attendanceGrants)) gd.obj.attendanceGrants = [];
      const idx = gd.obj.attendanceGrants.findIndex(function (g) { return g && String(g.id) === id; });
      if (idx < 0) return jsonResponse({ ok: false, error: 'not_found', message: 'مجوز یافت نشد.' }, 404);
      const g = gd.obj.attendanceGrants[idx];
      if (action === 'delete') {
        gd.obj.attendanceGrants.splice(idx, 1);
      } else {
        g.revoked = true;
        g.revokedAt = new Date().toISOString();
        g.revokedBy = who.name;
        // اگر رزرو شده با درخواست باز، رزرو را آزاد کن (درخواست همچنان باقی است تا ادمین/مدیر رد کند)
        g.reservedRequestId = null;
      }
      const put = await storePutData(cfg, gd.version, gd.obj, who.name);
      if (put.fail) return storeFailResponse(put.fail);
      if (put.conflict) continue;
      return jsonResponse({ ok: true, action: action, grant: g });
    }
    return jsonResponse({ ok: false, error: 'conflict' }, 409);
  }

  // صدور مجوز جدید
  const empCode = String(r.body.empCode || '').trim();
  const typeId = String(r.body.typeId || '').trim();
  const dateFrom = String(r.body.dateFrom || r.body.date || '').trim();
  const dateTo = String(r.body.dateTo || r.body.dateFrom || r.body.date || '').trim();
  if (!empCode || !typeId) return jsonResponse({ ok: false, error: 'bad_request', message: 'کد کارمند و نوع الزامی است.' }, 400);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    const emp = gd.obj.employees.find(function (e) { return String(e.code) === empCode; });
    if (!emp) return jsonResponse({ ok: false, error: 'not_found', message: 'کارمند یافت نشد.' }, 404);
    let types = gd.obj.attendanceTypes || [];
    if (!types.length) types = defaultAttendanceTypes();
    const tdef = types.find(function (t) { return String(t.id) === typeId; });
    if (!tdef) return jsonResponse({ ok: false, error: 'bad_type', message: 'نوع مرخصی یافت نشد.' }, 404);
    if (!Array.isArray(gd.obj.attendanceGrants)) gd.obj.attendanceGrants = [];
    const grant = {
      id: 'g_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6),
      empCode: empCode,
      empName: emp.fullName || '',
      typeId: typeId,
      typeName: tdef.name || '',
      date: dateFrom || '',
      dateFrom: dateFrom || '',
      dateTo: dateTo || dateFrom || '',
      grantedBy: who.name,
      grantedAt: new Date().toISOString(),
      usedRequestId: null,
      consumed: false,
      revoked: false,
      revokedAt: null,
      revokedBy: null,
      allowAdvance: !!(r.body.allowAdvance || tdef.allowAdvance || (tdef.deductFromEntitlement && String(tdef.id || '').indexOf('leave') === 0))
    };
    gd.obj.attendanceGrants.unshift(grant);
    if (gd.obj.attendanceGrants.length > 2000) gd.obj.attendanceGrants.length = 2000;
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, grant: grant });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}


async function handleAdminSetCurrentMonth(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  const month = Number(r.body.month);
  if (!isInt(year, 1300, 1600) || !isInt(month, 1, 12)) {
    return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!gd.obj.settings) gd.obj.settings = {};
    gd.obj.settings.currentYear = year;
    gd.obj.settings.currentMonth = month;
    ensureContractCalendars(gd.obj);
    const ct = String(r.body.contractType || 'normal').trim() || 'normal';
    if (!gd.obj.settings.contractCalendars[ct]) {
      gd.obj.settings.contractCalendars[ct] = { workWeekDays: [6,0,1,2,3], countNonWorkDaysAsLeave: false, holidaysByYear: {} };
    }
    const cal = gd.obj.settings.contractCalendars[ct];
    if (r.body.countNonWorkDaysAsLeave != null) {
      cal.countNonWorkDaysAsLeave = !!r.body.countNonWorkDaysAsLeave;
    }
    // نوع «ساعتی» همیشه کل شبانه‌روز/همه روزها محاسبه می‌شود؛ ساعت و روز کاری آن ذخیره نمی‌شود
    if (ct !== 'hourly') {
      if (Array.isArray(r.body.workWeekDays)) {
        cal.workWeekDays = r.body.workWeekDays.map(Number).filter(function (d) { return d >= 0 && d <= 6; });
      }
      const schedFields = ['workStart','workEnd','breakStart','breakEnd','dayEnd'];
      schedFields.forEach(function (f) {
        if (r.body[f] != null && String(r.body[f]).trim() !== '') cal[f] = String(r.body[f]).trim();
      });
      if (r.body.floatMinutes != null) cal.floatMinutes = Math.max(0, Number(r.body.floatMinutes) || 0);
      if (r.body.hasBreak != null) cal.hasBreak = !!r.body.hasBreak;
      if (r.body.breakCountsAsWork != null) cal.breakCountsAsWork = !!r.body.breakCountsAsWork;
      if (r.body.floatCompensate != null) cal.floatCompensate = !!r.body.floatCompensate;
    }
    // سازگاری با فیلدهای قدیمی
    if (ct === 'normal') {
      gd.obj.settings.workWeekDays = cal.workWeekDays.slice();
      gd.obj.settings.countNonWorkDaysAsLeave = cal.countNonWorkDaysAsLeave;
    }
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    const tdef = (gd.obj.settings.contractTypesList || []).find(function (t) { return t.id === ct; });
    return jsonResponse({
      ok: true,
      year: year,
      month: month,
      contractType: ct,
      contractTypeName: tdef ? tdef.name : ct,
      workWeekDays: cal.workWeekDays,
      countNonWorkDaysAsLeave: !!cal.countNonWorkDaysAsLeave,
      workStart: cal.workStart,
      workEnd: cal.workEnd,
      breakStart: cal.breakStart,
      breakEnd: cal.breakEnd,
      dayEnd: cal.dayEnd,
      floatMinutes: cal.floatMinutes,
      breakCountsAsWork: !!cal.breakCountsAsWork,
      floatCompensate: !!cal.floatCompensate,
      contractTypesList: gd.obj.settings.contractTypesList
    });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}



async function handleAdminContractTypes(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  if (request.method === 'GET') {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) gd.obj = {};
    ensureContractCalendars(gd.obj);
    return jsonResponse({ ok: true, contractTypesList: gd.obj.settings.contractTypesList });
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const id = String(r.body.id || '').trim();
  const name = String(r.body.name || '').trim();
  if (!id || !name) return jsonResponse({ ok: false, error: 'bad_request', message: 'شناسه و نام الزامی است.' }, 400);
  if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(id)) {
    return jsonResponse({ ok: false, error: 'bad_request', message: 'شناسه باید با حرف انگلیسی شروع شود.' }, 400);
  }
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    ensureContractCalendars(gd.obj);
    const list = gd.obj.settings.contractTypesList;
    if (list.some(function (t) { return t.id === id; })) {
      return jsonResponse({ ok: false, error: 'exists', message: 'این شناسه قبلاً ثبت شده است.' }, 400);
    }
    list.push({ id: id, name: name });
    gd.obj.settings.contractCalendars[id] = {
      workWeekDays: [6, 0, 1, 2, 3],
      countNonWorkDaysAsLeave: false,
      holidaysByYear: {}
    };
    // leave policy byContractType slot
    if (!gd.obj.settings.leavePolicy) gd.obj.settings.leavePolicy = {};
    if (!gd.obj.settings.leavePolicy.byContractType) gd.obj.settings.leavePolicy.byContractType = {};
    if (gd.obj.settings.leavePolicy.byContractType[id] == null) {
      gd.obj.settings.leavePolicy.byContractType[id] = Number(gd.obj.settings.leavePolicy.annualDays) || 26;
    }
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, contractTypesList: list, id: id, name: name });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminGetHolidays(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const url = new URL(request.url);
  const year = Number(url.searchParams.get('year')) || 1405;
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) gd.obj = {};
  ensureContractCalendars(gd.obj);
  const urlCt = new URL(request.url);
  const ct = String(urlCt.searchParams.get('contractType') || 'normal').trim() || 'normal';
  const cal = getContractCalendar(gd.obj, ct);
  const by = cal.holidaysByYear || {};
  const allDs = cal.daySchedules || {};
  const yearPrefix = String(year) + '/';
  const yearPrefix2 = String(year) + '-';
  const daySchedules = {};
  Object.keys(allDs).forEach(function (k) {
    if (k.indexOf(yearPrefix) === 0 || k.indexOf(yearPrefix2) === 0) daySchedules[k.replace(/-/g, '/')] = allDs[k];
  });
  return jsonResponse({ ok: true, year: year, contractType: ct, days: by[String(year)] || [], daySchedules: daySchedules, defaultSchedule: normalizeWorkSchedule(cal) });
}

async function handleAdminSaveHolidays(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  // آبجکت‌های تعطیل شرایطی را نگه دار (map(String) آن‌ها را خراب می‌کرد)
  const days = Array.isArray(r.body.days) ? r.body.days.map(function (item) {
    if (item != null && typeof item === 'object') {
      const o = {
        date: String(item.date || item.day || '').trim(),
        type: item.type || (item.conditional ? 'conditional' : 'official'),
        conditional: !!(item.conditional || item.type === 'conditional'),
        fullDay: item.fullDay !== false && !item.closeFrom,
        closeFrom: item.closeFrom || null,
        closeTo: item.closeTo || null,
        otDuringOfficial: item.otDuringOfficial != null ? !!item.otDuringOfficial : true,
        otAfterOfficial: item.otAfterOfficial != null ? !!item.otAfterOfficial : true,
        applyFloat: item.applyFloat != null ? !!item.applyFloat : false,
        reason: item.reason ? String(item.reason).trim() : ''
      };
      if (!o.date) return null;
      return o;
    }
    const s = String(item || '').trim();
    return s || null;
  }).filter(Boolean) : [];
  if (!isInt(year, 1300, 1600)) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!gd.obj.settings) gd.obj.settings = {};
    ensureContractCalendars(gd.obj);
    const ct = String(r.body.contractType || 'normal').trim() || 'normal';
    if (!gd.obj.settings.contractCalendars[ct]) {
      gd.obj.settings.contractCalendars[ct] = { workWeekDays: [6,0,1,2,3], countNonWorkDaysAsLeave: false, holidaysByYear: {} };
    }
    if (!gd.obj.settings.contractCalendars[ct].holidaysByYear) gd.obj.settings.contractCalendars[ct].holidaysByYear = {};
    gd.obj.settings.contractCalendars[ct].holidaysByYear[String(year)] = days.slice();
    if (!gd.obj.settings.contractCalendars[ct]._seededYears) gd.obj.settings.contractCalendars[ct]._seededYears = {};
    gd.obj.settings.contractCalendars[ct]._seededYears[String(year)] = true; // حتی اگر خالی — دیگر پیش‌فرض نریز
    // برنامه موظفی روزانه (اولویت بر ساعت کلی نوع قرارداد)
    if (r.body.daySchedules != null && typeof r.body.daySchedules === 'object') {
      if (!gd.obj.settings.contractCalendars[ct].daySchedules) gd.obj.settings.contractCalendars[ct].daySchedules = {};
      const ds = gd.obj.settings.contractCalendars[ct].daySchedules;
      const yearPrefix = String(year) + '/';
      // حذف برنامه‌های همان سال سپس نوشتن جدید
      Object.keys(ds).forEach(function (k) {
        const kk = String(k).replace(/-/g, '/');
        if (kk.indexOf(yearPrefix) === 0) delete ds[k];
      });
      Object.keys(r.body.daySchedules).forEach(function (k) {
        const kk = String(k).replace(/-/g, '/');
        if (kk.indexOf(yearPrefix) !== 0) return;
        const v = r.body.daySchedules[k];
        if (!v || typeof v !== 'object') return;
        if (!v.workStart && !v.workEnd) return;
        ds[kk] = {
          workStart: v.workStart ? String(v.workStart).trim() : '',
          workEnd: v.workEnd ? String(v.workEnd).trim() : '',
          dayEnd: v.dayEnd ? String(v.dayEnd).trim() : '',
          floatMinutes: v.floatMinutes != null && v.floatMinutes !== '' ? Number(v.floatMinutes) : null
        };
      });
    }
    if (ct === 'normal') {
      if (!gd.obj.settings.holidaysByYear) gd.obj.settings.holidaysByYear = {};
      gd.obj.settings.holidaysByYear[String(year)] = days.slice();
    }
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, year: year, contractType: ct, count: days.length });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminGetCurrentMonth(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) gd.obj = {};
  ensureContractCalendars(gd.obj);
  const s = gd.obj.settings || {};
  const url = new URL(request.url);
  const ct = String(url.searchParams.get('contractType') || 'normal').trim() || 'normal';
  const cal = getContractCalendar(gd.obj, ct);
  const tdef = (s.contractTypesList || []).find(function (t) { return t.id === ct; });
  return jsonResponse({
    ok: true,
    year: Number(s.currentYear) || 1405,
    month: Number(s.currentMonth) || Number(s.activeMonth) || 0,
    contractType: ct,
    contractTypeName: tdef ? tdef.name : ct,
    workWeekDays: cal.workWeekDays,
    countNonWorkDaysAsLeave: cal.countNonWorkDaysAsLeave,
    workStart: cal.workStart,
    workEnd: cal.workEnd,
    hasBreak: !!cal.hasBreak,
    breakStart: cal.breakStart,
    breakEnd: cal.breakEnd,
    dayEnd: cal.dayEnd,
    floatMinutes: cal.floatMinutes,
    breakCountsAsWork: !!cal.breakCountsAsWork,
    floatCompensate: !!cal.floatCompensate,
    officialWorkMinutes: officialWorkMinutes(cal),
    contractTypesList: s.contractTypesList || defaultContractTypesList()
  });
}

async function handleAdminListAttendanceRequests(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  const month = Number(r.body.month);
  const code = String(r.body.code || '').trim();
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  let list = (gd.obj && gd.obj.attendanceRequests) || [];
  if (isInt(year, 1300, 1600) && isInt(month, 1, 12)) {
    list = list.filter(function (x) {
      const p = parseJalaliYMD(x.startDate);
      if (!p) return false;
      if (p.y === year && p.m === month) return true;
      if (x.mode === 'daily' && x.endDate) {
        return splitDaysByMonth(x.startDate, x.endDate).some(function (c) { return c.year === year && c.month === month; });
      }
      return false;
    });
  }
  if (code) list = list.filter(function (x) { return String(x.empCode) === code; });
  return jsonResponse({ ok: true, requests: list.slice(0, 500) });
}

async function handleAdminUpdateAttendanceRequest(request, who, env) {
  if (who.role !== 'admin') {
    return jsonResponse({ ok: false, error: 'forbidden', message: 'فقط ادمین می‌تواند ویرایش کند.' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const b = r.body;
  const id = String(b.id || '').trim();
  if (!id) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.attendanceRequests)) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    const req = gd.obj.attendanceRequests.find(function (x) { return x.id === id; });
    if (!req) return jsonResponse({ ok: false, error: 'not_found' }, 404);
    if (b.empCode != null) req.empCode = String(b.empCode).trim();
    if (b.typeId != null) req.typeId = String(b.typeId).trim();
    if (b.startDate != null) req.startDate = String(b.startDate).trim();
    if (b.endDate != null) req.endDate = String(b.endDate).trim();
    if (b.fromTime != null) req.fromTime = String(b.fromTime).trim();
    if (b.toTime != null) req.toTime = String(b.toTime).trim();
    if (b.place != null) req.place = String(b.place).trim();
    if (b.reason != null) req.reason = String(b.reason).trim();
    const prevStatus = req.status;
    if (b.status != null) req.status = String(b.status);
    // اگر از تأیید نهایی خارج شد → برگرداندن اثر؛ اگر تازه تأیید شد → اعمال
    if (prevStatus === 'approved' && req.status !== 'approved') {
      try { restoreLeaveDeduction(gd.obj, req); } catch (e) {}
      try {
        reverseApprovedRequestFromTimesheet(gd.obj, req);
        req._timesheetApplied = false;
      } catch (e) {}
    } else if (prevStatus !== 'approved' && req.status === 'approved') {
      try { applyLeaveDeduction(gd.obj, req); } catch (e) {}
      try {
        if (!req._timesheetApplied) {
          applyApprovedRequestToTimesheet(gd.obj, req);
          req._timesheetApplied = true;
        }
      } catch (e) {}
    }
    // resolve type name
    let types = gd.obj.attendanceTypes || [];
    if (!types.length) types = defaultAttendanceTypes();
    const tdef = types.find(function (t) { return String(t.id) === String(req.typeId); });
    if (tdef) {
      req.typeName = tdef.name || '';
      req.kind = tdef.kind === 'mission' ? 'mission' : 'leave';
      req.mode = tdef.mode === 'hourly' ? 'hourly' : 'daily';
    }
    const emp = (gd.obj.employees || []).find(function (e) { return String(e.code) === String(req.empCode); });
    if (emp) req.empName = emp.fullName || '';
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, request: req });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminCreateAttendanceRequest(request, who, env) {
  if (who.role !== 'admin') {
    return jsonResponse({ ok: false, error: 'forbidden', message: 'فقط ادمین سیستم می‌تواند مستقیم ثبت کند.' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const b = r.body;
  const empCode = String(b.empCode || '').trim();
  const typeId = String(b.typeId || '').trim();
  let startDate = String(b.startDate || '').trim();
  let endDate = String(b.endDate || b.startDate || '').trim();
  const fromTime = String(b.fromTime || '').trim();
  const toTime = String(b.toTime || '').trim();
  const place = String(b.place || '').trim();
  const reason = String(b.reason || '').trim();
  if (!empCode || !startDate) return jsonResponse({ ok: false, error: 'bad_request', message: 'کد و تاریخ الزامی است.' }, 400);

  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj || !Array.isArray(gd.obj.employees)) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    const emp = gd.obj.employees.find(function (e) { return String(e.code) === empCode; });
    if (!emp) return jsonResponse({ ok: false, error: 'not_found' }, 404);
    let types = gd.obj.attendanceTypes || [];
    if (!types.length) types = defaultAttendanceTypes();
    const tdef = typeId ? types.find(function (t) { return String(t.id) === typeId; }) : null;
    let kind = 'leave', mode = 'daily', typeName = '', fixedDays = null, deduct = false;
    if (tdef) {
      kind = tdef.kind === 'mission' ? 'mission' : 'leave';
      mode = tdef.mode === 'hourly' ? 'hourly' : 'daily';
      typeName = tdef.name || '';
      fixedDays = tdef.fixedDays != null && tdef.fixedDays !== '' ? Number(tdef.fixedDays) : null;
      deduct = kind === 'leave' && !!tdef.deductFromEntitlement;
      if (fixedDays && mode === 'daily') {
        const p = parseJalaliYMD(startDate);
        if (p) {
          let d = p.d + fixedDays - 1, m = p.m, y = p.y;
          while (d > daysInJalaliMonth(y, m)) { d -= daysInJalaliMonth(y, m); m++; if (m > 12) { m = 1; y++; } }
          endDate = y + '/' + String(m).padStart(2, '0') + '/' + String(d).padStart(2, '0');
        }
      }
    }
    if (mode === 'hourly') {
      if (!fromTime || !toTime) {
        return jsonResponse({ ok: false, error: 'bad_request', message: 'ساعت شروع و پایان الزامی است.' }, 400);
      }
      const sh = assertHourlyWithinShift(gd.obj, emp, fromTime, toTime);
      if (!sh.ok) {
        return jsonResponse({ ok: false, error: 'outside_shift', message: sh.message }, 400);
      }
    }
    if (kind === 'mission' && !place) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'محل مأموریت الزامی است.' }, 400);
    }
    if (!Array.isArray(gd.obj.attendanceRequests)) gd.obj.attendanceRequests = [];
    const req = {
      id: newRequestId(),
      empCode: String(emp.code),
      empName: emp.fullName || '',
      managerCode: String(emp.managerCode || ''),
      managerName: '',
      typeId: typeId || '',
      typeName: typeName,
      deductFromEntitlement: deduct,
      fixedDays: fixedDays,
      kind, mode,
      startDate,
      endDate: mode === 'hourly' ? startDate : endDate,
      fromTime: mode === 'hourly' ? fromTime : '',
      toTime: mode === 'hourly' ? toTime : '',
      place: kind === 'mission' ? place : '',
      reason: reason,
      status: 'approved',
      rejectReason: '',
      createdAt: new Date().toISOString(),
      decidedAt: new Date().toISOString(),
      decidedBy: 'admin:' + who.name,
      adminOverride: true
    };
    // overlap check
    const conflict = gd.obj.attendanceRequests.find(function (x) {
      if (String(x.empCode) !== String(emp.code) || x.status === 'rejected') return false;
      return requestsOverlap(req, x);
    });
    if (conflict) {
      return jsonResponse({ ok: false, error: 'overlap', message: 'تداخل با درخواست موجود: ' + (conflict.typeName || conflict.id) }, 400);
    }
    gd.obj.attendanceRequests.unshift(req);
    if (gd.obj.attendanceRequests.length > 2000) gd.obj.attendanceRequests.length = 2000;
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true, request: req });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminDeleteAttendanceRequest(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden', message: 'دسترسی حذف ندارید.' }, 403);
  }
  const url = new URL(request.url);
  let id = String(url.searchParams.get('id') || '').trim();
  if (!id) {
    const r = await readBody(request);
    if (r.error) return r.error;
    id = String((r.body && r.body.id) || '').trim();
  }
  if (!id) return jsonResponse({ ok: false, error: 'bad_request', message: 'شناسه درخواست لازم است.' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!Array.isArray(gd.obj.attendanceRequests)) gd.obj.attendanceRequests = [];
    let idx = gd.obj.attendanceRequests.findIndex(function (x) { return String(x.id) === String(id); });
    // اگر id پیدا نشد ولی قبلاً حذف شده — موفق
    if (idx < 0) {
      return jsonResponse({ ok: true, alreadyGone: true, message: 'این درخواست از قبل حذف شده بود.' });
    }
    const doomed = gd.obj.attendanceRequests[idx];
    if (doomed && (doomed.status === 'approved' || doomed.status === 'approved_l1' || doomed.bulkCover)) {
      try { restoreLeaveDeduction(gd.obj, doomed); } catch (e) {}
      try { reverseApprovedRequestFromTimesheet(gd.obj, doomed); } catch (e) {}
      // پاک کردن توضیح خودکار از dailyAttendance
      try {
        const code = String(doomed.empCode || '');
        const p = parseJalaliYMD(doomed.startDate);
        if (code && p && gd.obj.dailyAttendance && gd.obj.dailyAttendance[code]) {
          const dk = p.y + '-' + String(p.m).padStart(2, '0') + '-' + String(p.d).padStart(2, '0');
          const dateFa = p.y + '/' + String(p.m).padStart(2, '0') + '/' + String(p.d).padStart(2, '0');
          const rec = gd.obj.dailyAttendance[code][dk] || gd.obj.dailyAttendance[code][dateFa];
          if (rec && rec.note) {
            const auto = 'ثبت خودکار پوشش کسر کار';
            let n = String(rec.note);
            n = n.split('؛').map(function (s) { return s.trim(); }).filter(function (s) {
              return s && s.indexOf(auto) < 0 && s.indexOf('پوشش کسر') < 0;
            }).join('؛ ');
            rec.note = n;
            if (!rec.note && !rec.in1 && !rec.out1 && !rec.in2 && !rec.out2) {
              delete gd.obj.dailyAttendance[code][dk];
              delete gd.obj.dailyAttendance[code][dateFa];
            }
          }
        }
      } catch (e) {}
    }
    const empCodeDel = doomed ? doomed.empCode : '';
    gd.obj.attendanceRequests.splice(idx, 1);
    // حذف تکراری‌های همان پوشش خودکار (id خراب / تکراری)
    if (doomed && doomed.bulkCover) {
      gd.obj.attendanceRequests = gd.obj.attendanceRequests.filter(function (x) {
        if (!x || !x.bulkCover) return true;
        if (String(x.empCode) !== String(doomed.empCode)) return true;
        if (String(x.startDate) !== String(doomed.startDate)) return true;
        if (String(x.fromTime || '') !== String(doomed.fromTime || '')) return true;
        if (String(x.toTime || '') !== String(doomed.toTime || '')) return true;
        if (String(x.kind) !== String(doomed.kind)) return true;
        // این یکی همان رکورد در حال حذف است که splice شده — بقیه تکراری
        return String(x.id) === String(doomed.id);
      });
    }
    if (empCodeDel) {
      try { rebuildEmpLeaveUsedFromRequests(gd.obj, empCodeDel); } catch (e) {}
    }
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

// ---------- Login page (admin/operator) ----------
async function checkLogin(name, pass, users) {
  const nh = await sha256(name);
  const ph = await sha256(pass);
  let found = null;
  for (const n of Object.keys(users)) {
    const userOk = sameBytes(nh, await sha256(n));
    const passOk = sameBytes(ph, await sha256(users[n].password));
    if (userOk && passOk && found === null) found = { name: n, role: users[n].role };
  }
  return found;
}

function safeNext(n) {
  return (typeof n === 'string' && n.charAt(0) === '/' && n.charAt(1) !== '/' && n.indexOf('\\') < 0 && n.length < 500) ? n : '/';
}

function loginPage(opts) {
  const msg = opts.error ? 'نام کاربری یا رمز عبور اشتباه است.'
    : (opts.expired ? 'نشست شما به پایان رسید؛ لطفاً دوباره وارد شوید.'
    : (opts.loggedOut ? 'از سیستم خارج شدید.' : ''));
  const action = '/login?next=' + encodeURIComponent(opts.next || '/') + (opts.popup ? '&popup=1' : '');
  const html = '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1"><title>ورود — پارسپهر</title>' +
    '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f766e;font-family:Tahoma,Arial,sans-serif;}' +
    '.c{background:#fff;border-radius:12px;padding:28px;width:100%;max-width:360px;box-shadow:0 8px 30px rgba(0,0,0,.25);}' +
    'h1{font-size:1.1rem;color:#0f766e;text-align:center;margin:0 0 6px}p.s{font-size:.85rem;color:#64748b;text-align:center;margin:0 0 16px}' +
    'label{display:block;font-size:.85rem;margin:10px 0 4px;color:#0f172a}input{width:100%;box-sizing:border-box;padding:9px;border:1px solid #99f6e4;border-radius:8px;font-size:1rem}' +
    'button{width:100%;margin-top:16px;padding:10px;border:0;border-radius:8px;background:#0f766e;color:#fff;font-size:1rem;cursor:pointer}' +
    '.m{color:#b91c1c;font-size:.85rem;text-align:center;margin-bottom:8px;min-height:1em}' +
    'a.emp{display:block;text-align:center;margin-top:14px;font-size:.8rem;color:#0f766e}</style></head><body><div class="c">' +
    '<h1>ورود به سیستم حقوق و دستمزد پارسپهر</h1><p class="s">نام کاربری و رمز عبور خود را وارد کنید</p>' +
    '<div class="m">' + msg + '</div>' +
    '<form method="post" action="' + action + '"><label for="u">نام کاربری</label>' +
    '<input id="u" name="username" autocomplete="username" autofocus required>' +
    '<label for="p">رمز عبور</label><input id="p" name="password" type="password" autocomplete="current-password" required>' +
    '<button type="submit">ورود</button></form>' +
    '<a class="emp" href="/employee">ورود کارکنان (مشاهده فیش)</a></div></body></html>';
  return new Response(html, {
    status: opts.error ? 401 : 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
      'X-Robots-Tag': 'noindex, nofollow'
    }
  });
}

async function handleLogin(request, env, users) {
  const url = new URL(request.url);
  const next = safeNext(url.searchParams.get('next'));
  const popup = url.searchParams.get('popup') === '1';
  if (request.method === 'GET') {
    return loginPage({ next: next, popup: popup, expired: url.searchParams.get('expired') === '1', loggedOut: url.searchParams.get('loggedout') === '1' });
  }
  if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin') return new Response('Forbidden', { status: 403 });
  let name = '';
  let pass = '';
  try {
    const form = await request.formData();
    name = String(form.get('username') || '');
    pass = String(form.get('password') || '');
  } catch (e) {}
  const found = await checkLogin(name, pass, users);
  if (!found) {
    await new Promise(function (r) { setTimeout(r, 600); });
    return loginPage({ next: next, popup: popup, error: true });
  }
  const cookie = sessionCookie(await makeToken(env, found.name, Math.floor(Date.now() / 1000) + SESSION_IDLE_SECONDS));
  console.log(JSON.stringify({ event: 'login', user: found.name }));
  if (popup) {
    return new Response('<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"></head><body style="font-family:Tahoma,Arial,sans-serif;text-align:center;padding:40px">' +
      '<p>ورود انجام شد. این پنجره را ببندید و به برنامه برگردید.</p><script>try{window.close()}catch(e){}</script></body></html>', {
      status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': cookie, 'Cache-Control': 'no-store' }
    });
  }
  return new Response(null, { status: 303, headers: { Location: next, 'Set-Cookie': cookie, 'Cache-Control': 'no-store' } });
}

function handleLogout() {
  return new Response(null, { status: 303, headers: { Location: '/login?loggedout=1', 'Set-Cookie': CLEAR_COOKIE, 'Cache-Control': 'no-store' } });
}

function notLoggedIn(request, url) {
  // employee portal pages are public (they handle their own auth)
  if (url.pathname === '/employee' || url.pathname.indexOf('/employee/') === 0) {
    return null; // signal to continue
  }
  const dest = request.headers.get('Sec-Fetch-Dest');
  const accept = request.headers.get('Accept') || '';
  const isPage = request.method === 'GET' && url.pathname.indexOf('/api/') !== 0 &&
    (dest === 'document' || (dest === null && accept.indexOf('text/html') >= 0));
  if (isPage) {
    return new Response(null, { status: 303, headers: { Location: '/login?next=' + encodeURIComponent(url.pathname + url.search), 'Cache-Control': 'no-store' } });
  }
  return jsonResponse({ ok: false, error: 'login_required' }, 401);
}

function withCookie(res, cookie) {
  const h = new Headers(res.headers);
  h.append('Set-Cookie', cookie);
  return new Response(res.body, { status: res.status, headers: h });
}

async function route(request, env, users, found) {
  const user = found.name;
  const adminConfigured = Object.keys(users).some(function (n) { return users[n].role === 'admin'; });
  const who = { name: user, role: adminConfigured ? found.role : 'admin' };
  const path = new URL(request.url).pathname;

  if (path === '/api/whoami') return handleWhoami(request, who, adminConfigured, env);
  if (path.indexOf('/api/state/') === 0) return handleState(request, who, env, path);
  if (path === '/api/payroll') return handlePayroll(request, user, env);
  if (path === '/api/calc') return handleCalc(request, user, env);
  if (path === '/api/admin/contracts') return handleAdminContracts(request, who, env);
  if (path === '/api/admin/accounting-export') return handleAdminAccountingExport(request, who, env);
  if (path === '/api/admin/payroll-contract-check') return handleAdminPayrollContractCheck(request, who, env);
  if (path === '/api/admin/portal-view') {
    if (request.method === 'GET') return handleAdminGetPortalView(request, who, env);
    return handleAdminSavePortalView(request, who, env);
  }
  if (path === '/api/admin/user-access') {
    if (request.method === 'GET') return handleAdminGetUserAccess(request, who, env);
    return handleAdminSaveUserAccess(request, who, env);
  }
  if (path === '/api/admin/set-emp-password') return handleAdminSetEmpPassword(request, who, env);
  if (path === '/api/admin/set-manager') return handleAdminSetManager(request, who, env);
  if (path === '/api/admin/get-manager') return handleAdminGetManager(request, who, env);
  if (path === '/api/admin/timesheet') return handleAdminTimesheet(request, who, env);
  if (path === '/api/admin/bulk-hourly-cover') return handleAdminBulkHourlyCover(request, who, env);
  if (path === '/api/admin/shortfall-settings') return handleAdminShortfallSettings(request, who, env);
  if (path === '/api/admin/import-punches') return handleAdminImportPunches(request, who, env);
  if (path === '/api/admin/employee-extra') return handleAdminEmployeeExtra(request, who, env);
  if (path === '/api/admin/system-messages') return handleAdminSystemMessages(request, who, env);
  if (path === '/api/admin/family-overview') return handleAdminFamilyOverview(request, who, env);
  if (path === '/api/admin/timesheet-days') return handleAdminSaveTimesheetDays(request, who, env);
  if (path === '/api/admin/portal-boot.js') {
    return new Response(PORTAL_ADMIN_JS, {
      status: 200,
      headers: {
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  }
  if (path === '/api/admin/attendance-types') {
    if (request.method === 'GET') return handleAdminGetAttendanceTypes(env);
    return handleAdminSaveAttendanceTypes(request, who, env);
  }
  if (path === '/api/admin/grant-attendance') return handleAdminGrantAttendance(request, who, env);
  if (path === '/api/admin/leave-adjust') return handleAdminLeaveAdjust(request, who, env);
  if (path === '/api/admin/set-current-month') return handleAdminSetCurrentMonth(request, who, env);
  if (path === '/api/admin/get-current-month') return handleAdminGetCurrentMonth(request, who, env);
  if (path === '/api/admin/contract-types') return handleAdminContractTypes(request, who, env);
  if (path === '/api/admin/holidays') {
    if (request.method === 'POST') return handleAdminSaveHolidays(request, who, env);
    return handleAdminGetHolidays(request, who, env);
  }
  if (path === '/api/admin/attendance-requests') return handleAdminListAttendanceRequests(request, who, env);
  if (path === '/api/admin/attendance-request') {
    if (request.method === 'DELETE') return handleAdminDeleteAttendanceRequest(request, who, env);
    if (request.method === 'PUT') return handleAdminUpdateAttendanceRequest(request, who, env);
    return handleAdminCreateAttendanceRequest(request, who, env);
  }

  const h = new Headers(request.headers);
  h.delete('If-None-Match');
  h.delete('If-Modified-Since');
  const res = await env.ASSETS.fetch(new Request(request, { headers: h }));

  const headers = new Headers(res.headers);
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Robots-Tag', 'noindex, nofollow');

  const type = res.headers.get('Content-Type') || '';
  if (request.method !== 'GET' || res.status !== 200 || type.indexOf('text/html') < 0) {
    return new Response(res.body, { status: res.status, headers });
  }

  console.log(JSON.stringify({ event: 'page', user: user, path: path }));
  const html = await res.text();
  headers.delete('Content-Length');
  headers.delete('Content-Encoding');
  headers.delete('ETag');
  return new Response(await stamp(html, user, env), { status: 200, headers });
}


// ---------- Employee decree & profile (portal view) ----------
function getPortalViewConfig(obj) {
  const c = (obj && obj.portalViewConfig) || {};
  return {
    showDecree: c.showDecree !== false,
    decreeMode: c.decreeMode || 'self', // self | self_and_manager | all | selected
    decreeSelectedCodes: Array.isArray(c.decreeSelectedCodes) ? c.decreeSelectedCodes.map(String) : [],
    decreeFields: Array.isArray(c.decreeFields) ? c.decreeFields : null, // null = all available
    showProfile: c.showProfile !== false,
    profileMode: c.profileMode || 'self',
    profileSelectedCodes: Array.isArray(c.profileSelectedCodes) ? c.profileSelectedCodes.map(String) : [],
    profileFields: Array.isArray(c.profileFields) ? c.profileFields : null
  };
}

function canViewPortalSection(cfg, modeKey, selectedKey, empCode, emp, allEmployees) {
  const mode = cfg[modeKey] || 'self';
  const code = String(empCode);
  if (mode === 'all') return true;
  if (mode === 'self') return true; // viewer is always self for emp portal; managers handled separately if needed
  if (mode === 'self_and_manager') return true; // employee always sees own
  if (mode === 'selected') {
    const list = cfg[selectedKey] || [];
    return list.indexOf(code) >= 0 || list.length === 0; // empty selected = treat as none visible unless self always?
  }
  return true;
}

function buildDecreeItemsForEmp(obj, emp, allowedFieldIds) {
  const items = [];
  const code = String(emp.code);
  const headers = Array.isArray(obj.decreeHeaders) ? obj.decreeHeaders : [];
  const vals = (obj.decreeValues && (obj.decreeValues[code] || obj.decreeValues[emp.code])) || {};
  const seenNames = {};

  function isAllowed(id, name) {
    if (!allowedFieldIds || !allowedFieldIds.length) return true;
    if (allowedFieldIds.indexOf('decree_all') >= 0) return true;
    const idS = String(id || '');
    const nameS = String(name || '').trim();
    for (let i = 0; i < allowedFieldIds.length; i++) {
      const a = String(allowedFieldIds[i]);
      if (a === idS || a === nameS) return true;
      if (a.indexOf('name:') === 0 && a.slice(5) === nameS) return true;
      // partial name match for flexibility
      if (nameS && (a === nameS || nameS.indexOf(a) >= 0 || a.indexOf(nameS) >= 0)) return true;
    }
    return false;
  }

  function push(id, name, amount) {
    const n = String(name || '').trim();
    if (!n) return;
    if (!isAllowed(id, n)) return;
    if (seenNames[n]) {
      // keep higher absolute amount if duplicate name
      const existing = items.find(function (x) { return x.name === n; });
      if (existing && Math.abs(Number(amount) || 0) > Math.abs(Number(existing.amount) || 0)) {
        existing.amount = Number(amount) || 0;
        existing.id = id;
      }
      return;
    }
    seenNames[n] = true;
    items.push({ id: String(id || n), name: n, amount: Number(amount) || 0 });
  }

  // 1) حقوق پایه
  push('basic', 'حقوق پایه', emp.basicSalary);

  // 2) همه هدرهای حکم (انتقال انتخابی) + مقادیر ذخیره‌شده
  headers.forEach(function (h) {
    if (!h) return;
    const id = String(h.id != null ? h.id : (h.name || ''));
    const name = String(h.name || h.id || '').trim();
    if (!name) return;
    let amt = 0;
    if (vals[h.id] != null && vals[h.id] !== '') amt = Number(vals[h.id]) || 0;
    else if (vals[id] != null && vals[id] !== '') amt = Number(vals[id]) || 0;
    else if (vals[name] != null && vals[name] !== '') amt = Number(vals[name]) || 0;
    else {
      // search any key in vals that matches id or name
      Object.keys(vals).forEach(function (k) {
        if (String(k) === id || String(k) === name || String(k) === String(h.id)) {
          amt = Number(vals[k]) || 0;
        }
      });
    }
    push(id, name, amt);
  });

  // 3) اگر در decreeValues کلیدهایی هست که در headers نیست
  Object.keys(vals).forEach(function (k) {
    const nameGuess = String(k);
    // skip pure numeric if already covered
    if (seenNames[nameGuess]) return;
    // try find header by id
    const h = headers.find(function (x) { return x && (String(x.id) === String(k) || String(x.name) === String(k)); });
    if (h) return; // already handled
    const amt = Number(vals[k]) || 0;
    push(String(k), nameGuess, amt);
  });

  // 4) همه مزایا (allowances) — نه فقط ۵ مورد ثابت
  (obj.allowances || []).forEach(function (a) {
    if (!a || !a.name) return;
    if (String(a.name).startsWith('آیتم جدید')) return;
    if (a.fromEmployee) return; // employee-specific handled via custom
    const id = String(a.id || a.name);
    const name = String(a.name).trim();
    let amt = Number(a.amount) || 0;
    // common adjustments
    if (a.id === 'child' || name.indexOf('اولاد') >= 0) { var _ec = 0; (emp.family && emp.family.members || []).forEach(function(m){ if (m && m.relation==='فرزند' && m.eligibleChildAllowance === true) _ec++; }); amt = amt * _ec; }
    if (a.id === 'marital' || name.indexOf('تأهل') >= 0 || name.indexOf('تاهل') >= 0) {
      if (!(emp.marital === 'married' || emp.marital === 'provider')) amt = 0;
    }
    if (a.id === 'seniority' || name.indexOf('سنوات') >= 0) {
      const empSen = Number(emp.seniorityBase);
      if (!isNaN(empSen) && emp.seniorityBase !== '' && emp.seniorityBase != null) amt = empSen;
    }
    push(id, name, amt);
  });

  // 5) آیتم‌های سفارشی کارمند (غیر کسورات)
  (emp.customItems || emp.customs || []).forEach(function (ci, idx) {
    if (!ci || !ci.name) return;
    if (ci.isDeduction) return;
    const n = String(ci.name).trim();
    if (/^(کسورات|کسر|معوقه)/.test(n)) return;
    const id = 'custom_' + idx + '_' + n;
    push(id, n, ci.amount);
    // also allow match via name: prefix
    if (allowedFieldIds && allowedFieldIds.length && allowedFieldIds.indexOf('name:' + n) >= 0) {
      // already pushed if isAllowed passed; ensure
      if (!seenNames[n]) push('name:' + n, n, ci.amount);
    }
  });

  // 6) فیلدهای رایج روی خود کارت کارمند اگر مقدار دارند
  const empDirect = [
    { id: 'seniorityBase', name: 'پایه سنوات', amount: emp.seniorityBase },
    { id: 'dailyRate', name: 'نرخ روزانه', amount: emp.dailyRate },
    { id: 'hourlyRate', name: 'نرخ ساعتی', amount: emp.hourlyRate }
  ];
  empDirect.forEach(function (d) {
    if (d.amount == null || d.amount === '') return;
    if (seenNames[d.name]) return;
    push(d.id, d.name, d.amount);
  });

  return items;
}

function buildProfileFieldsForEmp(emp, allowedKeys) {
  const contractFa = { normal: 'عادی', daily: 'روزمزد', hourly: 'ساعتی' };
  const maritalFa = { single: 'مجرد', married: 'متأهل', provider: 'معیل' };
  const statusFa = { active: 'فعال', inactive: 'غیرفعال', sick: 'استعلاجی', suspend: 'تعلیق' };
  const all = [
    { key: 'fullName', label: 'نام و نام خانوادگی', value: emp.fullName || '' },
    { key: 'code', label: 'کد پرسنلی', value: emp.code || '' },
    { key: 'position', label: 'سمت', value: emp.position || '' },
    { key: 'unit', label: 'واحد', value: emp.unit || '' },
    { key: 'workplace', label: 'محل خدمت', value: emp.workplace || '' },
    { key: 'hireDate', label: 'تاریخ استخدام', value: emp.hireDate || '' },
    { key: 'endDate', label: 'تاریخ پایان', value: emp.endDate || '' },
    { key: 'contractType', label: 'نوع قرارداد', value: contractFa[emp.contractType] || emp.contractType || 'عادی' },
    { key: 'marital', label: 'وضعیت تأهل', value: maritalFa[emp.marital] || emp.marital || '' },
    { key: 'children', label: 'تعداد اولاد', value: emp.children != null ? emp.children : '' },
    { key: 'bankName', label: 'نام بانک', value: emp.bankName || '' },
    { key: 'accountNumber', label: 'شماره حساب', value: emp.accountNumber || '' },
    { key: 'insuranceNo', label: 'شماره بیمه', value: emp.insuranceNo || '' },
    { key: 'nationalId', label: 'کد ملی', value: emp.nationalId || emp.nationalCode || '' },
    { key: 'mobile', label: 'موبایل', value: emp.mobile || emp.phone || '' },
    { key: 'status', label: 'وضعیت', value: statusFa[emp.status] || emp.status || 'فعال' },
    { key: 'managerCode', label: 'کد مدیر سطح ۱', value: emp.managerCode || '' },
    { key: 'managerCode2', label: 'کد مدیر سطح ۲', value: emp.managerCode2 || '' },
    { key: 'basicSalary', label: 'حقوق پایه', value: emp.basicSalary != null ? Number(emp.basicSalary).toLocaleString('fa-IR') : '' },
    { key: 'seniorityBase', label: 'پایه سنوات', value: emp.seniorityBase != null && emp.seniorityBase !== '' ? Number(emp.seniorityBase).toLocaleString('fa-IR') : '' },
    { key: 'insuranceNo2', label: 'شماره بیمه (ثانویه)', value: emp.insuranceNo2 || '' },
    { key: 'fatherName', label: 'نام پدر', value: emp.fatherName || '' },
    { key: 'birthDate', label: 'تاریخ تولد', value: emp.birthDate || '' },
    { key: 'address', label: 'آدرس', value: emp.address || '' },
    { key: 'email', label: 'ایمیل', value: emp.email || '' }
  ];
  // also include any extra keys on emp that look useful (string/number)
  const skip = { customItems:1, customs:1, portalPassHash:1, portalEnabled:1, loanRemaining:1, monthlyLoan:1, loanLocked:1, password:1 };
  Object.keys(emp || {}).forEach(function (k) {
    if (skip[k]) return;
    if (all.some(function (f) { return f.key === k; })) return;
    const v = emp[k];
    if (v == null || v === '') return;
    if (typeof v === 'object') return;
    all.push({ key: k, label: k, value: v });
  });
  if (!allowedKeys || !allowedKeys.length) return all;
  return all.filter(function (f) { return allowedKeys.indexOf(f.key) >= 0; });
}

async function handleEmpDecree(request, env) {
  if (request.method !== 'GET') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const cfgStore = storeConfig(env);
  if (!cfgStore) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfgStore);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) return jsonResponse({ ok: false, message: 'داده‌ای یافت نشد.' }, 404);
  const pvc = getPortalViewConfig(gd.obj);
  if (!pvc.showDecree) return jsonResponse({ ok: false, error: 'disabled', message: 'نمایش حکم توسط ادمین غیرفعال است.' });
  const emp = (gd.obj.employees || []).find(function (e) { return String(e.code) === String(sess.code); });
  if (!emp) return jsonResponse({ ok: false, message: 'کارمند یافت نشد.' }, 404);
  // selected mode: must be in list
  if (pvc.decreeMode === 'selected') {
    const list = pvc.decreeSelectedCodes || [];
    if (list.length && list.indexOf(String(sess.code)) < 0) {
      return jsonResponse({ ok: false, error: 'disabled', message: 'نمایش حکم برای شما فعال نیست.' });
    }
  }
  const items = buildDecreeItemsForEmp(gd.obj, emp, pvc.decreeFields);
  let total = 0;
  items.forEach(function (it) { total += Number(it.amount) || 0; });
  return jsonResponse({ ok: true, fullName: emp.fullName || '', position: emp.position || '', code: emp.code, items: items, total: total });
}

async function handleEmpProfile(request, env) {
  if (request.method !== 'GET') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const cfgStore = storeConfig(env);
  if (!cfgStore) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfgStore);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) return jsonResponse({ ok: false, message: 'داده‌ای یافت نشد.' }, 404);
  const pvc = getPortalViewConfig(gd.obj);
  if (!pvc.showProfile) return jsonResponse({ ok: false, error: 'disabled', message: 'نمایش مشخصات توسط ادمین غیرفعال است.' });
  const emp = (gd.obj.employees || []).find(function (e) { return String(e.code) === String(sess.code); });
  if (!emp) return jsonResponse({ ok: false, message: 'کارمند یافت نشد.' }, 404);
  if (pvc.profileMode === 'selected') {
    const list = pvc.profileSelectedCodes || [];
    if (list.length && list.indexOf(String(sess.code)) < 0) {
      return jsonResponse({ ok: false, error: 'disabled', message: 'نمایش مشخصات برای شما فعال نیست.' });
    }
  }
  const fields = buildProfileFieldsForEmp(emp, pvc.profileFields);
  return jsonResponse({ ok: true, fields: fields });
}


function defaultUserAccess() {
  return {
    portalTabs: {
      work: true,
      leaveDaily: true,
      leaveHourly: true,
      missionDaily: true,
      missionHourly: true,
      ot: true,
      night: true,
      absenceHourly: true
    },
    timesheetCols: {
      punch: true,
      work: true,
      ot: true,
      night: true,
      eot: true,
      abs: true,
      mis: true,
      lv: true,
      note: true
    }
  };
}

function normalizeUserAccess(raw) {
  const d = defaultUserAccess();
  const r = raw && typeof raw === 'object' ? raw : {};
  const pt = r.portalTabs && typeof r.portalTabs === 'object' ? r.portalTabs : {};
  const tc = r.timesheetCols && typeof r.timesheetCols === 'object' ? r.timesheetCols : {};
  Object.keys(d.portalTabs).forEach(function (k) {
    if (pt[k] != null) d.portalTabs[k] = !!pt[k];
  });
  Object.keys(d.timesheetCols).forEach(function (k) {
    if (tc[k] != null) d.timesheetCols[k] = !!tc[k];
  });
  return d;
}

async function handleAdminGetUserAccess(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  if (!gd.obj) gd.obj = {};
  if (!gd.obj.settings) gd.obj.settings = {};
  const ua = normalizeUserAccess(gd.obj.settings.userAccess);
  return jsonResponse({ ok: true, userAccess: ua });
}

async function handleAdminSaveUserAccess(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) gd.obj = {};
    if (!gd.obj.settings) gd.obj.settings = {};
    gd.obj.settings.userAccess = normalizeUserAccess(r.body.userAccess || r.body);
    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put && put.ok) {
      return jsonResponse({ ok: true, userAccess: gd.obj.settings.userAccess });
    }
    if (put && put.conflict) continue;
    return jsonResponse({ ok: false, error: (put && put.error) || 'save_failed' }, 500);
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleAdminGetPortalView(request, who, env) {
  if (request.method !== 'GET') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  if (who.role !== 'admin') return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  const cfgStore = storeConfig(env);
  if (!cfgStore) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfgStore);
  if (gd.fail) return storeFailResponse(gd.fail);
  const obj = gd.obj || {};
  const pvc = getPortalViewConfig(obj);
  // available decree field options from live data
  const decreeOptions = [];
  decreeOptions.push({ id: 'basic', name: 'حقوق پایه' });
  (obj.decreeHeaders || []).forEach(function (h) {
    if (!h) return;
    const id = String(h.id || h.name || '');
    const name = String(h.name || h.id || '').trim();
    if (name) decreeOptions.push({ id: id, name: name });
  });
  (obj.allowances || []).forEach(function (a) {
    if (!a || !a.name) return;
    if (String(a.name).startsWith('آیتم جدید')) return;
    const id = a.id || a.name;
    if (!decreeOptions.some(function (o) { return o.name === a.name; })) {
      decreeOptions.push({ id: String(id), name: String(a.name) });
    }
  });
  // unique custom item names across employees
  const customNames = {};
  (obj.employees || []).forEach(function (e) {
    (e.customItems || e.customs || []).forEach(function (ci) {
      if (!ci || !ci.name || ci.isDeduction) return;
      const n = String(ci.name).trim();
      if (/^(کسورات|کسر|معوقه)/.test(n)) return;
      customNames[n] = true;
    });
  });
  Object.keys(customNames).forEach(function (n) {
    if (!decreeOptions.some(function (o) { return o.name === n; })) {
      decreeOptions.push({ id: 'name:' + n, name: n });
    }
  });
  const profileOptions = [
    { key: 'fullName', label: 'نام و نام خانوادگی' },
    { key: 'code', label: 'کد پرسنلی' },
    { key: 'position', label: 'سمت' },
    { key: 'unit', label: 'واحد' },
    { key: 'workplace', label: 'محل خدمت' },
    { key: 'hireDate', label: 'تاریخ استخدام' },
    { key: 'endDate', label: 'تاریخ پایان' },
    { key: 'contractType', label: 'نوع قرارداد' },
    { key: 'marital', label: 'وضعیت تأهل' },
    { key: 'children', label: 'تعداد اولاد' },
    { key: 'bankName', label: 'نام بانک' },
    { key: 'accountNumber', label: 'شماره حساب' },
    { key: 'insuranceNo', label: 'شماره بیمه' },
    { key: 'nationalId', label: 'کد ملی' },
    { key: 'mobile', label: 'موبایل' },
    { key: 'status', label: 'وضعیت' },
    { key: 'managerCode', label: 'کد مدیر سطح ۱' },
    { key: 'managerCode2', label: 'کد مدیر سطح ۲' },
    { key: 'basicSalary', label: 'حقوق پایه' },
    { key: 'seniorityBase', label: 'پایه سنوات' },
    { key: 'fatherName', label: 'نام پدر' },
    { key: 'birthDate', label: 'تاریخ تولد' },
    { key: 'address', label: 'آدرس' },
    { key: 'email', label: 'ایمیل' }
  ];
  const employees = (obj.employees || []).filter(function (e) { return e && e.status !== 'inactive'; }).map(function (e) {
    return { code: String(e.code), fullName: e.fullName || '', unit: e.unit || '' };
  }).sort(function (a, b) { return String(a.fullName).localeCompare(String(b.fullName), 'fa'); });
  return jsonResponse({ ok: true, config: pvc, decreeOptions: decreeOptions, profileOptions: profileOptions, employees: employees });
}

async function handleAdminSavePortalView(request, who, env) {
  if (request.method !== 'POST') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  if (who.role !== 'admin') return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  const r = await readBody(request);
  if (r.error) return r.error;
  const body = r.body || {};
  const cfgStore = storeConfig(env);
  if (!cfgStore) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfgStore);
  if (gd.fail) return storeFailResponse(gd.fail);
  const obj = gd.obj || {};
  obj.portalViewConfig = {
    showDecree: !!body.showDecree,
    decreeMode: ['self', 'self_and_manager', 'all', 'selected'].indexOf(body.decreeMode) >= 0 ? body.decreeMode : 'self',
    decreeSelectedCodes: Array.isArray(body.decreeSelectedCodes) ? body.decreeSelectedCodes.map(String).slice(0, 500) : [],
    decreeFields: Array.isArray(body.decreeFields) ? body.decreeFields.map(String).slice(0, 200) : [],
    showProfile: !!body.showProfile,
    profileMode: ['self', 'self_and_manager', 'all', 'selected'].indexOf(body.profileMode) >= 0 ? body.profileMode : 'self',
    profileSelectedCodes: Array.isArray(body.profileSelectedCodes) ? body.profileSelectedCodes.map(String).slice(0, 500) : [],
    profileFields: Array.isArray(body.profileFields) ? body.profileFields.map(String).slice(0, 100) : []
  };
  // persist
  const put = await storePutData(cfgStore, gd.version || 0, obj, who.name || 'admin');
  if (put && put.fail) return storeFailResponse(put.fail);
  return jsonResponse({ ok: true, config: obj.portalViewConfig });
}



// ---------- Contracts ----------
function contractIsExpired(c, todayYMD) {
  if (!c || !c.endDate) return false;
  if (c.status === 'terminated' || c.status === 'expired') return true;
  // simple string compare for Jalali yyyy/mm/dd
  const a = String(c.endDate).replace(/-/g, '/');
  const b = String(todayYMD || '').replace(/-/g, '/');
  if (!b) return false;
  return a < b;
}

function todayJalaliApprox() {
  // fallback: leave empty — client filter uses status; server marks expired when endDate past stored flag
  return '';
}

async function handleAdminContracts(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);

  if (request.method === 'GET') {
    const url = new URL(request.url);
    const filter = url.searchParams.get('filter') || 'all';
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    let list = (gd.obj && gd.obj.contracts) || [];
    // refresh expired flag
    list = list.map(function (c) {
      const copy = Object.assign({}, c);
      if (copy.endDate && copy.adminApproved && copy.status !== 'terminated') {
        // keep status; client can still filter
      }
      return copy;
    });
    if (filter === 'pending' || filter === 'unapproved') list = list.filter(function (c) { return !c.adminApproved; });
    else if (filter === 'active') list = list.filter(function (c) { return c.adminApproved && c.status !== 'expired' && c.status !== 'terminated'; });
    else if (filter === 'expired') list = list.filter(function (c) { return c.status === 'expired' || c.status === 'terminated'; });
    return jsonResponse({ ok: true, contracts: list });
  }

  if (request.method !== 'POST') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  const r = await readBody(request);
  if (r.error) return r.error;
  const body = r.body || {};
  const action = String(body.action || 'create');

  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!Array.isArray(gd.obj.contracts)) gd.obj.contracts = [];

    if (action === 'create') {
      const codes = Array.isArray(body.codes) ? body.codes.map(String) : [];
      if (!codes.length) return jsonResponse({ ok: false, message: 'کد پرسنلی الزامی است.' }, 400);
      const startDate = String(body.startDate || '').trim();
      const endDate = String(body.endDate || '').trim();
      if (!startDate) return jsonResponse({ ok: false, message: 'تاریخ شروع الزامی است.' }, 400);
      const type = String(body.type || 'fixed');
      const note = String(body.note || '').trim();
      const showDur = body.showDurationToEmployee !== false;
      const visibleEmp = body.visibleToEmployee !== false;
      let created = 0;
      const missing = [];
      codes.forEach(function (code) {
        const emp = (gd.obj.employees || []).find(function (e) { return String(e.code) === String(code); });
        if (!emp) { missing.push(code); return; }
        var durM = body.durationMonths != null && body.durationMonths !== '' ? parseInt(body.durationMonths, 10) : null;
        if (isNaN(durM)) durM = null;
        var fn = emp.firstName || emp.name || '';
        var ln = emp.lastName || emp.family || emp.familyName || '';
        if (!fn && !ln && emp.fullName) {
          var parts = String(emp.fullName).trim().split(/\s+/);
          if (parts.length >= 2) { fn = parts[0]; ln = parts.slice(1).join(' '); }
          else { fn = emp.fullName; }
        }
        gd.obj.contracts.unshift({
          id: 'ctr_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7),
          empCode: String(emp.code),
          empName: emp.fullName || ((fn + ' ' + ln).trim()),
          empFirstName: fn,
          empLastName: ln,
          startDate: startDate,
          endDate: endDate,
          type: type,
          durationMonths: durM,
          note: note,
          status: 'pending',
          adminApproved: false,
          adminApprovedAt: '',
          adminApprovedBy: '',
          showDurationToEmployee: showDur,
          visibleToEmployee: visibleEmp,
          signedFileName: '',
          signedUploadedAt: '',
          editLog: [],
          edited: false,
          createdAt: new Date().toISOString(),
          createdBy: who.name
        });
        created++;
      });
      if (gd.obj.contracts.length > 5000) gd.obj.contracts.length = 5000;
      const put = await storePutData(cfg, gd.version, gd.obj, who.name);
      if (put.fail) return storeFailResponse(put.fail);
      if (put.conflict) continue;
      return jsonResponse({ ok: true, created: created, missing: missing });
    }

    const id = String(body.id || '');
    const ctr = gd.obj.contracts.find(function (c) { return c.id === id; });
    if (!ctr && action !== 'create') return jsonResponse({ ok: false, message: 'قرارداد یافت نشد.' }, 404);

    if (action === 'approve') {
      ctr.adminApproved = true;
      ctr.status = 'active';
      ctr.adminApprovedAt = new Date().toISOString();
      ctr.adminApprovedBy = who.name;
    } else if (action === 'revoke') {
      ctr.adminApproved = false;
      ctr.status = 'pending';
      ctr.adminApprovedAt = '';
      ctr.adminApprovedBy = '';
    } else if (action === 'delete') {
      gd.obj.contracts = gd.obj.contracts.filter(function (c) { return c.id !== id; });
    } else if (action === 'set_show_duration') {
      ctr.showDurationToEmployee = !!body.showDurationToEmployee;
    } else if (action === 'set_visible') {
      ctr.visibleToEmployee = !!body.visibleToEmployee;
    } else if (action === 'edit') {
      const prevStart = ctr.startDate || '';
      const prevEnd = ctr.endDate || '';
      const prevType = ctr.type || '';
      const prevDur = ctr.durationMonths != null ? ctr.durationMonths : '';
      if (body.startDate != null) ctr.startDate = String(body.startDate || '').trim();
      if (body.endDate != null) ctr.endDate = String(body.endDate || '').trim();
      if (body.type != null) ctr.type = String(body.type || '').trim() || ctr.type;
      if (body.note != null) ctr.note = String(body.note || '').trim();
      if (body.durationMonths != null && body.durationMonths !== '') {
        const dm = parseInt(body.durationMonths, 10);
        ctr.durationMonths = isNaN(dm) ? null : dm;
      }
      if (body.showDurationToEmployee != null) ctr.showDurationToEmployee = !!body.showDurationToEmployee;
      if (body.visibleToEmployee != null) ctr.visibleToEmployee = !!body.visibleToEmployee;
      const parts = [];
      if (prevStart !== (ctr.startDate || '') || prevEnd !== (ctr.endDate || '')) {
        parts.push('قرارداد از تاریخ ' + (prevStart || '—') + ' تا ' + (prevEnd || '—') + ' به ' + (ctr.startDate || '—') + ' تا ' + (ctr.endDate || '—') + ' تغییر یافت');
      }
      if (prevType && prevType !== (ctr.type || '')) {
        parts.push('نوع از ' + prevType + ' به ' + (ctr.type || '') + ' تغییر یافت');
      }
      if (String(prevDur) !== String(ctr.durationMonths != null ? ctr.durationMonths : '')) {
        parts.push('مدت از ' + (prevDur !== '' ? prevDur + ' ماه' : '—') + ' به ' + (ctr.durationMonths != null ? ctr.durationMonths + ' ماه' : '—') + ' تغییر یافت');
      }
      const noteEdit = String(body.editNote || '').trim();
      if (noteEdit) parts.push(noteEdit);
      if (!parts.length) parts.push('ویرایش شد');
      const entry = {
        at: new Date().toISOString(),
        by: who.name,
        text: parts.join('؛ ')
      };
      if (!Array.isArray(ctr.editLog)) ctr.editLog = [];
      ctr.editLog.unshift(entry);
      if (ctr.editLog.length > 30) ctr.editLog.length = 30;
      ctr.editedAt = entry.at;
      ctr.editedBy = who.name;
      ctr.edited = true;
    } else if (action === 'upload_signed') {
      const fileName = String(body.fileName || '').trim().slice(0, 200);
      const fileData = String(body.fileData || '');
      if (!fileName) return jsonResponse({ ok: false, message: 'نام فایل الزامی است.' }, 400);
      if (fileData && fileData.length > 500000) {
        return jsonResponse({ ok: false, message: 'حجم فایل زیاد است.' }, 400);
      }
      ctr.signedFileName = fileName;
      ctr.signedUploadedAt = new Date().toISOString();
      ctr.signedUploadedBy = who.name;
      if (fileData) ctr.signedFileData = fileData;
    } else if (action === 'mark_expired') {
      ctr.status = 'expired';
    } else {
      return jsonResponse({ ok: false, message: 'عملیات نامعتبر' }, 400);
    }

    const put = await storePutData(cfg, gd.version, gd.obj, who.name);
    if (put.fail) return storeFailResponse(put.fail);
    if (put.conflict) continue;
    return jsonResponse({ ok: true });
  }
  return jsonResponse({ ok: false, error: 'conflict' }, 409);
}

async function handleEmpContracts(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  if (request.method !== 'GET') {
    return jsonResponse({ ok: false, error: 'forbidden', message: 'آپلود قرارداد فقط توسط ادمین انجام می‌شود.' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  function monthsBetweenJalali(a, b) {
    if (!a || !b) return null;
    const ma = String(a).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
    const mb = String(b).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
    if (!ma || !mb) return null;
    let months = (Number(mb[1]) - Number(ma[1])) * 12 + (Number(mb[2]) - Number(ma[2]));
    // inclusive month span: Jan 1 to Jun 30/31 => 6 months
    if (Number(mb[3]) >= Number(ma[3])) months += 1;
    if (months < 1) months = 1;
    return months;
  }
  const raw = ((gd.obj && gd.obj.contracts) || []).filter(function (c) {
    return String(c.empCode) === String(sess.code) && c.visibleToEmployee !== false;
  });
  // sort oldest first for ordinal
  raw.sort(function (a, b) {
    return String(a.startDate || '').localeCompare(String(b.startDate || ''));
  });
  const list = raw.map(function (c, idx) {
    const out = {
      id: c.id,
      type: c.type,
      status: c.status,
      adminApproved: !!c.adminApproved,
      signedFileName: c.signedFileName || '',
      note: c.note || '',
      showDuration: !!c.showDurationToEmployee,
      orderIndex: idx
    };
    if (c.showDurationToEmployee) {
      out.startDate = c.startDate || '';
      out.endDate = c.endDate || '';
      out.durationMonths = monthsBetweenJalali(c.startDate, c.endDate);
    }
    return out;
  });
  return jsonResponse({ ok: true, contracts: list });
}

async function handleAdminPayrollContractCheck(request, who, env) {
  // list employees without approved active contract (for calc warning)
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  const unapproved = listEmployeesMissingContract(gd.obj || {});
  return jsonResponse({ ok: true, unapproved: unapproved });
}



async function handleEmpBalances(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  const emp = ((gd.obj && gd.obj.employees) || []).find(function (e) { return String(e.code) === String(sess.code); });
  if (!emp) return jsonResponse({ ok: false, message: 'کارمند یافت نشد.' }, 404);
  ensureEmpLeaveYears(emp, gd.obj);
  const pol = getLeavePolicy(gd.obj);
  // همیشه از سیاست فعلی (نه مقدار قدیمی leaveYears.entitled)
  let annualForEmp = getAnnualLeaveDaysForEmp(gd.obj, emp);
  const cy = Number((gd.obj.settings || {}).currentYear) || 1405;
  // فقط سال جاری در پرتال
  // entitled همیشه از سیاست فعلی
  const years = listLeaveYearsSorted(emp).filter(function (r) { return Number(r.year) === cy; }).map(function (r) {
    const entitledNow = annualForEmp;
    const accruedNow = computeAccruedLeaveDaysW(gd.obj, emp, cy);
    const usedNow = Number(r.used) || 0;
    return {
      year: r.year,
      entitled: entitledNow,
      accrued: accruedNow,
      used: usedNow,
      remaining: r.settled ? 0 : Math.round((accruedNow - usedNow) * 100) / 100,
      settled: !!r.settled,
      settledAt: r.settledAt || null,
      settledMode: r.settledMode || null
    };
  });
  const cur = emp.leaveYears[String(cy)] || {};
  return jsonResponse({
    ok: true,
    leave: {
      balance: sumUnsettledLeaveRemaining(emp),
      usedYear: Number(cur.used) || 0,
      annualDays: annualForEmp,
      defaultAnnualDays: pol.annualDays,
      contractType: emp.contractType || 'normal',
      group: emp.group || '',
      year: cy,
      years: years,
      usedFromPrior: (emp.leaveUsedFromPrior && emp.leaveUsedFromPrior[String(cy)]) || []
    },
    loan: {
      remaining: Number(emp.loanRemaining || 0),
      monthly: Number(emp.monthlyLoan || 0),
      locked: !!emp.loanLocked
    }
  });
}

async function handleAdminAccountingExport(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  const month = Number(r.body.month);
  if (!year || !month) return jsonResponse({ ok: false, message: 'سال و ماه الزامی است.' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  const key = year + '-' + month;
  const payrolls = ((gd.obj && gd.obj.payrolls) || {})[key] || {};
  // build simple journal lines (does not post to accounting — export only)
  const lines = [];
  Object.keys(payrolls).forEach(function (code) {
    const p = payrolls[code];
    if (!p) return;
    const name = p.fullName || code;
    const gross = Number(p.gross) || 0;
    const ins = Number(p.insurance) || 0;
    const tax = Number(p.tax) || 0;
    const loan = Number(p.loanDeduction) || 0;
    const net = Number(p.net) || 0;
    const employerIns = Number(p.employerInsurance) || Math.round(ins * 2); // fallback estimate if missing
    if (gross) lines.push({ code: code, name: name, account: 'هزینه حقوق و دستمزد', side: 'bed', amount: gross });
    if (employerIns) lines.push({ code: code, name: name, account: 'هزینه بیمه سهم کارفرما', side: 'bed', amount: employerIns });
    if (ins) lines.push({ code: code, name: name, account: 'بیمه پرداختنی (سهم کارگر)', side: 'bes', amount: ins });
    if (employerIns) lines.push({ code: code, name: name, account: 'بیمه پرداختنی (سهم کارفرما)', side: 'bes', amount: employerIns });
    if (tax) lines.push({ code: code, name: name, account: 'مالیات حقوق پرداختنی', side: 'bes', amount: tax });
    if (loan) lines.push({ code: code, name: name, account: 'وام کارکنان', side: 'bes', amount: loan });
    if (net) lines.push({ code: code, name: name, account: 'حقوق پرداختنی / بانک', side: 'bes', amount: net });
  });
  return jsonResponse({ ok: true, year: year, month: month, lines: lines, count: lines.length });
}



async function handleEmpPayslipArchive(request, env) {
  const sess = await readEmpSession(request, env);
  if (!sess) return jsonResponse({ ok: false, error: 'login_required' }, 401);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  const gd = await storeGetData(cfg);
  if (gd.fail) return storeFailResponse(gd.fail);
  const code = String(sess.code);
  const payrolls = (gd.obj && gd.obj.payrolls) || {};
  const months = [];
  Object.keys(payrolls).forEach(function (key) {
    const bucket = payrolls[key];
    if (!bucket) return;
    // payrolls[key] may be array or object map
    let found = null;
    if (Array.isArray(bucket)) {
      found = bucket.find(function (r) { return String(r.code) === code; });
    } else if (bucket[code]) {
      found = bucket[code];
    } else {
      Object.keys(bucket).forEach(function (k) {
        if (k === '_meta') return;
        const r = bucket[k];
        if (r && String(r.code) === code) found = r;
      });
    }
    if (found) {
      const parts = key.split('-');
      months.push({
        key: key,
        year: Number(parts[0]),
        month: Number(parts[1]),
        net: found.net != null ? found.net : found.netPay,
        gross: found.gross
      });
    }
  });
  months.sort(function (a, b) {
    if (a.year !== b.year) return b.year - a.year;
    return b.month - a.month;
  });
  return jsonResponse({ ok: true, months: months });
}

export default {
  async fetch(request, env) {
    let users;
    try {
      users = parseUsers(env);
    } catch (e) {
      return new Response('The user list (SITE_USERS) is not valid JSON.', { status: 500 });
    }
    if (Object.keys(users).length === 0) {
      return new Response('Site is not configured yet.', { status: 500 });
    }
    const url = new URL(request.url);

    // ---- Employee portal routes (no admin session required) ----
    if (url.pathname === '/api/emp/balances') return handleEmpBalances(request, env);
    if (url.pathname === '/api/emp/payslip-archive') return handleEmpPayslipArchive(request, env);
    if (url.pathname === '/api/emp/contracts') return handleEmpContracts(request, env);
    if (url.pathname === '/api/emp/decree') return handleEmpDecree(request, env);
    if (url.pathname === '/api/emp/profile') return handleEmpProfile(request, env);
    if (url.pathname === '/api/emp/login') return handleEmpLogin(request, env);
    if (url.pathname === '/api/emp/logout') return handleEmpLogout();
    if (url.pathname === '/api/emp/whoami') return handleEmpWhoami(request, env);
    if (url.pathname === '/api/emp/payslip') return handleMyPayslip(request, env);
    if (url.pathname === '/api/emp/change-password') return handleEmpChangePassword(request, env);
    if (url.pathname === '/api/emp/request') return handleEmpCreateRequest(request, env);
    if (url.pathname === '/api/emp/requests') return handleEmpListRequests(request, env);
    if (url.pathname === '/api/emp/decide') return handleEmpDecideRequest(request, env);
    if (url.pathname === '/api/emp/timesheet') return handleEmpTimesheet(request, env);
    if (url.pathname === '/api/emp/attendance-types') return handleEmpAttendanceTypes(request, env);

    // ---- Portal admin boot JS (always application/javascript; needs session) ----
    if (url.pathname === '/api/admin/portal-boot.js') {
      const sessBoot = await readSession(request, env, users);
      if (!sessBoot) {
        return new Response(
          'console.error("[psp] portal-boot: login required");'
          + 'window.__pspPortalAdmin=false;'
          + '(function(){var p=document.getElementById("panel-portalatt");'
          + 'if(p&&!document.getElementById("pspSub-ts"))'
          + 'p.innerHTML="<div class=card style=padding:14px;color:#b91c1c>نشست منقضی شده. خارج شوید و دوباره وارد شوید.</div>";})();',
          {
            status: 200,
            headers: {
              'Content-Type': 'application/javascript; charset=utf-8',
              'Cache-Control': 'no-store',
              'X-Content-Type-Options': 'nosniff'
            }
          }
        );
      }
      return new Response(PORTAL_ADMIN_JS, {
        status: 200,
        headers: {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }


    // LOGIN_MODE = basic (emergency)
    if (env.LOGIN_MODE === 'basic') {
      const b = await authenticate(request, users);
      if (b === null) {
        return new Response('Login required', {
          status: 401,
          headers: { 'WWW-Authenticate': 'Basic realm="parspehr", charset="UTF-8"', 'Cache-Control': 'no-store' }
        });
      }
      return route(request, env, users, b);
    }

    if (url.pathname === '/login') return handleLogin(request, env, users);
    if (url.pathname === '/logout') return handleLogout();

    // Employee portal (always from worker so leave/mission UI is up to date)
    if (url.pathname === '/employee' || url.pathname === '/employee/') {
      return new Response(BUILTIN_EMPLOYEE_HTML, {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Robots-Tag': 'noindex, nofollow'
        }
      });
    }

    const sess = await readSession(request, env, users);
    if (sess === null) {
      const nl = notLoggedIn(request, url);
      if (nl !== null) return nl;
    }
    const now = Math.floor(Date.now() / 1000);
    const renew = sess && (sess.exp - now < SESSION_IDLE_SECONDS / 2)
      ? sessionCookie(await makeToken(env, sess.name, now + SESSION_IDLE_SECONDS)) : null;
    const res = await route(request, env, users, sess ? { name: sess.name, role: sess.role } : { name: 'guest', role: 'operator' });
    return renew ? withCookie(res, renew) : res;
  }
};

// Minimal fallback if employee.html is missing from assets
const BUILTIN_EMPLOYEE_HTML = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>پرتال کارکنان — پارسپهر</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Vazirmatn', Tahoma, sans-serif; background: #f0fdfa; color: #134e4a; min-height: 100vh; padding: 10px; direction: rtl; font-size: 0.88rem; }
  .wrap { max-width: 1100px; margin: 0 auto; }
  .box table { font-size: 0.68rem !important; }
  .box table th, .box table td { padding: 2px 4px !important; white-space: nowrap; }
  .box table td { line-height: 1.25; }
  .card { background: #fff; border-radius: 14px; padding: 22px 18px; box-shadow: 0 8px 30px rgba(15,118,110,0.10); margin-bottom: 14px; }
  h1 { font-size: 1.2rem; color: #0f766e; text-align: center; margin-bottom: 4px; }
  h2 { font-size: 1rem; color: #0f766e; margin: 0 0 10px; }
  .sub { text-align: center; font-size: 0.82rem; color: #64748b; margin-bottom: 16px; }
  label { display: block; font-size: 0.8rem; font-weight: 600; margin: 8px 0 4px; color: #0f766e; }
  input, select, textarea { width: 100%; padding: 8px 10px; border: 1px solid #99f6e4; border-radius: 8px; font-family: inherit; font-size: 0.92rem; }
  textarea { min-height: 64px; resize: vertical; }
  button.primary { width: 100%; margin-top: 12px; padding: 10px; border: 0; border-radius: 8px; background: #0f766e; color: #fff; font-size: 0.95rem; font-weight: 600; cursor: pointer; font-family: inherit; }
  button.sm { padding: 6px 10px; border: 1px solid #99f6e4; border-radius: 7px; background: #fff; color: #0f766e; font-size: 0.78rem; font-weight: 600; cursor: pointer; font-family: inherit; }
  button.danger { background: #fee2e2; border-color: #fecaca; color: #b91c1c; }
  button.ok { background: #dcfce7; border-color: #bbf7d0; color: #15803d; }
  .err { color: #b91c1c; font-size: 0.82rem; text-align: center; margin-top: 8px; min-height: 1.1em; }
  .okmsg { color: #16a34a; }
  .hidden { display: none !important; }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; font-size: 0.85rem; gap: 8px; flex-wrap: wrap; }
  .link { color: #0f766e; cursor: pointer; background: none; border: 0; font-family: inherit; font-size: 0.82rem; text-decoration: underline; padding: 0; }
  .tabs { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 12px; background: #fff; padding: 6px; border-radius: 10px; }
  .tab { padding: 6px 10px; border: 0; border-radius: 7px; background: transparent; font-size: 0.78rem; font-weight: 600; color: #0f766e; cursor: pointer; font-family: inherit; }
  .tab.active { background: #0f766e; color: #fff; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  @media (max-width: 520px) { .grid2 { grid-template-columns: 1fr; } }
  .payslip, .box { margin-top: 12px; border: 1px solid #99f6e4; border-radius: 10px; padding: 12px; font-size: 0.85rem; background: #fafafa; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th, td { border: 1px solid #cbd5e1; padding: 5px 6px; text-align: right; }
  th { background: #f0fdfa; }
  .net { font-size: 1.1rem; font-weight: 700; color: #0f766e; text-align: center; margin-top: 10px; padding: 8px; background: #f0fdfa; border-radius: 8px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.72rem; font-weight: 600; }
  .b-pending { background: #fef3c7; color: #92400e; }
  .b-approved { background: #dcfce7; color: #166534; }
  .b-rejected { background: #fee2e2; color: #991b1b; }
  .req-card { border: 1px solid #e2e8f0; border-radius: 10px; padding: 10px 12px; margin-bottom: 8px; background: #fff; font-size: 0.82rem; }
  .req-card .meta { color: #64748b; font-size: 0.75rem; margin-top: 4px; }
  .actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
  @media print { body { background: #fff; padding: 0; } .no-print { display: none !important; } .card { box-shadow: none; } }
</style>
</head>
<body>
<div class="wrap">
<div class="card" id="loginCard">
  <h1>پرتال کارکنان پارسپهر</h1>
  <p class="sub">کد پرسنلی و رمز عبور<br><span style="font-size:0.78rem;color:#0f766e">رمز اولیه = همان کد پرسنلی</span></p>
  <label>کد پرسنلی</label><input id="code" autocomplete="username" autofocus>
  <label>رمز عبور</label><input id="pass" type="password" autocomplete="current-password">
  <button class="primary" onclick="doLogin()">ورود</button>
  <div class="err" id="loginErr"></div>
</div>
<div class="hidden" id="appCard">
  <div class="card no-print">
    <div class="topbar"><span id="whoLabel" style="font-weight:600;"></span><button class="link" onclick="doLogout()">خروج</button></div>
    <div class="tabs">
      <button class="tab active" data-tab="payslip" onclick="showTab('payslip')">فیش حقوقی</button>
      <button class="tab" data-tab="request" onclick="showTab('request')">درخواست مرخصی/مأموریت</button>
      <button class="tab" data-tab="mine" onclick="showTab('mine')">درخواست‌های من</button>
      <button class="tab hidden" data-tab="approve" id="tabApprove" onclick="showTab('approve')">نتیجه درخواست‌ها</button>
      <button class="tab" data-tab="timesheet" onclick="showTab('timesheet')">تایم‌شیت</button>
      <button class="tab" data-tab="decree" id="tabDecree" onclick="showTab('decree')">حکم</button>
      <button class="tab" data-tab="profile" id="tabProfile" onclick="showTab('profile')">مشخصات پرسنلی</button>
      <button class="tab" data-tab="contracts" id="tabContracts" onclick="showTab('contracts')">قراردادها</button>
      <button class="tab" data-tab="balances" id="tabBalances" onclick="showTab('balances')">مانده مرخصی و وام</button>
      <button class="tab" data-tab="password" onclick="showTab('password')">تغییر رمز</button>
    </div>
  </div>
  <div class="card panel" id="panel-payslip">
    <h2 class="no-print">فیش حقوقی</h2>
    <div class="grid2 no-print"><div><label>سال</label><input type="number" id="year" value="1405"></div>
    <div><label>ماه</label><select id="month"><option value="1">فروردین</option><option value="2">اردیبهشت</option><option value="3">خرداد</option><option value="4">تیر</option><option value="5">مرداد</option><option value="6">شهریور</option><option value="7">مهر</option><option value="8">آبان</option><option value="9">آذر</option><option value="10">دی</option><option value="11">بهمن</option><option value="12">اسفند</option></select></div></div>
    <button class="primary no-print" onclick="loadPayslip()">نمایش فیش</button>
    <button class="sm no-print" style="margin-top:8px;width:auto;" onclick="window.print()">چاپ</button>
    <div class="err no-print" id="appErr"></div><div id="payslipBox"></div>
  </div>
  <div class="card panel hidden" id="panel-request">
    <h2>ثبت درخواست مرخصی / مأموریت</h2>
    <label>نوع درخواست</label>
    <select id="rqType" onchange="onTypeChange()"></select>
    <p class="sub" id="rqTypeHint" style="text-align:right;margin:6px 0 0;"></p>
    <div class="grid2 hidden">
      <div><label>نوع</label><select id="rqKind"><option value="leave">مرخصی</option><option value="mission">مأموریت</option></select></div>
      <div><label>روزانه / ساعتی</label><select id="rqMode"><option value="daily">روزانه</option><option value="hourly">ساعتی</option></select></div>
    </div>
    <div class="grid2">
      <div><label id="rqStartLabel">از تاریخ</label><input id="rqStart" placeholder="1405/01/15" dir="ltr" oninput="applyFixedEnd()"></div>
      <div id="rqEndWrap"><label>تا تاریخ</label><input id="rqEnd" placeholder="1405/01/17" dir="ltr" oninput="this.dataset.manual='1'"></div>
    </div>
    <div class="grid2 hidden" id="rqTimeWrap">
      <div><label>از ساعت</label><input id="rqFrom" type="time" value="08:00"></div>
      <div><label>تا ساعت</label><input id="rqTo" type="time" value="10:00"></div>
    </div>
    <div id="rqPlaceWrap" class="hidden"><label>محل مأموریت *</label><input id="rqPlace" placeholder="شهر / سازمان مقصد" required></div>
    <label>توضیح / دلیل (برای مأموریت الزامی)</label><textarea id="rqReason"></textarea>
    <button class="primary" onclick="submitRequest()">ارسال برای تأیید مدیر</button>
    <div class="err" id="rqErr"></div>
  </div>
  <div class="card panel hidden" id="panel-mine"><h2>درخواست‌های من</h2><button class="sm" onclick="loadRequests()">بروزرسانی</button><div id="mineList" style="margin-top:10px;"></div></div>
  <div class="card panel hidden" id="panel-approve"><h2>نتیجه درخواست‌ها (تأیید / رد زیرمجموعه)</h2><button class="sm" onclick="loadRequests()">بروزرسانی</button><div id="pendingList" style="margin-top:10px;"></div></div>
  <div class="card panel hidden" id="panel-timesheet">
    <h2>تایم‌شیت</h2>
    <div class="grid2"><div><label>سال</label><input type="number" id="tsYear" value="1405"></div>
    <div><label>ماه</label><select id="tsMonth"><option value="1">فروردین</option><option value="2">اردیبهشت</option><option value="3">خرداد</option><option value="4">تیر</option><option value="5">مرداد</option><option value="6">شهریور</option><option value="7">مهر</option><option value="8">آبان</option><option value="9">آذر</option><option value="10">دی</option><option value="11">بهمن</option><option value="12">اسفند</option></select></div></div>
    <button class="primary" onclick="loadTimesheet()">نمایش</button>
    <div class="err" id="tsErr"></div><div id="tsBox"></div>
  </div>
  <div class="card panel hidden" id="panel-decree">
    <h2>حکم کارگزینی</h2>
    <p class="sub" style="text-align:right;margin-bottom:10px;">اقلام حکم شما</p>
    <div id="decreeBox"><div class="sub">در حال بارگذاری…</div></div>
  </div>
  <div class="card panel hidden" id="panel-profile">
    <h2>مشخصات پرسنلی</h2>
    <p class="sub" style="text-align:right;margin-bottom:10px;">اطلاعات کارت پرسنلی</p>
    <div id="profileBox"><div class="sub">در حال بارگذاری…</div></div>
  </div>
  <div class="card panel hidden" id="panel-balances">
    <h2>مانده مرخصی و وام</h2>
    <p class="sub" style="text-align:right;margin-bottom:10px;">مانده مرخصی استحقاقی پس از تأیید مدیر به‌روز می‌شود.</p>
    <div id="balancesBox"><div class="sub">در حال بارگذاری…</div></div>
  </div>
  <div class="card panel hidden" id="panel-contracts">
    <h2>قراردادهای من</h2>
    <p class="sub" style="text-align:right;margin-bottom:10px;">در صورت مجاز بودن، مدت قرارداد نمایش داده می‌شود.</p>
    <div id="contractsBox"><div class="sub">در حال بارگذاری…</div></div>
  </div>
  <div class="card panel hidden" id="panel-password">
    <h2>تغییر رمز عبور</h2>
    <label>رمز فعلی</label><input id="oldPass" type="password">
    <label>رمز جدید (حداقل ۶ کاراکتر)</label><input id="newPass" type="password">
    <label>تکرار رمز جدید</label><input id="newPass2" type="password">
    <button class="primary" onclick="changePass()">ثبت رمز جدید</button>
    <div class="err" id="passErr"></div>
  </div>
</div>
</div>
<script>
var monthsFa=['','فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'];
function fmt(n){return (Number(n)||0).toLocaleString('fa-IR')}
function showTab(name){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('active',t.getAttribute('data-tab')===name)});
  document.querySelectorAll('.panel').forEach(function(p){p.classList.add('hidden')});
  var el=document.getElementById('panel-'+name); if(el) el.classList.remove('hidden');
  if(name==='mine'||name==='approve') loadRequests();
  if(name==='timesheet') loadTimesheet();
  if(name==='decree') loadDecree();
  if(name==='profile') loadProfile();
  if(name==='contracts') loadContractsEmp();
  if(name==='balances') loadBalancesEmp();
  if(name==='payslip') loadPayslipArchive();
}
async function loadBalancesEmp(){
  var box=document.getElementById('balancesBox'); if(!box) return;
  box.innerHTML='<div class="sub">در حال بارگذاری…</div>';
  try{
    var r=await fetch('/api/emp/balances',{credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){ box.innerHTML='<div class="sub">'+(j.message||'خطا')+'</div>'; return; }
    var L=j.leave||{}, Ln=j.loan||{};
    var html='<div class="box">';
    html+='<p class="sub" style="margin-bottom:8px;">سقف سالانه: '+(L.annualDays!=null?L.annualDays:'—')+' روز — مانده سال جاری: <b>'+(L.balance!=null?L.balance:'—')+'</b> روز (بر اساس ماه‌های کارکرد)</p>';
    html+='<table><thead><tr><th>سال</th><th>سقف سال</th><th>استحقاق تا این ماه</th><th>استفاده‌شده</th><th>مانده</th><th>وضعیت</th></tr></thead><tbody>';
    var years=L.years||[];
    if(!years.length){
      html+='<tr><td>'+(L.year||'—')+'</td><td>'+(L.annualDays!=null?L.annualDays:'—')+'</td><td>'+(L.usedYear!=null?L.usedYear:'—')+'</td><td>'+(L.balance!=null?L.balance:'—')+'</td><td>—</td></tr>';
    } else {
      years.forEach(function(y){
        var st=y.settled?('<span style="color:#0f766e;font-weight:700;">تسویه شد'+(y.settledMode==='final'?' (نهایی)':' (سالیانه)')+'</span>'):'باز';
        var rem=y.settled?0:(y.remaining!=null?y.remaining:'—');
        html+='<tr><td>'+y.year+'</td><td>'+(y.entitled!=null?y.entitled:'—')+'</td><td>'+(y.accrued!=null?y.accrued:'—')+'</td><td>'+(y.used!=null?y.used:'—')+'</td><td>'+rem+'</td><td>'+st+'</td></tr>';
      });
    }
    html+='</tbody></table>';
    var prior=L.usedFromPrior||[];
    if(prior.length){
      html+='<p style="margin-top:10px;padding:8px;background:#fffbeb;border-radius:8px;color:#92400e;font-size:0.8rem;"><b>استفاده از ذخیره سال‌های قبل در '+(L.year||'')+':</b><br>';
      prior.forEach(function(p){
        var fy=(p.fromYears||[]).map(function(x){return x.year+'('+x.days+' روز)';}).join('، ');
        html+= (p.days||'')+' روز'+(fy?(' از '+fy):'')+(p.reason?(' — '+p.reason):'')+'<br>';
      });
      html+='</p>';
    }
    html+='<table style="margin-top:12px;"><tr><td><b>باقی‌مانده وام</b></td><td>'+(Ln.remaining!=null?Number(Ln.remaining).toLocaleString('fa-IR'):'—')+' ریال</td></tr>';
    html+='<tr><td><b>قسط ماهانه</b></td><td>'+(Ln.monthly?Number(Ln.monthly).toLocaleString('fa-IR'):'—')+' ریال</td></tr></table></div>';
    box.innerHTML=html;
  }catch(e){ box.innerHTML='<div class="sub">خطا در دریافت اطلاعات.</div>'; }
}


async function loadPayslipArchive(){
  var box=document.getElementById('payslipArchiveBox'); if(!box) return;
  box.innerHTML='<div class="sub">در حال بارگذاری آرشیو…</div>';
  try{
    var r=await fetch('/api/emp/payslip-archive',{credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){ box.innerHTML='<div class="sub">آرشیو در دسترس نیست.</div>'; return; }
    var list=j.months||[];
    if(!list.length){ box.innerHTML='<div class="sub">هنوز فیش محاسبه‌شده‌ای برای شما ثبت نشده.</div>'; return; }
    var monthNames=['','فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'];
    var html='<div class="box"><table><thead><tr><th>دوره</th><th>ناخالص</th><th>خالص</th><th></th></tr></thead><tbody>';
    list.forEach(function(m){
      var label=(monthNames[m.month]||m.month)+' '+m.year;
      html+='<tr><td>'+label+'</td><td>'+(m.gross!=null?Number(m.gross).toLocaleString('fa-IR'):'—')+'</td><td>'+(m.net!=null?Number(m.net).toLocaleString('fa-IR'):'—')+'</td>';
      html+='<td><button type="button" class="primary" style="padding:4px 8px;font-size:0.75rem;" onclick="openArchivedPayslip('+m.year+','+m.month+')">نمایش</button></td></tr>';
    });
    html+='</tbody></table></div>';
    box.innerHTML=html;
  }catch(e){ box.innerHTML='<div class="sub">خطا در دریافت آرشیو.</div>'; }
}
function openArchivedPayslip(y,m){
  var ye=document.getElementById('year')||document.getElementById('psYear');
  var me=document.getElementById('month')||document.getElementById('psMonth');
  if(ye) ye.value=y; if(me) me.value=m;
  if(typeof loadPayslip==='function') loadPayslip();
}

async function loadContractsEmp(){
  var box=document.getElementById('contractsBox'); if(!box) return;
  box.innerHTML='<div class="sub">در حال بارگذاری…</div>';
  try{
    var r=await fetch('/api/emp/contracts',{credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){ box.innerHTML='<div class="sub">'+(j.message||'خطا')+'</div>'; return; }
    var list=j.contracts||[];
    if(!list.length){ box.innerHTML='<div class="sub">قراردادی برای شما ثبت نشده.</div>'; return; }
    var typeFa={fixed:'مدت‌موقت',permanent:'دائم',hourly:'ساعتی',daily:'روزمزد',other:'سایر'};
    var ordinals=['اول','دوم','سوم','چهارم','پنجم','ششم','هفتم','هشتم','نهم','دهم'];
    function monthsBetween(a,b){
      if(!a||!b) return null;
      var ma=String(a).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
      var mb=String(b).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
      if(!ma||!mb) return null;
      var months=(+mb[1]-+ma[1])*12+(+mb[2]-+ma[2]);
      if(+mb[3]>=+ma[3]) months+=1; // inclusive rough
      if(months<1) months=1;
      return months;
    }
    // oldest first for ordinal numbering
    var sorted=list.slice().sort(function(a,b){
      return String(a.startDate||'').localeCompare(String(b.startDate||''));
    });
    var orderMap={};
    sorted.forEach(function(c,i){ orderMap[c.id]=i; });
    function fmtDate(d){
      if(!d) return '';
      var m=String(d).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
      if(!m) return String(d);
      return String(m[3]).padStart(2,'0')+'/'+String(m[2]).padStart(2,'0')+'/'+m[1];
    }
    var html='<div class="box" style="overflow:auto;"><table style="width:100%;font-size:0.82rem;">';
    html+='<thead><tr>';
    html+='<th style="text-align:right;">نوع</th>';
    html+='<th style="text-align:center;">دوره قرارداد</th>';
    html+='<th style="text-align:center;">مدت قرارداد</th>';
    html+='<th style="text-align:center;">نوبت قرارداد</th>';
    html+='</tr></thead><tbody>';
    list.forEach(function(c){
      var typ=typeFa[c.type]||c.type||'—';
      var period='—';
      var dur='—';
      if(c.showDuration){
        var a=fmtDate(c.startDate), b=fmtDate(c.endDate);
        if(a&&b) period=a+'-'+b;
        else if(a||b) period=a||b;
        var m=c.durationMonths!=null?c.durationMonths:monthsBetween(c.startDate,c.endDate);
        if(m!=null) dur=m+'ماه';
      }
      var oi=c.orderIndex!=null?c.orderIndex:orderMap[c.id];
      var nob=oi!=null?(oi<ordinals.length?'قرارداد '+ordinals[oi]:'قرارداد '+(oi+1)):'—';
      html+='<tr>';
      html+='<td style="text-align:right;"><b>'+typ+'</b></td>';
      html+='<td style="text-align:center;direction:ltr;">'+period+'</td>';
      html+='<td style="text-align:center;">'+dur+'</td>';
      html+='<td style="text-align:center;">'+nob+'</td>';
      html+='</tr>';
    });
    html+='</tbody></table></div>';
    box.innerHTML=html;
  }catch(e){ box.innerHTML='<div class="sub">خطا در دریافت قراردادها.</div>'; }
}

async function loadDecree(){
  var box=document.getElementById('decreeBox'); if(!box) return;
  box.innerHTML='<div class="sub">در حال بارگذاری…</div>';
  try{
    var r=await fetch('/api/emp/decree',{credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){ box.innerHTML='<div class="sub">'+(j.message||'نمایش حکم برای شما فعال نیست.')+'</div>'; return; }
    var rows=(j.items||[]).map(function(it){return '<tr><td>'+it.name+'</td><td>'+fmt(it.amount)+'</td></tr>'}).join('');
    if(!rows) rows='<tr><td colspan="2">موردی برای نمایش نیست</td></tr>';
    var total=j.total!=null?('<div class="net">جمع حکم: '+fmt(j.total)+' ریال</div>'):'';
    box.innerHTML='<div class="box"><b>'+(j.fullName||'')+'</b>'+(j.position?' — '+j.position:'')+
      '<table style="margin-top:8px"><tr><th>شرح</th><th>مبلغ</th></tr>'+rows+'</table>'+total+'</div>';
  }catch(e){ box.innerHTML='<div class="sub">خطا در دریافت حکم.</div>'; }
}
async function loadProfile(){
  var box=document.getElementById('profileBox'); if(!box) return;
  box.innerHTML='<div class="sub">در حال بارگذاری…</div>';
  try{
    var r=await fetch('/api/emp/profile',{credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){ box.innerHTML='<div class="sub">'+(j.message||'نمایش مشخصات برای شما فعال نیست.')+'</div>'; return; }
    var html='<div class="box"><table>';
    (j.fields||[]).forEach(function(f){
      html+='<tr><td style="width:40%"><b>'+(f.label||f.key)+'</b></td><td>'+(f.value!=null&&f.value!==''?f.value:'—')+'</td></tr>';
    });
    html+='</table></div>';
    box.innerHTML=html;
  }catch(e){ box.innerHTML='<div class="sub">خطا در دریافت مشخصات.</div>'; }
}
var attTypes=[];
function syncRequestForm(){
  var mode=document.getElementById('rqMode').value, kind=document.getElementById('rqKind').value;
  document.getElementById('rqTimeWrap').classList.toggle('hidden', mode!=='hourly');
  document.getElementById('rqEndWrap').classList.toggle('hidden', mode==='hourly');
  document.getElementById('rqPlaceWrap').classList.toggle('hidden', kind!=='mission');
  var lab=document.getElementById('rqStartLabel');
  if(lab) lab.textContent = mode==='hourly' ? 'تاریخ' : 'از تاریخ';
}
function daysInJMonth(y,m){if(m>=1&&m<=6)return 31;if(m>=7&&m<=11)return 30;return 29;}
function addJDays(startStr,nDays){
  var m=String(startStr||'').trim().match(/(\\d{4})[\\/\\-](\\d{1,2})[\\/\\-](\\d{1,2})/);
  if(!m) return '';
  var y=+m[1], mo=+m[2], d=+m[3];
  // nDays is total inclusive count; advance nDays-1
  var left=(nDays||1)-1;
  while(left>0){
    var dim=daysInJMonth(y,mo);
    var room=dim-d;
    if(left<=room){d+=left;left=0;}
    else{left-=room+1;d=1;mo++;if(mo>12){mo=1;y++;}}
  }
  return y+'/'+String(mo).padStart(2,'0')+'/'+String(d).padStart(2,'0');
}
function applyFixedEnd(){
  var id=document.getElementById('rqType').value;
  var t=attTypes.find(function(x){return String(x.id)===String(id)});
  var start=document.getElementById('rqStart').value.trim();
  var endEl=document.getElementById('rqEnd');
  if(t&&t.fixedDays!=null&&t.fixedDays!==''&&t.mode!=='hourly'&&start){
    // auto-fill end but allow manual change
    if(!endEl.dataset.manual||endEl.dataset.manual==='0'){
      endEl.value=addJDays(start,Number(t.fixedDays)||1);
    }
    endEl.readOnly=false;
    endEl.style.background='#fff';
    endEl.title='خودکار پر شد؛ در صورت نیاز دستی تغییر دهید';
  } else {
    endEl.readOnly=false;
    endEl.style.background='';
    endEl.dataset.manual='0';
  }
}
function onTypeChange(){
  var id=document.getElementById('rqType').value;
  var t=attTypes.find(function(x){return String(x.id)===String(id)});
  if(!t){return}
  document.getElementById('rqKind').value=t.kind==='mission'?'mission':'leave';
  document.getElementById('rqMode').value=t.mode==='hourly'?'hourly':'daily';
  var hint=[];
  if(t.kind==='leave') hint.push(t.deductFromEntitlement?'از مرخصی استحقاقی کسر می‌شود':'از استحقاقی کسر نمی‌شود');
  if(t.fixedDays!=null&&t.fixedDays!=='') hint.push('مدت ثابت: '+t.fixedDays+' روز — فقط تاریخ شروع را بزنید');
  var freq=t.frequency||'throughout_year';
  if(freq==='once_employment') hint.push('یک‌بار در طول استخدام');
  else if(freq==='once_year') hint.push('یک‌بار در طول سال');
  else hint.push('قابل استفاده در طول سال');
  if(t.requiresAdminGrant) hint.push('با مجوز ادمین');
  document.getElementById('rqTypeHint').textContent=hint.join(' — ');
  syncRequestForm();
  applyFixedEnd();
}
async function loadAttTypes(){
  try{
    var r=await fetch('/api/emp/attendance-types',{credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok) return;
    attTypes=j.types||[];
    var sel=document.getElementById('rqType');
    sel.innerHTML=attTypes.map(function(t){return '<option value="'+t.id+'">'+t.name+(t.kind==='mission'?' (مأموریت)':' (مرخصی)')+'</option>'}).join('')||'<option value="">—</option>';
    onTypeChange();
  }catch(e){}
}
async function doLogin(){
  var err=document.getElementById('loginErr'); err.textContent='';
  var code=document.getElementById('code').value.trim(), password=document.getElementById('pass').value;
  if(!code||!password){err.textContent='کد و رمز را وارد کنید.';return}
  try{
    var r=await fetch('/api/emp/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:code,password:password}),credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){err.textContent=j.message||'کد یا رمز اشتباه است یا دسترسی غیرفعال است.';return}
    showApp(j);
    if(j.mustChangePassword) setTimeout(function(){alert('رمز فعلی همان کد پرسنلی است. از بخش تغییر رمز عوض کنید.');},300);
  }catch(e){err.textContent='خطا در ارتباط با سرور.'}
}
function showApp(j){
  document.getElementById('loginCard').classList.add('hidden');
  document.getElementById('appCard').classList.remove('hidden');
  document.getElementById('whoLabel').textContent=(j.fullName||'')+' — کد '+j.code;
  loadRequests();
  loadAttTypes();
}
async function checkSession(){try{var r=await fetch('/api/emp/whoami',{credentials:'same-origin'});var j=await r.json();if(j.ok)showApp(j)}catch(e){}}
async function doLogout(){try{await fetch('/api/emp/logout',{method:'POST',credentials:'same-origin'})}catch(e){}location.reload()}
async function loadPayslip(){
  var err=document.getElementById('appErr'); err.textContent=''; document.getElementById('payslipBox').innerHTML='';
  var year=Number(document.getElementById('year').value), month=Number(document.getElementById('month').value);
  try{
    var r=await fetch('/api/emp/payslip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({year:year,month:month}),credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){err.textContent=j.message||'فیشی یافت نشد.';return}
    var p=j.payslip, items='';
    (p.itemDetails||[]).forEach(function(it){items+='<tr><td>'+it.name+(it.qty!=null&&it.qty!==''?' ('+it.qty+')':'')+'</td><td>'+fmt(it.amount)+'</td></tr>'});
    var companyName=(j.company&&j.company.name)?j.company.name:'فیش حقوقی';
    document.getElementById('payslipBox').innerHTML='<div class="payslip"><h2 style="text-align:center;color:#0f766e">'+companyName+'</h2><div style="text-align:center;font-size:0.82rem;color:#64748b">'+p.fullName+(p.position?' — '+p.position:'')+'<br>'+monthsFa[month]+' '+year+' — کارکرد: '+p.workDays+' روز</div><table style="margin-top:8px"><tr><th>شرح</th><th>مبلغ</th></tr><tr><td>حقوق پایه</td><td>'+fmt(p.basicAmount)+'</td></tr>'+(p.otAmount?'<tr><td>اضافه‌کار</td><td>'+fmt(p.otAmount)+'</td></tr>':'')+(p.nightAmount?'<tr><td>شب‌کاری</td><td>'+fmt(p.nightAmount)+'</td></tr>':'')+(p.shiftAmount?'<tr><td>نوبت‌کاری</td><td>'+fmt(p.shiftAmount)+'</td></tr>':'')+items+'<tr><td><b>جمع ناخالص</b></td><td><b>'+fmt(p.gross)+'</b></td></tr><tr><td>بیمه</td><td>'+fmt(p.insurance)+'</td></tr><tr><td>مالیات</td><td>'+fmt(p.tax)+'</td></tr>'+(p.loanDeduction?'<tr><td>کسر وام</td><td>'+fmt(p.loanDeduction)+'</td></tr>':'')+(p.totalDeductions?'<tr><td>سایر کسورات</td><td>'+fmt(p.totalDeductions)+'</td></tr>':'')+'</table><div class="net">خالص: '+fmt(p.net)+' ریال</div></div>';
  }catch(e){err.textContent='خطا در دریافت فیش.'}
}
async function submitRequest(){
  var err=document.getElementById('rqErr'); err.textContent=''; err.classList.remove('okmsg');
  var body={typeId:document.getElementById('rqType').value,kind:document.getElementById('rqKind').value,mode:document.getElementById('rqMode').value,startDate:document.getElementById('rqStart').value.trim(),endDate:document.getElementById('rqEnd').value.trim(),fromTime:document.getElementById('rqFrom').value,toTime:document.getElementById('rqTo').value,place:document.getElementById('rqPlace').value.trim(),reason:document.getElementById('rqReason').value.trim(),usePriorYears:false};
  if(body.kind==='mission'&&!body.place){err.textContent='محل مأموریت الزامی است.';return}
  if(body.kind==='mission'&&!body.reason){err.textContent='توضیح / دلیل مأموریت الزامی است.';return}
  if(!body.startDate){err.textContent='تاریخ الزامی است.';return}

  try{
    var r=await fetch('/api/emp/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});
    var j=null;
    try{ j=await r.json(); }catch(pe){ err.textContent='پاسخ نامعتبر از سرور ('+r.status+')'; return; }
    if(!j.ok && j.error==='need_prior_years_confirm'){
      if(confirm(j.message||'مانده امسال کافی نیست. از ذخیره سال‌های قبل استفاده شود؟')){
        body.usePriorYears=true;
        r=await fetch('/api/emp/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});
        try{ j=await r.json(); }catch(pe2){ err.textContent='پاسخ نامعتبر ('+r.status+')'; return; }
      } else { err.textContent='ثبت لغو شد.'; return; }
    }
    if(!j.ok){err.textContent=j.message||j.error||('خطا '+r.status);return}
    err.classList.add('okmsg'); err.textContent='درخواست ثبت و برای مدیر ارسال شد.'+(body.usePriorYears?' (از ذخیره سال‌های قبل)':''); loadRequests();
  }catch(e){err.textContent='خطا در ارتباط: '+(e&&e.message?e.message:e)}
}
function statusBadge(s){if(s==='approved')return'<span class="badge b-approved">تأیید نهایی</span>';if(s==='approved_l1')return'<span class="badge b-pending">تأیید سطح ۱ — منتظر سطح ۲</span>';if(s==='rejected')return'<span class="badge b-rejected">رد شده</span>';return'<span class="badge b-pending">در انتظار</span>'}
function reqHtml(x,forManager){
  var title=(x.typeName||((x.kind==='mission'?'مأموریت':'مرخصی')+' '+(x.mode==='hourly'?'ساعتی':'روزانه')));
  var dates=x.mode==='hourly'?(x.startDate+' از '+x.fromTime+' تا '+x.toTime):(x.startDate+(x.endDate&&x.endDate!==x.startDate?' تا '+x.endDate:''));
  var extra=''; if(x.place)extra+='<div>محل: '+x.place+'</div>'; if(x.reason)extra+='<div>دلیل: '+x.reason+'</div>'; if(x.usePriorYears||x.managerNote)extra+='<div style="color:#b45309;font-weight:600;background:#fffbeb;padding:4px 6px;border-radius:6px;margin-top:4px;">⚠ '+(x.managerNote||'استفاده از ذخیره مرخصی سال‌های قبل')+'</div>'; if(x.status==='rejected'&&x.rejectReason)extra+='<div style="color:#b91c1c">دلیل رد: '+x.rejectReason+'</div>';
  var actions=''; if(forManager&&(x.status==='pending'||x.status==='approved_l1')) actions='<div class="actions"><button class="sm ok" onclick="decide(\\''+x.id+'\\',\\'approved\\')">تأیید</button><button class="sm danger" onclick="decide(\\''+x.id+'\\',\\'rejected\\')">رد</button></div>';
  return '<div class="req-card"><div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><b>'+title+'</b>'+statusBadge(x.status)+'</div><div class="meta">'+(forManager?(x.empName+' — کد '+x.empCode+'<br>'):'')+dates+'</div>'+extra+actions+'</div>';
}
async function loadRequests(){
  try{
    var r=await fetch('/api/emp/requests',{credentials:'same-origin'}); var j=await r.json(); if(!j.ok)return;
    var mine=document.getElementById('mineList');
    mine.innerHTML=!(j.mine||[]).length?'<div class="sub">درخواستی ندارید.</div>':j.mine.map(function(x){return reqHtml(x,false)}).join('');
    var tab=document.getElementById('tabApprove');
    // only managers see this tab
    if(j.isManager) tab.classList.remove('hidden'); else tab.classList.add('hidden');
    var list=j.managedForMe||j.pendingForMe||[];
    document.getElementById('pendingList').innerHTML=!list.length?'<div class="sub">درخواستی برای زیرمجموعه نیست.</div>':list.map(function(x){return reqHtml(x,true)}).join('');
  }catch(e){}
}
async function decide(id,decision){
  var rejectReason='';
  if(decision==='rejected'){rejectReason=prompt('دلیل رد درخواست:'); if(rejectReason===null)return; if(!String(rejectReason).trim()){alert('دلیل رد الزامی است.');return}}
  else if(!confirm('تأیید شود؟ در صورت مرخصی استحقاقی، از مانده کسر و در تایم‌شیت ثبت می‌شود. اگر از ذخیره سال‌های قبل باشد در کارت مشخص است.')) return;
  try{
    var r=await fetch('/api/emp/decide',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id,decision:decision,rejectReason:rejectReason}),credentials:'same-origin'});
    var j=await r.json(); if(!j.ok){alert(j.message||j.error||'خطا');return} loadRequests();
  }catch(e){alert('خطا در ارتباط')}
}
async function loadTimesheet(){
  var err=document.getElementById('tsErr'); err.textContent='';
  var year=Number(document.getElementById('tsYear').value), month=Number(document.getElementById('tsMonth').value);
  try{
    var r=await fetch('/api/emp/timesheet',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({year:year,month:month}),credentials:'same-origin'});
    var j=await r.json(); if(!j.ok){err.textContent=j.message||'خطا';return}
    var sumAbs=0,sumWork=0,sumDelay=0,sumOt=0;
    if(j.daily&&j.daily.days){ j.daily.days.forEach(function(d){ sumAbs+=Number(d.hourlyAbsenceMin)||0; sumWork+=Number(d.workHours)||0; sumDelay+=Number(d.delayMin)||0; sumOt+=Number(d.otHours)||0; }); } sumAbs=sumAbs/60; if(j.otHoursTotal!=null) sumOt=Number(j.otHoursTotal)||sumOt; if(j.otHours!=null&&j.otHoursTotal==null) sumOt=Number(j.otHours)||sumOt;
    var html='<div class="box"><b>'+(j.fullName||'')+'</b> — '+monthsFa[month]+' '+year;

    var ua=j.userAccess||{}; var pt=ua.portalTabs||{}; var tc=ua.timesheetCols||{};
    function _showTab(k){ return pt[k]==null?true:!!pt[k]; }
    function _showCol(k){ return tc[k]==null?true:!!tc[k]; }
    function _hm(h){var m=Math.round((Number(h)||0)*60);var hh=Math.floor(m/60),mm=m%60;return (hh<10?'0':'')+hh+':'+(mm<10?'0':'')+mm;}
    html+='<table style="margin-top:8px"><tr>';
    if(_showTab('work')) html+='<th>کارکرد</th>';
    if(_showTab('leaveDaily')) html+='<th>مرخصی روزانه</th>';
    if(_showTab('leaveHourly')) html+='<th>مرخصی ساعتی</th>';
    if(_showTab('missionDaily')) html+='<th>مأموریت روزانه</th>';
    if(_showTab('missionHourly')) html+='<th>مأموریت ساعتی</th>';
    if(_showTab('ot')) html+='<th>اضافه‌کار</th>';
    if(_showTab('night')) html+='<th>شب‌کاری</th>';
    if(_showTab('absenceHourly')) html+='<th>غیبت ساعتی</th>';
    html+='</tr><tr>';
    if(_showTab('work')) html+='<td>'+(j.workDays!=null?j.workDays:0)+'</td>';
    if(_showTab('leaveDaily')) html+='<td>'+(j.leaveDays!=null?j.leaveDays:0)+'</td>';
    if(_showTab('leaveHourly')) html+='<td>'+_hm(j.hourlyLeave)+'</td>';
    if(_showTab('missionDaily')) html+='<td>'+(j.missionDays!=null?j.missionDays:0)+'</td>';
    if(_showTab('missionHourly')) html+='<td>'+_hm(j.missionHours)+'</td>';
    if(_showTab('ot')) html+='<td>'+(j.otHoursHM||_hm(j.otHours))+(j.otHoursUnapproved?(' / تأیید نشده '+(j.otHoursUnapprovedHM||_hm(j.otHoursUnapproved))):'')+'</td>';
    if(_showTab('night')) html+='<td>'+(j.nightHoursHM||_hm(j.nightHours))+'</td>';
    if(_showTab('absenceHourly')) html+='<td>'+(j.hourlyAbsenceHM||_hm(sumAbs))+'</td>';
    html+='</tr></table>';
    function _hm2(h){var m=Math.round((Number(h)||0)*60);if(m<=0)return '';var hh=Math.floor(m/60),mm=m%60;return (hh<10?'0':'')+hh+':'+(mm<10?'0':'')+mm;}
    html+='<p style="font-size:0.78rem;color:#0f766e;margin-top:6px;">';
    if(_showTab('work')||_showCol('work')) html+='ساعت کار: <b>'+(j.otHoursTotalHM||_hm2(sumWork)||'')+'</b> ';
    if(_showTab('ot')||_showCol('ot')) html+='| اضافه‌کار تأیید: <b>'+(j.otHoursHM||_hm2(j.otHours)||_hm2(sumOt)||'')+'</b> | تأییدنشده: <b>'+(j.otHoursUnapprovedHM&&j.otHoursUnapprovedHM!=='00:00'?j.otHoursUnapprovedHM:'')+'</b> ';
    if(_showTab('night')||_showCol('night')) html+='| شب‌کاری: <b>'+(j.nightHoursHM&&j.nightHoursHM!=='00:00'?j.nightHoursHM:_hm2(j.nightHours))+'</b> ';
    if(_showTab('absenceHourly')||_showCol('abs')) html+='| غیبت: <b>'+(j.hourlyAbsenceHM&&j.hourlyAbsenceHM!=='00:00'?j.hourlyAbsenceHM:_hm2(sumAbs))+'</b>';
    html+='</p>';
    if(j.daily&&j.daily.days&&j.daily.days.length){
      html+='<h2 style="margin-top:14px">تایم‌شیت روزبه‌روز</h2>';
      var thE='background:#ecfdf5;border:1px solid #99f6e4;padding:1px 0;text-align:center;vertical-align:middle;font-size:0.55rem;white-space:nowrap;line-height:1.1;';
      var tdE='border:1px solid #e2e8f0;padding:0 1px;text-align:center;vertical-align:middle;font-size:0.52rem;line-height:1.1;';
      html+='<div style="overflow:auto;max-height:65vh"><table style="font-size:0.55rem;width:100%;border-collapse:collapse;table-layout:fixed"><thead style="position:sticky;top:0;z-index:2"><tr>';
      html+='<th style="'+thE+'width:40px">تاریخ</th>';
      if(_showCol('punch')){ for(var hi=1;hi<=4;hi++){html+='<th style="'+thE+'width:22px" title="ورود'+hi+'">ورود'+hi+'</th><th style="'+thE+'width:22px" title="خروج'+hi+'">خروج'+hi+'</th>';} }
      if(_showCol('work')) html+='<th style="'+thE+'width:28px">کارکرد</th>';
      if(_showCol('ot')) html+='<th style="'+thE+'width:26px">اضافه‌کار</th>';
      if(_showCol('night')) html+='<th style="'+thE+'width:26px">شب‌کاری</th>';
      if(_showCol('eot')) html+='<th style="'+thE+'width:24px">اض.قبل</th>';
      if(_showCol('abs')) html+='<th style="'+thE+'width:26px">غیبت‌س</th>';
      if(_showCol('mis')) html+='<th style="'+thE+'width:70px">مأموریت</th>';
      if(_showCol('lv')) html+='<th style="'+thE+'width:70px">مرخصی</th>';
      if(_showCol('note')) html+='<th style="'+thE+'width:90px">توضیح</th>';
      html+='</tr></thead><tbody>';
      j.daily.days.forEach(function(d){
        var bg=d.isNonWork?'background:#fef2f2;':(d.leaveConflict||d.missionConflict?'background:#fff7ed;':'');
        var ic=d.incomplete||{};
        var red='color:#b91c1c;font-weight:700;';
        var abs=(d.hourlyAbsenceHM&&d.hourlyAbsenceHM!=='00:00')?d.hourlyAbsenceHM:((d.hourlyAbsenceMin>0)?(function(m){m=Math.round(m);var h=Math.floor(m/60),mm=m%60;return (h<10?'0':'')+h+':'+(mm<10?'0':'')+mm;})(d.hourlyAbsenceMin):'');
        function cell(v,bad){ return '<td style="'+tdE+'direction:ltr;'+(bad?red:'')+'">'+(v||'')+'</td>'; }
        html+='<tr style="'+bg+'"><td style="'+tdE+'white-space:nowrap;font-size:0.48rem">'+d.date+'</td>';
        if(_showCol('punch')){ for(var pi=1;pi<=4;pi++){html+=cell(d['in'+pi],ic['in'+pi])+cell(d['out'+pi],ic['out'+pi]);} }
        if(_showCol('work')) html+='<td style="'+tdE+'">'+(d.workHoursHM?d.workHoursHM:(d.workHours!=null&&d.workHours>0?d.workHours:''))+'</td>';
        if(_showCol('ot')) html+='<td style="'+tdE+'">'+(d.otHoursHM&&d.otHoursHM!=='00:00'&&d.otHoursHM!=='0'?d.otHoursHM:'')+'</td>';
        if(_showCol('night')) html+='<td style="'+tdE+'color:#1d4ed8">'+(d.nightHoursHM&&d.nightHoursHM!=='00:00'?d.nightHoursHM:'')+'</td>';
        if(_showCol('eot')) html+='<td style="'+tdE+'color:#7c3aed">'+(d.earlyOtHoursHM&&d.earlyOtHoursHM!=='00:00'?d.earlyOtHoursHM:'')+'</td>';
        if(_showCol('abs')) html+='<td style="'+tdE+(abs?red:'')+'">'+abs+'</td>';
        if(_showCol('mis')) html+='<td style="'+tdE+(d.missionConflict?red:'')+'">'+[d.missionDaily,d.missionHourly].filter(Boolean).join(' / ')+'</td>';
        if(_showCol('lv')) html+='<td style="'+tdE+(d.leaveConflict?red:'')+'">'+[d.leaveDaily,d.leaveHourly].filter(Boolean).join(' / ')+'</td>';
        if(_showCol('note')) html+='<td style="'+tdE+'overflow:hidden;text-overflow:ellipsis;max-width:90px" title="'+(d.note||'').replace(/"/g,'&quot;')+'">'+(d.note||'')+'</td>';
        html+='</tr>';
      });
      html+='</tbody></table></div>';

    }
    document.getElementById('tsBox').innerHTML=html+'</div>';
  }catch(e){err.textContent='خطا در دریافت تایم‌شیت'}
}
async function changePass(){
  var err=document.getElementById('passErr'); err.textContent=''; err.classList.remove('okmsg');
  var oldPassword=document.getElementById('oldPass').value, newPassword=document.getElementById('newPass').value, n2=document.getElementById('newPass2').value;
  if(newPassword!==n2){err.textContent='رمز جدید و تکرار یکسان نیست.';return}
  if(newPassword.length<6){err.textContent='رمز حداقل ۶ کاراکتر باشد.';return}
  try{
    var r=await fetch('/api/emp/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldPassword:oldPassword,newPassword:newPassword}),credentials:'same-origin'});
    var j=await r.json(); if(!j.ok){err.textContent=j.message||'خطا';return}
    err.classList.add('okmsg'); err.textContent='رمز تغییر کرد.'; document.getElementById('oldPass').value=''; document.getElementById('newPass').value=''; document.getElementById('newPass2').value='';
  }catch(e){err.textContent='خطا در ارتباط'}
}
syncRequestForm(); checkSession();
</script>
</body>
</html>
`;
