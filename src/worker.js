// parspehr gate: personal login + watermark + payroll API + employee self-service portal
import { makeEngine } from './engine.js';
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
  // Inject employee-portal admin UI into the main app (no need to edit index.html)
  const portalAdminScript = `
<script>
(function(){
  if (window.__pspPortalAdmin) return;
  window.__pspPortalAdmin = true;

  function ensurePortalBox() {
    if (document.getElementById('pspPortalBox')) return;
    var modal = document.getElementById('empModal');
    if (!modal) return;
    var form = modal.querySelector('form') || modal;
    var box = document.createElement('div');
    box.id = 'pspPortalBox';
    box.style.cssText = 'margin-top:14px;padding:12px 14px;border:1px solid #99f6e4;border-radius:10px;background:#f0fdfa;';
    box.innerHTML = '<div style="font-weight:700;color:#0f766e;margin-bottom:8px;font-size:0.9rem;">پرتال فیش حقوقی کارکنان</div>' +
      '<p style="font-size:0.75rem;color:#64748b;margin-bottom:8px;line-height:1.5;">' +
      'ورود کارکنان از آدرس <b>/employee</b> — نام کاربری = کد پرسنلی، رمز اولیه = همان کد پرسنلی.<br>' +
      'اگر رمز را فراموش کردند، با دکمه زیر به حالت اولیه برگردانید یا رمز جدید بگذارید.' +
      '</p>' +
      '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">' +
      '<label style="font-size:0.78rem;display:flex;align-items:center;gap:4px;"><input type="checkbox" id="pspPortalEnabled" checked> دسترسی فعال</label>' +
      '<input type="password" id="pspPortalPass" placeholder="رمز جدید (خالی = رمز اولیه = کد)" style="padding:6px 8px;border:1px solid #99f6e4;border-radius:7px;font-size:0.82rem;max-width:200px;font-family:inherit;">' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspPortalSaveBtn">ذخیره / ریست رمز پرتال</button>' +
      '<span id="pspPortalStatus" style="font-size:0.75rem;color:#0f766e;"></span>' +
      '</div>';
    // insert before custom items section or at end of form
    var customTitle = null;
    var titles = form.querySelectorAll('.section-title');
    for (var i = 0; i < titles.length; i++) {
      if ((titles[i].textContent || '').indexOf('آیتم') >= 0) { customTitle = titles[i]; break; }
    }
    if (customTitle && customTitle.parentNode) {
      customTitle.parentNode.insertBefore(box, customTitle);
    } else {
      form.appendChild(box);
    }
    document.getElementById('pspPortalSaveBtn').onclick = function() {
      var codeEl = document.getElementById('e_code') || document.getElementById('editEmpId');
      var code = codeEl ? String(codeEl.value || '').trim() : '';
      if (!code) { alert('ابتدا کد پرسنلی را مشخص کنید (حالت ویرایش کارمند).'); return; }
      var enabled = document.getElementById('pspPortalEnabled').checked;
      var password = document.getElementById('pspPortalPass').value || '';
      var st = document.getElementById('pspPortalStatus');
      st.textContent = 'در حال ذخیره…';
      fetch('/api/admin/set-emp-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ code: code, password: password, enabled: enabled })
      }).then(function(r){ return r.json(); }).then(function(j){
        if (j.ok) {
          st.style.color = '#16a34a';
          st.textContent = enabled
            ? (password ? 'رمز جدید ذخیره شد.' : 'رمز به حالت اولیه (همان کد پرسنلی) برگشت.')
            : 'دسترسی پرتال غیرفعال شد.';
          document.getElementById('pspPortalPass').value = '';
        } else {
          st.style.color = '#b91c1c';
          st.textContent = 'خطا: ' + (j.message || j.error || 'نامشخص');
        }
      }).catch(function(){
        st.style.color = '#b91c1c';
        st.textContent = 'خطا در ارتباط با سرور';
      });
    };
  }

  // when employee modal opens, ensure box exists and reset status
  var _origOpen = window.openEmployeeModal;
  if (typeof _origOpen === 'function') {
    window.openEmployeeModal = function() {
      var r = _origOpen.apply(this, arguments);
      setTimeout(function(){
        ensurePortalBox();
        var st = document.getElementById('pspPortalStatus');
        if (st) st.textContent = '';
        var pe = document.getElementById('pspPortalEnabled');
        if (pe) pe.checked = true;
        var pp = document.getElementById('pspPortalPass');
        if (pp) pp.value = '';
      }, 50);
      return r;
    };
  } else {
    // fallback: watch for modal display
    setInterval(function(){
      var m = document.getElementById('empModal');
      if (m && m.style.display === 'flex') ensurePortalBox();
    }, 800);
  }

  // quick reset button on each row in employee table
  function addResetButtons() {
    var table = document.getElementById('empTable');
    if (!table) return;
    table.querySelectorAll('tbody tr').forEach(function(tr){
      if (tr.querySelector('.psp-reset-btn')) return;
      var tds = tr.querySelectorAll('td');
      if (!tds.length) return;
      var code = (tds[0].textContent || '').trim();
      if (!code) return;
      var actions = tds[tds.length - 1];
      if (!actions) return;
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-outline btn-sm psp-reset-btn';
      btn.textContent = 'ریست رمز پرتال';
      btn.title = 'رمز پرتال را به همان کد پرسنلی برمی‌گرداند';
      btn.style.marginRight = '4px';
      btn.onclick = function(ev){
        ev.stopPropagation();
        if (!confirm('رمز پرتال کد ' + code + ' به حالت اولیه (همان کد پرسنلی) برگردد؟')) return;
        fetch('/api/admin/set-emp-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ code: code, password: '', enabled: true })
        }).then(function(r){ return r.json(); }).then(function(j){
          alert(j.ok ? 'رمز پرتال «' + code + '» ریست شد (رمز = کد پرسنلی).' : ('خطا: ' + (j.error || '')));
        }).catch(function(){ alert('خطا در ارتباط'); });
      };
      actions.insertBefore(btn, actions.firstChild);
    });
  }
  setInterval(addResetButtons, 1500);
  setTimeout(addResetButtons, 2000);
})();
</script>`;
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
  if (request.method !== 'POST') return { error: jsonResponse({ ok: false, error: 'method_not_allowed' }, 405) };
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
  return { version: Number(row.version) || 0, obj: obj };
}

async function storePutData(cfg, baseVersion, obj, updatedBy) {
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

// ---------- Payroll calculation (unchanged) ----------
async function handlePayroll(request, user) {
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
  const data = {
    settings: body.settings,
    allowances: body.allowances,
    employees: body.employees,
    monthlyData: body.monthlyData,
    payrolls: body.payrolls,
    loanDeductedMonths: isPlainObject(body.loanDeductedMonths) ? body.loanDeductedMonths : {},
    transferredAdjustments: isPlainObject(body.transferredAdjustments) ? body.transferredAdjustments : {}
  };
  let out;
  try {
    out = makeEngine(data).runMonth(year, month, { skipLoanSE: !!body.skipLoanSE });
  } catch (e) {
    console.log(JSON.stringify({ event: 'payroll_error', user: user, message: String(e && e.message) }));
    return jsonResponse({ ok: false, error: 'calculation_failed' }, 500);
  }
  console.log(JSON.stringify({ event: 'payroll', user: user, year: year, month: month, employees: data.employees.length }));
  return jsonResponse(out, out.ok ? 200 : 400);
}

async function handleCalc(request, user) {
  const r = await readBody(request);
  if (r.error) return r.error;
  const body = r.body;
  const op = body.op;
  const data = {
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

async function handleEmpLogin(request, env) {
  if (request.method !== 'POST') return jsonResponse({ ok: false, error: 'method_not_allowed' }, 405);
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin') return jsonResponse({ ok: false, error: 'forbidden' }, 403);

  let code = '', password = '';
  try {
    const body = await request.json();
    code = String(body.code || '').trim();
    password = String(body.password || '');
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
    return jsonResponse({ ok: false, error: 'invalid' }, 401);
  }

  const emp = gd.obj.employees.find(e => String(e.code) === code);
  // inactive or explicitly disabled → reject
  if (!emp || emp.status === 'inactive' || emp.portalEnabled === false) {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid' }, 401);
  }

  // Password rules:
  // 1) If a custom hash exists → must match that hash
  // 2) If no hash yet → default password is the employee code itself (auto account)
  let ok = false;
  let usedDefault = false;
  if (emp.portalPassHash) {
    ok = await checkPassword(password, emp.portalPassHash);
  } else {
    // default: password === code
    ok = (password === code);
    usedDefault = ok;
  }
  if (!ok) {
    await new Promise(r => setTimeout(r, 600));
    return jsonResponse({ ok: false, error: 'invalid' }, 401);
  }

  // On first successful login with default password, store the hash so it is explicit
  // (optional; keeps data consistent). Soft write — ignore conflict.
  if (usedDefault && !emp.portalPassHash) {
    try {
      emp.portalEnabled = true;
      emp.portalPassHash = await hashPassword(code);
      emp.portalPassChangedAt = new Date().toISOString();
      await storePutData(cfg, gd.version, gd.obj, 'emp-auto:' + code);
    } catch (e) { /* non-fatal */ }
  }

  const exp = Math.floor(Date.now() / 1000) + SESSION_IDLE_SECONDS;
  const token = await makeEmpToken(env, emp.code, emp.fullName || '', exp);
  console.log(JSON.stringify({ event: 'emp_login', code: emp.code, defaultPass: usedDefault }));
  return new Response(JSON.stringify({
    ok: true,
    code: emp.code,
    fullName: emp.fullName || '',
    position: emp.position || '',
    mustChangePassword: usedDefault // UI can hint them to change it
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
  if (path === '/api/payroll') return handlePayroll(request, user);
  if (path === '/api/calc') return handleCalc(request, user);
  if (path === '/api/admin/set-emp-password') return handleAdminSetEmpPassword(request, who, env);

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
    if (url.pathname === '/api/emp/login') return handleEmpLogin(request, env);
    if (url.pathname === '/api/emp/logout') return handleEmpLogout();
    if (url.pathname === '/api/emp/whoami') return handleEmpWhoami(request, env);
    if (url.pathname === '/api/emp/payslip') return handleMyPayslip(request, env);
    if (url.pathname === '/api/emp/change-password') return handleEmpChangePassword(request, env);

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

    // Employee HTML page is public
    if (url.pathname === '/employee' || url.pathname === '/employee/') {
      const h = new Headers(request.headers);
      h.delete('If-None-Match');
      h.delete('If-Modified-Since');
      // try to serve employee.html from assets
      const assetReq = new Request(new URL('/employee.html', request.url), { headers: h });
      let res = await env.ASSETS.fetch(assetReq);
      if (res.status === 404) {
        // fallback: try /employee/index.html style
        res = await env.ASSETS.fetch(new Request(new URL('/employee/index.html', request.url), { headers: h }));
      }
      if (res.status === 200) {
        const headers = new Headers(res.headers);
        headers.set('Cache-Control', 'no-store');
        headers.set('X-Robots-Tag', 'noindex, nofollow');
        return new Response(res.body, { status: 200, headers });
      }
      // if file not found, return a minimal built-in page
      return new Response(BUILTIN_EMPLOYEE_HTML, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
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
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>فیش حقوقی — پارسپهر</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Vazirmatn,Tahoma,sans-serif;background:#f0fdfa;color:#134e4a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:14px;padding:28px;max-width:420px;width:100%;box-shadow:0 8px 30px rgba(15,118,110,.12)}
h1{font-size:1.2rem;color:#0f766e;text-align:center;margin-bottom:6px}
.sub{text-align:center;font-size:.85rem;color:#64748b;margin-bottom:18px}
label{display:block;font-size:.82rem;font-weight:600;margin:10px 0 4px;color:#0f766e}
input,select{width:100%;padding:9px 11px;border:1px solid #99f6e4;border-radius:8px;font-family:inherit;font-size:.95rem}
button{width:100%;margin-top:14px;padding:11px;border:0;border-radius:8px;background:#0f766e;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{background:#0d9488}
.err{color:#b91c1c;font-size:.85rem;text-align:center;margin-top:10px;min-height:1.2em}
.hidden{display:none}
.payslip{margin-top:16px;border:1px solid #99f6e4;border-radius:10px;padding:14px;font-size:.85rem}
.payslip h2{font-size:1rem;text-align:center;margin-bottom:8px}
.payslip table{width:100%;border-collapse:collapse;margin-top:8px}
.payslip td,.payslip th{border:1px solid #cbd5e1;padding:5px 7px;text-align:right}
.net{font-size:1.1rem;font-weight:700;color:#0f766e;text-align:center;margin-top:10px;padding:8px;background:#f0fdfa;border-radius:8px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;font-size:.85rem}
.link{color:#0f766e;cursor:pointer;text-decoration:underline;background:none;border:0;font-family:inherit;font-size:.82rem;width:auto;padding:0;margin:0}
</style>
</head>
<body>
<div class="card" id="loginCard">
  <h1>مشاهده فیش حقوقی</h1>
  <p class="sub">کد پرسنلی و رمز عبور خود را وارد کنید</p>
  <label>کد پرسنلی</label>
  <input id="code" autocomplete="username">
  <label>رمز عبور</label>
  <input id="pass" type="password" autocomplete="current-password">
  <button onclick="doLogin()">ورود</button>
  <div class="err" id="loginErr"></div>
</div>

<div class="card hidden" id="appCard">
  <div class="topbar">
    <span id="whoLabel"></span>
    <button class="link" onclick="doLogout()">خروج</button>
  </div>
  <h1>فیش حقوقی</h1>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
    <div><label>سال</label><input type="number" id="year" value="1405"></div>
    <div><label>ماه</label>
      <select id="month">
        <option value="1">فروردین</option><option value="2">اردیبهشت</option><option value="3">خرداد</option>
        <option value="4">تیر</option><option value="5">مرداد</option><option value="6">شهریور</option>
        <option value="7">مهر</option><option value="8">آبان</option><option value="9">آذر</option>
        <option value="10">دی</option><option value="11">بهمن</option><option value="12">اسفند</option>
      </select>
    </div>
  </div>
  <button onclick="loadPayslip()">نمایش فیش</button>
  <div class="err" id="appErr"></div>
  <div id="payslipBox"></div>

  <hr style="margin:20px 0;border:0;border-top:1px solid #e2e8f0">
  <h1 style="font-size:1rem">تغییر رمز عبور</h1>
  <label>رمز فعلی</label><input id="oldPass" type="password">
  <label>رمز جدید (حداقل ۶ کاراکتر)</label><input id="newPass" type="password">
  <label>تکرار رمز جدید</label><input id="newPass2" type="password">
  <button onclick="changePass()">ثبت رمز جدید</button>
  <div class="err" id="passErr"></div>
</div>

<script>
function fmt(n){return (Number(n)||0).toLocaleString('fa-IR')}
async function doLogin(){
  document.getElementById('loginErr').textContent='';
  const code=document.getElementById('code').value.trim();
  const password=document.getElementById('pass').value;
  try{
    const r=await fetch('/api/emp/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code,password}),credentials:'same-origin'});
    const j=await r.json();
    if(!j.ok){document.getElementById('loginErr').textContent='کد یا رمز اشتباه است یا دسترسی فعال نیست.';return}
    showApp(j);
  }catch(e){document.getElementById('loginErr').textContent='خطا در ارتباط با سرور';}
}
function showApp(j){
  document.getElementById('loginCard').classList.add('hidden');
  document.getElementById('appCard').classList.remove('hidden');
  document.getElementById('whoLabel').textContent=(j.fullName||'')+' — کد '+j.code;
}
async function checkSession(){
  try{
    const r=await fetch('/api/emp/whoami',{credentials:'same-origin'});
    const j=await r.json();
    if(j.ok) showApp(j);
  }catch(e){}
}
async function doLogout(){
  await fetch('/api/emp/logout',{method:'POST',credentials:'same-origin'});
  location.reload();
}
async function loadPayslip(){
  document.getElementById('appErr').textContent='';
  document.getElementById('payslipBox').innerHTML='';
  const year=Number(document.getElementById('year').value);
  const month=Number(document.getElementById('month').value);
  try{
    const r=await fetch('/api/emp/payslip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({year,month}),credentials:'same-origin'});
    const j=await r.json();
    if(!j.ok){document.getElementById('appErr').textContent=j.message||'فیشی برای این ماه یافت نشد.';return}
    const p=j.payslip;
    const months=['','فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'];
    let items='';
    (p.itemDetails||[]).forEach(it=>{
      items+='<tr><td>'+it.name+(it.qty!=null?' ('+it.qty+')':'')+'</td><td>'+fmt(it.amount)+'</td></tr>';
    });
    document.getElementById('payslipBox').innerHTML=\`
      <div class="payslip">
        <h2>\${j.company&&j.company.name?j.company.name:'فیش حقوقی'}</h2>
        <p style="text-align:center">\${p.fullName} — \${months[month]} \${year}</p>
        <table>
          <tr><th>شرح</th><th>مبلغ</th></tr>
          <tr><td>حقوق پایه</td><td>\${fmt(p.basicAmount)}</td></tr>
          \${p.otAmount?\`<tr><td>اضافه‌کار</td><td>\${fmt(p.otAmount)}</td></tr>\`:''}
          \${p.nightAmount?\`<tr><td>شب‌کاری</td><td>\${fmt(p.nightAmount)}</td></tr>\`:''}
          \${p.shiftAmount?\`<tr><td>نوبت‌کاری</td><td>\${fmt(p.shiftAmount)}</td></tr>\`:''}
          \${items}
          <tr><td><b>جمع ناخالص</b></td><td><b>\${fmt(p.gross)}</b></td></tr>
          <tr><td>بیمه سهم کارمند</td><td>\${fmt(p.insurance)}</td></tr>
          <tr><td>مالیات</td><td>\${fmt(p.tax)}</td></tr>
          \${p.loanDeduction?\`<tr><td>کسر وام</td><td>\${fmt(p.loanDeduction)}</td></tr>\`:''}
          \${p.totalDeductions?\`<tr><td>سایر کسورات</td><td>\${fmt(p.totalDeductions)}</td></tr>\`:''}
        </table>
        <div class="net">خالص پرداختی: \${fmt(p.net)} ریال</div>
      </div>\`;
  }catch(e){document.getElementById('appErr').textContent='خطا در دریافت فیش';}
}
async function changePass(){
  document.getElementById('passErr').textContent='';
  const oldPassword=document.getElementById('oldPass').value;
  const newPassword=document.getElementById('newPass').value;
  const n2=document.getElementById('newPass2').value;
  if(newPassword!==n2){document.getElementById('passErr').textContent='رمز جدید و تکرار آن یکسان نیست.';return}
  try{
    const r=await fetch('/api/emp/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldPassword,newPassword}),credentials:'same-origin'});
    const j=await r.json();
    if(!j.ok){document.getElementById('passErr').textContent=j.message||'خطا در تغییر رمز';return}
    document.getElementById('passErr').style.color='#16a34a';
    document.getElementById('passErr').textContent='رمز با موفقیت تغییر کرد.';
    document.getElementById('oldPass').value='';
    document.getElementById('newPass').value='';
    document.getElementById('newPass2').value='';
  }catch(e){document.getElementById('passErr').textContent='خطا در ارتباط';}
}
checkSession();
</script>
</body>
</html>`;
