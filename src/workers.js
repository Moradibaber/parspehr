None selected 

Skip to content
Using Gmail with screen readers
1 of 5,762
(no subject)
Inbox

M. Moradi <mmoradibabersad@gmail.com>
Attachments
4:19 PM (0 minutes ago)
to me

 2 Attachments
  •  Scanned by Gmail
workers.txt
100%
// parspehr gate: personal login + watermark + payroll API + employee self-service portal
import { makeEngine } from './engine.js';
import PORTAL_ADMIN_JS from './portal-admin-src.js';

const PSP_BUILD = '2026-11-22-hse-v3';

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
  const bootVer = '20261120v325';
  const floatFixScript = '<script>(function(){try{console.log("[psp] float-fix v325");}catch(e){}var busy=false,pending=null,timer=null;function readF(){var el=document.getElementById("pspWsFloat");if(!el)return null;var s=String(el.value||"").replace(/[\\u06F0-\\u06F9]/g,function(d){return"0123456789"["\\u06F0\\u06F1\\u06F2\\u06F3\\u06F4\\u06F5\\u06F6\\u06F7\\u06F8\\u06F9".indexOf(d)]}).replace(/[^\\d]/g,"");var n=parseInt(s,10);if(!isFinite(n)||n<0)n=0;if(n>480)n=480;return n}function writeF(n){var el=document.getElementById("pspWsFloat");if(!el||n==null)return;if(document.activeElement===el)return;el.value=String(n)}function doSave(n,cb){if(n==null){if(cb)cb(null);return}if(busy){pending=n;return}busy=true;fetch("/api/admin/set-float-minutes",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",body:JSON.stringify({floatMinutes:n})}).then(function(r){return r.text().then(function(t){var j=null;try{j=t?JSON.parse(t):null}catch(e){}return{ok:r.ok,status:r.status,j:j,t:t}})}).then(function(x){busy=false;try{console.log("[psp] float save result",x.status,x.j||x.t)}catch(e){}if(x.j&&x.j.ok){writeF(x.j.floatMinutes);window.__pspFloatSaved=x.j.floatMinutes;if(cb)cb(x.j)}else if(x.status===409||x.status===502||(x.j&&(x.j.error==="conflict"||x.j.reason==="conflict"))){setTimeout(function(){doSave(n,cb)},1000)}else{if(cb)cb(x.j)}if(pending!=null){var p=pending;pending=null;doSave(p)}}).catch(function(e){busy=false;try{console.error("[psp] float save fail",e)}catch(x){}if(cb)cb(null)})}function saveF(n,cb){clearTimeout(timer);timer=setTimeout(function(){doSave(n,cb)},400)}function bind(){var el=document.getElementById("pspWsFloat");if(!el||el.getAttribute("data-psp-ff"))return;el.setAttribute("data-psp-ff","1");el.addEventListener("change",function(){saveF(readF())});el.addEventListener("blur",function(){saveF(readF())})}setInterval(bind,1000);document.addEventListener("click",function(ev){var t=ev.target;if(!t||!t.closest)return;var b=t.closest("button,#pspCurSave");if(!b)return;var id=b.id||"";var tx=(b.textContent||"");if(id==="pspCurSave"||/ثبت\\s*ماه|ماه\\s*جاری/.test(tx)){setTimeout(function(){saveF(readF())},600)}},true)})();<\/script>';
  const portalAdminScript = '<script src="/api/admin/portal-boot.js?v=' + bootVer + '" onerror="console.error(\'[psp] portal-boot LOAD FAIL\');try{var d=document.createElement(\'div\');d.style.cssText=\'padding:12px;margin:12px;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;color:#991b1b;font-family:Tahoma;direction:rtl\';d.textContent=\'خطا در بارگذاری portal-boot.js (شبکه یا دیپلوی). Worker را دوباره دیپلوی کنید.\';document.body&&document.body.prepend(d);}catch(e){}"><\/script>';
  const emergencyInline = '<script>(function(){function n(s){return String(s||\'\').replace(/[\\u200c\\u200d\\u200e\\u200f\\u00a0]/g,\'\').replace(/\\s+/g,\' \').trim();}function hide(el){el.setAttribute(\'data-psp-struct-hide\',\'1\');el.setAttribute(\'hidden\',\'hidden\');el.style.setProperty(\'display\',\'none\',\'important\');el.style.setProperty(\'visibility\',\'hidden\',\'important\');}function show(el){el.removeAttribute(\'data-psp-struct-hide\');el.removeAttribute(\'hidden\');el.style.removeProperty(\'display\');el.style.removeProperty(\'visibility\');}function red(t){if(!t||t.length>36)return false;if(t===\'غیرفعال\'||t===\'فعال\')return false;if(t.indexOf(\'غیرفعال\')>=0)return true;if(t.indexOf(\'سفارش\')>=0&&t.indexOf(\'آیتم\')>=0)return true;if(t.indexOf(\'ثابت\')>=0&&t.indexOf(\'ماهان\')>=0)return true;if(t.indexOf(\'ترتیب\')>=0&&t.indexOf(\'ستون\')>=0)return true;if(t===\'مرخصی\'||t===\'مأموریت\'||t===\'ماموریت\'||t===\'سایر\')return true;if(t===\'مرخصی و مأموریت\'||t===\'مرخصی و ماموریت\')return true;return false;}function go(){try{var nodes=document.querySelectorAll(\'button,[role=tab],a,.tab-btn\');var hasPortal=!!(document.getElementById(\'pspPortalTabBtn\')||document.querySelector(\'[data-tab="portalatt"]\')||document.getElementById(\'panel-portalatt\'));for(var i=0;i<nodes.length;i++){var el=nodes[i];try{if(el.closest&&el.closest(\'table,form,.psp-subtabs,#pspSubTabs\'))continue;var t=n(el.textContent);var isPortal=el.id===\'pspPortalTabBtn\'||el.getAttribute(\'data-tab\')===\'portalatt\';var leave=t.indexOf(\'مرخصی\')>=0;var mis=t.indexOf(\'مأموریت\')>=0||t.indexOf(\'ماموریت\')>=0;var oth=t.indexOf(\'سایر\')>=0;if(isPortal||(leave&&mis)||(leave&&mis&&oth)){el.textContent=\'کارکرد\';try{el.setAttribute(\'title\',\'کارکرد\');}catch(e0){}show(el);continue;}if(hasPortal&&red(t)){var r=el.getBoundingClientRect();var cnt=0,emp=0;for(var j=0;j<nodes.length;j++){try{var r2=nodes[j].getBoundingClientRect();if(Math.abs(r2.top-r.top)<50){cnt++;var tx=n(nodes[j].textContent);if(/^کارکنان\\s*فعال/.test(tx)||tx.indexOf(\'غیرفعال\')>=0)emp++;}}catch(e){}}if(cnt<=3&&emp>=2)continue;hide(el);}}catch(e1){}}var pb=document.getElementById(\'pspPortalTabBtn\');if(pb){pb.textContent=\'کارکرد\';show(pb);}}catch(e){}}if(!document.getElementById(\'pspStructHideCSS\')){var st=document.createElement(\'style\');st.id=\'pspStructHideCSS\';st.textContent=\'[data-psp-struct-hide="1"]{display:none!important;visibility:hidden!important;}\';(document.head||document.documentElement).appendChild(st);}go();setInterval(go,200);})();</script>';



  const bottom = emergencyInline + floatFixScript + portalAdminScript + '<script>/*psp:' + safe + '*/</script><!-- psp:' + safe + ' -->';
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
    // ترمیم شناوری: فقط portal/settings — هرگز max تقویم‌ها (که ۹۰ را برمی‌گرداند)
    try {
      if (obj.settings && typeof obj.settings === 'object') {
        var fm = parseFloatMinutesValue(obj.settings.portalFloatMinutes, null);
        if (fm == null) fm = parseFloatMinutesValue(obj.settings.floatMinutes, null);
        if (fm == null) {
          var nc = obj.settings.contractCalendars && obj.settings.contractCalendars.normal;
          fm = parseFloatMinutesValue(nc && nc.floatMinutes, null);
        }
        if (fm != null) {
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


/** سند «settings» (ثابت‌های ماهانه، قوانین کسر، برچسب‌ها) جدا از سند «data» ذخیره می‌شود */
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

/** ثابت‌های ماهانه فقط با حذف صریح (tombstone) پاک می‌شوند؛ ذخیرهٔ ناقص یک کلاینت قدیمی آن‌ها را نمی‌برد */
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
    byId[id] = v; // نسخهٔ کلاینت (آخرین ویرایش) مقدم است
  });
  curList.forEach(function (v) { // آیتم بدون id را هم نگه دار
    if (v && !v.id) { const k = 'noid:' + String(v.name || ''); if (!byId[k]) { order.push(k); byId[k] = v; } }
  });
  if (order.length || prevList.length || curList.length) inc.monthlyVars = order.map(function (k) { return byId[k]; });
  inc.monthlyVarsDeleted = Object.keys(tomb);
  return inc;
}

function employeeFieldLabels() {
  return {
    fullName: 'نام و نام خانوادگی',
    firstName: 'نام',
    lastName: 'نام خانوادگی',
    birthDate: 'تاریخ تولد',
    management: 'مدیریت',
    deputy: 'معاونت',
    unit: 'واحد',
    group: 'گروه',
    jobGrade: 'رده شغلی',
    workplace: 'محل کار',
    city: 'شهر محل سکونت',
    province: 'استان محل سکونت',
    gender: 'جنسیت',
    militaryStatus: 'وضعیت نظام وظیفه',
    militaryExemptType: 'نوع معافیت نظام وظیفه',
    educationLevel: 'مقطع تحصیلی',
    educationField: 'رشته تحصیلی',
    hireDate: 'تاریخ استخدام',
    endDate: 'تاریخ پایان همکاری',
    position: 'سمت',
    basicSalary: 'حقوق پایه',
    status: 'وضعیت',
    contractType: 'نوع قرارداد',
    bankName: 'نام بانک',
    accountNumber: 'شماره حساب',
    insuranceNo: 'شماره بیمه',
    nationalId: 'کد ملی',
    mobile: 'شماره همراه',
    fatherName: 'نام پدر',
    address: 'آدرس',
    marital: 'وضعیت تأهل',
    childrenCount: 'تعداد اولاد',
    taxPercent: 'درصد مالیات',
    exemption: 'معافیت',
    seniorityBase: 'پایه سنوات'
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
        out.push({ field: k, label: labels[k], from: fa || '—', to: fb || '—' });
      }
      return;
    }
    if (a !== b && (a || b)) {
      out.push({ field: k, label: labels[k], from: a || '—', to: b || '—' });
    }
  });
  // customItems by name — فقط تغییر واقعی مبلغ/فعال بودن (نه 0 در برابر غیرفعال)
  function itemSig(emp) {
    const m = {};
    (emp.customItems || emp.customs || emp.items || []).forEach(function (ci) {
      if (!ci || !ci.name) return;
      const name = String(ci.name).trim();
      if (!name) return;
      const amount = Number(ci.amount);
      const amt = isFinite(amount) ? amount : 0;
      // فعال بودن: صریح false/0 = خاموش؛ در غیر این صورت اگر مبلغ > 0 یا enabled true
      let en = true;
      if (ci.enabled === false || ci.enabled === 0 || ci.enabled === '0') en = false;
      if (ci.active === false || ci.active === 0) en = false;
      // مبلغ صفر و بدون فلگ فعال = معادل غیرفعال/خالی
      if (!en || !(amt > 0)) {
        m[name] = { key: 'off', label: 'غیرفعال' };
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
    if (!s || s === '—' || s === 'غیرفعال' || s === 'حذف شد') return true;
    var n = Number(String(s).replace(/,/g, ''));
    if (isFinite(n) && n === 0) return true;
    return false;
  }
  Object.keys(names).forEach(function (n) {
    const a = pm[n] || { key: 'off', label: '—' };
    const b = nm[n] || { key: 'off', label: '—' };
    if (a.key === b.key) return;
    // 0 / غیرفعال / نبودن = معادل هم — ثبت نشود
    if (isOffState(a) && isOffState(b)) return;
    out.push({ field: 'custom:' + n, label: 'آیتم «' + n + '»', from: a.label, to: b.label });
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
      text: (c.label || c.field) + ' از «' + c.from + '» به «' + c.to + '» تغییر کرد'
    });
  });
  // keep last 300
  if (obj.employeeChangeLog[key].length > 300) {
    obj.employeeChangeLog[key] = obj.employeeChangeLog[key].slice(-300);
  }
}

async function storePutData(cfg, baseVersion, obj, updatedBy) {
  // Preserve portal fields the main app form does not know about (managerCode, portal password, requests…)
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
            // اگر کلاینت family نفرستاد، از قبلی نگه دار (تا F5 پاک نکند)
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
            // تاریخچه تغییرات کارت کارمند
            try {
              const ch = diffEmployeeChanges(p, e);
              if (ch.length) appendEmployeeChangeLog(obj, e.code, ch, updatedBy);
            } catch (eLog) {}
          }
        });
        // حفظ تاریخچه قبلی اگر کلاینت نفرستاده
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
        // تنظیمات نمایش حکم/مشخصات فقط توسط خود ذخیره‌ی پورتال‌ویو (updatedBy = 'portal-view:...') قابل تغییر است؛
        // ذخیره‌های دیگر (فرم اصلی) نسخه‌ی قبلی را حفظ می‌کنند. (قبلاً این خط ذخیره‌ی خود پورتال‌ویو را هم برمی‌گرداند!)
        if (String(updatedBy || '').indexOf('portal-view:') !== 0) {
          if (prev.obj.portalViewConfig) obj.portalViewConfig = prev.obj.portalViewConfig;
        }
        // پیام‌های همگانی ادمین: فقط ذخیره‌های خود پیام‌رسان (updatedBy = 'bcast:...') می‌توانند تغییرشان دهند
        if (String(updatedBy || '').indexOf('bcast:') !== 0) {
          if (Array.isArray(prev.obj.broadcastMessages)) obj.broadcastMessages = prev.obj.broadcastMessages;
        }
        // خانواده / بیمه تکمیلی / عکس — هرگز با ذخیره فرم اصلی پاک نشوند
        if (prev.obj.employeeExtras && typeof prev.obj.employeeExtras === 'object') {
          obj.employeeExtras = Object.assign({}, prev.obj.employeeExtras, obj.employeeExtras || {});
        }
        if (prev.obj.employeePhotos && typeof prev.obj.employeePhotos === 'object') {
          obj.employeePhotos = Object.assign({}, prev.obj.employeePhotos, obj.employeePhotos || {});
        }
        // شرح وظایف — فقط با updatedBy jobdesc: تغییر کند
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
        // نوع قرارداد و تقویم قرارداد: اگر کلاینت (فرم اصلی) لیست ناقص فرستاد، لیست کامل سرور حفظ شود
        try {
          if (prev.obj.settings && typeof prev.obj.settings === 'object') {
            if (!obj.settings || typeof obj.settings !== 'object') obj.settings = {};
            var prevList = Array.isArray(prev.obj.settings.contractTypesList) ? prev.obj.settings.contractTypesList : [];
            var curList = Array.isArray(obj.settings.contractTypesList) ? obj.settings.contractTypesList : [];
            if (prevList.length > curList.length) {
              // ادغام: همهٔ قبلی + جدیدهای کلاینت
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
                    if (k === 'floatMinutes') return; // جداگانه
                    if ((curCal[k] == null || curCal[k] === '') && prevCal[k] != null && prevCal[k] !== '') curCal[k] = prevCal[k];
                  });
                  // شناوری نوع قرارداد: فقط اگر خالی است از قبلی پر کن — هر عدد صریح (از جمله ۱۵) محترم است
                  var prevFm = parseFloatMinutesValue(prevCal.floatMinutes, null);
                  var curFm = parseFloatMinutesValue(curCal.floatMinutes, null);
                  if (curFm == null && prevFm != null) {
                    curCal.floatMinutes = prevFm;
                  }
                });
                // شناوری سراسری: مقدار جدید ذخیره‌شده را هرگز به‌خاطر «قبلی ۹۰» برنگردان
                (function () {
                  var prevSF = parseFloatMinutesValue(prev.obj.settings && prev.obj.settings.floatMinutes, null);
                  var curSF = parseFloatMinutesValue(obj.settings && obj.settings.floatMinutes, null);
                  var fromFloatSet = String(updatedBy || '').indexOf('float-set:') === 0;
                  var prevPfm = parseFloatMinutesValue(prev.obj.settings && prev.obj.settings.portalFloatMinutes, null);
                  var curPfm = parseFloatMinutesValue(obj.settings && obj.settings.portalFloatMinutes, null);
                  var finalFm = null;
                  if (fromFloatSet && curSF != null) {
                    finalFm = curSF;
                  } else if (fromFloatSet && curPfm != null) {
                    finalFm = curPfm;
                  } else if (prevPfm != null) {
                    // غیر float-set: همیشه portal سرور — کلاینت ۹۰ را برنگرداند
                    finalFm = prevPfm;
                  } else if (prevSF != null) {
                    finalFm = prevSF;
                  } else if (curPfm != null) {
                    finalFm = curPfm;
                  } else if (curSF != null) {
                    finalFm = curSF;
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

  // سبک‌سازی قبل از ذخیره: عکس تکراری داخل extras و روی emp اگر در employeePhotos هست
  try {
    if (obj.employeeExtras && typeof obj.employeeExtras === 'object') {
      Object.keys(obj.employeeExtras).forEach(function (k) {
        if (obj.employeeExtras[k] && obj.employeeExtras[k].photo) delete obj.employeeExtras[k].photo;
      });
    }
  } catch (eStrip) {}
  // شناوری اجباری: بعد از همهٔ mergeها اعمال شود تا ۹۰ برنگردد
  try {
    if (obj && obj.__forceFloatMinutes != null) {
      var _ff = obj.__forceFloatMinutes;
      delete obj.__forceFloatMinutes;
      forceApplyCompanyFloat(obj, _ff);
    } else if (String(updatedBy || '').indexOf('float-set:') === 0) {
      var _fm = parseFloatMinutesValue(obj && obj.settings && obj.settings.portalFloatMinutes, null);
      if (_fm == null) _fm = parseFloatMinutesValue(obj && obj.settings && obj.settings.floatMinutes, null);
      if (_fm != null) forceApplyCompanyFloat(obj, _fm);
    }
  } catch (eForceF) {}
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

const DECREE_ARREARS_ITEM = 'معوقه حکم';
const DECREE_ARREARS_VAR_ITEM = 'معوقه اضافه‌کار و نوبت‌کاری حکم';

function faDigitsToLatin(s) {
  return String(s == null ? '' : s)
    .replace(/[۰-۹]/g, function (c) { return String(c.charCodeAt(0) - 1776); })
    .replace(/[٠-٩]/g, function (c) { return String(c.charCodeAt(0) - 1632); });
}

// اندیس ماهِ تاریخ اجرای حکم (سال*12 + ماه-1)
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
  // فقط آیتم‌های مشترک: در حکم قبلی و جدید هر دو مقدار غیرصفر دارند
  // (آیتمی که قبلاً نبوده، مثل حق اولاد جدید، یا حذف شده، در مابه‌التفاوت نمی‌آید)
  Object.keys(keys).forEach(function (k) {
    const a = Number(oldV[k]) || 0, b = Number(newV[k]) || 0;
    if (a !== 0 && b !== 0) s += b - a;
  });
  return s;
}

// مقادیر حکمِ معتبر در ماهِ idx، بدون حکم dec (اگر حکم قبلی نبود: مقادیر قبل از همین حکم)

/** قبل از محاسبه: حقوق پایه و پایه سنوات از کارت کارمند روی decreeValues */
function syncCardSalaryIntoDecreeData(data) {
  if (!data || !Array.isArray(data.employees)) return data;
  if (!data.decreeValues || typeof data.decreeValues !== 'object') data.decreeValues = {};
  var headers = Array.isArray(data.decreeHeaders) ? data.decreeHeaders : [];
  function isBas(h) {
    if (!h) return false;
    if (String(h.id) === 'basic' || String(h.id) === 'basicSalary') return true;
    var n = String(h.name || '').replace(/[\u200c\u200d]/g, ' ').replace(/\s+/g, ' ').trim();
    return n === 'حقوق پایه' || n.indexOf('حقوق پایه') === 0 || /^حقوق (و مزد )?پایه/.test(n);
  }
  function isSen(h) {
    if (!h) return false;
    if (String(h.id) === 'seniorityBase' || String(h.id) === 'seniority') return true;
    var n = String(h.name || '').replace(/[\u200c\u200d]/g, ' ').replace(/\s+/g, ' ').trim();
    return n === 'پایه سنوات' || n.indexOf('پایه سنوات') === 0;
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

// کلیدهای «حقوق پایه» در مقادیر حکم (اضافه‌کار/شب‌کاری/نوبت‌کاری بر پایه همین مبلغ محاسبه می‌شوند)
function decreeBasicKeys(headers) {
  const keys = ['basic'];
  (headers || []).forEach(function (h) {
    if (!h) return;
    const nm = String(h.name || '').replace(/[\u200c\u200f\u200e]/g, ' ').replace(/ي/g, 'ی').replace(/ك/g, 'ک').replace(/\s+/g, ' ').trim();
    if (/^حقوق (و مزد )?پایه( ماهانه)?$/.test(nm) || String(h.id) === 'basic') {
      const id = String(h.id == null ? h.name : h.id);
      if (keys.indexOf(id) < 0) keys.push(id);
    }
  });
  return keys;
}

// کلیدهای «پایه سنوات» در مقادیر حکم
function decreeSeniorityKeys(headers) {
  const keys = ['seniorityBase'];
  (headers || []).forEach(function (h) {
    if (!h) return;
    const nm = String(h.name || '').replace(/[\u200c\u200f\u200e]/g, ' ').replace(/ي/g, 'ی').replace(/ك/g, 'ک').replace(/\s+/g, ' ').trim();
    if (/^پایه سنوات( ماهانه)?$/.test(nm) || String(h.id) === 'seniorityBase') {
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

// معوقه‌ای که باید در حقوق (year, month) پرداخت شود: احکامی که تاریخ اجرایشان در همین ماه است و «با معوقه N ماه» دارند
// ctx (اختیاری): { eng, emp, basicKeys } — برای محاسبه مجدد اضافه‌کار/شب‌کاری/نوبت‌کاری ماه‌های معوقه با پایه جدید
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
      // «محاسبه از آیتم‌ها»: مبلغ جدید − مبلغ فیش هر ماه معوقه (عکس لحظه صدور حکم)
      // اضافه‌کاری/شب‌کاری/نوبت‌کاری (auto): با ساعات هر ماه معوقه و حقوق پایه جدید توسط موتور محاسبه می‌شود
      const newB = ctx ? decreeBasicOf(dec.values, ctx.basicKeys) : 0;
      dec.arrearsItems.forEach(function (it) {
        if (!it) return;
        if (it.auto) {
          if (!(ctx && ctx.eng && ctx.emp) || !(newB > 0)) return;
          (it.olds || []).forEach(function (o) {
            if (!o || o.amount == null) return; // ماهی که فیش نداشته
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
      // «محاسبه از حکم»: فقط تفاوت آیتم‌های مشترک مبالغ حکم (بدون اضافه‌کار/شب‌کاری/نوبت‌کاری)
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
    // حقوق پایه / پایه سنوات کارت با حکم همگام شده است؛ برای ماه‌های قبل از اجرای حکم، مقادیر «قبل از حکم» همان حکم استفاده می‌شود
    // (فقط احکام صادرشده با همگام‌سازی کارت: cardSynced)
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
    // اجرای مجدد محاسبه، آیتم‌های خودکار قبلی را جایگزین می‌کند
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
        flag: 'بلی',
        qtyDefault: 1,
        duration: 'always',
        note: note
      });
      row.qty[name] = 1;
    }
    if (res.total) pushItem(DECREE_ARREARS_ITEM, res.total, 'خودکار از احکام: ' + res.items.map(function (x) { return x.months + ' ماه'; }).join('، '));
    if (res.varTotal) pushItem(DECREE_ARREARS_VAR_ITEM, res.varTotal, 'اضافه‌کاری/شب‌کاری/نوبت‌کاری ماه‌های معوقه با پایه جدید: ' + res.varItems.map(function (x) { return x.months + ' ماه'; }).join('، '));
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
    // punchDays؛ workDays از کلاینت (ورود داده/تایم‌شیت) حفظ می‌شود — دوباره کم نشود
    try {
      const key = year + '-' + month;
      if (!data.monthlyData) data.monthlyData = {};
      if (!data.monthlyData[key]) data.monthlyData[key] = {};
      // کلیدهای جایگزین 1405-8 و 1405-08
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
        // اگر workDays صفر/خالی است از کلید جایگزین بخوان
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
      let text = (await request.text()).trim();
      if (text.length > MAX_DOC_BYTES) return jsonResponse({ ok: false, error: 'too_large' }, 413);
      if (text.charAt(0) !== '{' || text.charAt(text.length - 1) !== '}') return jsonResponse({ ok: false, error: 'bad_body' }, 400);

      // سند data: حفظ/ادغام نوع‌قرارداد + حذف تکراری هنگام همگام‌سازی فرم اصلی
      if (rest === 'data' && base > 0) {
        try {
          const incoming = JSON.parse(text);
          if (incoming && typeof incoming === 'object') {
            const prev = await storeGetData(cfg);
            if (!prev.fail && prev.obj && prev.obj.settings) {
              if (!incoming.settings || typeof incoming.settings !== 'object') incoming.settings = {};
              const prevList = Array.isArray(prev.obj.settings.contractTypesList) ? prev.obj.settings.contractTypesList : [];
              const curList = Array.isArray(incoming.settings.contractTypesList) ? incoming.settings.contractTypesList : [];
              // اول لیست قبلی را بگذار تا حذف نشوند، بعد لیست کلاینت
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
                    // فقط اگر خالی است از قبلی پر کن — عدد ۱۵ هم معتبر است
                    if (curFm2 == null && prevFm2 != null) {
                      curCal.floatMinutes = prevFm2;
                    }
                  });
                  (function () {
                    // شناوری فقط از سرور — کلاینت شیت اصلی (با ۹۰ قدیمی در حافظه) حق بازنویسی ندارد
                    var prevSF = parseFloatMinutesValue(prev.obj.settings && prev.obj.settings.floatMinutes, null);
                    var prevPfm = parseFloatMinutesValue(prev.obj.settings && prev.obj.settings.portalFloatMinutes, null);
                    var finalFm = (prevPfm != null) ? prevPfm : prevSF;
                    if (finalFm != null) {
                      incoming.settings.floatMinutes = finalFm;
                      incoming.settings.portalFloatMinutes = finalFm;
                      incoming.settings.companyFloatMinutes = finalFm;
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
            // حذف تکراری + برداشت از کارکنان
            try { mergeDedupeContractTypes(incoming); } catch (eDd) {}
            text = JSON.stringify(incoming);
          }
        } catch (eMergeCt) { /* non-fatal — keep original text */ }
      }

      if (rest === 'settings' && base > 0) {
        try {
          const incS = JSON.parse(text);
          const prevS = await storeGetSettingsDoc(cfg);
          if (incS && typeof incS === 'object' && prevS) {
            protectMonthlyVarsOnPut(prevS, incS);
            text = JSON.stringify(incS);
          }
        } catch (eMvp) { /* non-fatal — keep original text */ }
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
  var isSafetyOfficerFlag = false;
  try {
    const cfg3 = storeConfig(env);
    if (cfg3) {
      const gd3 = await storeGetData(cfg3);
      if (gd3 && !gd3.fail && gd3.obj) {
        const sh = getSafetyHealth(gd3.obj);
        isSafetyOfficerFlag = isSafetyOfficer(sh.config, sess.code);
      }
    }
  } catch (eS) {}
  return jsonResponse({
    ok: true, userAccess: userAccess,
    realJalaliYear: realJalaliYear, realJalaliMonth: realJalaliMonth, realJalaliDay: realJalaliDay,
    requestYear: requestYear, requestMonth: requestMonth, requestGraceDays: requestGraceDays,
    currentYear: adminYear, currentMonth: adminMonth,
    isSafetyOfficer: isSafetyOfficerFlag
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
      return jsonResponse({ ok: false, error: 'forbidden', message: 'مشاهده فیش این فرد برای شما مجاز نیست.' }, 403);
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
    return jsonResponse({ ok: false, error: 'not_found', message: 'برای این ماه فیشی ثبت نشده است.', viewable: viewableP, code: payCode }, 404);
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

function faDigitsToEn(str) {
  return String(str || '').replace(/[۰-۹]/g, function (c) { return String(c.charCodeAt(0) - 1776); })
    .replace(/[٠-٩]/g, function (c) { return String(c.charCodeAt(0) - 1632); });
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
      // ازدواج/تولد/… را از qty بازسازی کن (نه کم‌کردن دستی که دوبل می‌شود)
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
        Object.keys(row.qty).forEach(function (nm) { if (/جاب/.test(String(nm))) row.qty[nm] = 0; });
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
  /* کسر استحقاقی فقط روزهای کاری — پنجشنبه/جمعه و تعطیل رسمی شمرده نمی‌شوند
     مگر countNonWorkDaysAsLeave یا نوع مجاز روی غیرکاری */
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
        if (/مرخص|استحقاق|استعلاج|بدون\s*حقوق|غیبت|غایب|مأمور|مامور|mission|leave/i.test(s)) return false;
        return (s.indexOf('رست') >= 0) || /\brest\b/i.test(s);
      }
      if (_isRestNameOnly(tname) || _isRestNameOnly(req.typeId) || _isRestNameOnly(req.kind)) {
        const qtyName = matchQtyItemName(data, code, tname) || 'رست کاری';
        splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
          const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
          const days = leaveDaysForMonthChunk(data, req, chunk);
          addQtyDaysToMonthRow(row, qtyName, days);
          try { rebuildRestQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eRR) {}
        });
      } else if (tname) {
        // شمارش مطلق از همه درخواست‌ها — جلوگیری از دو برابر شدن
        splitDaysByMonth(req.startDate, req.endDate || req.startDate).forEach(function (chunk) {
          const row = ensureEmpMonthRow(data, chunk.year, chunk.month, code);
          try { rebuildLeaveTypeQtyFromRequests(data, chunk.year, chunk.month, code, row); } catch (eLt) {
            const days = leaveDaysForMonthChunk(data, req, chunk);
            const qtyName = matchQtyItemName(data, code, tname) || tname;
            if (!row.qty) row.qty = {};
            row.qty[qtyName] = days;
            if (/ازدواج/.test(tname)) {
              row.qty['مرخصی ازدواج'] = days;
              row.qty['تعداد مرخصی ازدواج'] = days;
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
    // کارکرد را مثل پرتال از نو حساب کن
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
  if (!startDate) return jsonResponse({ ok: false, error: 'bad_request', message: 'تاریخ شروع الزامی است.' }, 400);

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
    if (!pStart) return jsonResponse({ ok: false, error: 'bad_request', message: 'فرمت تاریخ نامعتبر است.' }, 400);
    let okMonth = (pStart.y === portalCal.realYear && pStart.m === portalCal.realMonth);
    if (!okMonth && portalCal.graceDays > 0 && portalCal.realDay <= portalCal.graceDays) {
      let py = portalCal.realYear, pm = portalCal.realMonth - 1;
      if (pm < 1) { pm = 12; py -= 1; }
      okMonth = (pStart.y === py && pStart.m === pm);
    }
    // مهلت ثبت بر اساس بازه‌های تعریف‌شده توسط ادمین (settings.requestWindows)
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
      let msg = 'فقط درخواست در ماه شمسی جاری (' + portalCal.realYear + '/' + portalCal.realMonth + ') مجاز است.';
      if (portalCal.graceDays > 0) msg += ' تا ' + portalCal.graceDays + ' روز اول ماه، ماه قبل هم مجاز است.';
      return jsonResponse({ ok: false, error: 'wrong_month', message: msg }, 400);
    }
    const cy = portalCal.realYear;
    const cm = portalCal.realMonth;
    // ماه هدف = ماهی که تاریخ شروع در آن مجاز شناخته شد (ماه جاری، یا ماه قبل در روزهای مهلت)
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
        // فقط اگر پایان اصلاً نیامده — ثبت یک‌روزه (از=تا) را ۳روزه نکن
        var endWasSentEmp = (typeof endDate === 'string' && endDate && endDate !== startDate);
        // اگر endDate از body آمده و پر است، حتی اگر = start باشد، گسترش نده
        // در پرتال کارمند: endDate معمولاً بعد از نرمال‌سازی = start می‌شود؛ فقط وقتی واقعاً خالی بود گسترش بده
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
      const typeAllowedNw = isLeaveTypeAllowedOnNonWork(gd.obj, empCt, typeId, typeName);
      if (!ws.countNonWorkDaysAsLeave && !typeAllowedNw) {
        const endD = endDate || startDate;
        const sp = parseJalaliYMD(startDate);
        const ep = parseJalaliYMD(endD);
        if (sp && isHolidayOrNonWork(gd.obj, sp.y, sp.m, sp.d, empCt)) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'روز شروع (' + startDate + ') تعطیل/غیرکاری است و به‌عنوان مرخصی محسوب نمی‌شود. تاریخ شروع را روی یک روز کاری بگذارید (یا این نوع مرخصی را در تنظیمات تایم‌شیت برای غیرکاری مجاز کنید).'
          }, 400);
        }
        if (ep && isHolidayOrNonWork(gd.obj, ep.y, ep.m, ep.d, empCt)) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'روز پایان (' + endD + ') تعطیل/غیرکاری است و به‌عنوان مرخصی محسوب نمی‌شود. تاریخ پایان را روی یک روز کاری بگذارید.'
          }, 400);
        }
        const daysNeeded0 = countLeaveDays({ mode: 'daily', startDate: startDate, endDate: endD, typeId: typeId, typeName: typeName }, gd.obj, empCt);
        if (daysNeeded0 <= 0) {
          return jsonResponse({
            ok: false,
            error: 'holiday_not_leave',
            message: 'در بازه انتخاب‌شده هیچ روز کاری وجود ندارد؛ مرخصی فقط روی روزهای کاری ثبت می‌شود.'
          }, 400);
        }
      }
    }

    // بررسی مانده مرخصی استحقاقی (سال جاری / ذخیره سال‌های قبل)
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
  if (!cm) cm = Number((obj.settings || {}).currentMonth) || Number((obj.settings || {}).activeMonth) || 0;
  if (!cm) { try { var _pc = (typeof getPortalCalendarNow === 'function') ? getPortalCalendarNow(obj) : null; cm = (_pc && _pc.realMonth) || 0; } catch(eCm){} }
  if (!cm) cm = 1;
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

/** جمع مرخصی استفاده‌شده سال از درخواست‌های تأییدشده + ورود داده ماهانه */
function sumUsedLeaveDaysForYear(obj, empCode, year) {
  year = Number(year) || 0;
  var code = String(empCode || '');
  var daily = 0, hourly = 0;
  // از درخواست‌های تأییدشده استحقاقی
  (obj.attendanceRequests || []).forEach(function (x) {
    if (!x || String(x.empCode) !== code) return;
    if (x.status !== 'approved') return;
    if (x.kind !== 'leave') return;
    // فقط استحقاقی (کسر از مانده) — اگر فلگ نبود و نوع استحقاقی است هم حساب کن
    var deduct = x.deductFromEntitlement;
    if (deduct === false) return;
    if (x.mode === 'daily') {
      var p1 = parseJalaliYMD(x.startDate);
      var p2 = parseJalaliYMD(x.endDate || x.startDate);
      if (!p1) return;
      // روزهای متعلق به این سال
      if (p1.y === year || (p2 && p2.y === year)) {
        try {
          daily += countLeaveDays(x, obj, null);
        } catch (e) {
          // fallback: اختلاف ساده
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
  // از ورود داده ماهانه (اگر بیشتر باشد)
  var mdDaily = 0, mdHourly = 0;
  var md = (obj && obj.monthlyData) || {};
  for (var m = 1; m <= 12; m++) {
    var key = year + '-' + m;
    var row = md[key] && md[key][code];
    if (!row) continue;
    mdDaily += Number(row.leaveDays) || 0;
    mdHourly += Number(row.hourlyLeave) || 0;
  }
  // ساعتی → روز (تقریبی ۸ ساعت کاری)
  var fromReq = Math.round((daily + hourly / 8) * 100) / 100;
  var fromMd = Math.round((mdDaily + mdHourly / 8) * 100) / 100;
  return Math.max(fromReq, fromMd);
}

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
  // همگام‌سازی used با مرخصی واقعی (تایم‌شیت / درخواست تأییدشده)
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
    // مانده = سقف قابل استفاده − مصرف
    // استخدام قبل از امسال / بدون تاریخ: سقف کامل سالانه
    // استخدام در همین سال: تناسب از تاریخ استخدام تا پایان سال
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

/** کلید یکسان‌سازی برای حذف تکراری نوع قرارداد (فاصله/خط تیره/نیم‌فاصله نادیده) */
function normContractKey(s) {
  return String(s || '')
    .replace(/[\u200c\u200d\u200e\u200f\u00a0]/g, '')
    .replace(/[\s\-_]+/g, '')
    .toLowerCase();
}

/** نام فارسی استاندارد برای شناسه‌های رایج انگلیسی */
var CONTRACT_TYPE_FA = {
  normal: 'عادی',
  daily: 'روزمزد',
  hourly: 'ساعتی',
  fixed: 'دائم',
  permanent: 'دائم',
  temporary: 'موقت',
  temp: 'موقت',
  contract: 'پیمانی',
  shift: 'شیفتی',
  parttime: 'پاره‌وقت',
  'part-time': 'پاره‌وقت',
  fulltime: 'تمام‌وقت',
  'full-time': 'تمام‌وقت',
  intern: 'کارآموزی',
  seasonal: 'فصلی'
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

/** ادغام و حذف تکراری لیست نوع قرارداد + برداشت از قرارداد کارکنان */
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
  try { mergeDedupeContractTypes(obj); } catch (eMd) {
    if (!Array.isArray(s.contractTypesList) || !s.contractTypesList.length) {
      s.contractTypesList = defaultContractTypesList();
    }
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

function parseFloatMinutesValue(v, fallback) {
  if (v == null || v === '') return fallback;
  var s = String(v).replace(/[۰-۹]/g, function (d) {
    return '0123456789'['۰۱۲۳۴۵۶۷۸۹'.indexOf(d)];
  }).replace(/[^\d.]/g, '');
  var n = parseInt(s, 10);
  if (!isFinite(n) || n < 0) return fallback;
  if (n > 480) n = 480;
  return n;
}


function forceApplyCompanyFloat(obj, minutes) {
  if (!obj) return;
  if (!obj.settings || typeof obj.settings !== 'object') obj.settings = {};
  var n = parseFloatMinutesValue(minutes, null);
  if (n == null) return;
  if (n < 0) n = 0;
  if (n > 480) n = 480;
  obj.settings.floatMinutes = n;
  obj.settings.portalFloatMinutes = n;
  obj.settings.companyFloatMinutes = n;
  ensureContractCalendars(obj);
  Object.keys(obj.settings.contractCalendars || {}).forEach(function (cid) {
    if (String(cid) === 'hourly') return;
    var c = obj.settings.contractCalendars[cid];
    if (!c || typeof c !== 'object') return;
    c.floatMinutes = n;
    if (c.daySchedules && typeof c.daySchedules === 'object') {
      Object.keys(c.daySchedules).forEach(function (dk) {
        var ds = c.daySchedules[dk];
        if (ds && typeof ds === 'object' && Object.prototype.hasOwnProperty.call(ds, 'floatMinutes')) {
          delete ds.floatMinutes;
        }
      });
    }
  });
}


function normalizeWorkSchedule(cal, globalFloat) {
  const d = defaultWorkSchedule();
  const c = cal || {};
  const hasBreak = c.hasBreak != null ? !!c.hasBreak : !!(c.breakStart && c.breakEnd && c._breakExplicit);
  const hb = c.hasBreak != null ? !!c.hasBreak : false;
  // اولویت: شناوری سراسری settings → تقویم نوع قرارداد → پیش‌فرض ۱۵
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


/** شناوری در سند جدا (float_config) تا ذخیره data آن را با ۹۰ قدیمی بازنویسی نکند */
async function storeGetFloatConfig(cfg) {
  try {
    const r = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.float_config&select=version,data',
      { headers: storeHeaders(cfg, { Accept: 'application/vnd.pgrst.object+json' }) });
    if (r.status === 406) return { version: 0, minutes: null };
    if (!r.ok) return { fail: await storeFail(r) };
    const row = await r.json();
    var minutes = null;
    if (row && row.data) {
      try {
        var o = typeof row.data === 'string' ? JSON.parse(row.data) : row.data;
        minutes = parseFloatMinutesValue(o && o.floatMinutes, null);
      } catch (e) {}
    }
    return { version: Number(row.version) || 0, minutes: minutes };
  } catch (e) {
    return { fail: { reason: 'unreachable', status: 502 } };
  }
}

async function storePutFloatConfig(cfg, minutes, whoName) {
  var n = parseFloatMinutesValue(minutes, null);
  if (n == null) return { fail: { reason: 'bad_float', status: 400 } };
  if (n < 0) n = 0;
  if (n > 480) n = 480;
  const payloadObj = { floatMinutes: n, updatedAt: new Date().toISOString() };
  const dataStr = JSON.stringify(payloadObj);
  const who = whoName || 'float';

  // اول: upsert مستقیم (بدون اتکا به version=0)
  try {
    const up = await fetch(cfg.url + '/rest/v1/app_docs?on_conflict=name', {
      method: 'POST',
      headers: storeHeaders(cfg, {
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=representation'
      }),
      body: JSON.stringify([{
        name: 'float_config',
        version: 1,
        data: dataStr,
        updated_by: who,
        updated_at: new Date().toISOString()
      }])
    });
    if (up.ok) {
      return { ok: true, minutes: n, version: 1, method: 'upsert' };
    }
  } catch (eUp) {}

  for (var attempt = 0; attempt < 6; attempt++) {
    const cur = await storeGetFloatConfig(cfg);
    if (cur.fail && cur.fail.status !== 406 && cur.fail.reason !== 'unreachable') {
      // ادامه بده برای insert
    }
    var base = (cur && !cur.fail && cur.version) ? cur.version : 0;
    if (!base) {
      const ins = await fetch(cfg.url + '/rest/v1/app_docs', {
        method: 'POST',
        headers: storeHeaders(cfg, { 'Content-Type': 'application/json', Prefer: 'return=representation' }),
        body: JSON.stringify([{
          name: 'float_config',
          version: 1,
          data: dataStr,
          updated_by: who,
          updated_at: new Date().toISOString()
        }])
      });
      if (ins.ok) return { ok: true, minutes: n, version: 1, method: 'insert' };
      // اگر تکراری است، از PATCH استفاده کن
    }
    const r = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.float_config&version=eq.' + base + '&select=version', {
      method: 'PATCH',
      headers: storeHeaders(cfg, { 'Content-Type': 'application/json', Prefer: 'return=representation' }),
      body: JSON.stringify({
        version: base + 1,
        updated_by: who,
        updated_at: new Date().toISOString(),
        data: dataStr
      })
    });
    if (!r.ok) continue;
    const rows = await r.json();
    if (Array.isArray(rows) && rows.length === 1) return { ok: true, minutes: n, version: base + 1, method: 'patch' };
    // بدون شرط version
    const r2 = await fetch(cfg.url + '/rest/v1/app_docs?name=eq.float_config', {
      method: 'PATCH',
      headers: storeHeaders(cfg, { 'Content-Type': 'application/json', Prefer: 'return=representation' }),
      body: JSON.stringify({
        version: (base || 0) + 1,
        updated_by: who,
        updated_at: new Date().toISOString(),
        data: dataStr
      })
    });
    if (r2.ok) {
      const rows2 = await r2.json();
      if (Array.isArray(rows2) && rows2.length >= 1) return { ok: true, minutes: n, version: (base || 0) + 1, method: 'patch-any' };
    }
  }
  return { fail: { reason: 'conflict', status: 409, message: 'ذخیره شناوری ناموفق' } };
}

async function resolveFloatMinutesAuthoritative(cfg, obj) {
  // اولویت: settings.portalFloatMinutes / floatMinutes در سند data
  var fromData = resolveCompanyFloatMinutes(obj, null);
  if (fromData != null) return fromData;
  try {
    const fc = await storeGetFloatConfig(cfg);
    if (!fc.fail && fc.minutes != null) return fc.minutes;
  } catch (e) {}
  return 15;
}

function resolveCompanyFloatMinutes(obj, calHint) {
  const s = (obj && obj.settings) || {};
  // اولویت مطلق: آخرین مقدار ذخیره‌شده سراسری (portal سپس settings)
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
  // شناوری شرکت‌محور — نه قفل‌شده روی ۱۵ داخل یک نوع قدیمی
  const companyFloat = resolveCompanyFloatMinutes(obj, cal);
  const sched = normalizeWorkSchedule(cal, companyFloat);
  // ساعتی: بازه کاری کل شبانه‌روز (حضور هر ساعتی معتبر است)
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

/** برنامه موظفی یک روز خاص — در صورت نبود، برنامه پیش‌فرض نوع قرارداد */
function getDayWorkSchedule(cal, y, m, d) {
  // cal ممکن است خروجی getContractCalendar باشد (floatMinutes از قبل ست شده)
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
  // شناوری روزانه را نادیده بگیر — همیشه شناوری نوع قرارداد / سراسری (تا ۱۵ قفل نماند)
  // if (over.floatMinutes != null && over.floatMinutes !== '') out.floatMinutes = ...
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
  const _gFloat = (cal && cal._globalFloatMinutes != null) ? cal._globalFloatMinutes : (cal && cal.floatMinutes);
  if (opts.daySchedule && typeof opts.daySchedule === 'object') {
    sched = Object.assign({}, normalizeWorkSchedule(cal, _gFloat), opts.daySchedule);
    // شناوری روز را از daySchedule نپذیر (قفل ۱۵)
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
  // شناوری: برنامه روز → تقویم نوع قرارداد → سراسری (هرگز به‌خاطر daySchedule روی ۱۵ قفل نشود)
  const floatM = isHourly ? 0 : Math.max(0,
    parseFloatMinutesValue(sched.floatMinutes, null) != null ? parseFloatMinutesValue(sched.floatMinutes, null)
      : (parseFloatMinutesValue(cal && cal.floatMinutes, null) != null ? parseFloatMinutesValue(cal && cal.floatMinutes, null)
        : (parseFloatMinutesValue(cal && cal._globalFloatMinutes, null) != null ? parseFloatMinutesValue(cal && cal._globalFloatMinutes, null) : 0))
  );
  const compensate = isHourly ? false : (!!sched.floatCompensate || !!opts.floatCompensate || !!(cal && cal.floatCompensate));
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
   * شناوری (شروع 06:45، پایان 15:30، float مثلاً ۱۵د):
   * 1) ورود 06:48 / خروج 15:30 → کسری صبح 3د (داخل شناوری؛ بدون ماندن = بدون جبران)
   * 2) ورود 06:45 / خروج 15:20 → کسری عصر 10د
   * 3) ورود 06:50 / خروج 15:20 → کسری صبح 5د + عصر 10د
   * 4) ورود 07:01 / خروج 15:30 → خارج شناوری؛ کسری صبح کامل 16د (بدون جبران)
   * 5) ورود 07:01 / خروج 15:20 → کسری صبح 16د + عصر 10د
   * 6) ورود 07:08 / خروج 15:40 → ماندن بعد از پایان تا سقف float روی کسری صبح می‌نشیند؛
   *    مثال: ماندن 10د → 10د جبران، باقی 13د مرخصی؛ ماندن 20د → 15د جبران + 5د اضافه‌کار، باقی 8د مرخصی
   *    تیک floatCompensate: جبران بدون سقف float (کل تأخیر در حد ماندن)
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

  // جبران با ماندن بعد از end:
  // - همیشه تا سقف float دقیقه (حتی اگر ورود بعد از مرز شناوری باشد) — مورد 6
  // - با تیک floatCompensate: تا کل تأخیر (بدون سقف float)
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

  // اقماری / همه روزهای هفته کاری: در تعطیل رسمی تا سقف موظفی = کارکرد، فقط مازاد = اضافه‌کار
  const allWeekWork = Array.isArray(cal && cal.workWeekDays) && cal.workWeekDays.length >= 7;
  if (isHoliday && present > 0 && !(dayMeta && dayMeta.conditional)) {
    if (allWeekWork && official > 0) {
      // مثل روز عادی: کارکرد تا موظفی، اضافه‌کار فقط بعد از پایان شیفت (منهای شب)
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
      // تعطیل رسمی/هفته (قرارداد عادی): تمام حضور = اضافه‌کار (شب‌کاری جدا)
      ot = Math.max(0, present - nightMin);
      workPresent = 0;
      delay = 0;
      earlyLeave = 0;
      compensated = 0;
    }
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
    // تعطیل رسمی/هفته (نه شرایطی)
    // اقماری (همه روز کاری): کارکرد تا موظفی حفظ شود؛ ot فقط بعد از پایان شیفت (بالا محاسبه شده)
    if (allWeekWork && official > 0) {
      // ot و workPresent از بلوک اول حفظ می‌شوند؛ بازنویسی نشود
    } else {
      // قرارداد عادی: کل حضور غیرشب = اضافه‌کار
      ot = Math.max(0, present - nightMin);
      workPresent = 0;
    }
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
  // اقماری (همه روز کاری): تعطیل رسمی هم روز موظفی است → بدون حضور/پوشش = غیبت
  // فقط تعطیل شرایطی (یا قرارداد غیر اقماری) shortfall را صفر می‌کند
  const aqmariDutyHoliday = allWeekWork && official > 0 && isHoliday
    && !(dayMeta && (dayMeta.conditional || dayMeta.type === 'conditional'));
  if (holidayFull && !aqmariDutyHoliday) {
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
  // اقماری در تعطیل: workPresent از قبل تا موظفی پر شده — نمایش شود
  let displayWorkMin = workPresent + ((isHoliday && !(allWeekWork && official > 0)) ? 0 : covered);
  if ((!isHoliday || (allWeekWork && official > 0)) && !opts.unpaidLeave) {
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
  // فقط تقویم همان نوع قرارداد کارمند — نه تقویم انواع دیگر
  // (قبلاً اگر هر نوعی پنجشنبه/جمعه تعطیل بود، برای همه غیبت صفر می‌شد)
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

function isRestOrNonLeaveColumnType(obj, req) {
  if (!req) return false;
  function hasRestWord(s) {
    s = String(s || '');
    // استحقاقی / استعلاجی / بدون‌حقوق هرگز «رست» نیست
    if (s.indexOf('استحقاق') >= 0) return false;
    if (s.indexOf('استعلاج') >= 0) return false;
    if (s.indexOf('بدون حقوق') >= 0 || s.indexOf('بدون‌حقوق') >= 0) return false;
    return s.indexOf('رست') >= 0 || /\brest\b/i.test(s);
  }
  // کسر از استحقاق → ستون مرخصی
  if (req.deductFromEntitlement === true) return false;
  const name = String(req.typeName || req.type || req.name || '');
  const id = String(req.typeId || '').toLowerCase();
  if (name.indexOf('استحقاق') >= 0 || id.indexOf('leave_annual') >= 0 || id === 'annual') return false;
  if (hasRestWord(name) || hasRestWord(id)) return true;
  try {
    const types = [].concat((obj && obj.settings && obj.settings.attendanceTypes) || [], (obj && obj.attendanceTypes) || []);
    // فقط تطبیق id یا نام دقیق — نباید «هر نوع رست» در لیست باعث match شود
    const t = types.find(function (x) {
      if (!x) return false;
      if (req.typeId && String(x.id) === String(req.typeId)) return true;
      if (name && String(x.name || '') === name) return true;
      return false;
    });
    if (t) {
      const tn = String(t.name || '');
      // استحقاقی / کسر از مانده هرگز رست نیست
      if (tn.indexOf('استحقاق') >= 0 || tn.indexOf('مرخص') >= 0 || t.deductFromEntitlement === true) return false;
      // فقط نام/شناسه که صریحاً «رست» دارد
      if (hasRestWord(t.name) || hasRestWord(t.id)) return true;
      // excludeFromLeaveDays به‌تنهایی یعنی «رست» نیست — دیگر رست حساب نکن
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
  // استحقاقی → ستون leaveDays
  if (nm.indexOf('استحقاق') >= 0) return false;
  if (req.deductFromEntitlement === true) return false;
  if (tdef && tdef.deductFromEntitlement === true) return false;
  if (tid.indexOf('leave_annual') >= 0 || tid === 'annual') return false;
  if (tdef && /leave_annual|annual/i.test(String(tdef.id || ''))) return false;
  // غیر استحقاقی → ستون qty جدا (ازدواج، تولد، فوت، …)
  if (req.deductFromEntitlement === false) return true;
  if (tdef && tdef.deductFromEntitlement === false) return true;
  if (/ازدواج|تولد|فوت|بدون\s*حقوق|استعلاج|خاص|marriage|birth|death|unpaid|sick/i.test(nm)) return true;
  if (/leave_marriage|leave_birth|leave_death|leave_unpaid|leave_special|leave_sick/i.test(tid)) return true;
  if (isUnpaidLeaveRequest(obj, req)) return true;
  if (typeof isRestOrNonLeaveColumnType === 'function' && isRestOrNonLeaveColumnType(obj, req)) return true;
  return false;
}
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

function empOtCeilingHours(emp, settings) {
  // سقف فردی > پیش‌فرض تنظیمات > ۰
  // ۰ یعنی هیچ اضافه‌کاری تأیید نمی‌شود (نه «بدون سقف»)
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
  return 0; // پیش‌فرض: بدون اضافه‌کار
}



/** نرمال‌سازی ارقام و یافتن سلول تردد یک روز — یکسان برای پانچ/کارکرد/غیبت */
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


/** تعداد روزهای کاری تقویم ماه: موظفی منهای پنجشنبه/جمعه و تعطیل رسمی/شرایطی کامل */
function countFunctionalDaysInMonth(obj, year, month, contractType) {
  year = Number(year); month = Number(month);
  const dim = daysInJalaliMonth(year, month);
  const ct = contractType || 'normal';
  let n = 0;
  for (let d = 1; d <= dim; d++) {
    try {
      if (!isHolidayOrNonWork(obj, year, month, d, ct)) n++;
    } catch (e) {
      // در خطا روز را موظفی فرض نکن
    }
  }
  return n > 0 ? n : 0;
}

function recountEmpMonthWorkDays(obj, year, month, code) {
  /* کارکرد ماه:
     پایه = روزهای تقویمی بازه استخدام در ماه.
     هر روز کاری با حضور یا مرخصی یا مأموریت → کارکرد (حتی بدون تردد).
     فقط روز کاری کاملاً خالی → غیبت.
     مرخصی بدون حقوق → کارکرد نیست.
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
      if (/مرخص|مأمور|مامور|leave|mission/i.test(note) && !/بدون\s*حقوق|unpaid/i.test(note)) markDay(d);
    } catch (eN) {}
  }

  let leaveDaysFromReq = 0;
  let missionDaysFromReq = 0;
  (obj.attendanceRequests || []).forEach(function (req) {
    if (!req) return;
    if (String(req.empCode) !== String(code)) return;
    const st = String(req.status || '').toLowerCase();
    // تأیید شده / سطح ۱ / نهایی
    if (!(st === 'approved' || st === 'approved_l1' || st === 'final' || st === 'تایید' || st === 'تأیید' || st === 'تایید شده' || st === 'تأیید شده')) return;
    try {
      // فقط مرخصی بدون حقوق از کل حلقه حذف می‌شود؛ رست فقط از ستون روز مرخصی حذف می‌شود
      if (typeof isUnpaidLeaveRequest === 'function' && isUnpaidLeaveRequest(obj, req)) return;
    } catch (eU) {}
    const kind = String(req.kind || '');
    const tn = String(req.typeName || req.type || '');
    const isLeave = kind === 'leave' || kind === 'مرخصی' || /مرخص|leave/i.test(tn);
    const isMission = kind === 'mission' || kind === 'مأموریت' || kind === 'ماموریت' || /مأمور|مامور|mission/i.test(tn);
    const isRest = kind === 'rest' || kind === 'work_rest' || kind === 'رست' || (tn.indexOf('رست') >= 0 && !/استحقاق|استعلاج|مرخص/.test(tn));
    if (!isLeave && !isMission && !isRest) return;
    const mode = String(req.mode || 'daily');
    if (mode === 'hourly') {
      // ساعتی: همان روز شروع را فعالیت بدان
      const p = parseJalaliYMD(req.startDate);
      if (p && p.y === year && p.m === month) markDay(p.d);
      return;
    }
    const keys = (typeof listDayKeys === 'function')
      ? listDayKeys(req.startDate, req.endDate || req.startDate)
      : [];
    keys.forEach(function (k) {
      const parts = String(k).split(/[-\/]/);
      if (parts.length < 3) return;
      const yy = Number(parts[0]), mm = Number(parts[1]), dd = Number(parts[2]);
      if (yy !== year || mm !== month) return;
      markDay(dd);
    });
    try {
      if (isLeave) {
        var skipCol = false;
        try { skipCol = (typeof shouldSkipLeaveDaysColumn === 'function' && shouldSkipLeaveDaysColumn(obj, req)); } catch (eS) {}
        if (!skipCol) {
          leaveDaysFromReq += (typeof countWorkingDaysInMonth === 'function')
            ? countWorkingDaysInMonth(req.startDate, req.endDate || req.startDate, year, month, obj, ct)
            : keys.length;
        }
      }
      if (isMission) {
        missionDaysFromReq += (typeof countAllDaysInMonth === 'function')
          ? countAllDaysInMonth(req.startDate, req.endDate || req.startDate, year, month)
          : keys.length;
      }
    } catch (eC) {}
  });

  // کارکرد = روزهای تقویم ماه (در بازه استخدام) − فقط غیبت
  // پنجشنبه/جمعه و تعطیل هم جزو کارکرد هستند؛ فقط روز موظفیِ بدون حضور/مرخصی/مأموریت = غیبت
  const baseDays = toD - fromD + 1;
  let absence = 0;
  for (let d = fromD; d <= toD; d++) {
    let nonWork = isHolidayOrNonWork(obj, year, month, d, ct);
    if (allWeekWorkR && nonWork) {
      const metaR = getDayMeta(obj, year, month, d, ct);
      if (!(metaR && (metaR.conditional || metaR.type === 'conditional'))) {
        nonWork = false;
      }
    }
    // تعطیل هفتگی/رسمی غیبت نیست
    if (nonWork) continue;
    if (!dayActivity[d]) absence++;
  }
  const wd = Math.max(0, baseDays - absence);
  return Math.max(0, Math.round(wd * 100) / 100);
}

/** تعداد روزهای غیبت ماه (روز کاری بدون حضور/مرخصی/مأموریت) */
function countEmpMonthAbsenceDays(obj, year, month, code) {
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
    try {
      const lab = String(punch.leaveDaily || punch.missionDaily || punch.note || punch.status || '');
      if (lab && !/غایب|غیبت|absent/i.test(lab)) markDay(d);
    } catch (eL) {}
  }
  (obj.attendanceRequests || []).forEach(function (req) {
    if (!req) return;
    if (String(req.empCode) !== String(code)) return;
    const st = String(req.status || '').toLowerCase();
    if (!(st === 'approved' || st === 'approved_l1' || st === 'final' || st === 'تایید' || st === 'تأیید' || st === 'تایید شده' || st === 'تأیید شده')) return;
    try {
      if (typeof isUnpaidLeaveRequest === 'function' && isUnpaidLeaveRequest(obj, req)) return;
    } catch (eU) {}
    const kind = String(req.kind || '');
    const tn = String(req.typeName || req.type || '');
    const isLeave = kind === 'leave' || kind === 'مرخصی' || /مرخص|leave/i.test(tn);
    const isMission = kind === 'mission' || kind === 'مأموریت' || kind === 'ماموریت' || /مأمور|مامور|mission/i.test(tn);
    const isRest = kind === 'rest' || kind === 'work_rest' || kind === 'رست' || (tn.indexOf('رست') >= 0 && !/استحقاق|استعلاج|مرخص/.test(tn));
    if (!isLeave && !isMission && !isRest) return;
    const mode = String(req.mode || 'daily');
    if (mode === 'hourly') {
      const p = parseJalaliYMD(req.startDate);
      if (p && p.y === year && p.m === month) markDay(p.d);
      return;
    }
    const keys = (typeof listDayKeys === 'function')
      ? listDayKeys(req.startDate, req.endDate || req.startDate)
      : [];
    keys.forEach(function (k) {
      const parts = String(k).split(/[-\/]/);
      if (parts.length < 3) return;
      const yy = Number(parts[0]), mm = Number(parts[1]), dd = Number(parts[2]);
      if (yy !== year || mm !== month) return;
      markDay(dd);
    });
  });
  let absence = 0;
  for (let d = fromD; d <= toD; d++) {
    let nonWork = isHolidayOrNonWork(obj, year, month, d, ct);
    if (allWeekWorkR && nonWork) {
      const metaR = getDayMeta(obj, year, month, d, ct);
      if (!(metaR && (metaR.conditional || metaR.type === 'conditional'))) {
        nonWork = false;
      }
    }
    if (nonWork) continue;
    if (!dayActivity[d]) absence++;
  }
  return Math.max(0, absence);
}

/** از آیتم‌های «تعداد خالص» (qty_flat) به اندازه روز غیبت کسر کن — بدون دست زدن به تیک ثابت/مرخصی/رست */

/** همه منابع «ثابت ماهانه / ستون عددی ورود داده» — آیتم جدید هم از اینجا خوانده می‌شود */
function listMonthlyConstantSources(obj) {
  // کش نباید همراه داده ذخیره شود (وگرنه تیک‌های جدید «ثابت‌های ماهانه» نادیده گرفته می‌شود)
  try { if (obj && Object.prototype.propertyIsEnumerable.call(obj, '__pspConstSources')) delete obj.__pspConstSources; } catch (ePg) {}
  if (obj && obj.__pspConstSources && Array.isArray(obj.__pspConstSources)) {
    return obj.__pspConstSources;
  }
  var out = [];
  var seen = [];
  function add(arr) {
    if (!arr || !arr.length) return;
    // جلوگیری از دوبار اضافه کردن همان آرایه
    if (seen.indexOf(arr) >= 0) return;
    seen.push(arr);
    var lim = Math.min(arr.length, 300);
    for (var i = 0; i < lim; i++) {
      if (arr[i] && typeof arr[i] === 'object') out.push(arr[i]);
    }
  }
  try {
    add(obj && obj.monthlyConstants);
    add(obj && obj.fixedMonthlyItems);
    add(obj && obj.constantItems);
    add(obj && obj.customItemTemplates);
    add(obj && obj.payItems);
    add(obj && obj.dataEntryColumns);
    add(obj && obj.monthlyQtyItems);
    var s = (obj && obj.settings) || {};
    add(s.monthlyVars);
    add(s.monthlyConstants);
    add(s.fixedMonthlyItems);
    add(s.monthlyFixedItems);
    add(s.customItemTemplates);
    add(s.payItems);
    add(s.dataEntryColumns);
    add(s.monthlyQtyItems);
    add(s.qtyItems);
    add(s.countItems);
    add(s.fixedCountItems);
    add(s.systemQtyItems);
    add(s.entryQtyItems);
    // کلیدهای صریح UI ثابت ماهانه
    add(s.monthlyFixed);
    add(s.fixedItems);
    add(s.entryColumns);
    try {
      var sks = Object.keys(s);
      for (var si = 0; si < sks.length && si < 20; si++) {
        var v = s[sks[si]];
        if (!Array.isArray(v) || !v.length || !v[0] || typeof v[0] !== 'object') continue;
        if (v[0].name == null && v[0].title == null && v[0].label == null) continue;
        if (v.length > 300) continue;
        add(v);
      }
    } catch (e0) {}
  } catch (e) {}
  if (obj && typeof obj === 'object') {
    try { Object.defineProperty(obj, '__pspConstSources', { value: out, enumerable: false, writable: true, configurable: true }); } catch (eDp) {}
  }
  return out;
}

function monthlyConstantDeductsFromPure(item) {
  if (!item || typeof item !== 'object') return false;
  function truthy(v) {
    if (v === true || v === 1 || v === '1' || v === 'true' || v === 'yes' || v === 'on' || v === 'checked') return true;
    if (typeof v === 'string') {
      var s = v.replace(/\s+/g, '');
      if (s === 'بله' || s === 'بلی' || s === 'آری' || s === 'دارد' || s === '✓' || s === '✔' || s === 'کسر') return true;
      if (s.indexOf('کسر') >= 0 && s.indexOf('خالص') >= 0) return true;
    }
    return false;
  }
  // ثابت‌های ماهانهٔ ساخت‌شده در برنامه (settings.monthlyVars): تیک «کسر از تعداد خالص» = deductQtyFlat
  // (اگر تعریف نشده بود، مثل کلاینت: deductCounts)
  if (item.deductQtyFlat !== undefined) return truthy(item.deductQtyFlat);
  if (item.deductCounts !== undefined && /^mv_/.test(String(item.id || ''))) return truthy(item.deductCounts);
  var keys = [
    'deductFromNetCount', 'deductFromPure', 'deductFromNet', 'deductFromFunctional',
    'deductFromQtyFlat', 'qtyFlatDeduct', 'deductPure', 'pureCountDeduct', 'deductKhales',
    'ksrAzKhales', 'ksr_az_khales', 'fromNetCount', 'affectPureCount', 'affectsQtyFlat',
    'deductFromPureCount', 'netCountDeduct', 'khalesDeduct',
    'effectOnPureCount', 'pureCountEffect', 'deductPureCount',
    'effectQtyFlat', 'qtyFlatEffect', 'deductFromKhales',
    'pureEffect', 'khalesEffect', 'netCountEffect', 'qtyFlatEffectOnPure'
  ];
  for (var i = 0; i < keys.length; i++) if (truthy(item[keys[i]])) return true;
  try {
    var ex = item.effects || item.effect || item.flags || item.options || {};
    if (truthy(ex.pureCount) || truthy(ex.qtyFlat) || truthy(ex.deductFromNetCount) || truthy(ex.khales)) return true;
    if (truthy(ex.effectOnPureCount) || truthy(ex.deductFromPureCount)) return true;
    if (String(ex.pureCount || ex.effectOnPureCount || '').indexOf('کسر') >= 0) return true;
  } catch (e1) {}
  try {
    if (truthy(item['کسر از تعداد خالص']) || truthy(item['اثر روی تعداد خالص'])) return true;
    if (truthy(item['اثر روی خالص']) || truthy(item['کسر از خالص'])) return true;
  } catch (e2) {}
  // اسکن همه کلیدها: اگر نام کلید به خالص/کسر اشاره دارد و مقدار truthy است
  try {
    var ik = Object.keys(item);
    for (var ii = 0; ii < ik.length; ii++) {
      var kn = String(ik[ii] || '');
      var knLow = kn.toLowerCase();
      if ((/خالص/.test(kn) || /pure|khales|qtyflat|qty_flat/.test(knLow)) &&
          (/کسر|deduct|effect|اثر|from/.test(kn) || /کسر|deduct|effect|اثر|from/.test(knLow))) {
        if (truthy(item[ik[ii]])) return true;
      }
      // مقدار رشته‌ای که خودش «کسر از تعداد خالص» است
      var vv = item[ik[ii]];
      if (typeof vv === 'string' && /کسر/.test(vv) && /خالص/.test(vv)) return true;
    }
  } catch (e3) {}
  return false;
}

/** آیا این نوع در ثابت ماهانه / تعریف نوع، تیک «کسر از تعداد خالص» دارد؟ */
function typeDeductsFromNetCount(obj, typeId, typeName) {
  function truthyFlag(v) {
    if (v === true || v === 1 || v === '1' || v === 'true' || v === 'yes' || v === 'on') return true;
    if (typeof v === 'string') {
      var s = v.replace(/\s+/g, '');
      if (s === 'بله' || s === 'بلی' || s === 'آری' || s === 'دارد' || s === '✓' || s === '✔') return true;
    }
    return false;
  }
  function hasDeductFlag(o) {
    if (!o || typeof o !== 'object') return false;
    try {
      if (typeof monthlyConstantDeductsFromPure === 'function' && monthlyConstantDeductsFromPure(o)) return true;
    } catch (eM) {}
    var keys = [
      'deductFromNetCount', 'deductFromPure', 'deductFromNet', 'deductFromFunctional',
      'deductFromQtyFlat', 'qtyFlatDeduct', 'deductPure', 'pureCountDeduct', 'deductKhales',
      'ksrAzKhales', 'ksr_az_khales', 'fromNetCount', 'affectPureCount', 'affectsQtyFlat',
      'deductFromPureCount', 'netCountDeduct', 'khalesDeduct',
      'effectOnPureCount', 'pureCountEffect', 'deductPureCount', 'pureEffect'
    ];
    for (var ki = 0; ki < keys.length; ki++) {
      if (truthyFlag(o[keys[ki]])) return true;
    }
    try {
      var pk = ['کسر از تعداد خالص', 'کسر از خالص', 'از تعداد خالص', 'اثر روی تعداد خالص', 'اثر روی خالص'];
      for (var pi = 0; pi < pk.length; pi++) {
        if (truthyFlag(o[pk[pi]])) return true;
      }
    } catch (eP) {}
    return false;
  }
  function nameMatch(a, b) {
    function norm(s) {
      return String(s || '')
        .replace(/[\u200c\u200d\u200e\u200f\u00a0]/g, ' ')
        .replace(/ي/g, 'ی').replace(/ك/g, 'ک')
        .replace(/\s+/g, ' ').trim();
    }
    a = norm(a); b = norm(b);
    if (!a || !b) return false;
    if (a === b) return true;
    var ab = a.replace(/^تعداد\s+/, '').trim();
    var bb = b.replace(/^تعداد\s+/, '').trim();
    if (ab === bb) return true;
    // تطبیق جزئی فقط اگر یکی زیرمجموعه معنی‌دار دیگری باشد (حداقل ۳ کاراکتر)
    if (ab.length >= 3 && bb.length >= 3) {
      if (ab.indexOf(bb) >= 0 || bb.indexOf(ab) >= 0) return true;
    }
    // نام‌های رایج معادل
    var aliases = {
      'مرخصی استحقاقی روزانه': ['مرخصی روزانه', 'استحقاقی روزانه', 'مرخصی استحقاقی', 'مرخصی'],
      'رست کاری': ['رست', 'work rest', 'work_rest'],
      'جاب خدمات فنی': ['جاب', 'خدمات فنی', 'جاب فنی']
    };
    function listFor(x) {
      var out = [x];
      Object.keys(aliases).forEach(function (k) {
        if (x === k || aliases[k].indexOf(x) >= 0) {
          out.push(k);
          aliases[k].forEach(function (v) { out.push(v); });
        }
      });
      return out;
    }
    var la = listFor(ab), lb = listFor(bb);
    for (var i = 0; i < la.length; i++) {
      for (var j = 0; j < lb.length; j++) {
        if (la[i] === lb[j]) return true;
      }
    }
    return false;
  }
  try {
    var tid = String(typeId || '');
    var tn = String(typeName || '');
    if (!tid && !tn) return false;

    // لیست انواع مرخصی/حضور
    var types = [].concat(
      (obj && obj.attendanceTypes) || [],
      (obj && obj.settings && obj.settings.attendanceTypes) || [],
      (obj && obj.leaveTypes) || [],
      (obj && obj.settings && obj.settings.leaveTypes) || []
    );
    for (var i = 0; i < types.length; i++) {
      var t = types[i];
      if (!t) continue;
      var match = (tid && String(t.id) === tid) || (tn && nameMatch(t.name, tn));
      if (!match) continue;
      if (hasDeductFlag(t)) return true;
    }
    // ثابت‌های ماهانه (تیک UI) — هر آیتم جدید هم اینجا دیده می‌شود
    try {
      var mc = listMonthlyConstantSources(obj);
      for (var j = 0; j < mc.length; j++) {
        var c = mc[j];
        if (!c) continue;
        if (!monthlyConstantDeductsFromPure(c) && !hasDeductFlag(c)) continue;
        if (tid && (String(c.typeId || '') === tid || String(c.id || '') === tid || String(c.attendanceTypeId || '') === tid)) return true;
        if (tn && (nameMatch(c.name, tn) || nameMatch(c.typeName, tn) || nameMatch(c.label, tn) || nameMatch(c.title, tn))) return true;
      }
    } catch (eMC) {}

    // ثابت‌های ماهانه + قالب آیتم‌ها (منبع اصلی تیک در UI)
    var consts = [].concat(
      (obj && obj.monthlyConstants) || [],
      (obj && obj.settings && obj.settings.monthlyConstants) || [],
      (obj && obj.fixedMonthlyItems) || [],
      (obj && obj.settings && obj.settings.fixedMonthlyItems) || [],
      (obj && obj.settings && obj.settings.monthlyFixedItems) || [],
      (obj && obj.constantItems) || [],
      (obj && obj.customItemTemplates) || [],
      (obj && obj.settings && obj.settings.customItemTemplates) || [],
      (obj && obj.payItems) || [],
      (obj && obj.settings && obj.settings.payItems) || [],
      (obj && obj.allowances) || [],
      (obj && obj.settings && obj.settings.allowances) || []
    );
    // اگر settings خودش آرایه‌ای با نام‌های مرتبط دارد
    try {
      var s = obj && obj.settings;
      if (s && typeof s === 'object') {
        Object.keys(s).forEach(function (sk) {
          var v = s[sk];
          if (Array.isArray(v) && v.length && v[0] && typeof v[0] === 'object') {
            // فقط آرایه‌هایی که شبیه آیتم/نوع هستند
            if (v[0].name != null || v[0].typeName != null || v[0].id != null) {
              consts = consts.concat(v);
            }
          }
        });
      }
    } catch (eS) {}

    for (var j = 0; j < consts.length; j++) {
      var c = consts[j];
      if (!c) continue;
      if (!hasDeductFlag(c)) continue;
      if (tid && (String(c.typeId || '') === tid || String(c.id || '') === tid || String(c.attendanceTypeId || '') === tid)) return true;
      if (tn && (nameMatch(c.name, tn) || nameMatch(c.typeName, tn) || nameMatch(c.label, tn) || nameMatch(c.title, tn))) return true;
    }

    // لیست صریح شناسه/نام در settings
    try {
      var lists = [].concat(
        (obj && obj.settings && obj.settings.pureCountDeductTypeIds) || [],
        (obj && obj.settings && obj.settings.qtyFlatDeductTypes) || [],
        (obj && obj.settings && obj.settings.deductFromNetCountTypes) || []
      );
      for (var li = 0; li < lists.length; li++) {
        var item = lists[li];
        if (tid && String(item) === tid) return true;
        if (tn && nameMatch(String(item), tn)) return true;
      }
    } catch (eL) {}
  } catch (e) {}
  return false;
}

/**
 * تعداد روز مشمول «تعداد خالص» (ناهار و …):
 * اول روزهای پانچ + پوشش بدون‌تیک را نگه می‌دارد؛
 * روزهای فقط با نوع تیک‌دار و روز خالی (غیبت) ناهار نمی‌گیرند.
 * سقف = کارکرد خالص ماه.
 */
function countQtyFlatEarnDays(obj, year, month, code) {
  year = Number(year); month = Number(month);
  var emp = ((obj.employees || []).find(function (e) { return String(e.code) === String(code); })) || null;
  var ct = (emp && emp.contractType) || 'normal';
  var dim = daysInJalaliMonth(year, month);
  var fromD = 1, toD = dim;
  try {
    var hire = parseJalaliYMD(emp && emp.hireDate);
    if (hire) {
      if (hire.y > year || (hire.y === year && hire.m > month)) return 0;
      if (hire.y === year && hire.m === month) fromD = Math.max(1, Math.min(dim, hire.d || 1));
    }
    var end = parseJalaliYMD(emp && emp.endDate);
    if (end) {
      if (end.y < year || (end.y === year && end.m < month)) return 0;
      if (end.y === year && end.m === month) toD = Math.max(1, Math.min(dim, end.d || dim));
    }
  } catch (eH) {}
  if (toD < fromD) return 0;

  function approved(st) {
    st = String(st || '').toLowerCase();
    return st === 'approved' || st === 'approved_l1' || st === 'final' ||
      st === 'تایید' || st === 'تأیید' || st === 'تایید شده' || st === 'تأیید شده' ||
      st === 'accept' || st === 'ok' || st === 'done';
  }

  // dayFlags[d] = { punch, unticked, ticked }
  var dayFlags = {};
  function flag(d, key) {
    d = Number(d);
    if (d < fromD || d > toD) return;
    if (!dayFlags[d]) dayFlags[d] = { punch: false, unticked: false, ticked: false };
    dayFlags[d][key] = true;
  }

  var store = ((obj.dailyAttendance || {})[String(code)]) || ((obj.dailyAttendance || {})[code]) || {};

  // پانچ / تردد
  for (var d = fromD; d <= toD; d++) {
    try {
      var cell = (typeof lookupPunchCell === 'function') ? lookupPunchCell(store, year, month, d) : null;
      if (cell && typeof cellHasAnyPunch === 'function' && cellHasAnyPunch(cell)) flag(d, 'punch');
      // برچسب سلول
      if (cell) {
        var labs = [cell.leaveDaily, cell.missionDaily, cell.restDaily, cell.leave, cell.mission, cell.note];
        for (var li = 0; li < labs.length; li++) {
          var lab = String(labs[li] || '').trim();
          if (!lab || /غایب|غیبت|absent/i.test(lab)) continue;
          if (typeDeductsFromNetCount(obj, '', lab)) flag(d, 'ticked');
          else flag(d, 'unticked');
        }
      }
    } catch (eP) {}
  }

  // درخواست‌های تأییدشده
  try {
    (obj.attendanceRequests || []).forEach(function (x) {
      if (!x || String(x.empCode) !== String(code)) return;
      if (!approved(x.status)) return;
      if (x.mode === 'hourly') return;
      var tn = String(x.typeName || x.type || x.name || '');
      var flagged = !!(x.deductFromNetCount || x.deductFromPure || x.deductFromNet || x.ksrAzKhales);
      if (!flagged) flagged = typeDeductsFromNetCount(obj, x.typeId, tn);
      var keys = [];
      try {
        if (typeof listDayKeys === 'function') keys = listDayKeys(x.startDate, x.endDate || x.startDate) || [];
      } catch (eK) { keys = []; }
      keys.forEach(function (dk) {
        var parts = String(dk).split(/[-/]/);
        if (parts.length < 3) return;
        if (Number(parts[0]) !== year || Number(parts[1]) !== month) return;
        var dd = Number(parts[2]);
        if (flagged) flag(dd, 'ticked');
        else flag(dd, 'unticked');
      });
    });
  } catch (eR) {}

  var earn = 0;
  var abs = 0;
  var tickedOnly = 0;
  for (var d2 = fromD; d2 <= toD; d2++) {
    // فقط روزهای موظفی (کاری) در سقف تعداد خالص
    var nonWork = false;
    try { nonWork = isHolidayOrNonWork(obj, year, month, d2, ct); } catch (eN) { nonWork = false; }
    if (nonWork) continue;
    var f = dayFlags[d2];
    if (!f) { abs++; continue; }
    // اولویت: تیک «کسر از تعداد خالص» بر همه‌چیز غالب است (حتی اگر پانچ داشته باشد)
    // سپس پانچ یا پوشش بدون‌تیک → مشمول ناهار؛ وگرنه غیبت
    if (f.punch) { earn++; continue; }
    if (f.ticked) { tickedOnly++; continue; }
    if (f.unticked) { earn++; continue; }
    abs++;
  }

  return {
    earnDays: Math.max(0, earn),
    absenceDays: Math.max(0, abs),
    tickedDays: Math.max(0, tickedOnly)
  };
}

/** سازگاری با کد قبلی: روزهایی که از سقف تعداد خالص کم می‌شوند */
function countNetDeductionDays(obj, year, month, code) {
  var r = { earnDays: 0, absenceDays: 0, tickedDays: 0 };
  try { r = countQtyFlatEarnDays(obj, year, month, code) || r; } catch (e) {}
  return Math.max(0, (Number(r.absenceDays) || 0) + (Number(r.tickedDays) || 0));
}

/**
 * آیتم‌های «تعداد خالص» (qty_flat / ناهار):
 * مقدار = روزهای پانچ + پوشش بدون‌تیک (سقف: کارکرد خالص)
 * تیک‌دار و غیبت ناهار نمی‌گیرند.
 */

/** نام‌های نرمال‌شدهٔ ثابت‌هایی که تیک «کسر از تعداد خالص» دارند — یک‌بار در هر آبجکت کش می‌شود */
function getTickedPureCountNames(obj) {
  if (!obj || typeof obj !== 'object') return [];
  try { if (Object.prototype.propertyIsEnumerable.call(obj, '__pspTickedPureNames')) delete obj.__pspTickedPureNames; } catch (ePg2) {}
  if (obj.__pspTickedPureNames && Array.isArray(obj.__pspTickedPureNames)) {
    return obj.__pspTickedPureNames;
  }
  function normName(s) {
    return String(s || '')
      .replace(/[\u200c\u200d\u200e\u200f\u00a0]/g, ' ')
      .replace(/ي/g, 'ی').replace(/ك/g, 'ک')
      .replace(/^تعداد\s+/, '')
      .replace(/\s+/g, ' ').trim();
  }
  var names = [];
  var seen = {};
  function push(nm) {
    nm = normName(nm);
    if (!nm || seen[nm]) return;
    // روز کارکرد / کارکرد خالص هرگز از تعداد خالص کسر نمی‌شود (حتی اگر تیک خورده باشد)
    if (/^روز\s*کارکرد$|^کارکرد$|کارکرد\s*خالص|^work\s*days?$/i.test(nm)) return;
    seen[nm] = true;
    names.push(nm);
  }
  try {
    var consts = (typeof listMonthlyConstantSources === 'function') ? listMonthlyConstantSources(obj) : [];
    // سقف برای جلوگیری از کندی
    var lim = Math.min(consts.length, 400);
    for (var i = 0; i < lim; i++) {
      var c = consts[i];
      if (!c) continue;
      if (c.active === false) continue; // ثابت غیرفعال اثری ندارد
      var flagged = false;
      try { flagged = monthlyConstantDeductsFromPure(c); } catch (eF) { flagged = false; }
      if (!flagged) continue;
      if (c.name) push(c.name);
      if (c.title) push(c.title);
      if (c.label) push(c.label);
      if (c.systemName) push(c.systemName);
      if (c.typeName) push(c.typeName);
    }
  } catch (eC) {}
  try {
    var types = [].concat(
      (obj && obj.attendanceTypes) || [],
      (obj && obj.settings && obj.settings.attendanceTypes) || [],
      (obj && obj.leaveTypes) || [],
      (obj && obj.settings && obj.settings.leaveTypes) || []
    );
    var tlim = Math.min(types.length, 200);
    for (var ti = 0; ti < tlim; ti++) {
      var t = types[ti];
      if (!t) continue;
      var fl = false;
      try { fl = monthlyConstantDeductsFromPure(t); } catch (e1) {}
      if (!fl) {
        try {
          if (typeof hasDeductFlag === 'function') { /* skip */ }
        } catch (e2) {}
      }
      if (!fl) continue;
      if (t.name) push(t.name);
    }
  } catch (eTy) {}
  // پیش‌فرض‌های رایج اگر در لیست نبودند ولی معمولاً تیک می‌خورند — فقط وقتی حداقل یک تیک از settings خوانده شده
  try { Object.defineProperty(obj, '__pspTickedPureNames', { value: names, enumerable: false, writable: true, configurable: true }); } catch (eDp2) {}
  return names;
}

function applyAbsenceToQtyFlatItems(obj, year, month, code, row) {
  if (!row) return;
  if (!row.qty) row.qty = {};
  if (!row.qtyAbsBase || typeof row.qtyAbsBase !== 'object') row.qtyAbsBase = {};

  var emp = ((obj.employees || []).find(function (e) { return String(e.code) === String(code); })) || null;
  var ct = (emp && emp.contractType) || 'normal';

  // ─── پایه = تعداد روزهای ماه (۲۹/۳۰/۳۱) ───
  var monthDays = 30;
  try { monthDays = daysInJalaliMonth(year, month) || 30; } catch (eDim) { monthDays = 30; }
  if (!(monthDays >= 28 && monthDays <= 31)) monthDays = 30;

  // ─── سقف = کارکرد خالص ───
  // سقف = «کارکرد خالص» همان ماه (فیلد بالای ورود داده)، نه «روز کارکرد» کارمند
  // اولویت: meta.functionalDays → پیش‌فرض تنظیمات → شمارش تقویمی
  var funcDays = 0;
  if (!(funcDays > 0)) {
    try {
      var key = year + '-' + month;
      var meta = (obj.monthlyData && obj.monthlyData[key] && obj.monthlyData[key]._meta) || {};
      funcDays = Number(meta.functionalDays) || Number((obj.settings || {}).defaultFunctionalDays) || 0;
    } catch (eF) {}
  }
  if (!(funcDays > 0)) {
    try { funcDays = countFunctionalDaysInMonth(obj, year, month, ct); } catch (eF2) { funcDays = 0; }
  }
  if (!(funcDays > 0)) {
    try { funcDays = Math.max(1, monthDays - Math.round(monthDays * 2 / 7)); } catch (eD) { funcDays = 22; }
  }
  // سقف هرگز از روزهای ماه بیشتر نشود
  if (funcDays > monthDays) funcDays = monthDays;

  // ─── کسر = فقط آیتم/انواعی که در ثابت ماهانه تیک «کسر از تعداد خالص» دارند ───
  var deduct = 0;
  var deductedTags = {};
  // تیک‌های آیتم‌های سیستمی در settings.countRules (مثل کلاینت: پیش‌فرض‌ها)
  var _rules = (obj.settings && obj.settings.countRules) || {};
  var leaveFlatRule = (_rules.leaveDaysFlat !== undefined) ? !!_rules.leaveDaysFlat : (_rules.leaveDays !== false);
  var missionFlatRule = (_rules.missionDaysFlat !== undefined) ? !!_rules.missionDaysFlat : false;
  var hourlyFlatRule = (_rules.hourlyLeaveFlat !== undefined) ? !!_rules.hourlyLeaveFlat : (_rules.hourlyLeave !== false);

  function addDeduct(amount, tag) {
    amount = Number(amount) || 0;
    if (!(amount > 0)) return;
    tag = String(tag || ('x' + deduct));
    if (deductedTags[tag]) return;
    deductedTags[tag] = true;
    deduct += amount;
  }

  function normName(s) {
    return String(s || '')
      .replace(/[\u200c\u200d\u200e\u200f\u00a0]/g, ' ')
      .replace(/ي/g, 'ی').replace(/ك/g, 'ک')
      .replace(/^تعداد\s+/, '')
      .replace(/\s+/g, ' ').trim();
  }

  var tickedConstNames = [];
  try {
    // کش را یک‌بار پاک کن تا حذف «روز کارکرد» از لیست کسر اعمال شود
    if (obj && obj.__pspTickedPureNames) delete obj.__pspTickedPureNames;
    tickedConstNames = getTickedPureCountNames(obj) || [];
  } catch (eG) { tickedConstNames = []; }

  function nameIsTicked(qn) {
    // فقط تیک «کسر از تعداد خالص» در ثابت‌های ماهانه — نه فلگ نوع که تیک را بی‌اثر می‌کند
    var n = normName(qn);
    if (!n) return false;
    for (var i = 0; i < tickedConstNames.length; i++) {
      var t = tickedConstNames[i];
      if (!t) continue;
      if (t === n) return true;
      // تطبیق محافظه‌کارانه: یکی شامل دیگری باشد و حداقل ۳ کاراکتر
      if (t.length >= 3 && n.length >= 3 && (t.indexOf(n) >= 0 || n.indexOf(t) >= 0)) return true;
    }
    return false;
  }

  try {
    // ۱) مرخصی روزانه
    var leaveTicked = nameIsTicked('مرخصی استحقاقی روزانه')
      || nameIsTicked('مرخصی روزانه')
      || nameIsTicked('استحقاقی روزانه')
      || nameIsTicked('مرخصی استحقاقی')
      || nameIsTicked('مرخصی');
    if (leaveTicked || leaveFlatRule) addDeduct(row.leaveDays, 'leaveDays');

    // ۲) همه qty به‌جز ناهار
    var q = row.qty || {};
    Object.keys(q).forEach(function (qn) {
      if (/ناهار|نهار|اهاری/i.test(qn)) return;
      // روز کارکرد / کارکرد خالص هرگز از تعداد خالص ناهار کسر نمی‌شود
      if (/روز\s*کارکرد|^کارکرد$|کارکرد\s*خالص/i.test(qn)) return;
      var n = Number(q[qn]) || 0;
      if (!(n > 0)) return;
      if (nameIsTicked(qn)) addDeduct(n, 'qty:' + normName(qn));
    });

    // ۳) رست
    if (!Object.keys(deductedTags).some(function (k) { return /رست|rest/.test(k); })) {
      if (nameIsTicked('رست کاری') || nameIsTicked('رست') || nameIsTicked('تعداد رست کاری')) {
        var rv = Number(row.restDays) || Number(row.workRestDays) || 0;
        if (!(rv > 0)) {
          Object.keys(q).forEach(function (qn) {
            if (/رست/.test(qn)) rv = Math.max(rv, Number(q[qn]) || 0);
          });
        }
        if (rv > 0) addDeduct(rv, 'rest');
      }
    }

    // ۴) جاب خدمات فنی
    if (!Object.keys(deductedTags).some(function (k) { return /جاب|خدمات/.test(k); })) {
      if (nameIsTicked('جاب خدمات فنی') || nameIsTicked('جاب') || nameIsTicked('تعداد جاب خدمات فنی')) {
        var jv = 0;
        Object.keys(q).forEach(function (qn) {
          if (/جاب|خدمات\s*فنی/.test(qn)) jv = Math.max(jv, Number(q[qn]) || 0);
        });
        if (jv > 0) addDeduct(jv, 'jab');
      }
    }
  } catch (eDed) {}

  // ─── مبنای اصلی تعداد خالص = روزهای تردد / حضور بدون نوع تیک‌دار ───
  // طبق توضیح کاربر: اگر فقط ۸ روز تردد باشد و بقیه مرخصی/رست/جاب (تیک‌دار) باشد → خالص = ۸
  var punchDays = 0;
  try {
    punchDays = Number(row.punchDays) || 0;
    if (!(punchDays > 0) && typeof countEmpMonthPunchDays === 'function') {
      punchDays = countEmpMonthPunchDays(obj, year, month, code) || 0;
      row.punchDays = punchDays;
    }
  } catch (ePd) { punchDays = Number(row.punchDays) || 0; }

  var earnDays = null;
  try {
    var info = countQtyFlatEarnDays(obj, year, month, code) || {};
    // earnDays = روزهایی که پانچ یا پوشش بدون‌تیک دارند
    if (info.earnDays != null) earnDays = Number(info.earnDays) || 0;
    // tickedDays را برای گزارش نگه دار
    if (!(deduct > 0) && info.tickedDays != null) {
      var t2 = Number(info.tickedDays) || 0;
      if (t2 > 0) deduct = t2;
    }
  } catch (e2) {}

  row.netDeductionDays = Math.max(0, deduct);
  try { row.absenceDays = countEmpMonthAbsenceDays(obj, year, month, code) || 0; } catch (eA) { row.absenceDays = 0; }

  // ─── فرمول قطعی (طبق کاربر) ───
  // تعداد خالص = روزهای ماه − جمع آیتم‌های تیک‌خوردهٔ ثابت ماهانه (که در تایم‌شیت مقدار دارند) − غیبت
  // تیک برداشته شود → آن آیتم از کسر حذف می‌شود و خالص بالا می‌رود
  // هرگز رست را از روی punch کم نکن (باعث صفر شدن اشتباه می‌شود)
  var absence = 0;
  try {
    absence = Number(row.absenceDays) || 0;
    if (!(absence > 0) && typeof countEmpMonthAbsenceDays === 'function') {
      absence = Number(countEmpMonthAbsenceDays(obj, year, month, code)) || 0;
    }
  } catch (eAb) { absence = Number(row.absenceDays) || 0; }
  // غیبت ساعتی را به روز تبدیل نکن مگر مقدار روز باشد
  if (absence > monthDays) absence = 0;

  var ceiling = monthDays;
  if (funcDays > 0 && funcDays < ceiling) ceiling = funcDays;
  var finalQty = 0; // بعد از شناخت نام آیتم‌ها محاسبه می‌شود
  row.punchDays = punchDays;
  row.netDeductionDays = Math.max(0, deduct);

  // ─── همهٔ آیتم‌های «تعداد خالص» (ناهار، موتور، خودرو و …) با همین فرمول ───
  // رست/جاب/مرخصی/مأموریت/اولاد/سهام/بیمه/کسورات تعداد رویدادی هستند و دست نمی‌خورند
  var EXCL = /رست|جاب|اولاد|سهام|بیمه|کسور|مأمور|مامور|مرخص|استعلاج|ازدواج|تولد|اضافه|شب\s*کار|مساعده|وام|معوق/;
  var names = {};
  function isFlatName(nm) {
    nm = String(nm || '').trim();
    if (!nm) return false;
    return !EXCL.test(nm);
  }
  function addName(nm) {
    nm = String(nm || '').trim();
    if (!nm || !isFlatName(nm)) return;
    names[nm] = true;
    var bare = nm.replace(/^تعداد\s+/, '').trim();
    if (bare && isFlatName(bare)) {
      names[bare] = true;
      names['تعداد ' + bare] = true;
    }
  }
  function isQtyFlatItem(ci) {
    if (!ci || typeof ci !== 'object') return false;
    var et = String(ci.entryType || ci.type || ci.mode || ci.entry || '').toLowerCase();
    return et === 'qty_flat' || et === 'qtyflat' || et === 'تعداد خالص';
  }
  // نام‌های پیش‌فرض ناهار / موتور / خودرو
  ['کمک هزینه ناهاری', 'حق ناهاری', 'ناهار', 'جبران هزینه ناهاری', 'تعداد ناهاری',
   'حق موتور', 'حق موتوری', 'حق خودرو', 'کمک هزینه خودرو', 'جبران هزینه خودرو'].forEach(addName);
  try {
    (emp && emp.customItems || []).forEach(function (ci) { if (isQtyFlatItem(ci) && ci.name) addName(ci.name); });
  } catch (eC) {}
  try {
    [].concat(obj.customItemTemplates || [], (obj.settings && obj.settings.customItemTemplates) || []).forEach(function (ci) {
      if (isQtyFlatItem(ci) && ci.name) addName(ci.name);
    });
  } catch (eT) {}
  try {
    var consts = (typeof listMonthlyConstantSources === 'function') ? listMonthlyConstantSources(obj) : [];
    consts.forEach(function (c) { if (isQtyFlatItem(c) && c.name) addName(c.name); });
  } catch (eCs) {}
  // ستون‌هایی که همین الان در ردیف هستند و شبیه ناهار/موتور/خودرو هستند
  Object.keys(row.qty || {}).forEach(function (k) {
    if (/ناهار|نهار|اهاری|موتور|خودرو/.test(k)) addName(k);
  });

  // ─── فرمول: تردد + آیتم‌های «بدون تیک کسر از تعداد خالص» (رست، جاب، ...) — تا سقف کارکرد خالص ماه ───
  // آیتم‌های تیک‌دار (مثل مرخصی استحقاقی) و غیبت اضافه نمی‌شوند؛ مقدار هیچ‌وقت از کارکرد خالص ماه بیشتر نمی‌شود
  var dayUnit = {};
  try {
    ((typeof listMonthlyConstantSources === 'function') ? listMonthlyConstantSources(obj) : []).forEach(function (c) {
      if (!c) return;
      var u = String(c.unit || c['واحد'] || c.uom || '');
      if (!/روز|day/i.test(u)) return;
      [c.name, c.title, c.label, c.systemName].forEach(function (n) { n = normName(n); if (n) dayUnit[n] = true; });
    });
  } catch (eU) {}
  var SKIP_Q = /کارکرد|نوبت|ساعت|مأموریت\s*روزانه|ماموریت\s*روزانه|^مرخصی/;
  var DAYLIKE = /رست|جاب|خدمات\s*فنی|استعلاج|تعلیق/;
  var addBy = {};
  Object.keys(row.qty || {}).forEach(function (qn) {
    var nn = normName(qn);
    if (!nn || names[qn] || names[nn] || names['تعداد ' + nn]) return;
    if (SKIP_Q.test(nn)) return;
    if (!(dayUnit[nn] || DAYLIKE.test(nn))) return;
    if (nameIsTicked(qn)) return;
    var n = Number(row.qty[qn]) || 0;
    if (!(n > 0)) return;
    addBy[nn] = Math.max(addBy[nn] || 0, n); // «رست کاری» و «تعداد رست کاری» یک آیتم‌اند
  });
  var unticked = 0;
  Object.keys(addBy).forEach(function (k) { unticked += addBy[k]; });
  // مرخصی / مأموریت روزانه فقط اگر تیک «کسر از تعداد خالص» ندارند
  if (!(leaveTicked || leaveFlatRule)) unticked += Math.max(0, Number(row.leaveDays) || 0);
  if (!(missionFlatRule || nameIsTicked('روز مأموریت') || nameIsTicked('مأموریت روزانه') || nameIsTicked('ماموریت روزانه') || nameIsTicked('مأموریت'))) {
    unticked += Math.max(0, Number(row.missionDays) || 0);
  }
  row.untickedAddDays = Math.round(unticked * 100) / 100;
  var baseQty;
  if ((Number(punchDays) || 0) > 0 || unticked > 0) {
    baseQty = (Number(punchDays) || 0) + unticked;
    if (leaveTicked || leaveFlatRule) baseQty -= Math.max(0, Number(row.leaveDays) || 0);
    if (hourlyFlatRule) baseQty -= (Number(row.hourlyLeave) || 0) / 7.33;
    if (missionFlatRule) baseQty -= Math.max(0, Number(row.missionDays) || 0);
  } else {
    baseQty = Math.min(Number(row.workDays) || 0, ceiling) - deduct;
    if (hourlyFlatRule) baseQty -= (Number(row.hourlyLeave) || 0) / 7.33;
  }
  finalQty = Math.max(0, Math.round(Math.min(ceiling, baseQty) * 100) / 100);

  if (!row.qtyAuto || typeof row.qtyAuto !== 'object') row.qtyAuto = {};
  Object.keys(names).forEach(function (k) {
    row.qtyAbsBase[k] = funcDays;
    row.qty[k] = finalQty;
    row.qtyAuto[k] = false; // مقدار سرور نهایی است؛ پیشنهاد خودکار برنامه آن را پاک نکند
  });
}


/** مأموریت‌هایی که نام‌شان با آیتم تعداد یکی است → qty؛ بقیه → missionDays */

function matchQtyItemName(data, empCode, typeName) {
  const raw = String(typeName || '').trim();
  if (!raw) return null;
  const candidates = [raw];
  if (raw.indexOf('تعداد ') === 0) candidates.push(raw.slice(6).trim());
  else {
    candidates.push('تعداد ' + raw);
    candidates.push(raw.replace(/^تعداد\s+/, ''));
  }
  // بدون پیشوند «تعداد»
  const bare = raw.replace(/^تعداد\s+/, '').trim();
  if (bare && candidates.indexOf(bare) < 0) candidates.push(bare);
  // «ماموریت روزانه» فیلد سیستمی است — هرگز به ستون تعداد نرود
  if (((/ماموریت/.test(bare)||/مأموریت/.test(bare))&&/روزانه/.test(bare)) || bare === 'مأموریت' || bare === 'ماموریت') return null;
  const emp = ((data.employees || []).find(function (e) { return String(e.code) === String(empCode); })) || null;
  function hitList(list) {
    if (!list || !list.length) return null;
    for (let i = 0; i < list.length; i++) {
      const ci = list[i];
      if (!ci || !ci.name) continue;
      if (ci.entryType !== 'quantity' && ci.entryType !== 'qty_flat') continue;
      if (ci.enabled === false || ci.enabled === 0 || ci.enabled === '0') continue;
      const nm = String(ci.name).trim();
      const nmBare = nm.replace(/^تعداد\s+/, '').trim();
      for (let c = 0; c < candidates.length; c++) {
        const cand = candidates[c];
        const candBare = String(cand).replace(/^تعداد\s+/, '').trim();
        if (nm === cand || nmBare === cand || nm === candBare || nmBare === candBare) return nm;
        if (nmBare && candBare && (nmBare.indexOf(candBare) >= 0 || candBare.indexOf(nmBare) >= 0)) return nm;
      }
    }
    return null;
  }
  var hit = hitList(emp && emp.customItems) || hitList(data.customItemTemplates);
  if (hit) return hit;
  // ثابت‌های ماهانه — بدون فیلتر entryType تا آیتم جدید/سیستمی هم match شود
  try {
    var consts = (typeof listMonthlyConstantSources === 'function') ? listMonthlyConstantSources(data) : [];
    for (var ci = 0; ci < consts.length; ci++) {
      var c = consts[ci];
      if (!c || !c.name) continue;
      if (c.enabled === false || c.enabled === 0 || c.enabled === '0') continue;
      var nm = String(c.name).trim();
      var nmBare = nm.replace(/^تعداد\s+/, '').trim();
      for (var c2 = 0; c2 < candidates.length; c2++) {
        var cand = String(candidates[c2] || '').trim();
        var candBare = cand.replace(/^تعداد\s+/, '').trim();
        if (cand === nm || candBare === nmBare || cand === nmBare || candBare === nm) return nm;
        if (candBare && nmBare && (nmBare.indexOf(candBare) >= 0 || candBare.indexOf(nmBare) >= 0)) return nm;
      }
    }
  } catch (eC) {}
  return null;
}
function addQtyDaysToMonthRow(row, qtyName, days) {
  if (!row || !qtyName || !(days > 0)) return;
  if (!row.qty) row.qty = {};
  row.qty[qtyName] = Math.round(((Number(row.qty[qtyName]) || 0) + days) * 100) / 100;
  if (!row.qtyAuto) row.qtyAuto = {};
  row.qtyAuto[qtyName] = false;
}



function rebuildLeaveTypeQtyFromRequests(obj, year, month, code, md) {
  if (!md) return;
  if (!md.qty || typeof md.qty !== 'object') md.qty = {};
  year = Number(year); month = Number(month);
  const emp = ((obj.employees || []).find(function (e) { return String(e.code) === String(code); })) || null;
  const ct = (emp && emp.contractType) || 'normal';
  function isApprovedStatus(st) {
    st = String(st || '').toLowerCase();
    return st === 'approved' || st === 'approved_l1' || st === 'final' ||
      st === 'تایید' || st === 'تأیید' || st === 'تایید شده' || st === 'تأیید شده';
  }
  // صفر کردن ستون‌های شناخته‌شده غیر استحقاقی قبل از جمع
  ['مرخصی ازدواج', 'تعداد مرخصی ازدواج', 'مرخصی تولد فرزند', 'تعداد مرخصی تولد فرزند',
   'مرخصی فوت بستگان', 'تعداد مرخصی فوت بستگان'].forEach(function (k) {
    if (md.qty[k] != null) md.qty[k] = 0;
  });
  const byName = {};
  const seenId = {};
  (obj.attendanceRequests || []).forEach(function (x) {
    if (!x || String(x.empCode) !== String(code)) return;
    if (!isApprovedStatus(x.status)) return;
    if (x.kind !== 'leave' || x.mode !== 'daily') return;
    // جلوگیری از شمارش تکراری همان id
    if (x.id) {
      if (seenId[x.id]) return;
      seenId[x.id] = true;
    }
    if (!(typeof shouldSkipLeaveDaysColumn === 'function' && shouldSkipLeaveDaysColumn(obj, x))) return;
    let nm = String(x.typeName || '').trim();
    if (!nm && x.typeId) {
      try {
        const types = [].concat(obj.attendanceTypes || [], (obj.settings && obj.settings.attendanceTypes) || []);
        const td = types.find(function (t) { return t && String(t.id) === String(x.typeId); });
        if (td) nm = String(td.name || '').trim();
      } catch (e) {}
    }
    if (!nm || nm.indexOf('رست') >= 0) return;
    // فقط روزهای واقعی بازه — نه fixedDays
    const days = (typeof countWorkingDaysInMonth === 'function')
      ? countWorkingDaysInMonth(x.startDate, x.endDate || x.startDate, year, month, obj, ct) : 0;
    if (!(days > 0)) return;
    byName[nm] = (byName[nm] || 0) + days;
  });
  Object.keys(byName).forEach(function (nm) {
    const keys = [nm, 'تعداد ' + nm];
    if (/ازدواج/.test(nm)) keys.push('مرخصی ازدواج', 'تعداد مرخصی ازدواج');
    if (/تولد/.test(nm)) keys.push('مرخصی تولد فرزند', 'تعداد مرخصی تولد فرزند');
    if (/فوت/.test(nm)) keys.push('مرخصی فوت بستگان', 'تعداد مرخصی فوت بستگان');
    keys.forEach(function (k) { md.qty[k] = byName[nm]; });
  });
}

function rebuildRestQtyFromRequests(obj, year, month, code, row) {
  if (!row) return;
  if (!row.qty) row.qty = {};
  // فقط در پایان مقدار رست را می‌نویسیم — بقیه qty را دست نزن
  function isExplicitRestOnly(s) {
    s = String(s || '').replace(/\u200c/g, ' ').replace(/\s+/g, ' ').trim();
    if (!s) return false;
    // هر مرخصی/استحقاق/استعلاج/غیبت/مأموریت = رست نیست
    if (/مرخص|استحقاق|استعلاج|بدون\s*حقوق|غیبت|غایب|مأمور|مامور|mission|leave/i.test(s)) return false;
    // فقط وقتی کلمه رست (یا rest) هست
    return (s.indexOf('رست') >= 0) || /\brest\b/i.test(s);
  }
  function approved(st) {
    st = String(st || '').toLowerCase().trim();
    if (!st) return true; // بعضی ثبت‌ها بدون status
    return st === 'approved' || st === 'approved_l1' || st === 'approved_l2' || st === 'final' ||
      st === 'تایید' || st === 'تأیید' || st === 'تایید شده' || st === 'تأیید شده' ||
      st === 'accept' || st === 'ok' || st === 'done' || st === 'active' ||
      st.indexOf('تایید') >= 0 || st.indexOf('تأیید') >= 0 || st.indexOf('approve') >= 0;
  }
  var seen = {};
  var total = 0;
  var ct = 'normal';
  try {
    var emp = ((obj.employees || []).find(function (e) { return String(e.code) === String(code); })) || null;
    if (emp && emp.contractType) ct = emp.contractType;
  } catch (e0) {}

  function addDay(d) {
    d = Number(d) || 0;
    if (d < 1 || d > 31) return;
    var dk = year + '-' + month + '-' + d;
    if (seen[dk]) return;
    seen[dk] = true;
    total += 1;
  }

  // 1) درخواست‌های تأییدشده با نام/kind صریح رست
  // توجه: در پرتال غالباً kind=leave و typeName=«رست کاری» است — نباید به‌خاطر kind=leave رد شود
  (obj.attendanceRequests || []).forEach(function (x) {
    if (!x || String(x.empCode) !== String(code)) return;
    if (!approved(x.status)) return;
    var k = String(x.kind || '').toLowerCase();
    var tn = String(x.typeName || x.type || x.name || '');
    var isRestKind = (k === 'rest' || k === 'work_rest' || k === 'رست' || k === 'رست کاری');
    var isRestName = (tn.indexOf('رست') >= 0) || isExplicitRestOnly(tn) || isExplicitRestOnly(String(x.typeId || ''));
    // استحقاق / استعلاج خالص (بدون کلمه رست) رست نیست
    if (/استحقاق|استعلاج/.test(tn) && tn.indexOf('رست') < 0) return;
    if (/مأمور|مامور|mission/i.test(tn) && tn.indexOf('رست') < 0) return;
    // نام صریح رست کافی است حتی اگر kind=leave باشد
    if (!isRestKind && !isRestName) return;
    if (x.mode === 'hourly') return;
    try {
      if (x.startDate) {
        var keys = (typeof listDayKeys === 'function')
          ? listDayKeys(x.startDate, x.endDate || x.startDate)
          : [];
        if (keys && keys.length) {
          keys.forEach(function (dk) {
            var parts = String(dk).split(/[-/]/);
            if (parts.length < 3) return;
            if (Number(parts[0]) !== year || Number(parts[1]) !== month) return;
            addDay(Number(parts[2]));
    
Displaying workers.txt.
