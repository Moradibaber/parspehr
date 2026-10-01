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
    box.innerHTML = '<div style="font-weight:700;color:#0f766e;margin-bottom:8px;font-size:0.9rem;">پرتال فیش / مرخصی / مأموریت</div>' +
      '<p style="font-size:0.75rem;color:#64748b;margin-bottom:8px;line-height:1.5;">' +
      'ورود از <b>/employee</b> — رمز اولیه = کد پرسنلی. مدیر مستقیم درخواست‌های مرخصی/مأموریت را تأیید می‌کند.' +
      '</p>' +
      '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px;">' +
      '<label style="font-size:0.78rem;">مدیر سطح ۱:</label>' +
      '<select id="pspManagerCode" autocomplete="off" style="padding:6px 8px;border:1px solid #99f6e4;border-radius:7px;font-size:0.82rem;max-width:220px;font-family:inherit;"><option value="">— بدون —</option></select>' +
      '<label style="font-size:0.78rem;">مدیر سطح ۲ (اختیاری):</label>' +
      '<select id="pspManagerCode2" autocomplete="off" style="padding:6px 8px;border:1px solid #99f6e4;border-radius:7px;font-size:0.82rem;max-width:220px;font-family:inherit;"><option value="">— بدون —</option></select>' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspManagerSaveBtn">ذخیره مدیران</button>' +
      '<span id="pspManagerStatus" style="font-size:0.75rem;color:#0f766e;"></span>' +
      '</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">' +
      '<label style="font-size:0.78rem;display:flex;align-items:center;gap:4px;"><input type="checkbox" id="pspPortalEnabled" checked> دسترسی پرتال فعال</label>' +
      '<input type="text" id="pspPortalPass" autocomplete="new-password" data-lpignore="true" data-form-type="other" placeholder="رمز جدید (خالی = رمز اولیه = کد)" style="padding:6px 8px;border:1px solid #99f6e4;border-radius:7px;font-size:0.82rem;max-width:200px;font-family:inherit;-webkit-text-security:disc;">' +
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
    document.getElementById('pspManagerSaveBtn').onclick = function() {
      var codeEl = document.getElementById('e_code') || document.getElementById('editEmpId');
      var code = codeEl ? String(codeEl.value || '').trim() : '';
      if (!code) { alert('ابتدا کد پرسنلی کارمند را مشخص کنید.'); return; }
      var managerCode = (document.getElementById('pspManagerCode').value || '').trim();
      var managerCode2 = (document.getElementById('pspManagerCode2').value || '').trim();
      var st = document.getElementById('pspManagerStatus');
      st.textContent = '…';
      fetch('/api/admin/set-manager', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ code: code, managerCode: managerCode, managerCode2: managerCode2 })
      }).then(function(r){ return r.json(); }).then(function(j){
        if (j.ok) {
          st.style.color = '#16a34a';
          st.textContent = 'ذخیره شد' + (managerCode ? ' | ل۱: ' + managerCode : '') + (managerCode2 ? ' | ل۲: ' + managerCode2 : (!managerCode ? ' (بدون مدیر)' : ''));
          try {
            if (typeof data !== 'undefined' && data.employees) {
              var emp = data.employees.find(function(e){ return String(e.code) === code; });
              if (emp) { emp.managerCode = managerCode; emp.managerCode2 = managerCode2; }
            }
          } catch (e) {}
        } else {
          st.style.color = '#b91c1c';
          st.textContent = j.message || j.error || 'خطا';
        }
      }).catch(function(){ st.style.color = '#b91c1c'; st.textContent = 'خطا در ارتباط'; });
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
        var ms = document.getElementById('pspManagerStatus');
        if (ms) ms.textContent = '';
        var pe = document.getElementById('pspPortalEnabled');
        if (pe) pe.checked = true;
        var pp = document.getElementById('pspPortalPass');
        if (pp) pp.value = '';
        try {
          var codeEl = document.getElementById('e_code') || document.getElementById('editEmpId');
          var code = codeEl ? String(codeEl.value || '').trim() : '';
          var mc = document.getElementById('pspManagerCode');
          var mc2 = document.getElementById('pspManagerCode2');
          var keep = '', keep2 = '';
          try {
            if (code && typeof data !== 'undefined' && data.employees) {
              var emp0 = data.employees.find(function(e){ return String(e.code) === code; });
              keep = emp0 && emp0.managerCode ? String(emp0.managerCode) : '';
              keep2 = emp0 && emp0.managerCode2 ? String(emp0.managerCode2) : '';
            }
          } catch (e) {}
          function fillMgrSelect(sel, selected) {
            if (!sel) return;
            sel.innerHTML = '<option value=\"\">— بدون —</option>';
            try {
              if (typeof data !== 'undefined' && data.employees) {
                data.employees.slice().sort(function(a,b){
                  return String(a.fullName||'').localeCompare(String(b.fullName||''), 'fa');
                }).forEach(function(e){
                  if (String(e.code) === code) return;
                  if (e.status === 'inactive') return;
                  var opt = document.createElement('option');
                  opt.value = String(e.code);
                  opt.textContent = (e.fullName || '') + ' (' + e.code + ')';
                  sel.appendChild(opt);
                });
              }
            } catch (e) {}
            sel.value = selected || '';
            if (selected && sel.value !== selected) {
              var opt2 = document.createElement('option');
              opt2.value = selected;
              opt2.textContent = selected + ' (ذخیره‌شده)';
              sel.appendChild(opt2);
              sel.value = selected;
            }
          }
          fillMgrSelect(mc, keep);
          fillMgrSelect(mc2, keep2);
          if (code) {
            fetch('/api/admin/get-manager?code=' + encodeURIComponent(code), { credentials: 'same-origin' })
              .then(function(r){ return r.json(); })
              .then(function(j){
                if (!j.ok) return;
                fillMgrSelect(mc, j.managerCode || '');
                fillMgrSelect(mc2, j.managerCode2 || '');
                try {
                  if (typeof data !== 'undefined' && data.employees) {
                    var empX = data.employees.find(function(e){ return String(e.code) === code; });
                    if (empX) { empX.managerCode = j.managerCode || ''; empX.managerCode2 = j.managerCode2 || ''; }
                  }
                } catch (e) {}
              }).catch(function(){});
          }
        } catch (e) {}
      }, 100);
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
  // پاکسازی دکمه شناور قدیمی پایین-چپ
  setTimeout(function(){
    try {
      var f = document.getElementById('pspPortalFab');
      if (f && f.parentNode) f.parentNode.removeChild(f);
    } catch (e) {}
  }, 500);


  function ensurePortalTab() {
    var existingBtn = document.getElementById('pspPortalTabBtn');
    var existingPanel = document.getElementById('panel-portalatt');
    // اگر تب هست ولی محتوای اصلی نیست، از نو بساز
    if (existingBtn && existingPanel && document.getElementById('pspSub-ts') && document.getElementById('pspSubTabs')) {
      return;
    }
    if (existingBtn) { try { existingBtn.parentNode.removeChild(existingBtn); } catch (e) {} }
    if (existingPanel) { try { existingPanel.parentNode.removeChild(existingPanel); } catch (e) {} }
    // Find tab strip: parent of any existing tab button
    var sample = document.querySelector('button.tab-btn[data-tab], button.tab-btn, .tabs button, [class*="tab"] button[data-tab]');
    if (!sample) sample = document.querySelector('button.tab-btn');
    var tabs = null;
    if (sample && sample.parentElement) tabs = sample.parentElement;
    if (!tabs) tabs = document.querySelector('.tabs, .tab-bar, nav.tabs, .tablist, [role="tablist"]');
    if (!tabs) {
      // last resort: create a strip under the main header
      var header = document.querySelector('header, .app-header, .topbar, .navbar') || document.body;
      tabs = document.getElementById('pspPortalTabStrip');
      if (!tabs) {
        tabs = document.createElement('div');
        tabs.id = 'pspPortalTabStrip';
        tabs.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;padding:8px 12px;background:#f0fdfa;border-bottom:1px solid #99f6e4;';
        if (header.parentNode) header.parentNode.insertBefore(tabs, header.nextSibling);
        else document.body.insertBefore(tabs, document.body.firstChild);
      }
    }
    if (existingBtn && !existingPanel) {
      try { existingBtn.parentNode.removeChild(existingBtn); } catch (e) {}
    }
    if (existingPanel && !existingBtn) {
      try { existingPanel.parentNode.removeChild(existingPanel); } catch (e) {}
    }
    var btn = document.createElement('button');
    btn.id = 'pspPortalTabBtn';
    btn.className = (sample && sample.className) ? sample.className : 'tab-btn';
    btn.type = 'button';
    btn.setAttribute('data-tab', 'portalatt');
    btn.textContent = 'مأموریت/مرخصی و سایر';
    btn.style.cssText = (btn.style.cssText||'') + ';cursor:pointer;';
    tabs.appendChild(btn);

    var panel = document.createElement('div');
    panel.className = 'panel';
    panel.id = 'panel-portalatt';
    panel.innerHTML =
      '<div class="card">' +
      '<div class="section-title" style="margin-bottom:10px;">مأموریت / مرخصی و تایم‌شیت</div>' +
      '<div id="pspSubTabs" style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:14px;background:#f0fdfa;padding:6px;border-radius:10px;border:1px solid #99f6e4;">' +
      '<button type="button" class="btn btn-sm psp-subtab active" data-sub="ts" style="background:#0f766e;color:#fff;">تایم‌شیت و کارکرد</button>' +
      '<button type="button" class="btn btn-outline btn-sm psp-subtab" data-sub="types">انواع مرخصی/مأموریت</button>' +
      '<button type="button" class="btn btn-outline btn-sm psp-subtab" data-sub="grants">مجوزها</button>' +
      '<button type="button" class="btn btn-outline btn-sm psp-subtab" data-sub="reqs">مدیریت درخواست‌ها</button>' +
      '<button type="button" class="btn btn-outline btn-sm psp-subtab" data-sub="upload">آپلود فایل کارکرد</button>' +
      '<button type="button" class="btn btn-outline btn-sm psp-subtab" data-sub="portalview">نمایش در پرتال کارمند</button>' +
      '<button type="button" class="btn btn-outline btn-sm psp-subtab" data-sub="contracts">قراردادها</button>' +
      '</div>' +
      '<div class="psp-subpanel" id="pspSub-ts">' +
      '<div class="section-title">تایم‌شیت پرتال کارکنان</div>' +
      '<p style="font-size:0.8rem;color:#64748b;margin-bottom:10px;">این گزارش از درخواست‌های تأییدشده پرتال است و فعلاً روی محاسبه حقوق اثر ندارد.</p>' +
      '<div class="form-grid" style="margin-bottom:10px;">' +
      '<div class="form-group"><label>سال</label><input type="number" id="pspTsYear" value="1405"></div>' +
      '<div class="form-group"><label>ماه</label><select id="pspTsMonth"><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option></select></div>' +
      '<div class="form-group"><label>کد پرسنلی</label><input id="pspTsCode" placeholder="خالی = همه" autocomplete="off"></div>' +
      '<div class="form-group"><label>کد مدیر</label><input id="pspTsMgr" placeholder="فیلتر زیرمجموعه" autocomplete="off"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-primary btn-sm" id="pspTsLoad">نمایش</button></div>' +
      '</div>' +
      '<p style="font-size:0.78rem;color:#64748b;margin:6px 0 10px;">برای جدول <b>روزبه‌روز شبیه اکسل</b> حتماً کد پرسنلی را پر کنید.</p>' +
      '<div class="form-grid" style="margin-bottom:10px;align-items:end;">' +
      '<div class="form-group"><label>ماه جاری درخواست‌ها</label><select id="pspCurMonth"><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option></select></div>' +
      '<div class="form-group"><label>سال جاری</label><input type="number" id="pspCurYear" value="1405"></div>' +
      '<div class="form-group"><label>نوع قرارداد (تقویم)</label><select id="pspCalContractType"></select></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-outline btn-sm" id="pspCurSave">ثبت ماه جاری و روزهای کاری</button></div>' +
      '</div>' +
      '<div class="form-grid" style="margin-bottom:10px;align-items:end;">' +
      '<div class="form-group"><label>شناسه نوع جدید</label><input id="pspNewCtId" placeholder="مثلاً shift" dir="ltr"></div>' +
      '<div class="form-group"><label>نام فارسی</label><input id="pspNewCtName" placeholder="مثلاً شیفتی"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-outline btn-sm" id="pspAddCtBtn">+ نوع قرارداد</button></div>' +
      '<div class="form-group" style="grid-column:1/-1;"><label>روزهای کاری هفته <span style="color:#64748b;font-weight:400;">(برای نوع انتخاب‌شده)</span></label>' +
      '<div style="display:flex;flex-wrap:wrap;gap:8px;font-size:0.78rem;">' +
      '<label><input type="checkbox" class="psp-wd" value="6" checked> شنبه</label>' +
      '<label><input type="checkbox" class="psp-wd" value="0" checked> یکشنبه</label>' +
      '<label><input type="checkbox" class="psp-wd" value="1" checked> دوشنبه</label>' +
      '<label><input type="checkbox" class="psp-wd" value="2" checked> سه‌شنبه</label>' +
      '<label><input type="checkbox" class="psp-wd" value="3" checked> چهارشنبه</label>' +
      '<label><input type="checkbox" class="psp-wd" value="4"> پنجشنبه</label>' +
      '<label><input type="checkbox" class="psp-wd" value="5"> جمعه</label>' +
      '</div></div>' +
      '<div class="form-group" style="grid-column:1/-1;"><label>روزهای غیرکاری بین بازه مرخصی جزو مرخصی حساب شوند؟</label>' +
      '<select id="pspCountNonWorkAsLeave"><option value="no">خیر — فقط روزهای کاری</option><option value="yes">بلی — تعطیل/غیرکاری هم شمرده شود</option></select></div>' +
      '<div class="section-title" style="grid-column:1/-1;margin:12px 0 4px;font-size:0.9rem;">ساعت کاری نوع قرارداد انتخاب‌شده</div>' +
      '<div class="form-group"><label>شروع کار</label><input id="pspWsStart" type="text" value="08:00" dir="ltr" placeholder="08:00" style="font-variant-numeric:tabular-nums;"></div>' +
      '<div class="form-group"><label>پایان کار</label><input id="pspWsEnd" type="text" value="17:00" dir="ltr" placeholder="17:00" style="font-variant-numeric:tabular-nums;"></div>' +
      '<div class="form-group"><label>پایان روز (حد ثبت)</label><input id="pspWsDayEnd" type="text" value="23:59" dir="ltr" placeholder="23:59"></div>' +
      '<div class="form-group"><label>شناوری (دقیقه)</label><input id="pspWsFloat" type="number" min="0" step="1" value="15"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;padding-bottom:4px;"><label style="font-size:0.78rem;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="pspWsHasBreak"> دارای وقفه (ناهار/نماز)</label></div>' +
            '<div class="form-group"><label>شروع وقفه</label><input id="pspWsBreakStart" type="text" value="12:00" dir="ltr" placeholder="12:00" disabled style="opacity:0.45;"></div>' +
      '<div class="form-group"><label>پایان وقفه</label><input id="pspWsBreakEnd" type="text" value="13:00" dir="ltr" placeholder="13:00" disabled style="opacity:0.45;"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;padding-bottom:4px;"><label style="font-size:0.78rem;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="pspWsBreakAsWork" disabled> وقفه جزو ساعت کار باشد</label></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;padding-bottom:4px;"><label style="font-size:0.78rem;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="pspWsFloatComp"> جبران تأخیر با ماندن در پایان</label></div>' +
      '<div class="form-group" style="grid-column:1/-1;"><span id="pspWsHint" style="font-size:0.72rem;color:#64748b;">بدون وقفه = فقط شروع/پایان. با وقفه + تیک «جزو کار» = وقفه در مجموع کار؛ بدون تیک = از کار کسر می‌شود. جبران تأخیر: ورود دیرتر → ماندن معادل در پایان.</span></div>' +
      '<div class="form-group" style="grid-column:1/-1;"><span id="pspCurStatus" style="font-size:0.8rem;color:#0f766e;"></span></div>' +
      '</div>' +      '<div class="section-title" style="margin-top:16px;">تقویم تعطیلات سال</div>' +
      '<p style="font-size:0.75rem;color:#64748b;margin-bottom:8px;">پیش‌فرض ایران: پنجشنبه و جمعه تعطیل + تعطیلات رسمی شمسی (نوروز، ۲۲ بهمن، …). مناسبت‌های قمری را ادمین اضافه کند. هر نوع قرارداد تقویم مستقل دارد و روی بقیه کپی/پاک نمی‌شود.</p>' +
      '<div class="form-grid" style="margin-bottom:8px;">' +
      '<div class="form-group"><label>سال تقویم</label><input type="number" id="pspCalYear" value="1405"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;gap:6px;">' +
      '<button type="button" class="btn btn-primary btn-sm" id="pspCalLoad">نمایش تقویم</button>' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspCalSave">ذخیره تعطیلات</button></div>' +
      '</div><div id="pspCalBox" style="overflow:auto;margin-bottom:12px;"></div>' +
      '<span id="pspCalStatus" style="font-size:0.8rem;color:#0f766e;"></span>' +
'<div id="pspTsOut" style="overflow:auto;margin-bottom:20px;"></div></div>' +
      '<div class="psp-subpanel" id="pspSub-types" style="display:none;">' +
      '<div class="section-title">انواع مرخصی و مأموریت</div>' +
      '<p style="font-size:0.8rem;color:#64748b;margin-bottom:8px;">نام‌ها در پرتال کارکنان نمایش داده می‌شوند.</p>' +
      '<div id="pspTypesList" style="overflow:auto;"></div>' +
      '<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspTypeAdd">+ نوع جدید</button>' +
      '<button type="button" class="btn btn-primary btn-sm" id="pspTypeSave">ذخیره انواع</button>' +
      '<span id="pspTypeStatus" style="font-size:0.8rem;color:#0f766e;"></span></div></div>' +
      '<div class="psp-subpanel" id="pspSub-grants" style="display:none;">' +
      '<div class="section-title">مجوز مرخصی خاص برای کارمند</div>' +
      
      '<div class="form-grid" style="align-items:end;">' +
      '<div class="form-group"><label>کد پرسنلی</label><input id="pspGrantCode" autocomplete="off" placeholder="کد کارمند"></div>' +
      '<div class="form-group"><label>نوع</label><select id="pspGrantType"></select></div>' +
      '<div class="form-group"><label>از تاریخ</label><input id="pspGrantFrom" placeholder="1405/02/01" dir="ltr"></div>' +
      '<div class="form-group"><label>تا تاریخ</label><input id="pspGrantTo" placeholder="1405/02/29" dir="ltr"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-primary btn-sm" id="pspGrantBtn">صدور مجوز</button></div>' +
      '</div><span id="pspGrantStatus" style="font-size:0.8rem;color:#0f766e;"></span>' +
      '<div class="section-title" style="margin-top:18px;">تعدیل مانده مرخصی استحقاقی (+ / −)</div>' +
      
      '<div class="form-grid" style="margin-bottom:10px;align-items:end;">' +
      '<div class="form-group"><label>کد پرسنلی</label><input id="pspAdjCode" placeholder="کد"></div>' +
      '<div class="form-group"><label>سال هدف</label><input id="pspAdjYear" placeholder="1405" dir="ltr"></div>' +
      '<div class="form-group"><label>منبع مانده</label><select id="pspAdjSource"><option value="current">مرخصی سال جاری</option><option value="prior">ذخیره سال‌های قبل</option></select></div>' +
      '<div class="form-group"><label>نوع</label><select id="pspAdjSign"><option value="+">+ بستانکار</option><option value="-">− بدهکار</option></select></div>' +
      '<div class="form-group"><label>روز</label><input id="pspAdjDays" type="number" min="0" step="0.01" value="10"></div>' +
      '<div class="form-group"><label>ساعت (اختیاری)</label><input id="pspAdjHours" type="number" min="0" step="0.5" value="0"></div>' +
      '<div class="form-group"><label>توضیح</label><input id="pspAdjReason" placeholder="مثلاً استفاده از ذخیره ۱۴۰۴"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-warning btn-sm" id="pspAdjBtn">ثبت تعدیل</button></div>' +
      '</div><span id="pspAdjStatus" style="font-size:0.8rem;color:#0f766e;"></span>' +
      '</div>' +
      '<div class="psp-subpanel" id="pspSub-reqs" style="display:none;">' +
      '<div class="section-title">همه درخواست‌های مرخصی / مأموریت</div>' +
      '<div class="form-grid">' +
      '<div class="form-group"><label>سال</label><input type="number" id="pspReqYear" value="1405"></div>' +
      '<div class="form-group"><label>ماه</label><select id="pspReqMonth"><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option></select></div>' +
      '<div class="form-group"><label>کد (اختیاری)</label><input id="pspReqCode" autocomplete="off" placeholder="همه"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;gap:6px;">' +
      '<button type="button" class="btn btn-primary btn-sm" id="pspReqLoad">بارگذاری</button>' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspReqAddRow">+ ردیف جدید</button></div></div>' +
      '<div id="pspReqSheet" style="overflow:auto;margin-top:8px;"></div>' +
      '<span id="pspAdmStatus" style="font-size:0.8rem;color:#0f766e;"></span></div>' +
      '<div class="psp-subpanel" id="pspSub-upload" style="display:none;">' +
      '<div class="section-title">آپلود فایل کارکرد / تایم‌شیت (TXT یا Excel)</div>' +
      '<p style="font-size:0.85rem;color:#64748b;margin-bottom:12px;">این بخش برای آینده آماده شده است.</p>' +
      '<div style="border:2px dashed #99f6e4;border-radius:12px;padding:18px;background:#fafafa;">' +
      '<div class="form-grid">' +
      '<div class="form-group"><label>سال</label><input type="number" id="pspUpYear" value="1405"></div>' +
      '<div class="form-group"><label>ماه</label><select id="pspUpMonth"><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option></select></div>' +
      '<div class="form-group"><label>فایل</label><input type="file" id="pspUpFile" accept=".txt,.csv,.xlsx,.xls" disabled></div></div>' +
      '<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">' +
      '<button type="button" class="btn btn-primary btn-sm" id="pspUpBtn" disabled>آپلود و پردازش (به‌زودی)</button>' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspUpSample">دانلود نمونه فرمت</button>' +
      '<span id="pspUpStatus" style="font-size:0.8rem;color:#64748b;">فعلاً غیرفعال</span></div></div></div>' +
      '<div class="psp-subpanel" id="pspSub-portalview" style="display:none;">' +
      '<div class="section-title">نمایش در پرتال کارمند — حکم و مشخصات پرسنلی</div>' +
      '<p style="font-size:0.82rem;color:#64748b;margin-bottom:12px;">آیتم‌های حکم از «انتقال انتخابی کارکنان و مزایا» بارگذاری می‌شوند. افراد را با تیک انتخاب کنید.</p>' +
      '<div id="pspPortalViewBody"><div style="color:#64748b;font-size:0.85rem;">در حال بارگذاری تنظیمات…</div></div>' +
      '<div style="margin-top:12px;display:flex;gap:8px;align-items:center;">' +
      '<button type="button" class="btn btn-primary btn-sm" id="pspPortalViewSave">ذخیره تنظیمات</button>' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspPortalViewReload">بروزرسانی لیست‌ها</button>' +
      '<span id="pspPortalViewStatus" style="font-size:0.8rem;color:#0f766e;"></span></div></div>' +
      
      '<div class="psp-subpanel" id="pspSub-contracts" style="display:none;">' +
      '<div class="section-title">قراردادهای کارکنان</div>' +
      '<p style="font-size:0.82rem;color:#64748b;margin-bottom:10px;line-height:1.6;">صدور قرارداد فردی/گروهی با انتخاب از لیست. آپلود قرارداد امضاشده فقط توسط <b>ادمین</b> است. مشاهده توسط کارمند اختیاری است.</p>' +
      '<div class="form-grid" style="margin-bottom:10px;">' +
      '<div class="form-group"><label>از تاریخ</label><input id="pspCtrFrom" placeholder="1405/01/01" dir="ltr"></div>' +
      '<div class="form-group"><label>تا تاریخ</label><input id="pspCtrTo" placeholder="1405/12/29" dir="ltr"></div>' +
      '<div class="form-group"><label>نوع</label><select id="pspCtrType"><option value="fixed">مدت‌موقت</option><option value="permanent">دائم</option><option value="hourly">ساعتی</option><option value="daily">روزمزد</option><option value="other">سایر</option></select></div>' +
      '<div class="form-group"><label>توضیح</label><input id="pspCtrNote" placeholder="اختیاری"></div>' +
      '</div>' +
      '<div style="margin-bottom:8px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;font-size:0.8rem;">' +
      '<label><input type="checkbox" id="pspCtrShowDurDef" checked> نمایش مدت قرارداد به کارمند (پیش‌فرض)</label>' +
      '<label><input type="checkbox" id="pspCtrVisibleDef" checked> قابل مشاهده بودن قرارداد در پرتال کارمند (پیش‌فرض)</label>' +
      '</div>' +
      '<div style="margin-bottom:10px;border:1px solid #99f6e4;border-radius:10px;background:#fafafa;overflow:hidden;">' +
      '<button type="button" id="pspCtrEmpToggle" style="width:100%;text-align:right;padding:10px 12px;border:0;background:#ecfdf5;cursor:pointer;font-family:inherit;font-size:0.85rem;color:#0f766e;font-weight:700;display:flex;justify-content:space-between;align-items:center;gap:8px;">' +
      '<span id="pspCtrEmpSummary">انتخاب کارکنان — هیچ‌کس انتخاب نشده</span>' +
      '<span id="pspCtrEmpChevron" style="font-size:0.75rem;color:#64748b;">▼ باز کردن</span>' +
      '</button>' +
      '<div id="pspCtrEmpDropdown" style="display:none;padding:10px;border-top:1px solid #99f6e4;">' +
      '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px;font-size:0.78rem;">' +
      '<input id="pspCtrEmpSearch" placeholder="جستجوی نام یا کد…" style="flex:1;min-width:140px;padding:6px 8px;border:1px solid #99f6e4;border-radius:6px;font-size:0.78rem;">' +
      '<label style="white-space:nowrap;"><input type="checkbox" id="pspCtrEmpAll"> انتخاب همه (فیلترشده)</label>' +
      '<label style="cursor:pointer;color:#0f766e;white-space:nowrap;"><input type="file" id="pspCtrExcel" accept=".xlsx,.xls,.csv,.txt" style="display:none;">📥 اکسل/CSV</label>' +
      '</div>' +
      '<div id="pspCtrEmpList" style="max-height:220px;overflow:auto;font-size:0.78rem;border:1px solid #e2e8f0;border-radius:8px;padding:6px 8px;background:#fff;"></div>' +
      '<div style="font-size:0.72rem;color:#64748b;margin-top:6px;">فرمت اکسل/CSV: ستون اول کد پرسنلی. افراد متناظر تیک می‌خورند.</div>' +
      '</div></div>' +
      '<div style="margin-bottom:10px;display:flex;gap:8px;flex-wrap:wrap;">' +
      '<button type="button" class="btn btn-primary btn-sm" id="pspCtrCreate">صدور قرارداد برای انتخاب‌شده‌ها</button>' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspCtrLoad">بارگذاری لیست قراردادها</button>' +
      '<select id="pspCtrFilter"><option value="all">همه</option><option value="active">جاری</option><option value="pending">منتظر تأیید</option><option value="expired">پایان‌یافته</option><option value="unapproved">بدون تأیید حقوق</option></select>' +
      '</div>' +
      '<div id="pspCtrList" style="overflow:auto;max-height:420px;"></div>' +
      '<span id="pspCtrStatus" style="font-size:0.8rem;color:#0f766e;"></span>' +
      '<div style="margin-top:12px;padding:10px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;font-size:0.78rem;color:#9a3412;">' +
      'محاسبه حقوق فقط برای قرارداد <b>تأییدشده</b> مجاز است. آپلود فایل امضا فقط از همین صفحه توسط ادمین انجام می‌شود.' +
      '</div></div>' +

      '</div>';

    // insert panel after other panels
    var host = document.querySelector('.panel') && document.querySelector('.panel').parentNode;
    if (host) host.appendChild(panel);
    else document.body.appendChild(panel);
    try {
      var oldFab = document.getElementById('pspPortalFab');
      if (oldFab && oldFab.parentNode) oldFab.parentNode.removeChild(oldFab);
    } catch (e) {}

    (function(){
      function showSub(name){
        document.querySelectorAll('.psp-subtab').forEach(function(b){
          var on = b.getAttribute('data-sub') === name;
          b.classList.toggle('active', on);
          if (on) { b.style.background = '#0f766e'; b.style.color = '#fff'; b.classList.remove('btn-outline'); }
          else { b.style.background = ''; b.style.color = ''; b.classList.add('btn-outline'); }
        });
        document.querySelectorAll('.psp-subpanel').forEach(function(p){
          p.style.display = (p.id === 'pspSub-' + name) ? '' : 'none';
        });
        if (name === 'portalview') loadPortalViewCfg();
        if (name === 'contracts') { loadCtrEmployees(); loadContracts(); }
      }
      document.querySelectorAll('.psp-subtab').forEach(function(b){
        b.onclick = function(){ showSub(b.getAttribute('data-sub')); };
      });

      function pspToggleBreakFields() {
        var hb = document.getElementById('pspWsHasBreak');
        var on = !!(hb && hb.checked);
        ['pspWsBreakStart','pspWsBreakEnd','pspWsBreakAsWork'].forEach(function(id){
          var e = document.getElementById(id);
          if (!e) return;
          if (e.type === 'checkbox') {
            e.disabled = !on;
            if (!on) e.checked = false;
          } else {
            e.disabled = !on;
            e.style.opacity = on ? '' : '0.45';
          }
        });
      }
      var hbEl = document.getElementById('pspWsHasBreak');
      if (hbEl) {
        hbEl.addEventListener('change', pspToggleBreakFields);
        pspToggleBreakFields();
      }

      var sample = document.getElementById('pspUpSample');
      if (sample) sample.onclick = function(){
        alert('نمونه:\\nکد پرسنلی | تاریخ | ورود۱ | خروج۱ | ورود۲ | خروج۲ | اضافه‌کار | شب‌کاری | توضیح');
      };

      window.__pspPortalViewData = null;
      function loadPortalViewCfg(){
        var body = document.getElementById('pspPortalViewBody');
        if (!body) return;
        body.innerHTML = '<div style="color:#64748b;font-size:0.85rem;">در حال بارگذاری…</div>';
        fetch('/api/admin/portal-view', { credentials: 'same-origin' })
          .then(function(r){ return r.json(); })
          .then(function(j){
            if (!j.ok) { body.innerHTML = '<div style="color:#b91c1c;">خطا: ' + (j.message||j.error||'دسترسی') + '</div>'; return; }
            window.__pspPortalViewData = j;
            renderPortalViewCfg(j);
          })
          .catch(function(){ body.innerHTML = '<div style="color:#b91c1c;">خطا در ارتباط با سرور</div>'; });
      }
      function renderPortalViewCfg(j){
        var body = document.getElementById('pspPortalViewBody');
        var cfg = j.config || {};
        var dOpts = j.decreeOptions || [];
        var pOpts = j.profileOptions || [];
        var emps = j.employees || [];
        var dFields = cfg.decreeFields || [];
        var pFields = cfg.profileFields || [];
        var dCodes = cfg.decreeSelectedCodes || [];
        var pCodes = cfg.profileSelectedCodes || [];
        function modeSel(id, val){
          var opts = [
            ['self','فقط خود فرد (هر کس حکم/مشخصات خودش)'],
            ['self_and_manager','خود فرد + مدیران مستقیم'],
            ['all','همه کارکنان دارای پرتال'],
            ['selected','فقط افراد انتخاب‌شده (با تیک)']
          ];
          var h = '<select id="'+id+'" style="width:100%;padding:6px 8px;border:1px solid #99f6e4;border-radius:7px;font-size:0.82rem;margin-bottom:8px;">';
          opts.forEach(function(o){ h += '<option value="'+o[0]+'"'+(val===o[0]?' selected':'')+'>'+o[1]+'</option>'; });
          return h + '</select>';
        }
        function empChecks(prefix, selected){
          var h = '<div style="max-height:160px;overflow:auto;border:1px solid #e2e8f0;border-radius:8px;padding:8px;background:#fafafa;font-size:0.78rem;">';
          h += '<label style="display:block;margin-bottom:6px;"><input type="checkbox" id="'+prefix+'AllEmps"> انتخاب همه</label>';
          emps.forEach(function(e){
            var on = selected.indexOf(String(e.code))>=0;
            h += '<label style="display:block;margin:2px 0;"><input type="checkbox" class="'+prefix+'-emp" value="'+e.code+'"'+(on?' checked':'')+'> '+(e.fullName||'')+' ('+e.code+')'+(e.unit?' — '+e.unit:'')+'</label>';
          });
          return h + '</div>';
        }
        var html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">';
        // DECREE
        html += '<div style="border:1px solid #99f6e4;border-radius:10px;padding:12px;background:#fff;">';
        html += '<div style="font-weight:700;color:#0f766e;margin-bottom:8px;">تب «حکم»</div>';
        html += '<label style="display:flex;align-items:center;gap:6px;font-size:0.82rem;margin-bottom:8px;"><input type="checkbox" id="pspShowDecree"'+(cfg.showDecree!==false?' checked':'')+'> نمایش تب حکم</label>';
        html += '<label style="font-size:0.78rem;display:block;margin-bottom:4px;">چه کسانی ببینند؟</label>';
        html += modeSel('pspDecreeMode', cfg.decreeMode||'self');
        html += '<div id="pspDecreeEmpWrap" style="'+(cfg.decreeMode==='selected'?'':'display:none;')+'margin-bottom:8px;"><label style="font-size:0.78rem;">انتخاب افراد:</label>'+empChecks('pspDec', dCodes)+'</div>';
        html += '<label style="font-size:0.78rem;display:block;margin-bottom:4px;">آیتم‌های حکم (از انتقال انتخابی / مزایا / آیتم‌های کارمند):</label>';
        html += '<div style="max-height:180px;overflow:auto;border:1px solid #e2e8f0;border-radius:8px;padding:8px;background:#fafafa;font-size:0.78rem;">';
        html += '<label style="display:block;margin-bottom:4px;"><input type="checkbox" id="pspDecFieldAll"> همه آیتم‌ها</label>';
        dOpts.forEach(function(o){
          var on = !dFields.length || dFields.indexOf(String(o.id))>=0 || dFields.indexOf(String(o.name))>=0;
          html += '<label style="display:block;margin:2px 0;"><input type="checkbox" class="psp-dec-field" value="'+String(o.id).replace(/"/g,'&quot;')+'" data-name="'+String(o.name).replace(/"/g,'&quot;')+'"'+(on?' checked':'')+'> '+o.name+'</label>';
        });
        if (!dOpts.length) html += '<div style="color:#64748b;">آیتمی در حکم/مزایا یافت نشد.</div>';
        html += '</div></div>';
        // PROFILE
        html += '<div style="border:1px solid #99f6e4;border-radius:10px;padding:12px;background:#fff;">';
        html += '<div style="font-weight:700;color:#0f766e;margin-bottom:8px;">تب «مشخصات پرسنلی»</div>';
        html += '<label style="display:flex;align-items:center;gap:6px;font-size:0.82rem;margin-bottom:8px;"><input type="checkbox" id="pspShowProfile"'+(cfg.showProfile!==false?' checked':'')+'> نمایش تب مشخصات</label>';
        html += '<label style="font-size:0.78rem;display:block;margin-bottom:4px;">چه کسانی ببینند؟</label>';
        html += modeSel('pspProfileMode', cfg.profileMode||'self');
        html += '<div id="pspProfileEmpWrap" style="'+(cfg.profileMode==='selected'?'':'display:none;')+'margin-bottom:8px;"><label style="font-size:0.78rem;">انتخاب افراد:</label>'+empChecks('pspProf', pCodes)+'</div>';
        html += '<label style="font-size:0.78rem;display:block;margin-bottom:4px;">فیلدهای کارت کارمند:</label>';
        html += '<div style="max-height:180px;overflow:auto;border:1px solid #e2e8f0;border-radius:8px;padding:8px;background:#fafafa;font-size:0.78rem;">';
        html += '<label style="display:block;margin-bottom:4px;"><input type="checkbox" id="pspProfFieldAll"> همه فیلدها</label>';
        pOpts.forEach(function(o){
          var on = !pFields.length || pFields.indexOf(o.key)>=0;
          html += '<label style="display:block;margin:2px 0;"><input type="checkbox" class="psp-prof-field" value="'+o.key+'"'+(on?' checked':'')+'> '+o.label+'</label>';
        });
        html += '</div></div></div>';
        body.innerHTML = html;
        function bindAll(allId, cls){
          var all = document.getElementById(allId);
          if (!all) return;
          all.onchange = function(){
            document.querySelectorAll('.'+cls).forEach(function(c){ c.checked = all.checked; });
          };
        }
        bindAll('pspDecFieldAll', 'psp-dec-field');
        bindAll('pspProfFieldAll', 'psp-prof-field');
        bindAll('pspDecAllEmps', 'pspDec-emp');
        bindAll('pspProfAllEmps', 'pspProf-emp');
        var dm = document.getElementById('pspDecreeMode');
        if (dm) dm.onchange = function(){ document.getElementById('pspDecreeEmpWrap').style.display = dm.value==='selected'?'':'none'; };
        var pm = document.getElementById('pspProfileMode');
        if (pm) pm.onchange = function(){ document.getElementById('pspProfileEmpWrap').style.display = pm.value==='selected'?'':'none'; };
      }
      var saveBtn = document.getElementById('pspPortalViewSave');
      if (saveBtn) saveBtn.onclick = function(){
        var st = document.getElementById('pspPortalViewStatus');
        st.textContent = 'در حال ذخیره…';
        var payload = {
          showDecree: !!(document.getElementById('pspShowDecree')||{}).checked,
          decreeMode: (document.getElementById('pspDecreeMode')||{}).value || 'self',
          decreeSelectedCodes: Array.prototype.map.call(document.querySelectorAll('.pspDec-emp:checked'), function(c){ return c.value; }),
          decreeFields: Array.prototype.map.call(document.querySelectorAll('.psp-dec-field:checked'), function(c){ return c.value; }),
          showProfile: !!(document.getElementById('pspShowProfile')||{}).checked,
          profileMode: (document.getElementById('pspProfileMode')||{}).value || 'self',
          profileSelectedCodes: Array.prototype.map.call(document.querySelectorAll('.pspProf-emp:checked'), function(c){ return c.value; }),
          profileFields: Array.prototype.map.call(document.querySelectorAll('.psp-prof-field:checked'), function(c){ return c.value; })
        };
        fetch('/api/admin/portal-view', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify(payload)
        }).then(function(r){ return r.json(); }).then(function(j){
          if (j.ok) { st.style.color = '#16a34a'; st.textContent = 'ذخیره شد.'; }
          else { st.style.color = '#b91c1c'; st.textContent = j.message || j.error || 'خطا'; }
        }).catch(function(){ st.style.color = '#b91c1c'; st.textContent = 'خطا در ارتباط'; });
      };
      
      var rel = document.getElementById('pspPortalViewReload');
      if (rel) rel.onclick = loadPortalViewCfg;

      
      // ---- Contracts ----
      window.__pspCtrEmps = [];
      function ctrTypeFa(t){
        return ({fixed:'مدت‌موقت',permanent:'دائم',hourly:'ساعتی',daily:'روزمزد',other:'سایر'})[t]||t||'—';
      }
      function ctrStatusFa(c){
        if (c.adminApproved) {
          if (c.status === 'expired' || c.status === 'terminated') return '<span style="color:#b45309">پایان‌یافته</span>';
          return '<span style="color:#15803d">تأییدشده / جاری</span>';
        }
        return '<span style="color:#b91c1c">منتظر تأیید ادمین</span>';
      }
      function loadCtrEmployees(){
        fetch('/api/admin/portal-view', { credentials:'same-origin' })
          .then(function(r){ return r.json(); })
          .then(function(j){
            if (!j.ok) return;
            window.__pspCtrEmps = j.employees || [];
            renderCtrEmpList();
          }).catch(function(){});
      }
      function updateCtrEmpSummary(){
        var n = document.querySelectorAll('.psp-ctr-emp:checked').length;
        var sum = document.getElementById('pspCtrEmpSummary');
        if (!sum) return;
        if (n === 0) sum.textContent = 'انتخاب کارکنان — هیچ‌کس انتخاب نشده';
        else sum.textContent = 'انتخاب کارکنان — ' + n + ' نفر انتخاب شده';
      }
      function renderCtrEmpList(){
        var box = document.getElementById('pspCtrEmpList');
        if (!box) return;
        var q = ((document.getElementById('pspCtrEmpSearch')||{}).value || '').trim().toLowerCase();
        var prevChecked = {};
        document.querySelectorAll('.psp-ctr-emp:checked').forEach(function(c){ prevChecked[c.value] = true; });
        var list = window.__pspCtrEmps || [];
        if (q) {
          list = list.filter(function(e){
            return String(e.code).toLowerCase().indexOf(q) >= 0 || String(e.fullName||'').toLowerCase().indexOf(q) >= 0;
          });
        }
        if (!list.length) {
          box.innerHTML = '<div style="color:#64748b;padding:6px;">کارمندی یافت نشد.</div>';
          updateCtrEmpSummary();
          return;
        }
        var html = '';
        list.forEach(function(e){
          var ck = prevChecked[String(e.code)] ? ' checked' : '';
          html += '<label style="display:flex;align-items:center;gap:8px;margin:0;padding:5px 6px;border-radius:6px;cursor:pointer;">' +
            '<input type="checkbox" class="psp-ctr-emp" value="'+e.code+'"'+ck+'>' +
            '<span style="flex:1;">'+(e.fullName||'')+'</span>' +
            '<span style="color:#64748b;font-size:0.72rem;direction:ltr;">'+e.code+(e.unit?' · '+e.unit:'')+'</span></label>';
        });
        box.innerHTML = html;
        box.querySelectorAll('.psp-ctr-emp').forEach(function(c){
          c.onchange = updateCtrEmpSummary;
        });
        updateCtrEmpSummary();
      }
      function selectedCtrCodes(){
        return Array.prototype.map.call(document.querySelectorAll('.psp-ctr-emp:checked'), function(c){ return c.value; });
      }
      function loadContracts(){
        var st = document.getElementById('pspCtrStatus');
        if (st) st.textContent = 'در حال بارگذاری…';
        var filter = (document.getElementById('pspCtrFilter')||{}).value || 'all';
        fetch('/api/admin/contracts?filter=' + encodeURIComponent(filter), { credentials:'same-origin' })
          .then(function(r){ return r.json(); })
          .then(function(j){
            if (!j.ok) { if (st) st.textContent = j.message||j.error||'خطا'; return; }
            renderContracts(j.contracts||[]);
            if (st) st.textContent = (j.contracts||[]).length + ' قرارداد';
          }).catch(function(){ if (st) st.textContent = 'خطا در ارتباط'; });
      }
      function renderContracts(list){
        var box = document.getElementById('pspCtrList');
        if (!box) return;
        if (!list.length) { box.innerHTML = '<p style="font-size:0.85rem;color:#64748b;">قراردادی ثبت نشده.</p>'; return; }
        var html = '<table style="font-size:0.75rem;min-width:1100px;"><thead><tr>'+
          '<th>کد</th><th>نام</th><th>نوع</th><th>از</th><th>تا</th><th>وضعیت</th><th>محاسبه حقوق</th>'+
          '<th>نمایش مدت</th><th>قابل مشاهده در پرتال</th><th>فایل امضا (ادمین)</th><th>عملیات</th></tr></thead><tbody>';
        list.forEach(function(c){
          html += '<tr data-id="'+c.id+'">'+
            '<td>'+c.empCode+'</td><td>'+(c.empName||'')+'</td><td>'+ctrTypeFa(c.type)+'</td>'+
            '<td dir="ltr">'+(c.startDate||'')+'</td><td dir="ltr">'+(c.endDate||'')+'</td>'+
            '<td>'+ctrStatusFa(c)+'</td>'+
            '<td>'+(c.adminApproved?'<span style="color:#15803d">مجاز</span>':'<span style="color:#b91c1c">غیرمجاز</span>')+'</td>'+
            '<td style="text-align:center;"><input type="checkbox" class="psp-ctr-showdur" data-id="'+c.id+'"'+(c.showDurationToEmployee?' checked':'')+'></td>'+
            '<td style="text-align:center;"><input type="checkbox" class="psp-ctr-visible" data-id="'+c.id+'"'+(c.visibleToEmployee!==false?' checked':'')+'></td>'+
            '<td style="font-size:0.72rem;min-width:140px;">'+
              (c.signedFileName?('<div>✓ '+c.signedFileName+'</div>'):'<div style="color:#64748b;">—</div>')+
              '<label style="color:#0f766e;cursor:pointer;font-size:0.72rem;">آپلود<input type="file" class="psp-ctr-upload" data-id="'+c.id+'" accept=".pdf,.jpg,.jpeg,.png,.webp" style="display:none;"></label>'+
            '</td>'+
            '<td style="white-space:nowrap;">'+
              (c.adminApproved?'':'<button type="button" class="btn btn-primary btn-sm psp-ctr-approve" data-id="'+c.id+'">تأیید حقوق</button> ')+
              (c.adminApproved?'<button type="button" class="btn btn-outline btn-sm psp-ctr-revoke" data-id="'+c.id+'">لغو تأیید</button> ':'')+
              '<button type="button" class="btn btn-outline btn-sm psp-ctr-del" data-id="'+c.id+'" style="color:#b91c1c;">حذف</button>'+
            '</td></tr>';
        });
        html += '</tbody></table>';
        box.innerHTML = html;
        box.querySelectorAll('.psp-ctr-approve').forEach(function(b){
          b.onclick = function(){ ctrAction(b.getAttribute('data-id'), 'approve'); };
        });
        box.querySelectorAll('.psp-ctr-revoke').forEach(function(b){
          b.onclick = function(){ if(confirm('لغو تأیید محاسبه حقوق؟')) ctrAction(b.getAttribute('data-id'), 'revoke'); };
        });
        box.querySelectorAll('.psp-ctr-del').forEach(function(b){
          b.onclick = function(){
            var id = b.getAttribute('data-id');
            if (!confirm('حذف قرارداد؟ (تأیید ۱ از ۲)')) return;
            if (!confirm('آیا مطمئن هستید؟ قابل بازگشت نیست. (تأیید ۲ از ۲)')) return;
            ctrAction(id, 'delete');
          };
        });
        box.querySelectorAll('.psp-ctr-showdur').forEach(function(c){
          c.onchange = function(){
            fetch('/api/admin/contracts', {
              method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
              body: JSON.stringify({ action:'set_show_duration', id: c.getAttribute('data-id'), showDurationToEmployee: !!c.checked })
            }).then(function(r){return r.json();}).then(function(j){
              var st=document.getElementById('pspCtrStatus');
              if (st) st.textContent = j.ok ? 'ذخیره شد' : (j.message||'خطا');
            });
          };
        });
        box.querySelectorAll('.psp-ctr-visible').forEach(function(c){
          c.onchange = function(){
            fetch('/api/admin/contracts', {
              method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
              body: JSON.stringify({ action:'set_visible', id: c.getAttribute('data-id'), visibleToEmployee: !!c.checked })
            }).then(function(r){return r.json();}).then(function(j){
              var st=document.getElementById('pspCtrStatus');
              if (st) st.textContent = j.ok ? 'ذخیره شد' : (j.message||'خطا');
            });
          };
        });
        box.querySelectorAll('.psp-ctr-upload').forEach(function(inp){
          inp.onchange = function(){
            var f = inp.files && inp.files[0];
            if (!f) return;
            if (f.size > 400000) { alert('حداکثر حجم حدود ۳۵۰KB'); return; }
            var reader = new FileReader();
            reader.onload = function(){
              fetch('/api/admin/contracts', {
                method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
                body: JSON.stringify({
                  action: 'upload_signed',
                  id: inp.getAttribute('data-id'),
                  fileName: f.name,
                  fileData: reader.result
                })
              }).then(function(r){return r.json();}).then(function(j){
                var st=document.getElementById('pspCtrStatus');
                if (!j.ok) { if(st) st.textContent = j.message||'خطا'; alert(j.message||'خطا'); return; }
                if (st) st.textContent = 'فایل امضا ثبت شد.';
                loadContracts();
              });
            };
            reader.readAsDataURL(f);
          };
        });
      }
      function ctrAction(id, action){
        fetch('/api/admin/contracts', {
          method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
          body: JSON.stringify({ action: action, id: id })
        }).then(function(r){return r.json();}).then(function(j){
          var st=document.getElementById('pspCtrStatus');
          if (!j.ok) { if(st) st.textContent = j.message||j.error||'خطا'; return; }
          if (st) st.textContent = action==='delete'?'حذف شد.':(action==='approve'?'تأیید شد.':'انجام شد.');
          loadContracts();
        });
      }
      function parseCodesFromText(text){
        var codes = [];
        var lines = String(text||'').split(/\\r?\\n/);
        lines.forEach(function(line, idx){
          var cells = line.split(/[,;\\t]/);
          if (!cells.length) return;
          // header skip
          var first = (cells[0]||'').trim().replace(/^["']|["']$/g,'');
          if (idx === 0 && /code|کد|پرسنل/i.test(first)) {
            // find code column
            return;
          }
          if (idx === 0 && /code|کد/i.test(line)) {
            var hi = cells.findIndex(function(c){ return /code|کد/i.test(c); });
            if (hi >= 0) {
              // process rest of lines with that col - store on window
              window.__pspCtrExcelCol = hi;
              return;
            }
          }
          var col = window.__pspCtrExcelCol != null ? window.__pspCtrExcelCol : 0;
          var code = (cells[col]||cells[0]||'').trim().replace(/^["']|["']$/g,'');
          if (code && !/code|کد|نام/i.test(code) && codes.indexOf(code) < 0) codes.push(code);
        });
        window.__pspCtrExcelCol = null;
        return codes;
      }
      var ctrCreate = document.getElementById('pspCtrCreate');
      if (ctrCreate) ctrCreate.onclick = function(){
        var codes = selectedCtrCodes();
        if (!codes.length) { alert('حداقل یک نفر را از لیست تیک بزنید.'); return; }
        var body = {
          action: 'create',
          codes: codes,
          startDate: (document.getElementById('pspCtrFrom').value||'').trim(),
          endDate: (document.getElementById('pspCtrTo').value||'').trim(),
          type: document.getElementById('pspCtrType').value,
          note: (document.getElementById('pspCtrNote').value||'').trim(),
          showDurationToEmployee: !!(document.getElementById('pspCtrShowDurDef')||{}).checked,
          visibleToEmployee: !!(document.getElementById('pspCtrVisibleDef')||{}).checked
        };
        if (!body.startDate) { alert('تاریخ شروع الزامی است.'); return; }
        fetch('/api/admin/contracts', {
          method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
          body: JSON.stringify(body)
        }).then(function(r){return r.json();}).then(function(j){
          var st=document.getElementById('pspCtrStatus');
          if (!j.ok) { if(st) st.textContent = j.message||j.error||'خطا'; alert(j.message||'خطا'); return; }
          if (st) st.textContent = (j.created||0)+' قرارداد ایجاد شد.';
          loadContracts();
        });
      };
      var ctrLoad = document.getElementById('pspCtrLoad');
      if (ctrLoad) ctrLoad.onclick = loadContracts;
      var ctrFilter = document.getElementById('pspCtrFilter');
      if (ctrFilter) ctrFilter.onchange = loadContracts;
      var empSearch = document.getElementById('pspCtrEmpSearch');
      if (empSearch) empSearch.oninput = renderCtrEmpList;
      var empAll = document.getElementById('pspCtrEmpAll');
      if (empAll) empAll.onchange = function(){
        document.querySelectorAll('.psp-ctr-emp').forEach(function(c){ c.checked = empAll.checked; });
        updateCtrEmpSummary();
      };
      var empToggle = document.getElementById('pspCtrEmpToggle');
      if (empToggle) empToggle.onclick = function(){
        var dd = document.getElementById('pspCtrEmpDropdown');
        var ch = document.getElementById('pspCtrEmpChevron');
        if (!dd) return;
        var open = dd.style.display === 'none' || !dd.style.display;
        // currently hidden if display none
        if (dd.style.display === 'none') {
          dd.style.display = 'block';
          if (ch) ch.textContent = '▲ بستن';
          if (!(window.__pspCtrEmps||[]).length) loadCtrEmployees();
          else renderCtrEmpList();
        } else {
          dd.style.display = 'none';
          if (ch) ch.textContent = '▼ باز کردن';
        }
      };
      var excelInp = document.getElementById('pspCtrExcel');
      if (excelInp) excelInp.onchange = function(){
        var f = excelInp.files && excelInp.files[0];
        if (!f) return;
        var reader = new FileReader();
        reader.onload = function(){
          var codes = parseCodesFromText(reader.result);
          if (!codes.length) { alert('کدی از فایل خوانده نشد. ستون اول را کد پرسنلی بگذارید.'); return; }
          // tick matching employees
          var set = {};
          codes.forEach(function(c){ set[String(c)] = true; });
          document.querySelectorAll('.psp-ctr-emp').forEach(function(cb){
            if (set[cb.value]) cb.checked = true;
          });
          // if some codes not in current filter list, expand: clear search and retick
          var missing = codes.filter(function(c){
            return !(window.__pspCtrEmps||[]).some(function(e){ return String(e.code)===String(c); });
          });
          var st=document.getElementById('pspCtrStatus');
          updateCtrEmpSummary();
          if (st) st.textContent = codes.length + ' کد از فایل — ' + document.querySelectorAll('.psp-ctr-emp:checked').length + ' نفر تیک خورد' +
            (missing.length ? (' | یافت‌نشده: '+missing.slice(0,10).join(', ')) : '');
          excelInp.value = '';
        };
        reader.readAsText(f);
      };
      // preload employees when opening contracts tab
      var _origShowSub = null;
    })()
    try {
;



    var __tsLoad = document.getElementById('pspTsLoad');
    if (__tsLoad) __tsLoad.onclick = function() {
      fetch('/api/admin/timesheet', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({
          year: Number(document.getElementById('pspTsYear').value),
          month: Number(document.getElementById('pspTsMonth').value),
          code: document.getElementById('pspTsCode').value.trim(),
          managerCode: document.getElementById('pspTsMgr').value.trim()
        })
      }).then(function(r){ return r.json(); }).then(function(j){
        var out = document.getElementById('pspTsOut');
        if (!j.ok) { out.innerHTML = '<p style="color:#b91c1c">' + (j.error || 'خطا') + '</p>'; return; }
        var html = '';
        if (j.daily && j.daily.days) {
          var sch = j.daily.schedule || {};
          var sumWork = 0, sumDelay = 0, sumOt = 0, sumEarly = 0, filled = 0;
          j.daily.days.forEach(function(d){
            if (d.in1 || d.out1 || d.in2 || d.out2) filled++;
            sumWork += Number(d.workHours) || 0;
            sumDelay += Number(d.delayMin) || 0;
            sumEarly += Number(d.earlyMin) || 0;
            sumOt += Number(d.otHours) || 0;
          });
          html += '<p style="font-size:0.85rem;margin-bottom:6px;"><b>' + (j.daily.fullName||'') + '</b> — کد ' + j.daily.code + ' — ' + j.year + '/' + j.month;
          html += ' <span style="color:#64748b;font-size:0.75rem;">| شیفت ' + (sch.workStart||'') + '–' + (sch.workEnd||'') + (sch.hasBreak?(' وقفه '+sch.breakStart+'-'+sch.breakEnd):' بدون وقفه') + ' | رسمی ' + ((sch.officialMinutes||0)/60).toFixed(1) + 'س</span></p>';
          html += '<div style="margin-bottom:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">' +
            '<button type="button" class="btn btn-primary btn-sm" id="pspTsSaveDays">ذخیره ورود/خروج ماه</button>' +
            '<button type="button" class="btn btn-outline btn-sm" id="pspTsSample">نمونه اکسل</button>' +
            '<label class="btn btn-outline btn-sm" style="margin:0;cursor:pointer;">بارگذاری فایل<input type="file" id="pspTsFile" accept=".csv,.txt,.xlsx" style="display:none;"></label>' +
            '<span id="pspTsDayStatus" style="font-size:0.78rem;color:#0f766e;"></span></div>';
          html += '<p style="font-size:0.75rem;color:#0f766e;margin-bottom:6px;">روزهای دارای رکورد: <b>' + filled + '</b> | جمع کار: <b>' + sumWork.toFixed(2) + '</b> س | تأخیر: <b>' + sumDelay + '</b> د | تعجیل: <b>' + sumEarly + '</b> د | اضافه‌کار: <b>' + sumOt.toFixed(2) + '</b> س</p>';
          html += '<div style="overflow:auto;"><table style="font-size:0.72rem;min-width:1100px;"><thead><tr>' +
            '<th>تاریخ</th><th>روز</th><th>ورود۱</th><th>خروج۱</th><th>ورود۲</th><th>خروج۲</th>' +
            '<th>کار(س)</th><th>تأخیر(د)</th><th>تعجیل(د)</th><th>اضافه(س)</th>' +
            '<th>مأموریت</th><th>مرخصی</th><th>توضیح</th>' +
            '</tr></thead><tbody>';
          j.daily.days.forEach(function(d, idx){
            var bg = d.isNonWork ? 'background:#fef2f2;' : '';
            html += '<tr style="'+bg+'" data-ts-day="'+idx+'">' +
              '<td data-date="'+d.date+'">' + d.date + '</td><td>' + (d.weekday||'') + '</td>' +
              '<td><input class="ts-in1" value="'+(d.in1||'')+'" style="width:58px;padding:2px;" dir="ltr" placeholder="08:00"></td>' +
              '<td><input class="ts-out1" value="'+(d.out1||'')+'" style="width:58px;padding:2px;" dir="ltr" placeholder="12:00"></td>' +
              '<td><input class="ts-in2" value="'+(d.in2||'')+'" style="width:58px;padding:2px;" dir="ltr"></td>' +
              '<td><input class="ts-out2" value="'+(d.out2||'')+'" style="width:58px;padding:2px;" dir="ltr"></td>' +
              '<td>' + (d.workHours!=null?d.workHours:'') + '</td>' +
              '<td>' + (d.delayMin||'') + '</td><td>' + (d.earlyMin||'') + '</td><td>' + (d.otHours||'') + '</td>' +
              '<td>' + [d.missionDaily,d.missionHourly].filter(Boolean).join(' / ') + '</td>' +
              '<td>' + [d.leaveDaily,d.leaveHourly].filter(Boolean).join(' / ') + '</td>' +
              '<td><input class="ts-note" value="'+(d.note||'').replace(/"/g,'&quot;')+'" style="width:90px;padding:2px;"></td></tr>';
          });
          html += '</tbody></table></div>';
          window.__pspTsDaily = j.daily;
          window.__pspTsYear = j.year;
          window.__pspTsMonth = j.month;
          setTimeout(function(){
            function collectDays(){
              var days = [];
              document.querySelectorAll('#pspTsOut tr[data-ts-day]').forEach(function(tr){
                var date = (tr.querySelector('[data-date]')||{}).getAttribute('data-date');
                if (!date) return;
                days.push({
                  date: date,
                  in1: (tr.querySelector('.ts-in1')||{}).value || '',
                  out1: (tr.querySelector('.ts-out1')||{}).value || '',
                  in2: (tr.querySelector('.ts-in2')||{}).value || '',
                  out2: (tr.querySelector('.ts-out2')||{}).value || '',
                  note: (tr.querySelector('.ts-note')||{}).value || ''
                });
              });
              return days;
            }
            function saveDays(thenReload){
              var days = collectDays();
              var st = document.getElementById('pspTsDayStatus');
              if (st) st.textContent = 'ذخیره…';
              return fetch('/api/admin/timesheet-days', {
                method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
                body: JSON.stringify({
                  code: (window.__pspTsDaily||{}).code,
                  year: window.__pspTsYear,
                  month: window.__pspTsMonth,
                  updateWorkDays: true,
                  days: days
                })
              }).then(function(r){return r.json()}).then(function(res){
                if (st) {
                  if (res.ok) {
                    st.style.color='#16a34a';
                    st.textContent = 'ذخیره شد ('+(res.saved||0)+' روز).';
                    if (thenReload) setTimeout(function(){ var b=document.getElementById('pspTsLoad'); if(b) b.click(); }, 400);
                  } else { st.style.color='#b91c1c'; st.textContent = res.message||res.error||'خطا'; }
                }
                return res;
              }).catch(function(){ if(st){ st.style.color='#b91c1c'; st.textContent='خطا در ارتباط'; }});
            }
            var btn = document.getElementById('pspTsSaveDays');
            if (btn) btn.onclick = function(){ saveDays(true); };
            var sample = document.getElementById('pspTsSample');
            if (sample) sample.onclick = function(){
              var lines = ['تاریخ,ورود1,خروج1,ورود2,خروج2,توضیح'];
              var y = window.__pspTsYear, m = window.__pspTsMonth;
              for (var d=1; d<=3; d++) {
                var ds = y + '/' + String(m).padStart(2,'0') + '/' + String(d).padStart(2,'0');
                lines.push(ds + ',08:00,12:00,13:00,17:05,');
              }
              var blob = new Blob([lines.join('\n')], {type:'text/csv;charset=utf-8'});
              var a = document.createElement('a');
              a.href = URL.createObjectURL(blob);
              a.download = 'timesheet-sample.csv';
              a.click();
            };
            var finp = document.getElementById('pspTsFile');
            if (finp) finp.onchange = function(){
              var f = finp.files && finp.files[0];
              if (!f) return;
              var reader = new FileReader();
              reader.onload = function(){
                var text = String(reader.result||'');
                var lines = text.split(/\r?\n/).filter(function(l){ return l.trim(); });
                var map = {};
                lines.forEach(function(line, li){
                  var parts = line.split(/[,;\t|]/);
                  if (!parts.length) return;
                  var date = (parts[0]||'').trim().replace(/-/g,'/');
                  if (!/\d{4}\/\d{1,2}\/\d{1,2}/.test(date)) return;
                  // normalize pad
                  var p = date.split('/');
                  date = p[0] + '/' + String(Number(p[1])).padStart(2,'0') + '/' + String(Number(p[2])).padStart(2,'0');
                  map[date] = {
                    in1: (parts[1]||'').trim(),
                    out1: (parts[2]||'').trim(),
                    in2: (parts[3]||'').trim(),
                    out2: (parts[4]||'').trim(),
                    note: (parts[5]||'').trim()
                  };
                });
                var n = 0;
                document.querySelectorAll('#pspTsOut tr[data-ts-day]').forEach(function(tr){
                  var date = (tr.querySelector('[data-date]')||{}).getAttribute('data-date');
                  if (!date || !map[date]) return;
                  var r = map[date];
                  var el;
                  el = tr.querySelector('.ts-in1'); if (el) el.value = r.in1;
                  el = tr.querySelector('.ts-out1'); if (el) el.value = r.out1;
                  el = tr.querySelector('.ts-in2'); if (el) el.value = r.in2;
                  el = tr.querySelector('.ts-out2'); if (el) el.value = r.out2;
                  el = tr.querySelector('.ts-note'); if (el && r.note) el.value = r.note;
                  n++;
                });
                var st = document.getElementById('pspTsDayStatus');
                if (st) { st.style.color='#0f766e'; st.textContent = n + ' روز از فایل در جدول قرار گرفت. «ذخیره» را بزنید.'; }
              };
              reader.readAsText(f);
            };
          }, 50);
                } else if (!document.getElementById('pspTsCode').value.trim()) {
          html += '<p style="font-size:0.8rem;color:#0f766e;margin-bottom:8px;">برای جدول روزبه‌روز و ثبت ورود/خروج، یک کد پرسنلی وارد کنید.</p>';
        }
        var rows = (j.rows || []).map(function(x){
          return '<tr><td>' + x.code + '</td><td>' + x.fullName + '</td><td>' + (x.unit||'') + '</td><td>' + (x.managerCode||'') + '</td><td>' + x.workDays + '</td><td>' + x.leaveDays + '</td><td>' + x.hourlyLeave + '</td><td>' + x.missions + '</td><td>' + x.leaves + '</td></tr>';
        }).join('');
        html += '<h4 style="margin-top:14px;">خلاصه ماه</h4><table><thead><tr><th>کد</th><th>نام</th><th>واحد</th><th>مدیر</th><th>کارکرد</th><th>مرخصی روز</th><th>مرخصی ساعت</th><th>مأموریت</th><th>مرخصی</th></tr></thead><tbody>' + rows + '</tbody></table>';
        out.innerHTML = html;
      });
    };

    function pspSelectedCt() {
      var el = document.getElementById('pspCalContractType');
      return (el && el.value) ? el.value : 'normal';
    }
    function pspFillContractTypes(list, selected) {
      var sel = document.getElementById('pspCalContractType');
      if (!sel) return;
      var cur = selected || sel.value || 'normal';
      sel.innerHTML = (list || []).map(function(t){
        return '<option value="'+t.id+'"'+(t.id===cur?' selected':'')+'>'+(t.name||t.id)+'</option>';
      }).join('');
      if (!sel.value && list && list[0]) sel.value = list[0].id;
    }
    function pspLoadCalForCt() {
      var ct = pspSelectedCt();
      fetch('/api/admin/get-current-month?contractType='+encodeURIComponent(ct), { credentials:'same-origin' })
        .then(function(r){return r.json()}).then(function(j){
          if (!j || !j.ok) return;
          if (j.year) { var y=document.getElementById('pspCurYear'); if(y) y.value=j.year; }
          if (j.month) { var m=document.getElementById('pspCurMonth'); if(m) m.value=String(j.month); }
          if (Array.isArray(j.workWeekDays)) {
            document.querySelectorAll('.psp-wd').forEach(function(c){
              c.checked = j.workWeekDays.indexOf(Number(c.value)) >= 0;
            });
          }
          var nw=document.getElementById('pspCountNonWorkAsLeave');
          if (nw) nw.value = j.countNonWorkDaysAsLeave ? 'yes' : 'no';
          function setT(id,v){ var el=document.getElementById(id); if(el&&v!=null) el.value=v; }
          setT('pspWsStart', j.workStart||'08:00');
          setT('pspWsEnd', j.workEnd||'17:00');
          setT('pspWsBreakStart', j.breakStart||'12:00');
          setT('pspWsBreakEnd', j.breakEnd||'13:00');
          setT('pspWsDayEnd', j.dayEnd||'23:59');
          setT('pspWsFloat', j.floatMinutes!=null?j.floatMinutes:15);
          var hb=document.getElementById('pspWsHasBreak');
          if(hb){
            hb.checked=!!j.hasBreak;
            hb.onchange && hb.onchange();
            // force enable state
            var on=!!j.hasBreak;
            ['pspWsBreakStart','pspWsBreakEnd','pspWsBreakAsWork'].forEach(function(id){
              var e=document.getElementById(id); if(!e)return;
              if(e.type==='checkbox'){ e.disabled=!on; } else { e.disabled=!on; e.style.opacity=on?'':'0.45'; }
            });
          }
          var ba=document.getElementById('pspWsBreakAsWork'); if(ba){ ba.checked=!!j.breakCountsAsWork; ba.disabled=!j.hasBreak; }
          var fc=document.getElementById('pspWsFloatComp'); if(fc) fc.checked=!!j.floatCompensate;
          pspFillContractTypes(j.contractTypesList || [], ct);
          var st=document.getElementById('pspCurStatus');
          if (st && j.month) { st.style.color='#0f766e'; st.textContent='ماه جاری: '+j.year+'/'+j.month+' | تقویم: '+(j.contractTypeName||ct); }
        }).catch(function(){});
    }
    document.getElementById('pspCurSave').onclick = function(){
      var wds = [];
      document.querySelectorAll('.psp-wd:checked').forEach(function(c){ wds.push(Number(c.value)); });
      var st = document.getElementById('pspCurStatus');
      if (st) st.textContent = 'در حال ذخیره…';
      fetch('/api/admin/set-current-month', {
        method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
        body: JSON.stringify({
          year: Number(document.getElementById('pspCurYear').value),
          month: Number(document.getElementById('pspCurMonth').value),
          contractType: pspSelectedCt(),
          workWeekDays: wds,
          countNonWorkDaysAsLeave: (document.getElementById('pspCountNonWorkAsLeave')||{}).value === 'yes',
          workStart: (document.getElementById('pspWsStart')||{}).value || '08:00',
          workEnd: (document.getElementById('pspWsEnd')||{}).value || '17:00',
          breakStart: (document.getElementById('pspWsBreakStart')||{}).value || '12:00',
          breakEnd: (document.getElementById('pspWsBreakEnd')||{}).value || '13:00',
          dayEnd: (document.getElementById('pspWsDayEnd')||{}).value || '23:59',
          floatMinutes: Number((document.getElementById('pspWsFloat')||{}).value) || 0,
          hasBreak: !!(document.getElementById('pspWsHasBreak')||{}).checked,
          breakCountsAsWork: !!(document.getElementById('pspWsBreakAsWork')||{}).checked,
          floatCompensate: !!(document.getElementById('pspWsFloatComp')||{}).checked
        })
      }).then(function(r){return r.json()}).then(function(j){
        if (j.ok) {
          var msg = 'ثبت شد: ماه '+j.year+'/'+j.month+' + روزهای کاری نوع «'+(j.contractType||'')+'»';
          if (st) { st.style.color='#16a34a'; st.textContent = msg; }
          else alert(msg);
          if (j.contractTypesList) pspFillContractTypes(j.contractTypesList, j.contractType);
        } else {
          var err = j.message||j.error||'خطا';
          if (st) { st.style.color='#b91c1c'; st.textContent = err; }
          else alert(err);
        }
      }).catch(function(){ if(st){ st.style.color='#b91c1c'; st.textContent='خطا در ارتباط'; }});
    };
    var ctSel = document.getElementById('pspCalContractType');
    if (ctSel) ctSel.onchange = function(){ pspLoadCalForCt(); var y=document.getElementById('pspCalYear'); if(y){ /* auto reload holidays */ var b=document.getElementById('pspCalLoad'); if(b) b.click(); } };
    var addCt = document.getElementById('pspAddCtBtn');
    if (addCt) addCt.onclick = function(){
      var id = ((document.getElementById('pspNewCtId')||{}).value||'').trim();
      var name = ((document.getElementById('pspNewCtName')||{}).value||'').trim();
      if (!id || !name) { alert('شناسه و نام نوع قرارداد الزامی است'); return; }
      if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(id)) { alert('شناسه باید انگلیسی باشد (حروف و عدد)'); return; }
      fetch('/api/admin/contract-types', {
        method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
        body: JSON.stringify({ id: id, name: name })
      }).then(function(r){return r.json()}).then(function(j){
        if (!j.ok) { alert(j.message||j.error||'خطا'); return; }
        pspFillContractTypes(j.contractTypesList || [], id);
        var st=document.getElementById('pspCurStatus');
        if (st) { st.style.color='#16a34a'; st.textContent='نوع قرارداد «'+name+'» اضافه شد و در کارت کارمند قابل انتخاب است'; }
        pspLoadCalForCt();
      });
    };
    // بارگذاری ماه جاری + لیست نوع قرارداد + تقویم نوع انتخابی
    fetch('/api/admin/get-current-month', { credentials:'same-origin' }).then(function(r){return r.json()}).then(function(j){
      if (!j || !j.ok) return;
      pspFillContractTypes(j.contractTypesList || defaultContractTypesClient(), j.contractType || 'normal');
      if (typeof pspLoadCalForCt === 'function') pspLoadCalForCt();
      else {
        if (j.year) { var y=document.getElementById('pspCurYear'); if(y) y.value=j.year; }
        if (j.month) { var m=document.getElementById('pspCurMonth'); if(m) m.value=String(j.month); }
      }
    }).catch(function(){});
    function defaultContractTypesClient(){ return [{id:'normal',name:'عادی'},{id:'daily',name:'روزمزد'},{id:'hourly',name:'ساعتی'}]; }

    window.__pspHolidays = {}; // key: contractType + '|' + year
    function pspHolKey(ct, year) { return String(ct || 'normal') + '|' + String(year); }
    function renderHolidayCal() {
      var box = document.getElementById('pspCalBox');
      if (!box) return;
      var year = Number(document.getElementById('pspCalYear').value) || 1405;
      var ct = (typeof pspSelectedCt === 'function') ? pspSelectedCt() : 'normal';
      var monthNames = ['','فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'];
      var mdays = [0,31,31,31,31,31,31,30,30,30,30,30,29];
      var cy = year - 979; var k = cy % 33; var breaks = [1,5,9,13,17,22,26,30];
      if (breaks.indexOf(k)>=0) mdays[12]=30;
      var hol = window.__pspHolidays[pspHolKey(ct, year)] || [];
      var holSet = {}; hol.forEach(function(d){ holSet[d]=true; });
      var html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;">';
      for (var m=1;m<=12;m++) {
        html += '<div style="border:1px solid #99f6e4;border-radius:8px;padding:6px;"><div style="font-weight:700;font-size:0.8rem;color:#0f766e;margin-bottom:4px;">'+monthNames[m]+'</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:2px;font-size:0.65rem;">';
        for (var d=1;d<=mdays[m];d++) {
          var key = year+'/'+String(m).padStart(2,'0')+'/'+String(d).padStart(2,'0');
          var on = !!holSet[key];
          // پنجشنبه/جمعه و روزهای غیرکاری هفته (از تیک‌های بالای صفحه) هم قرمز نمایش داده شوند
          var isNonWork = false;
          try {
            var wd = (function(jy,jm,jd){
              // تقریب روز هفته جلالی (0=یکشنبه … 6=شنبه)
              var jy2=jy-979, days=365*jy2+Math.floor(jy2/33)*8+Math.floor(((jy2%33)+3)/4)+78+jd+(jm<7?(jm-1)*31:((jm-7)*30+186));
              var gy2=1600+400*Math.floor(days/146097); days%=146097; var leap=true;
              if(days>=36525){days--;gy2+=100*Math.floor(days/36524);days%=36524;if(days>=365)days++;else leap=false;}
              gy2+=4*Math.floor(days/1461);days%=1461;
              if(days>=366){leap=false;gy2+=Math.floor((days-1)/365);days=(days-1)%365;}
              var sal=[0,31,(leap?29:28),31,30,31,30,31,31,30,31,30,31], gm=0;
              for(;gm<13;gm++){var v=sal[gm];if(days<v)break;days-=v;}
              return (new Date(Date.UTC(gy2,gm-1,days+1))).getUTCDay();
            })(year,m,d);
            var wds = [];
            document.querySelectorAll('.psp-wd:checked').forEach(function(c){ wds.push(Number(c.value)); });
            if (wds.length && wds.indexOf(wd) < 0) isNonWork = true;
          } catch(e) {}
          var mark = on || isNonWork;
          var title = key + (on ? ' (تعطیل رسمی)' : (isNonWork ? ' (غیرکاری هفته)' : ''));
          html += '<button type="button" data-hday="'+key+'" style="padding:3px 0;border-radius:4px;border:1px solid '+(mark?'#b91c1c':'#e2e8f0')+';background:'+(on?'#fecaca':(isNonWork?'#fee2e2':'#fff'))+';cursor:pointer;opacity:'+(isNonWork&&!on?'0.85':'1')+';" title="'+title+'">'+d+'</button>';
        }
        html += '</div></div>';
      }
      html += '</div><p style="font-size:0.72rem;color:#64748b;margin-top:6px;">قرمز = تعطیل رسمی/تعطیل‌شده توسط ادمین. کلیک = تغییر وضعیت.</p>';
      box.innerHTML = html;
      box.querySelectorAll('[data-hday]').forEach(function(btn){
        btn.onclick = function(){
          var key = btn.getAttribute('data-hday');
          var ct2 = (typeof pspSelectedCt === 'function') ? pspSelectedCt() : 'normal';
          var hk = pspHolKey(ct2, year);
          var list = (window.__pspHolidays[hk] || []).slice();
          var ix = list.indexOf(key);
          if (ix >= 0) list.splice(ix,1); else list.push(key);
          window.__pspHolidays[hk] = list;
          renderHolidayCal();
        };
      });
    }
    var calLoad = document.getElementById('pspCalLoad');
    if (calLoad) calLoad.onclick = function(){
      var year = Number(document.getElementById('pspCalYear').value)||1405;
      fetch('/api/admin/holidays?year='+year+'&contractType='+encodeURIComponent(pspSelectedCt()), {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(j){
        if (j.ok) {
          var ctL = j.contractType || pspSelectedCt();
          var daysL = (j.days || []).slice();
          if (!daysL.length) {
            // پیش‌فرض تعطیلات رسمی شمسی اگر سرور خالی بود
            function dI(m,day){ return year+'/'+String(m).padStart(2,'0')+'/'+String(day).padStart(2,'0'); }
            daysL = [dI(1,1),dI(1,2),dI(1,3),dI(1,4),dI(1,12),dI(1,13),dI(3,14),dI(3,15),dI(11,22),dI(12,29)];
          }
          window.__pspHolidays[pspHolKey(ctL, year)] = daysL;
          renderHolidayCal();
          var st=document.getElementById('pspCalStatus'); if(st){ st.style.color='#0f766e'; st.textContent='بارگذاری شد: '+(j.days||[]).length+' روز تعطیل'; }
        }
      });
    };
    var calSave = document.getElementById('pspCalSave');
    if (calSave) calSave.onclick = function(){
      var year = Number(document.getElementById('pspCalYear').value)||1405;
      var days = (window.__pspHolidays[pspHolKey(pspSelectedCt(), year)] || []).slice();
      var st=document.getElementById('pspCalStatus'); if(st) st.textContent='ذخیره…';
      fetch('/api/admin/holidays', {
        method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
        body: JSON.stringify({ year: year, days: days, contractType: pspSelectedCt() })
      }).then(function(r){return r.json()}).then(function(j){
        if (st) {
          if (j.ok) { st.style.color='#16a34a'; st.textContent='تعطیلات سال '+year+' ذخیره شد ('+days.length+' روز)'; }
          else { st.style.color='#b91c1c'; st.textContent=j.message||j.error||'خطا'; }
        }
      });
    };

    window.__pspTypes = [];
    function renderTypes() {
      var box = document.getElementById('pspTypesList');
      if (!window.__pspTypes.length) {
        box.innerHTML = '<p style="font-size:0.85rem;color:#64748b;">هنوز نوعی تعریف نشده. «+ نوع جدید» را بزنید.</p>';
        return;
      }
      var html = '<table style="font-size:0.78rem;"><thead><tr><th>نام</th><th>دسته</th><th>روزانه/ساعتی</th><th>کسر استحقاقی</th><th>تعداد روز</th><th>محدودیت دفعات</th><th>فقط مجوز ادمین</th><th></th></tr></thead><tbody>';
      window.__pspTypes.forEach(function(t, i) {
        var freq = t.frequency || 'throughout_year';
        html += '<tr>' +
          '<td><input data-i="' + i + '" data-f="name" value="' + (t.name || '').replace(/"/g, '&quot;') + '" style="width:100%;min-width:100px;padding:4px 6px;border:1px solid #99f6e4;border-radius:6px;font-family:inherit;"></td>' +
          '<td><select data-i="' + i + '" data-f="kind"><option value="leave"' + (t.kind === 'leave' ? ' selected' : '') + '>مرخصی</option><option value="mission"' + (t.kind === 'mission' ? ' selected' : '') + '>مأموریت</option></select></td>' +
          '<td><select data-i="' + i + '" data-f="mode"><option value="daily"' + (t.mode !== 'hourly' ? ' selected' : '') + '>روزانه</option><option value="hourly"' + (t.mode === 'hourly' ? ' selected' : '') + '>ساعتی</option></select></td>' +
          '<td style="text-align:center;"><input type="checkbox" data-i="' + i + '" data-f="deduct"' + (t.deductFromEntitlement ? ' checked' : '') + (t.kind === 'mission' ? ' disabled' : '') + '></td>' +
          '<td><select data-i="' + i + '" data-f="fixedMode"><option value="none"' + (t.fixedDays == null || t.fixedDays === '' ? ' selected' : '') + '>بدون ثابت</option><option value="fixed"' + (t.fixedDays != null && t.fixedDays !== '' ? ' selected' : '') + '>معین</option></select> ' +
          '<input type="number" min="1" max="365" data-i="' + i + '" data-f="fixedDays" value="' + (t.fixedDays != null && t.fixedDays !== '' ? t.fixedDays : '') + '" style="width:60px;padding:4px;border:1px solid #99f6e4;border-radius:6px;"' + (t.fixedDays == null || t.fixedDays === '' ? ' disabled' : '') + '></td>' +
          '<td><select data-i="' + i + '" data-f="frequency">' +
          '<option value="once_employment"' + (freq === 'once_employment' ? ' selected' : '') + '>یک‌بار در استخدام</option>' +
          '<option value="once_year"' + (freq === 'once_year' ? ' selected' : '') + '>یک‌بار در سال</option>' +
          '<option value="throughout_year"' + (freq === 'throughout_year' ? ' selected' : '') + '>در طول سال</option>' +
          '</select></td>' +
          '<td style="text-align:center;"><input type="checkbox" data-i="' + i + '" data-f="requiresAdminGrant"' + (t.requiresAdminGrant ? ' checked' : '') + '></td>' +
          '<td><button type="button" class="btn btn-outline btn-sm" data-del="' + i + '">حذف</button></td></tr>';
      });
      html += '</tbody></table>';
      box.innerHTML = html;
      // refresh grant / admin type dropdowns
      var gsel = document.getElementById('pspGrantType');
      if (gsel) {
        gsel.innerHTML = window.__pspTypes.filter(function(t){ return t.requiresAdminGrant; }).map(function(t){
          return '<option value="' + t.id + '">' + t.name + '</option>';
        }).join('') || '<option value="">— نوعی با مجوز ادمین تعریف نشده —</option>';
      }
      var asel = document.getElementById('pspAdmType');
      if (asel) {
        asel.innerHTML = window.__pspTypes.map(function(t){
          return '<option value="' + t.id + '">' + t.name + '</option>';
        }).join('') || '<option value="">—</option>';
      }
      box.querySelectorAll('[data-f]').forEach(function(el) {
        el.onchange = el.oninput = function() {
          var i = Number(el.getAttribute('data-i'));
          var f = el.getAttribute('data-f');
          if (!window.__pspTypes[i]) return;
          if (f === 'deduct') window.__pspTypes[i].deductFromEntitlement = !!el.checked;
          else if (f === 'requiresAdminGrant') window.__pspTypes[i].requiresAdminGrant = !!el.checked;
          else if (f === 'fixedMode') {
            if (el.value === 'none') {
              window.__pspTypes[i].fixedDays = null;
              var inp = box.querySelector('input[data-f="fixedDays"][data-i="' + i + '"]');
              if (inp) { inp.value = ''; inp.disabled = true; }
            } else {
              var inp2 = box.querySelector('input[data-f="fixedDays"][data-i="' + i + '"]');
              if (inp2) { inp2.disabled = false; if (!inp2.value) inp2.value = '1'; window.__pspTypes[i].fixedDays = Number(inp2.value) || 1; }
            }
          } else if (f === 'fixedDays') window.__pspTypes[i].fixedDays = el.value === '' ? null : Number(el.value);
          else if (f === 'kind') {
            window.__pspTypes[i].kind = el.value;
            if (el.value === 'mission') window.__pspTypes[i].deductFromEntitlement = false;
            renderTypes();
          } else window.__pspTypes[i][f] = el.value;
        };
      });
      box.querySelectorAll('[data-del]').forEach(function(b) {
        b.onclick = function() {
          window.__pspTypes.splice(Number(b.getAttribute('data-del')), 1);
          renderTypes();
        };
      });
    }

    document.getElementById('pspTypeAdd').onclick = function() {
      window.__pspTypes.push({
        id: 't_' + Date.now().toString(36),
        name: 'نوع جدید',
        kind: 'leave',
        mode: 'daily',
        deductFromEntitlement: true,
        fixedDays: null,
        frequency: 'throughout_year',
        requiresAdminGrant: false
      });
      renderTypes();
    };
    document.getElementById('pspGrantBtn').onclick = function() {
      var st = document.getElementById('pspGrantStatus');
      st.textContent = '…';
      fetch('/api/admin/grant-attendance', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({
          empCode: document.getElementById('pspGrantCode').value.trim(),
          typeId: document.getElementById('pspGrantType').value,
          dateFrom: document.getElementById('pspGrantFrom').value.trim(),
          dateTo: document.getElementById('pspGrantTo').value.trim()
        })
      }).then(function(r){ return r.json(); }).then(function(j){
        if (j.ok) { st.style.color = '#16a34a'; st.textContent = 'مجوز صادر شد برای کد ' + j.grant.empCode; }
        else { st.style.color = '#b91c1c'; st.textContent = j.message || j.error || 'خطا'; }
      }).catch(function(){ st.style.color = '#b91c1c'; st.textContent = 'خطا در ارتباط'; });
    };
    var adjBtn = document.getElementById('pspAdjBtn');
    if (adjBtn) adjBtn.onclick = function(){
      var st = document.getElementById('pspAdjStatus');
      if (st) { st.textContent = '…'; st.style.color = '#0f766e'; }
      fetch('/api/admin/leave-adjust', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({
          empCode: (document.getElementById('pspAdjCode') || {}).value.trim(),
          year: Number((document.getElementById('pspAdjYear') || {}).value) || undefined,
          source: (document.getElementById('pspAdjSource') || {}).value || 'current',
          sign: (document.getElementById('pspAdjSign') || {}).value || '+',
          days: Number((document.getElementById('pspAdjDays') || {}).value) || 0,
          hours: Number((document.getElementById('pspAdjHours') || {}).value) || 0,
          reason: ((document.getElementById('pspAdjReason') || {}).value || '').trim()
        })
      }).then(function(r){ return r.json(); }).then(function(j){
        if (!st) return;
        if (j.ok) { st.style.color = '#16a34a'; st.textContent = j.message || 'ثبت شد'; }
        else { st.style.color = '#b91c1c'; st.textContent = j.message || j.error || 'خطا'; }
      }).catch(function(){ if (st) { st.style.color = '#b91c1c'; st.textContent = 'خطا در ارتباط'; } });
    };
    window.__pspReqRows = [];
    function statusFa(s){
      if(s==='approved') return 'تأیید نهایی';
      if(s==='approved_l1') return 'تأیید سطح ۱';
      if(s==='rejected') return 'رد شده';
      return 'در انتظار';
    }
    function renderReqSheet(){
      var box = document.getElementById('pspReqSheet');
      if(!box) return;
      var types = window.__pspTypes || [];
      var typeOpts = types.map(function(t){ return '<option value="'+t.id+'">'+t.name+'</option>'; }).join('');
      var html = '<table style="font-size:0.75rem;min-width:1100px;"><thead><tr>'+
        '<th>کد</th><th>نام</th><th>نوع</th><th>از تاریخ</th><th>تا تاریخ</th><th>از ساعت</th><th>تا ساعت</th><th>محل</th><th>دلیل</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>';
      window.__pspReqRows.forEach(function(x,i){
        html += '<tr data-i="'+i+'">'+
          '<td><input data-f="empCode" value="'+(x.empCode||'')+'" style="width:80px"></td>'+
          '<td style="white-space:nowrap">'+(x.empName||'')+'</td>'+
          '<td><select data-f="typeId">'+typeOpts.replace('value="'+x.typeId+'"','value="'+x.typeId+'" selected')+'</select></td>'+
          '<td><input data-f="startDate" value="'+(x.startDate||'')+'" style="width:90px" dir="ltr"></td>'+
          '<td><input data-f="endDate" value="'+(x.endDate||'')+'" style="width:90px" dir="ltr"></td>'+
          '<td><input data-f="fromTime" value="'+(x.fromTime||'')+'" style="width:70px" dir="ltr"></td>'+
          '<td><input data-f="toTime" value="'+(x.toTime||'')+'" style="width:70px" dir="ltr"></td>'+
          '<td><input data-f="place" value="'+(x.place||'')+'" style="width:90px"></td>'+
          '<td><input data-f="reason" value="'+(x.reason||'')+'" style="width:100px"></td>'+
          '<td><select data-f="status">'+
            '<option value="pending"'+(x.status==='pending'?' selected':'')+'>در انتظار</option>'+
            '<option value="approved_l1"'+(x.status==='approved_l1'?' selected':'')+'>تأیید سطح ۱</option>'+
            '<option value="approved"'+(x.status==='approved'?' selected':'')+'>تأیید نهایی</option>'+
            '<option value="rejected"'+(x.status==='rejected'?' selected':'')+'>رد شده</option>'+
          '</select></td>'+
          '<td style="white-space:nowrap">'+
            '<button type="button" class="btn btn-primary btn-sm" data-save="'+i+'">ذخیره</button> '+
            '<button type="button" class="btn btn-outline btn-sm" data-del="'+i+'">حذف</button>'+
          '</td></tr>';
      });
      html += '</tbody></table>';
      box.innerHTML = html;
      box.querySelectorAll('[data-f]').forEach(function(el){
        el.onchange = el.oninput = function(){
          var tr = el.closest('tr'); var i = Number(tr.getAttribute('data-i'));
          if(window.__pspReqRows[i]) window.__pspReqRows[i][el.getAttribute('data-f')] = el.value;
        };
      });
      box.querySelectorAll('[data-save]').forEach(function(b){
        b.onclick = function(){
          var i = Number(b.getAttribute('data-save'));
          var row = window.__pspReqRows[i];
          if(!row) return;
          var st = document.getElementById('pspAdmStatus'); st.textContent='…';
          var method = row.id ? 'PUT' : 'POST';
          fetch('/api/admin/attendance-request', {
            method: method, headers:{'Content-Type':'application/json'}, credentials:'same-origin',
            body: JSON.stringify(row)
          }).then(function(r){return r.json()}).then(function(j){
            if(j.ok){ st.style.color='#16a34a'; st.textContent='ذخیره شد'; if(j.request){ window.__pspReqRows[i]=j.request; renderReqSheet(); } }
            else { st.style.color='#b91c1c'; st.textContent=j.message||j.error||'خطا'; }
          }).catch(function(){ st.style.color='#b91c1c'; st.textContent='خطا'; });
        };
      });
      box.querySelectorAll('[data-del]').forEach(function(b){
        b.onclick = function(){
          var i = Number(b.getAttribute('data-del'));
          var row = window.__pspReqRows[i];
          if(!row) return;
          if(!confirm('حذف این درخواست؟')) return;
          var st = document.getElementById('pspAdmStatus'); st.textContent='…';
          if(!row.id){ window.__pspReqRows.splice(i,1); renderReqSheet(); st.textContent='حذف شد'; return; }
          fetch('/api/admin/attendance-request', {
            method:'DELETE', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
            body: JSON.stringify({ id: row.id })
          }).then(function(r){return r.json()}).then(function(j){
            if(j.ok){ st.style.color='#16a34a'; st.textContent='حذف شد'; window.__pspReqRows.splice(i,1); renderReqSheet(); }
            else { st.style.color='#b91c1c'; st.textContent=j.message||j.error||'خطا'; }
          });
        };
      });
    }
    function loadReqSheet(){
      var st = document.getElementById('pspAdmStatus'); if(st) st.textContent='…';
      fetch('/api/admin/attendance-requests', {
        method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
        body: JSON.stringify({
          year: Number(document.getElementById('pspReqYear').value),
          month: Number(document.getElementById('pspReqMonth').value),
          code: document.getElementById('pspReqCode').value.trim()
        })
      }).then(function(r){return r.json()}).then(function(j){
        if(!j.ok){ if(st){ st.style.color='#b91c1c'; st.textContent=j.error||'خطا'; } return; }
        window.__pspReqRows = j.requests || [];
        renderReqSheet();
        if(st){ st.style.color='#16a34a'; st.textContent = (window.__pspReqRows.length)+' درخواست'; }
      }).catch(function(){ if(st){ st.style.color='#b91c1c'; st.textContent='خطا'; } });
    }
    document.getElementById('pspReqLoad').onclick = loadReqSheet;
    document.getElementById('pspReqAddRow').onclick = function(){
      window.__pspReqRows.unshift({
        id:'', empCode:'', empName:'', typeId: (window.__pspTypes[0]&&window.__pspTypes[0].id)||'',
        startDate:'', endDate:'', fromTime:'', toTime:'', place:'', reason:'', status:'approved'
      });
      renderReqSheet();
    };
    // auto load when tab opens (after types)
    setTimeout(function(){ try{ loadReqSheet(); }catch(e){} }, 500);
    document.getElementById('pspTypeSave').onclick = function() {
      var st = document.getElementById('pspTypeStatus');
      st.textContent = '…';
      fetch('/api/admin/attendance-types', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({ types: window.__pspTypes })
      }).then(function(r){ return r.json(); }).then(function(j){
        if (j.ok) { st.style.color = '#16a34a'; st.textContent = 'ذخیره شد (' + (j.types || []).length + ' نوع)'; window.__pspTypes = j.types || window.__pspTypes; renderTypes(); }
        else { st.style.color = '#b91c1c'; st.textContent = j.message || j.error || 'خطا'; }
      }).catch(function(){ st.style.color = '#b91c1c'; st.textContent = 'خطا در ارتباط'; });
    };

    function loadTypes() {
      fetch('/api/admin/attendance-types', { credentials: 'same-origin' })
        .then(function(r){ return r.json(); })
        .then(function(j){
          if (j.ok) { window.__pspTypes = j.types || []; renderTypes(); }
        }).catch(function(){});
    }

    // Hook into existing tab system: when our tab is clicked, show only our panel
    btn.addEventListener('click', function() {
      document.querySelectorAll('.tab-btn').forEach(function(b){ b.classList.remove('active'); });
      document.querySelectorAll('.panel').forEach(function(p){ p.classList.remove('active'); });
      btn.classList.add('active');
      panel.classList.add('active');
      loadTypes();
    });
    // When other tabs clicked, hide our panel (their handler already removes active from panels)
    // Ensure our panel is not left active: observe other tab clicks
    tabs.querySelectorAll('.tab-btn').forEach(function(other) {
      if (other === btn) return;
      other.addEventListener('click', function() {
        panel.classList.remove('active');
        btn.classList.remove('active');
      });
    });
      } catch (e) { console.error('psp portal tab', e); }
  }
  function bootPortalTab() {
    try { ensurePortalTab(); } catch (e) { console.error('psp ensurePortalTab', e); }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootPortalTab);
  }
  bootPortalTab();
  setTimeout(bootPortalTab, 500);
  setTimeout(bootPortalTab, 1500);
  setTimeout(bootPortalTab, 3000);
  setTimeout(bootPortalTab, 6000);
  setInterval(bootPortalTab, 8000);
  try {
    var obs = new MutationObserver(function() { bootPortalTab(); });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(function(){ try { obs.disconnect(); } catch(e){} }, 20000);
  } catch (e) {}

  // ---- Register new tabs/options into operator access list if present ----
  function pspRegisterAccessItems() {
    var extra = [
      'مأموریت/مرخصی و سایر',
      'تایم‌شیت و کارکرد',
      'انواع مرخصی/مأموریت',
      'مجوزها',
      'مدیریت درخواست‌ها',
      'آپلود فایل کارکرد',
      'نمایش در پرتال کارمند',
      'قراردادها',
      'حکم (پرتال کارمند)',
      'مشخصات پرسنلی (پرتال)'
    ];
    // common patterns: checkboxes in دسترسی اپراتور panel
    var panel = null;
    document.querySelectorAll('.panel, .card, form, [id*="access"], [id*="operator"]').forEach(function(el) {
      var t = (el.textContent || '');
      if (t.indexOf('دسترسی') >= 0 && (t.indexOf('اپراتور') >= 0 || t.indexOf('تب') >= 0)) panel = el;
    });
    if (!panel) return;
    // find container of existing tab checkboxes
    var labels = panel.querySelectorAll('label');
    var host = null;
    for (var i = 0; i < labels.length; i++) {
      var lt = (labels[i].textContent || '').trim();
      if (lt.indexOf('کارکنان') >= 0 || lt.indexOf('محاسبه') >= 0) {
        host = labels[i].parentNode;
        break;
      }
    }
    if (!host) host = panel;
    extra.forEach(function(name) {
      // skip if already exists
      var exists = false;
      host.querySelectorAll('label').forEach(function(l) {
        if ((l.textContent || '').indexOf(name) >= 0) exists = true;
      });
      if (exists) return;
      var lab = document.createElement('label');
      lab.style.cssText = 'display:inline-flex;align-items:center;gap:4px;margin:4px 6px;font-size:0.8rem;';
      lab.innerHTML = '<input type="checkbox" class="psp-access-item" data-psp-access="'+name+'" checked> ' + name;
      host.appendChild(lab);
    });
  }
  setTimeout(pspRegisterAccessItems, 1500);
  setTimeout(pspRegisterAccessItems, 3500);
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
          }
        });
        if (obj.attendanceTypes === undefined && prev.obj.attendanceTypes) obj.attendanceTypes = prev.obj.attendanceTypes;
        if (obj.attendanceRequests === undefined && prev.obj.attendanceRequests) obj.attendanceRequests = prev.obj.attendanceRequests;
        if (obj.attendanceGrants === undefined && prev.obj.attendanceGrants) obj.attendanceGrants = prev.obj.attendanceGrants;
        if (obj.contracts === undefined && prev.obj.contracts) obj.contracts = prev.obj.contracts;
        if (obj.portalViewConfig === undefined && prev.obj.portalViewConfig) obj.portalViewConfig = prev.obj.portalViewConfig;
      }
    }
  } catch (e) { /* non-fatal */ }

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
  return 'r_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
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

    if (mode === 'hourly' && (!fromTime || !toTime)) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'ساعت شروع و پایان الزامی است.' }, 400);
    }
    if (kind === 'mission' && !place) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'محل مأموریت الزامی است.' }, 400);
    }
    // reason/description required only for mission
    if (kind === 'mission' && !reason) {
      return jsonResponse({ ok: false, error: 'bad_request', message: 'توضیح / دلیل مأموریت الزامی است.' }, 400);
    }

    const emp = gd.obj.employees.find(e => String(e.code) === String(sess.code));
    if (!emp || emp.status === 'inactive') return jsonResponse({ ok: false, error: 'disabled' }, 403);
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
        if (x.usedRequestId) return false;
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
  // اطمینان از سال جاری — مانده واقعی = استحقاق تناسبی ماه‌های کارکرد − استفاده‌شده (+ تعدیل‌های +)
  const row = emp.leaveYears[String(cy)];
  row.entitled = getAnnualLeaveDaysForEmp(obj, emp);
  const accrued = computeAccruedLeaveDaysW(obj, emp, cy);
  row.accrued = accrued;
  if (row.settled) {
    row.remaining = 0;
  } else {
    let adjPos = 0, adjNeg = 0;
    (emp.leaveAdjustments || []).forEach(function (a) {
      if (String(a.year) !== String(cy)) return;
      const d = Number(a.delta) || 0;
      if (d > 0) adjPos += d;
      else adjNeg += Math.abs(d);
    });
    // used در دفتر ممکن است شامل بدهکار باشد؛ مانده نمایشی = accrued - used + adjPos
    // (adjNeg معمولاً در used هم نشسته)
    row.remaining = Math.round((accrued - Number(row.used || 0) + adjPos) * 100) / 100;
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
      // اگر سال جاری هیچ تعطیلی ندارد، فقط همان سال را با پیش‌فرض پر کن (سال‌های دیگر دست نخورند)
      if (!Array.isArray(cal.holidaysByYear[String(cy)]) || cal.holidaysByYear[String(cy)].length === 0) {
        if (cal._seededYears && cal._seededYears[String(cy)]) {
          // قبلاً ادمین عمداً خالی کرده — دست نزن
        } else {
          cal.holidaysByYear[String(cy)] = defaultIranHolidaysForYear(cy);
        }
      }
    }
  });
  return s;
}

function defaultWorkSchedule() {
  return {
    workStart: '08:00',
    workEnd: '17:00',
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
    floatMinutes: Math.max(0, Number(c.floatMinutes) || 0),
    floatCompensate: !!c.floatCompensate
  };
}

function getContractCalendar(obj, contractType) {
  ensureContractCalendars(obj || {});
  const s = (obj && obj.settings) || {};
  const ct = String(contractType || 'normal').trim() || 'normal';
  const cal = (s.contractCalendars && s.contractCalendars[ct]) || (s.contractCalendars && s.contractCalendars.normal) || {};
  const sched = normalizeWorkSchedule(cal);
  return {
    workWeekDays: Array.isArray(cal.workWeekDays) ? cal.workWeekDays.map(Number) : [6, 0, 1, 2, 3],
    countNonWorkDaysAsLeave: !!cal.countNonWorkDaysAsLeave,
    holidaysByYear: (cal.holidaysByYear && typeof cal.holidaysByYear === 'object') ? cal.holidaysByYear : {},
    workStart: sched.workStart,
    workEnd: sched.workEnd,
    hasBreak: sched.hasBreak,
    breakStart: sched.breakStart,
    breakEnd: sched.breakEnd,
    breakCountsAsWork: sched.breakCountsAsWork,
    dayEnd: sched.dayEnd,
    floatMinutes: sched.floatMinutes,
    floatCompensate: sched.floatCompensate
  };
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
function computeDayTimesheet(cal, punches) {
  const sched = normalizeWorkSchedule(cal);
  const start = timeToMinutes(sched.workStart);
  const end = timeToMinutes(sched.workEnd);
  const dayEnd = timeToMinutes(sched.dayEnd);
  const floatM = sched.floatMinutes;
  const compensate = sched.floatCompensate;
  const official = officialWorkMinutes(sched);

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
    if (punches.in1 || punches.out1) pairs.push({ inn: timeToMinutes(punches.in1), out: timeToMinutes(punches.out1) });
    if (punches.in2 || punches.out2) pairs.push({ inn: timeToMinutes(punches.in2), out: timeToMinutes(punches.out2) });
  }
  pairs = pairs.filter(function (p) { return p.inn != null || p.out != null; });

  let present = 0;
  pairs.forEach(function (p) {
    let a = p.inn, b = p.out;
    if (a == null && b == null) return;
    if (a == null) a = start;
    if (b == null) b = end;
    if (b < a) b += 24 * 60; // عبور از نیمه‌شب تا dayEnd
    present += Math.max(0, b - a);
  });

  // کسر وقفه فقط اگر وقفه فعال و جزو کار نباشد
  if (sched.hasBreak && !sched.breakCountsAsWork) {
    const bs = timeToMinutes(sched.breakStart);
    const be = timeToMinutes(sched.breakEnd);
    if (bs != null && be != null && pairs.length) {
      let br = be - bs;
      if (br < 0) br += 24 * 60;
      // اگر حداقل یک بازه حضور کل وقفه را پوشش دهد، کسر کن
      let covers = false;
      pairs.forEach(function (p) {
        let a = p.inn, b = p.out;
        if (a == null) a = start;
        if (b == null) b = end;
        if (b < a) b += 24 * 60;
        if (a <= bs && b >= be) covers = true;
      });
      if (covers) present = Math.max(0, present - br);
    }
  }

  const firstIn = pairs.length ? pairs.map(function (p) { return p.inn; }).filter(function (x) { return x != null; }).sort(function (a, b) { return a - b; })[0] : null;
  const lastOut = pairs.length ? pairs.map(function (p) { return p.out; }).filter(function (x) { return x != null; }).sort(function (a, b) { return b - a; })[0] : null;

  let delay = 0; // تأخیر ورود (دقیقه)
  let earlyLeave = 0; // تعجیل خروج
  let compensated = 0; // دقایق جبران‌شده با ماندن بیشتر
  let requiredEnd = end;

  if (firstIn != null && start != null) {
    delay = Math.max(0, firstIn - start);
  }
  if (compensate && delay > 0 && end != null) {
    // اجازه جبران: پایان مورد انتظار = پایان رسمی + تأخیر
    requiredEnd = end + delay;
    if (lastOut != null) {
      if (lastOut >= requiredEnd) {
        compensated = delay;
        delay = 0; // جبران کامل
      } else if (lastOut > end) {
        compensated = lastOut - end;
        delay = Math.max(0, delay - compensated);
      }
    }
  } else if (!compensate && delay > 0) {
    // تأخیر می‌ماند؛ شناوری فقط برای نمایش پنجره است
  }

  if (lastOut != null && end != null && !compensate) {
    earlyLeave = Math.max(0, end - lastOut);
  } else if (lastOut != null && requiredEnd != null && compensate) {
    earlyLeave = Math.max(0, requiredEnd - lastOut);
  }

  // اضافه‌کار نسبت به پایان رسمی (پس از جبران)
  let ot = 0;
  if (lastOut != null && end != null) {
    const beyond = lastOut - (compensate && compensated ? requiredEnd : end);
    if (beyond > 0) ot = beyond;
  }

  // کمبود کارکرد نسبت به شیفت رسمی
  const shortfall = Math.max(0, official - present);

  return {
    officialMinutes: official,
    presentMinutes: Math.round(present),
    delayMinutes: Math.round(delay),
    earlyLeaveMinutes: Math.round(earlyLeave),
    compensatedMinutes: Math.round(compensated),
    otMinutes: Math.round(ot),
    shortfallMinutes: Math.round(shortfall),
    floatMinutes: floatM,
    floatCompensate: compensate,
    firstIn: firstIn != null ? minutesToTime(firstIn) : null,
    lastOut: lastOut != null ? minutesToTime(lastOut) : null,
    requiredEnd: requiredEnd != null ? minutesToTime(requiredEnd) : null,
    workHours: Math.round((present / 60) * 100) / 100,
    otHours: Math.round((ot / 60) * 100) / 100
  };
}


function getHolidaySet(obj, year, contractType) {
  const cal = getContractCalendar(obj, contractType);
  const list = cal.holidaysByYear[String(year)] || cal.holidaysByYear[year] || [];
  const set = {};
  (list || []).forEach(function (d) {
    const k = String(d).replace(/\//g, '-');
    set[k] = true;
    set[String(d)] = true;
  });
  return set;
}

function isHolidayOrNonWork(obj, y, m, d, contractType) {
  const keyDash = y + '-' + String(m).padStart(2, '0') + '-' + String(d).padStart(2, '0');
  const keySlash = y + '/' + String(m).padStart(2, '0') + '/' + String(d).padStart(2, '0');
  const hol = getHolidaySet(obj, y, contractType);
  if (hol[keyDash] || hol[keySlash]) return true;
  const cal = getContractCalendar(obj, contractType);
  const wd = jalaliWeekday(y, m, d);
  if (cal.workWeekDays.indexOf(wd) < 0) return true;
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
  // بازمحاسبه کارکرد مرخصی/مأموریت از روی درخواست‌های تأییدشده (تا با حذف/رد همخوان باشد)
  let reLeaveDays = 0, reHourlyLeave = 0, reMissionDays = 0, reMissionHours = 0;
  reqs.forEach(function (x) {
    if (x.kind === 'leave' && x.mode === 'daily') {
      splitDaysByMonth(x.startDate, x.endDate || x.startDate).forEach(function (chunk) {
        if (chunk.year === year && chunk.month === month) reLeaveDays += chunk.days;
      });
    } else if (x.kind === 'leave' && x.mode === 'hourly') {
      const p = parseJalaliYMD(x.startDate);
      if (p && p.y === year && p.m === month) reHourlyLeave += hoursBetween(x.fromTime, x.toTime);
    } else if (x.kind === 'mission' && x.mode === 'daily') {
      splitDaysByMonth(x.startDate, x.endDate || x.startDate).forEach(function (chunk) {
        if (chunk.year === year && chunk.month === month) reMissionDays += chunk.days;
      });
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
  const dayMap = {};
  for (let d = 1; d <= dim; d++) {
    const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
    dayMap[dk] = {
      day: d,
      date: year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0'),
      leaveDaily: '',
      leaveHourly: '',
      missionDaily: '',
      missionHourly: '',
      note: ''
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
      const label = x.typeName || (x.kind === 'mission' ? 'مأموریت' : 'مرخصی');
      if (x.kind === 'leave' && x.mode === 'daily') cell.leaveDaily = (cell.leaveDaily ? cell.leaveDaily + '؛ ' : '') + label;
      if (x.kind === 'leave' && x.mode === 'hourly') { var tr = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (tr) cell.leaveHourly = (cell.leaveHourly ? cell.leaveHourly + '؛ ' : '') + tr; }
      if (x.kind === 'mission' && x.mode === 'daily') cell.missionDaily = (cell.missionDaily ? cell.missionDaily + '؛ ' : '') + label + (x.place ? ' (' + x.place + ')' : '');
      if (x.kind === 'mission' && x.mode === 'hourly') { var trm = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (trm) cell.missionHourly = (cell.missionHourly ? cell.missionHourly + '؛ ' : '') + trm; }
      if (x.reason) cell.note = (cell.note ? cell.note + '؛ ' : '') + x.reason;
    });
  });
  const dailyDays = Object.keys(dayMap).sort().map(function (k) { return dayMap[k]; });

  return jsonResponse({
    ok: true,
    code,
    fullName: emp ? emp.fullName : '',
    year, month,
    workDays: Number(row.workDays) || 0,
    leaveDays: (typeof reLeaveDays === 'number' ? reLeaveDays : (Number(row.leaveDays) || 0)),
    hourlyLeave: (typeof reHourlyLeave === 'number' ? reHourlyLeave : (Number(row.hourlyLeave) || 0)),
    missionDays: (typeof reMissionDays === 'number' ? reMissionDays : (Number(row.missionDays) || 0)),
    missionHours: (typeof reMissionHours === 'number' ? reMissionHours : (Number(row.missionHours) || 0)),
    otHours: Number(row.otHours) || 0,
    nightHours: Number(row.nightHours) || 0,
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

async function handleAdminTimesheet(request, who, env) {
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
    rows.push({
      code: emp.code,
      fullName: emp.fullName || '',
      unit: emp.unit || '',
      managerCode: emp.managerCode || '',
      workDays: Number(row.workDays) || 0,
      leaveDays: Number(row.leaveDays) || 0,
      hourlyLeave: Number(row.hourlyLeave) || 0,
      otHours: Number(row.otHours) || 0,
      nightHours: Number(row.nightHours) || 0,
      missions: empReqs.filter(x => x.kind === 'mission').length,
      leaves: empReqs.filter(x => x.kind === 'leave').length,
      requests: empReqs
    });
  });
  rows.sort(function (a, b) { return String(a.code).localeCompare(String(b.code), 'fa'); });

  // Day-by-day sheet when a single employee code is selected (Excel-like)
  let daily = null;
  if (filterCode && rows.length === 1) {
    const emp0 = (gd.obj.employees || []).find(function (e) { return String(e.code) === String(filterCode); });
    const cal = getContractCalendar(gd.obj, (emp0 && emp0.contractType) || 'normal');
    const dim = daysInJalaliMonth(year, month);
    if (!gd.obj.dailyAttendance) gd.obj.dailyAttendance = {};
    const punchStore = gd.obj.dailyAttendance[String(filterCode)] || {};
    const dayMap = {};
    for (let d = 1; d <= dim; d++) {
      const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
      const dateFa = year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0');
      const punch = punchStore[dk] || punchStore[dateFa] || {};
      const calc = computeDayTimesheet(cal, {
        in1: punch.in1 || '', out1: punch.out1 || '',
        in2: punch.in2 || '', out2: punch.out2 || ''
      });
      let wd = '';
      try { wd = ['یکشنبه','دوشنبه','سه‌شنبه','چهارشنبه','پنجشنبه','جمعه','شنبه'][jalaliWeekday(year, month, d)] || ''; } catch (e) {}
      dayMap[dk] = {
        day: d,
        date: dateFa,
        weekday: wd,
        in1: punch.in1 || '',
        out1: punch.out1 || '',
        in2: punch.in2 || '',
        out2: punch.out2 || '',
        workHours: calc.workHours,
        delayMin: calc.delayMinutes,
        earlyMin: calc.earlyLeaveMinutes,
        otHours: calc.otHours,
        compensatedMin: calc.compensatedMinutes,
        leaveDaily: '',
        leaveHourly: '',
        missionDaily: '',
        missionHourly: '',
        note: punch.note || '',
        isNonWork: isHolidayOrNonWork(gd.obj, year, month, d, (emp0 && emp0.contractType) || 'normal')
      };
    }
    (rows[0].requests || []).forEach(function (x) {
      const days = x.mode === 'hourly'
        ? [dateKey(x.startDate)]
        : listDayKeys(x.startDate, x.endDate || x.startDate);
      days.forEach(function (dk) {
        const parts = dk.split('-');
        if (Number(parts[0]) !== year || Number(parts[1]) !== month) return;
        const cell = dayMap[dk];
        if (!cell) return;
        const label = x.typeName || (x.kind === 'mission' ? 'مأموریت' : 'مرخصی');
        if (x.kind === 'leave' && x.mode === 'daily') cell.leaveDaily = (cell.leaveDaily ? cell.leaveDaily + '؛ ' : '') + label;
        if (x.kind === 'leave' && x.mode === 'hourly') { var tr = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (tr) cell.leaveHourly = (cell.leaveHourly ? cell.leaveHourly + '؛ ' : '') + tr; }
        if (x.kind === 'mission' && x.mode === 'daily') cell.missionDaily = (cell.missionDaily ? cell.missionDaily + '؛ ' : '') + label + (x.place ? ' (' + x.place + ')' : '');
        if (x.kind === 'mission' && x.mode === 'hourly') { var trm = [x.fromTime, x.toTime].filter(Boolean).join('-'); if (trm) cell.missionHourly = (cell.missionHourly ? cell.missionHourly + '؛ ' : '') + trm; }
        if (x.reason) cell.note = (cell.note ? cell.note + '؛ ' : '') + x.reason;
      });
    });
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
      days: Object.keys(dayMap).sort().map(function (k) { return dayMap[k]; })
    };
  }

  return jsonResponse({ ok: true, year, month, rows, daily: daily });
}

/** ذخیره ورود/خروج روزانه یک کارمند (یک روز یا چند روز ماه) */
async function handleAdminSaveTimesheetDays(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const empCode = String(r.body.code || r.body.empCode || '').trim();
  const days = Array.isArray(r.body.days) ? r.body.days : [];
  if (!empCode || !days.length) {
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
    const cal = getContractCalendar(gd.obj, (emp && emp.contractType) || 'normal');
    let saved = 0;
    days.forEach(function (d) {
      if (!d || !d.date) return;
      const p = parseJalaliYMD(d.date);
      if (!p) return;
      const dk = p.y + '-' + String(p.m).padStart(2, '0') + '-' + String(p.d).padStart(2, '0');
      const rec = {
        in1: String(d.in1 || '').trim(),
        out1: String(d.out1 || '').trim(),
        in2: String(d.in2 || '').trim(),
        out2: String(d.out2 || '').trim(),
        note: String(d.note || '').trim()
      };
      // اگر همه خالی → حذف
      if (!rec.in1 && !rec.out1 && !rec.in2 && !rec.out2 && !rec.note) {
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
      let sumOt = 0, sumWorkMin = 0, workDays = 0, sumDelay = 0;
      const dim = daysInJalaliMonth(year, month);
      for (let d = 1; d <= dim; d++) {
        const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
        const punch = store[dk];
        if (!punch) continue;
        if (!punch.in1 && !punch.out1 && !punch.in2 && !punch.out2) continue;
        const calc = computeDayTimesheet(cal, punch);
        if (calc.presentMinutes > 0) {
          workDays++;
          sumWorkMin += calc.presentMinutes;
          sumOt += calc.otMinutes;
          sumDelay += calc.delayMinutes;
        }
      }
      const md = gd.obj.monthlyData[key][empCode];
      md.otHours = Math.round((sumOt / 60) * 100) / 100;
      md.workMinutes = sumWorkMin;
      md.delayMinutes = sumDelay;
      // workDays فقط اگر از قبل خالی بوده یا از روی تایم‌شیت پر شود
      if (!md.workDays || r.body.updateWorkDays) md.workDays = workDays;
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
      requiresAdminGrant: !!t.requiresAdminGrant
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
    return String(g.empCode) === String(sess.code) && !g.consumed && !g.usedRequestId;
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
  const r = await readBody(request);
  if (r.error) return r.error;
  const empCode = String(r.body.empCode || '').trim();
  const typeId = String(r.body.typeId || '').trim();
  const dateFrom = String(r.body.dateFrom || r.body.date || '').trim();
  const dateTo = String(r.body.dateTo || r.body.dateFrom || r.body.date || '').trim();
  if (!empCode || !typeId) return jsonResponse({ ok: false, error: 'bad_request', message: 'کد کارمند و نوع الزامی است.' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
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
    if (Array.isArray(r.body.workWeekDays)) {
      cal.workWeekDays = r.body.workWeekDays.map(Number).filter(function (d) { return d >= 0 && d <= 6; });
    }
    if (r.body.countNonWorkDaysAsLeave != null) {
      cal.countNonWorkDaysAsLeave = !!r.body.countNonWorkDaysAsLeave;
    }
    const schedFields = ['workStart','workEnd','breakStart','breakEnd','dayEnd'];
    schedFields.forEach(function (f) {
      if (r.body[f] != null && String(r.body[f]).trim() !== '') cal[f] = String(r.body[f]).trim();
    });
    if (r.body.floatMinutes != null) cal.floatMinutes = Math.max(0, Number(r.body.floatMinutes) || 0);
    if (r.body.hasBreak != null) cal.hasBreak = !!r.body.hasBreak;
    if (r.body.breakCountsAsWork != null) cal.breakCountsAsWork = !!r.body.breakCountsAsWork;
    if (r.body.floatCompensate != null) cal.floatCompensate = !!r.body.floatCompensate;
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
  return jsonResponse({ ok: true, year: year, contractType: ct, days: by[String(year)] || [] });
}

async function handleAdminSaveHolidays(request, who, env) {
  if (who.role !== 'admin' && who.role !== 'operator') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const year = Number(r.body.year);
  const days = Array.isArray(r.body.days) ? r.body.days.map(String) : [];
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
  if (who.role !== 'admin') {
    return jsonResponse({ ok: false, error: 'forbidden', message: 'فقط ادمین سیستم می‌تواند حذف کند.' }, 403);
  }
  const r = await readBody(request);
  if (r.error) return r.error;
  const id = String(r.body.id || '').trim();
  if (!id) return jsonResponse({ ok: false, error: 'bad_request' }, 400);
  const cfg = storeConfig(env);
  if (!cfg) return jsonResponse({ ok: false, error: 'sync_not_configured' }, 503);
  for (let attempt = 0; attempt < 4; attempt++) {
    const gd = await storeGetData(cfg);
    if (gd.fail) return storeFailResponse(gd.fail);
    if (!gd.obj) return jsonResponse({ ok: false, error: 'no_data' }, 404);
    if (!Array.isArray(gd.obj.attendanceRequests)) gd.obj.attendanceRequests = [];
    const idx = gd.obj.attendanceRequests.findIndex(function (x) { return x.id === id; });
    if (idx < 0) return jsonResponse({ ok: false, error: 'not_found' }, 404);
    const doomed = gd.obj.attendanceRequests[idx];
    // برگرداندن اثر روی کارکرد و مانده اگر تأیید نهایی شده بود
    if (doomed && doomed.status === 'approved') {
      try { restoreLeaveDeduction(gd.obj, doomed); } catch (e) {}
      try {
        if (doomed._timesheetApplied) {
          reverseApprovedRequestFromTimesheet(gd.obj, doomed);
          doomed._timesheetApplied = false;
        } else {
          reverseApprovedRequestFromTimesheet(gd.obj, doomed);
        }
      } catch (e) {}
    }
    const empCodeDel = doomed ? doomed.empCode : '';
    gd.obj.attendanceRequests.splice(idx, 1);
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
  if (path === '/api/payroll') return handlePayroll(request, user);
  if (path === '/api/calc') return handleCalc(request, user);
  if (path === '/api/admin/contracts') return handleAdminContracts(request, who, env);
  if (path === '/api/admin/accounting-export') return handleAdminAccountingExport(request, who, env);
  if (path === '/api/admin/payroll-contract-check') return handleAdminPayrollContractCheck(request, who, env);
  if (path === '/api/admin/portal-view') {
    if (request.method === 'GET') return handleAdminGetPortalView(request, who, env);
    return handleAdminSavePortalView(request, who, env);
  }
  if (path === '/api/admin/set-emp-password') return handleAdminSetEmpPassword(request, who, env);
  if (path === '/api/admin/set-manager') return handleAdminSetManager(request, who, env);
  if (path === '/api/admin/get-manager') return handleAdminGetManager(request, who, env);
  if (path === '/api/admin/timesheet') return handleAdminTimesheet(request, who, env);
  if (path === '/api/admin/timesheet-days') return handleAdminSaveTimesheetDays(request, who, env);
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
    if (a.id === 'child' || name.indexOf('اولاد') >= 0) amt = amt * (Number(emp.children) || 0);
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
        gd.obj.contracts.unshift({
          id: 'ctr_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7),
          empCode: String(emp.code),
          empName: emp.fullName || '',
          startDate: startDate,
          endDate: endDate,
          type: type,
          note: note,
          status: 'pending',
          adminApproved: false,
          adminApprovedAt: '',
          adminApprovedBy: '',
          showDurationToEmployee: showDur,
          visibleToEmployee: visibleEmp,
          signedFileName: '',
          signedUploadedAt: '',
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
  const emps = (gd.obj && gd.obj.employees) || [];
  const contracts = (gd.obj && gd.obj.contracts) || [];
  const unapproved = [];
  emps.forEach(function (e) {
    if (e.status === 'inactive') return;
    const mine = contracts.filter(function (c) { return String(c.empCode) === String(e.code); });
    const ok = mine.some(function (c) { return c.adminApproved && c.status !== 'terminated'; });
    if (!ok) {
      unapproved.push({
        code: e.code,
        fullName: e.fullName || '',
        reason: mine.length ? 'قرارداد بدون تأیید ادمین' : 'بدون قرارداد'
      });
    }
  });
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
  body { font-family: 'Vazirmatn', Tahoma, sans-serif; background: #f0fdfa; color: #134e4a; min-height: 100vh; padding: 16px; direction: rtl; }
  .wrap { max-width: 720px; margin: 0 auto; }
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
    var j=await r.json();
    if(!j.ok && j.error==='need_prior_years_confirm'){
      if(confirm(j.message||'مانده امسال کافی نیست. از ذخیره سال‌های قبل استفاده شود؟')){
        body.usePriorYears=true;
        r=await fetch('/api/emp/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});
        j=await r.json();
      } else { err.textContent='ثبت لغو شد.'; return; }
    }
    if(!j.ok){err.textContent=j.message||j.error||'خطا';return}
    err.classList.add('okmsg'); err.textContent='درخواست ثبت و برای مدیر ارسال شد.'+(body.usePriorYears?' (از ذخیره سال‌های قبل)':''); loadRequests();
  }catch(e){err.textContent='خطا در ارتباط'}
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
    var html='<div class="box"><b>'+(j.fullName||'')+'</b> — '+monthsFa[month]+' '+year;
    html+='<table style="margin-top:8px"><tr><th>کارکرد</th><th>مرخصی روزانه</th><th>مرخصی ساعتی</th><th>اضافه‌کار</th><th>شب‌کاری</th></tr>';
    html+='<tr><td>'+j.workDays+'</td><td>'+j.leaveDays+'</td><td>'+j.hourlyLeave+'</td><td>'+j.otHours+'</td><td>'+j.nightHours+'</td></tr></table>';
    if(j.daily&&j.daily.days&&j.daily.days.length){
      html+='<h2 style="margin-top:14px">تایم‌شیت روزبه‌روز</h2>';
      html+='<div style="overflow:auto"><table style="font-size:0.78rem;min-width:720px"><thead><tr>';
      html+='<th>تاریخ</th><th>ورود۱</th><th>خروج۱</th><th>ورود۲</th><th>خروج۲</th>';
      html+='<th>مأموریت ساعتی</th><th>مأموریت روزانه</th><th>مرخصی ساعتی</th><th>مرخصی روزانه</th><th>توضیح</th>';
      html+='</tr></thead><tbody>';
      j.daily.days.forEach(function(d){
        html+='<tr><td>'+d.date+'</td><td></td><td></td><td></td><td></td>';
        html+='<td>'+(d.missionHourly||'')+'</td><td>'+(d.missionDaily||'')+'</td>';
        html+='<td>'+(d.leaveHourly||'')+'</td><td>'+(d.leaveDaily||'')+'</td>';
        html+='<td>'+(d.note||'')+'</td></tr>';
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
