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
  function ensurePortalTab() {
    if (document.getElementById('pspPortalTabBtn')) return;
    var tabs = document.querySelector('.tabs');
    if (!tabs) return;
    // Proper separate tab (same mechanism as other tabs: panel-{id})
    var btn = document.createElement('button');
    btn.id = 'pspPortalTabBtn';
    btn.className = 'tab-btn';
    btn.type = 'button';
    btn.setAttribute('data-tab', 'portalatt');
    btn.textContent = 'مأموریت/مرخصی و سایر';
    tabs.appendChild(btn);

    var panel = document.createElement('div');
    panel.className = 'panel';
    panel.id = 'panel-portalatt';
    panel.innerHTML =
      '<div class="card">' +
      '<div class="section-title">تایم‌شیت پرتال کارکنان</div>' +
      '<p style="font-size:0.8rem;color:#64748b;margin-bottom:10px;">این گزارش از درخواست‌های تأییدشده پرتال است و فعلاً روی محاسبه حقوق اثر ندارد.</p>' +
      '<div class="form-grid" style="margin-bottom:10px;">' +
      '<div class="form-group"><label>سال</label><input type="number" id="pspTsYear" value="1405"></div>' +
      '<div class="form-group"><label>ماه</label><select id="pspTsMonth"><option value="1">1</option><option value="2">2</option><option value="3">3</option><option value="4">4</option><option value="5">5</option><option value="6">6</option><option value="7">7</option><option value="8">8</option><option value="9">9</option><option value="10">10</option><option value="11">11</option><option value="12">12</option></select></div>' +
      '<div class="form-group"><label>کد پرسنلی</label><input id="pspTsCode" placeholder="خالی = همه" autocomplete="off"></div>' +
      '<div class="form-group"><label>کد مدیر</label><input id="pspTsMgr" placeholder="فیلتر زیرمجموعه" autocomplete="off"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-primary btn-sm" id="pspTsLoad">نمایش</button></div>' +
      '</div><div id="pspTsOut" style="overflow:auto;margin-bottom:20px;"></div>' +
      '<div class="section-title">انواع مرخصی و مأموریت</div>' +
      '<p style="font-size:0.8rem;color:#64748b;margin-bottom:8px;">نام‌ها در پرتال کارکنان نمایش داده می‌شوند. محدودیت دفعات: یک‌بار استخدام / یک‌بار در سال / در طول سال. گزینه «فقط با مجوز ادمین» یعنی در لیست کارمند نیست مگر ادمین مجوز بدهد.</p>' +
      '<div id="pspTypesList" style="overflow:auto;"></div>' +
      '<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">' +
      '<button type="button" class="btn btn-outline btn-sm" id="pspTypeAdd">+ نوع جدید</button>' +
      '<button type="button" class="btn btn-primary btn-sm" id="pspTypeSave">ذخیره انواع</button>' +
      '<span id="pspTypeStatus" style="font-size:0.8rem;color:#0f766e;"></span>' +
      '</div>' +
      '<div class="section-title" style="margin-top:22px;">مجوز مرخصی خاص برای کارمند</div>' +
      '<p style="font-size:0.8rem;color:#64748b;margin-bottom:8px;">برای انواع «فقط با مجوز ادمین»: بازه تاریخ (از–تا) یا خالی = بدون محدودیت تاریخ.</p>' +
      '<div class="form-grid">' +
      '<div class="form-group"><label>کد پرسنلی</label><input id="pspGrantCode" autocomplete="off" placeholder="کد کارمند"></div>' +
      '<div class="form-group"><label>نوع</label><select id="pspGrantType"></select></div>' +
      '<div class="form-group"><label>از تاریخ</label><input id="pspGrantFrom" placeholder="1405/02/01" dir="ltr" autocomplete="off"></div>' +
      '<div class="form-group"><label>تا تاریخ</label><input id="pspGrantTo" placeholder="1405/02/29" dir="ltr" autocomplete="off"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-primary btn-sm" id="pspGrantBtn">صدور مجوز</button></div>' +
      '</div><span id="pspGrantStatus" style="font-size:0.8rem;color:#0f766e;"></span>' +
      '<div class="section-title" style="margin-top:22px;">ثبت / حذف توسط ادمین (بدون تأیید مدیر)</div>' +
      '<p style="font-size:0.8rem;color:#64748b;margin-bottom:8px;">ادمین می‌تواند مرخصی/مأموریت را مستقیم تأییدشده ثبت کند یا درخواست تأییدشده را حذف کند.</p>' +
      '<div class="form-grid">' +
      '<div class="form-group"><label>کد پرسنلی</label><input id="pspAdmCode" autocomplete="off"></div>' +
      '<div class="form-group"><label>نوع</label><select id="pspAdmType"></select></div>' +
      '<div class="form-group"><label>از تاریخ</label><input id="pspAdmStart" placeholder="1405/01/10" dir="ltr" autocomplete="off"></div>' +
      '<div class="form-group"><label>تا تاریخ</label><input id="pspAdmEnd" placeholder="1405/01/12" dir="ltr" autocomplete="off"></div>' +
      '<div class="form-group"><label>از ساعت</label><input id="pspAdmFrom" type="time" value="08:00"></div>' +
      '<div class="form-group"><label>تا ساعت</label><input id="pspAdmTo" type="time" value="10:00"></div>' +
      '<div class="form-group"><label>محل مأموریت</label><input id="pspAdmPlace" autocomplete="off"></div>' +
      '<div class="form-group"><label>دلیل</label><input id="pspAdmReason" autocomplete="off"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;gap:6px;"><button type="button" class="btn btn-primary btn-sm" id="pspAdmAdd">ثبت تأییدشده</button></div>' +
      '</div>' +
      '<div class="form-grid" style="margin-top:8px;">' +
      '<div class="form-group"><label>شناسه درخواست برای حذف</label><input id="pspAdmDelId" placeholder="r_...." autocomplete="off"></div>' +
      '<div class="form-group" style="display:flex;align-items:flex-end;"><button type="button" class="btn btn-outline btn-sm" id="pspAdmDel">حذف درخواست</button></div>' +
      '</div><span id="pspAdmStatus" style="font-size:0.8rem;color:#0f766e;"></span>' +
      '</div>';
    // insert panel after other panels
    var host = document.querySelector('.panel') && document.querySelector('.panel').parentNode;
    if (host) host.appendChild(panel);
    else document.body.appendChild(panel);

    document.getElementById('pspTsLoad').onclick = function() {
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
          html += '<p style="font-size:0.85rem;margin-bottom:8px;"><b>' + (j.daily.fullName||'') + '</b> — کد ' + j.daily.code + ' — ' + j.year + '/' + j.month + '</p>';
          html += '<p style="font-size:0.75rem;color:#64748b;margin-bottom:6px;">جدول روزبه‌روز (شبیه اکسل). ورود/خروج در نسخه بعدی با ثبت ساعت پر می‌شود.</p>';
          html += '<div style="overflow:auto;"><table style="font-size:0.75rem;min-width:900px;"><thead><tr>' +
            '<th>تاریخ</th><th>ورود ۱</th><th>خروج ۱</th><th>ورود ۲</th><th>خروج ۲</th>' +
            '<th>مأموریت ساعتی</th><th>مأموریت روزانه</th><th>مرخصی ساعتی</th><th>مرخصی روزانه</th><th>توضیح</th>' +
            '</tr></thead><tbody>';
          j.daily.days.forEach(function(d){
            html += '<tr><td>' + d.date + '</td><td></td><td></td><td></td><td></td>' +
              '<td>' + (d.missionHourly||'') + '</td><td>' + (d.missionDaily||'') + '</td>' +
              '<td>' + (d.leaveHourly||'') + '</td><td>' + (d.leaveDaily||'') + '</td>' +
              '<td>' + (d.note||'') + '</td></tr>';
          });
          html += '</tbody></table></div>';
        } else if (!document.getElementById('pspTsCode').value.trim()) {
          html += '<p style="font-size:0.8rem;color:#0f766e;margin-bottom:8px;">برای جدول روزبه‌روز شبیه اکسل، یک کد پرسنلی وارد کنید.</p>';
        }
        var rows = (j.rows || []).map(function(x){
          return '<tr><td>' + x.code + '</td><td>' + x.fullName + '</td><td>' + (x.unit||'') + '</td><td>' + (x.managerCode||'') + '</td><td>' + x.workDays + '</td><td>' + x.leaveDays + '</td><td>' + x.hourlyLeave + '</td><td>' + x.missions + '</td><td>' + x.leaves + '</td></tr>';
        }).join('');
        html += '<h4 style="margin-top:14px;">خلاصه ماه</h4><table><thead><tr><th>کد</th><th>نام</th><th>واحد</th><th>مدیر</th><th>کارکرد</th><th>مرخصی روز</th><th>مرخصی ساعت</th><th>مأموریت</th><th>مرخصی</th></tr></thead><tbody>' + rows + '</tbody></table>';
        out.innerHTML = html;
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
    document.getElementById('pspAdmAdd').onclick = function() {
      var st = document.getElementById('pspAdmStatus');
      st.textContent = '…';
      fetch('/api/admin/attendance-request', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({
          empCode: document.getElementById('pspAdmCode').value.trim(),
          typeId: document.getElementById('pspAdmType').value,
          startDate: document.getElementById('pspAdmStart').value.trim(),
          endDate: document.getElementById('pspAdmEnd').value.trim(),
          fromTime: document.getElementById('pspAdmFrom').value,
          toTime: document.getElementById('pspAdmTo').value,
          place: document.getElementById('pspAdmPlace').value.trim(),
          reason: document.getElementById('pspAdmReason').value.trim()
        })
      }).then(function(r){ return r.json(); }).then(function(j){
        if (j.ok) { st.style.color = '#16a34a'; st.textContent = 'ثبت شد — شناسه: ' + j.request.id; }
        else { st.style.color = '#b91c1c'; st.textContent = j.message || j.error || 'خطا'; }
      }).catch(function(){ st.style.color = '#b91c1c'; st.textContent = 'خطا در ارتباط'; });
    };
    document.getElementById('pspAdmDel').onclick = function() {
      var id = document.getElementById('pspAdmDelId').value.trim();
      if (!id) { alert('شناسه را وارد کنید'); return; }
      if (!confirm('حذف درخواست ' + id + '؟')) return;
      var st = document.getElementById('pspAdmStatus');
      st.textContent = '…';
      fetch('/api/admin/attendance-request', {
        method: 'DELETE', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({ id: id })
      }).then(function(r){ return r.json(); }).then(function(j){
        if (j.ok) { st.style.color = '#16a34a'; st.textContent = 'حذف شد'; }
        else { st.style.color = '#b91c1c'; st.textContent = j.message || j.error || 'خطا'; }
      }).catch(function(){ st.style.color = '#b91c1c'; st.textContent = 'خطا در ارتباط'; });
    };
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
  }
  setTimeout(ensurePortalTab, 1200);
  setInterval(ensurePortalTab, 4000);
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
      shiftType: 'none', shiftDays: 0, vars: {}, qty: {}
    };
  }
  return data.monthlyData[key][code];
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
  }
  // missions are kept on the request record for timesheet display (not forced into leaveDays)
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
      if (g) g.usedRequestId = req.id;
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
  const emp = (gd.obj.employees || []).find(e => String(e.code) === code);
  return jsonResponse({
    ok: true,
    code,
    fullName: emp ? emp.fullName : '',
    year, month,
    workDays: Number(row.workDays) || 0,
    leaveDays: Number(row.leaveDays) || 0,
    hourlyLeave: Number(row.hourlyLeave) || 0,
    otHours: Number(row.otHours) || 0,
    nightHours: Number(row.nightHours) || 0,
    requests: reqs
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
    const weekdays = ['', 'شنبه', 'یکشنبه', 'دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه'];
    // approximate weekday from a fixed epoch is hard for Jalali; leave blank or compute roughly
    const dim = daysInJalaliMonth(year, month);
    const dayMap = {};
    for (let d = 1; d <= dim; d++) {
      const dk = year + '-' + String(month).padStart(2, '0') + '-' + String(d).padStart(2, '0');
      dayMap[dk] = {
        day: d,
        date: year + '/' + String(month).padStart(2, '0') + '/' + String(d).padStart(2, '0'),
        weekday: '',
        leaveDaily: '',
        leaveHourly: '',
        missionDaily: '',
        missionHourly: '',
        note: ''
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
        if (x.kind === 'leave' && x.mode === 'hourly') cell.leaveHourly = (cell.leaveHourly ? cell.leaveHourly + '؛ ' : '') + label + ' ' + (x.fromTime || '') + '-' + (x.toTime || '');
        if (x.kind === 'mission' && x.mode === 'daily') cell.missionDaily = (cell.missionDaily ? cell.missionDaily + '؛ ' : '') + label + (x.place ? ' (' + x.place + ')' : '');
        if (x.kind === 'mission' && x.mode === 'hourly') cell.missionHourly = (cell.missionHourly ? cell.missionHourly + '؛ ' : '') + label + ' ' + (x.fromTime || '') + '-' + (x.toTime || '');
        if (x.reason) cell.note = (cell.note ? cell.note + '؛ ' : '') + x.reason;
      });
    });
    daily = {
      code: rows[0].code,
      fullName: rows[0].fullName,
      days: Object.keys(dayMap).sort().map(function (k) { return dayMap[k]; })
    };
  }

  return jsonResponse({ ok: true, year, month, rows, daily: daily });
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
  const grants = ((gd.obj && gd.obj.attendanceGrants) || []).filter(function (g) {
    return String(g.empCode) === String(sess.code) && !g.usedRequestId;
  });
  // hide admin-grant types unless employee has an open grant
  const visible = types.filter(function (t) {
    if (!t.requiresAdminGrant) return true;
    return grants.some(function (g) { return String(g.typeId) === String(t.id); });
  });
  return jsonResponse({ ok: true, types: visible, grants: grants });
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
      usedRequestId: null
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
    gd.obj.attendanceRequests.splice(idx, 1);
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
  if (path === '/api/admin/set-emp-password') return handleAdminSetEmpPassword(request, who, env);
  if (path === '/api/admin/set-manager') return handleAdminSetManager(request, who, env);
  if (path === '/api/admin/get-manager') return handleAdminGetManager(request, who, env);
  if (path === '/api/admin/timesheet') return handleAdminTimesheet(request, who, env);
  if (path === '/api/admin/attendance-types') {
    if (request.method === 'GET') return handleAdminGetAttendanceTypes(env);
    return handleAdminSaveAttendanceTypes(request, who, env);
  }
  if (path === '/api/admin/grant-attendance') return handleAdminGrantAttendance(request, who, env);
  if (path === '/api/admin/attendance-request') {
    if (request.method === 'DELETE') return handleAdminDeleteAttendanceRequest(request, who, env);
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
      <div id="rqEndWrap"><label>تا تاریخ</label><input id="rqEnd" placeholder="1405/01/17" dir="ltr"></div>
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
    endEl.value=addJDays(start,Number(t.fixedDays)||1);
    endEl.readOnly=true;
    endEl.style.background='#f0fdfa';
  } else {
    endEl.readOnly=false;
    endEl.style.background='';
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
  var body={typeId:document.getElementById('rqType').value,kind:document.getElementById('rqKind').value,mode:document.getElementById('rqMode').value,startDate:document.getElementById('rqStart').value.trim(),endDate:document.getElementById('rqEnd').value.trim(),fromTime:document.getElementById('rqFrom').value,toTime:document.getElementById('rqTo').value,place:document.getElementById('rqPlace').value.trim(),reason:document.getElementById('rqReason').value.trim()};
  if(body.kind==='mission'&&!body.place){err.textContent='محل مأموریت الزامی است.';return}
  if(body.kind==='mission'&&!body.reason){err.textContent='توضیح / دلیل مأموریت الزامی است.';return}
  if(!body.startDate){err.textContent='تاریخ الزامی است.';return}

  try{
    var r=await fetch('/api/emp/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'same-origin'});
    var j=await r.json();
    if(!j.ok){err.textContent=j.message||j.error||'خطا';return}
    err.classList.add('okmsg'); err.textContent='درخواست ثبت و برای مدیر ارسال شد.'; loadRequests();
  }catch(e){err.textContent='خطا در ارتباط'}
}
function statusBadge(s){if(s==='approved')return'<span class="badge b-approved">تأیید نهایی</span>';if(s==='approved_l1')return'<span class="badge b-pending">تأیید سطح ۱ — منتظر سطح ۲</span>';if(s==='rejected')return'<span class="badge b-rejected">رد شده</span>';return'<span class="badge b-pending">در انتظار</span>'}
function reqHtml(x,forManager){
  var title=(x.typeName||((x.kind==='mission'?'مأموریت':'مرخصی')+' '+(x.mode==='hourly'?'ساعتی':'روزانه')));
  var dates=x.mode==='hourly'?(x.startDate+' از '+x.fromTime+' تا '+x.toTime):(x.startDate+(x.endDate&&x.endDate!==x.startDate?' تا '+x.endDate:''));
  var extra=''; if(x.place)extra+='<div>محل: '+x.place+'</div>'; if(x.reason)extra+='<div>دلیل: '+x.reason+'</div>'; if(x.status==='rejected'&&x.rejectReason)extra+='<div style="color:#b91c1c">دلیل رد: '+x.rejectReason+'</div>';
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
  else if(!confirm('تأیید شود؟ مرخصی در تایم‌شیت ثبت می‌شود.')) return;
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
    var reqRows=(j.requests||[]).map(function(x){var t=(x.kind==='mission'?'مأموریت':'مرخصی')+' '+(x.mode==='hourly'?'ساعتی':'روزانه'); var d=x.mode==='hourly'?(x.startDate+' '+x.fromTime+'-'+x.toTime):(x.startDate+(x.endDate&&x.endDate!==x.startDate?' تا '+x.endDate:'')); return '<tr><td>'+t+'</td><td>'+d+'</td><td>'+(x.place||'—')+'</td><td>'+(x.reason||'—')+'</td></tr>'}).join('');
    document.getElementById('tsBox').innerHTML='<div class="box"><b>'+(j.fullName||'')+'</b> — '+monthsFa[month]+' '+year+'<table style="margin-top:8px"><tr><th>کارکرد</th><th>مرخصی روزانه</th><th>مرخصی ساعتی</th><th>اضافه‌کار</th><th>شب‌کاری</th></tr><tr><td>'+j.workDays+'</td><td>'+j.leaveDays+'</td><td>'+j.hourlyLeave+'</td><td>'+j.otHours+'</td><td>'+j.nightHours+'</td></tr></table>'+(reqRows?'<h2 style="margin-top:12px">مرخصی/مأموریت تأییدشده</h2><table><tr><th>نوع</th><th>بازه</th><th>محل</th><th>دلیل</th></tr>'+reqRows+'</table>':'')+'</div>';
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
