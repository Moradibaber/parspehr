// AUTO-GENERATED payroll engine. Runs ONLY on the server (never sent to browsers).
// Functions are copied verbatim from the original app; only screen/permission parts were removed.
export function makeEngine(data) {
  function defaultMonthDaysMap() {
    return {1:31,2:31,3:31,4:31,5:31,6:31,7:30,8:30,9:30,10:30,11:30,12:29};
  }

  function getMonthDaysMapForYear(year) {
    year = String(year || data.settings.currentYear || 1405);
    if (!data.settings.monthDaysByYear) data.settings.monthDaysByYear = {};
    if (!data.settings.monthDaysByYear[year]) {
      // اگر برای این سال تعریف نشده، از پیش‌فرض تقویم یا از monthDays قدیمی کپی کن
      data.settings.monthDaysByYear[year] = Object.assign({}, data.settings.monthDays || defaultMonthDaysMap());
    }
    return data.settings.monthDaysByYear[year];
  }

  function getMonthDays(year, month) {
    month = Number(month);
    const md = getMonthDaysMapForYear(year);
    if (md && md[month] != null && Number(md[month]) > 0) return Number(md[month]);
    if (month >= 1 && month <= 6) return 31;
    if (month >= 7 && month <= 11) return 30;
    return 29;
  }

  function parseJalali(str) {
    if (!str) return null;
    const p = str.replace(/\//g,'-').split('-').map(Number);
    if (p.length < 3) return null;
    return { y:p[0], m:p[1], d:p[2] };
  }

  function yearsOfService(hireStr, payYear, payMonth) {
    const h = parseJalali(hireStr);
    if (!h) return 0;
    let years = payYear - h.y;
    if (payMonth < h.m || (payMonth === h.m && 1 < h.d)) years--;
    return Math.max(0, years);
  }

  function maxWorkDaysForEmployee(emp, year, month) {
    const monthDays = getMonthDays(year, month) || 30;
    if (!emp) return monthDays;
    let startDay = 1;
    let endDay = monthDays;
    const hire = parseJalali(emp.hireDate);
    if (hire && hire.y === Number(year) && hire.m === Number(month)) {
      startDay = Math.max(1, Math.min(monthDays, hire.d || 1));
    } else if (hire) {
      // اگر هنوز استخدام نشده
      if (hire.y > Number(year) || (hire.y === Number(year) && hire.m > Number(month))) {
        return 0;
      }
    }
    const end = parseJalali(emp.endDate);
    if (end && end.y === Number(year) && end.m === Number(month)) {
      endDay = Math.max(1, Math.min(monthDays, end.d || monthDays));
    } else if (end) {
      // اگر قبلاً پایان یافته
      if (end.y < Number(year) || (end.y === Number(year) && end.m < Number(month))) {
        return 0;
      }
    }
    if (endDay < startDay) return 0;
    return endDay - startDay + 1;
  }

  function findAllowanceFlags(name) {
    const a = data.allowances.find(x => x.name === name);
    return a ? { ins: !!a.ins, tax: !!a.tax } : { ins: true, tax: true };
  }

  function getActiveEmployees() { return data.employees.filter(e => e.status !== 'inactive'); }

  function nameStartsWithDeductionOrArrears(name) {
    const n = String(name || '').trim();
    if (!n) return false;
    // شروع با یکی از این کلمات + جداکننده یا پایان رشته
    return /^(کسورات|کسر|معوقه)(?=$|[\s\(\)\[\]\{\}\-\–\—_\/،,.:：])/.test(n);
  }

  function isNameDeductionItem(name) {
    const n = String(name || '').trim();
    if (!n) return false;
    return /^(کسورات|کسر)(?=$|[\s\(\)\[\]\{\}\-\–\—_\/،,.:：])/.test(n);
  }

  function isNameArrearsItem(name) {
    const n = String(name || '').trim();
    if (!n) return false;
    return /^معوقه(?=$|[\s\(\)\[\]\{\}\-\–\—_\/،,.:：])/.test(n);
  }

  function isDeductionOrArrearsItem(ci) {
    if (!ci) return true;
    if (ci.isDeduction) return true;
    const n = String(ci.name || '').trim();
    if (!n) return true;
    return nameStartsWithDeductionOrArrears(n);
  }

  function isActiveAllowance(a) { return a && a.name && !a.name.startsWith('آیتم جدید'); }

  function defaultTaxBrackets1405() {
    return [
      { upTo: 400000000, rate: 0 },
      { upTo: 800000000, rate: 10 },
      { upTo: 1000000000, rate: 15 },
      { upTo: 1200000000, rate: 20 },
      { upTo: 1400000000, rate: 25 },
      { upTo: null, rate: 30 }
    ];
  }

  function ensureTaxBrackets() {
    if (!data.settings.taxBrackets || !data.settings.taxBrackets.length) {
      data.settings.taxBrackets = defaultTaxBrackets1405();
    }
    return data.settings.taxBrackets;
  }

  function calcIncomeTax(taxable) {
    const amount = Math.max(0, Number(taxable) || 0);
    if (amount <= 0) return 0;
    const brackets = ensureTaxBrackets().slice().sort(function(a, b) {
      const au = (a.upTo == null || a.upTo === '') ? Infinity : Number(a.upTo);
      const bu = (b.upTo == null || b.upTo === '') ? Infinity : Number(b.upTo);
      return au - bu;
    });
    // آستانه‌ها و اختلاف نرخ‌ها (مثل ستون F و G اکسل)
    // پله نرخ ۰ با سقف ۴۰۰م → آستانه اول ۴۰۰م با دلتای نرخ پله بعدی (۱۰٪)
    const thresholds = [];
    const deltas = [];
    let prevRate = 0;
    for (let i = 0; i < brackets.length; i++) {
      const ratePct = Number(brackets[i].rate) || 0;
      const delta = ratePct - prevRate;
      if (i === 0 && ratePct === 0) {
        // معافیت: آستانه در SUMPRODUCT همان سقف این پله است، دلتا از پله بعد می‌آید
        prevRate = 0;
        continue;
      }
      // آستانه شروع این نرخ = سقف پله قبلی (اگر پله اول غیرصفر باشد، آستانه ۰)
      let thr = 0;
      if (i > 0) {
        const pu = brackets[i - 1].upTo;
        thr = (pu == null || pu === '') ? 0 : Number(pu);
      }
      if (delta !== 0) {
        thresholds.push(thr);
        deltas.push(delta / 100);
      }
      prevRate = ratePct;
    }
    // اگر پله اول نرخ ۰ بود و سقف داشت، اولین آستانه باید سقف پله ۰ باشد
    if (brackets.length && (Number(brackets[0].rate) || 0) === 0) {
      const firstCap = brackets[0].upTo;
      if (firstCap != null && firstCap !== '' && thresholds.length) {
        thresholds[0] = Number(firstCap);
      }
    }
    let tax = 0;
    for (let i = 0; i < thresholds.length; i++) {
      if (amount > thresholds[i]) {
        tax += (amount - thresholds[i]) * deltas[i];
      }
    }
    return Math.round(tax);
  }

  function defaultInsuranceCeilings() {
    return {
      29: { maxBase: 1124995550, employee7: 78749689, employer23: 258748977 },
      30: { maxBase: 1163788500, employee7: 81465195, employer23: 267671355 },
      31: { maxBase: 1202581450, employee7: 84180702, employer23: 276593734 }
    };
  }

  function ensureInsuranceCeilings() {
    if (!data.settings.insuranceCeilings) data.settings.insuranceCeilings = defaultInsuranceCeilings();
    [29, 30, 31].forEach(function(d) {
      if (!data.settings.insuranceCeilings[d]) {
        data.settings.insuranceCeilings[d] = defaultInsuranceCeilings()[d];
      }
    });
    return data.settings.insuranceCeilings;
  }

  function getInsuranceCeilingRow(monthDays) {
    const map = ensureInsuranceCeilings();
    const md = Number(monthDays) || 30;
    if (map[md]) return map[md];
    // تناسب از ماه ۳۰ روزه
    const base = map[30] || defaultInsuranceCeilings()[30];
    const f = md / 30;
    return {
      maxBase: Math.round(base.maxBase * f),
      employee7: Math.round(base.employee7 * f),
      employer23: Math.round(base.employer23 * f)
    };
  }

  function calcEmployeeInsurance(insBase, workDays, monthDays, ratePct) {
    const rate = (ratePct != null ? ratePct : (data.settings.insEmployee || 7)) / 100;
    const md = Number(monthDays) || 30;
    const wd = Math.max(0, Number(workDays) || 0);
    const ratio = md > 0 ? Math.min(1, wd / md) : 1;
    const row = getInsuranceCeilingRow(md);
    const maxBasePeriod = row.maxBase * ratio;
    const maxEmpPeriod = row.employee7 * ratio;
    const cappedBase = Math.min(Math.max(0, Number(insBase) || 0), maxBasePeriod);
    let ins = Math.round(cappedBase * rate);
    const empCap = Math.round(maxEmpPeriod);
    if (empCap > 0) ins = Math.min(ins, empCap);
    return ins;
  }

  function monthsFromStart(y1, m1, y2, m2) {
    return (Number(y2) - Number(y1)) * 12 + (Number(m2) - Number(m1));
  }

  function isCustomItemInDuration(ci, year, month) {
    if (!ci) return false;
    const dur = ci.duration;
    if (dur == null || dur === '' || dur === 'always') return true;
    const n = Number(dur);
    if (!n || n < 1) return true;
    const sy = Number(ci.startYear);
    const sm = Number(ci.startMonth);
    if (!sy || !sm) return true;
    const diff = monthsFromStart(sy, sm, year, month);
    if (diff < 0) return false;
    return diff < n;
  }

  function isCustomItemActive(ci, year, month) {
    if (!ci) return false;
    if (ci.enabled === false) return false; // غیرفعال: حتی با مبلغ در محاسبه نمی‌آید
    return isCustomItemInDuration(ci, year, month);
  }

  function ensureDecreeHeaders() {
    if (!data.decreeHeaders) data.decreeHeaders = [];
    if (!data.decreeValues) data.decreeValues = {};
    return data.decreeHeaders;
  }

  function getDecreeEmpTotals(code) {
    const headers = ensureDecreeHeaders();
    const vals = (data.decreeValues && data.decreeValues[code]) || {};
    let decreeSum = 0, eidSum = 0;
    headers.forEach(function(h) {
      const amt = Number(vals[h.id]) || 0;
      if (h.subjectDecree !== false) decreeSum += amt;
      if (h.subjectEid !== false) eidSum += amt;
    });
    return { decreeSum: decreeSum, eidSum: eidSum };
  }

  function getYearWorkAndLeave(emp, year, leaveCeiling) {
    let workDays = 0, leaveUsed = 0, hourlyLeave = 0;
    for (let m = 1; m <= 12; m++) {
      const key = year + '-' + m;
      const row = (data.monthlyData[key] && data.monthlyData[key][emp.code]) || null;
      if (!row) continue;
      workDays += Number(row.workDays) || 0;
      leaveUsed += Number(row.leaveDays) || 0;
      hourlyLeave += Number(row.hourlyLeave) || 0;
    }
    // مرخصی ساعتی ≈ روز (۷.۳۳ ساعت = ۱ روز)
    leaveUsed += hourlyLeave / 7.33;
    const ceiling = (leaveCeiling != null && !isNaN(Number(leaveCeiling)) && Number(leaveCeiling) >= 0)
      ? Number(leaveCeiling)
      : 30;
    // استحقاقی = تناسب خالص کارکرد (۳۰ روز به ازای ۳۶۵) — سقف دخالت ندارد
    const entitledLeave = (workDays / 365) * 30;
    // مانده = استحقاقی − استفاده‌شده (می‌تواند منفی باشد؛ سقف دخالت ندارد)
    const remaining = entitledLeave - leaveUsed;
    // قابل پرداخت = حداقل(مانده، سقف) — اگر مانده منفی باشد، قابل پرداخت هم منفی می‌شود
    const payableLeave = Math.min(remaining, ceiling);
    return {
      workDays: workDays,
      leaveUsed: leaveUsed,
      entitledLeave: entitledLeave,
      remainingLeave: remaining,
      payableLeave: payableLeave,
      leaveCeiling: ceiling,
      effectiveDays: workDays
    };
  }

  function calcEidAmount(dailyWage, effectiveDays, minDailyLegal) {
    const ratio = Math.min(1, Math.max(0, effectiveDays / 365));
    let eid = dailyWage * 60 * ratio;
    const legalMax = (minDailyLegal || 5541850) * 90 * ratio;
    const legalMin = (minDailyLegal || 5541850) * 60 * ratio;
    if (dailyWage < (minDailyLegal || 5541850)) {
      eid = legalMin;
    }
    if (eid > legalMax) eid = legalMax;
    return Math.round(eid);
  }

  function calcSeveranceAmount(dailyWage, effectiveDays) {
    return Math.round(dailyWage * 30 * Math.min(1, Math.max(0, effectiveDays / 365)));
  }

  function calcEidTax(eidAmount) {
    const exempt = 400000000;
    const excess = Math.max(0, (Number(eidAmount) || 0) - exempt);
    return Math.round(excess * 0.10);
  }

  function calcLeavePayAmount(decreeSum, basicSalary, payableLeaveDays) {
    const base = (Number(decreeSum) > 0) ? Number(decreeSum) : (Number(basicSalary) || 0);
    const daily = base / 30;
    return Math.round(daily * (Number(payableLeaveDays) || 0));
  }

  function applyTransferredAdjustmentsToResults(key, results) {
    const list = (data.transferredAdjustments && data.transferredAdjustments[key]) || [];
    if (!list.length || !results || !results.length) return results;
    results.forEach(function(r) {
      const adjs = list.filter(function(a) { return String(a.code) === String(r.code); });
      if (!adjs.length) return;
      adjs.forEach(function(a) {
        if (!r.itemDetails) r.itemDetails = [];
        (a.itemDetails || []).forEach(function(it) {
          // ردیف‌های مالیات/بیمه اصلاحی جداگانه در جمع بیمه/مالیات اعمال می‌شوند؛ در شرح هم نمایش داده شوند
          r.itemDetails.push({
            name: it.name + (a.fromKey ? ' (از ' + a.fromKey + ')' : ''),
            amount: it.amount,
            isAdjustment: true,
            noTax: true,
            noIns: true,
            isDeduction: it.isDeduction || (Number(it.amount) < 0)
          });
        });
        // فقط مابه‌التفاوت ازپیش‌محاسبه‌شده — بدون محاسبه مجدد مالیات/بیمه روی مبلغ اصلاح
        r.gross = Math.round((Number(r.gross) || 0) + (Number(a.gross) || 0));
        r.insurance = Math.round((Number(r.insurance) || 0) + (Number(a.insurance) || 0));
        r.tax = Math.round((Number(r.tax) || 0) + (Number(a.tax) || 0));
        r.net = Math.round((Number(r.net) || 0) + (Number(a.net) || 0));
        r.hasTransferredAdjustment = true;
        r.adjustmentNote = 'اصلاحات ماه‌های قبل بدون محاسبه مجدد مالیات/بیمه لحاظ شد';
      });
    });
    return results;
  }

  function getAnnualTaxBrackets() {
    return ensureTaxBrackets().map(function(b) {
      return {
        upTo: (b.upTo == null || b.upTo === '') ? null : Number(b.upTo) * 12,
        rate: Number(b.rate) || 0
      };
    });
  }

  function calcIncomeTaxWithBrackets(taxable, bracketsIn) {
    const amount = Math.max(0, Number(taxable) || 0);
    if (amount <= 0) return 0;
    const brackets = (bracketsIn || ensureTaxBrackets()).slice().sort(function(a, b) {
      const au = (a.upTo == null || a.upTo === '') ? Infinity : Number(a.upTo);
      const bu = (b.upTo == null || b.upTo === '') ? Infinity : Number(b.upTo);
      return au - bu;
    });
    const thresholds = [];
    const deltas = [];
    let prevRate = 0;
    for (let i = 0; i < brackets.length; i++) {
      const ratePct = Number(brackets[i].rate) || 0;
      const delta = ratePct - prevRate;
      if (i === 0 && ratePct === 0) {
        prevRate = 0;
        continue;
      }
      let thr = 0;
      if (i > 0) {
        const pu = brackets[i - 1].upTo;
        thr = (pu == null || pu === '') ? 0 : Number(pu);
      }
      if (delta !== 0) {
        thresholds.push(thr);
        deltas.push(delta / 100);
      }
      prevRate = ratePct;
    }
    if (brackets.length && (Number(brackets[0].rate) || 0) === 0) {
      const firstCap = brackets[0].upTo;
      if (firstCap != null && firstCap !== '' && thresholds.length) {
        thresholds[0] = Number(firstCap);
      }
    }
    let tax = 0;
    for (let i = 0; i < thresholds.length; i++) {
      if (amount > thresholds[i]) tax += (amount - thresholds[i]) * deltas[i];
    }
    return Math.round(tax);
  }

  function calcIncomeTaxAnnual(taxableAnnual) {
    return calcIncomeTaxWithBrackets(taxableAnnual, getAnnualTaxBrackets());
  }

  function getYtdTaxInfo(code, year, upToMonthExclusive) {
    let taxable = 0, withheld = 0, monthCount = 0;
    const codeStr = String(code);
    for (let m = 1; m < upToMonthExclusive; m++) {
      const rows = (data.payrolls[year + '-' + m]) || [];
      const r = rows.find(function(x) { return String(x.code) === codeStr; });
      if (!r) continue;
      taxable += estimateTaxableFromPayrollRow(r);
      withheld += Number(r.tax) || 0;
      monthCount += 1;
    }
    return { taxable: taxable, withheld: withheld, monthCount: monthCount };
  }

  function estimateTaxableFromPayrollRow(r) {
    if (r.taxable != null && r.taxable !== '') return Math.max(0, Number(r.taxable) || 0);
    if (r.taxBase != null) return Math.max(0, (Number(r.taxBase) || 0) - (Number(r.insurance) || 0));
    return Math.max(0, (Number(r.gross) || 0) - (Number(r.insurance) || 0));
  }

  function isSpecialStatus(emp) {
    return emp && (emp.status === 'sick' || emp.status === 'suspend');
  }

  function parseJalaliParts(str) {
    if (!str) return null;
    const m = String(str).trim().match(/(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/);
    if (!m) return null;
    return { y: Number(m[1]), m: Number(m[2]), d: Number(m[3]) };
  }

  function countSpecialDaysInMonth(emp, year, month) {
    if (!emp) return 0;
    // فقط وقتی وضعیت فعلی استعلاجی/تعلیق است، یا تاریخ‌ها پر باشد
    const start = parseJalaliParts(emp.statusStart);
    const end = parseJalaliParts(emp.statusEnd);
    if (!start && !end) {
      // بدون تاریخ: اگر special است کل ماه را استعلاجی فرض نکن — 0 (کاربر باید تاریخ بزند)
      return 0;
    }
    const monthDays = getMonthDays(year, month) || 30;
    const rangeStart = start || { y: year, m: month, d: 1 };
    const rangeEnd = end || { y: year, m: month, d: monthDays };
  
    // اگر بازه کاملاً خارج از این ماه باشد
    // شروع بعد از پایان ماه یا پایان قبل از اول ماه
    if (rangeStart.y > year || (rangeStart.y === year && rangeStart.m > month)) return 0;
    if (rangeEnd.y < year || (rangeEnd.y === year && rangeEnd.m < month)) return 0;
  
    let fromDay = 1;
    let toDay = monthDays;
    if (rangeStart.y === year && rangeStart.m === month) fromDay = Math.max(1, rangeStart.d);
    if (rangeEnd.y === year && rangeEnd.m === month) toDay = Math.min(monthDays, rangeEnd.d);
    // اگر شروع قبل از این ماه باشد fromDay=1؛ اگر پایان بعد از این ماه باشد toDay=monthDays
    if (rangeStart.y < year || (rangeStart.y === year && rangeStart.m < month)) fromDay = 1;
    if (rangeEnd.y > year || (rangeEnd.y === year && rangeEnd.m > month)) toDay = monthDays;
  
    if (toDay < fromDay) return 0;
    return (toDay - fromDay + 1);
  }

  function maxWorkDaysWithSpecial(emp, year, month) {
    const monthDays = getMonthDays(year, month) || 30;
    const baseMax = maxWorkDaysForEmployee(emp, year, month);
    const specialDays = countSpecialDaysInMonth(emp, year, month);
    return Math.max(0, Math.min(baseMax, monthDays - specialDays));
  }

  function runMonth(year, month, opts) {
    opts = opts || {};
    const key = year + '-' + month;
    const monthDays = getMonthDays(year, month);
    if (!data.monthlyData[key]) return { ok: false, error: 'no_monthly_data' };
    const workDayCaps = {};
    const loanUpdates = [];
    const s = data.settings;
    const meta = data.monthlyData[key]._meta || {};
    let functionalDays = Number(meta.functionalDays) || Number(s.defaultFunctionalDays) || 22;
    if (functionalDays < 1) functionalDays = 22;
    const results = [];
    getActiveEmployees().forEach(emp => {
      const d = data.monthlyData[key][emp.code] || { workDays: 30, leaveDays: 0, otHours: 0, nightHours: 0, shiftType: 'none', shiftDays: 0, vars: {}, qty: {} };
      const contractType = emp.contractType || 'normal';
      // سقف کارکرد با کسر روزهای استعلاجی/تعلیق همان ماه
      const specialDaysMonth = countSpecialDaysInMonth(emp, year, month);
      if (specialDaysMonth > 0 && d.workDays != null) {
        const cap = maxWorkDaysWithSpecial(emp, year, month);
        if (Number(d.workDays) > cap) { d.workDays = cap; if (data.monthlyData[key][emp.code] === d) workDayCaps[emp.code] = cap; }
      }
  
  
      // —— قرارداد روزمزد / ساعتی (جدا از عادی) ——
      if (contractType === 'daily' || contractType === 'hourly') {
        const units = Number(d.workDays) || 0; // تعداد روز یا ساعت از شیت ورود داده
        const isDaily = contractType === 'daily';
        const divisor = isDaily ? 30 : 192; // روزمزد ÷۳۰ | ساعتی ÷۱۹۲
        const rate = isDaily ? (Number(emp.dailyRate) || 0) : (Number(emp.hourlyRate) || 0);
  
        // مزایای ثابت از شیت مزایا (ماهانه) → سهم واحد (روز یا ساعت)
        function monthlyAllow(id, namePart) {
          const a = (data.allowances || []).find(x => x && (x.id === id || (x.name && x.name.indexOf(namePart) >= 0)));
          return a ? (Number(a.amount) || 0) : 0;
        }
        let housingM = monthlyAllow('housing', 'مسکن');
        let foodM = monthlyAllow('food', 'خواربار');
        let childM = monthlyAllow('child', 'اولاد') * (Number(emp.children) || 0);
        let maritalM = (emp.marital === 'married' || emp.marital === 'provider') ? monthlyAllow('marital', 'تأهل') : 0;
        let seniorityM = 0;
        if (yearsOfService(emp.hireDate, year, month) >= 1) {
          seniorityM = monthlyAllow('seniority', 'سنوات');
        }
  
        const unitHousing = housingM / divisor;
        const unitFood = foodM / divisor;
        const unitChild = childM / divisor;
        const unitMarital = maritalM / divisor;
        const unitSeniority = seniorityM / divisor;
        const unitBenefits = unitHousing + unitFood + unitChild + unitMarital + unitSeniority;
  
        // پایه واحد = نرخ یک روز/ساعت منهای جمع سهم مزایا
        const unitBasic = rate - unitBenefits;
  
        const basicAmount = Math.round(unitBasic * units);
        const amtHousing = Math.round(unitHousing * units);
        const amtFood = Math.round(unitFood * units);
        const amtChild = Math.round(unitChild * units);
        const amtMarital = Math.round(unitMarital * units);
        const amtSeniority = Math.round(unitSeniority * units);
        const rateTotal = Math.round(rate * units); // مزد روز/ساعت × تعداد
  
        // فیش: حقوق پایه = (نرخ − سهم روزانه/ساعتی مزایا) × تعداد
        // هر مزایا = (مبلغ ماهانه ÷ ۳۰ یا ۱۹۲) × تعداد
        // جمع ناخالص = نرخ × تعداد  (بدون اضافه‌کار و شب‌کاری)
        const itemDetails = [];
        if (amtHousing) itemDetails.push({ name: 'حق مسکن', amount: amtHousing });
        if (amtFood) itemDetails.push({ name: 'بن خواربار', amount: amtFood });
        if (amtChild) itemDetails.push({ name: 'حق اولاد', amount: amtChild });
        if (amtMarital) itemDetails.push({ name: 'حق تأهل', amount: amtMarital });
        if (amtSeniority) itemDetails.push({ name: 'پایه سنوات', amount: amtSeniority });
  
        const gross = rateTotal;
        const totalAllow = amtHousing + amtFood + amtChild + amtMarital + amtSeniority;
  
        let insurance = 0, tax = 0;
        if (emp.optInsNormal) {
          // روزمزد: units=روز؛ ساعتی: نسبت به ۱۹۲ ساعت ماه
          const wdForIns = contractType === 'hourly' ? (units / 192) * monthDays : units;
          insurance = calcEmployeeInsurance(gross, wdForIns, monthDays, s.insEmployee);
        }
        if (emp.optTax10) tax = Math.round(gross * 0.10);
  
        const loanKey = emp.code + '-' + key;
        let loanDeduction = 0;
        const alreadyDeducted = data.loanDeductedMonths[loanKey];
        const hasActiveLoan = (Number(emp.loanRemaining) > 0 && Number(emp.monthlyLoan) > 0);
        if (hasActiveLoan) {
          if (!alreadyDeducted) loanDeduction = Math.min(emp.monthlyLoan, emp.loanRemaining);
          else {
            const prev = (data.payrolls[key] || []).find(r => r.code === emp.code);
            loanDeduction = prev ? (prev.loanDeduction || 0) : Math.min(emp.monthlyLoan, emp.loanRemaining);
          }
        }
        const net = gross - insurance - tax - loanDeduction;
        const remainingLoanAfter = alreadyDeducted ? (emp.loanRemaining || 0) : Math.max(0, (emp.loanRemaining || 0) - loanDeduction);
        results.push({
          code: emp.code, fullName: emp.fullName, position: emp.position||'', unit: emp.unit||'',
          workplace: emp.workplace||'', workDays: units, leaveDays: d.leaveDays||0,
          basicAmount, otAmount: 0, nightAmount: 0, totalAllow, totalDeductions: 0, itemDetails,
          gross, insurance, tax, loanDeduction, remainingLoan: remainingLoanAfter, net,
          bankName: emp.bankName||'', accountNumber: emp.accountNumber||'', insuranceNo: emp.insuranceNo||'',
          contractType: contractType, hideOtNight: true
        });
        return;
      }
  
      // —— قرارداد عادی ——
      const maxAllowed = maxWorkDaysForEmployee(emp, year, month);
      const workDays = Math.min(Number(d.workDays)||0, maxAllowed, monthDays);
      // حقوق پایه و پایه سنوات: مبنا ۳۰ روز
      const ratioBase = workDays / 30;
      const ratioFunc = functionalDays > 0 ? (workDays / functionalDays) : 0;
      const basicAmount = Math.round(emp.basicSalary * ratioBase);
      const daily = emp.basicSalary / 30;
      const otAmount = Math.round((daily / 7.33) * (d.otHours||0) * s.overtimeFactor);
      const nightAmount = Math.round((daily / 7.33) * (d.nightHours||0) * (s.nightFactor||1.35));
      // نوبت‌کاری: مزد روزانه × روزهای نوبت × درصد
      // فرمول رایج: تعداد روزهای نوبت × (درصد × مزد روزانه)
      let shiftAmount = 0;
      const st = d.shiftType || 'none';
      let shiftPct = 0;
      if (st === 'me') shiftPct = Number(s.shiftMorningEvening) || 10;
      else if (st === 'mn') shiftPct = Number(s.shiftWithNight) || 22.5;
      else if (st === 'all') shiftPct = Number(s.shiftAllThree) || 15;
      let shiftDays = Number(d.shiftDays) || 0;
      // اگر نوع نوبت انتخاب شده ولی روز وارد نشده، پیش‌فرض = روز کارکرد
      if (shiftPct > 0 && shiftDays <= 0 && workDays > 0) shiftDays = workDays;
      if (shiftPct > 0 && shiftDays > 0) {
        shiftAmount = Math.round(daily * shiftDays * (shiftPct / 100));
      }
      let totalAllow = 0, totalDeductions = 0;
      let insBase = basicAmount, taxBase = basicAmount + otAmount + nightAmount + shiftAmount;
      const itemDetails = [];
  
      data.allowances.filter(a => isActiveAllowance(a) && !a.fromEmployee).forEach(a => {
        let raw = Number(a.amount)||0;
        if (raw === 0) return;
        if (a.id === 'seniority' || a.name.includes('سنوات')) {
          // پایه سنوات: مثل حقوق پایه — مبنا ۳۰ روز
          if (yearsOfService(emp.hireDate, year, month) < 1) return;
          const val = Math.round(raw * ratioBase);
          if (val === 0) return;
          totalAllow += val;
          itemDetails.push({ name: a.name, amount: val });
          if (a.ins) insBase += val;
          if (a.tax) taxBase += val;
          return;
        }
        // حق تأهل، حق مسکن، بن خواربار، حق اولاد و سایر مزایای ثابت: مبلغ کامل بدون تناسب
        if (a.id === 'child') raw = (emp.children||0) * raw;
        if (a.id === 'marital') raw = (emp.marital === 'married' || emp.marital === 'provider') ? raw : 0;
        const val = Math.round(raw);
        if (val === 0) return;
        totalAllow += val;
        itemDetails.push({ name: a.name, amount: val });
        if (a.ins) insBase += val;
        if (a.tax) taxBase += val;
      });
  
      (emp.customItems || []).forEach(ci => {
        if (!ci.name) return;
        // مدت آیتم: همیشه / یک ماه / … — خارج از بازه محاسبه نشود
        if (!isCustomItemActive(ci, year, month)) return;
        const flags = findAllowanceFlags(ci.name);
        const asDeduction = !!ci.isDeduction || isNameDeductionItem(ci.name);
        const asArrears = isNameArrearsItem(ci.name);
        let val = 0;
        let qtyUsed = null;
        const amt = Number(ci.amount) || 0;
        if (ci.entryType === 'quantity') {
          const qty = (d.qty && d.qty[ci.name] !== undefined) ? Number(d.qty[ci.name]) : 0;
          qtyUsed = qty;
          if (qty > 0) {
            val = Math.round(qty * amt);
          } else if ((asDeduction || asArrears) && amt > 0) {
            // کسر/کسورات/معوقه: اگر تعداد وارد نشده، خود مبلغ آیتم ملاک است
            val = Math.round(amt);
            qtyUsed = null;
          }
        } else if (ci.entryType === 'qty_flat') {
          // تعداد خالص: مبلغ × (تعداد مؤثر ÷ کارکرد خالص)
          // تعداد مؤثر = تعداد واردشده؛ اگر صفر/خالی باشد از روز کارکرد استفاده می‌شود
          // تا وقتی کارکرد کم است (مثلاً ۵ روز) مبلغ صفر نشود و تناسب حفظ شود
          let qty = (d.qty && d.qty[ci.name] !== undefined) ? Number(d.qty[ci.name]) : 0;
          if (!(qty > 0) && workDays > 0) qty = workDays;
          qtyUsed = qty;
          if (functionalDays > 0 && amt > 0 && qty > 0) {
            const effectiveQty = Math.min(qty, functionalDays);
            val = Math.round(amt * (effectiveQty / functionalDays));
          } else if ((asDeduction || asArrears) && amt > 0) {
            val = Math.round(amt);
            qtyUsed = null;
          } else {
            val = 0;
          }
        } else {
          // بر اساس کارکرد
          if (ci.isFixed || asDeduction || asArrears) {
            // ثابت / کسر / معوقه: مبلغ کامل
            val = Math.round(amt);
          } else {
            val = Math.round(amt * ratioBase);
          }
        }
        if (val <= 0) return;
        if (asDeduction) {
          totalDeductions += val;
          itemDetails.push({ name: ci.name, amount: val, isDeduction: true, qty: qtyUsed });
        } else {
          totalAllow += val;
          itemDetails.push({ name: ci.name, amount: val, qty: qtyUsed });
          if (flags.ins) insBase += val;
          if (flags.tax) taxBase += val;
        }
      });
  
      if (shiftAmount > 0) {
        const shiftLabels = { me: 'نوبت‌کاری صبح و عصر', mn: 'نوبت‌کاری صبح/عصر و شب', all: 'نوبت‌کاری سه‌نوبته' };
        itemDetails.push({ name: shiftLabels[st] || 'نوبت‌کاری', amount: shiftAmount });
        // نوبت‌کاری معمولاً مشمول بیمه و مالیات است
        insBase += shiftAmount;
      }
      const gross = basicAmount + otAmount + nightAmount + shiftAmount + totalAllow;
      let insurance = 0, tax = 0;
      const exempt = emp.exemption || 'none';
      if (exempt !== 'insurance' && exempt !== 'both') {
        insurance = calcEmployeeInsurance(insBase, workDays, monthDays, s.insEmployee);
      }
      let taxable = 0;
      if (exempt !== 'tax' && exempt !== 'both') {
        taxable = Math.max(0, taxBase - insurance);
        const tp = Number(emp.taxPercent);
        const taxMode = (data.settings.taxMode === 'monthly') ? 'monthly' : 'cumulative';
        if (taxMode === 'cumulative') {
          // تجمعی: مالیات متعلقه تا این ماه − جمع مالیات ماه‌های قبل
          const prev = getYtdTaxInfo(emp.code, year, month);
          const ytdTaxable = prev.taxable + taxable;
          const monthsCount = Math.max(1, prev.monthCount + 1);
          const annualized = ytdTaxable * (12 / monthsCount);
          let taxYtdDue = calcIncomeTaxAnnual(annualized);
          taxYtdDue = Math.round(taxYtdDue * (monthsCount / 12));
          if (tp === 50) taxYtdDue = Math.round(taxYtdDue * 0.5);
          tax = Math.max(0, taxYtdDue - prev.withheld);
        } else {
          tax = calcIncomeTax(taxable);
          if (tp === 50) tax = Math.round(tax * 0.5);
        }
      }
  
      const loanKey = emp.code + '-' + key;
      let loanDeduction = 0;
      const alreadyDeducted = data.loanDeductedMonths[loanKey];
      const hasActiveLoan = (Number(emp.loanRemaining) > 0 && Number(emp.monthlyLoan) > 0);
      if (hasActiveLoan) {
        if (!alreadyDeducted) {
          loanDeduction = Math.min(emp.monthlyLoan, emp.loanRemaining);
        } else {
          // همین ماه قبلاً کسر شده — همان مبلغ را نمایش بده بدون کسر دوباره از مانده
          const prev = (data.payrolls[key] || []).find(r => r.code === emp.code);
          loanDeduction = prev ? (prev.loanDeduction || 0) : Math.min(emp.monthlyLoan, emp.loanRemaining);
        }
      } else {
        // وام حذف یا صفر شده — هیچ کسری اعمال نشود (حتی اگر قبلاً محاسبه شده بود)
        loanDeduction = 0;
      }
  
      const net = gross - insurance - tax - loanDeduction - totalDeductions;
      const remainingLoanAfter = alreadyDeducted
        ? (emp.loanRemaining || 0)
        : Math.max(0, (emp.loanRemaining || 0) - loanDeduction);
  
      results.push({
        code: emp.code, fullName: emp.fullName, position: emp.position||'', unit: emp.unit||'',
        workplace: emp.workplace||'', workDays, leaveDays: d.leaveDays||0,
        basicAmount, otAmount, nightAmount, shiftAmount, shiftType: st, shiftDays: shiftDays, totalAllow, totalDeductions, itemDetails,
        gross, insurance, tax, taxable, taxBase, loanDeduction, remainingLoan: remainingLoanAfter, net,
        bankName: emp.bankName||'', accountNumber: emp.accountNumber||'', insuranceNo: emp.insuranceNo||'',
        taxPercent: Number(emp.taxPercent) || 100, exemption: exempt
      });
    });
  
    if (!opts.skipLoanSE) {
      results.forEach(r => {
        const emp = data.employees.find(e => e.code === r.code);
        if (!emp) return;
        const loanKey = emp.code + '-' + key;
        if (!data.loanDeductedMonths[loanKey] && r.loanDeduction > 0) {
          emp.loanRemaining = Math.max(0, (emp.loanRemaining||0) - r.loanDeduction);
          emp.loanLocked = true;
          data.loanDeductedMonths[loanKey] = true;
          loanUpdates.push({ code: emp.code, loanRemaining: emp.loanRemaining, loanLocked: true, loanKey: loanKey });
        }
      });
    }
    applyTransferredAdjustmentsToResults(key, results);
    data.payrolls[key] = results;
    return { ok: true, results: results, loanUpdates: loanUpdates, workDayCaps: workDayCaps };
  }

  function runEid(year, minDaily, leaveCeilingVal, includeSpecialDays) {
    const results = [];
    getActiveEmployees().forEach(function(emp) {
      let wl = getYearWorkAndLeave(emp, year, leaveCeilingVal);
      // اگر استعلاجی/تعلیق و کاربر گفته کسر شود: فقط روزهای همپوشان با سال از کارکرد کسر شود
      // مرخصی منفی همچنان حفظ و کسر می‌شود
      if (isSpecialStatus(emp) && !includeSpecialDays) {
        let deduct = 0;
        for (let mm = 1; mm <= 12; mm++) {
          deduct += countSpecialDaysInMonth(emp, year, mm);
        }
        const newWork = Math.max(0, (wl.workDays || 0) - deduct);
        const leaveUsed = wl.leaveUsed || 0;
        // استحقاقی متناسب با کارکرد جدید، ولی مرخصی استفاده‌شده حفظ می‌شود
        const entitledNew = Math.round((newWork / 365) * 30 * 10) / 10;
        const remainingNew = Math.round((entitledNew - leaveUsed) * 10) / 10;
        // قابل پرداخت: می‌تواند منفی باشد (بدهی مرخصی)
        let payableNew = remainingNew;
        const ceil = leaveCeilingVal;
        if (payableNew > ceil) payableNew = ceil;
        // منفی را صفر نکن — باید کسر شود
        wl = {
          workDays: newWork,
          leaveUsed: leaveUsed,
          entitledLeave: entitledNew,
          remainingLeave: remainingNew,
          payableLeave: payableNew,
          effectiveDays: newWork
        };
      }
  
      const tots = getDecreeEmpTotals(emp.code);
      const eidSubjectSum = tots.eidSum;
      const decreeSum = tots.decreeSum;
      // مزد روزانه عیدی/سنوات از مشمول عیدی
      const dailyEid = eidSubjectSum > 0 ? (eidSubjectSum / 30) : ((Number(emp.basicSalary) || 0) / 30);
      const eidGross = calcEidAmount(dailyEid, wl.effectiveDays, minDaily);
      const eidTax = calcEidTax(eidGross);
      const eidNet = eidGross - eidTax;
      const severance = calcSeveranceAmount(dailyEid, wl.effectiveDays);
      // مبلغ مرخصی از جمع حکم ÷ ۳۰ × روز قابل پرداخت (مثبت یا منفی)
      const leaveDaily = decreeSum > 0 ? (decreeSum / 30) : ((Number(emp.basicSalary) || 0) / 30);
      const leavePay = calcLeavePayAmount(decreeSum, emp.basicSalary, wl.payableLeave);
      let totalPay = eidNet + severance + leavePay;
      let annualTaxAdj = 0;
      let annualTaxAdjTitle = '';
      if (data.eidTaxAdjustments && data.eidTaxAdjustments[year] && data.eidTaxAdjustments[year][String(emp.code)]) {
        const adj = data.eidTaxAdjustments[year][String(emp.code)];
        annualTaxAdj = Number(adj.netAdj) || 0;
        annualTaxAdjTitle = adj.title || ('اصلاح مالیات سالانه (تسویه وسط سال) ' + year);
        totalPay = Math.round(totalPay + annualTaxAdj);
      }
      results.push({
        code: emp.code,
        fullName: emp.fullName,
        hireDate: emp.hireDate || '',
        workDays: Math.round(wl.workDays * 10) / 10,
        leaveUsed: Math.round(wl.leaveUsed * 10) / 10,
        entitledLeave: Math.round(wl.entitledLeave * 10) / 10,
        remainingLeave: Math.round(wl.remainingLeave * 10) / 10,
        payableLeave: Math.round(wl.payableLeave * 10) / 10,
        leaveCeiling: leaveCeilingVal,
        dailyWage: Math.round(dailyEid),
        leaveDailyWage: Math.round(leaveDaily),
        eidSubjectSum: eidSubjectSum,
        decreeSum: decreeSum,
        eidGross: eidGross,
        eidTax: eidTax,
        eidNet: eidNet,
        severance: severance,
        leavePay: leavePay,
        totalPay: totalPay,
        totalPayBase: eidNet + severance + leavePay,
        annualTaxAdj: annualTaxAdj,
        annualTaxAdjTitle: annualTaxAdjTitle,
        specialStatus: isSpecialStatus(emp) ? emp.status : '',
        statusStart: emp.statusStart || '',
        statusEnd: emp.statusEnd || '',
        includeSpecialDays: isSpecialStatus(emp) ? includeSpecialDays : null
      });
    });
    return results;
  }

  function runAnnualTax(year, until, selected) {
    const selectedSet = {};
    selected.forEach(function(c) { selectedSet[String(c)] = true; });
    const byCode = {};
  
    for (let m = 1; m <= until; m++) {
      const rows = data.payrolls[year + '-' + m] || [];
      rows.forEach(function(r) {
        if (!r || !r.code) return;
        const code = String(r.code);
        if (!selectedSet[code]) return;
        if (!byCode[code]) {
          byCode[code] = {
            code: r.code,
            fullName: r.fullName || '',
            months: 0,
            totalTaxable: 0,
            totalTaxWithheld: 0,
            taxPercent: Number(r.taxPercent) || 100,
            exemption: r.exemption || 'none'
          };
        }
        byCode[code].months += 1;
        byCode[code].totalTaxable += estimateTaxableFromPayrollRow(r);
        byCode[code].totalTaxWithheld += Number(r.tax) || 0;
        if (r.taxPercent != null) byCode[code].taxPercent = Number(r.taxPercent) || 100;
        if (r.exemption) byCode[code].exemption = r.exemption;
      });
    }
  
    (data.employees || []).forEach(function(emp) {
      const c = String(emp.code);
      if (byCode[c]) {
        byCode[c].fullName = emp.fullName || byCode[c].fullName;
        byCode[c].taxPercent = Number(emp.taxPercent) || byCode[c].taxPercent || 100;
        byCode[c].exemption = emp.exemption || byCode[c].exemption || 'none';
      }
    });
  
    const results = Object.keys(byCode).map(function(code) {
      const row = byCode[code];
      let dueTax = 0;
      if (row.exemption !== 'tax' && row.exemption !== 'both') {
        const mc = Math.max(1, row.months);
        // تا ماه انتخابی: سالیانه‌سازی سپس سهم همان تعداد ماه
        const annualized = row.totalTaxable * (12 / mc);
        dueTax = calcIncomeTaxAnnual(annualized);
        dueTax = Math.round(dueTax * (mc / 12));
        if (Number(row.taxPercent) === 50) dueTax = Math.round(dueTax * 0.5);
      }
      const diff = Math.round(dueTax - row.totalTaxWithheld);
      let status = 'تسویه';
      if (diff > 0) status = 'بدهکار (کسری)';
      else if (diff < 0) status = 'بستانکار (اضافه پرداخت)';
      return {
        code: row.code,
        fullName: row.fullName,
        months: row.months,
        totalTaxable: Math.round(row.totalTaxable),
        totalTaxWithheld: Math.round(row.totalTaxWithheld),
        annualTax: dueTax,
        diff: diff,
        status: status,
        year: year,
        untilMonth: until
      };
    }).sort(function(a, b) {
      return String(a.code).localeCompare(String(b.code), 'fa');
    });
    return results;
  }

  let bonusItemNames = [];
  function calcBonusBaseForEmp(emp, baseType) {
    if (baseType === 'basic') return Number(emp.basicSalary) || 0;
    const tots = typeof getDecreeEmpTotals === 'function' ? getDecreeEmpTotals(emp.code) : { decreeSum: 0, eidSum: 0 };
    if (baseType === 'eidSubject') return tots.eidSum || 0;
    if (baseType === 'decree') return tots.decreeSum || Number(emp.basicSalary) || 0;
    if (baseType === 'items') {
      const names = bonusItemNames;
      let sum = 0;
      if (names.indexOf('__basic__') >= 0) sum += Number(emp.basicSalary) || 0;
      const allowMap = {};
      (data.allowances || []).forEach(function(a) { if (a && a.name) allowMap[a.name] = Number(a.amount) || 0; });
      // custom per employee
      const customs = emp.customItems || emp.customs || [];
      names.forEach(function(n) {
        if (n === '__basic__') return;
        // from decree values if available
        if (data.decreeValues && data.decreeValues[emp.code] && data.decreeValues[emp.code][n] != null) {
          sum += Number(data.decreeValues[emp.code][n]) || 0;
        } else if (allowMap[n] != null) {
          sum += allowMap[n];
        }
      });
      return sum;
    }
    return tots.decreeSum || 0;
  }
  function bonusBases(emps, baseType, names) {
    bonusItemNames = Array.isArray(names) ? names : [];
    const bases = {};
    emps.forEach(function(emp) { bases[emp.code] = calcBonusBaseForEmp(emp, baseType); });
    return bases;
  }
  function bonusRows(rows) {
    return rows.map(function(r) {
      const gross = r.eligible ? Math.round((Number(r.base) || 0) * (Number(r.pct) || 0) / 100) : 0;
      const tax = r.eligible ? calcIncomeTaxWithBrackets(gross) : 0;
      return { code: r.code, gross: gross, tax: tax, net: gross - tax };
    });
  }

  function decreeAmounts(year, selectedNames) {
    const selectedSet = {};
    selectedNames.forEach(function(n) { selectedSet[n] = true; });
    const month = 12;
    const entries = [];
  
    getActiveEmployees().forEach(function(emp) {
  
      if (selectedSet['حقوق پایه']) {
        entries.push({ code: emp.code, name: 'حقوق پایه', amount: Number(emp.basicSalary) || 0 });
      }
  
      (data.allowances || []).forEach(function(a) {
        if (!a || !a.name) return;
        const n = String(a.name).trim();
        if (!selectedSet[n]) return;
        if (isDeductionOrArrearsItem({ name: n })) return;
        let amt = Number(a.amount) || 0;
        if (a.id === 'child' || n.indexOf('اولاد') >= 0) {
          amt = (Number(emp.children) || 0) * (Number(a.amount) || 0);
        }
        if (a.id === 'marital' || n.indexOf('تأهل') >= 0 || n.indexOf('تاهل') >= 0) {
          amt = (emp.marital === 'married' || emp.marital === 'provider') ? (Number(a.amount) || 0) : 0;
        }
        if (a.id === 'seniority' || n.indexOf('سنوات') >= 0) {
          if (yearsOfService(emp.hireDate, year, month) < 1) amt = 0;
          else amt = Number(a.amount) || 0;
        }
        entries.push({ code: emp.code, name: n, amount: amt });
      });
  
      (emp.customItems || []).forEach(function(ci) {
        if (!ci || !ci.name) return;
        if (isDeductionOrArrearsItem(ci)) return;
        const n = String(ci.name).trim();
        if (!selectedSet[n]) return;
        entries.push({ code: emp.code, name: n, amount: Number(ci.amount) || 0 });
      });
    });
    return entries;
  }

  return { runMonth: runMonth, runEid: runEid, runAnnualTax: runAnnualTax, bonusBases: bonusBases, bonusRows: bonusRows, decreeAmounts: decreeAmounts };
}
