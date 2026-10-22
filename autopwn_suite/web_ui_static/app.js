// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-2026 Kaan Gültekin
// ── State ──────────────────────────────────────────────────────────────────────
let scans    = {};
let hosts    = {};
let profiles = {};
let schedules= {};
let selIp    = null;
let es       = null;
let pollT    = null;
let lastScansStr = '';
let lastHostsStr = '';
let pollBusy = false;

// ── Utilities ──────────────────────────────────────────────────────────────────
function _buildNmapBase(target, mode, speed, to, technique) {
  // Pick the scan type flag: user-selected technique replaces default -sS
  const scanType = technique || '-sS';
  let cmd = `nmap ${target} ${scanType} -sV --host-timeout ${to} -Pn -O -T ${speed}`;
  if (mode === 'evade') cmd += ' -f -g 53 --data-length 10';
  return cmd;
}
function updateNmapPreview() {
  const target = document.getElementById('f-target').value.trim() || '<target>';
  const mode = document.getElementById('f-mode').value;
  const speed = document.getElementById('f-speed').value;
  const to = document.getElementById('f-timeout').value || 240;
  const tech = document.getElementById('f-scantech');
  const technique = (tech && tech.value) ? tech.value : '';

  const base = _buildNmapBase(target, mode, speed, to, technique);

  const flags = [];
  const ports = document.getElementById('f-ports');
  if (ports && ports.value.trim()) flags.push('-p ' + ports.value.trim());
  const vint = document.getElementById('f-vint');
  if (vint && vint.value) flags.push('--version-intensity ' + vint.value);
  const os = document.getElementById('f-os');
  if (os && os.checked) flags.push('-O');

  const combinedFlags = flags.join(' ').trim();
  let previewCmd = base;
  if (combinedFlags) {
    let previewFlags = combinedFlags;
    if (previewCmd.includes('-O') && previewFlags.includes('-O')) {
      previewFlags = previewFlags.replace(/(^|\s)-O(\s|$)/g, ' ').trim();
    }
    if (previewFlags) previewCmd += ' ' + previewFlags;
  }

  const previewEl = document.getElementById('f-nmap-preview');
  if (previewEl) previewEl.value = previewCmd.trim();
}
function updateProfilePreview() {
  const mode = document.getElementById('pf-mode').value;
  const speed = document.getElementById('pf-speed').value;
  const to = document.getElementById('pf-timeout').value || 240;
  const tech = document.getElementById('pf-scantech');
  const technique = (tech && tech.value) ? tech.value : '';

  const base = _buildNmapBase('<target>', mode, speed, to, technique);

  const flags = [];
  const ports = document.getElementById('pf-ports');
  if (ports && ports.value.trim()) flags.push('-p ' + ports.value.trim());
  const vint = document.getElementById('pf-vint');
  if (vint && vint.value) flags.push('--version-intensity ' + vint.value);
  const os = document.getElementById('pf-os');
  if (os && os.checked) flags.push('-O');

  const combinedFlags = flags.join(' ').trim();
  let previewCmd = base;
  if (combinedFlags) {
    let previewFlags = combinedFlags;
    if (previewCmd.includes('-O') && previewFlags.includes('-O')) {
      previewFlags = previewFlags.replace(/(^|\s)-O(\s|$)/g, ' ').trim();
    }
    if (previewFlags) previewCmd += ' ' + previewFlags;
  }

  const previewEl = document.getElementById('pf-nmap-preview');
  if (previewEl) previewEl.value = previewCmd.trim();
}
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function shortId(id){ return id ? id.slice(0,8) : ''; }
// Severity comes from the vulnerability database, which a copied mirror can fill with anything: it only
// ever reaches a class attribute or the page as one of these words, and a CVSS score is escaped as text.
const SEVERITIES = ['critical','high','medium','low','unknown'];
function sevClass(s){ const k = String(s ?? '').toLowerCase(); return SEVERITIES.includes(k) ? k : 'unknown'; }
function cvssText(c){ return c ? esc(c) : '—'; }
// The same rule for the categories of a finding: they are saved with the scan, and only these words ever reach the page.
// A finding saved before categories existed has none, so it appears only under "All".
const VULN_CATEGORIES = ['rce','privilege_escalation','injection','xss','auth_bypass','info_disclosure','dos','memory_corruption','other'];
let vulnCategoryFilter = '';
let vulnTally = {shown: 0, total: 0};
function vulnCategories(v){ return Array.isArray(v.categories) ? VULN_CATEGORIES.filter(c => v.categories.includes(c)) : []; }
function categoryLabel(c){ return window.i18n.t('vuln.cat_' + c); }
function categoryBadges(v){ return vulnCategories(v).map(c => `<span class="cat">${esc(categoryLabel(c))}</span>`).join(' '); }
function categoryCounts(rows){
  const counts = {};
  rows.forEach(v => vulnCategories(v).forEach(c => { counts[c] = (counts[c] || 0) + 1; }));
  return counts;
}
function renderCategoryBar(rows){
  const bar = document.getElementById('vuln-cats');
  const counts = categoryCounts(rows);
  if(vulnCategoryFilter && !counts[vulnCategoryFilter]) vulnCategoryFilter = '';
  bar.hidden = !rows.length;
  if(!rows.length){ bar.innerHTML = ''; return; }
  const chip = (cat, label, n) => `<button type="button" class="cat-chip" data-cat="${cat}" aria-pressed="${vulnCategoryFilter === cat}">${esc(label)} (${n})</button>`;
  bar.innerHTML = chip('', window.i18n.t('vuln.cat_all'), rows.length)
    + VULN_CATEGORIES.filter(c => counts[c]).map(c => chip(c, categoryLabel(c), counts[c])).join('')
    + `<span class="cat-note">${esc(window.i18n.t('vuln.cat_note'))}</span>`;
}
function pickVulnCategory(event){
  const button = event.target.closest('button[data-cat]');
  if(!button) return;
  const cat = button.dataset.cat;
  vulnCategoryFilter = cat && cat !== vulnCategoryFilter ? cat : '';
  renderVulnTable();
  const again = document.querySelector(`#vuln-cats [data-cat="${cat}"]`);
  if(again) again.focus();
  // A screen reader hears what the press did to the table, which it cannot see change.
  document.getElementById('vuln-cat-status').textContent = vulnCategoryFilter
    ? window.i18n.t('vuln.cat_status', {category: categoryLabel(vulnCategoryFilter), shown: vulnTally.shown, total: vulnTally.total})
    : window.i18n.t('vuln.cat_status_all', {total: vulnTally.total});
}
function openReportWindow(){
  const win = window.open('', '_blank');
  if(!win) toast(window.i18n.t('toast.popup_blocked'), false);
  return win;
}
async function fetchJson(url){
  const response = await fetch(url);
  if(!response.ok) throw new Error(window.i18n.t('toast.request_failed', {status: response.status}));
  return response.json();
}
function latestHostObservations(rows){
  const latest = {};
  rows.forEach(h=>{
    const prev = latest[h.ip];
    const observed = Date.parse(h.observed_at || scans[h.scan_id]?.started_at || '') || 0;
    const previous = Date.parse(prev?.observed_at || scans[prev?.scan_id]?.started_at || '') || 0;
    if(!prev || observed >= previous) latest[h.ip] = h;
  });
  return latest;
}
function isHostDone(h){
  if(h.latest_attempt) return false;
  if(h.scan_status === 'scanning') return false;
  if(h.scan_status === 'failed' || h.scan_status === 'error') return false;
  if(h.scan_status === 'stopped') return false;
  if(h.scan_status === 'not_observed') return false;
  if(h.scan_status === 'partial' || h.lookup_status === 'partial') return false;
  if(h.lookup_status === 'skipped' || h.lookup_status === 'not_run') return false;
  return h.scan_status === 'completed';
}
function hostScanLabel(h){
  if(h.latest_attempt) return window.i18n.t('host.latest_scan', {status: hostScanLabel({...h.latest_attempt, latest_attempt:null})});
  if(h.scan_status === 'scanning') return window.i18n.t('host.scanning');
  if(h.scan_status === 'failed' || h.scan_status === 'error') return window.i18n.t('host.scan_failed');
  if(h.scan_status === 'stopped') return window.i18n.t('host.stopped');
  if(h.scan_status === 'not_observed') return window.i18n.t('host.not_observed');
  if(h.scan_status === 'partial' || h.lookup_status === 'partial') return window.i18n.t('host.incomplete');
  if(h.lookup_status === 'skipped' || h.lookup_status === 'not_run') return window.i18n.t('host.cves_not_checked');
  return h.scan_status === 'completed' ? window.i18n.t('host.done') : window.i18n.t('host.status_unknown');
}
async function printScan(scanId) {
  const job = scans[scanId];
  if(!job) return;
  // Open while the click still has user activation, before the download awaits.
  const win = openReportWindow();
  if(!win) return;
  let saved;
  try {
    saved = await fetchJson(`/api/scans/${encodeURIComponent(scanId)}/download`);
  } catch(e){
    win.close();
    toast(window.i18n.t('toast.could_not_load_scan_report', {detail: e.message}), false);
    return;
  }
  if(win.closed) return;
  let html = `<!DOCTYPE html><html><head><title>Scan Report - ${esc(job.target)}</title>
  <style>
    body{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; color: #333; line-height: 1.5;}
    h1, h2, h3, h4{color: #111; margin-bottom: 8px;}
    table{width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;}
    th, td{border: 1px solid #ddd; padding: 10px; text-align: left;}
    th{background-color: #f5f5f5;}
    .meta{background: #f9f9f9; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #eee;}
    .meta p{margin: 5px 0;}
    .sev-critical{color: #d32f2f; font-weight: bold;}
    .sev-high{color: #f57c00; font-weight: bold;}
    .sev-medium{color: #fbc02d; font-weight: bold;}
    .sev-low{color: #388e3c; font-weight: bold;}
    .sev-unknown{color: #777;}
    @media print { body { padding: 0; } }
  </style>
  </head><body>
  <div style="display: flex; align-items: center; margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px;">
    <img src="${window.location.origin}/favicon.ico" style="width: 40px; height: 40px; margin-right: 15px;" alt="Logo">
    <h1 style="margin: 0; color: #111;">AutoPWN Suite <span style="color: #777; font-weight: normal;">— Scan Report</span></h1>
  </div>
  <div class="meta">
    <p><strong>Target:</strong> ${esc(job.target)}</p>
    <p><strong>Scan ID:</strong> ${esc(job.id)}</p>
    <p><strong>Status:</strong> ${job.status}</p>
    <p><strong>Vulnerability data:</strong> ${esc(job.config?.vulnerability_source_used || job.config?.vulnerability_source || 'online')}${job.config?.vulnerability_database_updated_at ? ' · Database updated ' + esc(job.config.vulnerability_database_updated_at) : ''}</p>
    <p><strong>Started:</strong> ${job.started_at}</p>
    <p><strong>Finished:</strong> ${job.finished_at || 'N/A'}</p>
  </div>
  <h2>Hosts Discovered (${job.host_count})</h2>
  `;
  const scanHosts = (saved.hosts||[]).map(h=>({...h, vulns:h.vulns || (h.ports||[]).flatMap(p=>p.vulnerabilities||[]).concat(h.unmapped_vulnerabilities||[])}));
  if(scanHosts.length) {
    scanHosts.forEach(h => {
      html += `<h3>Host: ${esc(h.ip)}</h3>`;
      html += `<div class="meta"><p><strong>MAC:</strong> ${esc(h.mac || '—')} &nbsp;|&nbsp; <strong>OS:</strong> ${esc(h.os || '—')} &nbsp;|&nbsp; <strong>Vendor:</strong> ${esc(h.vendor || '—')}</p></div>`;
      if(h.ports && h.ports.length) {
        html += `<h4>Open Ports</h4><table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>`;
        h.ports.forEach(p => {
          html += `<tr><td>${esc(p.protocol||'tcp')}/${esc(p.port)}</td><td>${esc(p.service || '')}</td><td>${esc(p.product || '')}</td><td>${esc(p.version || '')}</td></tr>`;
        });
        html += `</table>`;
      } else {
        html += `<p>${job.config?.scan_ports === false ? 'Port scan was not selected.' : 'No open ports found.'}</p>`;
      }
      const vulns = (h.vulns || []);
      if(vulns.length) {
        html += `<h4>Vulnerabilities</h4><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>`;
        vulns.forEach(v => {
          const sev = sevClass(v.severity);
          html += `<tr><td>${esc(v.cve)}</td><td class="sev-${sev}">${sev.toUpperCase()}</td><td>${cvssText(v.cvss)}</td><td>${esc(v.description)}</td></tr>`;
        });
        html += `</table>`;
      }
      html += `<hr style="border:0; border-top:2px dashed #eee; margin:30px 0;">`;
    });
  } else {
    html += `<p>No hosts were found during this scan.</p>`;
  }
  if(saved.web_findings?.length){
    html += `<h2>Web Findings (${saved.web_findings.length})</h2><p>Evidence reproduction does not establish full exploit impact. Download the JSON report for captured exchanges and reproduction plans.</p>`;
    saved.web_findings.forEach(row=>{
      const detail = row.details || {};
      html += `<h3>${esc(detail.title || row.type)}</h3><p><strong>${esc(row.severity)} · ${esc(row.confidence)}</strong> · ${esc(row.url)}</p>
        <p><strong>Evidence:</strong> ${esc(row.evidence)}</p><p><strong>Remediation:</strong> ${esc(detail.remediation || 'Review application context.')}</p>
        <p><strong>Limitations:</strong> ${esc(detail.limitations || 'Impact has not been verified.')}</p>
        <p><strong>Verification:</strong> ${esc(row.verification?.status || 'Not run')} · ${esc(row.verification?.summary || '')}</p>`;
    });
  }
  if(saved.web_coverage?.length){
    html += `<h2>Web Coverage</h2>${saved.web_coverage.map(item=>`<p>${esc(item.endpoint || item.target)} · ${esc(item.status)} · ${esc(item.total_requests ?? item.requests)} requests${item.attempts > 1 ? ' over ' + esc(item.attempts) + ' attempts' : ''}${item.issues?.length ? ' · ' + esc(item.issues.join('; ')) : ''}</p>`).join('')}`;
  }
  html += `</body></html>`;
  win.document.write(html);
  win.document.close();
  setTimeout(() => { win.print(); }, 500);
}

function printHost(ip) {
  const h = hosts[ip];
  if(!h) return;
  let html = `<!DOCTYPE html><html><head><title>Host Report - ${esc(h.ip)}</title>
  <style>
    body{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; color: #333; line-height: 1.5;}
    h1, h2, h3, h4{color: #111; margin-bottom: 8px;}
    table{width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;}
    th, td{border: 1px solid #ddd; padding: 10px; text-align: left;}
    th{background-color: #f5f5f5;}
    .meta{background: #f9f9f9; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #eee;}
    .meta p{margin: 5px 0;}
    .sev-critical{color: #d32f2f; font-weight: bold;}
    .sev-high{color: #f57c00; font-weight: bold;}
    .sev-medium{color: #fbc02d; font-weight: bold;}
    .sev-low{color: #388e3c; font-weight: bold;}
    .sev-unknown{color: #777;}
    @media print { body { padding: 0; } }
  </style>
  </head><body>
  <div style="display: flex; align-items: center; margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px;">
    <img src="${window.location.origin}/favicon.ico" style="width: 40px; height: 40px; margin-right: 15px;" alt="Logo">
    <h1 style="margin: 0; color: #111;">AutoPWN Suite <span style="color: #777; font-weight: normal;">— Host Report</span></h1>
  </div>
  <div class="meta">
    <p><strong>Host IP:</strong> ${esc(h.ip)}</p>
    <p><strong>MAC Address:</strong> ${esc(h.mac || '—')}</p>
    <p><strong>Operating System:</strong> ${esc(h.os || '—')}</p>
    <p><strong>Vendor:</strong> ${esc(h.vendor || '—')}</p>
  </div>
  `;
  if(h.ports && h.ports.length) {
    html += `<h3>Open Ports (${h.ports.length})</h3><table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>`;
    h.ports.forEach(p => {
      html += `<tr><td>${esc(p.protocol||'tcp')}/${esc(p.port)}</td><td>${esc(p.service || '')}</td><td>${esc(p.product || '')}</td><td>${esc(p.version || '')}</td></tr>`;
    });
    html += `</table>`;
  } else {
    html += `<p>No open ports found.</p>`;
  }
  const vulns = (h.vulns || []);
  if(vulns.length) {
    html += `<h3>Vulnerabilities (${vulns.length})</h3><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>`;
    vulns.forEach(v => {
      const sev = sevClass(v.severity);
      html += `<tr><td>${esc(v.cve)}</td><td class="sev-${sev}">${sev.toUpperCase()}</td><td>${cvssText(v.cvss)}</td><td>${esc(v.description)}</td></tr>`;
    });
    html += `</table>`;
  }
  html += `</body></html>`;
  const win = openReportWindow();
  if(!win) return;
  win.document.write(html);
  win.document.close();
  setTimeout(() => { win.print(); }, 500);
}

function printAllVulns() {
  const all=[];
  Object.values(hosts).forEach(h=>(h.vulns||[]).forEach(v=>all.push({...v, hostBase:h.ip, scan_id:h.scan_id, host:h.ip+(v.port?':'+v.port:'')})));

  const fSearch = document.getElementById('vuln-search').value.toLowerCase();
  const fHost = document.getElementById('vuln-host').value;
  const fScan = document.getElementById('vuln-scanid').value;
  const fSev = document.getElementById('vuln-sev').value;

  const filtered = all.filter(v => (!fHost || v.hostBase === fHost) && (!fScan || v.scan_id === fScan) && (!fSev || sevClass(v.severity) === fSev) && (!fSearch || `${v.cve} ${v.keyword} ${v.description} ${v.host}`.toLowerCase().includes(fSearch))).filter(v => !vulnCategoryFilter || vulnCategories(v).includes(vulnCategoryFilter));
  filtered.sort((a,b)=>(b.cvss||0)-(a.cvss||0));

  if(!filtered.length) {
    toast(window.i18n.t('toast.no_vulns_to_export'), false);
    return;
  }

  const catCounts = categoryCounts(filtered);
  const catSummary = VULN_CATEGORIES.filter(c => catCounts[c]).map(c => `${esc(categoryLabel(c))}: ${catCounts[c]}`).join(' &nbsp;|&nbsp; ') || '—';
  let html = `<!DOCTYPE html><html><head><title>Vulnerabilities Report</title>
  <style>
    body{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; color: #333; line-height: 1.5;}
    h1, h2, h3, h4{color: #111; margin-bottom: 8px;}
    table{width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;}
    th, td{border: 1px solid #ddd; padding: 10px; text-align: left;}
    th{background-color: #f5f5f5;}
    .meta{background: #f9f9f9; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #eee;}
    .meta p{margin: 5px 0;}
    .sev-critical{color: #d32f2f; font-weight: bold;}
    .sev-high{color: #f57c00; font-weight: bold;}
    .sev-medium{color: #fbc02d; font-weight: bold;}
    .sev-low{color: #388e3c; font-weight: bold;}
    .sev-unknown{color: #777;}
    @media print { body { padding: 0; } }
  </style>
  </head><body>
  <div style="display: flex; align-items: center; margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px;">
    <img src="${window.location.origin}/favicon.ico" style="width: 40px; height: 40px; margin-right: 15px;" alt="Logo">
    <h1 style="margin: 0; color: #111;">AutoPWN Suite <span style="color: #777; font-weight: normal;">— Vulnerabilities Report</span></h1>
  </div>
  <div class="meta">
    <p><strong>Total Vulnerabilities:</strong> ${filtered.length}</p>
    <p><strong>Filters Applied:</strong> Host: ${esc(fHost||'All')} &nbsp;|&nbsp; Scan: ${esc(fScan||'All')} &nbsp;|&nbsp; Severity: ${esc(fSev?fSev.toUpperCase():'All')} &nbsp;|&nbsp; ${esc(window.i18n.t('vuln.col_category'))}: ${esc(vulnCategoryFilter ? categoryLabel(vulnCategoryFilter) : window.i18n.t('vuln.cat_all'))} &nbsp;|&nbsp; Search: ${esc(fSearch||'None')}</p>
    <p><strong>${esc(window.i18n.t('vuln.categories_label'))}:</strong> ${catSummary}</p>
  </div>
  <table>
    <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Host</th><th>Keyword</th><th>${esc(window.i18n.t('vuln.col_category'))}</th><th>Description</th></tr>
  `;
  filtered.forEach(v => {
    const sev = sevClass(v.severity);
    html += `<tr>
      <td style="white-space:nowrap;">${esc(v.cve)}</td>
      <td class="sev-${sev}">${sev.toUpperCase()}</td>
      <td>${cvssText(v.cvss)}</td>
      <td style="white-space:nowrap;">${esc(v.host)}</td>
      <td>${esc(v.keyword || '')}</td>
      <td>${categoryBadges(v)}</td>
      <td>${esc(v.description)}</td>
    </tr>`;
  });
  html += `</table></body></html>`;

  const win = openReportWindow();
  if(!win) return;
  win.document.write(html);
  win.document.close();
  setTimeout(() => { win.print(); }, 500);
}

function printAllHosts() {
  const list = Object.values(hosts);
  if(!list.length) {
    toast(window.i18n.t('toast.no_hosts_to_export'), false);
    return;
  }
  let html = `<!DOCTYPE html><html><head><title>All Hosts Report</title>
  <style>
    body{font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 20px; color: #333; line-height: 1.5;}
    h1, h2, h3, h4{color: #111; margin-bottom: 8px;}
    table{width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px;}
    th, td{border: 1px solid #ddd; padding: 10px; text-align: left;}
    th{background-color: #f5f5f5;}
    .meta{background: #f9f9f9; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #eee;}
    .meta p{margin: 5px 0;}
    .sev-critical{color: #d32f2f; font-weight: bold;}
    .sev-high{color: #f57c00; font-weight: bold;}
    .sev-medium{color: #fbc02d; font-weight: bold;}
    .sev-low{color: #388e3c; font-weight: bold;}
    .sev-unknown{color: #777;}
    @media print { body { padding: 0; } }
  </style>
  </head><body>
  <div style="display: flex; align-items: center; margin-bottom: 20px; border-bottom: 2px solid #eee; padding-bottom: 10px;">
    <img src="${window.location.origin}/favicon.ico" style="width: 40px; height: 40px; margin-right: 15px;" alt="Logo">
    <h1 style="margin: 0; color: #111;">AutoPWN Suite <span style="color: #777; font-weight: normal;">— Discovered Hosts Report</span></h1>
  </div>
  <div class="meta">
    <p><strong>Total Hosts:</strong> ${list.length}</p>
    <p><strong>Export Date:</strong> ${new Date().toLocaleString()}</p>
  </div>
  `;
  list.forEach(h => {
    html += `<h2>Host: ${esc(h.ip)}</h2>`;
    html += `<div class="meta"><p><strong>MAC:</strong> ${esc(h.mac || '—')} &nbsp;|&nbsp; <strong>OS:</strong> ${esc(h.os || '—')} &nbsp;|&nbsp; <strong>Vendor:</strong> ${esc(h.vendor || '—')}</p></div>`;
    if(h.ports && h.ports.length) {
      html += `<h4>Open Ports (${h.ports.length})</h4><table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>`;
      h.ports.forEach(p => { html += `<tr><td>${esc(p.protocol||'tcp')}/${esc(p.port)}</td><td>${esc(p.service || '')}</td><td>${esc(p.product || '')}</td><td>${esc(p.version || '')}</td></tr>`; });
      html += `</table>`;
    } else { html += `<p>No open ports found.</p>`; }
    const vulns = (h.vulns || []);
    if(vulns.length) {
      html += `<h4>Vulnerabilities (${vulns.length})</h4><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>`;
      vulns.forEach(v => { const sev = sevClass(v.severity); html += `<tr><td>${esc(v.cve)}</td><td class="sev-${sev}">${sev.toUpperCase()}</td><td>${cvssText(v.cvss)}</td><td>${esc(v.description)}</td></tr>`; });
      html += `</table>`;
    }
    html += `<hr style="border:0; border-top:2px dashed #eee; margin:30px 0;">`;
  });
  html += `</body></html>`;
  const win = openReportWindow();
  if(!win) return;
  win.document.write(html);
  win.document.close();
  setTimeout(() => { win.print(); }, 500);
}

function downloadHostJson(ip) {
  const h = hosts[ip];
  if(!h) return;
  const portList = (h.ports||[]).map(p => {
    const portVulns = (h.vulns||[]).filter(v => Number(v.port) === Number(p.port) && (v.protocol||'tcp') === (p.protocol||'tcp'));
    return {
      port: p.port,
      protocol: p.protocol||'tcp',
      service: p.service,
      product: p.product,
      version: p.version,
      vulnerabilities: portVulns
    };
  });
  const data = {
    ip: h.ip,
    scan_status: h.scan_status,
    lookup_status: h.lookup_status,
    observed_at: h.observed_at,
    latest_attempt: h.latest_attempt,
    mac: h.mac,
    vendor: h.vendor,
    os: h.os,
    ports: portList
  };
  const mappedVulns = portList.flatMap(p => p.vulnerabilities);
  const unmappedVulns = (h.vulns||[]).filter(v => !mappedVulns.includes(v));
  if (unmappedVulns.length) data.unmapped_vulnerabilities = unmappedVulns;
  
  const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `host_${ip.replace(/\./g, '_')}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
function timeAgo(iso){
  if(!iso) return '';
  const ms = Date.now() - new Date(iso).getTime();
  if(isNaN(ms) || ms < 0) return '';
  const s = Math.floor(ms / 1000);
  if(s<60) return window.i18n.t('time.just_now');
  const m = Math.floor(s/60);
  if(m<60) return window.i18n.t('time.minutes_ago', {m});
  const h = Math.floor(m/60);
  const rm = m % 60;
  if(h<24) return rm ? window.i18n.t('time.hours_minutes_ago', {h, m:rm}) : window.i18n.t('time.hours_ago', {h});
  const d = Math.floor(h/24);
  return window.i18n.t('time.days_ago', {d});
}
function cvssColor(s){ if(!s) return 'var(--text2)'; if(s>=9)return'var(--red)'; if(s>=7)return'var(--orange)'; if(s>=4)return'var(--yellow)'; return'var(--accent)'; }

let _toastTimer = null;
function toast(msg, ok=true){
  // #toast-el is a polite live region (role="status") in index.html; it must already be in the page for
  // assistive technology to announce a change, so it is filled here and never created here.
  const el = document.getElementById('toast-el');
  el.textContent = msg;
  el.className = 'toast ' + (ok?'ok':'err');
  el.style.opacity='1';
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(()=>{ el.style.opacity='0'; }, 3000);
}

// ── Tab switching ──────────────────────────────────────────────────────────────
function switchTab(name, el){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tc').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tc-'+name).classList.add('active');
  document.getElementById('app').classList.toggle('web-focus', name === 'web');
  if(name === 'web') window.webSecurity?.refresh();
}

// ── Advanced toggle ────────────────────────────────────────────────────────────
function toggleAdv(){
  const b=document.getElementById('adv-body'), a=document.getElementById('adv-arr');
  b.classList.toggle('open');
  a.style.transform = b.classList.contains('open') ? 'rotate(90deg)' : '';
}

// ── Profile loader (scan form) ─────────────────────────────────────────────────
// A profile saved by an earlier release can still hold free-text Nmap options. The dashboard no longer
// accepts them, shows no field for them and never applies them.
function hasLegacyOptions(c){ return typeof c.nmap_flags === 'string' && c.nmap_flags.trim() !== ''; }
// The ports field takes what the server accepts: port numbers from 1 to 65535, ranges and comma lists.
function portsError(ports){
  if(!ports) return '';
  const ranges = ports.match(/[0-9]+-[0-9]+/g) || [];
  const valid = ports.length <= 2048
    && /^[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?(,[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?)*$/.test(ports)
    && ports.match(/[0-9]+/g).every(number => Number(number) <= 65535)
    && ranges.every(range => Number(range.split('-')[0]) <= Number(range.split('-')[1]));
  return valid ? '' : window.i18n.t('profile.ports_invalid');
}
function loadProfile(){
  const pid = document.getElementById('f-profile').value;
  if(!pid || !profiles[pid]) return;
  const c = profiles[pid].config || {};
  if(c.mode)       document.getElementById('f-mode').value    = c.mode;
  if(c.speed != null) document.getElementById('f-speed').value = String(c.speed);
  if(c.scan_type !== undefined) document.getElementById('f-scantype').value = c.scan_type || '';
  document.getElementById('f-scantech').value = c.scan_technique || '';
  document.getElementById('f-ports').value = c.ports || '';
  document.getElementById('f-vint').value = c.version_intensity != null ? String(c.version_intensity) : '';
  document.getElementById('f-os').checked = !!c.os_detection;
  if(c.host_timeout) document.getElementById('f-timeout').value = String(c.host_timeout);
  document.getElementById('f-skipd').checked  = !!c.skip_discovery;
  document.getElementById('f-vulns').checked  = c.scan_vulns !== false;
  document.getElementById('f-vuln-source').value = offlineServer ? 'offline' : (c.vulnerability_source || 'auto');
  window.webSecurity?.setControls('f', c);
  updateNmapPreview();
  if(hasLegacyOptions(c)) toast(window.i18n.t('profile.legacy_loaded'), false);
}

function refreshProfileSelects(){
  const opts = `<option value="">${esc(window.i18n.t('settings.no_profile_placeholder'))}</option>` +
    Object.values(profiles).map(p=>`<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  document.getElementById('f-profile').innerHTML = opts;
  document.getElementById('sf-profile').innerHTML = opts;
}

// ── Start scan ────────────────────────────────────────────────────────────────
// The Terminal tab is rarely the one in view, so a failed start or stop is toasted as well as logged.
function reportScanError(message){ addLog(null,message,'error'); toast(message,false); }
function reportUnreachable(e){ reportScanError(window.i18n.t('toast.cannot_reach_server',{detail:e.message})); }

let startingScan = false;
async function startScan(){
  if(startingScan) return;  // the form is only cleared once the server answers, so a second click would start a second scan
  const target = document.getElementById('f-target').value.trim();
  if(!target){ reportScanError(window.i18n.t('toast.please_enter_target')); return; }
  const webError = window.webSecurity?.validateControls('f');
  if(webError){ toast(webError, false); return; }
  const portsProblem = portsError(document.getElementById('f-ports').value.trim());
  if(portsProblem){ toast(portsProblem, false); return; }

  const body = {
    target,
    mode:           document.getElementById('f-mode').value,
    speed:          parseInt(document.getElementById('f-speed').value),
    scan_type:      document.getElementById('f-scantype').value || null,
    scan_technique: document.getElementById('f-scantech').value,
    ports:          document.getElementById('f-ports').value.trim(),
    version_intensity: document.getElementById('f-vint').value ? parseInt(document.getElementById('f-vint').value) : null,
    os_detection:   document.getElementById('f-os').checked,
    host_timeout:   parseInt(document.getElementById('f-timeout').value)||240,
    scan_vulns:     document.getElementById('f-vulns').checked,
    vulnerability_source: document.getElementById('f-vuln-source').value,
    skip_discovery: document.getElementById('f-skipd').checked,
    ...(window.webSecurity?.readControls('f') || {}),
  };
  startingScan = true;
  const startButton = document.getElementById('start-scan');
  const hadFocus = document.activeElement === startButton;  // disabling a focused button drops focus to <body>
  startButton.disabled = true;
  try{
    const r = await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    // A proxy or crash can answer with an HTML page; that is a server answer, not an unreachable server.
    const d = await r.json().catch(()=>null);
    if(!r.ok || !d){ reportScanError(d ? window.i18n.tErrorCode(d.code, d.error||window.i18n.t('toast.failed_to_start_scan')) : `Failed to start scan (HTTP ${r.status}).`); return; }
    document.getElementById('f-target').value='';
    addTermFilterOption(d.scan_id, target);
    if(body.scan_web && body.scan_ports === false) switchTab('web', document.getElementById('web-tab-button'));
    else switchTab('scans', document.querySelector('.tab'));
    poll();
  }catch(e){ reportUnreachable(e); }
  finally{
    startingScan = false;
    startButton.disabled = false;
    // Give focus back only if nothing else took it meanwhile, so a keyboard user stays where they were.
    if(hadFocus && (!document.activeElement || document.activeElement === document.body)) startButton.focus();
  }
}

async function stopScan(scanId){
  try{
    const r = await fetch('/api/scan/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:scanId})});
    if(!r.ok){
      const d = await r.json().catch(()=>({}));
      reportScanError(d.code ? window.i18n.tErrorCode(d.code, d.error||d.message) : (d.error||d.message||window.i18n.t('toast.stop_failed')));
    }
  }catch(e){ reportUnreachable(e); }
}

// ── SSE ────────────────────────────────────────────────────────────────────────
// Log entries carry an increasing id. The stream is opened after the newest one the page has (the history
// from /api/log, then every entry received), so a line logged while the page was loading or reconnecting
// arrives once, from the server's replay, and nothing is shown twice.
let lastLogId = 0;
let sseRetryT = null;
let sseRetryDelay = 1000;
function connectSSE(){
  clearTimeout(sseRetryT);
  if(es){ es.close(); es=null; }
  const source = es = new EventSource('/api/events?after=' + lastLogId);
  source.onopen = ()=>{ sseRetryDelay = 1000; };
  source.onerror = ()=>{
    // The browser reconnects a dropped connection by itself (sending Last-Event-ID) but gives up for good
    // after an HTTP error, for example a 502 from a proxy that is restarting the dashboard. Open it again.
    if(es !== source || source.readyState !== EventSource.CLOSED) return;
    sseRetryT = setTimeout(connectSSE, sseRetryDelay);
    sseRetryDelay = Math.min(sseRetryDelay * 2, 30000);
  };
  source.onmessage = ev => {
    const d = JSON.parse(ev.data);
    if(typeof d.id === 'number') lastLogId = d.id;
    if(d.level==='__scan_progress__'){
      const job = scans[d.scan_id];
      if(job && (d.progress?.revision ?? 0) > (job.progress?.revision ?? -1)){
        job.progress = d.progress;
        job.status = d.status;
        job.finished_at = d.finished_at;
        renderScans();
      }
      return;
    }
    if(d.level==='__scan_done__'){ poll(); window.webSecurity?.refresh(); return; }
    if(d.level==='__web_finding__'){ window.webSecurity?.refresh(); return; }
    addLog(d.scan_id, d.msg, d.level, d.ts);
    if(d.msg && d.msg.includes('Scheduled scan fired')){ loadSchedulesFromServer(); poll(); }
    // The scheduler switches off a schedule that no longer validates: show it as disabled without a reload.
    else if(d.msg && d.msg.includes('Scheduled scan disabled')) loadSchedulesFromServer();
  };
}

// ── Poll ───────────────────────────────────────────────────────────────────────
// Every poll downloads all scans and every host with its CVEs. Progress and completion arrive over the event
// stream, so polling is quick (1.5 s) only while a scan is active, slow (10 s) otherwise, and skipped while
// the tab is hidden. A scan this page starts, or a schedule that fires, is fetched at once (see startScan and
// connectSSE), and a tab that becomes visible polls immediately.
function pollDelay(){
  return Object.values(scans).some(j=>j.status==='running'||j.status==='stopping') ? 1500 : 10000;
}
let pollScheduledDelay = 0;
function schedulePoll(){
  clearTimeout(pollT);
  pollScheduledDelay = pollDelay();
  pollT = setTimeout(async()=>{ if(!document.hidden) await poll(); schedulePoll(); }, pollScheduledDelay);
}
document.addEventListener('visibilitychange', ()=>{ if(!document.hidden) poll(); });
async function poll(){
  if(pollBusy) return;
  pollBusy = true;
  try{
    const [scansR, hostsR] = await Promise.all([
      fetchJson('/api/scans'),
      fetchJson('/api/hosts'),
    ]);
    const scansStr = JSON.stringify(scansR);
    const hostsStr = JSON.stringify(hostsR);
    if(scansStr === lastScansStr && hostsStr === lastHostsStr) return;
    lastScansStr = scansStr; lastHostsStr = hostsStr;
    const previousSelection = selIp && JSON.stringify(hosts[selIp]);
    const previousScans = scans;
    scans={}; scansR.forEach(s=>{
      const previous = previousScans[s.id];
      if((previous?.progress?.revision ?? -1) > (s.progress?.revision ?? -1)){
        s.progress = previous.progress;
        s.status = previous.status;
        s.finished_at = previous.finished_at;
      }
      scans[s.id]=s;
      addTermFilterOption(s.id,s.target);  // also lists scans this page did not start, such as scheduled ones
    });
    hosts = latestHostObservations(hostsR);
    renderScans(); renderHosts(); renderVulnTable(); updateBadges();
    // The pending timer was set before this scan started (or finished): replace it at once instead of
    // letting a 10 s idle wait run out while a scan is active.
    if(pollT !== null && pollDelay() !== pollScheduledDelay) schedulePoll();
    if(selIp && hosts[selIp]) {
      if(previousSelection !== JSON.stringify(hosts[selIp])) renderDetail(hosts[selIp]);
    } else if(selIp){
      selIp = null;
      document.getElementById('no-sel').style.display = '';
      document.getElementById('det-content').style.display = 'none';
    }
  }catch(_){}
  finally{ pollBusy = false; }
}

// ── Render: Active Scans ──────────────────────────────────────────────────────
// The server words its progress details in English; the fixed ones and the keyword ones are shown in the active language.
function progressDetail(detail){
  const fixed = {'Preparing scan':'progress.preparing', 'Discovering hosts':'progress.discovering', 'Port and service scan':'progress.port_scan',
    'Searching service vulnerabilities':'progress.searching', 'No searchable service versions':'progress.nothing_searchable',
    'Resuming unfinished work':'progress.resuming', 'Scan completed':'progress.completed', 'Scan failed':'progress.failed'};
  if(fixed[detail]) return window.i18n.t(fixed[detail]);
  const keyword = {Querying:'progress.querying', Checked:'progress.checked'};
  const match = /^(Querying|Checked) (.+)$/.exec(detail || '');
  if(match) return window.i18n.t(keyword[match[1]], {keyword: match[2]});
  const failed = /^Lookup failed: (.+)$/.exec(detail || '');
  return failed ? window.i18n.t('progress.lookup_failed', {keyword: failed[1]}) : detail;
}
function scanProgressMarkup(job){
  const progress = job.progress || {};
  const active = job.status === 'running' || job.status === 'stopping';
  let percent = typeof progress.percent === 'number' && Number.isFinite(progress.percent)
    ? Math.max(0, Math.min(100, progress.percent)) : null;
  if(job.status === 'completed') percent = 100;
  const labelKeys = {preparing:'status.preparing', discovery:'status.discovery', port_scan:'status.port_scan',
    vulnerabilities:'status.vulnerabilities', web_checks:'status.web_checks', completed:'status.completed', partial:'status.partial',
    stopped:'status.stopped', error:'status.error'};
  const phase = progress.phase || job.status;
  let label = labelKeys[phase] ? window.i18n.t(labelKeys[phase]) : window.i18n.t(active ? 'status.scanning_generic' : 'status.finished_generic');
  if(phase === 'vulnerabilities' && progress.total != null) label += ` ${progress.completed || 0}/${progress.total}`;
  const detail = progressDetail(progress.detail);
  if(detail && detail !== label && active) label += ' · ' + detail;
  if(job.status === 'stopping') label = window.i18n.t('status.stopping_prefix', {label});
  const indeterminate = active && percent === null;
  const percentText = percent === null ? (active ? window.i18n.t('status.working') : '') : `${Math.floor(percent)}%`;
  const targetText = progress.targets_total != null
    ? window.i18n.t('scans.targets_finished', {completed: progress.targets_completed || 0, total: progress.targets_total}) + (progress.host ? ' · ' + progress.host : '')
    : (progress.host || '');
  return `<div class="sc-progress-label"><span>${esc(label)}</span><span>${esc(percentText)}</span></div>
    <div class="sc-bar" role="progressbar" aria-label="${esc(window.i18n.t('scans.current_stage_aria'))}" aria-valuemin="0" aria-valuemax="100"
      ${percent === null ? '' : `aria-valuenow="${percent}"`} aria-valuetext="${esc(label + (percentText ? ' · ' + percentText : ''))}">
      <div class="sc-bar-fill ${indeterminate ? 'indeterminate' : esc(job.status)}" style="width:${indeterminate ? 30 : percent || 0}%"></div>
    </div>${targetText ? `<div class="sc-time">${esc(targetText)}</div>` : ''}`;
}
// A scan keeps one card element for as long as it is listed, and a part of the card is rewritten only when
// its markup changed. The buttons are a part of their own, so a progress update no longer replaces the Stop
// button under the keyboard focus or under a click that is in progress (mouse down on one button, up on its
// replacement, and no click at all). Parts that hold no content of their own use display:contents.
const scanCards = new Map();
function scanCardFor(job){
  let part = scanCards.get(job.id);
  if(!part){
    const make = className=>{ const el = document.createElement('div'); el.className = className; return el; };
    part = {card: make('scan-card'), top: make('sc-slot'), foot: make('sc-foot'), time: make('sc-time'),
      actions: make('sc-actions'), bottom: make('sc-slot'), markup: {}};
    part.foot.appendChild(part.time); part.foot.appendChild(part.actions);
    [part.top, part.foot, part.bottom].forEach(el=>part.card.appendChild(el));
    scanCards.set(job.id, part);
  }
  return part;
}
function setPartHtml(part, name, html){
  if(part.markup[name] === html) return;
  part.markup[name] = html;
  part[name].innerHTML = html;
}
function renderScans(){
  const container = document.getElementById('tc-scans');
  const empty     = document.getElementById('scans-empty');
  const jobs      = Object.values(scans).sort((a,b)=>{
    const o={running:0,stopping:1,partial:2,error:3,stopped:4,completed:5};
    const d=(o[a.status]??9)-(o[b.status]??9);
    return d||new Date(b.started_at)-new Date(a.started_at);
  });
  empty.style.display = jobs.length?'none':'flex';
  const listed = new Set();
  let previous = empty;  // the empty-state element comes first in the container, the cards follow in order
  jobs.forEach(job=>{
    const running = job.status==='running'||job.status==='stopping';
    const c = job.config||{};
    let base = _buildNmapBase(job.target, c.mode||'normal', c.speed??3, c.host_timeout||240, c.scan_technique||'');
    if(c.ports) base += ' -p ' + c.ports;
    if(c.version_intensity != null && c.version_intensity !== '') base += ' --version-intensity ' + c.version_intensity;
    if(c.scan_ports === false && c.scan_web) base = window.i18n.t('scan.website_scan_summary', {count: Object.values(c.web_options?.checks || {}).filter(Boolean).length});
    const part = scanCardFor(job);
    listed.add(job.id);
    part.card.className = `scan-card ${job.status}`;
    setPartHtml(part, 'top', `
      <div class="sc-header">
        <div class="sc-target">${esc(job.target)}</div>
        <div class="sc-id">#${shortId(job.id)}</div>
        <div class="sc-pill ${job.status}">${esc(window.i18n.t('scan_status.'+job.status))}</div>
      </div>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-top:-4px;margin-bottom:2px">${esc(base)}</div>
      <div class="sc-stats">
        <div class="sc-stat"><div class="sv">${job.host_count}</div><div class="sl">${esc(window.i18n.t('scans.hosts'))}</div></div>
        <div class="sc-stat"><div class="sv">${job.port_count}</div><div class="sl">${esc(window.i18n.t('scans.ports'))}</div></div>
        <div class="sc-stat"><div class="sv" style="color:${job.vuln_count?'var(--red)':'var(--accent)'}">${job.vuln_count}</div><div class="sl">${esc(window.i18n.t('scans.cves'))}</div></div>
        ${c.scan_web ? `<div class="sc-stat"><div class="sv">${job.web_finding_count || 0}</div><div class="sl">${esc(window.i18n.t('scans.web_findings'))}</div></div>` : ''}
      </div>
      ${scanProgressMarkup(job)}
    `);
    setPartHtml(part, 'time', esc(job.finished_at?window.i18n.t('scans.finished_ago',{time:timeAgo(job.finished_at)}):window.i18n.t('scans.started_ago',{time:timeAgo(job.started_at)})));
    setPartHtml(part, 'actions', `
          ${running?`<button class="btn btn-danger btn-sm" data-action="stop-scan" data-id="${esc(job.id)}">${esc(window.i18n.t('scans.stop'))}</button>`:''}
          ${job.can_resume?`<button class="btn btn-primary btn-sm" data-action="resume-scan" data-id="${esc(job.id)}">${esc(window.i18n.t('scans.resume'))}</button>`:''}
          ${!running?`<button class="btn btn-ghost btn-sm" data-action="print-scan" data-id="${esc(job.id)}">${esc(window.i18n.t('scans.export_pdf'))}</button>`:''}
          ${!running?`<a class="btn btn-ghost btn-sm" href="/api/scans/${encodeURIComponent(job.id)}/download" download style="text-decoration:none">${esc(window.i18n.t('scans.export_json'))}</a>`:''}
    `);
    setPartHtml(part, 'bottom', `
      ${job.error?`<div style="font-family:var(--mono);font-size:11px;color:var(--red)">${esc(job.error)}</div>`:''}
      <div class="sc-time">${esc(window.i18n.t('scans.vuln_data_line',{source:c.vulnerability_source_used || c.vulnerability_source || 'online'}))}${c.vulnerability_database_updated_at ? esc(window.i18n.t('scans.updated_suffix',{time:c.vulnerability_database_updated_at})) : ''}</div>
    `);
    if(previous.nextSibling !== part.card) container.insertBefore(part.card, previous.nextSibling);
    previous = part.card;
  });
  scanCards.forEach((part,id)=>{ if(!listed.has(id)){ part.card.remove(); scanCards.delete(id); } });
  document.getElementById('active-count').textContent =
    jobs.filter(j=>j.status==='running'||j.status==='stopping').length;
}

// ── Render: Discovered Hosts ──────────────────────────────────────────────────
function renderHosts(){
  const grid  = document.getElementById('hosts-grid');
  const empty = document.getElementById('hosts-empty');
  const action = document.getElementById('hosts-action-bar');
  const list  = Object.values(hosts);
  empty.style.display = list.length?'none':'flex';
  grid.style.display  = list.length?'':'none';
  if(action) action.style.display = list.length?'flex':'none';
  grid.innerHTML='';
  list.forEach(h=>{
    const vc=h.vulns?.length||0, scanning=h.scan_status==='scanning';
    const hasCrit=(h.vulns||[]).some(v=>sevClass(v.severity)==='critical');
    let bc,bt;
    if(scanning){bc='scanning';bt=window.i18n.t('host.scanning_badge');}
    else if(!isHostDone(h)){bc='warn';bt=hostScanLabel(h);}
    else if(vc===0){bc='clean';bt=window.i18n.t('host.clean');}
    else if(hasCrit){bc='vulns';bt=window.i18n.t(vc===1?'host.cve_count_one':'host.cve_count_other',{count:vc});}
    else{bc='warn';bt=window.i18n.t(vc===1?'host.cve_count_one':'host.cve_count_other',{count:vc});}
    const portCount=(h.ports||[]).length;
    const card=document.createElement('div');
    card.className='host-card'+(h.ip===selIp?' selected':'');
    card.dataset.ip=h.ip;
    card.innerHTML=`
      <div class="hc-ip">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/></svg>
        ${esc(h.ip)}<span class="hc-badge ${bc}">${bt}</span>
      </div>
      <div class="hc-meta">${esc(h.os||h.vendor||'—')} &nbsp; ${esc(window.i18n.t(portCount===1?'host.port_count_one':'host.port_count_other',{count:portCount}))}</div>
    `;
    card.onclick=()=>selectHost(h.ip);
    grid.appendChild(card);
  });
}

function selectHost(ip){
  selIp=ip;
  document.querySelectorAll('.host-card').forEach(el=>el.classList.toggle('selected',el.dataset.ip===ip));
  if(!hosts[ip]) return;
  renderDetail(hosts[ip]);
  // On a narrow viewport the detail panel sits below the main area, out of sight of the host list.
  if(window.matchMedia?.('(max-width: 760px)').matches) document.getElementById('right').scrollIntoView({block:'nearest'});
}

function renderDetail(h){
  document.getElementById('no-sel').style.display='none';
  const el=document.getElementById('det-content'); el.style.display='block';
  const ports=h.ports||[], vulns=h.vulns||[];
  const info=[[window.i18n.t('host.ip'),h.ip],[window.i18n.t('host.os'),h.os||window.i18n.t('vuln.unknown')],[window.i18n.t('host.mac'),h.mac||'—'],[window.i18n.t('host.vendor'),h.vendor||'—'],
              [window.i18n.t('host.status'),hostScanLabel(h)],[window.i18n.t('host.observed'),h.observed_at||'—'],[window.i18n.t('host.ports'),ports.length],[window.i18n.t('host.cves'),vulns.length]];
  const kvs=info.map(([k,v])=>`<div class="kv"><span class="kk">${esc(k)}</span><span class="kv2">${esc(String(v))}</span></div>`).join('');
  const prs=ports.length
    ?ports.map(p=>`<div class="pr"><span class="pn">${esc(p.protocol||'tcp')}/${esc(p.port)}</span><span class="ps">${esc(p.service||'')}</span><span style="color:var(--text2);font-size:11px">${esc(p.product||'')} ${esc(p.version||'')}</span></div>`).join('')
    :`<div style="color:var(--text3);font-family:var(--mono);font-size:11px;padding:4px 0">${esc(window.i18n.t('host.no_open_ports'))}</div>`;
  const vrs=vulns.length
    ?vulns.map(v=>{const sev=sevClass(v.severity);return `<div class="vr ${sev}"><div class="vc"><span class="sev ${sev}">${sev.toUpperCase()}</span>${esc(v.cve)}${v.cvss?`<span class="cvb ${sev}">${esc(v.cvss)}</span>`:''}</div><div class="vdesc">${esc(v.description)}</div></div>`;}).join('')
    :h.scan_status==='scanning'
      ?`<div style="color:var(--accent);font-family:var(--mono);font-size:11px;padding:4px 0">${esc(window.i18n.t('host.scan_in_progress'))}</div>`
      :!isHostDone(h)
        ?`<div style="color:var(--orange);font-family:var(--mono);font-size:11px;padding:4px 0">${esc(window.i18n.t('host.vulns_unavailable',{status:hostScanLabel(h)}))}</div>`
      :`<div style="color:var(--green2);font-family:var(--mono);font-size:11px;padding:4px 0">${esc(window.i18n.t('host.no_vulns_found'))}</div>`;
  el.innerHTML=`
    <div><div class="ds">${esc(window.i18n.t('host.detail_title'))}</div>${kvs}</div><div><div class="ds">${esc(window.i18n.t('host.open_ports_title',{count:ports.length}))}</div>${prs}</div><div><div class="ds">${esc(window.i18n.t('host.vulnerabilities_title',{count:vulns.length}))}</div>${vrs}</div>
    ${h.scan_status === 'completed' ? `
    <div style="margin-top:14px; display:flex; gap:8px;">
      <button class="btn btn-ghost btn-sm" style="flex:1" data-action="download-host" data-id="${esc(h.ip)}">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        JSON
      </button>
      <button class="btn btn-ghost btn-sm" style="flex:1" data-action="print-host" data-id="${esc(h.ip)}">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
        PDF
      </button>
    </div>` : ''}
  `;
}

// ── Render: Vuln table ────────────────────────────────────────────────────────
function renderVulnTable(){
  const all=[];
  Object.values(hosts).forEach(h=>(h.vulns||[]).forEach(v=>all.push({...v, hostBase:h.ip, scan_id:h.scan_id, host:h.ip+(v.port?':'+v.port:'')})));

  const hVal = document.getElementById('vuln-host').value;
  const sVal = document.getElementById('vuln-scanid').value;
  const hostSet = new Set(), scanSet = new Set();
  all.forEach(v => { hostSet.add(v.hostBase); if(v.scan_id) scanSet.add(v.scan_id); });

  let hHtml = `<option value="">${esc(window.i18n.t('vuln.all_hosts'))}</option>`;
  Array.from(hostSet).sort().forEach(ip => hHtml += `<option value="${esc(ip)}">${esc(ip)}</option>`);
  if(document.getElementById('vuln-host').innerHTML !== hHtml) {
    document.getElementById('vuln-host').innerHTML = hHtml;
    document.getElementById('vuln-host').value = hostSet.has(hVal) ? hVal : '';
  }

  let sHtml = `<option value="">${esc(window.i18n.t('vuln.all_scans'))}</option>`;
  Array.from(scanSet).forEach(id => sHtml += `<option value="${esc(id)}">#${esc(shortId(id))} ${scans[id]?('— '+esc(scans[id].target)):''}</option>`);
  if(document.getElementById('vuln-scanid').innerHTML !== sHtml) {
    document.getElementById('vuln-scanid').innerHTML = sHtml;
    document.getElementById('vuln-scanid').value = scanSet.has(sVal) ? sVal : '';
  }

  const fSearch = document.getElementById('vuln-search').value.toLowerCase();
  const fHost = document.getElementById('vuln-host').value;
  const fScan = document.getElementById('vuln-scanid').value;
  const fSev = document.getElementById('vuln-sev').value;

  const base = all.filter(v => (!fHost || v.hostBase === fHost) && (!fScan || v.scan_id === fScan) && (!fSev || sevClass(v.severity) === fSev) && (!fSearch || `${v.cve} ${v.keyword} ${v.description} ${v.host}`.toLowerCase().includes(fSearch)));
  renderCategoryBar(base);
  const filtered = vulnCategoryFilter ? base.filter(v => vulnCategories(v).includes(vulnCategoryFilter)) : base;
  vulnTally = {shown: filtered.length, total: base.length};

  filtered.sort((a,b)=>(b.cvss||0)-(a.cvss||0));
  const tb=document.getElementById('vtb');
  if(!filtered.length){tb.innerHTML=`<tr><td colspan="7" style="text-align:center;color:var(--text3);padding:40px;font-family:var(--mono);font-size:12px">${esc(window.i18n.t('vuln.no_matches'))}</td></tr>`;return;}
  tb.innerHTML=filtered.map(v=>{const sev=sevClass(v.severity);return `<tr><td style="font-family:var(--mono)">${esc(v.cve)}</td><td><span class="sev ${sev}">${sev.toUpperCase()}</span></td><td style="font-family:var(--mono);color:${cvssColor(v.cvss)}">${cvssText(v.cvss)}</td><td style="font-family:var(--mono)">${esc(v.host)}</td><td style="font-family:var(--mono);color:var(--text2)">${esc(v.keyword||'')}</td><td>${categoryBadges(v)}</td><td style="color:var(--text2)">${esc(v.description)}</td></tr>`;}).join('');
}

// ── Badges ────────────────────────────────────────────────────────────────────
function updateBadges(){
  const jobs=Object.values(scans), allH=Object.values(hosts), allV=allH.flatMap(h=>h.vulns||[]);
  const set=(id,n)=>{ const b=document.getElementById(id); b.textContent=n; b.classList.toggle('show',n>0); };
  set('badge-scans',jobs.length); set('badge-hosts',allH.length); set('badge-vulns',allV.length);
}

// ── Terminal ──────────────────────────────────────────────────────────────────
const MAX_TERM_LINES = 2000;
function addLog(scanId,msg,level='info',ts=null){
  const f=document.getElementById('term-filter').value;
  const term=document.getElementById('term');
  const atEnd=term.scrollHeight-term.scrollTop-term.clientHeight<40;
  const time=ts||new Date().toTimeString().slice(0,8);
  const sid=scanId?`#${shortId(scanId)}`:window.i18n.t('term.system');
  const line=document.createElement('div');
  line.className='ll '+level; line.dataset.scanId=scanId||'';
  line.style.display=(f&&scanId&&f!==scanId)?'none':'';
  line.innerHTML=`<span class="ll-sid">${esc(sid)}</span><span class="ll-ts">${time}</span><span class="ll-msg">${esc(msg)}</span>`;
  term.appendChild(line);
  if(term.children.length>MAX_TERM_LINES) term.firstElementChild.remove();
  // A reader who scrolled up to read an earlier line keeps their place; only a reader at the end follows.
  if(atEnd) term.scrollTop=term.scrollHeight;
}
const termFilterIds=new Set();
function addTermFilterOption(scanId,target){
  if(termFilterIds.has(scanId)) return;
  termFilterIds.add(scanId);
  const sel=document.getElementById('term-filter');
  const opt=document.createElement('option'); opt.value=scanId; opt.textContent=`#${shortId(scanId)} — ${target}`;
  sel.appendChild(opt);
}
document.getElementById('term-filter').addEventListener('change',function(){
  const f=this.value;
  document.querySelectorAll('#term .ll').forEach(el=>{
    el.style.display=(!f||!el.dataset.scanId||el.dataset.scanId===f)?'':'none';
  });
});

// ── Settings: NIST key ────────────────────────────────────────────────────────
let offlineServer = false;
let savingOfflineMode = false;
let sourceBeforeOffline = 'auto';
let databaseStatusRequest = 0;
async function loadDatabaseStatus(){
  const request = ++databaseStatusRequest;
  const status = await fetchJson('/api/vulnerability-database');
  if(request !== databaseStatusRequest) return;
  const wasOffline = offlineServer;
  offlineServer = !!status.offline_only;
  const source = document.getElementById('f-vuln-source');
  if(offlineServer && !wasOffline) sourceBeforeOffline = source.value || 'auto';
  if(!offlineServer && wasOffline) source.value = sourceBeforeOffline;
  source.disabled = offlineServer;
  const toggle = document.getElementById('s-offline-mode');
  if(!savingOfflineMode) toggle.checked = offlineServer;
  toggle.disabled = savingOfflineMode || !!status.offline_locked;
  toggle.title = status.offline_locked ? window.i18n.t('settings.offline_locked_hint') : '';
  const update = status.update || {};
  let message = status.ready
    ? window.i18n.t('settings.db_status_ready', {count: status.count.toLocaleString(), time: new Date(status.updated_at).toLocaleString(), size: (status.size_bytes / 1048576).toFixed(1)})
    : (status.error || window.i18n.t('settings.db_status_no_local'));
  if(update.running) message += window.i18n.t('settings.db_status_update_progress', {message: update.message, current: update.current, total: update.total || '?'});
  if(update.error) message += ` · ${update.error}`;
  if(offlineServer) message += window.i18n.t('settings.db_status_server_offline');
  document.getElementById('database-status').textContent = message;
  const button = document.getElementById('database-update');
  button.disabled = !!update.running || offlineServer;
  button.textContent = update.running ? window.i18n.t('settings.updating') : status.ready ? window.i18n.t('settings.update_database') : window.i18n.t('settings.download_db');
  document.getElementById('database-export').hidden = !status.ready;
  if(offlineServer){
    document.getElementById('f-vuln-source').value = 'offline';
  }
  window.webSecurity?.setOffline(offlineServer);
}
async function saveOfflineMode(){
  const toggle = document.getElementById('s-offline-mode');
  const enabled = toggle.checked;
  savingOfflineMode = true;
  toggle.disabled = true;
  try{
    const response = await fetch('/api/settings', {method:'PUT', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({offline_mode:enabled})});
    const result = await response.json();
    if(!response.ok) throw new Error(window.i18n.tErrorCode(result.code, result.error || window.i18n.t('toast.could_not_save_offline_mode')));
    toast(enabled ? window.i18n.t('toast.offline_mode_enabled') : window.i18n.t('toast.offline_mode_disabled'));
  }catch(error){
    toggle.checked = offlineServer;
    toast(error.message, false);
  }finally{
    savingOfflineMode = false;
    await loadDatabaseStatus().catch(()=>{ toggle.disabled = false; });
    await loadUpdateStatus().catch(()=>{});
  }
}
async function updateVulnerabilityDatabase(){
  const button = document.getElementById('database-update');
  button.disabled = true;
  try{
    const response = await fetch('/api/vulnerability-database/update', {method:'POST'});
    const result = await response.json();
    if(!response.ok) throw new Error(window.i18n.tErrorCode(result.code, result.error || window.i18n.t('toast.could_not_start_download')));
    toast(window.i18n.t('toast.database_download_started'));
  }catch(error){ toast(error.message, false); }
  await loadDatabaseStatus().catch(()=>{ button.disabled = false; });
}

// ── Settings: updates ─────────────────────────────────────────────────────────
// With automatic checks on, GitHub is asked when the page opens and then every 6 hours, never in offline mode. The
// server decides when a check is due (check_due, by its own clock), so other tabs, reloads and a browser clock that
// is wrong do not make it ask sooner. Applying is always the operator's click.
let updateState = null;
let updateBusy = false;
let savingUpdateAutoCheck = false;
function renderUpdateStatus(state){
  updateState = state;
  const t = window.i18n.t;
  const offline = !!state.offline_only;
  const status = state.status;
  let message;
  if(state.running === 'check') message = t('settings.update_checking');
  else if(state.running === 'apply') message = t('settings.update_applying');
  // Until the restart this process still reports its old version, so a fresh check would offer the same update.
  else if(state.restart_required && state.result && state.result.changed) message = t('settings.update_applied_status', {previous: state.result.previous, new: state.result.new, ref: state.result.ref});
  else if(state.error_code) message = window.i18n.tErrorCode(state.error_code, state.error);
  else if(status) message = t(status.update_available ? 'settings.update_available' : 'settings.update_up_to_date', {current: status.current, latest: status.latest});
  else message = t('settings.update_not_checked');
  if(state.checked_at && !state.running) message += t('settings.update_checked_at', {time: new Date(state.checked_at).toLocaleString()});
  if(offline) message += t('settings.update_server_offline');
  if(!state.checkout) message += t('settings.update_not_checkout');
  document.getElementById('update-status').textContent = message;
  const available = !!(status && status.update_available);
  const channel = document.getElementById('s-update-channel');
  if(!updateBusy) channel.value = state.channel;
  channel.disabled = updateBusy || offline || !!state.running;
  document.getElementById('s-update-channel-commit').disabled = !state.checkout;
  document.getElementById('update-check').disabled = updateBusy || offline || !!state.running;
  document.getElementById('update-apply').disabled = updateBusy || offline || !!state.running || !state.checkout || !!state.restart_required || !available;
  document.getElementById('update-restart').hidden = !state.restart_required;
  document.getElementById('update-dependencies').hidden = !(state.restart_required && state.result && state.result.dependencies_changed);
  const autoCheck = document.getElementById('s-update-auto');
  if(!savingUpdateAutoCheck) autoCheck.checked = state.auto_check !== false;
  autoCheck.disabled = savingUpdateAutoCheck;
  // The URL comes from GitHub's response: only a github.com page becomes a link.
  const link = document.getElementById('update-link');
  const url = available && typeof status.url === 'string' && status.url.startsWith('https://github.com/') ? status.url : '';
  link.hidden = !url;
  if(url) link.href = url;
  document.getElementById('badge-settings').classList.toggle('show', available || !!state.restart_required);
}
async function loadUpdateStatus(){
  const state = await fetchJson('/api/update');
  renderUpdateStatus(state);
  return state;
}
async function checkForUpdates(manual){
  updateBusy = true;
  document.getElementById('update-check').disabled = true;
  document.getElementById('update-apply').disabled = true;
  try{
    // Only the operator's choice is remembered; a periodic check uses the saved channel, and says it is automatic
    // so that the server refuses it when automatic checks are turned off.
    const body = manual ? {channel: document.getElementById('s-update-channel').value} : {automatic: true};
    const response = await fetch('/api/update/check', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
    const result = await response.json();
    if(!response.ok) throw new Error(window.i18n.tErrorCode(result.code, result.error || window.i18n.t('toast.could_not_check_updates')));
    if(manual && result.error_code) toast(window.i18n.tErrorCode(result.error_code, result.error), false);
  }catch(error){
    if(manual) toast(error.message, false);
  }finally{
    updateBusy = false;
    await loadUpdateStatus().catch(()=>{ if(updateState) renderUpdateStatus(updateState); else document.getElementById('update-check').disabled = false; });
  }
}
async function maybeCheckForUpdates(){
  const state = await loadUpdateStatus();
  if(!state.check_due || state.offline_only || state.running || state.restart_required) return;
  await checkForUpdates(false);
}
async function applyUpdate(){
  const status = updateState && updateState.status;
  if(!status || !status.update_available) return;
  if(!confirm(window.i18n.t('settings.update_apply_confirm', {latest: status.latest}))) return;
  updateBusy = true;
  document.getElementById('update-check').disabled = true;
  document.getElementById('update-apply').disabled = true;
  try{
    // Apply the channel whose result the operator saw, not whatever the selector shows now.
    const response = await fetch('/api/update/apply', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({channel: status.mode})});
    const result = await response.json();
    if(!response.ok) throw new Error(window.i18n.tErrorCode(result.code, result.error || window.i18n.t('toast.could_not_apply_update')));
    toast(window.i18n.t(result.result.changed ? 'toast.update_applied' : 'toast.update_already_current'));
  }catch(error){
    toast(error.message, false);
  }finally{
    updateBusy = false;
    await loadUpdateStatus().catch(()=>{ if(updateState) renderUpdateStatus(updateState); else document.getElementById('update-check').disabled = false; });
  }
}
async function saveUpdateAutoCheck(){
  const toggle = document.getElementById('s-update-auto');
  const enabled = toggle.checked;
  savingUpdateAutoCheck = true;
  toggle.disabled = true;
  try{
    const response = await fetch('/api/settings', {method:'PUT', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({update_auto_check:enabled})});
    const result = await response.json();
    if(!response.ok) throw new Error(window.i18n.tErrorCode(result.code, result.error || window.i18n.t('toast.could_not_save_update_auto_check')));
    toast(window.i18n.t(enabled ? 'toast.update_auto_check_on' : 'toast.update_auto_check_off'));
  }catch(error){
    toggle.checked = !enabled;
    toast(error.message, false);
  }finally{
    savingUpdateAutoCheck = false;
    toggle.disabled = false;
    await loadUpdateStatus().catch(()=>{});
  }
}
// Settings forms are only saved after the stored values were read into them: saving a form that is
// blank because loading failed would replace the stored webhook URL, SMTP password and NVD key.
let settingsLoaded=false;
function setSettingsLoaded(loaded){
  settingsLoaded=loaded;
  document.getElementById('s-nist-save').disabled=!loaded;
  document.getElementById('s-email-save').disabled=!loaded;
  toggleWebhookSection();
}
function settingsNotLoaded(){
  if(settingsLoaded) return false;
  toast(window.i18n.t('toast.settings_not_loaded'),false);
  return true;
}
async function saveNistKey(){
  if(settingsNotLoaded()) return;
  const key=document.getElementById('s-nist-key').value.trim();
  const r=await fetch('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({nist_api_key:key})});
  toast(r.ok?window.i18n.t('toast.nist_key_saved'):window.i18n.t('toast.failed_to_save'),r.ok);
}

// ── Settings: Email ───────────────────────────────────────────────────────────
function toggleEmailSection(){
  const on=document.getElementById('s-email-enabled').checked;
  document.getElementById('email-section').style.display=on?'flex':'none';
}
async function saveEmailSettings(){
  if(settingsNotLoaded()) return;
  const body={email:{
    enabled:   document.getElementById('s-email-enabled').checked,
    smtp_host: document.getElementById('s-smtp-host').value,
    smtp_port: parseInt(document.getElementById('s-smtp-port').value)||587,
    username:  document.getElementById('s-smtp-user').value,
    password:  document.getElementById('s-smtp-pass').value,
    from_addr: document.getElementById('s-email-from').value,
    to_addr:   document.getElementById('s-email-to').value,
    on_complete:   document.getElementById('s-email-oncomplete').checked,
    on_error:      document.getElementById('s-email-onerror').checked,
    on_vuln_found: document.getElementById('s-email-onvuln').checked,
  }};
  const r=await fetch('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  toast(r.ok?window.i18n.t('toast.email_settings_saved'):window.i18n.t('toast.failed_to_save'),r.ok);
}
async function testEmail(){
  const r=await fetch('/api/settings/test_email',{method:'POST'});
  const d=await r.json();
  toast(r.ok?window.i18n.t('toast.test_email_sent'):window.i18n.tErrorCode(d.code, d.error||window.i18n.t('toast.failed_generic')),r.ok);
}

// ── Settings: Webhook ─────────────────────────────────────────────────────────
let webhookPersisting=false, persistedWebhookEnabled=false, webhookRevision=0;
function toggleWebhookSection(){
  const on=document.getElementById('s-webhook-enabled').checked;
  document.getElementById('webhook-section').style.display=on?'flex':'none';
  document.getElementById('s-webhook-save').disabled=webhookPersisting||!settingsLoaded;
  document.getElementById('s-webhook-test').disabled=!on||webhookPersisting;
}
async function persistWebhookSettings(update,message){
  if(webhookPersisting) return;
  webhookPersisting=true;
  webhookRevision++;
  const checkbox=document.getElementById('s-webhook-enabled');
  checkbox.disabled=true;
  toggleWebhookSection();
  try{
    const r=await fetch('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({webhook:update})});
    if(!r.ok){
      const data=await r.json().catch(()=>({}));
      throw new Error(window.i18n.tErrorCode(data.code, data.error||window.i18n.t('toast.failed_generic')));
    }
    persistedWebhookEnabled=update.enabled;
    checkbox.checked=update.enabled;
    toast(message);
  }catch(error){
    checkbox.checked=persistedWebhookEnabled;
    toast(window.i18n.t('toast.webhook_not_saved',{detail:error.message}),false);
  }finally{
    webhookPersisting=false;
    checkbox.disabled=false;
    toggleWebhookSection();
  }
}
async function changeWebhookEnabled(){
  const enabled=document.getElementById('s-webhook-enabled').checked;
  await persistWebhookSettings({enabled},enabled?window.i18n.t('toast.webhook_enabled'):window.i18n.t('toast.webhook_disabled'));
}
async function saveWebhookSettings(){
  if(settingsNotLoaded()) return;
  const update={
    enabled:     document.getElementById('s-webhook-enabled').checked,
    url:         document.getElementById('s-webhook-url').value,
    on_complete:   document.getElementById('s-wh-oncomplete').checked,
    on_error:      document.getElementById('s-wh-onerror').checked,
    on_vuln_found: document.getElementById('s-wh-onvuln').checked,
  };
  await persistWebhookSettings(update,window.i18n.t('toast.webhook_settings_saved'));
}
async function testWebhook(){
  const r=await fetch('/api/settings/test_webhook',{method:'POST'});
  const d=await r.json();
  toast(r.ok?window.i18n.t('toast.webhook_ping_sent',{status:d.status_code}):window.i18n.tErrorCode(d.code, d.error||window.i18n.t('toast.failed_generic')),r.ok);
}

// ── Profiles ──────────────────────────────────────────────────────────────────
async function loadProfilesFromServer(){
  const list=await fetchJson('/api/profiles');
  profiles={}; list.forEach(p=>{ profiles[p.id]=p; });
  renderProfiles(); refreshProfileSelects();
}
function renderProfiles(){
  const el=document.getElementById('profiles-list');
  const list=Object.values(profiles);
  if(!list.length){el.innerHTML=`<div class="empty-list">${esc(window.i18n.t('settings.profiles_empty'))}</div>`;return;}
  el.innerHTML=list.map(p=>`
    <div class="item-card">
      <div class="item-card-info">
        <div class="item-card-name">${esc(p.name)}</div>
        <div class="item-card-meta">${esc(window.i18n.t('profile.meta',{mode:window.i18n.t('scan.mode_'+(p.config?.mode||'normal')),speed:p.config?.speed??3,description:p.description||window.i18n.t('profile.no_description')}))}${hasLegacyOptions(p.config||{})?esc(window.i18n.t('profile.legacy_note')):''}</div>
      </div>
      <div class="item-card-actions">
        <button class="btn btn-ghost btn-sm" data-action="edit-profile" data-id="${esc(p.id)}">${esc(window.i18n.t('settings.edit'))}</button>
        <button class="btn btn-danger btn-sm" data-action="delete-profile" data-id="${esc(p.id)}">${esc(window.i18n.t('settings.delete'))}</button>
      </div>
    </div>`).join('');
}
function showProfileForm(){
  document.getElementById('profile-form').style.display='flex';
  document.getElementById('pf-id').value='';
  document.getElementById('profile-form-title').textContent=window.i18n.t('settings.new_profile');
  document.getElementById('pf-name').value='';
  document.getElementById('pf-desc').value='';
  document.getElementById('pf-mode').value='normal';
  document.getElementById('pf-speed').value='3';
  document.getElementById('pf-scantype').value='';
  document.getElementById('pf-timeout').value='240';
  document.getElementById('pf-scantech').value='';
  document.getElementById('pf-ports').value='';
  document.getElementById('pf-vint').value='';
  document.getElementById('pf-os').checked=false;
  document.getElementById('pf-skipd').checked=false;
  document.getElementById('pf-vulns').checked=true;
  document.getElementById('pf-vuln-source').value='auto';
  window.webSecurity?.setControls('pf', {});
  updateProfilePreview();
}
function hideProfileForm(){ document.getElementById('profile-form').style.display='none'; }
function editProfile(pid){
  const p=profiles[pid]; if(!p) return;
  document.getElementById('profile-form').style.display='flex';
  document.getElementById('profile-form-title').textContent=window.i18n.t('settings.edit_profile');
  document.getElementById('pf-id').value=pid;
  document.getElementById('pf-name').value=p.name;
  document.getElementById('pf-desc').value=p.description||'';
  const c=p.config||{};
  document.getElementById('pf-mode').value=c.mode||'normal';
  document.getElementById('pf-speed').value=String(c.speed??3);
  document.getElementById('pf-scantype').value=c.scan_type||'';
  document.getElementById('pf-timeout').value=String(c.host_timeout||240);
  document.getElementById('pf-scantech').value=c.scan_technique||'';
  document.getElementById('pf-ports').value=c.ports||'';
  document.getElementById('pf-vint').value=c.version_intensity!=null?String(c.version_intensity):'';
  document.getElementById('pf-os').checked=!!c.os_detection;
  document.getElementById('pf-skipd').checked=!!c.skip_discovery;
  document.getElementById('pf-vulns').checked=c.scan_vulns!==false;
  document.getElementById('pf-vuln-source').value=c.vulnerability_source||'auto';
  window.webSecurity?.setControls('pf', c);
  updateProfilePreview();
  if(hasLegacyOptions(c)) toast(window.i18n.t('profile.legacy_saving'), false);
}
async function saveProfile(){
  const pid=document.getElementById('pf-id').value;
  const name=document.getElementById('pf-name').value.trim();
  if(!name){ toast(window.i18n.t('toast.profile_name_required'),false); return; }
  const webError = window.webSecurity?.validateControls('pf');
  if(webError){ toast(webError, false); return; }
  const portsProblem = portsError(document.getElementById('pf-ports').value.trim());
  if(portsProblem){ toast(portsProblem, false); return; }
  const body={
    name, description:document.getElementById('pf-desc').value,
    mode:    document.getElementById('pf-mode').value,
    speed:   parseInt(document.getElementById('pf-speed').value),
    scan_type:      document.getElementById('pf-scantype').value||null,
    scan_technique: document.getElementById('pf-scantech').value,
    ports:          document.getElementById('pf-ports').value.trim(),
    version_intensity: document.getElementById('pf-vint').value?parseInt(document.getElementById('pf-vint').value):null,
    os_detection:   document.getElementById('pf-os').checked,
    host_timeout:parseInt(document.getElementById('pf-timeout').value)||240,
    skip_discovery: document.getElementById('pf-skipd').checked,
    scan_vulns:     document.getElementById('pf-vulns').checked,
    vulnerability_source: document.getElementById('pf-vuln-source').value,
    ...(window.webSecurity?.readControls('pf') || {}),
  };
  const url=pid?`/api/profiles/${pid}`:'/api/profiles';
  const method=pid?'PUT':'POST';
  const r=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.ok){ hideProfileForm(); await loadProfilesFromServer(); if(pid) await loadSchedulesFromServer(); toast(window.i18n.t('toast.profile_saved')); }
  else{ const d=await r.json(); toast(window.i18n.tErrorCode(d.code, d.error||window.i18n.t('toast.failed_generic')),false); }
}
async function deleteProfile(pid){
  if(!confirm(window.i18n.t('toast.delete_profile_confirm'))) return;
  const r=await fetch(`/api/profiles/${pid}`,{method:'DELETE'});
  if(r.ok){ await loadProfilesFromServer(); await loadSchedulesFromServer(); toast(window.i18n.t('toast.profile_deleted')); }
}

// ── Schedules ─────────────────────────────────────────────────────────────────
async function loadSchedulesFromServer(){
  const list=await fetchJson('/api/schedules');
  schedules={}; list.forEach(s=>{ schedules[s.id]=s; });
  renderSchedules();
}
function renderSchedules(){
  const el=document.getElementById('schedules-list');
  const list=Object.values(schedules);
  if(!list.length){el.innerHTML=`<div class="empty-list">${esc(window.i18n.t('settings.schedules_empty'))}</div>`;return;}
  const dayKeys=['settings.monday','settings.tuesday','settings.wednesday','settings.thursday','settings.friday','settings.saturday','settings.sunday'];
  el.innerHTML=list.map(s=>{
    let when='';
    if(s.type==='interval') when=window.i18n.t('schedule.every',{value:s.interval_value,unit:window.i18n.t('settings.'+s.interval_unit)});
    else if(s.type==='daily') when=window.i18n.t('schedule.daily_at',{time:s.time_utc});
    else if(s.type==='weekly') when=window.i18n.t('schedule.weekly_at',{day:window.i18n.t(dayKeys[s.weekday||0]),time:s.time_utc});
    return `
    <div class="item-card">
      <div class="schedule-enabled-dot ${s.enabled?'on':'off'}"></div>
      <div class="item-card-info">
        <div class="item-card-name">${esc(s.name)}</div>
        <div class="item-card-meta">${esc(s.target)} · ${esc(when)}${(()=>{const a=timeAgo(s.last_run);return a?esc(window.i18n.t('schedule.last_run',{time:a})):'';})()}</div>
      </div>
      <div class="item-card-actions">
        <button class="btn btn-ghost btn-sm" data-action="edit-schedule" data-id="${esc(s.id)}">${esc(window.i18n.t('settings.edit'))}</button>
        <button class="btn btn-danger btn-sm" data-action="delete-schedule" data-id="${esc(s.id)}">${esc(window.i18n.t('settings.delete'))}</button>
      </div>
    </div>`}).join('');
}
function updateScheduleTypeUI(){
  const t=document.getElementById('sf-type').value;
  document.getElementById('sf-interval-wrap').style.display = t==='interval'?'':'none';
  document.getElementById('sf-time-wrap').style.display     = t!=='interval'?'':'none';
  document.getElementById('sf-weekday-wrap').style.display  = t==='weekly'?'':'none';
}
function showScheduleForm(){ document.getElementById('schedule-form').style.display='flex'; document.getElementById('sf-id').value=''; document.getElementById('schedule-form-title').textContent=window.i18n.t('settings.new_schedule'); updateScheduleTypeUI(); }
function hideScheduleForm(){ document.getElementById('schedule-form').style.display='none'; }
function editSchedule(sid){
  const s=schedules[sid]; if(!s) return;
  document.getElementById('schedule-form').style.display='flex';
  document.getElementById('schedule-form-title').textContent=window.i18n.t('settings.edit_schedule');
  document.getElementById('sf-id').value=sid;
  document.getElementById('sf-name').value=s.name;
  document.getElementById('sf-target').value=s.target;
  document.getElementById('sf-profile').value=s.profile_id||'';
  document.getElementById('sf-enabled').checked=s.enabled!==false;
  document.getElementById('sf-type').value=s.type||'interval';
  document.getElementById('sf-interval-value').value=s.interval_value||24;
  document.getElementById('sf-interval-unit').value=s.interval_unit||'hours';
  document.getElementById('sf-time').value=s.time_utc||'00:00';
  document.getElementById('sf-weekday').value=String(s.weekday||0);
  updateScheduleTypeUI();
}
async function saveSchedule(){
  const sid=document.getElementById('sf-id').value;
  const target=document.getElementById('sf-target').value.trim();
  if(!target){ toast(window.i18n.t('toast.schedule_target_required'),false); return; }
  if(!document.getElementById('sf-profile').value){ toast(window.i18n.t('toast.schedule_profile_required'),false); return; }
  const body={
    name:            document.getElementById('sf-name').value,
    target,
    profile_id:      document.getElementById('sf-profile').value||null,
    enabled:         document.getElementById('sf-enabled').checked,
    type:            document.getElementById('sf-type').value,
    interval_value:  parseInt(document.getElementById('sf-interval-value').value)||24,
    interval_unit:   document.getElementById('sf-interval-unit').value,
    time_utc:        document.getElementById('sf-time').value,
    weekday:         parseInt(document.getElementById('sf-weekday').value)||0,
  };
  const url=sid?`/api/schedules/${sid}`:'/api/schedules';
  const method=sid?'PUT':'POST';
  const r=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.ok){ hideScheduleForm(); await loadSchedulesFromServer(); toast(window.i18n.t('toast.schedule_saved')); }
  else{ const d=await r.json(); toast(window.i18n.tErrorCode(d.code, d.error||window.i18n.t('toast.failed_generic')),false); }
}
async function deleteSchedule(sid){
  if(!confirm(window.i18n.t('toast.delete_schedule_confirm'))) return;
  const r=await fetch(`/api/schedules/${sid}`,{method:'DELETE'});
  if(r.ok){ await loadSchedulesFromServer(); toast(window.i18n.t('toast.schedule_deleted')); }
}

// ── Load settings into form ───────────────────────────────────────────────────
async function loadSettingsIntoForm(){
  const revision=webhookRevision;
  const d=await fetchJson('/api/settings');
  document.getElementById('s-nist-key').value=d.nist_api_key||'';
  const em=d.email||{};
  document.getElementById('s-email-enabled').checked=!!em.enabled;
  document.getElementById('s-smtp-host').value=em.smtp_host||'';
  document.getElementById('s-smtp-port').value=em.smtp_port||587;
  document.getElementById('s-smtp-user').value=em.username||'';
  document.getElementById('s-smtp-pass').value=em.password||'';
  document.getElementById('s-email-from').value=em.from_addr||'';
  document.getElementById('s-email-to').value=em.to_addr||'';
  document.getElementById('s-email-oncomplete').checked=em.on_complete!==false;
  document.getElementById('s-email-onerror').checked=em.on_error!==false;
  document.getElementById('s-email-onvuln').checked=em.on_vuln_found!==false;
  toggleEmailSection();
  const wh=d.webhook||{};
  if(revision===webhookRevision&&!webhookPersisting){
    persistedWebhookEnabled=!!wh.enabled;
    document.getElementById('s-webhook-enabled').checked=persistedWebhookEnabled;
    document.getElementById('s-webhook-url').value=wh.url||'';
    document.getElementById('s-wh-oncomplete').checked=wh.on_complete!==false;
    document.getElementById('s-wh-onerror').checked=wh.on_error!==false;
    document.getElementById('s-wh-onvuln').checked=wh.on_vuln_found!==false;
  }
  document.getElementById('settings-unavailable').hidden=true;
  setSettingsLoaded(true);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('click', (e) => {
  const t = e.target.closest('[data-action]');
  if(!t) return;
  const id = t.dataset.id;
  switch(t.dataset.action){
    case 'stop-scan':       stopScan(id); break;
    case 'resume-scan':     window.webSecurity?.resume(id); break;
    case 'print-scan':      printScan(id); break;
    case 'download-host':   downloadHostJson(id); break;
    case 'print-host':      printHost(id); break;
    case 'edit-profile':    editProfile(id); break;
    case 'delete-profile':  deleteProfile(id); break;
    case 'edit-schedule':   editSchedule(id); break;
    case 'delete-schedule': deleteSchedule(id); break;
  }
});

// Every section loads on its own, so one failed request cannot leave the others empty. A failed settings
// request keeps the settings forms unsaveable (see setSettingsLoaded) instead of blank and saveable.
async function initDashboard(){
  let failed=false;
  const attempt=task=>task.catch(()=>{ failed=true; });
  let scansR=[], hostsR=[], logR=[], verR={version:''};
  setSettingsLoaded(false);
  await Promise.all([
    attempt(fetchJson('/api/scans').then(r=>{ scansR=r; })),
    attempt(fetchJson('/api/hosts').then(r=>{ hostsR=r; })),
    attempt(fetchJson('/api/log').then(r=>{ logR=r; })),
    fetchJson('/api/version').then(r=>{ verR=r; }, ()=>{}),
    attempt(loadSettingsIntoForm().catch(e=>{ document.getElementById('settings-unavailable').hidden=false; throw e; })),
    attempt(loadDatabaseStatus()),
    attempt(loadProfilesFromServer()),
    attempt(loadSchedulesFromServer()),
  ]);
  if(verR.version) document.getElementById('app-version').textContent = 'v' + verR.version;
  scansR.forEach(s=>{ scans[s.id]=s; addTermFilterOption(s.id,s.target); });
  hosts = latestHostObservations(hostsR);
  logR.filter(e=>!e.level?.startsWith('__')).forEach(e=>addLog(e.scan_id,e.msg,e.level,e.ts));
  if(logR.length) lastLogId = logR[logR.length-1].id;
  renderScans(); renderHosts(); renderVulnTable(); updateBadges();
  if(failed) addLog(null,window.i18n.t('log.data_load_failed'),'error');
}

// A render that throws on an unexpected field must not leave the page without its event stream and polling.
async function startDashboard(){
  try{ await initDashboard(); }
  catch(_){ addLog(null,window.i18n.t('log.data_load_failed'),'error'); }
  connectSSE();
  schedulePoll();
  setInterval(()=>loadDatabaseStatus().catch(()=>{}), 5000);
  // Reads the status every minute (offline mode, a restart); GitHub is still asked only every 6 hours.
  maybeCheckForUpdates().catch(()=>{});
  setInterval(()=>maybeCheckForUpdates().catch(()=>{}), 60 * 1000);
}

(async()=>{
  await startDashboard();
})();
