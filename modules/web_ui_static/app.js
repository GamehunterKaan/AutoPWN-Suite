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

  let base = _buildNmapBase(target, mode, speed, to, technique);

  let flags = [];
  const ports = document.getElementById('f-ports');
  if (ports && ports.value.trim()) flags.push('-p ' + ports.value.trim());
  const vint = document.getElementById('f-vint');
  if (vint && vint.value) flags.push('--version-intensity ' + vint.value);
  const os = document.getElementById('f-os');
  if (os && os.checked) flags.push('-O');

  const custom = document.getElementById('f-nmap-custom');
  if (custom && custom.value.trim()) flags.push(custom.value.trim());

  let combinedFlags = flags.join(' ').trim();
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

  // Store technique separately so _build_nmap_flags on the backend also uses it
  const hiddenEl = document.getElementById('f-nmap');
  if (hiddenEl) hiddenEl.value = (technique ? technique + ' ' : '') + flags.join(' ').trim();
}
function updateProfilePreview() {
  const mode = document.getElementById('pf-mode').value;
  const speed = document.getElementById('pf-speed').value;
  const to = document.getElementById('pf-timeout').value || 240;
  const tech = document.getElementById('pf-scantech');
  const technique = (tech && tech.value) ? tech.value : '';

  let base = _buildNmapBase('<target>', mode, speed, to, technique);

  let flags = [];
  const ports = document.getElementById('pf-ports');
  if (ports && ports.value.trim()) flags.push('-p ' + ports.value.trim());
  const vint = document.getElementById('pf-vint');
  if (vint && vint.value) flags.push('--version-intensity ' + vint.value);
  const os = document.getElementById('pf-os');
  if (os && os.checked) flags.push('-O');

  const custom = document.getElementById('pf-nmap');
  if (custom && custom.value.trim()) flags.push(custom.value.trim());

  let combinedFlags = flags.join(' ').trim();
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
function printScan(scanId) {
  const job = scans[scanId];
  if(!job) return;
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
    <p><strong>Started:</strong> ${job.started_at}</p>
    <p><strong>Finished:</strong> ${job.finished_at || 'N/A'}</p>
  </div>
  <h2>Hosts Discovered (${job.host_count})</h2>
  `;
  const scanHosts = Object.values(hosts).filter(h => h.scan_id === scanId);
  if(scanHosts.length) {
    scanHosts.forEach(h => {
      html += `<h3>Host: ${esc(h.ip)}</h3>`;
      html += `<div class="meta"><p><strong>MAC:</strong> ${esc(h.mac || '—')} &nbsp;|&nbsp; <strong>OS:</strong> ${esc(h.os || '—')} &nbsp;|&nbsp; <strong>Vendor:</strong> ${esc(h.vendor || '—')}</p></div>`;
      if(h.ports && h.ports.length) {
        html += `<h4>Open Ports</h4><table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>`;
        h.ports.forEach(p => {
          html += `<tr><td>${p.port}</td><td>${esc(p.service || '')}</td><td>${esc(p.product || '')}</td><td>${esc(p.version || '')}</td></tr>`;
        });
        html += `</table>`;
      } else {
        html += `<p>No open ports found.</p>`;
      }
      const vulns = (h.vulns || []);
      if(vulns.length) {
        html += `<h4>Vulnerabilities</h4><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>`;
        vulns.forEach(v => {
          html += `<tr><td>${esc(v.cve)}</td><td class="sev-${v.severity}">${v.severity.toUpperCase()}</td><td>${v.cvss || '—'}</td><td>${esc(v.description)}</td></tr>`;
        });
        html += `</table>`;
      }
      html += `<hr style="border:0; border-top:2px dashed #eee; margin:30px 0;">`;
    });
  } else {
    html += `<p>No hosts were found during this scan.</p>`;
  }
  html += `</body></html>`;
  const win = window.open('', '_blank');
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
      html += `<tr><td>${p.port}</td><td>${esc(p.service || '')}</td><td>${esc(p.product || '')}</td><td>${esc(p.version || '')}</td></tr>`;
    });
    html += `</table>`;
  } else {
    html += `<p>No open ports found.</p>`;
  }
  const vulns = (h.vulns || []);
  if(vulns.length) {
    html += `<h3>Vulnerabilities (${vulns.length})</h3><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>`;
    vulns.forEach(v => {
      html += `<tr><td>${esc(v.cve)}</td><td class="sev-${v.severity}">${v.severity.toUpperCase()}</td><td>${v.cvss || '—'}</td><td>${esc(v.description)}</td></tr>`;
    });
    html += `</table>`;
  }
  html += `</body></html>`;
  const win = window.open('', '_blank');
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

  const filtered = all.filter(v => (!fHost || v.hostBase === fHost) && (!fScan || v.scan_id === fScan) && (!fSev || v.severity === fSev) && (!fSearch || `${v.cve} ${v.keyword} ${v.description} ${v.host}`.toLowerCase().includes(fSearch)));
  filtered.sort((a,b)=>(b.cvss||0)-(a.cvss||0));

  if(!filtered.length) {
    toast('No vulnerabilities to export.', false);
    return;
  }

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
    <p><strong>Filters Applied:</strong> Host: ${esc(fHost||'All')} &nbsp;|&nbsp; Scan: ${esc(fScan||'All')} &nbsp;|&nbsp; Severity: ${esc(fSev?fSev.toUpperCase():'All')} &nbsp;|&nbsp; Search: ${esc(fSearch||'None')}</p>
  </div>
  <table>
    <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Host</th><th>Keyword</th><th>Description</th></tr>
  `;
  filtered.forEach(v => {
    html += `<tr>
      <td style="white-space:nowrap;">${esc(v.cve)}</td>
      <td class="sev-${v.severity}">${v.severity.toUpperCase()}</td>
      <td>${v.cvss || '—'}</td>
      <td style="white-space:nowrap;">${esc(v.host)}</td>
      <td>${esc(v.keyword || '')}</td>
      <td>${esc(v.description)}</td>
    </tr>`;
  });
  html += `</table></body></html>`;

  const win = window.open('', '_blank');
  win.document.write(html);
  win.document.close();
  setTimeout(() => { win.print(); }, 500);
}

function printAllHosts() {
  const list = Object.values(hosts);
  if(!list.length) {
    toast('No hosts to export.', false);
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
      h.ports.forEach(p => { html += `<tr><td>${p.port}</td><td>${esc(p.service || '')}</td><td>${esc(p.product || '')}</td><td>${esc(p.version || '')}</td></tr>`; });
      html += `</table>`;
    } else { html += `<p>No open ports found.</p>`; }
    const vulns = (h.vulns || []);
    if(vulns.length) {
      html += `<h4>Vulnerabilities (${vulns.length})</h4><table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>`;
      vulns.forEach(v => { html += `<tr><td>${esc(v.cve)}</td><td class="sev-${v.severity}">${v.severity.toUpperCase()}</td><td>${v.cvss || '—'}</td><td>${esc(v.description)}</td></tr>`; });
      html += `</table>`;
    }
    html += `<hr style="border:0; border-top:2px dashed #eee; margin:30px 0;">`;
  });
  html += `</body></html>`;
  const win = window.open('', '_blank');
  win.document.write(html);
  win.document.close();
  setTimeout(() => { win.print(); }, 500);
}

function downloadHostJson(ip) {
  const h = hosts[ip];
  if(!h) return;
  const portList = (h.ports||[]).map(p => {
    const portVulns = (h.vulns||[]).filter(v => v.port == p.port);
    return {
      port: p.port,
      service: p.service,
      product: p.product,
      version: p.version,
      vulnerabilities: portVulns
    };
  });
  const data = {
    ip: h.ip,
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
  if(s<60) return 'just now';
  const m = Math.floor(s/60);
  if(m<60) return `${m}m ago`;
  const h = Math.floor(m/60);
  const rm = m % 60;
  if(h<24) return rm ? `${h}h ${rm}m ago` : `${h}h ago`;
  const d = Math.floor(h/24);
  return `${d}d ago`;
}
function cvssColor(s){ if(!s) return 'var(--text2)'; if(s>=9)return'var(--red)'; if(s>=7)return'var(--orange)'; if(s>=4)return'var(--yellow)'; return'var(--accent)'; }

let _toastTimer = null;
function toast(msg, ok=true){
  let el = document.getElementById('toast-el');
  if(!el){ el=document.createElement('div'); el.id='toast-el'; el.className='toast'; document.body.appendChild(el); }
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
}

// ── Advanced toggle ────────────────────────────────────────────────────────────
function toggleAdv(){
  const b=document.getElementById('adv-body'), a=document.getElementById('adv-arr');
  b.classList.toggle('open');
  a.style.transform = b.classList.contains('open') ? 'rotate(90deg)' : '';
}

// ── Profile loader (scan form) ─────────────────────────────────────────────────
function loadProfile(){
  const pid = document.getElementById('f-profile').value;
  if(!pid || !profiles[pid]) return;
  const c = profiles[pid].config || {};
  if(c.mode)       document.getElementById('f-mode').value    = c.mode;
  if(c.speed)      document.getElementById('f-speed').value   = String(c.speed);
  if(c.scan_type !== undefined) document.getElementById('f-scantype').value = c.scan_type || '';
  document.getElementById('f-nmap-custom').value = c.nmap_flags || '';
  document.getElementById('f-scantech').value = c.scan_technique || '';
  document.getElementById('f-ports').value = c.ports || '';
  document.getElementById('f-vint').value = c.version_intensity ? String(c.version_intensity) : '';
  document.getElementById('f-os').checked = !!c.os_detection;
  if(c.host_timeout) document.getElementById('f-timeout').value = String(c.host_timeout);
  document.getElementById('f-skipd').checked  = !!c.skip_discovery;
  document.getElementById('f-vulns').checked  = c.scan_vulns !== false;
  updateNmapPreview();
}

function refreshProfileSelects(){
  const opts = `<option value="">— No profile —</option>` +
    Object.values(profiles).map(p=>`<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  document.getElementById('f-profile').innerHTML = opts;
  document.getElementById('sf-profile').innerHTML = opts;
}

// ── Start scan ────────────────────────────────────────────────────────────────
async function startScan(){
  const target = document.getElementById('f-target').value.trim();
  if(!target){ addLog(null,'Please enter a target.','error'); return; }

  const body = {
    target,
    mode:           document.getElementById('f-mode').value,
    speed:          parseInt(document.getElementById('f-speed').value),
    scan_type:      document.getElementById('f-scantype').value || null,
    nmap_flags:     document.getElementById('f-nmap').value,
    host_timeout:   parseInt(document.getElementById('f-timeout').value)||240,
    scan_vulns:     document.getElementById('f-vulns').checked,
    skip_discovery: document.getElementById('f-skipd').checked,
  };
  try{
    const r = await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d = await r.json();
    if(!r.ok){ addLog(null,d.error||'Failed to start scan.','error'); return; }
    document.getElementById('f-target').value='';
    addTermFilterOption(d.scan_id, target);
    switchTab('scans', document.querySelector('.tab'));
  }catch(e){ addLog(null,'Cannot reach server: '+e.message,'error'); }
}

async function stopScan(scanId){
  await fetch('/api/scan/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:scanId})});
}

// ── SSE ────────────────────────────────────────────────────────────────────────
function connectSSE(){
  if(es){ es.close(); es=null; }
  es = new EventSource('/api/events');
  es.onmessage = ev => {
    const d = JSON.parse(ev.data);
    if(d.level==='__scan_done__') return;
    addLog(d.scan_id, d.msg, d.level, d.ts);
    if(d.msg && d.msg.includes('Scheduled scan fired')) loadSchedulesFromServer();
  };
  es.onerror = ()=>{};
}

// ── Poll ───────────────────────────────────────────────────────────────────────
async function poll(){
  try{
    const [scansR, hostsR] = await Promise.all([
      fetch('/api/scans').then(r=>r.json()),
      fetch('/api/hosts').then(r=>r.json()),
    ]);
    const scansStr = JSON.stringify(scansR);
    const hostsStr = JSON.stringify(hostsR);
    if(scansStr === lastScansStr && hostsStr === lastHostsStr) return;
    lastScansStr = scansStr; lastHostsStr = hostsStr;
    scans={}; scansR.forEach(s=>{ scans[s.id]=s; });
    hosts={}; hostsR.forEach(h=>{
      if(hosts[h.ip]){
        // Merge: keep longer ports/vulns lists, prefer completed status
        const prev=hosts[h.ip];
        if((h.ports||[]).length>=(prev.ports||[]).length) hosts[h.ip]=h;
        // Merge vulns from both scans (dedupe by cve+port)
        const seen=new Set((hosts[h.ip].vulns||[]).map(v=>v.cve+':'+v.port));
        (h===hosts[h.ip]?prev:h).vulns?.forEach(v=>{
          const key=v.cve+':'+v.port;
          if(!seen.has(key)){ hosts[h.ip].vulns.push(v); seen.add(key); }
        });
      } else { hosts[h.ip]=h; }
    });
    renderScans(); renderHosts(); renderVulnTable(); updateBadges();
    if(selIp && hosts[selIp]) renderDetail(hosts[selIp]);
  }catch(_){}
}

// ── Render: Active Scans ──────────────────────────────────────────────────────
function renderScans(){
  const container = document.getElementById('tc-scans');
  const empty     = document.getElementById('scans-empty');
  const jobs      = Object.values(scans).sort((a,b)=>{
    const o={running:0,stopping:1,completed:2,error:3};
    const d=(o[a.status]||9)-(o[b.status]||9);
    return d||new Date(b.started_at)-new Date(a.started_at);
  });
  empty.style.display = jobs.length?'none':'flex';
  container.querySelectorAll('.scan-card').forEach(e=>e.remove());
  jobs.forEach(job=>{
    const running = job.status==='running'||job.status==='stopping';
    const c = job.config||{};
    const techMatch = (c.nmap_flags||'').match(/-s[STAUWMNFX]/);
    const cardTech = techMatch ? techMatch[0] : '';
    let base = _buildNmapBase(job.target, c.mode||'normal', c.speed||3, c.host_timeout||240, cardTech);
    if(c.nmap_flags){
      let f = c.nmap_flags;
      // Remove the technique flag since it's already in the base
      if(cardTech) f = f.replace(cardTech, '').trim();
      if(base.includes('-O') && f.includes('-O')) f = f.replace(/(^|\s)-O(\s|$)/g, ' ').trim();
      if(f) base += ' ' + f;
    }
    const card = document.createElement('div');
    card.className = `scan-card ${job.status}`;
    card.innerHTML = `
      <div class="sc-header">
        <div class="sc-target">${esc(job.target)}</div>
        <div class="sc-id">#${shortId(job.id)}</div>
        <div class="sc-pill ${job.status}">${job.status}</div>
      </div>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-top:-4px;margin-bottom:2px">${esc(base)}</div>
      <div class="sc-stats">
        <div class="sc-stat"><div class="sv">${job.host_count}</div><div class="sl">Hosts</div></div>
        <div class="sc-stat"><div class="sv">${job.port_count}</div><div class="sl">Ports</div></div>
        <div class="sc-stat"><div class="sv" style="color:${job.vuln_count?'var(--red)':'var(--accent)'}">${job.vuln_count}</div><div class="sl">CVEs</div></div>
      </div>
      <div class="sc-bar"><div class="sc-bar-fill${running?'':' done'}"></div></div>
      <div style="display:flex;align-items:center;justify-content:space-between">
        <div class="sc-time">${esc(job.finished_at?`Finished ${timeAgo(job.finished_at)}`:`Started ${timeAgo(job.started_at)}`)}</div>
        <div style="display:flex;gap:8px">
          ${running?`<button class="btn btn-danger btn-sm" data-action="stop-scan" data-id="${esc(job.id)}">Stop</button>`:''}
          ${!running?`<button class="btn btn-ghost btn-sm" data-action="print-scan" data-id="${esc(job.id)}">Export PDF</button>`:''}
          ${!running?`<a class="btn btn-ghost btn-sm" href="/api/scans/${encodeURIComponent(job.id)}/download" download style="text-decoration:none">Export JSON</a>`:''}
        </div>
      </div>
      ${job.error?`<div style="font-family:var(--mono);font-size:11px;color:var(--red)">${esc(job.error)}</div>`:''}
    `;
    container.appendChild(card);
  });
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
    const hasCrit=(h.vulns||[]).some(v=>v.severity==='critical');
    let bc,bt;
    if(scanning){bc='scanning';bt='scanning…';}
    else if(vc===0){bc='clean';bt='clean';}
    else if(hasCrit){bc='vulns';bt=vc+' CVE'+(vc>1?'s':'');}
    else{bc='warn';bt=vc+' CVE'+(vc>1?'s':'');}
    const card=document.createElement('div');
    card.className='host-card'+(h.ip===selIp?' selected':'');
    card.dataset.ip=h.ip;
    card.innerHTML=`
      <div class="hc-ip">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/></svg>
        ${esc(h.ip)}<span class="hc-badge ${bc}">${bt}</span>
      </div>
      <div class="hc-meta">${esc(h.os||h.vendor||'—')} &nbsp; ${(h.ports||[]).length} port(s)</div>
    `;
    card.onclick=()=>selectHost(h.ip);
    grid.appendChild(card);
  });
}

function selectHost(ip){
  selIp=ip;
  document.querySelectorAll('.host-card').forEach(el=>el.classList.toggle('selected',el.dataset.ip===ip));
  if(hosts[ip]) renderDetail(hosts[ip]);
}

function renderDetail(h){
  document.getElementById('no-sel').style.display='none';
  const el=document.getElementById('det-content'); el.style.display='block';
  const ports=h.ports||[], vulns=h.vulns||[];
  const info=[['IP',h.ip],['OS',h.os||'Unknown'],['MAC',h.mac||'—'],['Vendor',h.vendor||'—'],
              ['Status',h.scan_status==='scanning'?'Scanning…':'Done'],['Ports',ports.length],['CVEs',vulns.length]];
  const kvs=info.map(([k,v])=>`<div class="kv"><span class="kk">${k}</span><span class="kv2">${esc(String(v))}</span></div>`).join('');
  const prs=ports.length
    ?ports.map(p=>`<div class="pr"><span class="pn">${p.port}</span><span class="ps">${esc(p.service||'')}</span><span style="color:var(--text2);font-size:11px">${esc(p.product||'')} ${esc(p.version||'')}</span></div>`).join('')
    :'<div style="color:var(--text3);font-family:var(--mono);font-size:11px;padding:4px 0">No open ports found.</div>';
  const vrs=vulns.length
    ?vulns.map(v=>`<div class="vr ${v.severity}"><div class="vc"><span class="sev ${v.severity}">${v.severity.toUpperCase()}</span>${esc(v.cve)}${v.cvss?`<span class="cvb ${v.severity}">${v.cvss}</span>`:''}</div><div class="vdesc">${esc(v.description)}</div></div>`).join('')
    :h.scan_status==='scanning'
      ?'<div style="color:var(--accent);font-family:var(--mono);font-size:11px;padding:4px 0">Scanning in progress…</div>'
      :'<div style="color:var(--green2);font-family:var(--mono);font-size:11px;padding:4px 0">No vulnerabilities found.</div>';
  el.innerHTML=`
    <div><div class="ds">Host Info</div>${kvs}</div><div><div class="ds">Open Ports (${ports.length})</div>${prs}</div><div><div class="ds">Vulnerabilities (${vulns.length})</div>${vrs}</div>
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

  let hHtml = '<option value="">All Hosts</option>';
  Array.from(hostSet).sort().forEach(ip => hHtml += `<option value="${esc(ip)}">${esc(ip)}</option>`);
  if(document.getElementById('vuln-host').innerHTML !== hHtml) {
    document.getElementById('vuln-host').innerHTML = hHtml;
    document.getElementById('vuln-host').value = hostSet.has(hVal) ? hVal : '';
  }

  let sHtml = '<option value="">All Scans</option>';
  Array.from(scanSet).forEach(id => sHtml += `<option value="${esc(id)}">#${esc(shortId(id))} ${scans[id]?('— '+esc(scans[id].target)):''}</option>`);
  if(document.getElementById('vuln-scanid').innerHTML !== sHtml) {
    document.getElementById('vuln-scanid').innerHTML = sHtml;
    document.getElementById('vuln-scanid').value = scanSet.has(sVal) ? sVal : '';
  }

  const fSearch = document.getElementById('vuln-search').value.toLowerCase();
  const fHost = document.getElementById('vuln-host').value;
  const fScan = document.getElementById('vuln-scanid').value;
  const fSev = document.getElementById('vuln-sev').value;

  const filtered = all.filter(v => (!fHost || v.hostBase === fHost) && (!fScan || v.scan_id === fScan) && (!fSev || v.severity === fSev) && (!fSearch || `${v.cve} ${v.keyword} ${v.description} ${v.host}`.toLowerCase().includes(fSearch)));

  filtered.sort((a,b)=>(b.cvss||0)-(a.cvss||0));
  const tb=document.getElementById('vtb');
  if(!filtered.length){tb.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--text3);padding:40px;font-family:var(--mono);font-size:12px">No vulnerabilities matched.</td></tr>';return;}
  tb.innerHTML=filtered.map(v=>`<tr><td style="font-family:var(--mono)">${esc(v.cve)}</td><td><span class="sev ${v.severity}">${v.severity.toUpperCase()}</span></td><td style="font-family:var(--mono);color:${cvssColor(v.cvss)}">${v.cvss||'—'}</td><td style="font-family:var(--mono)">${esc(v.host)}</td><td style="font-family:var(--mono);color:var(--text2)">${esc(v.keyword||'')}</td><td style="color:var(--text2)">${esc(v.description)}</td></tr>`).join('');
}

// ── Badges ────────────────────────────────────────────────────────────────────
function updateBadges(){
  const jobs=Object.values(scans), allH=Object.values(hosts), allV=allH.flatMap(h=>h.vulns||[]);
  const set=(id,n)=>{ const b=document.getElementById(id); b.textContent=n; b.classList.toggle('show',n>0); };
  set('badge-scans',jobs.length); set('badge-hosts',allH.length); set('badge-vulns',allV.length);
}

// ── Terminal ──────────────────────────────────────────────────────────────────
function addLog(scanId,msg,level='info',ts=null){
  const f=document.getElementById('term-filter').value;
  const term=document.getElementById('term');
  const time=ts||new Date().toTimeString().slice(0,8);
  const sid=scanId?`#${shortId(scanId)}`:'system';
  const line=document.createElement('div');
  line.className='ll '+level; line.dataset.scanId=scanId||'';
  line.style.display=(f&&scanId&&f!==scanId)?'none':'';
  line.innerHTML=`<span class="ll-sid">${esc(sid)}</span><span class="ll-ts">${time}</span><span class="ll-msg">${esc(msg)}</span>`;
  term.appendChild(line); term.scrollTop=term.scrollHeight;
}
function addTermFilterOption(scanId,target){
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
async function saveNistKey(){
  const key=document.getElementById('s-nist-key').value.trim();
  const r=await fetch('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({nist_api_key:key})});
  toast(r.ok?'NIST API key saved.':'Failed to save.',r.ok);
}

// ── Settings: Email ───────────────────────────────────────────────────────────
function toggleEmailSection(){
  const on=document.getElementById('s-email-enabled').checked;
  document.getElementById('email-section').style.display=on?'flex':'none';
}
async function saveEmailSettings(){
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
  toast(r.ok?'Email settings saved.':'Failed to save.',r.ok);
}
async function testEmail(){
  const r=await fetch('/api/settings/test_email',{method:'POST'});
  const d=await r.json();
  toast(r.ok?'Test email sent!':d.error||'Failed.',r.ok);
}

// ── Settings: Webhook ─────────────────────────────────────────────────────────
function toggleWebhookSection(){
  const on=document.getElementById('s-webhook-enabled').checked;
  document.getElementById('webhook-section').style.display=on?'flex':'none';
}
async function saveWebhookSettings(){
  const body={webhook:{
    enabled:     document.getElementById('s-webhook-enabled').checked,
    url:         document.getElementById('s-webhook-url').value,
    on_complete:   document.getElementById('s-wh-oncomplete').checked,
    on_error:      document.getElementById('s-wh-onerror').checked,
    on_vuln_found: document.getElementById('s-wh-onvuln').checked,
  }};
  const r=await fetch('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  toast(r.ok?'Webhook settings saved.':'Failed to save.',r.ok);
}
async function testWebhook(){
  const r=await fetch('/api/settings/test_webhook',{method:'POST'});
  const d=await r.json();
  toast(r.ok?`Webhook ping sent (HTTP ${d.status_code})`:d.error||'Failed.',r.ok);
}

// ── Profiles ──────────────────────────────────────────────────────────────────
async function loadProfilesFromServer(){
  const r=await fetch('/api/profiles'); const list=await r.json();
  profiles={}; list.forEach(p=>{ profiles[p.id]=p; });
  renderProfiles(); refreshProfileSelects();
}
function renderProfiles(){
  const el=document.getElementById('profiles-list');
  const list=Object.values(profiles);
  if(!list.length){el.innerHTML='<div class="empty-list">No profiles yet.</div>';return;}
  el.innerHTML=list.map(p=>`
    <div class="item-card">
      <div class="item-card-info">
        <div class="item-card-name">${esc(p.name)}</div>
        <div class="item-card-meta">Mode: ${p.config?.mode||'normal'} · Speed: ${p.config?.speed||3} · ${p.description||'No description'}</div>
      </div>
      <div class="item-card-actions">
        <button class="btn btn-ghost btn-sm" data-action="edit-profile" data-id="${esc(p.id)}">Edit</button>
        <button class="btn btn-danger btn-sm" data-action="delete-profile" data-id="${esc(p.id)}">Delete</button>
      </div>
    </div>`).join('');
}
function showProfileForm(){ document.getElementById('profile-form').style.display='flex'; document.getElementById('pf-id').value=''; document.getElementById('profile-form-title').textContent='New Profile'; document.getElementById('pf-name').value=''; document.getElementById('pf-desc').value=''; document.getElementById('pf-mode').value='normal'; document.getElementById('pf-speed').value='3'; document.getElementById('pf-scantype').value=''; document.getElementById('pf-timeout').value='240'; document.getElementById('pf-scantech').value=''; document.getElementById('pf-ports').value=''; document.getElementById('pf-vint').value=''; document.getElementById('pf-os').checked=false; document.getElementById('pf-nmap').value=''; document.getElementById('pf-skipd').checked=false; document.getElementById('pf-vulns').checked=true; updateProfilePreview(); }
function hideProfileForm(){ document.getElementById('profile-form').style.display='none'; }
function editProfile(pid){
  const p=profiles[pid]; if(!p) return;
  document.getElementById('profile-form').style.display='flex';
  document.getElementById('profile-form-title').textContent='Edit Profile';
  document.getElementById('pf-id').value=pid;
  document.getElementById('pf-name').value=p.name;
  document.getElementById('pf-desc').value=p.description||'';
  const c=p.config||{};
  document.getElementById('pf-mode').value=c.mode||'normal';
  document.getElementById('pf-speed').value=String(c.speed||3);
  document.getElementById('pf-scantype').value=c.scan_type||'';
  document.getElementById('pf-timeout').value=String(c.host_timeout||240);
  document.getElementById('pf-scantech').value=c.scan_technique||'';
  document.getElementById('pf-ports').value=c.ports||'';
  document.getElementById('pf-vint').value=c.version_intensity?String(c.version_intensity):'';
  document.getElementById('pf-os').checked=!!c.os_detection;
  document.getElementById('pf-nmap').value=c.nmap_flags||'';
  document.getElementById('pf-skipd').checked=!!c.skip_discovery;
  document.getElementById('pf-vulns').checked=c.scan_vulns!==false;
  updateProfilePreview();
}
async function saveProfile(){
  const pid=document.getElementById('pf-id').value;
  const name=document.getElementById('pf-name').value.trim();
  if(!name){ toast('Profile name is required','',false); return; }
  const body={
    name, description:document.getElementById('pf-desc').value,
    mode:    document.getElementById('pf-mode').value,
    speed:   parseInt(document.getElementById('pf-speed').value),
    scan_type:      document.getElementById('pf-scantype').value||null,
    scan_technique: document.getElementById('pf-scantech').value,
    ports:          document.getElementById('pf-ports').value,
    version_intensity: document.getElementById('pf-vint').value?parseInt(document.getElementById('pf-vint').value):null,
    os_detection:   document.getElementById('pf-os').checked,
    host_timeout:parseInt(document.getElementById('pf-timeout').value)||240,
    nmap_flags:  document.getElementById('pf-nmap').value,
    skip_discovery: document.getElementById('pf-skipd').checked,
    scan_vulns:     document.getElementById('pf-vulns').checked,
  };
  const url=pid?`/api/profiles/${pid}`:'/api/profiles';
  const method=pid?'PUT':'POST';
  const r=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r.ok){ hideProfileForm(); await loadProfilesFromServer(); toast('Profile saved.'); }
  else{ const d=await r.json(); toast(d.error||'Failed.',false); }
}
async function deleteProfile(pid){
  if(!confirm('Delete this profile?')) return;
  const r=await fetch(`/api/profiles/${pid}`,{method:'DELETE'});
  if(r.ok){ await loadProfilesFromServer(); toast('Profile deleted.'); }
}

// ── Schedules ─────────────────────────────────────────────────────────────────
async function loadSchedulesFromServer(){
  const r=await fetch('/api/schedules'); const list=await r.json();
  schedules={}; list.forEach(s=>{ schedules[s.id]=s; });
  renderSchedules();
}
function renderSchedules(){
  const el=document.getElementById('schedules-list');
  const list=Object.values(schedules);
  if(!list.length){el.innerHTML='<div class="empty-list">No schedules yet.</div>';return;}
  const typeLabel={interval:'Every',daily:'Daily at',weekly:'Weekly on'};
  const days=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  el.innerHTML=list.map(s=>{
    let when='';
    if(s.type==='interval') when=`Every ${s.interval_value} ${s.interval_unit}`;
    else if(s.type==='daily') when=`Daily at ${s.time_utc} UTC`;
    else if(s.type==='weekly') when=`${days[s.weekday||0]} at ${s.time_utc} UTC`;
    return `
    <div class="item-card">
      <div class="schedule-enabled-dot ${s.enabled?'on':'off'}"></div>
      <div class="item-card-info">
        <div class="item-card-name">${esc(s.name)}</div>
        <div class="item-card-meta">${esc(s.target)} · ${when}${(()=>{const a=timeAgo(s.last_run);return a?` · Last: ${a}`:'';})()}</div>
      </div>
      <div class="item-card-actions">
        <button class="btn btn-ghost btn-sm" data-action="edit-schedule" data-id="${esc(s.id)}">Edit</button>
        <button class="btn btn-danger btn-sm" data-action="delete-schedule" data-id="${esc(s.id)}">Delete</button>
      </div>
    </div>`}).join('');
}
function updateScheduleTypeUI(){
  const t=document.getElementById('sf-type').value;
  document.getElementById('sf-interval-wrap').style.display = t==='interval'?'':'none';
  document.getElementById('sf-time-wrap').style.display     = t!=='interval'?'':'none';
  document.getElementById('sf-weekday-wrap').style.display  = t==='weekly'?'':'none';
}
function showScheduleForm(){ document.getElementById('schedule-form').style.display='flex'; document.getElementById('sf-id').value=''; document.getElementById('schedule-form-title').textContent='New Schedule'; updateScheduleTypeUI(); }
function hideScheduleForm(){ document.getElementById('schedule-form').style.display='none'; }
function editSchedule(sid){
  const s=schedules[sid]; if(!s) return;
  document.getElementById('schedule-form').style.display='flex';
  document.getElementById('schedule-form-title').textContent='Edit Schedule';
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
  if(!target){ toast('Target is required.',false); return; }
  if(!document.getElementById('sf-profile').value){ toast('Please select a profile for scan settings.',false); return; }
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
  if(r.ok){ hideScheduleForm(); await loadSchedulesFromServer(); toast('Schedule saved.'); }
  else{ const d=await r.json(); toast(d.error||'Failed.',false); }
}
async function deleteSchedule(sid){
  if(!confirm('Delete this schedule?')) return;
  const r=await fetch(`/api/schedules/${sid}`,{method:'DELETE'});
  if(r.ok){ await loadSchedulesFromServer(); toast('Schedule deleted.'); }
}

// ── Load settings into form ───────────────────────────────────────────────────
async function loadSettingsIntoForm(){
  const r=await fetch('/api/settings'); const d=await r.json();
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
  document.getElementById('s-webhook-enabled').checked=!!wh.enabled;
  document.getElementById('s-webhook-url').value=wh.url||'';
  document.getElementById('s-wh-oncomplete').checked=wh.on_complete!==false;
  document.getElementById('s-wh-onerror').checked=wh.on_error!==false;
  document.getElementById('s-wh-onvuln').checked=wh.on_vuln_found!==false;
  toggleWebhookSection();
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('click', (e) => {
  const t = e.target.closest('[data-action]');
  if(!t) return;
  const id = t.dataset.id;
  switch(t.dataset.action){
    case 'stop-scan':       stopScan(id); break;
    case 'print-scan':      printScan(id); break;
    case 'download-host':   downloadHostJson(id); break;
    case 'print-host':      printHost(id); break;
    case 'edit-profile':    editProfile(id); break;
    case 'delete-profile':  deleteProfile(id); break;
    case 'edit-schedule':   editSchedule(id); break;
    case 'delete-schedule': deleteSchedule(id); break;
  }
});

(async()=>{
  try{
    const [scansR,hostsR,logR,verR]=await Promise.all([
      fetch('/api/scans').then(r=>r.json()),
      fetch('/api/hosts').then(r=>r.json()),
      fetch('/api/log').then(r=>r.json()),
      fetch('/api/version').then(r=>r.json()).catch(()=>({version:''})),
    ]);
    if(verR.version) document.getElementById('app-version').textContent = 'v' + verR.version;
    scansR.forEach(s=>{ scans[s.id]=s; scansR.length && addTermFilterOption(s.id,s.target); });
    hostsR.forEach(h=>{ hosts[h.ip]=h; });
    logR.forEach(e=>addLog(e.scan_id,e.msg,e.level,e.ts));
    renderScans(); renderHosts(); renderVulnTable(); updateBadges();
    await loadSettingsIntoForm();
    await loadProfilesFromServer();
    await loadSchedulesFromServer();
  }catch(e){ addLog(null,'Cannot connect to server. Refresh to retry.','error'); }
  connectSSE();
  pollT=setInterval(poll,1500);
})();
