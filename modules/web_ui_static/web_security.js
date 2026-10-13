/* Web controls and evidence inspector. Opening a report never replays probes. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const severity = value => ['high','medium','low','info'].includes(value) ? value : 'info';
  const confidence = value => ['candidate','advisory','observation'].includes(value) ? value : 'observation';
  const pending = {};
  const renderedPanels = new WeakMap();
  const limitLabels = {request_budget:'Request budget',timeout:'Timeout (seconds)',max_pages:'Crawl pages',max_urls:'Crawl URLs',max_depth:'Crawl depth',max_endpoints:'Probe endpoints',max_parameters:'Parameters / URL',max_response_kb:'Response cap (KB)'};
  let catalog = null, offline = false, rows = [], jobs = [], busy = false;
  let selected = null, detailRevision = 0, pocRevision = 0, detailBusy = false, displayedPoc = '';

  async function request(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Request failed (${response.status}).`);
    }
    return response;
  }
  const json = async (url, options) => (await request(url, options)).json();
  function notify(message, ok = true) { if (typeof toast === 'function') toast(message, ok); }
  const endpoint = row => `/api/web/findings/${encodeURIComponent(row.scan_id)}/${encodeURIComponent(row.id)}`;
  const pill = (text, style = '') => `<span class="web-pill ${escape(style)}">${escape(text)}</span>`;
  const pretty = value => JSON.stringify(value, null, 2);
  function safeReference(ref) {
    try {
      const url = new URL(ref.url);
      if (!['https:','http:'].includes(url.protocol)) return '';
      return `<a href="${escape(url.href)}" target="_blank" rel="noopener noreferrer">${escape(ref.title)}</a>`;
    } catch (_) { return ''; }
  }

  function renderDisclosurePanel(node, markup, scope, rememberMissingChoices = false) {
    const previous = renderedPanels.get(node);
    const sameScope = previous?.scope === scope;
    // Polls must not replace unchanged DOM, including a user's selection and focus.
    if (sameScope && previous.markup === markup) return;
    // A new verification briefly omits its exchanges while the replay is running.
    const choices = sameScope && rememberMissingChoices ? new Map(previous.choices) : new Map();
    if (sameScope) node.querySelectorAll('details[data-web-disclosure]').forEach(detail => {
      choices.set(detail.dataset.webDisclosure, detail.open);
    });
    node.innerHTML = markup;
    if (sameScope) node.querySelectorAll('details[data-web-disclosure]').forEach(detail => {
      if (choices.has(detail.dataset.webDisclosure)) detail.open = choices.get(detail.dataset.webDisclosure);
    });
    renderedPanels.set(node, {scope, markup, choices});
  }
  const findingScope = row => `${detailRevision}:${endpoint(row)}`;

  function mount(prefix) {
    const root = $(`${prefix}-web-controls`);
    if (!root || !catalog) return;
    root.innerHTML = `<div class="web-control-card">
      <div class="web-control-head"><div><div class="web-control-title">Web checks</div><div class="web-control-subtitle" id="${prefix}-web-count"></div></div>
        <label><span class="sr-only">Enable web checks</span><input type="checkbox" id="${prefix}-web-enabled"></label></div>
      <div class="web-control-options">
        <label><span class="sr-only">Scan scope</span><select id="${prefix}-web-scope"><option value="network">Network + selected web checks</option><option value="web">Website only · no port scan</option></select></label>
        <div class="web-control-warning" id="${prefix}-web-warning" hidden></div>
        <details><summary>Select checks</summary><div class="web-preset-actions"><button data-web-action="preset" data-prefix="${prefix}" data-preset="all">All</button><button data-web-action="preset" data-prefix="${prefix}" data-preset="light">Light</button><button data-web-action="preset" data-prefix="${prefix}" data-preset="none">None</button></div>
          <div class="web-check-grid">${Object.entries(catalog.checks).map(([key,label]) => `<label><input type="checkbox" id="${prefix}-web-check-${escape(key)}">${escape(label)}</label>`).join('')}</div></details>
        <details><summary>Limits &amp; crawl</summary><div class="web-limit-grid">${Object.entries(catalog.limits).map(([key,bounds]) => `<label>${escape(limitLabels[key] || key)}<input id="${prefix}-web-limit-${escape(key)}" type="number" step="1" min="${bounds[1]}" max="${bounds[2]}"></label>`).join('')}</div></details>
      </div></div>`;
    setControls(prefix, pending[prefix] || {});
  }
  function setControls(prefix, config = {}) {
    pending[prefix] = config;
    if (!catalog || !$(`${prefix}-web-enabled`)) return;
    const controls = config.web_options || {};
    $(`${prefix}-web-enabled`).checked = config.scan_web === true;
    $(`${prefix}-web-scope`).value = config.scan_ports === false ? 'web' : 'network';
    Object.keys(catalog.checks).forEach(key => { $(`${prefix}-web-check-${key}`).checked = controls.checks?.[key] ?? catalog.defaults.checks[key]; });
    Object.keys(catalog.limits).forEach(key => { $(`${prefix}-web-limit-${key}`).value = controls[key] ?? catalog.defaults[key]; });
    syncControls(prefix);
  }
  function sourceOffline(prefix) { return offline || $(`${prefix}-vuln-source`)?.value === 'offline'; }
  function syncControls(prefix) {
    const enabled = $(`${prefix}-web-enabled`);
    if (!enabled || !catalog) return;
    const blocked = sourceOffline(prefix);
    const webOnly = $(`${prefix}-web-scope`).value === 'web';
    if ($(`${prefix}-network-controls`)) $(`${prefix}-network-controls`).hidden = webOnly;
    enabled.disabled = blocked;
    const count = Object.keys(catalog.checks).filter(key => $(`${prefix}-web-check-${key}`).checked).length;
    $(`${prefix}-web-count`).textContent = `${count} of ${Object.keys(catalog.checks).length} checks selected`;
    const warning = $(`${prefix}-web-warning`);
    warning.hidden = !blocked;
    warning.textContent = 'Offline source disables web requests. Choose an online source to scan a website.';
    $(`${prefix}-web-controls`).querySelectorAll('details input, details button').forEach(node => { node.disabled = blocked || !enabled.checked; });
    if (prefix === 'f') $('f-target').placeholder = webOnly ? 'https://app.example.com/path' : '192.168.1.0/24 or hostname';
  }
  function readControls(prefix) {
    if (!catalog || !$(`${prefix}-web-enabled`)) return {};
    const webOnly = $(`${prefix}-web-scope`).value === 'web';
    const options = {checks:{}};
    Object.keys(catalog.checks).forEach(key => { options.checks[key] = $(`${prefix}-web-check-${key}`).checked; });
    Object.keys(catalog.limits).forEach(key => { options[key] = $(`${prefix}-web-limit-${key}`).value; });
    return {scan_web: $(`${prefix}-web-enabled`).checked && (prefix === 'pf' || !sourceOffline(prefix)),
      scan_ports: !webOnly, web_options:options, ...(webOnly ? {scan_vulns:false,skip_discovery:true} : {})};
  }
  function validateControls(prefix) {
    if (!catalog) return pending[prefix]?.scan_web ? 'Web controls have not loaded. Refresh the dashboard to retry.' : '';
    const controls = readControls(prefix);
    if (prefix === 'f' && controls.scan_ports === false && sourceOffline(prefix)) return 'Web-only scans require an online source.';
    if (!controls.scan_ports && !controls.scan_web) return 'Enable web checks for a website-only scan.';
    if (!controls.scan_web) return '';
    if (!Object.values(controls.web_options.checks).some(Boolean)) return 'Select at least one web check.';
    for (const [key, bounds] of Object.entries(catalog.limits)) {
      const raw = controls.web_options[key];
      if (!/^\d+$/.test(raw) || Number(raw) < bounds[1] || Number(raw) > bounds[2]) return `${limitLabels[key]} must be ${bounds[1]}–${bounds[2]}.`;
    }
    return '';
  }
  function setOffline(value) {
    offline = !!value;
    if ($('web-offline-note')) $('web-offline-note').hidden = !offline;
    ['f','pf'].forEach(syncControls);
    if (selected) renderVerification(selected);
  }

  function filteredRows() {
    const search = $('web-search').value.trim().toLowerCase();
    return rows.filter(row => (!$('web-confidence').value || confidence(row.confidence) === $('web-confidence').value)
      && (!$('web-severity').value || severity(row.severity) === $('web-severity').value)
      && (!$('web-scan-filter').value || row.scan_id === $('web-scan-filter').value)
      && (!search || [row.title,row.type,row.url,row.host,row.parameter,row.evidence].join(' ').toLowerCase().includes(search)))
      .sort((a,b) => ({high:0,medium:1,low:2,info:3}[severity(a.severity)] - {high:0,medium:1,low:2,info:3}[severity(b.severity)])
        || ({candidate:0,advisory:1,observation:2}[confidence(a.confidence)] - {candidate:0,advisory:1,observation:2}[confidence(b.confidence)])
        || (Date.parse(b.observed_at) || 0) - (Date.parse(a.observed_at) || 0));
  }
  function render() {
    const visible = filteredRows(), scanFilter = $('web-scan-filter').value;
    const scoped = scanFilter ? rows.filter(row => row.scan_id === scanFilter) : rows;
    const scopedJobs = jobs.filter(job => job.config?.scan_web && (!scanFilter || job.id === scanFilter));
    $('badge-web').textContent = rows.length;
    $('badge-web').classList.toggle('show', rows.length > 0);
    const stats = [[scoped.length,'Total findings',''],[scoped.filter(row => severity(row.severity) === 'high').length,'High severity','priority'],
      [scoped.filter(row => row.verification?.status === 'reproduced').length,'Evidence reproduced','verified'],[scopedJobs.filter(job => ['running','stopping'].includes(job.status)).length,'Active web scans','']];
    $('web-summary').innerHTML = stats.map(([value,label,style]) => `<div class="web-stat ${style}"><strong>${value}</strong><span>${label}</span></div>`).join('');
    $('web-result-count').textContent = `${visible.length} of ${rows.length} findings`;
    $('web-empty').hidden = !!visible.length;
    $('web-empty').querySelector('h2').textContent = rows.length ? 'No matching findings.' : scopedJobs.length ? 'No findings reported yet.' : 'Start with a website.';
    $('web-empty').querySelector('p').textContent = rows.length ? 'Adjust the filters to see more results.' : scopedJobs.length ? 'Review scan coverage below; incomplete checks cannot rule out vulnerabilities.' : 'Enable web checks and scan an application to see its findings here.';
    $('web-findings-list').innerHTML = visible.map(row => `<button class="web-finding-row ${severity(row.severity)}" data-web-action="open" data-scan="${escape(row.scan_id)}" data-id="${escape(row.id)}">
      <span class="web-severity-bar"></span><span><span class="web-finding-title">${escape(row.title || row.type)}${row.verification?.status === 'reproduced' ? pill('Evidence reproduced','reproduced') : ''}</span><span class="web-finding-url">${escape(row.url)}${row.parameter ? ` · ${escape(row.parameter)}` : ''}</span></span>
      <span class="web-finding-side">${pill(confidence(row.confidence),confidence(row.confidence))}${pill(severity(row.severity),severity(row.severity))}<span aria-hidden="true">↗</span></span></button>`).join('');
    renderDisclosurePanel($('web-coverage'), scopedJobs.map(job => {
      const coverage = job.web_coverage || [];
      if (!coverage.length) return `<div class="web-coverage-item">${escape(job.target)} · ${escape(job.status)}${job.status === 'completed' ? ' · web coverage not recorded' : ''}</div>`;
      return coverage.map(item => {
        const incomplete = item.status !== 'completed';
        const checks = Object.entries(item.controls?.checks || {}).filter(([,enabled]) => enabled).map(([key]) => catalog?.checks[key] || key);
        const issues = item.issues || [];
        return `<div class="web-coverage-item ${incomplete ? 'partial' : ''}"><details data-web-disclosure="${escape(JSON.stringify([job.id,item.host,item.endpoint || item.target]))}"><summary>${escape(item.endpoint || item.target)} · ${incomplete ? escape(item.status) : 'Checked'} · ${item.requests || 0} requests</summary><ul>${checks.length ? `<li>Enabled checks: ${escape(checks.join(', '))}</li>` : ''}${issues.map(issue => `<li>${escape(issue)}</li>`).join('')}${!issues.length ? '<li>Selected checks completed within the configured limits. Unreported vulnerabilities may still exist.</li>' : ''}</ul></details></div>`;
      }).join('');
    }).join(''), 'coverage');
  }
  async function refresh() {
    if (busy) return;
    busy = true;
    try {
      [rows,jobs] = await Promise.all([json('/api/web/findings'),json('/api/scans')]);
      const filter = $('web-scan-filter'), previous = filter.value;
      filter.innerHTML = '<option value="">All scans</option>' + jobs.filter(job => job.config?.scan_web || job.web_finding_count).map(job => `<option value="${escape(job.id)}">${escape(job.target)} · ${escape(job.id.slice(0,8))}</option>`).join('');
      filter.value = jobs.some(job => job.id === previous) ? previous : '';
      render();
      const updated = selected && rows.find(row => row.id === selected.id && row.scan_id === selected.scan_id);
      if (selected && $('web-finding-dialog').open && !detailBusy
          && (selected.verification?.status === 'running' || pretty(updated?.verification) !== pretty(selected.verification))) await refreshDetail();
    } catch (error) {
      $('web-result-count').textContent = `Could not refresh findings: ${error.message}`;
    } finally { busy = false; }
  }
  function card(title, value) { return `<div class="web-detail-card"><h3>${escape(title)}</h3><p>${escape(value || 'Not recorded.')}</p></div>`; }
  function renderDetail(row) {
    const info = row.details || {};
    $('web-detail-title').textContent = info.title || row.type;
    $('web-detail-kind').textContent = `${row.type}${info.cwe ? ' · ' + info.cwe : ''}`;
    $('web-detail-url').textContent = `${row.url}${row.parameter ? ' · parameter: ' + row.parameter : ''}`;
    $('web-detail-badges').innerHTML = pill(severity(row.severity),severity(row.severity)) + pill(confidence(row.confidence),confidence(row.confidence)) + pill(`Scan ${row.scan_id.slice(0,8)}`) + (row.verification?.status === 'reproduced' ? pill('Evidence reproduced','reproduced') : '');
    $('web-panel-overview').innerHTML = card('Observed evidence',row.evidence) + `<div class="web-detail-grid"><div>${card('How this was detected',info.detection)}${card('Potential impact',info.impact)}</div><div>${card('Remediation',info.remediation)}${card('What still needs verification',info.limitations)}</div></div><div class="web-detail-card"><h3>Verification steps</h3><ol>${(info.verification_steps || []).map(step => `<li>${escape(step)}</li>`).join('')}</ol></div><div class="web-detail-card"><h3>References</h3>${(info.references || []).map(safeReference).join('')}<p class="web-small-note">Observed ${escape(row.observed_at || 'time not recorded')} · Host ${escape(row.host)}</p></div>`;
    const observations = row.observations || [];
    renderDisclosurePanel($('web-panel-evidence'), `<p class="web-small-note">Recorded HTTP exchanges, including baseline comparisons. Sensitive query values are redacted. Response bodies and cookie values are omitted.</p>`
      + observations.map((record,index) => {
        const req = record.request || {}, res = record.response || {};
        return `<details class="web-request" data-web-disclosure="observation-${index}"${index === 0 ? ' open' : ''}><summary>${escape(req.role || 'probe')} · ${escape(req.method)} <span class="web-request-uri">${escape(req.url)}</span>${pill(`HTTP ${res.status}`)}</summary><pre>${escape(pretty({request:req,response:res,phase:record.phase}))}</pre></details>`;
      }).join('') + (!observations.length ? '<p class="web-small-note">No HTTP exchanges were attached to this finding. Review the recorded plan and available certificate metadata.</p>' : '')
      + (row.reproduction?.certificate ? `<details class="web-request" data-web-disclosure="certificate" open><summary>Certificate metadata</summary><pre>${escape(pretty(row.reproduction.certificate))}</pre></details>` : '')
      + `<details class="web-request" data-web-disclosure="complete-finding"><summary>Complete finding · plan and verification history</summary><pre>${escape(pretty(row))}</pre></details>`, findingScope(row));
    renderVerification(row);
  }
  function replayBlocked(row) {
    if (offline) return 'Verification is disabled in server offline mode.';
    const job = jobs.find(item => item.id === row.scan_id);
    if (job?.config?.vulnerability_source === 'offline') return 'This scan uses an offline source. Download the PoC to review it locally.';
    if (!row.type.startsWith('TLS_') && pretty(row.reproduction || {}).includes('REDACTED')) return 'A query value was redacted. Restore it locally in the downloaded Python PoC to verify.';
    return '';
  }
  function renderVerification(row) {
    const result = row.verification || {}, blocked = replayBlocked(row);
    const button = $('web-verify-button');
    button.disabled = !!blocked || result.status === 'running';
    button.textContent = result.status === 'running' ? 'Verifying…' : 'Verify evidence';
    button.title = blocked || 'Send the recorded requests to the scanned endpoint';
    const labels = {running:'Verification running',reproduced:'Evidence reproduced',not_reproduced:'Evidence not reproduced',inconclusive:'Inconclusive',needs_input:'Local input required'};
    const node = $('web-verification-result');
    node.className = `web-verification-result ${result.status === 'reproduced' ? 'reproduced' : ''}`;
    renderDisclosurePanel(node, `${blocked ? `<p>${escape(blocked)}</p>` : ''}${result.status ? `<strong>${escape(labels[result.status] || result.status)}</strong> · ${escape(result.summary)}${result.checked_at ? `<p class="web-small-note">${escape(result.checked_at)}</p>` : ''}` : '<p>No verification run yet.</p>'}<p class="web-small-note">Reproducing evidence does not establish full exploit impact. Review application context and the limitations above.</p>${result.observations?.length ? `<details class="web-request" data-web-disclosure="verification-exchanges"><summary>Verification exchanges · ${result.observations.length} requests</summary><pre>${escape(pretty(result.observations))}</pre></details>` : ''}`, findingScope(row), true);
  }
  async function refreshDetail() {
    if (!selected) return;
    const row = selected, revision = detailRevision;
    detailBusy = true;
    try {
      const fresh = await json(endpoint(row));
      if (revision !== detailRevision) return;
      selected = fresh;
      renderDetail(fresh);
    } finally { detailBusy = false; }
  }
  async function openFinding(scanId, findingId) {
    const revision = ++detailRevision;
    ++pocRevision;
    selected = null;
    displayedPoc = '';
    $('web-detail-title').textContent = 'Loading finding…';
    $('web-detail-kind').textContent = 'Finding';
    $('web-detail-url').textContent = '';
    $('web-detail-badges').innerHTML = '';
    $('web-panel-overview').innerHTML = '<p class="web-small-note">Loading recorded evidence…</p>';
    $('web-panel-evidence').innerHTML = '';
    $('web-poc-code').textContent = '';
    $('web-verification-result').textContent = '';
    $('web-poc-help').textContent = '';
    $('web-poc-download').removeAttribute('href');
    $('web-verify-button').disabled = true;
    panel('overview');
    if (!$('web-finding-dialog').open) $('web-finding-dialog').showModal();
    try {
      const row = await json(endpoint({scan_id:scanId,id:findingId}));
      if (revision !== detailRevision) return;
      selected = row;
      renderDetail(row);
      const html = $('web-poc-format').querySelector('option[value="html"]');
      html.disabled = !['CORS','XSS'].includes(row.type);
      $('web-poc-format').value = 'python';
    } catch (error) { if (revision === detailRevision) $('web-panel-overview').textContent = error.message; }
  }
  function closeFinding() {
    ++detailRevision; ++pocRevision; selected = null; displayedPoc = '';
    $('web-finding-dialog').close();
  }
  function panel(name) {
    if (!['overview','evidence','poc'].includes(name)) return;
    document.querySelectorAll('.web-detail-panel').forEach(node => { node.hidden = node.id !== `web-panel-${name}`; });
    document.querySelectorAll('[data-web-action="detail-tab"]').forEach(node => { node.classList.toggle('active',node.dataset.panel === name); });
    if (name === 'poc' && selected) loadPoc();
  }
  async function loadPoc() {
    if (!selected) return;
    const revision = ++pocRevision, row = selected, format = $('web-poc-format').value;
    displayedPoc = '';
    $('web-poc-code').textContent = 'Loading PoC…';
    $('web-poc-download').removeAttribute('href');
    try {
      const url = endpoint(row) + '/poc?format=' + encodeURIComponent(format);
      const code = await (await request(url)).text();
      if (revision !== pocRevision) return;
      displayedPoc = code;
      $('web-poc-code').textContent = code;
      $('web-poc-download').href = url;
      const notes = {python:'Install requests and cryptography, then run the downloaded file with Python. The result compares baseline and probe evidence; response bodies are not printed.',curl:'Commands use POSIX shell quoting. curl shows response headers and discards bodies; use the Python PoC for automatic comparisons and TLS checks.',html:'Download and review the browser PoC. Run its explicit test button from a controlled origin; use an authenticated browser session when assessing CORS. JavaScript execution and browser cookie rules still need manual review.',json:'Recorded reproduction plan. Baselines, probes and expected conditions are included in the Python PoC.'};
      $('web-poc-help').textContent = notes[format];
    } catch (error) { if (revision === pocRevision) $('web-poc-code').textContent = error.message; }
  }
  async function verify() {
    if (!selected || replayBlocked(selected) || selected.verification?.status === 'running') return;
    const row = selected, revision = detailRevision;
    $('web-verify-button').disabled = true;
    try {
      await json(endpoint(row) + '/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
      if (revision === detailRevision) { selected.verification = {status:'running',summary:'Replaying recorded requests.'}; renderVerification(selected); }
      refresh();
    } catch (error) { notify(error.message,false); if (revision === detailRevision) renderVerification(selected); }
  }
  async function exportReport() {
    const visible = filteredRows();
    if (!visible.length) { notify('There are no matching findings to export.',false); return; }
    try {
      const full = [];
      // Keep the inspector responsive and avoid flooding the dashboard server.
      for (let index = 0; index < visible.length; index += 4) full.push(...await Promise.all(visible.slice(index,index+4).map(row => json(endpoint(row)))));
      const scanIds = new Set(visible.map(row => row.scan_id));
      const report = {exported_at:new Date().toISOString(),scans:jobs.filter(job => scanIds.has(job.id)),web_findings:full};
      const url = URL.createObjectURL(new Blob([pretty(report)],{type:'application/json'}));
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = `autopwn-web-report-${new Date().toISOString().slice(0,10)}.json`;
      document.body.appendChild(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url),1000);
      notify(`Exported ${full.length} findings with evidence.`);
    } catch (error) { notify(`Could not export report: ${error.message}`,false); }
  }

  document.addEventListener('click', async event => {
    const node = event.target.closest('[data-web-action]');
    if (!node) return;
    const action = node.dataset.webAction;
    if (action === 'open') openFinding(node.dataset.scan,node.dataset.id);
    else if (action === 'close') closeFinding();
    else if (action === 'detail-tab') panel(node.dataset.panel);
    else if (action === 'verify') verify();
    else if (action === 'export') exportReport();
    else if (action === 'copy-poc' && displayedPoc) {
      try { await navigator.clipboard.writeText(displayedPoc); notify('PoC copied.'); }
      catch (_) { notify('Clipboard unavailable. Download the PoC or select its code.',false); }
    } else if (action === 'preset' && catalog) {
      Object.keys(catalog.checks).forEach(key => { $(`${node.dataset.prefix}-web-check-${key}`).checked = node.dataset.preset === 'all' || (node.dataset.preset === 'light' && ['headers','tls'].includes(key)); });
      syncControls(node.dataset.prefix);
    } else if (action === 'configure') {
      if (!catalog) return;
      $('f-web-scope').value = 'web'; $('f-web-enabled').checked = true; syncControls('f');
      $('f-target').focus(); $('f-web-controls').scrollIntoView({behavior:'smooth',block:'nearest'});
    }
  });
  document.addEventListener('change', event => {
    const id = event.target.id;
    if (id === 'web-poc-format') loadPoc();
    else if (['web-confidence','web-severity','web-scan-filter'].includes(id)) render();
    else if (/^(f|pf)-(web-|vuln-source)/.test(id)) {
      const prefix = id.startsWith('pf-') ? 'pf' : 'f';
      if (id.endsWith('web-scope') && event.target.value === 'web') $(`${prefix}-web-enabled`).checked = true;
      syncControls(prefix);
    }
  });
  document.addEventListener('input', event => { if (event.target.id === 'web-search') render(); });
  document.addEventListener('DOMContentLoaded', async () => {
    $('web-finding-dialog').addEventListener('close',() => { ++detailRevision; ++pocRevision; selected = null; displayedPoc = ''; });
    try {
      catalog = await json('/api/web/catalog');
      ['f','pf'].forEach(mount); setOffline(catalog.offline); await refresh();
    } catch (error) { $('web-result-count').textContent = `Could not load web controls: ${error.message}`; }
    setInterval(refresh,5000);
  });
  window.webSecurity = {setControls,readControls,validateControls,setOffline,refresh};
})();
