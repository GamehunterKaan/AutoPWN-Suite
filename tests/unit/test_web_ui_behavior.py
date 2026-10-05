"""Run dashboard behavior with mocked HTTP/DOM, without a browser or server."""

from pathlib import Path
import shutil
import subprocess

import pytest


APP_JS = Path(__file__).resolve().parents[2] / "modules" / "web_ui_static" / "app.js"
NODE = shutil.which("node")
pytestmark = [pytest.mark.unit, pytest.mark.skipif(not NODE, reason="Node.js is unavailable")]


def run_js(script):
    harness = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const nodes = new Map();
function node() {
  return {value:'', checked:false, innerHTML:'', textContent:'', style:{}, dataset:{}, children:[],
    classList:{add(){}, remove(){}, toggle(){}}, addEventListener(){}, querySelectorAll(){return []},
    appendChild(child){this.children.push(child)}, click(){}, remove(){}};
}
const document = {getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)},
  createElement(){return node()}, querySelectorAll(){return []}, querySelector(){return node()},
  addEventListener(){}, body:node()};
const context = vm.createContext({assert, nodes, document, window:{location:{origin:'http://localhost'}},
  setTimeout(){}, clearTimeout(){}, Blob, URL, console});
const source = fs.readFileSync(process.argv[1], 'utf8');
vm.runInContext(source.slice(0, source.lastIndexOf('\n(async()=>{')), context);
(async()=>{
  await vm.runInContext('(async()=>{' + process.argv[2] + '})()', context);
})().catch(error=>{console.error(error);process.exitCode=1});
"""
    result = subprocess.run([NODE, "-e", harness, str(APP_JS), script], text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_poll_replaces_old_findings_with_latest_observation():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
const jobs=[{id:'old',started_at:'2026-01-01T00:00:00Z'}, {id:'new',started_at:'2026-01-02T00:00:00Z'}];
const rows=[{ip:'10.0.0.1',scan_id:'new',ports:[],vulns:[]},
  {ip:'10.0.0.1',scan_id:'old',ports:[{port:80}],vulns:[{cve:'CVE-2020-0001',port:80}]}];
fetch=async url=>({ok:true,json:async()=>url==='/api/scans'?jobs:rows});
await poll();
assert.equal(hosts['10.0.0.1'].scan_id,'new');
assert.equal(hosts['10.0.0.1'].ports.length,0);
assert.equal(hosts['10.0.0.1'].vulns.length,0);
""")


def test_poll_does_not_overlap_slow_requests():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
const pending=[];
fetch=()=>new Promise(resolve=>pending.push(resolve));
const first=poll();
await poll();
assert.equal(pending.length,2);
pending.forEach(resolve=>resolve({ok:true,json:async()=>[]}));
await first;
assert.equal(pollBusy,false);
""")


def test_failed_poll_preserves_results_and_can_retry():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
hosts={'10.0.0.1':{ip:'10.0.0.1',ports:[{port:443}]}};
fetch=async()=>({ok:false,status:503,json:async()=>({error:'Unavailable'})});
await poll();
assert.equal(hosts['10.0.0.1'].ports[0].port,443);
assert.equal(pollBusy,false);
fetch=async()=>({ok:true,json:async()=>[]});
await poll();
assert.equal(Object.keys(hosts).length,0);
""")


def test_disappearing_host_clears_selected_details():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
selIp='10.0.0.1'; hosts={};
fetch=async()=>({ok:true,json:async()=>[]});
await poll();
assert.equal(selIp,null);
assert.equal(nodes.get('det-content').style.display,'none');
""")


def test_active_scans_sort_before_completed_and_preserve_speed_zero():
    run_js("""
scans={old:{id:'old',target:'running target',status:'running',started_at:'2026-01-01',config:{speed:0}},
  newer:{id:'newer',target:'completed target',status:'completed',started_at:'2026-01-02'}};
renderScans();
const cards=nodes.get('tc-scans').children;
assert.match(cards[0].innerHTML,/running target/);
assert.match(cards[0].innerHTML,/-T 0/);
""")


def test_profile_load_and_edit_preserve_zero_values():
    run_js("""
profiles={zero:{id:'zero',config:{speed:0,version_intensity:0}}};
document.getElementById('f-profile').value='zero';
loadProfile();
assert.equal(nodes.get('f-speed').value,'0');
assert.equal(nodes.get('f-vint').value,'0');
editProfile('zero');
assert.equal(nodes.get('pf-speed').value,'0');
assert.equal(nodes.get('pf-vint').value,'0');
""")


def test_scan_pdf_fetches_its_snapshot_and_opens_before_download():
    run_js("""
scans={old:{id:'old',target:'old scan',status:'completed',host_count:1}};
hosts={'10.0.0.2':{ip:'10.0.0.2',scan_id:'new'}};
const events=[]; let printed='';
window.open=()=>{events.push('open');return {document:{write(html){printed=html},close(){}},close(){}}};
fetch=async url=>{events.push('download'); assert.equal(url,'/api/scans/old/download');
  return {ok:true,json:async()=>({hosts:[{ip:'10.0.0.1',ports:[]}]})};};
await printScan('old');
assert.equal(events.join(','),'open,download');
assert.match(printed,/Host: 10.0.0.1/);
assert.doesNotMatch(printed,/Host: 10.0.0.2/);
""")


def test_blocked_popup_is_reported_without_throwing():
    run_js("""
scans={id:{id:'id'}};
window.open=()=>null;
let warning=''; toast=message=>{warning=message};
fetch=()=>{throw new Error('Download should not start')};
await printScan('id');
assert.match(warning,/Allow popups/);
""")


def test_profile_deletion_refreshes_disabled_schedules():
    run_js("""
confirm=()=>true;
const refreshed=[];
loadProfilesFromServer=async()=>refreshed.push('profiles');
loadSchedulesFromServer=async()=>refreshed.push('schedules');
toast=()=>{};
fetch=async()=>({ok:true});
await deleteProfile('removed');
assert.equal(refreshed.join(','),'profiles,schedules');
""")


def test_host_json_preserves_tcp_udp_separation():
    run_js("""
hosts={ip:{ip:'ip',ports:[{port:53,protocol:'tcp'},{port:53,protocol:'udp'}],
  vulns:[{cve:'TCP',port:53,protocol:'tcp'},{cve:'UDP',port:53,protocol:'udp'}]}};
let blob;
URL={createObjectURL(value){blob=value;return 'blob:test'},revokeObjectURL(){}};
downloadHostJson('ip');
const data=JSON.parse(await blob.text());
assert.equal(data.ports[0].protocol,'tcp');
assert.equal(data.ports[0].vulnerabilities[0].cve,'TCP');
assert.equal(data.ports[1].vulnerabilities[0].cve,'UDP');
assert.equal(data.ports[0].vulnerabilities.length,1);
""")


@pytest.mark.parametrize("status", ["error", "stopped", "partial", "not_observed"])
def test_incomplete_hosts_are_not_rendered_as_clean(status):
    run_js(f"""
hosts={{ip:{{ip:'ip',scan_status:'{status}',ports:[],vulns:[]}}}};
renderHosts(); renderDetail(hosts.ip);
assert.doesNotMatch(nodes.get('hosts-grid').children[0].innerHTML,/hc-badge clean/);
assert.doesNotMatch(nodes.get('det-content').innerHTML,/No vulnerabilities found/);
""")
