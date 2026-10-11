"""Exercise dashboard controls, untrusted findings and explicit verification."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from bs4 import BeautifulSoup

from modules.web.options import CHECKS, LIMITS, normalize_options
from tests.unit.test_web_ui_behavior import run_js as run_app_js


NODE = shutil.which("node")
SCRIPT = Path(__file__).resolve().parents[2] / "modules/web_ui_static/web_security.js"
pytestmark = [pytest.mark.unit, pytest.mark.skipif(not NODE, reason="Node.js is unavailable")]


def run_js(test):
    harness = r"""
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict');
const nodes=new Map(), listeners={}, calls=[], messages=[], intervals=[];
function node(id='') {
  const children=new Map();let html='',text='',details=[];
  const element={id,value:'',checked:false,disabled:false,hidden:false,open:false,dataset:{},scrollTop:0,
    classList:{toggle(){}}, querySelector(selector){
      if(selector.startsWith('details'))return this.querySelectorAll(selector)[0] || null;
      if(!children.has(selector))children.set(selector,node());return children.get(selector)},
    querySelectorAll(selector){return /^details(?:\[|$)/.test(selector)?details:[]},
    addEventListener(name,fn){listeners[id+':'+name]=fn},removeAttribute(name){delete this[name]},
    showModal(){this.open=true},close(){this.open=false},appendChild(){},remove(){},click(){},focus(){},scrollIntoView(){}};
  Object.defineProperty(element,'innerHTML',{get(){return html},set(value){html=value;text='';details=[];
    for(const match of value.matchAll(/<details\b([^>]*)>/g)){
      const detail=node();detail.open=/\bopen(?:\s|$)/.test(match[1]);
      detail.dataset.webDisclosure=/data-web-disclosure="([^"]*)"/.exec(match[1])?.[1];details.push(detail);
    }
  }});
  Object.defineProperty(element,'textContent',{get(){return text},set(value){text=value;html='';details=[]}});
  return element;
}
const document={getElementById(id){if(!nodes.has(id))nodes.set(id,node(id));return nodes.get(id)},
  querySelectorAll(){return []},createElement(){return node()},body:node(),addEventListener(name,fn){listeners[name]=fn}};
const catalog=JSON.parse(process.argv[2]);
const row={id:'finding',scan_id:'job',type:'CORS',title:'CORS policy',severity:'high',confidence:'candidate',
  url:'https://example.test/',evidence:'Reflected origin',details:{title:'CORS policy',references:[]},
  reproduction:{target:'https://example.test/',requests:[]},observations:[]};
let responseRows=[row], responseJobs=[{id:'job',target:'example.test',status:'completed',config:{scan_web:true},web_finding_count:1,web_coverage:[]}];
const context=vm.createContext({document,window:{},URL,Blob,assert,console,navigator:{clipboard:{writeText:async()=>{}}},
  toast:(...args)=>messages.push(args),setInterval:fn=>intervals.push(fn),setTimeout(){},
  fetch:async(url,opts)=>{calls.push([url,opts]);let data=url==='/api/web/catalog'?catalog:url==='/api/web/findings'?responseRows:url==='/api/scans'?responseJobs:row;
    return {ok:true,json:async()=>JSON.parse(JSON.stringify(data)),text:async()=>'<script>POC IS TEXT</script>'};}});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
context.nodes=nodes;context.calls=calls;context.row=row;context.catalog=catalog;context.messages=messages;context.responseJobs=responseJobs;
context.emit=async(name,id,dataset={})=>listeners[name]({target:{id,value:document.getElementById(id).value,closest:()=>({dataset})}});
context.flush=async()=>{for(let i=0;i<15;i++)await new Promise(resolve=>setImmediate(resolve));};
(async()=>{await listeners.DOMContentLoaded();await vm.runInContext('(async()=>{'+process.argv[3]+'})()',context)})()
  .catch(error=>{console.error(error);process.exitCode=1});
"""
    catalog = {"checks": CHECKS, "defaults": normalize_options(), "limits": LIMITS, "offline": False}
    result = subprocess.run([NODE, "-e", harness, str(SCRIPT), json.dumps(catalog), test], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_controls_round_trip_profiles_web_only_and_offline():
    run_js("""
window.webSecurity.setControls('f',{scan_web:true,scan_ports:false,web_options:{timeout:7,checks:{sqli:false}}});
let saved=window.webSecurity.readControls('f');
assert.equal(saved.scan_web,true);assert.equal(saved.scan_ports,false);assert.equal(saved.scan_vulns,false);
assert.equal(nodes.get('f-network-controls').hidden,true);
assert.equal(saved.web_options.checks.sqli,false);assert.equal(saved.web_options.checks.cors,true);assert.equal(saved.web_options.timeout,7);
assert.equal(window.webSecurity.validateControls('f'),'');
window.webSecurity.setOffline(true);
assert.equal(window.webSecurity.readControls('f').scan_web,false);
assert.equal(nodes.get('f-web-enabled').disabled,true);
assert.match(window.webSecurity.validateControls('f'),/online source/);
window.webSecurity.setOffline(false);assert.equal(window.webSecurity.readControls('f').scan_web,true);
nodes.get('f-vuln-source').value='offline';await emit('change','f-vuln-source');
assert.equal(window.webSecurity.readControls('f').scan_web,false);
""")


def test_presets_and_limits_reject_empty_or_unbounded_scans():
    run_js("""
window.webSecurity.setControls('f',{scan_web:true});
await emit('click','', {webAction:'preset',prefix:'f',preset:'none'});
assert.match(window.webSecurity.validateControls('f'),/at least one/);
await emit('click','', {webAction:'preset',prefix:'f',preset:'light'});
const saved=window.webSecurity.readControls('f');assert.equal(Object.values(saved.web_options.checks).filter(Boolean).length,2);
assert.equal(saved.web_options.checks.headers,true);assert.equal(saved.web_options.checks.tls,true);
nodes.get('f-web-limit-request_budget').value='2001';assert.match(window.webSecurity.validateControls('f'),/20–2000/);
nodes.get('f-web-limit-request_budget').value='20.5';assert.match(window.webSecurity.validateControls('f'),/20–2000/);
""")


def test_inspecting_findings_and_code_is_read_only_and_escapes_untrusted_data():
    run_js(r"""
row.title='\"\'><img src=x onerror=alert(1)>';row.id='\" onclick=\"alert(1)';
row.evidence='<script>bad()</script>';row.details.references=[{title:'Bad',url:'javascript:alert(1)'}];
await window.webSecurity.refresh();
assert.ok(!nodes.get('web-findings-list').innerHTML.includes('<img'));assert.match(nodes.get('web-findings-list').innerHTML,/&lt;img/);
await emit('click','',{webAction:'open',scan:'job',id:'finding'});await flush();
assert.ok(!nodes.get('web-panel-overview').innerHTML.includes('javascript:'));assert.ok(!nodes.get('web-panel-overview').innerHTML.includes('<script>'));
await emit('click','',{webAction:'detail-tab',panel:'poc'});await flush();
assert.equal(nodes.get('web-poc-code').textContent,'<script>POC IS TEXT</script>');
assert.equal(calls.filter(([,opts])=>opts?.method==='POST').length,0);
await emit('click','',{webAction:'verify'});await flush();
const posts=calls.filter(([,opts])=>opts?.method==='POST');assert.equal(posts.length,1);
assert.match(posts[0][0],/\/verify$/);assert.equal(posts[0][1].body,'{}');
""")


def test_redacted_inputs_block_server_replay_and_filters_are_inert():
    run_js("""
row.reproduction.target='https://example.test/?token=REDACTED';
await emit('click','',{webAction:'open',scan:'job',id:'finding'});await flush();
assert.equal(nodes.get('web-verify-button').disabled,true);
await emit('click','',{webAction:'verify'});await flush();assert.equal(calls.filter(([,opts])=>opts?.method==='POST').length,0);
nodes.get('web-search').value='not present';await emit('input','web-search');
assert.equal(nodes.get('web-findings-list').innerHTML,'');assert.equal(nodes.get('web-empty').hidden,false);
nodes.get('web-search').value='';nodes.get('web-confidence').value='advisory';await emit('change','web-confidence');
assert.equal(nodes.get('web-findings-list').innerHTML,'');
""")


def test_late_detail_response_cannot_overwrite_a_new_selection():
    run_js("""
let resolveOld;const original=fetch;
fetch=async(url,opts)=>url.endsWith('/old')?await new Promise(resolve=>{resolveOld=()=>resolve({ok:true,json:async()=>({...row,details:{title:'Old'}})})}):original(url,opts);
await emit('click','',{webAction:'open',scan:'job',id:'old'});await flush();
await emit('click','',{webAction:'open',scan:'job',id:'new'});await flush();
resolveOld();await flush();assert.equal(nodes.get('web-detail-title').textContent,'CORS policy');
""")


def test_scan_and_profile_forms_send_selected_controls_to_backend():
    run_app_js("""
window.webSecurity={validateControls:()=>'',readControls:()=>({scan_web:true,scan_ports:false,scan_vulns:false,web_options:{timeout:7}}),setControls:(prefix,c)=>{window.loaded=c}};
document.getElementById('f-target').value='https://example.test/';let posted;
fetch=async(url,opts)=>{posted=JSON.parse(opts.body);return {ok:true,json:async()=>({scan_id:'job'})}};
await startScan();assert.equal(posted.scan_ports,false);assert.equal(posted.scan_vulns,false);assert.equal(posted.web_options.timeout,7);
profiles.p={config:{scan_web:true,scan_ports:false}};document.getElementById('f-profile').value='p';loadProfile();
assert.equal(window.loaded.scan_web,true);
document.getElementById('pf-name').value='Web';loadProfilesFromServer=async()=>{};
await saveProfile();assert.equal(posted.scan_web,true);assert.equal(posted.web_options.timeout,7);
""")


def test_scan_scope_keeps_source_and_start_controls_outside_hidden_network_form():
    html = BeautifulSoup(SCRIPT.with_name("index.html").read_text(encoding="utf-8"), "html.parser")
    ids = [element["id"] for element in html.select("[id]")]
    assert len(ids) == len(set(ids))
    for prefix in ("f", "pf"):
        network = html.find(id=f"{prefix}-network-controls")
        assert network.find(id=f"{prefix}-mode")
        assert not network.find(id=f"{prefix}-vuln-source")
        assert not network.find(id=f"{prefix}-web-controls")
        assert not network.find("button")
    assert html.find(id="f-web-controls").find_parent(id="scan-form")
    assert html.find(id="pf-web-controls").find_parent(id="profile-form")


def test_scan_pdf_includes_web_evidence_and_coverage():
    run_app_js("""
scans={web:{id:'web',target:'example.test',config:{scan_ports:false},host_count:1}};let html='';
window.open=()=>({document:{write(value){html=value},close(){}},close(){}});
fetch=async()=>({ok:true,json:async()=>({hosts:[{ip:'example.test',ports:[]}],web_findings:[{type:'XSS',severity:'medium',confidence:'candidate',url:'http://example.test/',evidence:'<script>marker</script>',details:{title:'Reflected XSS',remediation:'Encode output'},verification:{status:'reproduced'}}],web_coverage:[{endpoint:'http://example.test/',status:'partial',requests:20,issues:['Budget reached']}]})});
await printScan('web');assert.match(html,/Web Findings/);assert.match(html,/Encode output/);assert.match(html,/Budget reached/);
assert.match(html,/&lt;script&gt;/);assert.ok(!html.includes('<script>marker'));assert.match(html,/Port scan was not selected/);
""")


def test_periodic_offline_status_poll_does_not_replace_open_verification_exchanges():
    run_js("""
row.verification={status:'reproduced',summary:'Recorded evidence matched',observations:[{status:200}]};
await emit('click','',{webAction:'open',scan:'job',id:'finding'});await flush();
const result=nodes.get('web-verification-result'), exchanges=result.querySelector('details');exchanges.open=true;
for(let i=0;i<3;i++)window.webSecurity.setOffline(false);
assert.equal(result.querySelector('details'),exchanges);assert.equal(exchanges.open,true);
window.webSecurity.setOffline(true);
assert.equal(result.querySelector('details').open,true);assert.equal(nodes.get('web-verify-button').disabled,true);
window.webSecurity.setOffline(false);
assert.equal(result.querySelector('details').open,true);assert.equal(nodes.get('web-verify-button').disabled,false);
""")


def test_new_verification_result_preserves_open_and_closed_evidence_sections():
    run_js("""
row.observations=[{request:{role:'baseline',url:row.url},response:{status:200}},
  {request:{role:'probe',url:row.url},response:{status:200}}];
row.reproduction.certificate={subject:'example.test'};
row.verification={status:'reproduced',summary:'First run',observations:[{status:200}]};
await emit('click','',{webAction:'open',scan:'job',id:'finding'});await flush();
const evidence=nodes.get('web-panel-evidence'), verification=nodes.get('web-verification-result');
const sections=evidence.querySelectorAll('details');sections[0].open=false;sections[1].open=true;sections[2].open=false;sections[3].open=true;
verification.querySelector('details').open=true;
row.verification={status:'not_reproduced',summary:'Second run: no match',observations:[{status:403}]};
await window.webSecurity.refresh();
assert.equal(verification.querySelector('details').open,true);assert.match(verification.innerHTML,/Second run: no match/);
assert.equal(evidence.querySelectorAll('details')[0].open,false);assert.equal(evidence.querySelectorAll('details')[1].open,true);
assert.equal(evidence.querySelectorAll('details')[2].open,false);assert.equal(evidence.querySelectorAll('details')[3].open,true);
""")


def test_verification_preserves_expansion_across_running_phase_and_resets_on_reopen():
    run_js("""
row.verification={status:'reproduced',summary:'First run',observations:[{status:200}]};
await emit('click','',{webAction:'open',scan:'job',id:'finding'});await flush();
const verification=nodes.get('web-verification-result');verification.querySelector('details').open=true;
row.verification={status:'running',summary:'Replaying recorded evidence'};
await window.webSecurity.refresh();assert.equal(verification.querySelector('details'),null);
row.verification={status:'not_reproduced',summary:'Second run',observations:[{status:403}]};
await window.webSecurity.refresh();assert.equal(verification.querySelector('details').open,true);
await emit('click','',{webAction:'close'});
await emit('click','',{webAction:'open',scan:'job',id:'finding'});await flush();
assert.match(verification.innerHTML,/Second run/);assert.equal(verification.querySelector('details').open,false);
row.id='other';await emit('click','',{webAction:'open',scan:'job',id:'other'});await flush();
assert.equal(verification.querySelector('details').open,false);
""")


def test_incomplete_coverage_card_stays_open_on_polls_and_issue_updates():
    run_js("""
responseJobs[0].status='partial';responseJobs[0].web_coverage=[{endpoint:row.url,status:'partial',requests:20,issues:['Request budget reached']}];
await window.webSecurity.refresh();const coverage=nodes.get('web-coverage'), detail=coverage.querySelector('details');detail.open=true;
await window.webSecurity.refresh();assert.equal(coverage.querySelector('details'),detail);assert.equal(detail.open,true);
responseJobs[0].web_coverage[0].issues.push('Response size limit reached');
await window.webSecurity.refresh();assert.equal(coverage.querySelector('details').open,true);assert.match(coverage.innerHTML,/Response size limit reached/);
coverage.querySelector('details').open=false;responseJobs[0].web_coverage[0].requests=21;
await window.webSecurity.refresh();assert.equal(coverage.querySelector('details').open,false);
assert.equal(calls.filter(([,opts])=>opts?.method==='POST').length,0);
""")
