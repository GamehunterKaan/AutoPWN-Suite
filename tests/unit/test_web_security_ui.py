"""Exercise dashboard controls, untrusted findings and explicit verification."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

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
  const children=new Map();
  return {id,value:'',checked:false,disabled:false,hidden:false,open:false,innerHTML:'',textContent:'',dataset:{},
    classList:{toggle(){}}, querySelector(selector){if(!children.has(selector))children.set(selector,node());return children.get(selector)},
    querySelectorAll(){return []}, addEventListener(name,fn){listeners[id+':'+name]=fn},removeAttribute(name){delete this[name]},
    showModal(){this.open=true},close(){this.open=false},appendChild(){},remove(){},click(){},focus(){},scrollIntoView(){}};
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
    return {ok:true,json:async()=>data,text:async()=>'<script>POC IS TEXT</script>'};}});
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
context.nodes=nodes;context.calls=calls;context.row=row;context.catalog=catalog;context.messages=messages;
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
