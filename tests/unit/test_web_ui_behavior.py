# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Run dashboard behavior with mocked HTTP/DOM, without a browser or server."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parents[2] / "autopwn_suite" / "web_ui_static" / "app.js"
I18N_JS = Path(__file__).resolve().parents[2] / "autopwn_suite" / "web_ui_static" / "i18n.js"
NODE = shutil.which("node")
pytestmark = [pytest.mark.unit, pytest.mark.skipif(not NODE, reason="Node.js is unavailable")]


def run_js(script):
    harness = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const nodes = new Map();
const listeners = {};  // what the script registered with document.addEventListener, by event type
function node() {  // children, parentNode, appendChild, insertBefore, nextSibling and remove behave like the DOM's
  return {value:'', checked:false, innerHTML:'', textContent:'', style:{}, dataset:{}, children:[], parentNode:null,
    classList:{add(){}, remove(){}, toggle(){}}, addEventListener(){}, querySelectorAll(){return []},
    appendChild(child){return this.insertBefore(child, null)},
    insertBefore(child, reference){
      if (child.parentNode) child.remove();
      const at = reference ? this.children.indexOf(reference) : -1;
      if (at < 0) this.children.push(child); else this.children.splice(at, 0, child);
      child.parentNode = this;
      return child;
    },
    get nextSibling(){ const siblings = this.parentNode && this.parentNode.children; return siblings ? siblings[siblings.indexOf(this) + 1] || null : null; },
    click(){},
    remove(){ if (this.parentNode) { this.parentNode.children.splice(this.parentNode.children.indexOf(this), 1); this.parentNode = null; } }};
}
const document = {getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)},
  createElement(){return node()}, querySelectorAll(){return []}, querySelector(){return node()},
  addEventListener(type, handler){(listeners[type] ||= []).push(handler)}, body:node(), documentElement:{lang:''}};
const localStorage = {store:new Map(),
  getItem(key){return this.store.has(key) ? this.store.get(key) : null;},
  setItem(key, value){this.store.set(key, String(value));},
  removeItem(key){this.store.delete(key);}};
const navigator = {language:'en-US'};
const context = vm.createContext({assert, nodes, listeners, document, localStorage, navigator,
  window:{location:{origin:'http://localhost'}},
  setTimeout(){}, clearTimeout(){}, Blob, URL, console});
context.window.localStorage = localStorage;
context.window.navigator = navigator;
context.window.document = document;
const i18nSource = fs.readFileSync(process.argv[1], 'utf8');
vm.runInContext(i18nSource, context);
const source = fs.readFileSync(process.argv[2], 'utf8');
vm.runInContext(source.slice(0, source.lastIndexOf('\n(async()=>{')), context);
let finished = false;
process.on('exit', () => { if (!finished && !process.exitCode) { console.error('The test script never finished.'); process.exitCode = 1; } });
(async()=>{
  await vm.runInContext('(async()=>{' + process.argv[3] + '})()', context);
  finished = true;
})().catch(error=>{console.error(error);process.exitCode=1});
"""
    result = subprocess.run([NODE, "-e", harness, str(I18N_JS), str(APP_JS), script], text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_profile_metadata_is_text_even_for_saved_markup_and_legacy_config():
    run_js(r"""
const payload='<img src=x onerror="alert(1)"><script>alert(2)</script>';
profiles={one:{id:'one',name:'Office & lab',description:payload,
  config:{mode:payload,speed:payload}}};
renderProfiles();
const html=nodes.get('profiles-list').innerHTML;
assert.doesNotMatch(html,/<img|<script/);
assert.equal((html.match(/&lt;img/g)||[]).length,3);
assert.match(html,/Office &amp; lab/);
profiles={two:{id:'two',name:'Normal',description:'Quotes " and <text>',config:{mode:'normal',speed:3}}};
renderProfiles();
assert.match(nodes.get('profiles-list').innerHTML,/Quotes &quot; and &lt;text&gt;/);
assert.match(nodes.get('profiles-list').innerHTML,/Mode: Normal · Speed: 3/);
""")


def test_database_controls_show_status_without_starting_a_download():
    run_js("""
const calls=[];
fetch=async url=>{calls.push(url);return {ok:true,json:async()=>({ready:true,count:123,
  size_bytes:1048576,updated_at:'2026-10-09T08:00:00Z',offline_only:true,offline_locked:true,update:{running:false}})}};
await loadDatabaseStatus();
assert.equal(calls.length,1);
assert.equal(calls[0],'/api/vulnerability-database');
assert.equal(nodes.get('database-update').disabled,true);
assert.equal(nodes.get('database-export').hidden,false);
assert.equal(nodes.get('f-vuln-source').value,'offline');
assert.equal(nodes.get('f-vuln-source').disabled,true);
assert.equal(nodes.get('s-offline-mode').checked,true);
assert.equal(nodes.get('s-offline-mode').disabled,true);
assert.match(nodes.get('database-status').textContent,/123 CVEs/);
""")


def test_webhook_toggle_persists_false_without_erasing_url_or_sending_a_ping():
    run_js("""
const stored={webhook:{enabled:true,url:'https://example.invalid/hook',on_complete:true,on_error:false,on_vuln_found:true}};
const calls=[];
fetch=async(url,opts)=>{
  calls.push([url,opts]);
  if(opts){Object.assign(stored.webhook,JSON.parse(opts.body).webhook);return {ok:true,json:async()=>({ok:true})};}
  return {ok:true,json:async()=>JSON.parse(JSON.stringify(stored))};
};
await loadSettingsIntoForm();
document.getElementById('s-webhook-enabled').checked=false;
await changeWebhookEnabled();
assert.equal(stored.webhook.enabled,false);
assert.equal(stored.webhook.url,'https://example.invalid/hook');
assert.equal(stored.webhook.on_error,false);
assert.equal(nodes.get('webhook-section').style.display,'none');
assert.equal(nodes.get('s-webhook-save').disabled,false);
assert.equal(nodes.get('s-webhook-test').disabled,true);
await loadSettingsIntoForm();
assert.equal(nodes.get('s-webhook-enabled').checked,false);
assert.deepEqual(JSON.parse(calls[1][1].body),{webhook:{enabled:false}});
assert.equal(calls.every(([url])=>url==='/api/settings'),true);
""")


def test_webhook_toggle_reverts_and_reports_failed_persistence():
    run_js("""
fetch=async(url,opts)=>opts ? {ok:false,json:async()=>({error:'Storage unavailable'})}
  : {ok:true,json:async()=>({webhook:{enabled:true,url:'https://example.invalid/hook'}})};
await loadSettingsIntoForm();
document.getElementById('s-webhook-enabled').checked=false;
await changeWebhookEnabled();
assert.equal(nodes.get('s-webhook-enabled').checked,true);
assert.equal(nodes.get('s-webhook-enabled').disabled,false);
assert.equal(nodes.get('s-webhook-test').disabled,false);
assert.match(nodes.get('toast-el').textContent,/not saved.*Storage unavailable/);
""")


def test_stale_settings_read_cannot_undo_successful_webhook_toggle():
    run_js("""
let finishRead;
fetch=async(url,opts)=>opts ? {ok:true,json:async()=>({ok:true})}
  : {ok:true,json:async()=>({webhook:{enabled:true,url:'https://example.invalid/hook'}})};
await loadSettingsIntoForm();
fetch=async(url,opts)=>opts ? {ok:true,json:async()=>({ok:true})}
  : {ok:true,json:()=>new Promise(resolve=>{finishRead=resolve})};
const stale=loadSettingsIntoForm();
await Promise.resolve();await Promise.resolve();
document.getElementById('s-webhook-enabled').checked=false;
await changeWebhookEnabled();
finishRead({webhook:{enabled:true}});
await stale;
assert.equal(nodes.get('s-webhook-enabled').checked,false);
""")


def test_dashboard_toggle_saves_global_setting_and_restores_online_controls():
    run_js("""
let enabled=false;
const calls=[];
document.getElementById('f-vuln-source').value='online';
fetch=async (url,opts)=>{
  calls.push([url,opts]);
  if(opts){enabled=JSON.parse(opts.body).offline_mode;return {ok:true,json:async()=>({ok:true})}}
  return {ok:true,json:async()=>({ready:true,count:2,size_bytes:1024,updated_at:'2026-10-10T00:00:00Z',
    offline_only:enabled,offline_locked:false,update:{running:false}})};
};
document.getElementById('s-offline-mode').checked=true;
await saveOfflineMode();
assert.equal(enabled,true);
assert.equal(calls[0][0],'/api/settings');
assert.equal(calls[0][1].method,'PUT');
assert.equal(nodes.get('database-update').disabled,true);
assert.equal(nodes.get('f-vuln-source').value,'offline');
assert.equal(nodes.get('s-offline-mode').disabled,false);
document.getElementById('s-offline-mode').checked=false;
await saveOfflineMode();
assert.equal(nodes.get('database-update').disabled,false);
assert.equal(nodes.get('f-vuln-source').disabled,false);
assert.equal(nodes.get('f-vuln-source').value,'online');
assert.equal(nodes.get('s-offline-mode').checked,false);
assert.equal(calls.length,4);
""")


def test_dashboard_toggle_reverts_after_active_scan_rejection():
    run_js("""
fetch=async (url,opts)=>opts
  ? {ok:false,json:async()=>({error:'Stop active online scans first'})}
  : {ok:true,json:async()=>({ready:false,offline_only:false,offline_locked:false,update:{}})};
document.getElementById('s-offline-mode').checked=true;
await saveOfflineMode();
assert.equal(nodes.get('s-offline-mode').checked,false);
assert.equal(nodes.get('s-offline-mode').disabled,false);
assert.equal(nodes.get('f-vuln-source').disabled,false);
""")


def test_database_status_responses_cannot_revert_a_newer_offline_setting():
    run_js("""
const pending=[];
fetch=()=>new Promise(resolve=>pending.push(resolve));
document.getElementById('f-vuln-source').value='online';
const old=loadDatabaseStatus();
const current=loadDatabaseStatus();
const status=enabled=>({ready:false,offline_only:enabled,offline_locked:false,update:{}});
pending[1]({ok:true,json:async()=>status(true)});
await current;
pending[0]({ok:true,json:async()=>status(false)});
await old;
assert.equal(nodes.get('s-offline-mode').checked,true);
assert.equal(nodes.get('f-vuln-source').disabled,true);
assert.equal(nodes.get('database-update').disabled,true);
""")


def test_scan_form_sends_selected_offline_source():
    run_js("""
document.getElementById('f-target').value='192.168.1.10';
document.getElementById('f-vuln-source').value='offline';
addLog=()=>{};
let sent;
fetch=async (url,opts)=>{sent=JSON.parse(opts.body);return {ok:false,json:async()=>({error:'missing database'})}};
await startScan();
assert.equal(sent.vulnerability_source,'offline');
assert.equal(sent.target,'192.168.1.10');
""")


@pytest.mark.parametrize("target,outcome,message,requests", [
    ("   ", {}, "Please enter a target.", 0),
    ("bad;target", {"body": {"error": "Invalid target"}}, "Invalid target", 1),
    ("192.0.2.1", {"body": {}}, "Failed to start scan.", 1),
    ("192.0.2.1", {"unreachable": "offline"}, "Cannot reach server: offline", 1),
])
def test_scan_start_failures_are_toasted_as_well_as_logged(target, outcome, message, requests):
    run_js(f"const target={json.dumps(target)}, outcome={json.dumps(outcome)}, message={json.dumps(message)}, "
           f"expectedRequests={requests};" + """
document.getElementById('f-target').value=target;
let requests=0;
fetch=async()=>{requests++;
  if(outcome.unreachable) throw new Error(outcome.unreachable);
  return {ok:false,status:400,json:async()=>outcome.body};};
await startScan();
assert.equal(requests,expectedRequests);
assert.equal(document.getElementById('toast-el').textContent,message);
assert.equal(document.getElementById('toast-el').className,'toast err');
assert.equal(nodes.get('term').children.length,1);
assert.ok(nodes.get('term').children[0].innerHTML.includes(message));
""")


@pytest.mark.parametrize("status,ok", [(500, False), (502, False), (200, True)])
def test_scan_start_with_a_non_json_response_reports_the_status_not_an_unreachable_server(status, ok):
    run_js(f"const status={status}, ok={json.dumps(ok)};" + """
document.getElementById('f-target').value='192.0.2.1';
fetch=async()=>({ok,status,json:async()=>{throw new SyntaxError("Unexpected token '<', \\"<html>\\" is not valid JSON")}});
await startScan();
const message=`Failed to start scan (HTTP ${status}).`;
assert.equal(document.getElementById('toast-el').textContent,message);
assert.equal(document.getElementById('toast-el').className,'toast err');
assert.ok(nodes.get('term').children[0].innerHTML.includes(message));
assert.equal(nodes.get('f-target').value,'192.0.2.1');
""")


def test_double_click_on_start_scan_sends_one_request_and_the_button_recovers():
    run_js("""
document.getElementById('f-target').value='192.0.2.1';
let requests=0, answer;
fetch=url=>{if(url==='/api/scan/start'){requests++;return new Promise(resolve=>{answer=resolve})}return Promise.resolve({ok:true,json:async()=>[]})};
const button=document.getElementById('start-scan');
const first=startScan();
const second=startScan();
assert.equal(requests,1);
assert.equal(button.disabled,true);
answer({ok:true,json:async()=>({scan_id:'0123456789abcdef'})});
await Promise.all([first,second]);
assert.equal(requests,1);
assert.equal(button.disabled,false);
// A rejected or unreachable start leaves the form usable for the next attempt.
document.getElementById('f-target').value='192.0.2.2';
fetch=async()=>{requests++;return {ok:false,status:400,json:async()=>({error:'Invalid target'})}};
await startScan();
fetch=async()=>{requests++;throw new Error('offline')};
await startScan();
assert.equal(requests,3);
assert.equal(button.disabled,false);
""")


def test_start_scan_returns_keyboard_focus_to_its_button_unless_focus_moved_on():
    run_js("""
const button=document.getElementById('start-scan');
let disabled=false;
// A browser drops focus to <body> when the focused button becomes disabled.
Object.defineProperty(button,'disabled',{get(){return disabled},set(value){disabled=value;if(value&&document.activeElement===button)document.activeElement=document.body}});
button.focus=()=>{document.activeElement=button};
fetch=async()=>({ok:true,json:async()=>({scan_id:'0123456789abcdef'})});
document.getElementById('f-target').value='192.0.2.1';
document.activeElement=button;
await startScan();
assert.equal(document.activeElement,button);
const other=document.getElementById('f-timeout');
document.getElementById('f-target').value='192.0.2.2';
document.activeElement=other;
await startScan();
assert.equal(document.activeElement,other);
""")


def test_accepted_scan_start_shows_no_error_toast():
    run_js("""
document.getElementById('f-target').value='192.0.2.1';
fetch=async()=>({ok:true,json:async()=>({ok:true,scan_id:'0123456789abcdef'})});
await startScan();
assert.equal(document.getElementById('toast-el').textContent,'');
assert.equal(nodes.get('f-target').value,'');
""")


@pytest.mark.parametrize("status,body,message", [
    (404, {"error": "Scan not found"}, "Scan not found"),
    (400, {"ok": False, "message": "Scan is not running"}, "Scan is not running"),
    (500, {}, "Failed to stop scan."),
])
def test_failed_stop_is_toasted_and_logged(status, body, message):
    run_js(f"const status={status}, body={json.dumps(body)}, message={json.dumps(message)};" + """
const calls=[];
fetch=async(url,opts)=>{calls.push([url,JSON.parse(opts.body)]);return {ok:false,status,json:async()=>body}};
await stopScan('0123456789abcdef');
assert.deepEqual(calls,[['/api/scan/stop',{scan_id:'0123456789abcdef'}]]);
assert.equal(document.getElementById('toast-el').textContent,message);
assert.equal(document.getElementById('toast-el').className,'toast err');
assert.ok(nodes.get('term').children[0].innerHTML.includes(message));
""")


def test_stop_reports_unreachable_server_and_success_stays_quiet():
    run_js("""
fetch=async()=>{throw new Error('offline')};
await stopScan('0123456789abcdef');
assert.equal(document.getElementById('toast-el').textContent,'Cannot reach server: offline');
document.getElementById('toast-el').textContent='';
fetch=async()=>({ok:true,json:async()=>({ok:true})});
await stopScan('0123456789abcdef');
assert.equal(document.getElementById('toast-el').textContent,'');
""")


def test_terminal_keeps_only_the_newest_lines():
    run_js("""
const term=document.getElementById('term');
Object.defineProperty(term,'firstElementChild',{get(){return this.children[0]}});
const createElement=document.createElement;
document.createElement=()=>{const line=createElement();line.remove=()=>{term.children.splice(term.children.indexOf(line),1)};return line};
for(let i=0;i<MAX_TERM_LINES+25;i++) addLog(null,'line '+i);
assert.equal(term.children.length,MAX_TERM_LINES);
assert.match(term.children[0].innerHTML,/line 25</);
assert.match(term.children[MAX_TERM_LINES-1].innerHTML,new RegExp('line '+(MAX_TERM_LINES+24)+'<'));
""")


def test_missing_profile_name_is_reported_as_an_error_toast_without_saving():
    run_js("""
const shown=[];
toast=(...args)=>{shown.push(args)};
let requests=0;
fetch=async()=>{requests++;return {ok:true,json:async()=>({})}};
document.getElementById('pf-name').value='   ';
await saveProfile();
assert.deepEqual(shown,[['Profile name is required',false]]);
assert.equal(requests,0);
""")


@pytest.mark.parametrize("narrow", [True, False])
def test_selecting_a_host_brings_its_detail_into_view_only_on_a_narrow_viewport(narrow):
    run_js(f"const narrow={json.dumps(narrow)};" + """
const queries=[], revealed=[];
window.matchMedia=query=>{queries.push(query);return {matches:narrow}};
document.getElementById('right').scrollIntoView=options=>revealed.push(options);
hosts={'192.0.2.1':{ip:'192.0.2.1',ports:[],vulns:[],scan_status:'completed'}};
selectHost('192.0.2.1');
assert.equal(selIp,'192.0.2.1');
assert.match(nodes.get('det-content').innerHTML,/192\\.0\\.2\\.1/);
assert.equal(revealed.length,narrow?1:0);
if(narrow) assert.equal(revealed[0].block,'nearest');
assert.deepEqual(queries.map(String),['(max-width: 760px)']);
selectHost('192.0.2.99');          // a host that is gone changes nothing
assert.equal(revealed.length,narrow?1:0);
""")


@pytest.mark.parametrize("scrolled,follows", [(790, True), (800, True), (100, False), (759, False)])
def test_terminal_follows_new_lines_only_while_the_reader_is_at_the_end(scrolled, follows):
    run_js(f"const scrolled={scrolled}, follows={json.dumps(follows)};" + """
const term=document.getElementById('term');
term.scrollHeight=1000; term.clientHeight=200; term.scrollTop=scrolled;
addLog(null,'new line');
assert.equal(term.scrollTop,follows?1000:scrolled);
assert.equal(term.children.length,1);
""")


def test_terminal_filter_lists_every_scan_the_dashboard_sees_once():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
const filter=document.getElementById('term-filter');
const listed=()=>filter.children.map(option=>option.value).join(',');
let jobs=[{id:'aaaaaaaa-1',target:'192.0.2.1',started_at:'2026-10-19T00:00:00Z'}];
fetch=async url=>({ok:true,json:async()=>url==='/api/scans'?jobs:[]});
// A scan started from this page is listed at once; the next poll must not list it again.
addTermFilterOption('aaaaaaaa-1','192.0.2.1');
await poll();
assert.equal(listed(),'aaaaaaaa-1');
// A scan that the dashboard started itself (a schedule) or another tab started appears with the next poll.
jobs=[...jobs,{id:'bbbbbbbb-2',target:'192.0.2.0/24',started_at:'2026-10-19T01:00:00Z'}];
await poll();
assert.equal(listed(),'aaaaaaaa-1,bbbbbbbb-2');
assert.equal(filter.children[1].textContent,'#bbbbbbbb — 192.0.2.0/24');
jobs=[...jobs];
await poll();
assert.equal(listed(),'aaaaaaaa-1,bbbbbbbb-2');
""")


def test_the_ports_check_accepts_what_the_server_accepts_and_names_the_rule_otherwise():
    run_js("""
for (const ok of ['', '80', '22,80,443', '1-1000', '22,80,1-1000', '1-65535', '65535', '80-80'])
  assert.equal(portsError(ok),'',ok);
const bad=['0','65536','100000','1-65536','80-22','-','80-','-80',',80','80,','80,,443','22, 80','22 80','T:80','U:53','http',
  '80;id','--script=banner','-oN x','080','80.5','+80','80/tcp','*','9'.repeat(40),Array(800).fill('80').join(',')];
for (const value of bad) assert.match(portsError(value),/Ports must be port numbers from 1 to 65535/,value);
""")


def test_the_browser_ports_check_agrees_with_the_server_on_random_and_edge_values():
    import random

    from autopwn_suite.web_ui import _checked_ports

    rng = random.Random(20261019)
    alphabet = "0123456789012345678901234567890123456789-,- ,:TU;pxo"
    corpus = ["", "80", "0", "65535", "65536", "1-65535", "1-65536", "80-22", "80-80", "22,80", "22, 80", "-", "80-", "-80",
              "0080", "99999", "100000", "1,2,3", ",", "1-2-3", "1--2", "T:80", "9" * 40, ",".join(["80"] * 50)]
    corpus += ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14))) for _ in range(700)]
    expected = []
    for value in corpus:
        try:
            _checked_ports(value.strip())
            expected.append(True)
        except ValueError:
            expected.append(False)
    assert any(expected) and not all(expected)
    run_js(f"const corpus={json.dumps(corpus)}, expected={json.dumps(expected)};" + """
const actual=corpus.map(value=>portsError(value.trim())==='');
const different=corpus.filter((value,i)=>actual[i]!==expected[i]);
assert.deepEqual(different,[]);
""")


@pytest.mark.parametrize("ports", ["22, 80", "0", "65536", "80-22", "T:80", "--script=banner", "80 -oN x"])
def test_scan_and_profile_forms_report_a_ports_value_the_server_would_refuse_without_sending_it(ports):
    run_js(f"const ports={json.dumps(ports)};" + """
const shown=[];
toast=(...args)=>{shown.push(args)};
let requests=0;
fetch=async()=>{requests++;return {ok:true,json:async()=>({scan_id:'0123456789abcdef'})}};
document.getElementById('f-target').value='192.0.2.1';
document.getElementById('f-ports').value=ports;
await startScan();
document.getElementById('pf-name').value='Profile';
document.getElementById('pf-ports').value=ports;
await saveProfile();
assert.equal(requests,0);
assert.equal(shown.length,2);
for (const [message,ok] of shown) { assert.match(message,/Ports must be port numbers from 1 to 65535/); assert.equal(ok,false); }
assert.equal(nodes.get('f-target').value,'192.0.2.1');   // the form keeps what was typed
""")


def test_scan_form_sends_the_structured_nmap_controls_and_no_free_text_options():
    run_js("""
document.getElementById('f-target').value='192.0.2.1';
document.getElementById('f-mode').value='evade';
document.getElementById('f-speed').value='4';
document.getElementById('f-scantech').value='-sU';
document.getElementById('f-ports').value='  22,80,1-1000 ';
document.getElementById('f-vint').value='4';
document.getElementById('f-os').checked=true;
document.getElementById('f-timeout').value='90';
let posted;
fetch=async(url,opts)=>{if(url==='/api/scan/start')posted=JSON.parse(opts.body);return {ok:true,json:async()=>({scan_id:'0123456789abcdef'})}};
await startScan();
assert.equal(posted.target,'192.0.2.1');
assert.equal(posted.scan_technique,'-sU');
assert.equal(posted.ports,'22,80,1-1000');
assert.equal(posted.version_intensity,4);
assert.equal(posted.os_detection,true);
assert.equal(posted.host_timeout,90);
assert.equal('nmap_flags' in posted,false);
// An empty intensity is sent as null, and zero stays zero.
document.getElementById('f-target').value='192.0.2.2';
document.getElementById('f-vint').value='';
document.getElementById('f-os').checked=false;
await startScan();
assert.equal(posted.version_intensity,null);
assert.equal(posted.os_detection,false);
document.getElementById('f-target').value='192.0.2.3';
document.getElementById('f-vint').value='0';
await startScan();
assert.equal(posted.version_intensity,0);
""")


def test_profile_form_sends_the_structured_nmap_controls_and_no_free_text_options():
    run_js("""
toast=()=>{};
loadProfilesFromServer=async()=>{};
let posted;
fetch=async(url,opts)=>{posted=JSON.parse(opts.body);return {ok:true,json:async()=>({})}};
document.getElementById('pf-name').value='Quick UDP';
document.getElementById('pf-scantech').value='-sU';
document.getElementById('pf-ports').value='53,161';
document.getElementById('pf-vint').value='0';
document.getElementById('pf-os').checked=true;
await saveProfile();
assert.equal(posted.name,'Quick UDP');
assert.equal(posted.scan_technique,'-sU');
assert.equal(posted.ports,'53,161');
assert.equal(posted.version_intensity,0);
assert.equal(posted.os_detection,true);
assert.equal('nmap_flags' in posted,false);
""")


def test_no_form_reads_or_writes_a_free_text_nmap_options_field():
    run_js("""
toast=()=>{};
loadProfilesFromServer=loadSchedulesFromServer=async()=>{};
fetch=async()=>({ok:true,json:async()=>({scan_id:'0123456789abcdef'})});
profiles={p:{id:'p',name:'P',config:{scan_technique:'-sT',ports:'22',nmap_flags:'--script banner'}}};
document.getElementById('f-profile').value='p';
document.getElementById('f-target').value='192.0.2.1';
document.getElementById('pf-name').value='P';
showProfileForm(); editProfile('p'); loadProfile(); updateNmapPreview(); updateProfilePreview();
await startScan(); await saveProfile();
for (const id of ['f-nmap','f-nmap-custom','pf-nmap']) assert.equal(nodes.has(id),false,id);
// The previews show only what the structured controls build.
assert.doesNotMatch(nodes.get('f-nmap-preview').value,/script|banner/);
assert.doesNotMatch(nodes.get('pf-nmap-preview').value,/script|banner/);
assert.match(nodes.get('f-nmap-preview').value,/-sT/);
""")


def test_a_profile_saved_with_nmap_options_shows_a_notice_and_never_applies_or_resends_them():
    run_js("""
const shown=[];
toast=(...args)=>{shown.push(args)};
loadProfilesFromServer=loadSchedulesFromServer=async()=>{};
const legacy={id:'old',name:'Old',description:'',config:{mode:'normal',speed:3,scan_technique:'-sT',ports:'22,80',
  nmap_flags:'-sV --script http-put --script-args http-put.file=/etc/passwd'}};
profiles={old:legacy,clean:{id:'clean',name:'Clean',config:{nmap_flags:'   '}}};
document.getElementById('f-profile').value='old';
loadProfile();
assert.equal(nodes.get('f-ports').value,'22,80');
assert.equal(nodes.get('f-scantech').value,'-sT');
assert.doesNotMatch(nodes.get('f-nmap-preview').value,/script|passwd/);
assert.deepEqual(shown.map(a=>a[1]),[false]);
assert.match(shown[0][0],/Nmap options from an earlier release/);
assert.match(shown[0][0],/not applied/);
shown.length=0;
editProfile('old');
assert.equal(nodes.get('pf-ports').value,'22,80');
assert.match(shown[0][0],/Saving it removes them and turns off the scheduled scans that use it/);
assert.doesNotMatch(nodes.get('pf-nmap-preview').value,/script|passwd/);
// Saving sends the structured fields and nothing of the old options.
let posted;
fetch=async(url,opts)=>{posted=JSON.parse(opts.body);return {ok:true,json:async()=>({})}};
document.getElementById('pf-id').value='old';
document.getElementById('pf-name').value='Old';
await saveProfile();
assert.equal(/http-put|passwd|--script/.test(JSON.stringify(posted)),false);
assert.equal('nmap_flags' in posted,false);
// A profile with a blank value, or none, raises no notice.
shown.length=0;
document.getElementById('f-profile').value='clean';
loadProfile(); editProfile('clean');
assert.equal(shown.length,0);
// The profile list says which profiles still carry them.
renderProfiles();
const html=nodes.get('profiles-list').innerHTML;
assert.equal((html.match(/Nmap options no longer accepted/g)||[]).length,1);
""")


def test_scan_cards_show_the_command_built_from_the_structured_job_settings():
    run_js("""
scans={a:{id:'a',target:'192.0.2.1',status:'completed',started_at:'2026-10-19T00:00:00Z',host_count:0,port_count:0,vuln_count:0,
  config:{mode:'normal',speed:4,host_timeout:90,scan_technique:'-sU',ports:'53,161',version_intensity:3,os_detection:true,
    nmap_flags:'-sU -p 53,161 --version-intensity 3 -O'}},
  b:{id:'b',target:'192.0.2.2',status:'completed',started_at:'2026-10-18T00:00:00Z',host_count:0,port_count:0,vuln_count:0,
    config:{mode:'normal',speed:3,scan_technique:'',version_intensity:0,nmap_flags:'--script banner'}}};
renderScans();
const cards=nodes.get('tc-scans').children;
const first=cards[0].children[0].innerHTML, second=cards[1].children[0].innerHTML;
assert.match(first,/nmap 192.0.2.1 -sU -sV --host-timeout 90 -Pn -O -T 4 -p 53,161 --version-intensity 3/);
assert.equal((first.match(/-sU/g)||[]).length,1);
assert.match(second,/nmap 192.0.2.2 -sS -sV .* --version-intensity 0/);
assert.doesNotMatch(second,/script|banner/);   // free text in an old job's settings is never shown as a command
""")


def test_profile_source_is_loaded_and_new_profile_resets_it():
    run_js("""
profiles={airgap:{id:'airgap',name:'Airgap',config:{vulnerability_source:'offline'}}};
editProfile('airgap');
assert.equal(nodes.get('pf-vuln-source').value,'offline');
document.getElementById('f-profile').value='airgap';
loadProfile();
assert.equal(nodes.get('f-vuln-source').value,'offline');
showProfileForm();
assert.equal(nodes.get('pf-vuln-source').value,'auto');
assert.equal(nodes.get('pf-timeout').value,'240');
""")


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


def test_polling_is_quick_only_while_a_scan_is_active():
    run_js("""
assert.equal(pollDelay(),10000);
scans={a:{status:'completed'},b:{status:'error'}};
assert.equal(pollDelay(),10000);
scans={a:{status:'completed'},b:{status:'stopping'}};
assert.equal(pollDelay(),1500);
scans={b:{status:'running'}};
assert.equal(pollDelay(),1500);
""")


def test_hidden_tab_skips_its_polls_and_polls_at_once_when_shown_again():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
const timers=[];
setTimeout=(callback,delay)=>{timers.push([callback,delay]);return timers.length};
let requests=0;
fetch=async()=>{requests++;return {ok:true,json:async()=>[]}};
document.hidden=true;
schedulePoll();
assert.equal(timers.at(-1)[1],10000);
await timers.at(-1)[0]();
assert.equal(requests,0);
assert.equal(timers.length,2);                 // it keeps scheduling while hidden
document.hidden=false;
await timers.at(-1)[0]();
assert.equal(requests,2);                      // /api/scans and /api/hosts
assert.equal(timers.length,3);
requests=0;
listeners.visibilitychange.forEach(handler=>handler());
assert.equal(requests,2);
document.hidden=true; requests=0;
listeners.visibilitychange.forEach(handler=>handler());
assert.equal(requests,0);
""")


def test_a_poll_that_finds_a_running_scan_replaces_the_pending_idle_timer():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
const timers=[], cleared=[];
setTimeout=(callback,delay)=>{timers.push([callback,delay]);return timers.length};
clearTimeout=id=>cleared.push(id);
let answer=[];
fetch=async url=>({ok:true,json:async()=>url==='/api/scans'?answer:[]});
schedulePoll();
assert.equal(timers.at(-1)[1],10000);
answer=[{id:'a',target:'192.0.2.1',status:'running'}];
await poll();
assert.equal(timers.at(-1)[1],1500);           // not another 10 s wait after the scan started
assert.ok(cleared.includes(1));                // and the pending idle timer is gone, so only one timer is armed
answer=[{id:'a',target:'192.0.2.1',status:'completed'}];
await poll();
assert.equal(timers.at(-1)[1],10000);          // back to the slow pace once nothing is running
""")


def test_a_started_or_scheduled_scan_shows_up_without_waiting_for_the_idle_poll():
    run_js(EVENT_SOURCE_SCRIPT + """
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
const requested=[];
fetch=async url=>{requested.push(url);return {ok:true,json:async()=>url==='/api/scan/start'?{scan_id:'0123456789abcdef'}:[]}};
document.getElementById('f-target').value='192.0.2.1';
await startScan();
assert.ok(requested.includes('/api/scans'),requested.join());
while(pollBusy) await Promise.resolve();
requested.length=0;
connectSSE();
eventSource.onmessage(message(1,'[*] Scheduled scan fired: Nightly → 192.0.2.0/24'));
assert.ok(requested.includes('/api/scans'),requested.join());
assert.ok(requested.includes('/api/schedules'));
""")


def test_a_schedule_the_scheduler_disabled_is_reloaded_without_waiting_for_a_page_reload():
    run_js(EVENT_SOURCE_SCRIPT + """
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
const requested=[];
fetch=async url=>{requested.push(url);return {ok:true,json:async()=>[]}};
connectSSE();
eventSource.onmessage(message(1,'[!] Scheduled scan disabled (Nightly): Invalid target. Edit the schedule or its profile and enable it again.','error'));
assert.ok(requested.includes('/api/schedules'),requested.join());
assert.ok(!requested.includes('/api/scans'),requested.join());  // only the list of schedules changed
requested.length=0;
eventSource.onmessage(message(2,'[!] Scheduled scan skipped (Nightly): the previous run is still active.','error'));
assert.equal(requested.length,0);
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
assert.match(cards[0].children[0].innerHTML,/running target/);
assert.match(cards[0].children[0].innerHTML,/-T 0/);
assert.match(cards[1].children[0].innerHTML,/completed target/);
""")


SCAN_CARDS_SCRIPT = r"""
const container=document.getElementById('tc-scans');
container.appendChild(document.getElementById('scans-empty'));   // the page puts the empty state first
const job=(id,status,started,extra={})=>({id,target:'target '+id,status,started_at:started,host_count:0,port_count:0,vuln_count:0,...extra});
const cardOf=id=>container.children.find(card=>card.children[0]&&card.children[0].innerHTML.includes('target '+id));
const actionsOf=card=>card.children[1].children[1];
"""


def test_progress_updates_keep_the_scan_card_and_its_buttons_in_place():
    run_js(SCAN_CARDS_SCRIPT + r"""
scans={a:job('a','running','2026-10-19T00:00:00Z',{progress:{revision:1,percent:10}})};
renderScans();
const card=cardOf('a'), actions=actionsOf(card);
assert.match(actions.innerHTML,/data-action="stop-scan" data-id="a"/);
assert.match(card.children[0].innerHTML,/10%/);
actions.innerHTML='the Stop button the operator is pressing';   // stands in for the live button node
scans.a.progress={revision:2,percent:55};
renderScans();
assert.equal(cardOf('a'),card);
assert.equal(actionsOf(card),actions);
assert.equal(actions.innerHTML,'the Stop button the operator is pressing');   // not replaced by the update
assert.match(card.children[0].innerHTML,/55%/);
// The buttons are rewritten only when the set of buttons changes.
scans.a.status='completed'; scans.a.finished_at='2026-10-19T00:10:00Z';
renderScans();
assert.equal(cardOf('a'),card);
assert.doesNotMatch(actions.innerHTML,/stop-scan/);
assert.match(actions.innerHTML,/data-action="print-scan" data-id="a"/);
assert.match(actions.innerHTML,/href="\/api\/scans\/a\/download"/);
assert.equal(card.className,'scan-card completed');
""")


def test_scan_cards_are_reordered_and_removed_without_rebuilding_the_others():
    run_js(SCAN_CARDS_SCRIPT + r"""
scans={a:job('a','running','2026-10-19T00:00:00Z'),b:job('b','completed','2026-10-19T01:00:00Z')};
renderScans();
const [empty,first,second]=container.children;
assert.equal(first,cardOf('a')); assert.equal(second,cardOf('b'));
const a=cardOf('a'), b=cardOf('b');
// a finishes: both are completed now, newest first, so b comes before a and neither is rebuilt.
scans.a.status='completed';
renderScans();
assert.deepEqual([...container.children],[empty,b,a]);
assert.equal(cardOf('a'),a); assert.equal(cardOf('b'),b);
// A new running scan goes to the top; a removed scan's card leaves the page.
scans.c=job('c','running','2026-10-19T02:00:00Z');
delete scans.b;
renderScans();
assert.deepEqual([...container.children],[empty,cardOf('c'),a]);
assert.equal(b.parentNode,null);
scans={};
renderScans();
assert.deepEqual([...container.children],[empty]);
assert.equal(empty.style.display,'flex');
""")


def test_scan_bar_uses_backend_percentage_and_lookup_count():
    run_js(r"""
const markup=scanProgressMarkup({status:'running',progress:{phase:'vulnerabilities',
  detail:'Querying OpenSSH',percent:25,completed:2,total:8,host:'192.0.2.1',targets_total:4,targets_completed:1}});
assert.match(markup,/width:25%/);
assert.match(markup,/aria-valuenow="25"/);
assert.match(markup,/CVE lookups 2\/8/);
assert.match(markup,/1\/4 targets finished/);
assert.doesNotMatch(markup,/indeterminate/);
""")


def test_stopped_and_failed_bars_do_not_become_completed():
    run_js("""
for(const status of ['stopped','error','partial']){
  const markup=scanProgressMarkup({status,progress:{phase:status,percent:37.5}});
  assert.match(markup,/width:37.5%/);
  assert.doesNotMatch(markup,/sc-bar-fill completed/);
  assert.doesNotMatch(markup,/indeterminate/);
}
const completed=scanProgressMarkup({status:'completed',progress:{phase:'completed',percent:100}});
assert.match(completed,/width:100%/);
assert.match(completed,/sc-bar-fill completed/);
""")


def test_unknown_nmap_percentage_is_indeterminate_and_details_are_escaped():
    run_js("""
const markup=scanProgressMarkup({status:'running',progress:{phase:'port_scan',percent:null,
  detail:'<script>bad</script>',host:'192.0.2.1',targets_total:1,targets_completed:0}});
assert.match(markup,/indeterminate/);
assert.match(markup,/Working…/);
assert.doesNotMatch(markup,/aria-valuenow=/);
assert.doesNotMatch(markup,/<script>/);
assert.match(markup,/&lt;script&gt;/);
""")


def test_live_progress_updates_ignore_older_events():
    run_js("""
EventSource=function(){globalThis.eventSource=this};
let rendered=0;
renderScans=()=>{rendered++};
scans={live:{id:'live',status:'running',progress:{revision:4,percent:40}}};
connectSSE();
eventSource.onmessage({data:JSON.stringify({level:'__scan_progress__',scan_id:'live',status:'running',
  finished_at:'',progress:{revision:5,phase:'port_scan',percent:50}})});
eventSource.onmessage({data:JSON.stringify({level:'__scan_progress__',scan_id:'live',status:'running',
  finished_at:'',progress:{revision:3,phase:'port_scan',percent:20}})});
assert.equal(scans.live.progress.percent,50);
assert.equal(rendered,1);
""")


def test_slow_poll_cannot_overwrite_newer_live_completion():
    run_js("""
renderScans=renderHosts=renderVulnTable=updateBadges=()=>{};
EventSource=function(){globalThis.eventSource=this};
const pending=[];
fetch=()=>new Promise(resolve=>pending.push(resolve));
scans={live:{id:'live',status:'running',progress:{revision:4,percent:40}}};
connectSSE();
const polling=poll();
eventSource.onmessage({data:JSON.stringify({level:'__scan_progress__',scan_id:'live',status:'completed',
  finished_at:'2026-10-10T00:00:00Z',progress:{revision:5,phase:'completed',percent:100}})});
pending[0]({ok:true,json:async()=>[{id:'live',status:'running',progress:{revision:4,percent:40}}]});
pending[1]({ok:true,json:async()=>[]});
await polling;
assert.equal(scans.live.progress.percent,100);
assert.equal(scans.live.status,'completed');
assert.equal(scans.live.finished_at,'2026-10-10T00:00:00Z');
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


def test_profile_edit_refreshes_the_schedules_it_disabled():
    run_js("""
const refreshed=[];
loadProfilesFromServer=async()=>refreshed.push('profiles');
loadSchedulesFromServer=async()=>refreshed.push('schedules');
toast=()=>{};
document.getElementById('pf-name').value='Web only';
fetch=async()=>({ok:true});
document.getElementById('pf-id').value='saved';
await saveProfile();  // the server turns off the schedules an edited profile no longer fits
assert.equal(refreshed.join(','),'profiles,schedules');
refreshed.length=0;
document.getElementById('pf-id').value='';
await saveProfile();  // a new profile has no schedules yet
assert.equal(refreshed.join(','),'profiles');
refreshed.length=0;
document.getElementById('pf-id').value='saved';
fetch=async()=>({ok:false,json:async()=>({error:'Invalid scan configuration'})});
await saveProfile();
assert.equal(refreshed.length,0);
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


HOSTILE_SEVERITY_SCRIPT = r"""
// A copied or poisoned vulnerability mirror controls these two fields.
const severity='high"><img src=x onerror=alert(1)>', cvss='9.8"><svg onload=alert(2)>';
const hostile={cve:'CVE-2020-0001',severity,cvss,description:'d',port:80,keyword:'k'};
const odd=[{cve:'CVE-2020-0002',severity:null,cvss:0,description:'d'},{cve:'CVE-2020-0003',severity:'Critical',cvss:9.8,description:'d'}];
const markup=/<img src=x|<svg onload/;  // the injected tags, not the page's own logo and icons
function reportHtml(){let html='';window.open=()=>({document:{write(value){html=value},close(){}},close(){}});return ()=>html}
"""


def test_detail_panel_and_vulnerability_table_never_render_severity_or_cvss_as_markup():
    run_js(HOSTILE_SEVERITY_SCRIPT + r"""
renderDetail({ip:'192.0.2.1',ports:[],vulns:[hostile,...odd],scan_status:'completed'});
const detail=nodes.get('det-content').innerHTML;
assert.doesNotMatch(detail,markup);
assert.match(detail,/<div class="vr unknown"><div class="vc"><span class="sev unknown">UNKNOWN<\/span>CVE-2020-0001<span class="cvb unknown">9.8&quot;&gt;&lt;svg onload=alert\(2\)&gt;<\/span>/);
assert.match(detail,/<div class="vr critical"><div class="vc"><span class="sev critical">CRITICAL<\/span>CVE-2020-0003<span class="cvb critical">9.8<\/span>/);
hosts={ip:{ip:'192.0.2.1',scan_id:'s',ports:[],vulns:[hostile,...odd]}};
renderVulnTable();
const table=nodes.get('vtb').innerHTML;
assert.doesNotMatch(table,markup);
assert.match(table,/<span class="sev unknown">UNKNOWN<\/span>/);
assert.match(table,/<span class="sev critical">CRITICAL<\/span><\/td><td style="font-family:var\(--mono\);color:var\(--red\)">9.8</);
assert.match(table,/CVE-2020-0002<\/td><td><span class="sev unknown">UNKNOWN<\/span><\/td><td style="font-family:var\(--mono\);color:var\(--text2\)">—</);
""")


def test_severity_filters_match_the_displayed_normalised_severity():
    run_js(HOSTILE_SEVERITY_SCRIPT + r"""
hosts={ip:{ip:'192.0.2.1',scan_id:'s',ports:[],vulns:[hostile,...odd]}};
document.getElementById('vuln-sev').value='unknown';
renderVulnTable();
const unknown=nodes.get('vtb').innerHTML;
assert.equal((unknown.match(/<tr>/g)||[]).length,2);
assert.doesNotMatch(unknown,/CVE-2020-0003/);
document.getElementById('vuln-sev').value='critical';
renderVulnTable();
assert.match(nodes.get('vtb').innerHTML,/CVE-2020-0003/);
assert.doesNotMatch(nodes.get('vtb').innerHTML,/CVE-2020-0001|CVE-2020-0002/);
hosts={ip:{ip:'192.0.2.1',scan_status:'completed',ports:[],vulns:[odd[1]]}};
renderHosts();
assert.match(nodes.get('hosts-grid').children[0].innerHTML,/hc-badge vulns/);
""")


@pytest.mark.parametrize("report", ["printHost('192.0.2.1')", "printAllVulns()", "printAllHosts()"])
def test_exported_reports_never_render_severity_or_cvss_as_markup(report):
    run_js(HOSTILE_SEVERITY_SCRIPT + f"const report={json.dumps(report)};" + r"""
hosts={'192.0.2.1':{ip:'192.0.2.1',scan_id:'s',ports:[],vulns:[hostile,...odd]}};
const html=reportHtml();
eval(report);
assert.doesNotMatch(html(),markup);
assert.match(html(),/<td class="sev-unknown">UNKNOWN<\/td>/);
assert.match(html(),/<td class="sev-critical">CRITICAL<\/td>/);
assert.match(html(),/9.8&quot;&gt;&lt;svg onload=alert\(2\)&gt;/);
""")


def test_scan_report_never_renders_severity_or_cvss_as_markup():
    run_js(HOSTILE_SEVERITY_SCRIPT + r"""
scans={s:{id:'s',target:'192.0.2.1',status:'completed',host_count:1,started_at:'2026-10-19T00:00:00Z'}};
const html=reportHtml();
fetch=async()=>({ok:true,json:async()=>({hosts:[{ip:'192.0.2.1',ports:[],vulns:[hostile,...odd]}]})});
await printScan('s');
assert.doesNotMatch(html(),markup);
assert.match(html(),/<td class="sev-unknown">UNKNOWN<\/td>/);
assert.match(html(),/<td class="sev-critical">CRITICAL<\/td>/);
""")


STARTUP_SCRIPT = r"""
// A dashboard whose startup requests answer from `routes`; a route set to a status code answers with it.
const stored={nist_api_key:'nvd-key',email:{enabled:true,smtp_host:'smtp.example.test',password:'••••••••'},
  webhook:{enabled:true,url:'https://example.invalid/hook'}};
const routes={'/api/scans':[{id:'0123456789abcdef',target:'192.0.2.1',status:'completed',started_at:'2026-10-19T00:00:00Z'}],
  '/api/hosts':[{ip:'192.0.2.1',scan_id:'0123456789abcdef',ports:[],vulns:[]}],'/api/log':[],'/api/version':{version:'2.7.0'},
  '/api/settings':stored,'/api/vulnerability-database':{ready:false,update:{}},
  '/api/profiles':[{id:'p1',name:'Quick',config:{}}],'/api/schedules':[]};
const puts=[];
fetch=async(url,opts)=>{
  if(opts&&opts.method==='PUT'){puts.push([url,JSON.parse(opts.body)]);return {ok:true,json:async()=>({ok:true})}}
  const answer=routes[url];
  if(typeof answer==='number') return {ok:false,status:answer,json:async()=>({error:'Unavailable'})};
  return {ok:true,status:200,json:async()=>JSON.parse(JSON.stringify(answer))};
};
"""


def test_failed_settings_request_leaves_saves_disabled_instead_of_blank_forms_that_erase_stored_values():
    run_js(STARTUP_SCRIPT + r"""
routes['/api/settings']=500;
await initDashboard();
for(const id of ['s-nist-save','s-email-save','s-webhook-save']) assert.equal(nodes.get(id).disabled,true,id);
assert.equal(nodes.get('settings-unavailable').hidden,false);
await saveWebhookSettings(); await saveEmailSettings(); await saveNistKey();
assert.deepEqual(puts,[]);
// The rest of the page still loaded, and says what did not.
assert.equal(Object.keys(scans).length,1);
assert.equal(Object.keys(profiles).length,1);
assert.equal(nodes.get('app-version').textContent,'v2.7.0');
assert.ok(nodes.get('term').children.some(line=>line.innerHTML.includes('Some dashboard data could not be loaded. Refresh to retry.')));
""")


def test_successful_settings_load_enables_saves_and_fills_the_forms():
    run_js(STARTUP_SCRIPT + r"""
await initDashboard();
for(const id of ['s-nist-save','s-email-save','s-webhook-save']) assert.equal(nodes.get(id).disabled,false,id);
assert.equal(nodes.get('settings-unavailable').hidden,true);
assert.equal(nodes.get('s-webhook-url').value,'https://example.invalid/hook');
assert.equal(nodes.get('s-nist-key').value,'nvd-key');
await saveWebhookSettings();
assert.deepEqual(puts.map(([url,body])=>[url,body.webhook.url]),[['/api/settings','https://example.invalid/hook']]);
assert.equal(document.getElementById('term').children.length,0);
""")


@pytest.mark.parametrize("route", ["/api/scans", "/api/hosts", "/api/log", "/api/vulnerability-database", "/api/profiles", "/api/schedules"])
def test_one_failed_startup_request_does_not_stop_settings_or_the_other_sections_loading(route):
    run_js(f"const failing={json.dumps(route)};" + STARTUP_SCRIPT + r"""
routes[failing]=503;
await initDashboard();
assert.equal(nodes.get('s-webhook-url').value,'https://example.invalid/hook');
assert.equal(nodes.get('s-webhook-save').disabled,false);
assert.equal(nodes.get('s-nist-save').disabled,false);
assert.equal(nodes.get('settings-unavailable').hidden,true);
assert.equal(Object.keys(profiles).length,failing==='/api/profiles'?0:1);
assert.equal(Object.keys(scans).length,failing==='/api/scans'?0:1);
assert.equal(Object.keys(hosts).length,failing==='/api/hosts'?0:1);
assert.ok(nodes.get('term').children.some(line=>line.innerHTML.includes('Refresh to retry.')));
""")


def test_a_render_failure_at_startup_does_not_stop_the_event_stream_or_polling():
    run_js("""
const started=[];
initDashboard=async()=>{throw new TypeError('a host without a field')};
connectSSE=()=>started.push('stream');
schedulePoll=()=>started.push('poll');
setInterval=()=>started.push('database status');
await startDashboard();
assert.deepEqual(started,['stream','poll','database status']);
assert.ok(nodes.get('term').children.some(line=>line.innerHTML.includes('Refresh to retry.')));
""")


EVENT_SOURCE_SCRIPT = r"""
const urls=[];
EventSource=function(url){urls.push(url);this.readyState=0;this.close=()=>{this.readyState=2};globalThis.eventSource=this};
EventSource.CLOSED=2;
const terminal=()=>document.getElementById('term').children.map(line=>line.innerHTML);
const message=(id,text,level='info')=>({data:JSON.stringify({id,scan_id:'',level,msg:text,ts:'00:00:00'})});
"""


def test_stream_resumes_after_the_newest_entry_of_the_history_the_page_loaded():
    run_js(STARTUP_SCRIPT + EVENT_SOURCE_SCRIPT + r"""
routes['/api/log']=[{id:101,scan_id:'',level:'info',msg:'first',ts:'00:00:01'},
  {id:102,scan_id:'',level:'__scan_done__',msg:'',ts:''}];
await initDashboard();
assert.equal(terminal().length,1);          // the internal event is not a terminal line
connectSSE();
assert.deepEqual(urls,['/api/events?after=102']);
// A line logged between the history request and the stream opening arrives once, through the stream.
eventSource.onmessage(message(103,'logged in the gap'));
assert.equal(terminal().length,2);
assert.match(terminal()[1],/logged in the gap/);
// The page re-opening the stream itself (after an HTTP error) resumes after the last line it showed.
connectSSE();
assert.equal(urls.at(-1),'/api/events?after=103');
// Progress events have no id and do not move the position.
eventSource.onmessage({data:JSON.stringify({level:'__scan_progress__',scan_id:'x',status:'running',progress:{revision:1}})});
connectSSE();
assert.equal(urls.at(-1),'/api/events?after=103');
""")


def test_stream_replays_everything_retained_when_the_history_could_not_be_loaded():
    run_js(STARTUP_SCRIPT + EVENT_SOURCE_SCRIPT + r"""
routes['/api/log']=500;
await initDashboard();
connectSSE();
assert.deepEqual(urls,['/api/events?after=0']);
eventSource.onmessage(message(7,'replayed from the server'));
assert.match(terminal().at(-1),/replayed from the server/);
""")


def test_stream_that_the_browser_gave_up_on_is_reopened_with_a_growing_pause():
    run_js(EVENT_SOURCE_SCRIPT + r"""
const timers=[];
setTimeout=(callback,delay)=>{timers.push([callback,delay]);return timers.length};
connectSSE();
const first=eventSource;
first.readyState=0; first.onerror();                      // the browser is retrying by itself
assert.equal(timers.length,0);
first.readyState=2; first.onerror();                      // an HTTP error closed it for good
assert.deepEqual(timers.map(([,delay])=>delay),[1000]);
timers[0][0]();
assert.equal(urls.length,2);
assert.notEqual(eventSource,first);
eventSource.readyState=2; eventSource.onerror();
assert.equal(timers.at(-1)[1],2000);
for(let i=0;i<8;i++){ timers.at(-1)[0](); eventSource.readyState=2; eventSource.onerror(); }
assert.equal(timers.at(-1)[1],30000);                      // never longer than that
timers.at(-1)[0]();
eventSource.onopen();                                      // a working connection resets the pause
eventSource.readyState=2; eventSource.onerror();
assert.equal(timers.at(-1)[1],1000);
// An error from a connection that was already replaced is ignored.
const replaced=eventSource; connectSSE(); const before=timers.length;
replaced.readyState=2; replaced.onerror();
assert.equal(timers.length,before);
""")


def test_settings_error_response_is_rejected_without_touching_the_forms():
    run_js(STARTUP_SCRIPT + r"""
document.getElementById('s-webhook-url').value='typed by the operator';
routes['/api/settings']=500;
await assert.rejects(loadSettingsIntoForm());
assert.equal(nodes.get('s-webhook-url').value,'typed by the operator');
""")


def test_vulnerability_tab_counts_categories_and_filters_by_one():
    run_js(r"""
const sel=id=>document.getElementById(id);
const row=(cve,severity,cvss,categories)=>({cve,severity,cvss,description:'Some flaw',keyword:'kw',port:80,categories});
hosts={'192.0.2.1':{ip:'192.0.2.1',scan_id:'s1',vulns:[
  row('CVE-1','critical',9.8,['rce','memory_corruption']),
  row('CVE-2','high',7.5,['dos']),
  row('CVE-3','medium',5,['dos','info_disclosure']),
  row('CVE-4','low',3,undefined),                      // saved before categories existed: only under All
  row('CVE-5','high',8,['<img src=x>','nope','xss'])]}};  // anything but the fixed words is ignored
const bar=sel('vuln-cats'), table=sel('vtb');
const chips=()=>[...bar.innerHTML.matchAll(/data-cat="([^"]*)" aria-pressed="(\w+)">([^<]*)</g)]
  .map(m=>`${m[1]}|${m[2]==='true'?'*':''}${m[3]}`).join(';');
const shown=()=>(table.innerHTML.match(/CVE-\d/g)||[]).join(',');
renderVulnTable();
assert.equal(bar.hidden,false);
assert.equal(chips(),'|*All (5);rce|Remote code execution (1);xss|Cross-site scripting (1);info_disclosure|Information disclosure (1);'
  +'dos|Denial of service (2);memory_corruption|Memory corruption (1)');
assert.match(bar.innerHTML,/more than one category/);
assert.doesNotMatch(bar.innerHTML+table.innerHTML,/<img|nope/);
assert.equal(shown(),'CVE-1,CVE-5,CVE-2,CVE-3,CVE-4');

const focused=[];
document.querySelector=selector=>({focus(){focused.push(selector)}});
const click=cat=>pickVulnCategory({target:{closest:()=>({dataset:{cat}})}});
click('dos');                                           // one category at a time
assert.equal(shown(),'CVE-2,CVE-3');
assert.equal(sel('vuln-cat-status').textContent,'Denial of service: showing 2 of 5 vulnerabilities');   // announced politely
assert.match(chips(),/dos\|\*Denial of service \(2\)/);
assert.deepEqual(focused,['#vuln-cats [data-cat="dos"]']);   // the clicked chip keeps the keyboard focus
assert.match(table.innerHTML,/<span class="cat">Denial of service<\/span>/);

sel('vuln-sev').value='high';                            // the counts follow the other filters
renderVulnTable();
assert.equal(chips(),'|All (2);xss|Cross-site scripting (1);dos|*Denial of service (1)');
assert.equal(shown(),'CVE-2');
sel('vuln-sev').value='critical';                        // a category without rows ends its filter
renderVulnTable();
assert.equal(chips(),'|*All (1);rce|Remote code execution (1);memory_corruption|Memory corruption (1)');
assert.equal(shown(),'CVE-1');
sel('vuln-sev').value='';
click('xss'); click('xss');                              // the same chip again clears it
assert.equal(shown(),'CVE-1,CVE-5,CVE-2,CVE-3,CVE-4');
assert.equal(sel('vuln-cat-status').textContent,'Showing all 5 vulnerabilities');
click('rce'); click('');                                 // and so does All
assert.equal(shown().split(',').length,5);

click('dos');
let report='';
window.open=()=>({document:{write(html){report=html},close(){}},print(){}});
printAllVulns();
assert.match(report,/<th>Category<\/th>/);
assert.match(report,/Category: Denial of service/);
assert.match(report,/Vulnerability categories:<\/strong> Information disclosure: 1 &nbsp;\|&nbsp; Denial of service: 2/);
assert.equal((report.match(/<td style="white-space:nowrap;">CVE-/g)||[]).length,2);

hosts={};
renderVulnTable();
assert.equal(bar.hidden,true);
assert.equal(bar.innerHTML,'');
""")
