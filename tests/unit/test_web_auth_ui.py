# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Execute login/account browser logic and shared request protection in Node."""

import shutil
import subprocess
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[2] / "autopwn_suite" / "web_ui_static"
NODE = shutil.which("node")
pytestmark = [pytest.mark.unit, pytest.mark.skipif(not NODE, reason="Node.js is unavailable")]


def run_js(file, test, setup=""):
    harness = r"""
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path'),assert=require('node:assert/strict');
const nodes=new Map(),handlers={},calls=[],redirects=[];
const document={getElementById(id){if(!nodes.has(id))nodes.set(id,{value:'',textContent:'',disabled:false,
  addEventListener(name,fn){handlers[id+':'+name]=fn}});return nodes.get(id)}};
const html=fs.readFileSync(path.join(path.dirname(process.argv[1]),process.argv[1].endsWith('login.js')?'login.html':'index.html'),'utf8');
for(const match of html.matchAll(/\bid="([^"]+)"/g))document.getElementById(match[1]);
function reply(status,data){return {status,ok:status>=200&&status<300,json:async()=>data}};
let responseHandler=async()=>reply(200,{username:'admin',csrf_token:'a'.repeat(43)});
const nativeFetch=async(input,options={})=>{calls.push([input,options]);return responseHandler(input,options)};
const context=vm.createContext({document,URL,Headers,Request,console,assert,fetch:nativeFetch,nodes,handlers,calls,redirects,reply,
 location:{href:'http://localhost/',origin:'http://localhost',replace:path=>redirects.push(path)},
 setTimeout,clearTimeout});context.window=context;
context.setResponse=handler=>{responseHandler=handler};
context.flush=async()=>{for(let i=0;i<12;i++)await new Promise(resolve=>setImmediate(resolve))};
vm.runInContext(process.argv[2],context);
vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{await context.flush();await vm.runInContext('(async()=>{'+process.argv[3]+'})()',context)})()
 .catch(error=>{console.error(error);process.exitCode=1});
"""
    result = subprocess.run([NODE, "-e", harness, str(ROOT / file), setup, test], text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_shared_fetch_gates_all_clients_preserves_headers_and_never_leaks_csrf_to_other_origins():
    run_js("auth.js", r"""
await dashboardAuth.ready;
await fetch('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:'{}'});
assert.equal(calls.at(-1)[1].headers.get('X-CSRF-Token'),'a'.repeat(43));
assert.equal(calls.at(-1)[1].headers.get('Content-Type'),'application/json');
await fetch(new Request('http://localhost/api/profiles/one',{method:'DELETE',headers:{'X-Test':'keep'}}));
assert.equal(calls.at(-1)[1].headers.get('X-CSRF-Token'),'a'.repeat(43));
assert.equal(calls.at(-1)[1].headers.get('X-Test'),'keep');
await fetch('/api/scans');assert.equal(calls.at(-1)[1].headers.has('X-CSRF-Token'),false);
await fetch('https://external.invalid/');assert.equal(calls.at(-1)[1].headers,undefined);
assert.equal(nodes.get('account-username').value,'admin');
""")


def test_account_change_renews_csrf_clears_passwords_and_updates_username_as_text():
    run_js("auth.js", r"""
await dashboardAuth.ready;
nodes.get('account-username').value='new-admin';nodes.get('account-current-password').value='old-secret';
nodes.get('account-password').value=nodes.get('account-confirm-password').value='new-strong-test-password';
setResponse(async()=>reply(200,{username:'new-admin',csrf_token:'b'.repeat(43)}));
await handlers['account-form:submit']({preventDefault(){}});
const body=JSON.parse(calls.at(-1)[1].body);
assert.equal(body.current_password,'old-secret');assert.equal(body.new_password,'new-strong-test-password');
assert.equal(nodes.get('account-current-password').value,'');assert.equal(nodes.get('account-password').value,'');
assert.equal(nodes.get('account-confirm-password').value,'');assert.equal(nodes.get('auth-username').textContent,'new-admin');
await fetch('/api/scan/stop',{method:'POST'});assert.equal(calls.at(-1)[1].headers.get('X-CSRF-Token'),'b'.repeat(43));
assert.match(nodes.get('account-message').textContent,/updated/);assert.equal(redirects.length,0);
""")


def test_account_errors_remain_visible_and_logout_uses_csrf():
    run_js("auth.js", r"""
await dashboardAuth.ready;
nodes.get('account-password').value='one';nodes.get('account-confirm-password').value='two';
const before=calls.length;await handlers['account-form:submit']({preventDefault(){}});
assert.equal(calls.length,before);assert.match(nodes.get('account-message').textContent,/do not match/);
nodes.get('account-password').value=nodes.get('account-confirm-password').value='';
setResponse(async()=>reply(403,{error:'Current password is incorrect.'}));
await handlers['account-form:submit']({preventDefault(){}});
assert.match(nodes.get('account-message').textContent,/incorrect/);assert.equal(redirects.length,0);
setResponse(async()=>reply(200,{ok:true}));await handlers['auth-logout:click']();
assert.equal(calls.at(-1)[0],'/api/auth/logout');assert.equal(calls.at(-1)[1].headers.get('X-CSRF-Token'),'a'.repeat(43));
assert.equal(redirects.join(','),'/login');
""")


def test_expired_bootstrap_redirects_and_prevents_dashboard_requests():
    run_js("auth.js", r"""
await assert.rejects(dashboardAuth.ready,/Sign in/);
await assert.rejects(fetch('/api/settings'),/Sign in/);
assert.equal(calls.length,1);assert.equal(redirects.join(','),'/login');
""", "setResponse(async()=>reply(401,{error:'Authentication required.'}));")


def test_login_success_uses_challenge_and_keeps_password_out_of_navigation():
    run_js("login.js", r"""
assert.equal(nodes.get('login-submit').disabled,false);
document.getElementById('login-username').value='admin';document.getElementById('login-password').value='test-secret';
setResponse(async()=>reply(200,{username:'admin'}));
await handlers['login-form:submit']({preventDefault(){}});
assert.equal(calls.at(-1)[0],'/api/auth/login');assert.equal(calls.at(-1)[1].headers['X-CSRF-Token'],'a'.repeat(43));
assert.equal(JSON.parse(calls.at(-1)[1].body).password,'test-secret');
assert.equal(nodes.get('login-password').value,'');assert.equal(redirects.join(','),'/');
""")


def test_login_failure_is_text_and_expired_challenge_is_refreshed():
    run_js("login.js", r"""
document.getElementById('login-username').value='admin';document.getElementById('login-password').value='incorrect';
setResponse(async()=>reply(401,{error:'<img src=x> Incorrect password'}));
await handlers['login-form:submit']({preventDefault(){}});
assert.equal(nodes.get('login-message').textContent,'<img src=x> Incorrect password');assert.equal(redirects.length,0);
setResponse(async(input,options)=>options.method==='POST'?reply(403,{error:'Refresh required'}):reply(200,{csrf_token:'c'.repeat(43)}));
await handlers['login-form:submit']({preventDefault(){}});
assert.equal(calls.at(-1)[1].method,undefined);assert.equal(nodes.get('login-submit').disabled,false);
setResponse(async()=>reply(200,{}));await handlers['login-form:submit']({preventDefault(){}});
assert.equal(calls.at(-1)[1].headers['X-CSRF-Token'],'c'.repeat(43));
""")


def test_auth_script_loads_before_both_dashboard_clients_and_forms_have_password_autocomplete():
    page = BeautifulSoup((ROOT / "index.html").read_text(encoding="utf-8"), "html.parser")
    scripts = [item["src"] for item in page.find_all("script", src=True)]
    assert scripts.index("/auth.js") < scripts.index("/app.js")
    assert scripts.index("/auth.js") < scripts.index("/web_security.js")
    assert page.select_one("#account-current-password")["autocomplete"] == "current-password"
    assert page.select_one("#account-password")["autocomplete"] == "new-password"
    login = BeautifulSoup((ROOT / "login.html").read_text(encoding="utf-8"), "html.parser")
    assert login.select_one("#login-password")["type"] == "password"
    assert login.select_one("#login-password")["autocomplete"] == "current-password"
