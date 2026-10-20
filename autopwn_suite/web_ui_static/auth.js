// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-2026 Kaan Gültekin
'use strict';
(() => {
  const nativeFetch = window.fetch.bind(window);
  let csrf = '';
  function expired() { window.location.replace('/login'); }
  function displayAccount(username) {
    document.getElementById('account-username').value = username;
    document.getElementById('auth-username').textContent = username;
  }
  const ready = (async () => {
    const response = await nativeFetch('/api/auth/session', {credentials:'same-origin', cache:'no-store'});
    if(response.status === 401) { expired(); throw new Error('Sign in to continue.'); }
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Account is unavailable.');
    csrf = result.csrf_token;
    displayAccount(result.username);
  })();
  // All dashboard fetch calls, including web-security controls, share this gate.
  window.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, window.location.href);
    if(url.origin !== window.location.origin) return nativeFetch(input, options);
    await ready;
    const headers = new Headers(options.headers || (typeof Request !== 'undefined' && input instanceof Request ? input.headers : undefined));
    const method = (options.method || input.method || 'GET').toUpperCase();
    headers.set('X-App-Language', window.i18n.getLang());
    if(!['GET','HEAD','OPTIONS'].includes(method)) headers.set('X-CSRF-Token', csrf);
    const response = await nativeFetch(input, {...options, headers, credentials:'same-origin'});
    if(response.status === 401) expired();
    return response;
  };
  document.getElementById('auth-logout').addEventListener('click', async () => {
    try {
      const response = await fetch('/api/auth/logout', {method:'POST'});
      if(response.ok || response.status === 401) expired();
    } catch(error) { window.toast?.(error.message, false); }
  });
  document.getElementById('account-form').addEventListener('submit', async event => {
    event.preventDefault();
    const message = document.getElementById('account-message');
    const button = document.getElementById('account-save');
    const current = document.getElementById('account-current-password');
    const password = document.getElementById('account-password');
    const confirm = document.getElementById('account-confirm-password');
    message.textContent = '';
    if(password.value !== confirm.value) { message.textContent = 'New passwords do not match.'; return; }
    button.disabled = true;
    try {
      const response = await fetch('/api/auth/account', {method:'PUT', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:document.getElementById('account-username').value,
          current_password:current.value, new_password:password.value})});
      const result = await response.json();
      if(!response.ok) throw new Error(result.error || 'Account could not be updated.');
      csrf = result.csrf_token;
      displayAccount(result.username);
      current.value = ''; password.value = ''; confirm.value = '';
      message.textContent = 'Account updated. Other sessions have been signed out.';
    } catch(error) { message.textContent = error.message; }
    finally { button.disabled = false; }
  });
  window.dashboardAuth = {ready};
  ready.catch(error => { document.getElementById('account-message').textContent = error.message; });
})();
