// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-2026 Kaan Gültekin
'use strict';
(() => {
  const form = document.getElementById('login-form');
  const message = document.getElementById('login-message');
  const button = document.getElementById('login-submit');
  let csrf = '';
  async function prepare() {
    button.disabled = true;
    csrf = '';
    try {
      const response = await fetch('/api/auth/login', {credentials:'same-origin', cache:'no-store'});
      const result = await response.json();
      if(!response.ok) throw new Error(result.error || 'Sign-in is unavailable.');
      csrf = result.csrf_token;
      button.disabled = false;
    } catch(error) {
      message.textContent = error.message;
    }
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if(button.disabled) return;
    button.disabled = true;
    message.textContent = '';
    try {
      const response = await fetch('/api/auth/login', {
        method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},
        body:JSON.stringify({username:document.getElementById('login-username').value,
          password:document.getElementById('login-password').value})
      });
      const result = await response.json();
      if(!response.ok) {
        if(response.status === 403) await prepare();
        throw new Error(result.error || 'Could not sign in.');
      }
      document.getElementById('login-password').value = '';
      window.location.replace('/');
    } catch(error) {
      message.textContent = error.message;
      button.disabled = !csrf;
    }
  });
  prepare();
})();
