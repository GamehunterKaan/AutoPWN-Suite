// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-2026 Kaan Gültekin
'use strict';
(() => {
  // The sign-in page is public, so it carries its own small table instead of the dashboard dictionary (i18n.js,
  // which stays behind sign-in). The keys and texts match that dictionary; a test checks it.
  const STORAGE_KEY = 'apwn_lang';
  const TEXT = {
    en: {
      'login.heading': 'Sign in',
      'login.subtitle': 'Use your dashboard account to manage scans.',
      'login.password_label': 'Password',
      'login.submit': 'Sign in',
      'login.hint': 'First launch? Your account details are shown in the server terminal.',
      'login.title': 'Sign in · AutoPWN Suite',
      'settings.username': 'Username',
      'settings.language': 'Language',
      'lang.english': 'English',
      'lang.turkish': 'Türkçe',
    },
    tr: {
      'login.heading': 'Giriş yap',
      'login.subtitle': 'Taramaları yönetmek için panel hesabınızı kullanın.',
      'login.password_label': 'Şifre',
      'login.submit': 'Giriş yap',
      'login.hint': 'İlk kez mi başlatıyorsunuz? Hesap bilgileriniz sunucu terminalinde gösterilir.',
      'login.title': 'Giriş yap · AutoPWN Suite',
      'settings.username': 'Kullanıcı adı',
      'settings.language': 'Dil',
      'lang.english': 'English',
      'lang.turkish': 'Türkçe',
    },
  };
  function detectLang() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'en' || stored === 'tr') return stored;
    } catch (_) { /* localStorage may be unavailable */ }
    return (navigator.language || '').toLowerCase().startsWith('tr') ? 'tr' : 'en';
  }
  function applyLang(lang) {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const text = TEXT[lang][el.getAttribute('data-i18n')];
      if (text) el.textContent = text;
    });
  }
  const langSelect = document.getElementById('login-lang');
  const lang = detectLang();
  langSelect.value = lang;
  applyLang(lang);
  langSelect.addEventListener('change', () => {
    const chosen = langSelect.value === 'tr' ? 'tr' : 'en';
    try { localStorage.setItem(STORAGE_KEY, chosen); } catch (_) { /* localStorage may be unavailable */ }
    applyLang(chosen);
  });
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
