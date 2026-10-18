// SPDX-License-Identifier: Apache-2.0
// Copyright 2022-2026 Kaan Gültekin
// JavaScript style and correctness rules for the dashboard (see docs/CODING_STANDARDS.md).
// Rules are listed explicitly so the config needs no packages beyond ESLint itself.
const browser = Object.fromEntries([
  "window", "document", "fetch", "console", "URL", "URLSearchParams", "Headers", "Request", "Response", "FormData",
  "Blob", "File", "FileReader", "EventSource", "AbortController", "TextEncoder", "TextDecoder", "navigator", "location",
  "history", "localStorage", "sessionStorage", "setTimeout", "clearTimeout", "setInterval", "clearInterval",
  "requestAnimationFrame", "cancelAnimationFrame", "confirm", "alert", "prompt", "performance", "crypto", "atob", "btoa",
  "Event", "CustomEvent", "MutationObserver", "ResizeObserver", "IntersectionObserver", "HTMLElement", "Node", "Element",
  "getComputedStyle", "matchMedia", "structuredClone", "queueMicrotask", "Intl", "DOMParser", "XMLSerializer",
].map(name => [name, "readonly"]));

// web_security.js runs after app.js and shares its script-scope helpers.
const shared = {toast: "readonly", poll: "readonly"};

export default [{
  files: ["autopwn_suite/web_ui_static/**/*.js"],
  languageOptions: {ecmaVersion: 2022, sourceType: "script", globals: browser},
  linterOptions: {reportUnusedDisableDirectives: "error"},
  rules: {
    "no-undef": "error", // vars "local": top-level functions are globals invoked from inline HTML handlers.
    "no-unused-vars": ["error", {vars: "local", args: "none", caughtErrors: "none"}],
    "no-redeclare": "error", "no-dupe-keys": "error", "no-dupe-args": "error", "no-dupe-else-if": "error",
    "no-duplicate-case": "error", "no-unreachable": "error", "no-unsafe-finally": "error", "no-unsafe-negation": "error",
    "no-self-assign": "error", "no-sparse-arrays": "error", "no-empty-pattern": "error", "no-fallthrough": "error",
    "no-func-assign": "error", "no-import-assign": "error", "no-inner-declarations": "error", "no-loss-of-precision": "error",
    "no-shadow-restricted-names": "error", "no-useless-catch": "error", "no-with": "error", "use-isnan": "error",
    "valid-typeof": "error", "no-eval": "error", "no-implied-eval": "error", "no-new-func": "error", "no-script-url": "error",
    "eqeqeq": ["error", "always", {null: "ignore"}], "no-var": "error", "prefer-const": ["error", {destructuring: "all"}],
    "no-const-assign": "error", "no-constant-condition": ["error", {checkLoops: false}], "no-cond-assign": ["error", "except-parens"],
    "no-global-assign": "error", "no-delete-var": "error", "no-octal": "error", "require-yield": "error",
  },
}, {
  files: ["autopwn_suite/web_ui_static/web_security.js"],
  languageOptions: {globals: shared},
}];
