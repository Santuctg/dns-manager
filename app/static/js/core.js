// DNS Manager console core: API, i18n, modal, side panel, toasts, shell chrome.

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

let dictionary = {};
let serverPending = { count: 0, domains: [] };
let pendingApplyInFlight = false;

export function bootDictionary() {
  const node = document.getElementById('i18n-data');
  if (!node) return;
  try {
    dictionary = JSON.parse(node.textContent || '{}') || {};
  } catch {
    dictionary = {};
  }
}

export function t(key, params = {}) {
  let text = dictionary[key];
  if (text === undefined) text = key;
  return String(text).replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match
  );
}

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  }[char]));
}

export function icon(name, className = 'icon') {
  return `<svg class="${className}" aria-hidden="true" focusable="false"><use href="/static/icons.svg#${name}"></use></svg>`;
}

export function cookie(name) {
  const found = document.cookie.split('; ').find((entry) => entry.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.split('=').slice(1).join('=')) : '';
}

export function setCookie(name, value) {
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${COOKIE_MAX_AGE}; SameSite=Lax`;
}

// ------------------------------------------------------------------ API
async function errorDetail(response) {
  try {
    const body = await response.json();
    if (typeof body.detail === 'string') return body.detail;
    if (body.detail) return JSON.stringify(body.detail);
    if (body.message) return String(body.message);
    return `${response.status} ${response.statusText}`;
  } catch {
    return `${response.status} ${response.statusText}`;
  }
}

const inflightGets = new Map();

export async function api(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  if (method !== 'GET' || options.signal || options.dedupe === false) {
    return request(url, { ...options, method });
  }
  // The shell and a page often ask for the same resource at the same time
  // (status, pending changes). Share the in-flight GET instead of sending it
  // twice; resolved responses are not cached.
  const pending = inflightGets.get(url);
  if (pending) return pending;
  const promise = request(url, { ...options, method }).finally(() => inflightGets.delete(url));
  inflightGets.set(url, promise);
  return promise;
}

async function request(url, options) {
  const method = options.method;
  const headers = new Headers(options.headers || {});
  const init = { ...options, method, headers, credentials: 'same-origin' };
  delete init.dedupe;
  if (options.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    init.body = JSON.stringify(options.json);
    delete init.json;
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const token = cookie('dns_manager_csrf');
    if (!token) throw new Error(t('error.csrf_missing'));
    headers.set('X-CSRF-Token', token);
  }
  const response = await fetch(url, init);
  if (response.status === 401) {
    location.assign(`/login?next=${encodeURIComponent(location.pathname)}`);
    throw new Error(t('error.auth_required'));
  }
  if (!response.ok) {
    const error = new Error(await errorDetail(response));
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) return null;
  const type = response.headers.get('content-type') || '';
  if (!type.includes('application/json')) return response.text();
  return response.json();
}

// ------------------------------------------------------------------ formatting
export function fmtBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value)) return '—';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

export function fmtDate(value, fallback = '—') {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? fallback : date.toLocaleString();
}

export function fmtTime(value, fallback = '—') {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? fallback : date.toLocaleTimeString();
}

export function daysLeft(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return Math.ceil((date.getTime() - Date.now()) / 86400000);
}

export function fmtPercent(value) {
  return Number.isFinite(Number(value)) ? `${Number(value).toFixed(1)}%` : '—';
}

export function fmtDuration(seconds) {
  const total = Number(seconds);
  if (!Number.isFinite(total)) return '—';
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

const GOOD = new Set(['UP', 'ACTIVE', 'READY', 'OK', 'ENABLED', 'SUCCESS', 'SAFE', 'ISSUED', 'TEST_SUCCESS']);
const BAD = new Set(['DOWN', 'HTTP_ERROR', 'TLS_ERROR', 'TIMEOUT', 'FAILED', 'ERROR', 'UNSAFE', 'EXPIRED', 'INACTIVE']);
const WARN = new Set(['EXPIRING', 'WARNING', 'PENDING', 'VALIDATED', 'GENERATED', 'UNKNOWN', 'NOT_ISSUED']);

export function tone(value) {
  const key = String(value ?? '').toUpperCase();
  if (GOOD.has(key)) return 'good';
  if (BAD.has(key)) return 'critical';
  if (WARN.has(key)) return 'warning';
  return 'info';
}

export function statusLabel(value) {
  const key = String(value ?? '').toUpperCase();
  const map = {
    UP: 'mappings.health.up',
    DOWN: 'mappings.health.down',
    HTTP_ERROR: 'mappings.health.http_error',
    TLS_ERROR: 'mappings.health.tls_error',
    TIMEOUT: 'mappings.health.timeout',
    UNKNOWN: 'mappings.health.unknown',
  };
  return map[key] ? t(map[key]) : (key || t('common.unknown'));
}

export function healthChip(status) {
  const key = String(status || 'UNKNOWN').toUpperCase();
  return `<span class="health"><span class="status-dot ${tone(key)}" aria-hidden="true"></span><span class="health-label">${escapeHtml(statusLabel(key))}</span></span>`;
}

export function statusChip(value, label = null) {
  const key = String(value ?? 'UNKNOWN').toUpperCase();
  const text = label === null ? key || '—' : label;
  return `<span class="chip chip-${tone(key)}">${escapeHtml(text)}</span>`;
}

export function badge(value, label = null) {
  const key = String(value ?? 'UNKNOWN').toUpperCase();
  const text = label === null ? key || '—' : label;
  return `<span class="badge ${tone(key)}">${escapeHtml(text)}</span>`;
}

// ------------------------------------------------------------------ toasts
export function toast(message, toneName = 'good', timeout = 5000) {
  let stack = $('#toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toast-stack';
    stack.className = 'toast-stack';
    stack.setAttribute('role', 'status');
    stack.setAttribute('aria-live', 'polite');
    document.body.appendChild(stack);
  }
  const node = document.createElement('div');
  node.className = `toast ${toneName}`;
  const copy = document.createElement('p');
  copy.textContent = String(message);
  node.appendChild(copy);
  stack.appendChild(node);
  setTimeout(() => node.remove(), timeout);
  return node;
}

// ------------------------------------------------------------------ action modal
let lastTrigger = null;
let modalResolver = null;
let activeActions = new Set();

const modalRoot = () => $('[data-action-modal]');
function modalParts() {
  const modal = modalRoot();
  if (!modal) return null;
  return {
    modal,
    title: $('[data-action-modal-title]', modal),
    kicker: $('[data-action-modal-kicker]', modal),
    body: $('[data-action-modal-body]', modal),
    icon: $('[data-action-modal-icon]', modal),
    spinner: $('[data-action-modal-spinner]', modal),
    inputWrap: $('[data-action-modal-input-wrap]', modal),
    inputLabel: $('[data-action-modal-input-label]', modal),
    input: $('[data-action-modal-input]', modal),
    cancel: $('[data-action-modal-cancel]', modal),
    confirm: $('[data-action-modal-confirm]', modal),
    close: $('[data-action-modal-close]', modal),
  };
}

function focusables(root) {
  return $$('button:not([hidden]):not(:disabled),input:not([hidden]):not(:disabled),select:not([hidden]):not(:disabled),textarea:not([hidden]):not(:disabled),a[href]', root)
    .filter((el) => el.offsetParent !== null || el === document.activeElement);
}

function trapFocus(event) {
  if (event.key !== 'Tab') return;
  const root = event.currentTarget;
  const items = focusables(root);
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function rememberTrigger(trigger) {
  if (trigger instanceof HTMLElement) lastTrigger = trigger;
}

function restoreTrigger() {
  const element = lastTrigger;
  lastTrigger = null;
  if (element && document.contains(element) && typeof element.focus === 'function') {
    setTimeout(() => element.focus(), 0);
  }
}

function resetModal() {
  const parts = modalParts();
  if (!parts) return null;
  const { modal, title, kicker, body, icon, spinner, inputWrap, inputLabel, input, cancel, confirm, close } = parts;
  modal.dataset.state = 'info';
  modal.dataset.blocking = 'false';
  icon.textContent = 'i';
  kicker.textContent = t('app.name');
  title.textContent = t('common.info');
  body.replaceChildren();
  spinner.hidden = true;
  inputWrap.hidden = true;
  inputLabel.textContent = t('common.value');
  input.type = 'text';
  input.placeholder = '';
  input.value = '';
  input.required = false;
  cancel.hidden = true;
  cancel.textContent = t('common.cancel');
  cancel.disabled = false;
  cancel.onclick = null;
  confirm.hidden = false;
  confirm.textContent = t('common.close');
  confirm.className = 'btn btn-primary';
  confirm.disabled = false;
  confirm.onclick = null;
  close.hidden = false;
  close.disabled = false;
  close.onclick = null;
  modal.oncancel = null;
  return parts;
}

function openModal({ blocking = false, trigger = document.activeElement, focusSelector = null } = {}) {
  const parts = modalParts();
  if (!parts) return null;
  rememberTrigger(trigger);
  parts.modal.dataset.blocking = blocking ? 'true' : 'false';
  if (!parts.modal.open) parts.modal.showModal();
  document.body.classList.add('modal-open');
  setTimeout(() => {
    const target = focusSelector ? $(focusSelector, parts.modal) : focusables(parts.modal)[0];
    target?.focus();
  }, 0);
  return parts;
}

export function closeModal(value = null) {
  const modal = modalRoot();
  if (!modal) return;
  if (modal.open) modal.close();
  document.body.classList.remove('modal-open');
  if (modalResolver) {
    const resolve = modalResolver;
    modalResolver = null;
    resolve(value);
  }
  restoreTrigger();
  const parts = modalParts();
  if (parts?.input) parts.input.value = '';
}

function addMessage(body, message, detail = '') {
  if (message) {
    const paragraph = document.createElement('p');
    paragraph.textContent = String(message);
    body.appendChild(paragraph);
  }
  if (detail) {
    const block = document.createElement('div');
    block.className = 'action-modal-detail';
    block.textContent = String(detail);
    body.appendChild(block);
  }
}

function present(state, title, message, { detail = '', kicker = '', trigger = document.activeElement } = {}) {
  const parts = resetModal();
  if (!parts) return null;
  parts.modal.dataset.state = state;
  parts.icon.textContent = state === 'success' ? '✓' : state === 'error' || state === 'warning' ? '!' : state === 'loading' ? '↻' : 'i';
  parts.kicker.textContent = kicker || t(`common.${state === 'loading' ? 'info' : state}`);
  parts.title.textContent = title;
  addMessage(parts.body, message, detail);
  openModal({ trigger, blocking: state === 'loading' });
  return parts;
}

export function showResult(state, { title, message = '', detail = '', trigger = document.activeElement } = {}) {
  const parts = present(state, title, message, { detail, trigger });
  if (!parts) return;
  parts.cancel.hidden = true;
  parts.confirm.hidden = false;
  parts.confirm.textContent = t('common.close');
  parts.close.disabled = false;
  parts.confirm.onclick = () => closeModal();
  parts.close.onclick = () => closeModal();
}

export function showLoading({ title = t('common.loading'), message = '', trigger = document.activeElement } = {}) {
  const parts = present('loading', title, message, { trigger });
  if (!parts) return;
  parts.spinner.hidden = false;
  parts.confirm.hidden = true;
  parts.close.disabled = true;
}

export function confirmAction({
  title = t('common.confirm'),
  message = '',
  detail = '',
  confirmLabel = t('common.confirm'),
  cancelLabel = t('common.cancel'),
  danger = false,
  trigger = document.activeElement,
} = {}) {
  return new Promise((resolve) => {
    const parts = present(danger ? 'warning' : 'info', title, message, { detail, trigger });
    if (!parts) return resolve(false);
    parts.modal.dataset.blocking = 'true';
    parts.cancel.hidden = false;
    parts.cancel.textContent = cancelLabel;
    parts.confirm.textContent = confirmLabel;
    parts.confirm.className = danger ? 'btn btn-danger' : 'btn btn-primary';
    modalResolver = resolve;
    parts.cancel.onclick = () => closeModal(false);
    parts.close.onclick = () => closeModal(false);
    parts.confirm.onclick = () => closeModal(true);
    parts.modal.oncancel = (event) => {
      event.preventDefault();
      closeModal(false);
    };
  });
}

export function promptAction({
  title = t('common.value'),
  message = '',
  inputLabel = t('common.value'),
  inputType = 'text',
  inputPlaceholder = '',
  inputValue = '',
  required = true,
  confirmLabel = t('common.confirm'),
  cancelLabel = t('common.cancel'),
  danger = false,
  trigger = document.activeElement,
} = {}) {
  return new Promise((resolve) => {
    const parts = present(danger ? 'warning' : 'info', title, message, { trigger });
    if (!parts) return resolve(null);
    parts.modal.dataset.blocking = 'true';
    parts.inputWrap.hidden = false;
    parts.inputLabel.textContent = inputLabel;
    parts.input.type = inputType;
    parts.input.placeholder = inputPlaceholder;
    parts.input.value = inputValue;
    parts.input.required = required;
    parts.cancel.hidden = false;
    parts.cancel.textContent = cancelLabel;
    parts.confirm.textContent = confirmLabel;
    parts.confirm.className = danger ? 'btn btn-danger' : 'btn btn-primary';
    modalResolver = resolve;
    const submit = () => {
      const value = parts.input.value.trim();
      if (required && !value) {
        parts.input.focus();
        return;
      }
      closeModal(value);
    };
    parts.cancel.onclick = () => closeModal(null);
    parts.close.onclick = () => closeModal(null);
    parts.confirm.onclick = submit;
    parts.input.onkeydown = (event) => {
      if (event.key === 'Enter') submit();
    };
    parts.modal.oncancel = (event) => {
      event.preventDefault();
      closeModal(null);
    };
    setTimeout(() => parts.input.focus(), 0);
  });
}

async function withBusy(trigger, controls, fn) {
  const list = [...new Set([trigger, ...(controls || [])].filter(Boolean))];
  const before = list.map((el) => el.disabled);
  list.forEach((el) => {
    el.disabled = true;
    el.setAttribute('aria-busy', 'true');
  });
  try {
    return await fn();
  } finally {
    list.forEach((el, index) => {
      el.disabled = before[index];
      el.removeAttribute('aria-busy');
    });
  }
}

export async function runAction({
  key,
  title,
  message = '',
  successTitle,
  successMessage,
  confirm: confirmOptions = null,
  input = null,
  trigger = document.activeElement,
  controls = [],
  request,
  onSuccess = null,
  silentSuccess = false,
} = {}) {
  const actionKey = key || `${title}:${message}`;
  if (activeActions.has(actionKey)) return null;
  activeActions.add(actionKey);
  try {
    if (confirmOptions) {
      const ok = await confirmAction({ ...confirmOptions, trigger });
      if (!ok) return null;
    }
    let inputValue = null;
    if (input) {
      inputValue = await promptAction({ ...input, trigger });
      if (inputValue === null) return null;
    }
    return await withBusy(trigger, controls, async () => {
      showLoading({ title, message, trigger });
      try {
        const result = await request(inputValue);
        if (onSuccess) await onSuccess(result);
        closeModal();
        if (!silentSuccess) {
          const finalMessage = typeof successMessage === 'function' ? successMessage(result) : (successMessage || t('common.success'));
          toast(finalMessage, 'good');
        }
        return result;
      } catch (error) {
        showResult('error', {
          title: t('error.action_failed'),
          message: error?.message || t('common.error'),
          trigger,
        });
        return null;
      }
    });
  } finally {
    activeActions.delete(actionKey);
  }
}

// ------------------------------------------------------------------ side panel
export function openPanel(panel, trigger = document.activeElement, focusSelector = null) {
  if (!panel) return;
  rememberTrigger(trigger);
  if (!panel.open) panel.showModal();
  document.body.classList.add('panel-open');
  setTimeout(() => {
    const target = focusSelector ? $(focusSelector, panel) : focusables(panel)[0];
    target?.focus();
  }, 0);
}

export function closePanel(panel) {
  if (!panel) return;
  if (panel.open) panel.close();
  document.body.classList.remove('panel-open');
  restoreTrigger();
}

export function wirePanel(panel) {
  if (!panel) return;
  $$('[data-panel-close]', panel).forEach((button) => button.addEventListener('click', () => closePanel(panel)));
  panel.addEventListener('keydown', trapFocus);
  panel.addEventListener('click', (event) => {
    if (event.target === panel) closePanel(panel);
  });
  panel.addEventListener('close', () => document.body.classList.remove('panel-open'));
}

// ------------------------------------------------------------------ polling
export function poll(fn, intervalMs = 1000, { maxBackoff = 30000 } = {}) {
  let timer = null;
  let stopped = false;
  let inFlight = false;
  let errors = 0;
  const schedule = (delay) => {
    clearTimeout(timer);
    timer = null;
    if (!stopped && !document.hidden) timer = setTimeout(run, delay);
  };
  const run = async () => {
    if (inFlight || stopped || document.hidden) return;
    inFlight = true;
    let delay = intervalMs;
    try {
      await fn();
      errors = 0;
    } catch (error) {
      errors += 1;
      delay = Math.min(maxBackoff, intervalMs * 2 ** Math.min(errors, 10));
      if (Number(error?.status) === 403) stopped = true;
    } finally {
      inFlight = false;
      if (!stopped && !document.hidden) schedule(delay);
    }
  };
  const onVisibility = () => {
    if (stopped) return;
    clearTimeout(timer);
    timer = null;
    if (!document.hidden) run();
  };
  document.addEventListener('visibilitychange', onVisibility);
  const stop = () => {
    stopped = true;
    clearTimeout(timer);
    document.removeEventListener('visibilitychange', onVisibility);
  };
  window.addEventListener('pagehide', stop, { once: true });
  if (!document.hidden) run();
  return { stop, run };
}

// ------------------------------------------------------------------ sparkline
export function createSparkline(svg, { capacity = 120, toneName = 'accent' } = {}) {
  const values = [];
  const render = () => {
    if (!svg) return;
    const width = svg.viewBox.baseVal.width || 240;
    const height = svg.viewBox.baseVal.height || 56;
    svg.replaceChildren();
    if (values.length < 2) return;
    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const span = max - min || 1;
    const step = width / Math.max(values.length - 1, 1);
    const points = values.map((value, index) => {
      const x = index * step;
      const y = height - ((value - min) / span) * (height - 6) - 3;
      return [x, y];
    });
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    line.setAttribute('points', points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' '));
    line.setAttribute('class', `spark-${toneName}`);
    const fill = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
    fill.setAttribute('class', 'spark-fill');
    fill.setAttribute('points', `${points[0][0]},${height} ${points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ')} ${points[points.length - 1][0]},${height}`);
    svg.append(fill, line);
  };
  return {
    push(value) {
      const number = Number(value);
      if (!Number.isFinite(number)) return;
      values.push(number);
      while (values.length > capacity) values.shift();
      render();
    },
    latest() {
      return values.length ? values[values.length - 1] : null;
    },
    reset() {
      values.length = 0;
      render();
    },
  };
}

// ------------------------------------------------------------------ pending banner
export function pendingDomains() {
  return [...serverPending.domains];
}

export async function refreshPending() {
  const banner = $('[data-pending-banner]');
  if (!banner) return serverPending;
  try {
    serverPending = await api('/api/v1/config/pending');
  } catch {
    banner.hidden = true;
    return serverPending;
  }
  renderPending(banner);
  return serverPending;
}

function renderPending(banner) {
  const canApply = document.body.dataset.canApply === 'true';
  const count = Number(serverPending.count || 0);
  if (!count) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  banner.classList.toggle('read-only', !canApply);
  const text = $('[data-pending-text]', banner);
  const domains = $('[data-pending-domains]', banner);
  const button = $('[data-apply-pending]', banner);
  if (text) {
    text.textContent = canApply
      ? t('pending.title', { count })
      : t('pending.read_only', { count });
  }
  if (domains) {
    const names = serverPending.domains || [];
    const shown = names.slice(0, 3).join(', ');
    const extra = names.length > 3 ? ` ${t('pending.more', { count: names.length - 3 })}` : '';
    domains.textContent = names.length ? `${shown}${extra}` : '';
  }
  if (button) button.hidden = !canApply;
}

export async function applyPending(trigger = document.activeElement) {
  if (pendingApplyInFlight) return null;
  pendingApplyInFlight = true;
  try {
    return await runAction({
      key: 'config-apply',
      title: t('system.apply'),
      message: t('pending.apply_message'),
      confirm: {
        title: t('pending.apply_title'),
        message: t('pending.apply_message'),
        confirmLabel: t('common.apply'),
      },
      trigger,
      request: () => api('/api/v1/config/apply', { method: 'POST' }),
      onSuccess: async (result) => {
        const failed = result?.ssl_sync?.failed || [];
        if (failed.length) {
          toast(t('pending.ssl_sync_failed', {
            count: failed.length,
            domains: failed.map((row) => row.domain).join(', '),
          }), 'warning', 9000);
        }
      },
      successMessage: t('pending.applied'),
    });
  } finally {
    pendingApplyInFlight = false;
    await refreshPending().catch(() => {});
    document.dispatchEvent(new CustomEvent('dns:pending-refreshed', { detail: serverPending }));
  }
}

// ------------------------------------------------------------------ shell chrome
function setTheme(theme) {
  const next = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  setCookie(document.body.dataset.themeCookie || 'dns_manager_theme', next);
  $$('[data-theme-switch]').forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.themeSwitch === next));
  });
}

function setSidebar(collapsed) {
  document.body.classList.toggle('sidebar-collapsed', collapsed);
  try {
    localStorage.setItem('dns_manager_sidebar', collapsed ? 'collapsed' : 'expanded');
  } catch {
    /* storage is a convenience only */
  }
  const toggle = $('[data-sidebar-toggle]');
  if (toggle) toggle.setAttribute('aria-label', t(collapsed ? 'nav.expand' : 'nav.collapse'));
}

function closeMobileNav() {
  document.body.classList.remove('sidebar-open');
}

function initSidebar() {
  let collapsed = false;
  try {
    collapsed = localStorage.getItem('dns_manager_sidebar') === 'collapsed';
  } catch {
    collapsed = false;
  }
  setSidebar(collapsed);
  $('[data-sidebar-toggle]')?.addEventListener('click', () => setSidebar(!document.body.classList.contains('sidebar-collapsed')));
  $$('[data-mobile-menu]').forEach((button) => button.addEventListener('click', () => {
    document.body.classList.toggle('sidebar-open');
  }));
  document.addEventListener('click', (event) => {
    if (!document.body.classList.contains('sidebar-open')) return;
    if (event.target.closest('.sidebar') || event.target.closest('[data-mobile-menu]')) return;
    closeMobileNav();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeMobileNav();
      $('[data-mobile-sheet]')?.close();
    }
  });
  const sheet = $('[data-mobile-sheet]');
  $('[data-mobile-more]')?.addEventListener('click', () => {
    if (sheet && !sheet.open) sheet.showModal();
  });
  $$('[data-mobile-sheet-close]').forEach((button) => button.addEventListener('click', () => sheet?.close()));
}

function initSwitches() {
  $$('[data-theme-switch]').forEach((button) => {
    button.setAttribute('aria-pressed', String(document.documentElement.dataset.theme === button.dataset.themeSwitch));
    button.addEventListener('click', () => setTheme(button.dataset.themeSwitch));
  });
  $$('[data-lang-switch]').forEach((button) => {
    button.addEventListener('click', () => {
      const lang = button.dataset.langSwitch;
      if (!lang || lang === document.documentElement.lang) return;
      setCookie(document.body.dataset.langCookie || 'dns_manager_lang', lang);
      location.reload();
    });
  });
}

async function refreshStatus() {
  const pill = $('[data-global-status]');
  const text = $('[data-global-status-text]');
  if (!pill) return;
  try {
    const status = await api('/api/v1/system/status');
    const ready = status.status === 'ready';
    pill.classList.toggle('good', ready);
    pill.classList.toggle('bad', !ready);
    if (text) text.textContent = ready ? t('status.all_running') : t('status.needs_attention');
    pill.dataset.ready = String(ready);
  } catch {
    pill.classList.remove('good', 'bad');
    if (text) text.textContent = t('status.unavailable');
  }
}

export function initShell() {
  bootDictionary();
  initSidebar();
  initSwitches();

  const modal = modalRoot();
  if (modal) {
    modal.addEventListener('keydown', trapFocus);
    modal.addEventListener('click', (event) => {
      if (event.target === modal && modal.dataset.blocking !== 'true') closeModal();
    });
    modal.addEventListener('close', () => {
      document.body.classList.remove('modal-open');
      const parts = modalParts();
      if (parts?.input) parts.input.value = '';
      restoreTrigger();
    });
  }

  document.addEventListener('click', async (event) => {
    const copy = event.target.closest('[data-copy-action-value]');
    if (!copy) return;
    try {
      await navigator.clipboard.writeText(copy.dataset.copyActionValue || '');
      const original = copy.textContent;
      copy.textContent = t('common.copied');
      setTimeout(() => { copy.textContent = original; }, 1200);
      toast(t('toast.copied'), 'good', 1800);
    } catch {
      toast(t('toast.copy_failed'), 'critical');
    }
  });

  $$('[data-action="logout"]').forEach((button) => button.addEventListener('click', async () => {
    try {
      await api('/api/v1/auth/logout', { method: 'POST' });
    } finally {
      location.assign('/login');
    }
  }));

  $('[data-apply-pending]')?.addEventListener('click', (event) => applyPending(event.currentTarget));

  const page = document.body.dataset.page;
  if (!page || page === 'login') return;
  refreshStatus();
  poll(refreshStatus, 30000);
  if ($('[data-pending-banner]')) {
    refreshPending().catch(() => {});
    poll(refreshPending, 30000);
  }
}

export function reportPageError(error) {
  toast(error?.message || t('error.load_failed'), 'critical', 8000);
}
