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
  return `<svg class="${className}" aria-hidden="true" focusable="false"><use href="/static/icons.svg#icon-${name}"></use></svg>`;
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
  if (value < 1024) return `${value.toFixed(2)} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(2)} MB`;
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

// ------------------------------------------------------------------ chart
export function createChart(svg, {
  series = [],
  capacity = 720,
  minIntervalMs = 5000,
  yMin = 0,
  yMax = null,
  formatValue = (value) => String(value),
  xLabels = null,
  storageKey = null,
} = {}) {
  const NS = 'http://www.w3.org/2000/svg';
  const history = new Map(series.map((s) => [s.key, []]));
  const stamps = new Map(series.map((s) => [s.key, []]));
  const latest = new Map();
  const lastRecord = new Map();
  // Last rendered plot geometry, used by the hover tooltip to map pointer x
  // back to the nearest recorded point index.
  const layout = { padLeft: 44, plotW: 1 };

  const el = (name, attrs) => {
    const node = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  };
  const legendFor = (key) => document.querySelector(`[data-chart-legend="${key}"]`);
  const setLegend = (key, value) => {
    const def = series.find((s) => s.key === key);
    const legend = legendFor(key);
    if (legend && def) legend.textContent = `${def.label} ${formatValue(value)}`;
  };
  // Append one downsampled point (respecting minIntervalMs) and mirror it to
  // localStorage. Shared by live push() and history replay().
  const record = (key, value, timestamp, persist) => {
    const arr = history.get(key);
    const times = stamps.get(key);
    arr.push(value);
    times.push(timestamp);
    while (arr.length > capacity) {
      arr.shift();
      times.shift();
    }
    lastRecord.set(key, timestamp);
    if (persist) saveHistory();
  };

  // Chart history survives reloads: points are mirrored to localStorage with
  // their timestamps, pruned to the visible window (~capacity * minIntervalMs).
  // Storage failures (private mode, quota) must never break the live chart.
  const loadHistory = () => {
    if (!storageKey) return;
    let saved;
    try {
      saved = JSON.parse(localStorage.getItem(storageKey) || 'null');
    } catch {
      return; // corrupted or unreadable storage: start empty
    }
    if (!saved || typeof saved !== 'object') return;
    const cutoff = Date.now() - capacity * minIntervalMs;
    for (const s of series) {
      const rows = Array.isArray(saved[s.key]) ? saved[s.key] : [];
      const hist = history.get(s.key);
      const times = stamps.get(s.key);
      for (const row of rows) {
        const timestamp = Number(row?.[0]);
        const value = Number(row?.[1]);
        if (!Number.isFinite(timestamp) || timestamp < cutoff || !Number.isFinite(value)) continue;
        if (hist.length >= capacity) break;
        hist.push(value);
        times.push(timestamp);
      }
      if (hist.length) {
        const lastValue = hist[hist.length - 1];
        lastRecord.set(s.key, times[times.length - 1]);
        latest.set(s.key, lastValue);
        setLegend(s.key, lastValue);
      }
    }
    render();
  };

  const saveHistory = () => {
    if (!storageKey) return;
    try {
      const data = {};
      for (const s of series) {
        const hist = history.get(s.key);
        const times = stamps.get(s.key);
        data[s.key] = hist.map((value, index) => [times[index], value]);
      }
      localStorage.setItem(storageKey, JSON.stringify(data));
    } catch {
      // storage unavailable or full: the live chart still works, it just
      // won't survive a reload.
    }
  };

  const render = () => {
    if (!svg) return;
    // Measure the real rendered size and match the viewBox to it 1:1 so the
    // axis/legend text is never scaled (or stretched) out of shape.
    const rect = svg.getBoundingClientRect();
    const width = Math.round(rect.width) || svg.viewBox.baseVal.width || 480;
    const height = Math.round(rect.height) || svg.viewBox.baseVal.height || 180;
    if (width > 0 && (svg.viewBox.baseVal.width !== width || svg.viewBox.baseVal.height !== height)) {
      svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    }
    const padLeftBase = 44, padRight = 10, padTop = 10, padBottom = 22;
    const plotH = Math.max(height - padTop - padBottom, 1);
    const baseY = padTop + plotH;

    let max = yMax;
    if (max == null) {
      const all = series.flatMap((s) => history.get(s.key));
      max = Math.max(...all, 1);
    }
    const min = yMin;
    const span = max - min || 1;
    const yFor = (value) => baseY - ((value - min) / span) * plotH;

    const ticks = 4;
    const tickValues = Array.from({ length: ticks + 1 }, (_, i) => min + (span * i) / ticks);
    const tickLabels = tickValues.map(formatValue);
    // Axis text is monospace ~6px/char at 10px size; widen the left gutter so
    // long labels (e.g. "4.41 KB/s") stay fully inside the chart.
    const padLeft = Math.max(padLeftBase, Math.max(...tickLabels.map((s) => s.length)) * 6 + 14);
    const plotW2 = Math.max(width - padLeft - padRight, 1);
    layout.padLeft = padLeft;
    layout.plotW = plotW2;
    const xFor = (index) => padLeft + index * (plotW2 / (capacity - 1));

    svg.replaceChildren();

    tickValues.forEach((value, i) => {
      const y = yFor(value);
      svg.append(el('line', { class: 'chart-grid', x1: padLeft, y1: y, x2: padLeft + plotW2, y2: y }));
      const label = el('text', { class: 'chart-axis chart-axis-y', x: padLeft - 6, y: y + 3, 'text-anchor': 'end' });
      label.textContent = tickLabels[i];
      svg.append(label);
    });

    if (xLabels && xLabels.length === 3) {
      [0, 0.5, 1].forEach((frac, index) => {
        const anchor = frac === 0 ? 'start' : frac === 1 ? 'end' : 'middle';
        const label = el('text', { class: 'chart-axis chart-axis-x', x: padLeft + frac * plotW2, y: height - 6, 'text-anchor': anchor });
        label.textContent = xLabels[index];
        svg.append(label);
      });
    }

    for (const s of series) {
      const points = history.get(s.key);
      if (points.length < 2) continue;
      const coords = points.map((value, index) => [xFor(index), yFor(value)]);
      const linePts = coords.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
      const fillPts = `${coords[0][0].toFixed(1)},${baseY} ${linePts} ${coords[coords.length - 1][0].toFixed(1)},${baseY}`;
      svg.append(el('polygon', { class: `chart-fill chart-fill-${s.toneName}`, points: fillPts }));
      svg.append(el('polyline', { class: `chart-line chart-line-${s.toneName}`, points: linePts }));
    }
  };

  // Keep the 1:1 viewBox in sync when the layout changes (resize, sidebar
  // toggle, orientation) so text never stretches.
  if (typeof ResizeObserver !== 'undefined' && svg) {
    const observer = new ResizeObserver(() => render());
    observer.observe(svg);
  }

  // Hover tooltip: show the values of the point nearest the pointer. The
  // markup contract is an absolutely-positioned div inside the chart card
  // (position: relative on the card); pointer events stay on the SVG.
  const card = svg ? svg.closest('.chart-card') : null;
  const tooltip = card ? card.querySelector('[data-chart-tooltip]') : null;
  if (tooltip && svg) {
    const hide = () => { tooltip.hidden = true; };
    svg.addEventListener('pointermove', (event) => {
      const times = stamps.get(series[0]?.key);
      const count = times ? times.length : 0;
      if (count < 1) { hide(); return; }
      const rect = svg.getBoundingClientRect();
      // Inverse of render()'s xFor(): map pointer x back to a point index.
      const frac = (event.clientX - rect.left - layout.padLeft) / Math.max(layout.plotW, 1);
      const index = Math.min(count - 1, Math.max(0, Math.round(frac * (capacity - 1))));
      const when = times[index];
      if (when == null) { hide(); return; }
      const lines = [new Date(when).toLocaleTimeString()];
      for (const s of series) {
        const arr = history.get(s.key);
        const value = arr ? arr[Math.min(index, arr.length - 1)] : undefined;
        if (!Number.isFinite(value)) continue;
        lines.push(`${s.label} ${formatValue(value)}`);
      }
      if (lines.length < 2) { hide(); return; } // no readable values at this index
      tooltip.textContent = lines.join('\n');
      tooltip.hidden = false;
      // Keep the tooltip inside the card: flip it to the pointer's left near
      // the right edge, and never past the card's left/top bounds.
      const cardRect = card.getBoundingClientRect();
      const tipRect = tooltip.getBoundingClientRect();
      let left = event.clientX - cardRect.left + 12;
      if (left + tipRect.width > cardRect.width - 4) {
        left = event.clientX - cardRect.left - tipRect.width - 12;
      }
      tooltip.style.left = `${Math.max(4, left)}px`;
      tooltip.style.top = `${Math.max(4, rect.top - cardRect.top + 4)}px`;
    });
    svg.addEventListener('pointerleave', hide);
  }

  loadHistory();

  return {
    push(key, value, timestamp = Date.now()) {
      const number = Number(value);
      if (!Number.isFinite(number)) return;
      latest.set(key, number);
      setLegend(key, number);
      const last = lastRecord.get(key);
      if (last == null || timestamp - last >= minIntervalMs) {
        record(key, number, timestamp, true);
        render();
      }
    },
    // Seed the chart from a recorded history (server endpoint or storage) with
    // real timestamps, then draw once. Points closer than minIntervalMs or
    // outside the retention window are ignored so live sampling continues
    // seamlessly without duplicating what is already drawn.
    replay(points) {
      const windowMs = capacity * minIntervalMs;
      const newest = points.reduce((max, p) => Math.max(max, Number(p.t) || 0), 0);
      const cutoff = newest - windowMs;
      const rows = points
        .filter((p) => {
          const t = Number(p.t);
          return Number.isFinite(t) && t >= cutoff && t <= newest;
        })
        .sort((a, b) => Number(a.t) - Number(b.t));
      const cutoffBy = new Map(series.map((s) => [s.key, -Infinity]));
      for (const point of rows) {
        const t = Number(point.t);
        for (const s of series) {
          const value = Number(point[s.key]);
          if (!Number.isFinite(value)) continue;
          if (t - cutoffBy.get(s.key) < minIntervalMs) continue;
          latest.set(s.key, value);
          setLegend(s.key, value);
          record(s.key, value, t, false);
          cutoffBy.set(s.key, t);
        }
      }
      saveHistory();
      render();
    },
    latest(key) { return latest.has(key) ? latest.get(key) : null; },
    reset() {
      for (const arr of history.values()) arr.length = 0;
      for (const arr of stamps.values()) arr.length = 0;
      latest.clear();
      lastRecord.clear();
      render();
      if (storageKey) {
        try {
          localStorage.removeItem(storageKey);
        } catch {
          // ignore: nothing to clean up if storage is unavailable
        }
      }
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
