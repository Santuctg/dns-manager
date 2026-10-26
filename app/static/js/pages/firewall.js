import {
  $, $$, api, escapeHtml, icon, t, toast,
  openPanel, closePanel, wirePanel, runAction, confirmAction,
  showResult, showLoading, closeModal, badge,
} from '../core.js';

const MAX_SOURCES = 32;
const state = { status: null, policy: null, countdown: null, deadline: 0, expired: false };
let confirmBarBound = false;

const statusTone = (value) => {
  const key = String(value || '').toLowerCase();
  if (key === 'active' || key === 'installed') return 'good';
  if (key === 'inactive' || key === 'failed') return 'critical';
  return 'warning';
};

function renderStatus() {
  const status = state.status || {};
  const policy = state.policy || {};
  const set = (name, value) => {
    const node = $(`[data-firewall="${name}"]`);
    if (node) node.innerHTML = value;
  };
  set('state', badge(status.active ? t('firewall.active') : t('firewall.inactive'), statusTone(status.active ? 'active' : 'inactive')));
  set('incoming', escapeHtml(status.default_incoming || policy.default_incoming || '—'));
  set('outgoing', escapeHtml(status.default_outgoing || policy.default_outgoing || '—'));
  set('managed', String(status.managed_count ?? (policy.rules || []).length));
  const ssh = (status.ssh_ports || []).join(', ');
  set('ssh', escapeHtml(ssh || '—'));
  set('ssh-state', escapeHtml(ssh ? t('firewall.ssh') : t('common.not_available')));
  const incomingDetail = $('[data-firewall="incoming-detail"]');
  if (incomingDetail) incomingDetail.textContent = status.available === false
    ? (status.error || t('common.not_available'))
    : `${t('firewall.ufw')}: ${status.installed ? t('firewall.active') : t('common.unknown')}`;
  const unmanaged = $('[data-firewall="unmanaged"]');
  if (unmanaged) unmanaged.textContent = Number.isFinite(Number(status.unmanaged_count))
    ? `${status.unmanaged_count} ${t('common.unknown').toLowerCase()}`
    : '—';

  const findings = $('[data-firewall-findings]');
  if (findings) {
    const rows = status.findings || [];
    findings.innerHTML = rows.length ? rows.map((finding) => `
      <article class="finding ${escapeHtml(finding.severity || 'info')}">
        <span class="status-dot ${escapeHtml(finding.severity || 'info')}" aria-hidden="true"></span>
        <div class="finding-copy">
          <strong>${escapeHtml(finding.code || '')}</strong>
          <p>${escapeHtml(finding.message || '')}</p>
        </div>
        ${badge(finding.severity || 'info')}
      </article>`).join('') : `<p class="muted small">${escapeHtml(t('firewall.no_findings'))}</p>`;
  }

  const enabled = $('[data-firewall-enabled]');
  if (enabled) enabled.checked = Boolean(policy.enabled);
  const incoming = $('[data-firewall-incoming]');
  if (incoming) incoming.value = policy.default_incoming || 'deny';
  const outgoing = $('[data-firewall-outgoing]');
  if (outgoing) outgoing.value = policy.default_outgoing || 'allow';
  const policyState = $('[data-firewall-policy-state]');
  if (policyState) {
    policyState.textContent = policy.desired_revision
      ? `#${policy.desired_revision} · ${policy.pending_revision === policy.applied_revision ? t('common.live') : t('common.pending')}`
      : t('common.never_applied');
  }
  renderRules();
}

function renderRules() {
  const table = $('[data-firewall-rules]');
  if (!table) return;
  const rules = state.policy?.rules || [];
  if (!rules.length) {
    table.innerHTML = `<tr><td colspan="7" class="muted">${escapeHtml(t('firewall.no_rules'))}</td></tr>`;
    return;
  }
  table.innerHTML = rules.map((rule) => {
    const sources = (rule.source_cidrs || [rule.source_cidr]).filter(Boolean);
    const port = rule.port_end ? `${rule.port_start}–${rule.port_end}` : String(rule.port_start);
    return `<tr>
      <td data-label="${escapeHtml(t('firewall.col.purpose'))}" class="cell-primary"><strong>${escapeHtml(rule.purpose)}</strong>${rule.enabled ? '' : ` <span class="chip chip-off">${escapeHtml(t('common.disabled'))}</span>`}</td>
      <td data-label="${escapeHtml(t('firewall.col.action'))}">${badge(rule.action, rule.action)}</td>
      <td data-label="${escapeHtml(t('firewall.col.protocol'))}" class="cell-mono">${escapeHtml(rule.protocol)}</td>
      <td data-label="${escapeHtml(t('firewall.col.port'))}" class="cell-mono">${escapeHtml(port)}</td>
      <td data-label="${escapeHtml(t('firewall.col.source'))}"><div class="firewall-rule-sources">${sources.map((cidr) => `<code>${escapeHtml(cidr)}</code>`).join('')}</div></td>
      <td data-label="${escapeHtml(t('firewall.col.comment'))}" class="muted small">${escapeHtml(rule.comment || '')}</td>
      <td data-label=""><div class="row-actions">
        <button class="btn btn-ghost btn-sm" type="button" data-firewall-edit="${rule.id}">${icon('edit', 'icon icon-sm')}${escapeHtml(t('common.edit'))}</button>
        <button class="btn btn-ghost btn-sm" type="button" data-firewall-delete="${rule.id}">${icon('trash', 'icon icon-sm')}${escapeHtml(t('common.delete'))}</button>
      </div></td>
    </tr>`;
  }).join('');
}

async function loadFirewall() {
  const [status, policy] = await Promise.all([
    api('/api/v1/firewall/status').catch((error) => ({ available: false, error: error.message, findings: [] })),
    api('/api/v1/firewall/policy'),
  ]);
  state.status = status;
  state.policy = policy;
  renderStatus();
}

// ---------------------------------------------------------------- sources
function renderSources(values = ['']) {
  const list = $('[data-firewall-source-list]');
  if (!list) return;
  const items = (values.length ? values : ['']).slice(0, MAX_SOURCES);
  list.replaceChildren();
  items.forEach((value, index) => {
    const row = document.createElement('div');
    row.className = 'firewall-source-row';
    const label = document.createElement('label');
    label.className = 'field';
    label.textContent = `${t('firewall.col.source')} ${index + 1}`;
    const input = document.createElement('input');
    input.name = 'source_cidrs';
    input.required = true;
    input.placeholder = '203.0.113.10/32';
    input.autocomplete = 'off';
    input.value = value;
    input.setAttribute('aria-label', `${t('firewall.col.source')} ${index + 1}`);
    label.append(input);
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'btn btn-ghost btn-sm';
    remove.dataset.firewallSourceRemove = '';
    remove.textContent = t('firewall.remove');
    remove.disabled = items.length === 1;
    row.append(label, remove);
    list.append(row);
  });
  const add = $('[data-firewall-source-add]');
  if (add) add.disabled = items.length >= MAX_SOURCES;
  const notice = $('[data-firewall-source-limit]');
  if (notice) notice.textContent = items.length >= MAX_SOURCES ? t('firewall.source_limit') : '';
}

function sourceValues() {
  return $$('input[name="source_cidrs"]', $('[data-firewall-source-list]')).map((input) => input.value.trim());
}

function openRulePanel(rule = null) {
  const panel = $('[data-firewall-panel]');
  const form = $('[data-firewall-form]');
  if (!panel || !form) return;
  form.reset();
  form.elements.id.value = rule?.id || '';
  form.elements.purpose.value = rule?.purpose || 'web';
  form.elements.action.value = rule?.action || 'allow';
  form.elements.protocol.value = rule?.protocol || 'tcp';
  form.elements.port_start.value = rule?.port_start ?? '';
  form.elements.port_end.value = rule?.port_end ?? '';
  form.elements.comment.value = rule?.comment || '';
  form.elements.enabled.checked = rule ? Boolean(rule.enabled) : true;
  const title = $('[data-firewall-panel-title]');
  if (title) title.textContent = rule ? t('firewall.edit') : t('firewall.add');
  renderSources(rule?.source_cidrs?.length ? rule.source_cidrs : ['']);
  openPanel(panel, document.activeElement, '#firewall-purpose');
}

// ---------------------------------------------------------------- confirmation bar
function renderCountdown() {
  const bar = $('[data-firewall-confirm-bar]');
  const label = $('[data-firewall-countdown]');
  if (!bar) return;
  const remaining = Math.max(0, Math.ceil((state.deadline - Date.now()) / 1000));
  if (label) label.textContent = String(remaining);
  const copy = $('[data-firewall-confirm-text]');
  if (copy) {
    copy.textContent = state.expired
      ? t('firewall.rolled_back')
      : t('firewall.confirm_bar', { seconds: remaining });
  }
  bar.classList.toggle('expired', state.expired);
  const confirm = $('[data-firewall-confirm]');
  const rollback = $('[data-firewall-rollback-now]');
  if (confirm) confirm.disabled = state.expired;
  if (rollback) rollback.disabled = state.expired;
}

function stopCountdown() {
  if (state.countdown) clearInterval(state.countdown);
  state.countdown = null;
}

function startCountdown(deadline) {
  const bar = $('[data-firewall-confirm-bar]');
  if (!bar) return;
  stopCountdown();
  state.expired = false;
  state.deadline = deadline ? new Date(deadline).getTime() : Date.now() + 120000;
  if (!Number.isFinite(state.deadline)) state.deadline = Date.now() + 120000;
  bar.hidden = false;
  bar.dataset.deadline = new Date(state.deadline).toISOString();
  renderCountdown();
  state.countdown = setInterval(() => {
    if (Date.now() >= state.deadline) {
      state.expired = true;
      stopCountdown();
      renderCountdown();
      loadFirewall().catch(() => {});
      return;
    }
    renderCountdown();
  }, 1000);
}

function expireBar() {
  state.expired = true;
  stopCountdown();
  renderCountdown();
}

// ---------------------------------------------------------------- actions
async function validatePolicy(trigger) {
  return api('/api/v1/firewall/validate', { method: 'POST', json: {} }).catch((error) => {
    showResult('error', { title: t('firewall.validate'), message: error.message, trigger });
    return null;
  });
}

async function applyPolicy(trigger) {
  const validation = await validatePolicy(trigger);
  if (!validation) return null;
  if (!validation.valid) {
    showResult('error', {
      title: t('firewall.validate'),
      message: (validation.errors || []).join(' · '),
      trigger,
    });
    return null;
  }
  let highRisk = false;
  if (validation.requires_high_risk_confirmation) {
    highRisk = await confirmAction({
      title: t('firewall.high_risk_title'),
      message: (validation.warnings || []).join(' · '),
      confirmLabel: t('firewall.high_risk_confirm'),
      danger: true,
      trigger,
    });
    if (!highRisk) return null;
  }
  const result = await runAction({
    key: 'firewall-apply',
    title: t('firewall.apply'),
    message: t('firewall.apply_message'),
    confirm: {
      title: t('firewall.apply_title'),
      message: t('firewall.apply_message'),
      confirmLabel: t('common.apply'),
    },
    trigger,
    silentSuccess: true,
    request: () => api('/api/v1/firewall/apply', { method: 'POST', json: { high_risk_confirmed: highRisk } }),
  });
  if (!result) return null;
  startCountdown(result.rollback_deadline);
  toast(t('firewall.apply_title'), 'warning', 6000);
  return result;
}

async function confirmChanges(trigger) {
  const result = await runAction({
    key: 'firewall-confirm',
    title: t('firewall.confirm'),
    message: t('firewall.confirm_bar', { seconds: 0 }),
    trigger,
    silentSuccess: true,
    request: () => api('/api/v1/firewall/confirm', { method: 'POST' }),
  });
  if (result) {
    stopCountdown();
    const bar = $('[data-firewall-confirm-bar]');
    if (bar) bar.hidden = true;
    toast(t('firewall.confirmed'), 'good');
  } else {
    expireBar();
  }
  await loadFirewall().catch(() => {});
}

async function rollbackFirewall(trigger) {
  const result = await runAction({
    key: 'firewall-rollback',
    title: t('firewall.rollback'),
    confirm: {
      title: t('firewall.rollback'),
      message: t('firewall.rollback_done'),
      confirmLabel: t('firewall.rollback'),
      danger: true,
    },
    trigger,
    request: () => api('/api/v1/firewall/rollback', { method: 'POST' }),
    successMessage: t('firewall.rollback_done'),
  });
  if (result) {
    stopCountdown();
    const bar = $('[data-firewall-confirm-bar]');
    if (bar) bar.hidden = true;
  }
  await loadFirewall().catch(() => {});
  return result;
}

function bindConfirmBar() {
  if (confirmBarBound) return;
  confirmBarBound = true;
  $('[data-firewall-confirm]')?.addEventListener('click', (event) => confirmChanges(event.currentTarget));
  $('[data-firewall-rollback-now]')?.addEventListener('click', (event) => rollbackFirewall(event.currentTarget));
}

export async function init() {
  const panel = $('[data-firewall-panel]');
  wirePanel(panel);
  bindConfirmBar();
  renderSources(['']);

  $('[data-firewall-refresh]')?.addEventListener('click', (event) => runAction({
    key: 'firewall-refresh',
    title: t('common.refresh'),
    trigger: event.currentTarget,
    request: loadFirewall,
    successMessage: t('common.success'),
  }));

  $('[data-firewall-add]')?.addEventListener('click', (event) => openRulePanel(null, event.currentTarget));

  $('[data-firewall-source-add]')?.addEventListener('click', () => {
    const values = sourceValues();
    if (values.length >= MAX_SOURCES) return;
    renderSources([...values, '']);
    $('[data-firewall-source-list]')?.lastElementChild?.querySelector('input')?.focus();
  });

  $('[data-firewall-source-list]')?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-firewall-source-remove]');
    if (!button) return;
    const rows = $$('.firewall-source-row', $('[data-firewall-source-list]'));
    if (rows.length <= 1) return;
    const values = rows
      .filter((row) => row !== button.closest('.firewall-source-row'))
      .map((row) => row.querySelector('input')?.value || '');
    renderSources(values.length ? values : ['']);
  });

  $('[data-firewall-rules]')?.addEventListener('click', async (event) => {
    const edit = event.target.closest('[data-firewall-edit]');
    if (edit) {
      const rule = (state.policy?.rules || []).find((row) => String(row.id) === String(edit.dataset.firewallEdit));
      if (rule) openRulePanel(rule);
      return;
    }
    const remove = event.target.closest('[data-firewall-delete]');
    if (!remove) return;
    const rule = (state.policy?.rules || []).find((row) => String(row.id) === String(remove.dataset.firewallDelete));
    const result = await runAction({
      key: `firewall-delete:${remove.dataset.firewallDelete}`,
      title: t('common.delete'),
      confirm: {
        title: t('firewall.rules'),
        message: rule ? `${rule.purpose}: ${rule.port_start}${rule.port_end ? `–${rule.port_end}` : ''}` : '',
        confirmLabel: t('common.delete'),
        danger: true,
      },
      trigger: remove,
      request: () => api(`/api/v1/firewall/rules/${remove.dataset.firewallDelete}`, { method: 'DELETE' }),
      onSuccess: loadFirewall,
      successMessage: t('toast.deleted'),
    });
    return result;
  });

  $('[data-firewall-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const id = formData.get('id');
    const values = formData.getAll('source_cidrs').map((value) => String(value).trim()).filter(Boolean);
    if (!values.length) {
      form.querySelector('input[name="source_cidrs"]')?.focus();
      return;
    }
    const payload = {
      purpose: formData.get('purpose'),
      action: formData.get('action'),
      protocol: formData.get('protocol'),
      port_start: Number(formData.get('port_start')),
      port_end: formData.get('port_end') ? Number(formData.get('port_end')) : null,
      source_cidrs: values,
      comment: formData.get('comment') || null,
      enabled: form.elements.enabled.checked,
      sort_key: 100,
    };
    await runAction({
      key: `firewall-save:${id || 'new'}`,
      title: t('common.save'),
      message: payload.comment || '',
      trigger: event.submitter || form,
      request: () => api(id ? `/api/v1/firewall/rules/${id}` : '/api/v1/firewall/rules', {
        method: id ? 'PUT' : 'POST',
        json: payload,
      }),
      onSuccess: async () => {
        closePanel(panel);
        await loadFirewall();
      },
      successMessage: t('toast.saved_pending'),
    });
  });

  $('[data-firewall-policy-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.submitter;
    await runAction({
      key: 'firewall-policy-save',
      title: `${t('firewall.policy')} · ${t('common.save')}`,
      trigger: button || event.currentTarget,
      request: () => api('/api/v1/firewall/policy', {
        method: 'PUT',
        json: {
          enabled: $('[data-firewall-enabled]')?.checked || false,
          default_incoming: $('[data-firewall-incoming]')?.value || 'deny',
          default_outgoing: $('[data-firewall-outgoing]')?.value || 'allow',
        },
      }),
      onSuccess: (policy) => {
        state.policy = policy;
        renderStatus();
      },
      successMessage: t('toast.saved_pending'),
    });
  });

  $('[data-firewall-preview]')?.addEventListener('click', async (event) => {
    try {
      showLoading({ title: t('firewall.preview'), message: t('common.loading'), trigger: event.currentTarget });
      const preview = await api('/api/v1/firewall/preview', { method: 'POST' });
      closeModal();
      showResult('info', {
        title: t('firewall.preview'),
        message: `${(preview.operations || []).length} ufw operation(s) · ${preview.default_incoming} / ${preview.default_outgoing}`,
        detail: JSON.stringify(preview.operations || [], null, 2),
        trigger: event.currentTarget,
      });
    } catch (error) {
      closeModal();
      showResult('error', { title: t('firewall.preview'), message: error.message, trigger: event.currentTarget });
    }
  });

  $('[data-firewall-validate]')?.addEventListener('click', async (event) => {
    const validation = await validatePolicy(event.currentTarget);
    if (!validation) return;
    if (validation.valid) {
      showResult('success', {
        title: t('firewall.validate'),
        message: (validation.warnings || []).join(' · ') || t('system.validated'),
        trigger: event.currentTarget,
      });
    } else {
      showResult('error', {
        title: t('firewall.validate'),
        message: (validation.errors || []).join(' · '),
        detail: (validation.warnings || []).join(' · '),
        trigger: event.currentTarget,
      });
    }
  });

  $('[data-firewall-apply]')?.addEventListener('click', (event) => applyPolicy(event.currentTarget));
  $('[data-firewall-rollback]')?.addEventListener('click', (event) => rollbackFirewall(event.currentTarget));

  try {
    await loadFirewall();
  } catch (error) {
    toast(error.message, 'critical');
  }

  // A refresh after apply re-arms the bar if the backend still reports a pending revision.
  const pending = state.policy?.pending_revision;
  if (pending != null && pending !== state.policy?.applied_revision) {
    startCountdown(null);
  }
}
