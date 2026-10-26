import {
  $, $$, api, escapeHtml, icon, t, toast, daysLeft, fmtDate,
  openPanel, closePanel, wirePanel, runAction, promptAction,
  showResult, showLoading, closeModal, statusChip, badge, tone,
} from '../core.js';

const state = { certificates: [] };

const PROVIDERS = {
  manual: 'ssl.provider.manual',
  cloudflare: 'ssl.provider.cloudflare',
  acme_delegation: 'ssl.provider.acme_delegation',
  acme_dns_hosted: 'ssl.provider.hosted',
};

const providerLabel = (provider) => t(PROVIDERS[provider] || 'common.unknown');

function expiryCell(cert) {
  if (!cert.expires_at) {
    return `<div class="ssl-expiry"><strong>—</strong><span class="muted tiny">${escapeHtml(t('common.not_available'))}</span></div>`;
  }
  const days = daysLeft(cert.expires_at);
  const state = days === null ? 'info' : days <= 0 ? 'critical' : days < 7 ? 'critical' : days < 30 ? 'warning' : 'good';
  const label = days === null
    ? t('common.unknown')
    : days <= 0 ? t('ssl.expired') : t('ssl.days_left', { days });
  return `<div class="ssl-expiry">
    <strong>${escapeHtml(fmtDate(cert.expires_at))}</strong>
    <span class="chip chip-${state}">${escapeHtml(label)}</span>
  </div>`;
}

function statusExtras(cert) {
  const parts = [];
  if (cert.provider === 'acme_delegation') {
    parts.push(cert.delegation_verified
      ? `<span class="chip chip-good">${escapeHtml(t('ssl.verify_delegation'))}</span>`
      : `<span class="chip chip-warning">${escapeHtml(t('ssl.verify_delegation'))}</span>`);
  }
  if (cert.provider === 'acme_dns_hosted') {
    parts.push(cert.hosted_acme_verified
      ? `<span class="chip chip-good">${escapeHtml(t('ssl.verify_cname'))}</span>`
      : `<span class="chip chip-warning">${escapeHtml(t('ssl.verify_cname'))}</span>`);
  }
  return parts.join('');
}

function primaryAction(cert) {
  const issued = ['ISSUED', 'EXPIRING', 'EXPIRED'].includes(String(cert.status || '').toUpperCase());
  if (cert.provider === 'manual') {
    return issued
      ? { action: 'apply', label: t('ssl.apply_vhost'), tone: 'btn-secondary' }
      : { action: 'manual-start', label: t('ssl.manual_start'), tone: 'btn-primary' };
  }
  return issued
    ? { action: 'renew', label: t('ssl.renew'), tone: 'btn-primary' }
    : { action: 'issue', label: t('ssl.issue'), tone: 'btn-primary' };
}

function menuItems(cert) {
  const items = [];
  const add = (action, label, danger = false) => items.push({ action, label, danger });
  if (cert.provider === 'manual') {
    add('manual-start', t('ssl.manual_start'));
    add('convert-cloudflare', t('ssl.convert_cloudflare'));
    add('convert-hosted', t('ssl.convert_hosted'));
  } else {
    add('test-renewal', t('ssl.test_renewal'));
    add('issue', t('ssl.issue'));
    add('renew', t('ssl.renew'));
    if (cert.auto_renew) add('disable-auto-renew', t('ssl.disable_auto_renew'));
    else add('enable-auto-renew', t('ssl.enable_auto_renew'));
  }
  if (cert.provider === 'acme_delegation') {
    add('show-delegation', t('ssl.show_delegation'));
    add('verify-delegation', t('ssl.verify_delegation'));
  }
  if (cert.provider === 'acme_dns_hosted') {
    add('show-cname', t('ssl.show_cname'));
    add('verify-cname', t('ssl.verify_cname'));
    add('reregister-hosted', t('ssl.reregister'));
  }
  add('apply', t('ssl.apply_vhost'));
  add('delete', t('ssl.delete_title').replace(/\?$/, ''), true);
  return items;
}

function renderTable() {
  const table = $('[data-ssl-table]');
  if (!table) return;
  const rows = state.certificates;
  if (!rows.length) {
    table.innerHTML = `<tr><td colspan="6" class="muted">${escapeHtml(t('ssl.no_certificates'))}</td></tr>`;
    return;
  }
  table.innerHTML = rows.map((cert) => {
    const primary = primaryAction(cert);
    const menu = menuItems(cert).map((item) => `
      <button class="btn btn-ghost btn-sm ${item.danger ? 'btn-danger' : ''}" type="button"
        data-ssl-action="${escapeHtml(item.action)}" data-ssl-domain="${escapeHtml(cert.domain)}">
        ${escapeHtml(item.label)}
      </button>`).join('');
    return `<tr data-ssl-row="${escapeHtml(cert.domain)}">
      <td data-label="${escapeHtml(t('ssl.domain'))}" class="cell-primary">
        <strong>${escapeHtml(cert.domain)}</strong>
        <div class="muted tiny">${escapeHtml(t('ssl.provider') + ': ' + providerLabel(cert.provider))}</div>
      </td>
      <td data-label="${escapeHtml(t('ssl.provider'))}">${escapeHtml(providerLabel(cert.provider))}</td>
      <td data-label="${escapeHtml(t('ssl.status'))}">
        <div class="ssl-status-cell">
          ${statusChip(cert.status, cert.status)}
          ${statusExtras(cert)}
          ${cert.auto_renew ? `<span class="chip chip-accent">${escapeHtml(t('ssl.auto_renew'))}</span>` : ''}
        </div>
      </td>
      <td data-label="${escapeHtml(t('ssl.expiry'))}">${expiryCell(cert)}</td>
      <td data-label="${escapeHtml(t('ssl.auto_renew'))}">${badge(cert.auto_renew ? 'enabled' : 'disabled', cert.auto_renew ? t('common.enabled') : t('common.disabled'))}</td>
      <td data-label="">
        <div class="row-actions">
          <button class="btn ${primary.tone} btn-sm" type="button"
            data-ssl-action="${escapeHtml(primary.action)}" data-ssl-domain="${escapeHtml(cert.domain)}">
            ${escapeHtml(primary.label)}
          </button>
          <details class="menu" data-ssl-menu>
            <summary aria-label="${escapeHtml(t('ssl.more'))}" title="${escapeHtml(t('ssl.more'))}">${icon('more', 'icon icon-sm')}</summary>
            <div class="menu-panel">${menu}</div>
          </details>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function updateSummary() {
  const summary = $('[data-ssl-summary]');
  if (!summary) return;
  const rows = state.certificates;
  const expiring = rows.filter((cert) => {
    const days = daysLeft(cert.expires_at);
    return days !== null && days <= 30;
  }).length;
  const auto = rows.filter((cert) => cert.auto_renew).length;
  summary.textContent = `${rows.length} · ${t('dashboard.expiring', { count: expiring })} · ${t('ssl.auto_renew')}: ${auto}`;
}

async function loadSsl() {
  state.certificates = await api('/api/v1/ssl/certificates');
  renderTable();
  updateSummary();
}

// ---------------------------------------------------------------- detail dialogs
function detailBlock(rows) {
  return rows.map(([label, value, code]) => `
    <div class="action-detail-row">
      <span class="muted small">${escapeHtml(label)}</span>
      ${code ? `<code>${escapeHtml(value ?? '—')}</code>` : `<strong>${escapeHtml(value ?? '—')}</strong>`}
    </div>`).join('');
}

async function showDelegation(domain, trigger) {
  try {
    showLoading({ title: t('ssl.delegation_title'), message: t('common.loading'), trigger });
    const data = await api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/delegation`);
    closeModal();
    showResult('info', {
      title: t('ssl.delegation_title'),
      message: domain,
      detail: `${t('ssl.type')}: CNAME · ${data.verified ? t('ssl.verify_ok', { domain }) : t('ssl.verify_failed', { domain })}\n${t('ssl.name')}: ${data.challenge_domain}\n${t('ssl.target')}: ${data.delegated_fqdn}\n${t('ssl.ttl')}: 300`,
      trigger,
    });
  } catch (error) {
    closeModal();
    showResult('error', { title: t('ssl.delegation_title'), message: error.message, trigger });
  }
}

async function showCname(domain, trigger) {
  try {
    showLoading({ title: t('ssl.hosted_title'), message: t('common.loading'), trigger });
    const data = await api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/hosted-acme`);
    closeModal();
    showResult('info', {
      title: t('ssl.hosted_title'),
      message: t('ssl.hosted_help', { domain }),
      detail: `${t('ssl.type')}: CNAME\n${t('ssl.name')}: ${data.challenge_domain}\n${t('ssl.target')}: ${data.fulldomain}\n${t('ssl.ttl')}: 300`,
      trigger,
    });
  } catch (error) {
    closeModal();
    showResult('error', { title: t('ssl.hosted_title'), message: error.message, trigger });
  }
}

async function openManualPanel(domain, trigger) {
  const panel = $('[data-ssl-manual-panel]');
  if (!panel) return;
  panel.dataset.domain = domain;
  const name = $('[data-ssl-manual-name]', panel);
  const value = $('[data-ssl-manual-value]', panel);
  const status = $('[data-ssl-manual-status]', panel);
  if (name) name.textContent = '—';
  if (value) value.textContent = '—';
  if (status) status.textContent = t('common.loading');
  openPanel(panel, trigger);
  try {
    const data = await api(`/api/v1/ssl/manual-dns/${encodeURIComponent(domain)}`);
    if (name) name.textContent = data.challenge_name || '—';
    if (value) value.textContent = data.challenge_value || '—';
    if (status) status.textContent = data.challenge_name ? t('ssl.manual_help') : t('common.not_available');
  } catch (error) {
    if (status) status.textContent = error.message;
  }
}

// ---------------------------------------------------------------- rows
async function rowAction(action, domain, trigger) {
  const row = trigger.closest('tr');
  const controls = row ? $$('button', row) : [];
  trigger.closest('details')?.removeAttribute('open');
  const base = `/api/v1/ssl/certificates/${encodeURIComponent(domain)}`;

  if (action === 'show-delegation') return showDelegation(domain, trigger);
  if (action === 'show-cname') return showCname(domain, trigger);
  if (action === 'manual-start') {
    const result = await runAction({
      key: `ssl:${action}:${domain}`,
      title: t('ssl.manual_start'),
      message: domain,
      trigger,
      controls,
      request: () => api(`${base}/manual-start`, { method: 'POST' }),
      onSuccess: loadSsl,
      successMessage: t('common.success'),
    });
    if (result) await openManualPanel(domain, trigger);
    return result;
  }
  if (action === 'convert-cloudflare') {
    return runAction({
      key: `ssl:${action}:${domain}`,
      title: t('ssl.convert_cloudflare'),
      message: domain,
      trigger,
      controls,
      input: {
        title: t('ssl.convert_cloudflare'),
        message: t('ssl.api_token'),
        inputLabel: t('ssl.api_token'),
        inputType: 'password',
        inputPlaceholder: '••••••••',
        confirmLabel: t('common.apply'),
      },
      request: (token) => api(`/api/v1/ssl/settings/${encodeURIComponent(domain)}`, {
        method: 'PUT',
        json: { provider: 'cloudflare', api_token: token, auto_renew: false },
      }),
      onSuccess: loadSsl,
      successMessage: t('common.success'),
    });
  }
  if (action === 'convert-hosted' || action === 'reregister-hosted') {
    const result = await runAction({
      key: `ssl:${action}:${domain}`,
      title: action === 'convert-hosted' ? t('ssl.convert_hosted') : t('ssl.reregister'),
      message: domain,
      trigger,
      controls,
      request: () => api(`${base}/hosted-acme/register`, { method: 'POST' }),
      onSuccess: loadSsl,
      silentSuccess: true,
    });
    if (result) await showCname(domain, trigger);
    return result;
  }
  if (action === 'verify-cname') {
    return runAction({
      key: `ssl:${action}:${domain}`,
      title: t('ssl.verify_cname'),
      message: domain,
      trigger,
      controls,
      request: () => api(`${base}/hosted-acme/verify`, { method: 'POST' }),
      onSuccess: async (result) => {
        await loadSsl();
        showResult(result.verified ? 'success' : 'error', {
          title: result.verified ? t('ssl.verify_ok', { domain }) : t('ssl.verify_failed', { domain }),
          message: result.last_verification_error || '',
          trigger,
        });
      },
      silentSuccess: true,
    });
  }
  if (action === 'verify-delegation') {
    return runAction({
      key: `ssl:${action}:${domain}`,
      title: t('ssl.verify_delegation'),
      message: domain,
      trigger,
      controls,
      request: () => api(`${base}/delegation/verify`, { method: 'POST' }),
      onSuccess: async (result) => {
        await loadSsl();
        showResult(result.verified ? 'success' : 'error', {
          title: result.verified ? t('ssl.verify_ok', { domain }) : t('ssl.verify_failed', { domain }),
          message: result.last_verification_error || '',
          trigger,
        });
      },
      silentSuccess: true,
    });
  }
  if (action === 'enable-auto-renew' || action === 'disable-auto-renew') {
    return runAction({
      key: `ssl:${action}:${domain}`,
      title: t(action === 'enable-auto-renew' ? 'ssl.enable_auto_renew' : 'ssl.disable_auto_renew'),
      message: domain,
      trigger,
      controls,
      request: () => api(`/api/v1/ssl/settings/${encodeURIComponent(domain)}`, {
        method: 'PUT',
        json: { auto_renew: action === 'enable-auto-renew' },
      }),
      onSuccess: loadSsl,
      successMessage: t('common.success'),
    });
  }
  if (action === 'test-renewal') {
    return runAction({
      key: `ssl:${action}:${domain}`,
      title: t('ssl.test_renewal'),
      message: domain,
      trigger,
      controls,
      request: () => api(`${base}/test-renewal`, { method: 'POST' }),
      onSuccess: loadSsl,
      successMessage: t('ssl.test_ok', { domain }),
    });
  }
  if (action === 'delete') {
    return runAction({
      key: `ssl:${action}:${domain}`,
      title: t('ssl.delete_title'),
      confirm: {
        title: t('ssl.delete_title'),
        message: t('ssl.delete_message', { domain }),
        confirmLabel: t('common.delete'),
        danger: true,
      },
      trigger,
      controls,
      request: () => api(base, { method: 'DELETE' }),
      onSuccess: loadSsl,
      successMessage: t('toast.deleted'),
    });
  }
  if (action === 'apply') {
    return runAction({
      key: `ssl:${action}:${domain}`,
      title: t('ssl.apply_vhost'),
      message: domain,
      trigger,
      controls,
      request: () => api(`${base}/apply`, { method: 'POST' }),
      successMessage: t('common.success'),
    });
  }
  return runAction({
    key: `ssl:${action}:${domain}`,
    title: t(action === 'issue' ? 'ssl.issue' : 'ssl.renew'),
    message: domain,
    trigger,
    controls,
    request: () => api(`${base}/${action}`, { method: 'POST' }),
    onSuccess: loadSsl,
    successMessage: action === 'issue'
      ? t('ssl.added', { domain })
      : t('common.success'),
  });
}

// ---------------------------------------------------------------- add form
function updateProviderFields() {
  const provider = $('[data-ssl-form]')?.provider?.value;
  const tokenField = $('[data-ssl-token-field]');
  if (tokenField) tokenField.hidden = provider !== 'cloudflare';
}

export async function init() {
  const panel = $('[data-ssl-panel]');
  const manual = $('[data-ssl-manual-panel]');
  wirePanel(panel);
  wirePanel(manual);

  $('[data-ssl-add]')?.addEventListener('click', () => {
    const form = $('[data-ssl-form]');
    form?.reset();
    updateProviderFields();
    openPanel(panel, document.activeElement, '#ssl-domain');
  });

  $('[data-ssl-provider]')?.addEventListener('change', updateProviderFields);

  $('[data-ssl-refresh]')?.addEventListener('click', (event) => runAction({
    key: 'ssl-refresh',
    title: t('common.refresh'),
    trigger: event.currentTarget,
    request: loadSsl,
    successMessage: t('common.success'),
  }));

  $('[data-ssl-table]')?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-ssl-action]');
    if (!button) return;
    rowAction(button.dataset.sslAction, button.dataset.sslDomain, button);
  });

  $('[data-ssl-manual-check]')?.addEventListener('click', async (event) => {
    const domain = manual?.dataset.domain;
    if (!domain) return;
    const status = $('[data-ssl-manual-status]', manual);
    await runAction({
      key: `ssl-manual-check:${domain}`,
      title: t('ssl.manual_check'),
      message: domain,
      trigger: event.currentTarget,
      request: () => api(`/api/v1/ssl/manual-dns/${encodeURIComponent(domain)}/check`, { method: 'POST' }),
      onSuccess: async (result) => {
        if (status) status.textContent = result.ready ? t('ssl.manual_ready') : t('ssl.manual_waiting');
        if (result.ready) {
          await loadSsl();
          setTimeout(() => closePanel(manual), 1800);
        }
      },
      successMessage: (result) => result?.ready ? t('ssl.manual_ready') : t('ssl.manual_waiting'),
    });
  });

  $('[data-ssl-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const requested = String(formData.get('provider') || 'cloudflare');
    const domain = String(formData.get('domain') || '').trim();
    const apiToken = String(formData.get('api_token') || '') || null;
    const redirect = form.elements.redirect_http.checked;
    const trigger = event.submitter || form;
    const payload = {
      domain,
      provider: requested === 'acme_dns_hosted' ? 'manual' : requested,
      api_token: requested === 'cloudflare' ? apiToken : null,
      auto_renew: false,
      redirect_http: redirect,
    };
    if (requested === 'cloudflare' && !apiToken) {
      $('[data-ssl-form]')?.elements.api_token?.focus();
      return;
    }
    let result = null;
    const created = await runAction({
      key: `ssl-add:${domain}`,
      title: t('ssl.add'),
      message: domain,
      trigger,
      request: async () => {
        result = await api('/api/v1/ssl/certificates', { method: 'POST', json: payload });
        if (requested === 'acme_dns_hosted') {
          result = await api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/hosted-acme/register`, { method: 'POST' });
        }
        return result;
      },
      onSuccess: async () => {
        closePanel(panel);
        await loadSsl();
      },
      successMessage: t('ssl.added', { domain }),
    });
    if (!created) return;
    if (requested === 'acme_dns_hosted') await showCname(domain, trigger);
    if (requested === 'acme_delegation') await showDelegation(domain, trigger);
  });

  updateProviderFields();
  try {
    await loadSsl();
  } catch (error) {
    toast(error.message, 'critical');
  }
}
