import {
  $, $$, api, escapeHtml, icon, t, toast,
  openPanel, closePanel, wirePanel, runAction, showResult,
} from '../core.js';

const state = { roles: [] };
const BUILTIN = new Set(['super_admin', 'admin', 'viewer']);
const canManage = () => document.body.dataset.canRoleManage === 'true';

function renderRoles() {
  const grid = $('[data-roles-grid]');
  if (!grid) return;
  const summary = $('[data-roles-summary]');
  if (summary) summary.textContent = String(state.roles.length);
  if (!state.roles.length) {
    grid.innerHTML = `<p class="muted">${escapeHtml(t('common.no_data'))}</p>`;
    return;
  }
  grid.innerHTML = state.roles.map((role) => {
    const builtin = BUILTIN.has(role.name);
    const editable = canManage() && role.name !== 'super_admin';
    const removable = canManage() && !builtin;
    return `<article class="role-card">
      <div class="card-head">
        <div>
          <p class="eyebrow">${builtin ? escapeHtml(t('roles.name')) : escapeHtml(t('roles.permissions'))}</p>
          <h2>${escapeHtml(role.name)}</h2>
          <p class="muted small">${escapeHtml(role.description || '')}</p>
        </div>
        <div class="toolbar-group">
          ${editable ? `<button class="btn btn-ghost btn-sm" type="button" data-role-edit="${role.id}">${icon('edit', 'icon icon-sm')}${escapeHtml(t('common.edit'))}</button>` : ''}
          ${removable ? `<button class="btn btn-ghost btn-sm btn-danger" type="button" data-role-delete="${role.id}">${icon('trash', 'icon icon-sm')}${escapeHtml(t('common.delete'))}</button>` : ''}
        </div>
      </div>
      <div class="permission-list">
        ${(role.permissions || []).map((permission) => `<span class="chip chip-info">${escapeHtml(permission)}</span>`).join('') || `<span class="muted small">${escapeHtml(t('common.no_data'))}</span>`}
      </div>
    </article>`;
  }).join('');
}

async function loadRoles() {
  state.roles = await api('/api/v1/roles');
  renderRoles();
}

function checkedPermissions(form) {
  return $$('input[name="permissions"]:checked', form).map((input) => input.value);
}

function openCreate(trigger) {
  const panel = $('[data-role-create-panel]');
  const form = $('[data-role-create-form]');
  if (!panel || !form) return;
  form.reset();
  $$('input[name="permissions"]', form).forEach((input) => { input.checked = false; });
  openPanel(panel, trigger, '#role-name');
}

function openEdit(role, trigger) {
  const panel = $('[data-role-panel]');
  const form = $('[data-role-form]');
  if (!panel || !form) return;
  form.elements.id.value = role.id;
  $$('input[name="permissions"]', form).forEach((input) => {
    input.checked = (role.permissions || []).includes(input.value);
  });
  const title = $('[data-role-panel-title]', panel);
  if (title) title.textContent = `${t('roles.edit')}: ${role.name}`;
  const description = $('[data-role-panel-description]', panel);
  if (description) description.textContent = role.description || '';
  openPanel(panel, trigger);
}

export async function init() {
  const createPanel = $('[data-role-create-panel]');
  const editPanel = $('[data-role-panel]');
  wirePanel(createPanel);
  wirePanel(editPanel);

  $('[data-role-add]')?.addEventListener('click', (event) => openCreate(event.currentTarget));

  $('[data-roles-refresh]')?.addEventListener('click', (event) => runAction({
    key: 'roles-refresh',
    title: t('common.refresh'),
    trigger: event.currentTarget,
    request: loadRoles,
    successMessage: t('common.success'),
  }));

  $('[data-roles-grid]')?.addEventListener('click', (event) => {
    const edit = event.target.closest('[data-role-edit]');
    if (edit) {
      const role = state.roles.find((row) => String(row.id) === String(edit.dataset.roleEdit));
      if (role) openEdit(role, edit);
      return;
    }
    const remove = event.target.closest('[data-role-delete]');
    if (!remove) return;
    const role = state.roles.find((row) => String(row.id) === String(remove.dataset.roleDelete));
    if (!role) return;
    runAction({
      key: `role-delete:${role.id}`,
      title: t('roles.delete_title'),
      confirm: {
        title: t('roles.delete_title'),
        message: t('roles.delete_message', { name: role.name }),
        confirmLabel: t('common.delete'),
        danger: true,
      },
      trigger: remove,
      request: () => api(`/api/v1/roles/${role.id}`, { method: 'DELETE' }),
      onSuccess: loadRoles,
      successMessage: t('toast.deleted'),
    });
  });

  $('[data-role-create-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const permissions = checkedPermissions(form);
    if (!permissions.length) {
      showResult('error', { title: t('roles.add'), message: t('roles.choose_permissions'), trigger: event.submitter || form });
      return;
    }
    const data = new FormData(form);
    await runAction({
      key: 'role-create',
      title: t('roles.add'),
      message: String(data.get('name') || ''),
      trigger: event.submitter || form,
      request: () => api('/api/v1/roles', {
        method: 'POST',
        json: {
          name: String(data.get('name') || '').trim(),
          description: String(data.get('description') || '').trim() || null,
          permissions,
        },
      }),
      onSuccess: async () => {
        closePanel(createPanel);
        await loadRoles();
      },
      successMessage: (role) => t('roles.created', { name: role.name }),
    });
  });

  $('[data-role-form]')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const id = form.elements.id.value;
    const permissions = checkedPermissions(form);
    if (!permissions.length) {
      showResult('error', { title: t('roles.edit'), message: t('roles.choose_permissions'), trigger: event.submitter || form });
      return;
    }
    await runAction({
      key: `role-save:${id}`,
      title: t('roles.edit'),
      trigger: event.submitter || form,
      request: () => api(`/api/v1/roles/${id}/permissions`, { method: 'PUT', json: { permissions } }),
      onSuccess: async () => {
        closePanel(editPanel);
        await loadRoles();
      },
      successMessage: t('roles.saved'),
    });
  });

  try {
    await loadRoles();
  } catch (error) {
    toast(error.message, 'critical');
  }
}
