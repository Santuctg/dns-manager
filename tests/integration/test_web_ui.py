from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.auth import Permission, Role, User
from app.security import hash_password
from app.services.auth_service import ALL_PERMISSIONS, ADMIN_PERMISSIONS, VIEWER_PERMISSIONS, create_session


def make_web_env(role_name: str | None = None):
    engine = create_engine(
        'sqlite+pysqlite:///:memory:',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    raw_session = None
    with Session(engine) as db:
        perms = {name: Permission(name=name) for name in sorted(ALL_PERMISSIONS)}
        db.add_all(perms.values())
        roles = {
            'super_admin': Role(name='super_admin', permissions=[perms[n] for n in sorted(ALL_PERMISSIONS)]),
            'admin': Role(name='admin', permissions=[perms[n] for n in sorted(ADMIN_PERMISSIONS)]),
            'viewer': Role(name='viewer', permissions=[perms[n] for n in sorted(VIEWER_PERMISSIONS)]),
        }
        db.add_all(roles.values())
        db.flush()
        if role_name:
            user = User(
                username=f'{role_name}-user',
                email=f'{role_name}@example.com',
                password_hash=hash_password('very-secure-password'),
                role=roles[role_name],
            )
            db.add(user)
            db.commit()
            raw_session = create_session(db, user, 'csrf-token')
        else:
            db.commit()

    def override_db():
        with Session(engine) as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app, base_url='https://testserver', follow_redirects=False)
    if raw_session:
        client.cookies.set('dns_manager_session', raw_session)
        client.cookies.set('dns_manager_csrf', 'csrf-token')
    return client


def cleanup():
    app.dependency_overrides.clear()


def test_public_login_page_and_root_redirect():
    client = make_web_env()
    try:
        root = client.get('/')
        assert root.status_code == 303
        assert root.headers['location'] == '/login'
        login = client.get('/login')
        assert login.status_code == 200
        assert 'DNS Manager' in login.text
        assert 'Sign in' in login.text
        assert '/static/app.js' in login.text
        assert 'https://' not in login.text
        assert 'http://' not in login.text
    finally:
        cleanup()


def test_unauthenticated_app_page_redirects_to_login_with_next():
    client = make_web_env()
    try:
        response = client.get('/app/dashboard')
        assert response.status_code == 303
        assert response.headers['location'] == '/login?next=/app/dashboard'
    finally:
        cleanup()


def test_viewer_gets_read_only_navigation_and_no_write_controls():
    client = make_web_env('viewer')
    try:
        response = client.get('/app/mappings')
        assert response.status_code == 200
        assert 'Mappings' in response.text
        assert 'Audit' in response.text
        assert 'System' in response.text
        assert 'data-action="mapping-create"' not in response.text
        assert 'data-action="config-apply"' not in response.text
        assert '>Users<' not in response.text
        assert '>Roles<' not in response.text
    finally:
        cleanup()


def test_admin_sees_mapping_apply_and_user_controls_but_not_role_manage():
    client = make_web_env('admin')
    try:
        mappings = client.get('/app/mappings')
        assert mappings.status_code == 200
        assert 'data-action="mapping-create"' in mappings.text
        assert 'data-action="config-apply"' in mappings.text

        users = client.get('/app/users')
        assert users.status_code == 200
        assert 'data-action="user-create"' in users.text

        roles = client.get('/app/roles')
        assert roles.status_code == 200
        assert 'data-action="role-permissions-save"' not in roles.text
    finally:
        cleanup()


def test_super_admin_sees_all_management_navigation_and_role_controls():
    client = make_web_env('super_admin')
    try:
        response = client.get('/app/roles')
        assert response.status_code == 200
        assert '>Users<' in response.text
        assert '>Roles<' in response.text
        assert 'data-action="role-permissions-save"' in response.text
        assert 'data-can-rollback="true"' in response.text
    finally:
        cleanup()


def test_dashboard_audit_and_system_have_expected_data_hooks():
    client = make_web_env('super_admin')
    try:
        dashboard = client.get('/app/dashboard')
        assert dashboard.status_code == 200
        assert 'data-page="dashboard"' in dashboard.text
        assert 'data-dashboard-status' in dashboard.text
        assert 'data-backend-summary' in dashboard.text

        audit = client.get('/app/audit')
        assert audit.status_code == 200
        assert 'data-page="audit"' in audit.text
        assert 'data-audit-table' in audit.text

        system = client.get('/app/system')
        assert system.status_code == 200
        assert 'data-page="system"' in system.text
        assert 'data-config-preview' in system.text
        assert 'data-action="config-validate"' in system.text
    finally:
        cleanup()


def test_local_static_assets_are_served_and_reference_no_external_resources():
    client = make_web_env()
    try:
        css = client.get('/static/app.css')
        js = client.get('/static/app.js')
        assert css.status_code == 200
        assert js.status_code == 200
        for body in (css.text, js.text):
            assert 'https://' not in body
            assert 'http://' not in body
            assert 'cdn.' not in body.lower()
        assert 'X-CSRF-Token' in js.text
        assert '/api/v1/auth/login' in js.text
        assert '/api/v1/mappings' in js.text
        assert '/api/v1/users' in js.text
        assert '/api/v1/roles' in js.text
        assert '/api/v1/audit' in js.text
        assert '/api/v1/system/status' in js.text
    finally:
        cleanup()


def test_system_backup_controls_are_super_admin_only():
    super_client = make_web_env('super_admin')
    try:
        system = super_client.get('/app/system')
        assert system.status_code == 200
        assert 'data-backup-section' in system.text
        assert 'data-action="backup-create"' in system.text
        assert 'data-backups-table' in system.text
    finally:
        cleanup()

    admin_client = make_web_env('admin')
    try:
        system = admin_client.get('/app/system')
        assert system.status_code == 200
        assert 'data-backup-section' not in system.text
        assert 'data-action="backup-create"' not in system.text
    finally:
        cleanup()


def test_modal_cancel_and_close_controls_never_submit_forms():
    client = make_web_env('super_admin')
    try:
        for path in ('/app/mappings', '/app/users', '/app/roles'):
            response = client.get(path)
            assert response.status_code == 200
            html = response.text
            assert 'value="cancel"' not in html
            assert 'type="button" data-dialog-close' in html

        js = client.get('/static/app.js')
        assert js.status_code == 200
        assert "[data-dialog-close]" in js.text
        assert ".closest('dialog')?.close()" in js.text
    finally:
        cleanup()


def test_system_backup_delete_ui_is_super_admin_only_and_confirms_irreversible_delete():
    client = make_web_env('super_admin')
    try:
        system = client.get('/app/system')
        assert system.status_code == 200
        js = client.get('/static/app.js')
        assert js.status_code == 200
        assert 'data-delete-backup' in js.text
        assert 'This cannot be undone' in js.text
        assert "method:'DELETE'" in js.text
        assert 'Backup deleted.' in js.text
    finally:
        cleanup()

def test_system_template_contains_superadmin_ssl_controls():
    html = open('app/templates/system.html').read()
    assert 'SSL / Certificates' in html
    assert 'data-ssl-section' in html
    assert 'type="password"' in html
    assert 'data-action="ssl-issue"' in html

def test_ssl_manual_ui_polls_for_challenge_without_restarting_certbot():
    js = open('app/static/app.js').read()
    assert 'pollManual' in js
    assert 'manual-start' in js


def test_ssl_ui_hides_manual_challenge_for_existing_issued_certificate():
    client = make_web_env('super_admin')
    try:
        js = client.get('/static/app.js')
        assert js.status_code == 200
        assert "c.provider==='manual'&&['NOT_ISSUED','ERROR'].includes(c.status)" in js.text
        assert "Start DNS challenge" in js.text
        assert "const manualStart=c.provider==='manual'&&['NOT_ISSUED','ERROR'].includes(c.status)" in js.text
    finally:
        cleanup()


def test_ssl_ui_supports_manual_to_cloudflare_conversion_and_auto_renew_gate():
    js = open('app/static/app.js').read()
    assert 'Convert to Cloudflare' in js
    assert 'Cloudflare API token for' in js
    assert "data-ssl-action=\"convert-cloudflare\"" in js
    assert 'Enable auto renew' in js
    assert 'Disable auto renew' in js
    assert "last_renewal_status==='TEST_SUCCESS'" in js
    assert "method:'PUT'" in js


def test_ssl_ui_keeps_legacy_acme_rows_manageable_but_does_not_offer_new_conversion():
    html=open('app/templates/system.html').read()
    js=open('app/static/app.js').read()
    assert 'value="acme_delegation"' not in html
    assert 'data-acme-delegation-panel' in html
    assert 'Convert to ACME Delegation' not in js
    assert 'Show delegation' in js
    assert 'Verify delegation' in js
    assert '/delegation/verify' in js
    assert "c.provider==='acme_delegation'" in js
    assert "c.delegation_verified" in js


def test_system_ui_hides_acme_provider_status_cards_but_keeps_ssl_workflow():
    html=open('app/templates/system.html').read()
    assert 'Hosted DNS-01 provider' not in html
    assert 'Self-hosted authoritative delegation' not in html
    assert 'data-hosted-acme-status' not in html
    assert 'data-acme-dns-status' not in html
    assert 'data-hosted-acme-panel' not in html
    assert 'value="acme_dns_hosted"' in html
    assert 'data-action-modal' in open('app/templates/base.html').read()


def test_system_ui_exposes_hosted_acme_workflow_for_super_admin():
    client=make_web_env('super_admin')
    try:
        html=client.get('/app/system').text
        js=(__import__('pathlib').Path('app/static/app.js')).read_text()
        assert 'Hosted ACME-DNS' in html
        assert 'data-hosted-acme-panel' not in html
        assert 'showHostedCnameModal' in js
        assert 'convert-hosted' in js
        assert '/hosted-acme/register' in js
        assert '/hosted-acme/verify' in js
    finally:
        app.dependency_overrides.clear()


def test_ssl_action_row_uses_reusable_modal_feedback_ui():
    client = make_web_env('super_admin')
    try:
        base = client.get('/app/system')
        assert base.status_code == 200
        html = base.text
        assert 'data-action-modal' in html
        assert 'data-action-modal-title' in html
        assert 'data-action-modal-body' in html
        assert 'data-action-modal-cancel' in html
        assert 'data-action-modal-confirm' in html

        js = client.get('/static/app.js')
        assert js.status_code == 200
        text = js.text
        assert 'showActionModal' in text
        assert 'showActionResult' in text
        assert 'setActionModalBusy' in text
        assert 'showHostedCnameModal' in text
        assert 'Copy Name' in text
        assert 'Copy Target' in text
        assert "data-ssl-action=\"show-hosted\"" in text
    finally:
        cleanup()


def test_hosted_cname_is_modal_only_not_inline_system_panel():
    client = make_web_env('super_admin')
    try:
        system = client.get('/app/system')
        assert system.status_code == 200
        html = system.text
        assert 'data-hosted-acme-panel' not in html
        assert 'data-hosted-acme-cname-name' not in html
        assert 'data-hosted-acme-cname-target' not in html
    finally:
        cleanup()


def test_ssl_action_modal_has_non_submitting_controls_and_loading_state():
    client = make_web_env('super_admin')
    try:
        system = client.get('/app/system')
        html = system.text
        assert 'type="button" data-action-modal-cancel' in html
        assert 'type="button" data-action-modal-confirm' in html
        assert 'data-action-modal-spinner' in html

        js = client.get('/static/app.js')
        text = js.text
        assert "setModalPresentation('loading'" in text
        assert "showResult('success'" in text
        assert "showResult('error'" in text
    finally:
        cleanup()


def test_action_modal_hidden_regions_are_forced_off_by_css():
    css = Path("app/static/app.css").read_text()
    assert ".action-modal [hidden]{display:none!important}" in css


def test_global_action_modal_core_contract_for_050():
    base = Path('app/templates/base.html').read_text()
    js = Path('app/static/app.js').read_text()
    css = Path('app/static/app.css').read_text()
    assert 'aria-labelledby="action-modal-title"' in base
    assert 'aria-describedby="action-modal-description"' in base
    assert 'id="action-modal-title"' in base
    assert 'id="action-modal-description"' in base
    for symbol in (
        'resetActionModal', 'showLoading', 'showSuccess', 'showError',
        'showWarning', 'showInfo', 'confirmAction', 'promptAction',
        'closeActionModal', 'trapActionModalFocus', 'restoreActionModalFocus'
    ):
        assert symbol in js
    assert 'lastActionTrigger' in js
    assert "e.key==='Tab'" in js or 'e.key === \'Tab\'' in js
    assert 'action-modal-open' in css
    assert '.action-modal [hidden]{display:none!important}' in css


def test_global_action_runner_contract_for_050():
    js = Path('app/static/app.js').read_text()
    for symbol in ('normalizeActionResponse', 'runAction', 'withBusyControls', 'activeActionKeys'):
        assert symbol in js
    assert 'textContent' in js
    assert 'finally' in js
    assert 'response.status === 204' in js or 'response.status===204' in js


def test_global_modal_page_adapters_exist_for_all_action_pages():
    js = Path('app/static/app.js').read_text()
    for adapter in ('mappingActions', 'userActions', 'roleActions', 'systemActions', 'backupActions', 'auditActions', 'dashboardActions', 'sslActions'):
        assert adapter in js


def test_mapping_actions_use_global_modal_runner():
    js=Path('app/static/app.js').read_text()
    for token in ('mappingActions.save', 'mappingActions.delete', 'mappingActions.apply'):
        assert token in js
    assert "title:'Delete mapping?'" in js
    assert "title:'Applying configuration'" in js


def test_user_actions_use_global_modal_runner_and_password_flow():
    js=Path('app/static/app.js').read_text()
    for token in ('userActions.save', 'userActions.disable', 'userActions.resetPassword'):
        assert token in js
    assert "title:'Disable user?'" in js
    assert 'Password reset and sessions revoked.' in js


def test_role_actions_use_global_modal_runner():
    js=Path('app/static/app.js').read_text()
    assert 'roleActions.savePermissions' in js
    assert 'Role permissions updated.' in js


def test_system_and_backup_actions_use_global_modal_runner():
    js=Path('app/static/app.js').read_text()
    for token in ('systemActions.validate', 'systemActions.apply', 'systemActions.rollback', 'backupActions.create', 'backupActions.restore', 'backupActions.delete'):
        assert token in js
    assert "title:'Rollback revision?'" in js
    assert 'This cannot be undone' in js


def test_audit_dashboard_and_ssl_actions_use_global_modal_api():
    js=Path('app/static/app.js').read_text()
    assert 'auditActions.filter' in js
    assert 'dashboardActions.refresh' in js
    assert 'sslActions.run' in js
    assert 'sslActions.manualCheck' in js


def test_no_native_dialogs_or_normal_action_flash_remain_in_050():
    js=Path('app/static/app.js').read_text()
    for token in ('window.confirm', 'window.prompt', 'window.alert'):
        assert token not in js
    assert js.count('flash(') == 1  # app-wide initialization failure only
    assert 'data-flash' in Path('app/templates/base.html').read_text()


def test_backup_upload_and_role_create_controls_are_exposed_to_authorized_users():
    client = make_web_env('super_admin')
    try:
        system = client.get('/app/system')
        roles = client.get('/app/roles')
        js = client.get('/static/app.js').text
        assert 'data-action="backup-upload"' in system.text
        assert 'data-backup-upload-dialog' in system.text
        assert 'accept=".tar.gz,.tgz,application/gzip"' in system.text
        assert '/api/v1/backups/upload' in js
        assert 'X-Backup-Filename' in js

        assert 'data-action="role-create"' in roles.text
        assert 'data-role-create-dialog' in roles.text
        assert 'name="description"' in roles.text
        assert "api('/api/v1/roles',{method:'POST'" in js
    finally:
        cleanup()


def test_role_delete_control_and_global_confirmation_are_wired_for_custom_roles():
    client = make_web_env('super_admin')
    try:
        roles = client.get('/app/roles')
        js = client.get('/static/app.js').text
        assert 'data-delete-role' in js
        assert 'roleActions.delete' in js
        assert "method:'DELETE'" in js
        assert "title:'Delete role?'" in js
        assert 'assigned users' in js.lower()
        assert 'ROLE_DELETED' not in roles.text  # action is handled by API/audit, not hard-coded into page markup
    finally:
        cleanup()


def test_super_admin_system_has_structured_firewall_ui():
    client=make_web_env('super_admin')
    try:
        response=client.get('/app/system'); assert response.status_code==200
        assert 'Firewall (UFW)' in response.text
        assert 'data-action="firewall-add"' in response.text
        assert 'data-action="firewall-apply"' in response.text
        assert 'data-action="firewall-rollback"' in response.text
        assert 'name="source_cidrs"' in response.text
        assert 'raw UFW commands' in response.text
        assert 'name="command"' not in response.text
    finally: cleanup()

def test_viewer_system_sees_firewall_restricted_without_mutation_controls():
    client=make_web_env('viewer')
    try:
        response=client.get('/app/system'); assert 'Firewall (UFW)' in response.text
        assert 'firewall.manage' in response.text
        assert 'data-action="firewall-add"' not in response.text
        assert 'data-action="firewall-apply"' not in response.text
    finally: cleanup()

def test_action_modal_native_close_event_does_not_resolve_confirmation_promise():
    """A stale dialog close event must not resolve the next confirmation."""
    js = Path("app/static/app.js").read_text()

    marker = "actionModal()?.addEventListener('close',()=>{"
    assert marker in js

    close_handler = js.split(marker, 1)[1].split("});", 1)[0]

    assert "actionModalResolver" not in close_handler
    assert "resolve(" not in close_handler



def test_060_design_system_has_overflow_safe_foundation():
    css = Path('app/static/app.css').read_text()
    compact = css.replace(' ', '')
    assert 'box-sizing:border-box' in compact
    assert 'min-width:0' in compact
    assert 'overflow-wrap:anywhere' in compact
    assert '--sidebar-width:' in css
    assert '--control-height:' in css
    assert '.machine-value' in css
    assert '.content-stack' in css
    assert 'body{overflow-x:hidden' not in compact


def test_060_shell_and_login_have_modern_responsive_wrappers():
    base = Path('app/templates/base.html').read_text()
    login = Path('app/templates/login.html').read_text()
    css = Path('app/static/app.css').read_text()
    assert 'class="page-content"' in base
    assert 'aria-label="Primary navigation"' in base
    assert 'data-action="logout"' in base
    assert 'data-global-status' in base
    assert 'class="login-shell"' in login
    assert 'grid-template-columns:repeat(3,1fr)' not in css.replace(' ', '')


def test_060_tables_forms_and_long_values_are_responsive():
    css = Path('app/static/app.css').read_text()
    for token in ('.table-wrap', '.row-actions', '.responsive-form', '.machine-value', '.toolbar-group'):
        assert token in css
    compact = css.replace(' ', '')
    assert '.table-wrap{overflow-x:auto' in compact
    assert 'max-width:100%' in compact
    for name in ('mappings.html', 'users.html', 'audit.html', 'system.html'):
        html = Path('app/templates', name).read_text()
        assert 'class="table-wrap"' in html


def test_060_modals_are_viewport_constrained_and_scroll_internally():
    css = Path('app/static/app.css').read_text().replace(' ', '')
    base = Path('app/templates/base.html').read_text()
    system = Path('app/templates/system.html').read_text()
    js = Path('app/static/app.js').read_text()
    assert 'max-height:' in css
    assert 'overflow-y:auto' in css
    assert 'data-action-modal-confirm' in base
    assert 'data-firewall-dialog' in system
    assert 'data-firewall-form' in system
    assert "actionModal()?.addEventListener('close'" in js


def test_060_system_dense_forms_use_named_responsive_layouts():
    html = Path('app/templates/system.html').read_text()
    assert 'class="rollback-form responsive-form"' in html
    assert 'class="firewall-policy responsive-form"' in html
    assert 'class="ssl-form responsive-form"' in html
    for hook in (
        'data-system-status', 'data-action="config-validate"', 'data-action="config-apply"',
        'data-firewall-section', 'data-firewall-rules', 'data-action="firewall-preview"',
        'data-action="firewall-validate"', 'data-action="firewall-apply"',
        'data-action="firewall-rollback"', 'data-firewall-dialog', 'data-ssl-section'
    ):
        assert hook in html


def test_060_all_primary_pages_use_common_content_contract():
    for name in ('dashboard.html', 'mappings.html', 'users.html', 'roles.html', 'audit.html', 'system.html'):
        html = Path('app/templates', name).read_text()
        assert 'class="content-stack"' in html
    css = Path('app/static/app.css').read_text()
    for token in ('@media(max-width:1024px)', '@media(max-width:720px)', '@media(max-width:560px)'):
        assert token in css.replace(' ', '')


def test_060_system_checkbox_controls_use_inline_check_alignment():
    html = Path('app/templates/system.html').read_text()
    assert '<label class="check"><input type="checkbox" data-firewall-enabled> Enable UFW</label>' in html
    assert '<label class="check"><input name="auto_renew" type="checkbox"> Auto renew after successful test</label>' in html
    assert '<label class="check"><input name="redirect_http" type="checkbox" checked> HTTP → HTTPS</label>' in html


def test_061_audit_table_keeps_row_values_on_single_lines():
    html = Path('app/templates/audit.html').read_text()
    css = Path('app/static/app.css').read_text().replace(' ', '')
    assert 'class="audit-table"' in html
    assert '.audit-table{min-width:' in css
    assert '.audit-tableth,.audit-tabletd{white-space:nowrap' in css
    assert '.audit-table.badge{white-space:nowrap' in css


def test_062_audit_detail_wraps_but_primary_columns_stay_single_line():
    css = Path('app/static/app.css').read_text().replace(' ', '')

    assert '.audit-tableth,.audit-tabletd{white-space:nowrap' in css
    assert '.audit-tabletd:nth-child(3).muted.small{white-space:normal' in css
    assert 'overflow-wrap:anywhere' in css


def test_063_firewall_helper_copy_is_removed_and_ssl_status_badges_have_gap():
    html = Path('app/templates/system.html').read_text()
    css = Path('app/static/app.css').read_text().replace(' ', '')

    assert 'Restrictive apply is protected by SSH-path validation' not in html
    assert 'After Apply, click <strong>Keep firewall changes</strong> to confirm.' not in html
    assert '[data-ssl-table]td:nth-child(3).badge+.badge{margin-left:' in css


def test_064_ssl_table_keeps_primary_cells_single_line_and_stacks_status_badges():
    html = Path('app/templates/system.html').read_text()
    css = Path('app/static/app.css').read_text().replace(' ', '')

    assert '<table class="ssl-table">' in html
    assert '.ssl-table{min-width:' in css
    assert '.ssl-tableth,.ssl-tabletd{white-space:nowrap' in css
    assert '.ssl-tabletd:nth-child(3){white-space:normal' in css
    assert '.ssl-tabletd:nth-child(3).badge{display:flex' in css
    assert '.ssl-tabletd:nth-child(3).badge+.badge{margin-left:0;margin-top:' in css
    assert '.ssl-table.row-actions{flex-wrap:nowrap' in css
    assert '.table-wrap{overflow-x:auto' in css


def test_065_mobile_layout_polishes_small_viewports_without_page_overflow_hacks():
    css = Path('app/static/app.css').read_text().replace(' ', '')

    assert '.table-wrap{overflow-x:auto' in css
    assert 'overscroll-behavior-inline:contain' in css
    assert '@media(max-width:720px)' in css
    assert '.subhead{flex-wrap:wrap;align-items:flex-start}' in css
    assert '@media(max-width:560px)' in css
    assert '.card-head>.btn{width:100%}' in css
    assert '.status-row{align-items:flex-start;flex-direction:column}' in css
    assert '.nav-list{scroll-snap-type:xproximity}' in css
    assert '.nav-item{scroll-snap-align:start}' in css
    assert 'body{overflow-x:hidden' not in css

def test_firewall_multi_source_editor_has_repeatable_accessible_inputs_and_actions():
    from pathlib import Path
    html=Path('app/templates/system.html').read_text()
    js=Path('app/static/app.js').read_text()
    assert 'data-firewall-source-list' in html
    assert 'data-firewall-source-add' in html
    assert 'data-firewall-source-remove' in js
    assert "source_cidrs:" in js
    assert 'source_cidrs||' in js
    assert 'source-limit' in js
