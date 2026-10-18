(() => {
  const page = document.body.dataset.page || window.DNS_MANAGER_PAGE || 'login';
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const cookie = (name) => document.cookie.split('; ').find(x => x.startsWith(`${name}=`))?.split('=').slice(1).join('=') || '';
  const csrf = () => decodeURIComponent(cookie('dns_manager_csrf'));
  const flash = (message, type = 'success') => { const el = $('[data-flash]'); if (!el) return; el.textContent = message; el.className = `flash ${type}`; el.hidden = false; setTimeout(() => { el.hidden = true; }, 5000); };
  const detail = async (response) => { try { const body = await response.json(); return typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail || body); } catch { return `${response.status} ${response.statusText}`; } };
  const api = async (url, options = {}) => {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    if (options.json !== undefined) { headers.set('Content-Type', 'application/json'); options.body = JSON.stringify(options.json); delete options.json; }
    if (!['GET','HEAD','OPTIONS'].includes(method)) { const token = csrf(); if (!token) throw new Error('CSRF token missing. Sign in again.'); headers.set('X-CSRF-Token', token); }
    const response = await fetch(url, {...options, method, headers, credentials: 'same-origin'});
    if (response.status === 401) { location.assign(`/login?next=${encodeURIComponent(location.pathname)}`); throw new Error('Authentication required'); }
    if (!response.ok) throw new Error(await detail(response));
    if (response.status === 204) return null;
    return response.json();
  };
  const renderConfigPreview = (p) => {
    if (!p || typeof p.dnsmasq_config !== 'string' || typeof p.nginx_config !== 'string') {
      throw new Error('Configuration preview is missing required DNS/Nginx fields.');
    }
    const dns = $('[data-preview-dns]'), nginx = $('[data-preview-nginx]');
    if (dns) dns.textContent = p.dnsmasq_config || 'No dnsmasq configuration generated.';
    if (nginx) nginx.textContent = p.nginx_config || 'No Nginx configuration generated.';
  };
  const badge = (value) => { const v = String(value || 'UNKNOWN').toUpperCase(); const cls = ['UP','ACTIVE','READY','OK','ENABLED','SUCCESS','SAFE'].includes(v) ? 'good' : ['DOWN','HTTP_ERROR','TLS_ERROR','TIMEOUT','FAILED','ERROR','DISABLED','UNSAFE'].includes(v) ? 'bad' : 'warn'; return `<span class="badge ${cls}">${escapeHtml(v)}</span>`; };
  const actionModal = () => $('[data-action-modal]');
  let lastActionTrigger = null;
  let actionModalResolver = null;
  const activeActionKeys = new Set();

  const actionModalElements = () => {
    const modal = actionModal();
    return modal ? {
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
    } : null;
  };

  const resetActionModal = () => {
    const x = actionModalElements(); if (!x) return null;
    const {modal,title,kicker,body,icon,spinner,inputWrap,inputLabel,input,cancel,confirm,close} = x;
    modal.dataset.state = 'info';
    modal.dataset.blocking = 'false';
    icon.textContent = 'i'; kicker.textContent = 'DNS Manager action'; title.textContent = 'Action';
    body.replaceChildren();
    spinner.hidden = true;
    inputWrap.hidden = true; inputLabel.textContent = 'Value'; input.type = 'text'; input.placeholder = ''; input.value=''; input.required=false;
    cancel.hidden = true; cancel.textContent = 'Cancel'; cancel.disabled = false; cancel.onclick = null;
    confirm.hidden = false; confirm.textContent = 'Close'; confirm.className = 'btn btn-primary'; confirm.disabled = false; confirm.onclick = null;
    close.hidden = false; close.disabled = false; close.onclick = null;
    modal.oncancel = null;
    return x;
  };

  const rememberActionTrigger = (trigger = document.activeElement) => { if (trigger instanceof HTMLElement) lastActionTrigger = trigger; };
  const restoreActionModalFocus = () => { const el=lastActionTrigger; lastActionTrigger=null; if(el && document.contains(el) && typeof el.focus==='function') setTimeout(()=>el.focus(),0); };
  const closeActionModal = (value = null) => {
    const modal = actionModal(); if (!modal) return;
    if (modal.open) modal.close();
    document.body.classList.remove('action-modal-open');
    if (actionModalResolver) { const resolve=actionModalResolver; actionModalResolver=null; resolve(value); }
    restoreActionModalFocus();
    const x=actionModalElements(); if(x?.input) x.input.value='';
  };
  const focusableActionModal = () => $$('button:not([hidden]):not(:disabled),input:not([hidden]):not(:disabled),select:not([hidden]):not(:disabled),textarea:not([hidden]):not(:disabled),a[href]', actionModal()).filter(el=>el.offsetParent!==null || el===document.activeElement);
  const trapActionModalFocus = (e) => {
    if(e.key === 'Tab'){
    const items=focusableActionModal(); if(!items.length)return;
    const first=items[0],last=items[items.length-1];
    if(e.shiftKey && document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey && document.activeElement===last){e.preventDefault();first.focus();}
    }
  };
  const openActionModal = ({trigger=document.activeElement, blocking=false, focusSelector=null}={}) => {
    const x=actionModalElements(); if(!x)return null;
    rememberActionTrigger(trigger); x.modal.dataset.blocking=blocking?'true':'false';
    if(!x.modal.open)x.modal.showModal(); document.body.classList.add('action-modal-open');
    setTimeout(()=>{const target=focusSelector?$(focusSelector,x.modal):focusableActionModal()[0];target?.focus();},0);
    return x;
  };
  const appendMessage = (body, message, detail='') => {
    if(message){const p=document.createElement('p');p.textContent=String(message);body.appendChild(p);}
    if(detail){const d=document.createElement('div');d.className='action-modal-detail';d.textContent=String(detail);body.appendChild(d);}
  };
  const setModalPresentation = (state,title,message,{detail='',kicker='',trigger=document.activeElement}={}) => {
    const x=resetActionModal(); if(!x)return;
    x.modal.dataset.state=state;
    x.icon.textContent=state==='success'?'✓':state==='error'?'!':state==='warning'?'!':state==='loading'?'↻':'i';
    x.kicker.textContent=kicker || (state==='success'?'Completed':state==='error'?'Action failed':state==='warning'?'Attention':state==='loading'?'Working':'Information');
    x.title.textContent=title; appendMessage(x.body,message,detail);
    openActionModal({trigger,blocking:state==='loading'});
    return x;
  };
  const showLoading = ({title='Working',message='Please wait while DNS Manager completes this action.',trigger=document.activeElement}={}) => {
    const x=setModalPresentation('loading',title,message,{trigger}); if(!x)return;
    x.spinner.hidden=false;x.confirm.hidden=true;x.close.disabled=true;
  };
  const showResult = (state,{title,message='',detail='',trigger=document.activeElement}={}) => {
    const x=setModalPresentation(state,title,message,{detail,trigger}); if(!x)return;
    x.cancel.hidden=true;x.confirm.hidden=false;x.confirm.textContent='Close';x.close.disabled=false;
    x.confirm.onclick=()=>closeActionModal();x.close.onclick=()=>closeActionModal();
  };
  const showSuccess = opts => showResult('success',opts);
  const showError = opts => showResult('error',opts);
  const showWarning = opts => showResult('warning',opts);
  const showInfo = opts => showResult('info',opts);
  const confirmAction = ({title='Confirm action',message='',detail='',confirmLabel='Continue',cancelLabel='Cancel',danger=false,trigger=document.activeElement}={}) => new Promise(resolve=>{
    const x=setModalPresentation(danger?'warning':'info',title,message,{detail,trigger}); if(!x)return resolve(false);
    x.modal.dataset.blocking='true';x.cancel.hidden=false;x.cancel.textContent=cancelLabel;x.confirm.textContent=confirmLabel;x.confirm.className=danger?'btn btn-danger':'btn btn-primary';
    actionModalResolver=resolve;x.cancel.onclick=()=>closeActionModal(false);x.close.onclick=()=>closeActionModal(false);x.confirm.onclick=()=>closeActionModal(true);
    x.modal.oncancel=e=>{e.preventDefault();closeActionModal(false);};
  });
  const promptAction = ({title='Enter value',message='',inputLabel='Value',inputType='text',inputPlaceholder='',inputValue='',required=true,confirmLabel='Continue',cancelLabel='Cancel',danger=false,trigger=document.activeElement}={}) => new Promise(resolve=>{
    const x=setModalPresentation(danger?'warning':'info',title,message,{trigger}); if(!x)return resolve(null);
    x.modal.dataset.blocking='true';x.inputWrap.hidden=false;x.inputLabel.textContent=inputLabel;x.input.type=inputType;x.input.placeholder=inputPlaceholder;x.input.value=inputValue;x.input.required=required;
    x.cancel.hidden=false;x.cancel.textContent=cancelLabel;x.confirm.textContent=confirmLabel;x.confirm.className=danger?'btn btn-danger':'btn btn-primary';
    actionModalResolver=resolve;x.cancel.onclick=()=>closeActionModal(null);x.close.onclick=()=>closeActionModal(null);x.confirm.onclick=()=>{const value=x.input.value.trim();if(required&&!value){x.input.focus();return;}closeActionModal(value);};
    x.modal.oncancel=e=>{e.preventDefault();closeActionModal(null);};setTimeout(()=>x.input.focus(),0);
  });

  const sanitizeActionText = value => String(value ?? '').replace(/(api[_ -]?key|token|password)\s*[:=]\s*\S+/gi,'$1: [redacted]');
  const normalizeActionResponse = async response => {
    let body=null; if(response.status !== 204){try{body=await response.json();}catch{try{body={detail:await response.text()};}catch{body=null;}}}
    const raw=body?.detail ?? body?.message ?? body?.status ?? '';
    const message=typeof raw==='string'?raw:(raw?JSON.stringify(raw):'');
    return {ok:response.ok,title:response.ok?'Completed':'Action failed',message:sanitizeActionText(message || (response.ok?'Action completed successfully.':`${response.status} ${response.statusText}`)),detail:'',code:response.status};
  };
  const withBusyControls = async (trigger,controls,fn) => {
    const list=[...new Set([trigger,...(controls||[])].filter(Boolean))]; const before=list.map(el=>el.disabled);
    list.forEach(el=>{el.disabled=true;el.setAttribute('aria-busy','true');});
    try{return await fn();}finally{list.forEach((el,i)=>{el.disabled=before[i];el.removeAttribute('aria-busy');});}
  };
  const runAction = async ({key,title,message='',successTitle='Completed',successMessage='Action completed successfully.',confirm=null,input=null,trigger=document.activeElement,controls=[],request,onSuccess=null,silentSuccess=false}={}) => {
    const actionKey=key||`${title}:${message}`; if(activeActionKeys.has(actionKey))return null;
    activeActionKeys.add(actionKey);
    try{
      if(confirm){const ok=await confirmAction({...confirm,trigger});if(!ok)return null;}
      let inputValue=null;if(input){inputValue=await promptAction({...input,trigger});if(inputValue===null)return null;}
      return await withBusyControls(trigger,controls,async()=>{
        showLoading({title,message,trigger});
        try{const result=await request(inputValue);if(onSuccess)await onSuccess(result);if(!silentSuccess)showSuccess({title:successTitle,message:typeof successMessage==='function'?successMessage(result):successMessage,trigger});return result;}
        catch(err){showError({title:'Action failed',message:sanitizeActionText(err?.message||'Unable to complete action.'),trigger});return null;}
      });
    } finally {activeActionKeys.delete(actionKey);}
  };

  // 0.4.x compatibility aliases; all new page actions use the global API above.
  const setActionModalBusy = (title,message='Please wait while DNS Manager completes this action.') => showLoading({title,message});
  const showActionResult = (type,title,message) => ({success:showSuccess,error:showError,warning:showWarning,info:showInfo}[type]||showInfo)({title,message});
  const showActionModal = opts => opts.inputLabel ? promptAction({title:opts.title,message:opts.message,inputLabel:opts.inputLabel,inputType:opts.inputType,inputPlaceholder:opts.inputPlaceholder,confirmLabel:opts.confirmLabel,cancelLabel:opts.cancelLabel,danger:opts.danger}) : confirmAction({title:opts.title,message:opts.message,confirmLabel:opts.confirmLabel,cancelLabel:opts.cancelLabel,danger:opts.danger});

  const showHostedCnameModal = async(domain, trigger=document.activeElement) => {
    showLoading({title:'Loading CNAME',message:'Retrieving the Hosted ACME-DNS delegation record.',trigger});
    try{
      const d=await api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/hosted-acme`);
      const x=setModalPresentation('info','Hosted ACME-DNS CNAME',`Use this CNAME for ${domain}.`,{trigger}); if(!x)return d;
      const detail=document.createElement('div');detail.className='action-detail';
      const addRow=(label,value,code=false)=>{const row=document.createElement('div');row.className='action-detail-row';const l=document.createElement('span');l.className='muted small';l.textContent=label;const v=document.createElement(code?'code':'strong');v.textContent=String(value);row.append(l,v);detail.appendChild(row);};
      addRow('Type','CNAME');addRow('Name',d.challenge_domain,true);addRow('Target',d.fulldomain,true);addRow('TTL','300');addRow('Status',d.verified?'Verified':'Not verified');
      const copy=document.createElement('div');copy.className='action-copy-row';
      [['Copy Name',d.challenge_domain],['Copy Target',d.fulldomain]].forEach(([label,value])=>{const b=document.createElement('button');b.className='btn btn-secondary';b.type='button';b.dataset.copyActionValue=value;b.textContent=label;copy.appendChild(b);});detail.appendChild(copy);x.body.appendChild(detail);
      x.confirm.textContent='Close';x.confirm.onclick=()=>closeActionModal();x.close.onclick=()=>closeActionModal();return d;
    } catch(err){showError({title:'Unable to load CNAME',message:sanitizeActionText(err.message),trigger});throw err;}
  };

  const mappingActions = {};
  const userActions = {};
  const roleActions = {};
  const systemActions = {};
  const backupActions = {};
  const auditActions = {};
  const dashboardActions = {};
  const sslActions = {};


  async function loginInit() {
    const form = $('[data-login-form]'); if (!form) return;
    form.addEventListener('submit', async (event) => {
      event.preventDefault(); const error = $('[data-login-error]'); error.hidden = true;
      const button = $('button[type="submit"]', form); button.disabled = true;
      try {
        const csrfResponse = await fetch('/api/v1/auth/csrf', {credentials:'same-origin'}); const csrfBody = await csrfResponse.json();
        const data = Object.fromEntries(new FormData(form));
        const response = await fetch('/api/v1/auth/login', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':csrfBody.csrf_token}, body:JSON.stringify({username:data.username,password:data.password})});
        if (!response.ok) throw new Error(await detail(response));
        location.assign(form.dataset.next || '/app/dashboard');
      } catch (err) { error.textContent = err.message; error.className = 'flash error'; error.hidden = false; button.disabled = false; }
    });
  }

  async function refreshGlobalStatus() {
    if (page === 'login') return;
    try { const status = await api('/api/v1/system/status'); const dot = $('[data-global-status]'); const text = $('[data-global-status-text]'); dot?.classList.toggle('good', status.status === 'ready'); dot?.classList.toggle('bad', status.status !== 'ready'); if (text) text.textContent = status.status === 'ready' ? 'Services ready' : 'Service attention required'; } catch (err) { const text = $('[data-global-status-text]'); if (text) text.textContent = 'Status unavailable'; }
  }


  function startHostMonitoring() {
    const host = $('[data-host-monitoring]'); if (!host) return;
    const mode = host.dataset.monitoringMode;
    if (mode !== 'detail') $('[data-monitor-details]', host)?.remove();
    const MONITOR_POLL_MS = 1000;
    const MONITOR_MAX_BACKOFF_MS = 30000;
    let previous = null, inFlight = false, timer = null, stopped = false, errorCount = 0;
    const field = key => $(`[data-monitor="${key}"]`, host);
    const display = (key, value) => { const node = field(key); if (node) node.textContent = value; };
    const fmt = bytes => Number.isFinite(bytes) ? `${(bytes / 1073741824).toFixed(2)} GiB` : 'N/A';
    const pct = value => Number.isFinite(value) ? `${value.toFixed(1)}%` : 'N/A';
    const bar = (key, value) => { const node = $(`[data-monitor-progress="${key}"]`, host); if (node) { node.value = Number.isFinite(value) ? Math.max(0,Math.min(100,value)) : 0; node.setAttribute('aria-valuetext', pct(value)); } };
    const speed = (now, old, elapsed) => Number.isFinite(now) && Number.isFinite(old) && now >= old && elapsed > 0 ? `${((now-old)*8000/elapsed/1000000).toFixed(2)} Mbps` : 'N/A';
    const selector = $('[data-monitor-interface]', host);
    const update = data => {
      const cpu = data.cpu || {}, mem = data.memory || {}, disks = data.disks || [], disk = disks.find(d=>d.mount==='/') || disks[0];
      display('cpu', pct(cpu.usage_percent)); bar('cpu', cpu.usage_percent);
      display('load', `Cores ${cpu.logical_cores ?? '—'} · Load ${[cpu.load_1,cpu.load_5,cpu.load_15].map(v=>Number.isFinite(v)?v.toFixed(2):'—').join(' / ')}`);
      display('memory', pct(mem.usage_percent)); display('memory-detail', `${fmt(mem.used_bytes)} / ${fmt(mem.total_bytes)} (available ${fmt(mem.available_bytes)})`); bar('memory', mem.usage_percent);
      display('disk', disk ? pct(disk.usage_percent) : 'N/A'); display('disk-detail', disk ? `${fmt(disk.used_bytes)} / ${fmt(disk.total_bytes)}` : 'Unavailable'); bar('disk', disk?.usage_percent);
      const sec = data.uptime?.seconds; display('uptime', Number.isFinite(sec) ? `${Math.floor(sec/86400)}d ${Math.floor(sec%86400/3600)}h ${Math.floor(sec%3600/60)}m` : 'N/A');
      display('boot', data.uptime?.boot_time_ms ? `Boot: ${new Date(data.uptime.boot_time_ms).toLocaleString()}` : 'Boot time unavailable');
      const entries = Object.entries(data.services || {}), active = entries.filter(([,v])=>v==='active').length;
      display('services', `${active} / ${entries.length} active`); display('service-summary', entries.filter(([,v])=>v!=='active').map(([k,v])=>`${k}: ${v}`).join(' · ') || 'All monitored services active');
      const interfaces = data.network?.interfaces || [];
      const existing = selector.value, names = interfaces.map(i=>i.name);
      if (names.join('|') !== [...selector.options].map(o=>o.value).join('|')) selector.replaceChildren(...names.map(name => {const opt=document.createElement('option');opt.value=name;opt.textContent=name;return opt;}));
      if (names.includes(existing)) selector.value=existing;
      const elapsed = previous && data.sampled_at_ms-previous.sampled_at_ms;
      const previousMap = new Map((previous?.network?.interfaces || []).map(i=>[i.name,i]));
      const measured = interfaces.map(i=>{const old=previousMap.get(i.name); return {...i,rx_rate:old?speed(i.rx_bytes,old.rx_bytes,elapsed):'Sampling…',tx_rate:old?speed(i.tx_bytes,old.tx_bytes,elapsed):'Sampling…'};});
      const selected = measured.find(i=>i.name===selector.value) || measured[0];
      display('network', selected ? `RX ${selected.rx_rate} / TX ${selected.tx_rate}` : 'No interfaces');
      if (mode === 'detail') {
        const table=$('[data-monitor-interfaces]',host); if(table) table.innerHTML=measured.length?measured.map(i=>`<tr><td>${escapeHtml(i.name)}</td><td>${escapeHtml(i.operstate)}</td><td>${escapeHtml(i.rx_rate)}</td><td>${escapeHtml(i.tx_rate)}</td></tr>`).join(''):'<tr><td colspan="4">No network interfaces available</td></tr>';
        const disksEl=$('[data-monitor-disks]',host); if(disksEl)disksEl.textContent=disks.map(d=>`${d.mount}: ${pct(d.usage_percent)} (${fmt(d.used_bytes)} / ${fmt(d.total_bytes)})`).join(' · ') || 'No filesystem information';
        const servicesEl=$('[data-monitor-services]',host); if(servicesEl)servicesEl.replaceChildren(...entries.map(([name,state])=>{const line=document.createElement('p');line.textContent=`${name}: ${state}`;return line;}));
      }
      previous=data;
      $('[data-monitor-time]',host).textContent=`Updated ${new Date(data.sampled_at_ms).toLocaleTimeString()}`;
      const status=$('[data-monitor-status]',host);status.textContent=(data.warnings?.length ? `Partial data: ${data.warnings.join('; ')}` : 'Live · updates every 1 second');
    };
    const scheduleNext = nextDelayMs => {
      clearTimeout(timer);
      timer = null;
      if (!stopped && !document.hidden) timer = setTimeout(fetchOnce, nextDelayMs);
    };
    const fetchOnce=async()=>{
      if(inFlight || stopped || document.hidden) return;
      inFlight=true;
      let nextDelayMs = MONITOR_POLL_MS;
      try{
        const data=await api('/api/v1/system/metrics');
        if(!stopped && !document.hidden)update(data);
        errorCount = 0;
      }
      catch(err){
        if(!stopped && !document.hidden){
          const status=$('[data-monitor-status]',host);
          status.textContent=`Metrics unavailable / stale: ${err.message}`;
        }
        if(String(err.message).includes('permission')) stopped=true;
        else {
          errorCount += 1;
          nextDelayMs = Math.min(MONITOR_MAX_BACKOFF_MS, MONITOR_POLL_MS * (2 ** Math.min(errorCount, 10)));
        }
      }
      finally{
        inFlight=false;
        if(!stopped && !document.hidden) scheduleNext(nextDelayMs);
      }
    };
    const onVisibility=()=>{
      if(stopped)return;
      clearTimeout(timer);timer=null;
      if(!document.hidden){
        previous=null; // Re-prime throughput sampling after time away from the tab.
        if(!inFlight)fetchOnce();
      }
    };
    document.addEventListener('visibilitychange',onVisibility);
    window.addEventListener('pagehide',()=>{stopped=true;clearTimeout(timer);document.removeEventListener('visibilitychange',onVisibility);},{once:true});
    selector?.addEventListener('change',()=>{if(previous){const selected=(previous.network?.interfaces || []).find(i=>i.name===selector.value);display('network',selected?'Sampling…':'N/A');}});
    onVisibility();
  }

  async function logout() { try { await api('/api/v1/auth/logout', {method:'POST'}); } finally { location.assign('/login'); } }

  async function dashboardInit() {
    const load = async () => {
      const [status,mappings,backends,audit] = await Promise.all([api('/api/v1/system/status'),api('/api/v1/mappings'),api('/api/v1/system/backends'),api('/api/v1/audit?limit=8')]);
      $('[data-metric="dnsmasq"]').textContent=status.dnsmasq;$('[data-metric="nginx"]').textContent=status.nginx;$('[data-metric="mappings"]').textContent=mappings.length;
      const pending=$('[data-metric="pending"]');try{const preview=await api('/api/v1/config/preview');pending.textContent=preview.pending_change_count;}catch{pending.textContent='—';}
      $('[data-backend-summary]').innerHTML=backends.length?backends.map(b=>`<div class="status-row"><div><strong>${escapeHtml(b.domain)}</strong><div class="muted small">${escapeHtml(b.latency_ms??'—')} ms · HTTP ${escapeHtml(b.http_status??'—')}</div></div>${badge(b.status)}</div>`).join(''):'<p class="muted">No mappings configured.</p>';
      $('[data-recent-audit]').innerHTML=audit.length?`<table><tbody>${audit.map(a=>`<tr><td><strong>${escapeHtml(a.action)}</strong><div class="muted small">${escapeHtml(a.username||'system')}</div></td><td>${badge(a.status)}</td></tr>`).join('')}</tbody></table>`:'<p class="muted">No audit events.</p>';
    };
    dashboardActions.refresh=async trigger=>{try{await load();}catch(err){showError({title:'Dashboard refresh failed',message:err.message,trigger});}};
    $('[data-action="refresh-dashboard"]')?.addEventListener('click',e=>dashboardActions.refresh(e.currentTarget));
    await load();
  }

  let mappingCache=[],backendCache=new Map();
  async function mappingsInit(){
    const tbody=$('[data-mappings-table]'),dialog=$('[data-mapping-dialog]'),form=$('[data-mapping-form]');
    const render=()=>{const q=($('[data-mapping-search]')?.value||'').toLowerCase(),filter=$('[data-mapping-filter]')?.value||'all';const rows=mappingCache.filter(m=>{const health=backendCache.get(m.id)?.status||'UNKNOWN';const text=`${m.domain} ${m.upstream_host}:${m.upstream_port}`.toLowerCase();return text.includes(q)&&(filter==='all'||(filter==='enabled'&&m.enabled)||(filter==='disabled'&&!m.enabled)||(filter==='up'&&health==='UP')||(filter==='down'&&health!=='UP'));});tbody.innerHTML=rows.length?rows.map(m=>{const health=backendCache.get(m.id)||{};return `<tr><td><strong>${escapeHtml(m.domain)}</strong><div class="muted small">${escapeHtml(m.description||'')}</div></td><td>${escapeHtml(m.upstream_scheme)}://${escapeHtml(m.upstream_host)}:${m.upstream_port}</td><td>${badge(health.status)}</td><td>${badge(m.enabled?'enabled':'disabled')}</td><td>${escapeHtml(m.updated_at?new Date(m.updated_at).toLocaleString():'—')}</td><td><div class="row-actions">${document.body.dataset.role!=='viewer'?`<button class="btn btn-ghost" data-edit-mapping="${m.id}">Edit</button><button class="btn btn-ghost" data-delete-mapping="${m.id}">Delete</button>`:''}</div></td></tr>`;}).join(''):'<tr><td colspan="6" class="muted">No mappings match.</td></tr>';};
    const load=async()=>{const [mappings,backends]=await Promise.all([api('/api/v1/mappings'),api('/api/v1/system/backends')]);mappingCache=mappings;backendCache=new Map(backends.map(b=>[b.mapping_id,b]));render();};
    mappingActions.save=async(trigger,payload,id)=>runAction({key:`mapping-save:${id||'new'}`,title:id?'Updating mapping':'Creating mapping',message:payload.domain,successTitle:'Mapping saved',successMessage:'Mapping saved. Apply changes to deploy.',trigger,request:()=>api(id?`/api/v1/mappings/${id}`:'/api/v1/mappings',{method:id?'PUT':'POST',json:payload}),onSuccess:async()=>{dialog.close();await load();}});
    mappingActions.delete=async(trigger,id)=>runAction({key:`mapping-delete:${id}`,title:'Deleting mapping',message:'Removing mapping from the pending configuration.',successTitle:'Mapping deleted',successMessage:'Mapping deleted. Apply changes to deploy.',trigger,confirm:{title:'Delete mapping?',message:'Delete this mapping? The change is pending until configuration is applied.',confirmLabel:'Delete',danger:true},request:()=>api(`/api/v1/mappings/${id}`,{method:'DELETE'}),onSuccess:load});
    mappingActions.apply=async trigger=>runAction({key:'mapping-config-apply',title:'Applying configuration',message:'Validating and deploying pending DNS/Nginx changes.',successTitle:'Configuration applied',successMessage:'Configuration applied successfully.',trigger,confirm:{title:'Apply configuration?',message:'Validate and apply all pending DNS/Nginx changes?',confirmLabel:'Apply'},request:()=>api('/api/v1/config/apply',{method:'POST'}),onSuccess:load});
    $('[data-mapping-search]')?.addEventListener('input',render);$('[data-mapping-filter]')?.addEventListener('change',render);
    $('[data-action="mapping-create"]')?.addEventListener('click',()=>{form.reset();form.elements.id.value='';form.elements.version.value='';form.elements.enabled.checked=true;form.elements.tls_verify.checked=true;$('[data-mapping-dialog-title]').textContent='Add mapping';dialog.showModal();});
    tbody.addEventListener('click',async e=>{const edit=e.target.closest('[data-edit-mapping]'),del=e.target.closest('[data-delete-mapping]');if(edit){const m=mappingCache.find(x=>x.id===Number(edit.dataset.editMapping));if(!m)return;for(const key of ['id','version','domain','upstream_scheme','upstream_host','upstream_port','custom_timeout','description'])if(form.elements[key])form.elements[key].value=m[key]??'';for(const key of ['enabled','websocket_enabled','preserve_host','tls_verify'])form.elements[key].checked=!!m[key];$('[data-mapping-dialog-title]').textContent='Edit mapping';dialog.showModal();}if(del)await mappingActions.delete(del,del.dataset.deleteMapping);});
    form?.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(form),id=fd.get('id');const payload={domain:fd.get('domain'),upstream_scheme:fd.get('upstream_scheme'),upstream_host:fd.get('upstream_host'),upstream_port:Number(fd.get('upstream_port')),enabled:form.elements.enabled.checked,websocket_enabled:form.elements.websocket_enabled.checked,preserve_host:form.elements.preserve_host.checked,tls_verify:form.elements.tls_verify.checked,custom_timeout:fd.get('custom_timeout')?Number(fd.get('custom_timeout')):null,description:fd.get('description')||null};if(id)payload.version=Number(fd.get('version'));await mappingActions.save(e.submitter||form,payload,id);});
    const showPreview=async trigger=>{try{const p=await api('/api/v1/config/preview');renderConfigPreview(p);$('[data-preview-dialog]')?.showModal();}catch(err){showError({title:'Preview unavailable',message:err.message,trigger});}};
    $('[data-action="config-preview"]')?.addEventListener('click',e=>showPreview(e.currentTarget));
    $('[data-action="config-apply"]')?.addEventListener('click',e=>mappingActions.apply(e.currentTarget));
    await load();
  }

  let usersCache=[],rolesCache=[];
  async function usersInit(){
    const tbody=$('[data-users-table]'),dialog=$('[data-user-dialog]'),form=$('[data-user-form]');
    const load=async()=>{[usersCache,rolesCache]=await Promise.all([api('/api/v1/users'),api('/api/v1/roles')]);tbody.innerHTML=usersCache.map(u=>`<tr><td><strong>${escapeHtml(u.username)}</strong><div class="muted small">${escapeHtml(u.email||'')}</div></td><td>${escapeHtml(u.role.name)}</td><td>${badge(u.is_active?'active':'disabled')}</td><td>${escapeHtml(u.last_login_at?new Date(u.last_login_at).toLocaleString():'Never')}</td><td><div class="row-actions">${u.role.name==='super_admin'&&document.body.dataset.role!=='super_admin'?'':`<button class="btn btn-ghost" data-edit-user="${u.id}">Edit</button><button class="btn btn-ghost" data-reset-user="${u.id}">Reset</button>${u.is_active?`<button class="btn btn-ghost" data-disable-user="${u.id}">Disable</button>`:''}`}</div></td></tr>`).join('');};
    const fillRoles=selected=>{form.elements.role_id.innerHTML=rolesCache.filter(r=>document.body.dataset.role==='super_admin'||r.name!=='super_admin').map(r=>`<option value="${r.id}" ${r.id===selected?'selected':''}>${escapeHtml(r.name)}</option>`).join('');};
    userActions.save=async(trigger,payload,id)=>runAction({key:`user-save:${id||payload.username}`,title:id?'Updating user':'Creating user',message:id?'Saving account changes.':`Creating ${payload.username}.`,successTitle:'User saved',successMessage:'User saved.',trigger,request:()=>api(id?`/api/v1/users/${id}`:'/api/v1/users',{method:id?'PUT':'POST',json:payload}),onSuccess:async()=>{dialog.close();if(form.elements.password)form.elements.password.value='';await load();}});
    userActions.disable=async(trigger,id,username)=>runAction({key:`user-disable:${id}`,title:'Disabling user',message:username||'User account',successTitle:'User disabled',successMessage:'User disabled.',trigger,confirm:{title:'Disable user?',message:`Disable ${username||'this user'} and revoke their sessions?`,confirmLabel:'Disable',danger:true},request:()=>api(`/api/v1/users/${id}`,{method:'DELETE'}),onSuccess:load});
    userActions.resetPassword=async(trigger,id,password,formEl)=>runAction({key:`user-password:${id}`,title:'Resetting password',message:'Revoking existing sessions and saving the new password.',successTitle:'Password reset',successMessage:'Password reset and sessions revoked.',trigger,request:()=>api(`/api/v1/users/${id}/reset-password`,{method:'POST',json:{password}}),onSuccess:async()=>{formEl.closest('dialog').close();formEl.reset();}});
    $('[data-action="user-create"]')?.addEventListener('click',()=>{form.reset();form.elements.id.value='';form.elements.username.disabled=false;$('[data-password-field]').hidden=false;$('[data-active-field]').hidden=true;fillRoles();$('[data-user-dialog-title]').textContent='Add user';dialog.showModal();});
    tbody.addEventListener('click',async e=>{const edit=e.target.closest('[data-edit-user]'),reset=e.target.closest('[data-reset-user]'),disable=e.target.closest('[data-disable-user]');if(edit){const u=usersCache.find(x=>x.id===Number(edit.dataset.editUser));form.reset();form.elements.id.value=u.id;form.elements.username.value=u.username;form.elements.username.disabled=true;form.elements.email.value=u.email||'';form.elements.is_active.checked=u.is_active;$('[data-password-field]').hidden=true;$('[data-active-field]').hidden=false;fillRoles(u.role.id);$('[data-user-dialog-title]').textContent='Edit user';dialog.showModal();}if(reset){$('[data-password-form]').elements.id.value=reset.dataset.resetUser;$('[data-password-dialog]').showModal();}if(disable){const u=usersCache.find(x=>x.id===Number(disable.dataset.disableUser));await userActions.disable(disable,disable.dataset.disableUser,u?.username);}});
    form.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(form),id=fd.get('id');const payload=id?{email:fd.get('email')||null,role_id:Number(fd.get('role_id')),is_active:form.elements.is_active.checked}:{username:fd.get('username'),email:fd.get('email')||null,password:fd.get('password'),role_id:Number(fd.get('role_id'))};await userActions.save(e.submitter||form,payload,id);});
    $('[data-password-form]')?.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(e.target);await userActions.resetPassword(e.submitter||e.target,fd.get('id'),fd.get('password'),e.target);});
    await load();
  }

  async function rolesInit(){
    const grid=$('[data-roles-grid]'),dialog=$('[data-role-dialog]'),form=$('[data-role-form]'),createDialog=$('[data-role-create-dialog]'),createForm=$('[data-role-create-form]');let roles=[];
    const load=async()=>{roles=await api('/api/v1/roles');grid.innerHTML=roles.map(r=>{const builtin=['super_admin','admin','viewer'].includes(r.name);const actions=dialog?`<div class="row-actions">${r.name!=='super_admin'?`<button class="btn btn-ghost" data-edit-role="${r.id}">Edit</button>`:''}${!builtin?`<button class="btn btn-danger" data-delete-role="${r.id}">Delete</button>`:''}</div>`:'';return `<article class="role-card"><div class="card-head"><div><h3>${escapeHtml(r.name)}</h3><p class="muted small">${escapeHtml(r.description||'')}</p></div>${actions}</div><div class="permission-list">${r.permissions.map(p=>`<span class="badge">${escapeHtml(p)}</span>`).join('')}</div></article>`;}).join('');};
    roleActions.create=async(trigger,payload)=>runAction({key:`role-create:${payload.name}`,title:'Creating role',message:payload.name,successTitle:'Role created',successMessage:r=>`Role ${r.name} created.`,trigger,request:()=>api('/api/v1/roles',{method:'POST',json:payload}),onSuccess:async()=>{createDialog.close();createForm.reset();await load();}});
    roleActions.savePermissions=async(trigger,id,permissions)=>runAction({key:`role-permissions:${id}`,title:'Saving permissions',message:'Updating role permissions.',successTitle:'Permissions saved',successMessage:'Role permissions updated.',trigger,request:()=>api(`/api/v1/roles/${id}/permissions`,{method:'PUT',json:{permissions}}),onSuccess:async()=>{dialog.close();await load();}});
    roleActions.delete=async(trigger,id,name)=>runAction({key:`role-delete:${id}`,title:'Deleting role',message:name||'Custom role',successTitle:'Role deleted',successMessage:`Role ${name||''} deleted.`,trigger,confirm:{title:'Delete role?',message:`Delete role ${name||'this role'}?`,detail:'This cannot be undone. Deletion is blocked automatically if the role has assigned users.',confirmLabel:'Delete',danger:true},request:()=>api(`/api/v1/roles/${id}`,{method:'DELETE'}),onSuccess:load});
    $('[data-action="role-create"]')?.addEventListener('click',()=>{createForm.reset();createDialog.showModal();});
    createForm?.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(createForm),permissions=fd.getAll('permissions');if(!permissions.length){showWarning({title:'Choose permissions',message:'Select at least one permission for the role.',trigger:e.submitter||createForm});return;}await roleActions.create(e.submitter||createForm,{name:String(fd.get('name')||'').trim().toLowerCase(),description:String(fd.get('description')||'').trim()||null,permissions});});
    grid.addEventListener('click',async e=>{const edit=e.target.closest('[data-edit-role]'),del=e.target.closest('[data-delete-role]');if(edit&&dialog){const role=roles.find(r=>r.id===Number(edit.dataset.editRole));form.elements.id.value=role.id;$('[data-role-title]').textContent=`Edit ${role.name}`;$$('input[name="permissions"]',form).forEach(i=>i.checked=role.permissions.includes(i.value));dialog.showModal();}if(del){const role=roles.find(r=>r.id===Number(del.dataset.deleteRole));if(role)await roleActions.delete(del,role.id,role.name);}});
    form?.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(form);await roleActions.savePermissions(e.submitter||form,fd.get('id'),fd.getAll('permissions'));});
    await load();
  }

  async function auditInit(){
    const tbody=$('[data-audit-table]'),form=$('[data-audit-filters]');
    const load=async()=>{const params=new URLSearchParams(new FormData(form));[...params.keys()].forEach(k=>{if(!params.get(k))params.delete(k)});params.set('limit','200');const rows=await api(`/api/v1/audit?${params}`);tbody.innerHTML=rows.length?rows.map(a=>`<tr><td>${escapeHtml(new Date(a.created_at).toLocaleString())}</td><td>${escapeHtml(a.username||'system')}</td><td><strong>${escapeHtml(a.action)}</strong>${a.error_message?`<div class="muted small">${escapeHtml(a.error_message)}</div>`:''}</td><td>${escapeHtml(a.object_type||'—')} ${escapeHtml(a.object_id??'')}</td><td>${escapeHtml(a.source_ip||'—')}</td><td>${badge(a.status)}</td></tr>`).join(''):'<tr><td colspan="6" class="muted">No matching events.</td></tr>';};
    auditActions.filter=async trigger=>{try{await load();}catch(err){showError({title:'Audit filter failed',message:err.message,trigger});}};
    form.addEventListener('submit',e=>{e.preventDefault();auditActions.filter(e.submitter||form);});await load();
  }

  async function systemInit(){
    const loadStatus=async()=>{const s=await api('/api/v1/system/status');['database','dnsmasq','nginx'].forEach(k=>{const el=$(`[data-system="${k}"]`);if(el)el.innerHTML=badge(s[k]);});const safety=$('[data-system="dns_safety"]');if(safety)safety.innerHTML=badge(s.dns_safety?.safe?'SAFE':'UNSAFE');const bind=$('[data-system="dns_bind"]');if(bind)bind.textContent=s.dns_safety?.expected_ip||'Not configured';};
    const loadPreview=async()=>{try{const p=await api('/api/v1/config/preview');renderConfigPreview(p);$('[data-pending-count]').textContent=`Pending ${p.pending_change_count}`;}catch(err){$('[data-preview-dns]').textContent=`Preview unavailable: ${err.message}`;$('[data-preview-nginx]').textContent='Preview unavailable.';}};
    systemActions.validate=async trigger=>runAction({key:'system-validate',title:'Validating configuration',message:'Checking generated DNS and Nginx configuration.',successTitle:'Configuration valid',successMessage:'Configuration validated successfully.',trigger,request:()=>api('/api/v1/config/validate',{method:'POST'})});
    systemActions.apply=async trigger=>runAction({key:'system-apply',title:'Applying configuration',message:'Deploying pending DNS and Nginx configuration.',successTitle:'Configuration applied',successMessage:'Configuration applied.',trigger,confirm:{title:'Apply configuration?',message:'Apply pending DNS/Nginx configuration now?',confirmLabel:'Apply'},request:()=>api('/api/v1/config/apply',{method:'POST'}),onSuccess:loadPreview});
    systemActions.rollback=async(trigger,id)=>runAction({key:`system-rollback:${id}`,title:'Rolling back configuration',message:`Revision ${id}`,successTitle:'Rollback completed',successMessage:'Rollback completed.',trigger,confirm:{title:'Rollback revision?',message:`Rollback to revision ID ${id}?`,detail:'Current managed DNS/Nginx configuration will be replaced.',confirmLabel:'Rollback',danger:true},request:()=>api(`/api/v1/config/rollback/${id}`,{method:'POST'}),onSuccess:async()=>Promise.all([loadStatus(),loadPreview()])});
    $('[data-action="config-validate"]')?.addEventListener('click',e=>systemActions.validate(e.currentTarget));$('[data-action="config-apply"]')?.addEventListener('click',e=>systemActions.apply(e.currentTarget));$('[data-action="config-rollback"]')?.addEventListener('click',e=>{const id=Number($('[data-rollback-id]').value);if(!id)return showError({title:'Revision required',message:'Enter a revision database ID.',trigger:e.currentTarget});systemActions.rollback(e.currentTarget,id);});

    const firewallSection=$('[data-firewall-section]');
    const firewallCanManage=firewallSection?.dataset.canManage==='true';
    let firewallPolicy=null;
    const renderFirewallFindings=(findings=[])=>{const el=$('[data-firewall-findings]');if(!el)return;el.innerHTML=findings.length?findings.map(f=>`<div class="status-row"><span>${escapeHtml(f.message)}</span>${badge(f.severity)}</div>`).join(''):'<p class="muted small">No firewall security findings.</p>';};
    const loadFirewall=async()=>{if(!firewallSection)return; if(!firewallCanManage){$('[data-firewall="state"]').textContent='Restricted';return;}const [status,policy]=await Promise.all([api('/api/v1/firewall/status'),api('/api/v1/firewall/policy')]);firewallPolicy=policy;$('[data-firewall="state"]').innerHTML=badge(status.active?'active':'inactive');$('[data-firewall="incoming"]').textContent=status.default_incoming||policy.default_incoming;$('[data-firewall="managed"]').textContent=String(status.managed_count??0);$('[data-firewall="ssh"]').textContent=(status.ssh_ports||[]).join(', ')||'Not detected';renderFirewallFindings(status.findings||[]);$('[data-firewall-enabled]').checked=policy.enabled;$('[data-firewall-incoming]').value=policy.default_incoming;$('[data-firewall-outgoing]').value=policy.default_outgoing;const tb=$('[data-firewall-rules]');tb.innerHTML=policy.rules.length?policy.rules.map(r=>`<tr><td>${escapeHtml(r.purpose)}</td><td>${badge(r.action)}</td><td>${escapeHtml(r.protocol)}</td><td>${r.port_start}${r.port_end?`-${r.port_end}`:''}</td><td><div class="firewall-rule-sources">${(r.source_cidrs||[r.source_cidr]).map(c=>`<code>${escapeHtml(c)}</code>`).join('')}</div></td><td>${escapeHtml(r.comment||'')}</td><td><div class="row-actions"><button class="btn btn-ghost" data-firewall-edit="${r.id}">Edit</button><button class="btn btn-danger" data-firewall-delete="${r.id}">Delete</button></div></td></tr>`).join(''):'<tr><td colspan="7" class="muted">No managed firewall rules.</td></tr>';};
    const firewallDialog=$('[data-firewall-dialog]'),firewallForm=$('[data-firewall-form]');
    const firewallSourceList=$('[data-firewall-source-list]');
    const firewallSourceNotice=$('[data-firewall-source-limit]');
    const renderFirewallSources=(values=[''])=>{if(!firewallSourceList)return;firewallSourceList.replaceChildren();const items=values.length?values:[''];items.slice(0,32).forEach((value,index)=>{const row=document.createElement('div');row.className='firewall-source-row';const label=document.createElement('label');label.textContent=`Source ${index+1}`;const input=document.createElement('input');input.name='source_cidrs';input.required=true;input.placeholder='203.0.113.10/32';input.setAttribute('aria-label',`Source CIDR ${index+1}`);input.value=value;label.append(input);const remove=document.createElement('button');remove.type='button';remove.className='btn btn-ghost';remove.dataset.firewallSourceRemove='';remove.textContent='Remove';remove.disabled=items.length===1;remove.setAttribute('aria-label',`Remove source ${index+1}`);row.append(label,remove);firewallSourceList.append(row);});const add=$('[data-firewall-source-add]');if(add)add.disabled=items.length>=32;if(firewallSourceNotice)firewallSourceNotice.textContent=items.length>=32?'source-limit: Maximum 32 IP/CIDR sources.':'';};
    $('[data-firewall-source-add]')?.addEventListener('click',()=>{const values=Array.from(firewallSourceList.querySelectorAll('input[name="source_cidrs"]'),e=>e.value);if(values.length>=32)return;renderFirewallSources([...values,'']);firewallSourceList.lastElementChild?.querySelector('input')?.focus();});
    firewallSourceList?.addEventListener('click',e=>{const button=e.target.closest('[data-firewall-source-remove]');if(!button)return;const rows=[...firewallSourceList.querySelectorAll('input[name="source_cidrs"]')];if(rows.length<=1)return;const selected=button.closest('.firewall-source-row')?.querySelector('input');renderFirewallSources(rows.filter(input=>input!==selected).map(input=>input.value));});
    $('[data-action="firewall-refresh"]')?.addEventListener('click',e=>runAction({key:'firewall-refresh',title:'Refreshing firewall',message:'Reading UFW state.',trigger:e.currentTarget,request:loadFirewall,successMessage:'Firewall status refreshed.'}));
    $('[data-action="firewall-add"]')?.addEventListener('click',()=>{firewallForm.reset();firewallForm.elements.id.value='';firewallForm.elements.enabled.checked=true;renderFirewallSources(['']);firewallDialog.showModal();});
    $('[data-firewall-rules]')?.addEventListener('click',e=>{const eb=e.target.closest('[data-firewall-edit]'),db=e.target.closest('[data-firewall-delete]');if(eb){const r=firewallPolicy.rules.find(x=>x.id===Number(eb.dataset.firewallEdit));Object.entries(r).forEach(([k,v])=>{if(k==='source_cidrs')return;if(firewallForm.elements[k]){if(firewallForm.elements[k].type==='checkbox')firewallForm.elements[k].checked=!!v;else firewallForm.elements[k].value=v??'';}});renderFirewallSources(r.source_cidrs||[r.source_cidr]);firewallDialog.showModal();}else if(db){runAction({key:`firewall-delete:${db.dataset.firewallDelete}`,title:'Deleting firewall rule',message:'This changes the draft policy only until Apply.',trigger:db,confirm:{title:'Delete firewall rule?',message:'Delete this managed rule?',confirmLabel:'Delete',danger:true},request:()=>api(`/api/v1/firewall/rules/${db.dataset.firewallDelete}`,{method:'DELETE'}),onSuccess:loadFirewall});}});
    firewallForm?.addEventListener('submit',e=>{e.preventDefault();const fd=new FormData(firewallForm),id=fd.get('id'),payload={purpose:fd.get('purpose'),action:fd.get('action'),protocol:fd.get('protocol'),port_start:Number(fd.get('port_start')),port_end:fd.get('port_end')?Number(fd.get('port_end')):null,source_cidrs:fd.getAll('source_cidrs').map(v=>String(v).trim()),comment:fd.get('comment')||null,enabled:firewallForm.elements.enabled.checked,sort_key:100};runAction({key:`firewall-save:${id||'new'}`,title:'Saving firewall rule',message:'Updating draft firewall policy.',trigger:e.submitter||firewallForm,request:()=>api(id?`/api/v1/firewall/rules/${id}`:'/api/v1/firewall/rules',{method:id?'PUT':'POST',json:payload}),onSuccess:async()=>{firewallDialog.close();await loadFirewall();},successMessage:'Firewall rule saved. Preview and Apply to deploy.'});});
    $('[data-action="firewall-policy-save"]')?.addEventListener('click',e=>runAction({key:'firewall-policy-save',title:'Saving firewall policy',message:'Saving desired UFW defaults.',trigger:e.currentTarget,request:()=>api('/api/v1/firewall/policy',{method:'PUT',json:{enabled:$('[data-firewall-enabled]').checked,default_incoming:$('[data-firewall-incoming]').value,default_outgoing:$('[data-firewall-outgoing]').value}}),onSuccess:loadFirewall,successMessage:'Draft firewall policy saved.'}));
    $('[data-action="firewall-preview"]')?.addEventListener('click',e=>runAction({key:'firewall-preview',title:'Firewall preview',message:'Building deterministic managed operations.',trigger:e.currentTarget,request:()=>api('/api/v1/firewall/preview',{method:'POST'}),onSuccess:r=>showInfo({title:'Firewall preview',message:`${r.operations.length} managed operation(s).`,detail:JSON.stringify(r.operations,null,2),trigger:e.currentTarget}),silentSuccess:true}));
    $('[data-action="firewall-validate"]')?.addEventListener('click',e=>runAction({key:'firewall-validate',title:'Validating firewall',message:'Checking CIDRs, DNS exposure and SSH lockout safety.',trigger:e.currentTarget,request:()=>api('/api/v1/firewall/validate',{method:'POST',json:{}}),onSuccess:r=>{if(!r.valid)showError({title:'Firewall validation failed',message:r.errors.join(' · '),detail:r.warnings.join(' · '),trigger:e.currentTarget});else showSuccess({title:'Firewall validation passed',message:r.warnings.join(' · ')||'Policy is safe to apply.',trigger:e.currentTarget});},silentSuccess:true}));
    $('[data-action="firewall-apply"]')?.addEventListener('click',async e=>{const validation=await api('/api/v1/firewall/validate',{method:'POST',json:{}}).catch(err=>{showError({title:'Validation failed',message:err.message,trigger:e.currentTarget});return null;});if(!validation||!validation.valid){if(validation)showError({title:'Firewall validation failed',message:validation.errors.join(' · '),trigger:e.currentTarget});return;}let high=false;if(validation.requires_high_risk_confirmation){high=await confirmAction({title:'High-risk firewall policy',message:validation.warnings.join(' · '),detail:'World-open DNS/SSH rules can expose this server. Continue only if intentional.',confirmLabel:'Apply high-risk policy',danger:true,trigger:e.currentTarget});if(!high)return;}const result=await runAction({key:'firewall-apply',title:'Applying firewall',message:'A 120-second emergency rollback will be armed.',trigger:e.currentTarget,confirm:{title:'Apply firewall policy?',message:'If management access is lost, the independent rollback unit will restore the previous managed firewall state.',confirmLabel:'Apply'},request:()=>api('/api/v1/firewall/apply',{method:'POST',json:{high_risk_confirmed:high}}),silentSuccess:true});if(!result)return;const keep=await confirmAction({title:'Keep firewall changes?',message:`Firewall revision ${result.revision} is pending confirmation.`,detail:`Emergency rollback deadline: ${result.rollback_deadline}`,confirmLabel:'Keep firewall changes',danger:true,trigger:e.currentTarget});if(keep){await runAction({key:'firewall-confirm',title:'Confirming firewall',message:'Cancelling emergency rollback.',trigger:e.currentTarget,request:()=>api('/api/v1/firewall/confirm',{method:'POST'}),onSuccess:loadFirewall,successMessage:'Firewall changes confirmed.'});}else{showWarning({title:'Emergency rollback remains armed',message:'Do not confirm if connectivity is not healthy. The previous managed firewall state will be restored automatically.',trigger:e.currentTarget});}});
    $('[data-action="firewall-rollback"]')?.addEventListener('click',e=>runAction({key:'firewall-rollback',title:'Rolling back firewall',message:'Restoring the latest managed firewall snapshot.',trigger:e.currentTarget,confirm:{title:'Rollback firewall?',message:'Restore the previous managed firewall state?',confirmLabel:'Rollback',danger:true},request:()=>api('/api/v1/firewall/rollback',{method:'POST'}),onSuccess:loadFirewall,successMessage:'Firewall rollback completed.'}));
    const sslTable=$('[data-ssl-table]'),sslForm=$('[data-ssl-form]');
    const loadSsl=async()=>{if(!sslTable)return;const rows=await api('/api/v1/ssl/certificates');sslTable.innerHTML=rows.length?rows.map(c=>{const manualStart=c.provider==='manual'&&['NOT_ISSUED','ERROR'].includes(c.status)?`<button class="btn btn-ghost" data-ssl-action="manual-start" data-domain="${escapeHtml(c.domain)}">Start DNS challenge</button>`:'';const convertAction=c.provider==='manual'?`<button class="btn btn-ghost" data-ssl-action="convert-cloudflare" data-domain="${escapeHtml(c.domain)}">Convert to Cloudflare</button><button class="btn btn-ghost" data-ssl-action="convert-hosted" data-domain="${escapeHtml(c.domain)}">Convert to Hosted ACME-DNS</button>`:'';const automated=['cloudflare','acme_delegation','acme_dns_hosted'].includes(c.provider);const providerVerified=c.provider==='acme_delegation'?c.delegation_verified:c.provider==='acme_dns_hosted'?c.hosted_acme_verified:true;const renewToggle=automated?(c.auto_renew?`<button class="btn btn-ghost" data-ssl-action="disable-auto-renew" data-domain="${escapeHtml(c.domain)}">Disable auto renew</button>`:(c.last_renewal_status==='TEST_SUCCESS'&&providerVerified?`<button class="btn btn-ghost" data-ssl-action="enable-auto-renew" data-domain="${escapeHtml(c.domain)}">Enable auto renew</button>`:'')):'';const providerActions=c.provider==='acme_delegation'?`<button class="btn btn-ghost" data-ssl-action="show-delegation" data-domain="${escapeHtml(c.domain)}">Show delegation</button><button class="btn btn-ghost" data-ssl-action="verify-delegation" data-domain="${escapeHtml(c.domain)}">Verify delegation</button>`:c.provider==='acme_dns_hosted'?`<button class="btn btn-ghost" data-ssl-action="show-hosted" data-domain="${escapeHtml(c.domain)}">Show CNAME</button><button class="btn btn-ghost" data-ssl-action="verify-hosted" data-domain="${escapeHtml(c.domain)}">Verify CNAME</button><button class="btn btn-ghost" data-ssl-action="reregister-hosted" data-domain="${escapeHtml(c.domain)}">Re-register</button>`:'';const automatedActions=automated?`${providerActions}<button class="btn btn-ghost" data-ssl-action="issue" data-domain="${escapeHtml(c.domain)}">Issue</button><button class="btn btn-ghost" data-ssl-action="renew" data-domain="${escapeHtml(c.domain)}">Renew</button><button class="btn btn-ghost" data-ssl-action="test-renewal" data-domain="${escapeHtml(c.domain)}">Test renewal</button>${renewToggle}`:'';const statusExtra=c.provider==='acme_delegation'?` ${badge(c.delegation_verified?'delegation verified':'delegation not verified')}`:c.provider==='acme_dns_hosted'?` ${badge(c.hosted_acme_verified?'cname verified':'cname not verified')}`:'';const providerLabel=c.provider==='acme_dns_hosted'?'Hosted ACME-DNS':c.provider;return `<tr><td><strong>${escapeHtml(c.domain)}</strong></td><td>${escapeHtml(providerLabel)}</td><td>${badge(c.status)}${statusExtra}</td><td>${escapeHtml(c.expires_at?new Date(c.expires_at).toLocaleString():'—')}</td><td>${badge(c.auto_renew?'enabled':'disabled')}</td><td><div class="row-actions">${manualStart}${convertAction}${automatedActions}<button class="btn btn-ghost" data-ssl-action="apply" data-domain="${escapeHtml(c.domain)}">Apply</button><button class="btn btn-danger" data-ssl-action="delete" data-domain="${escapeHtml(c.domain)}">Delete</button></div></td></tr>`;}).join(''):'<tr><td colspan="6" class="muted">No managed certificates.</td></tr>';};
    const showManual=async domain=>{const state=await api(`/api/v1/ssl/manual-dns/${encodeURIComponent(domain)}`),panel=$('[data-manual-dns-panel]');if(!panel)return false;if(state.challenge_name){panel.hidden=false;panel.dataset.domain=domain;$('[data-manual-dns-name]').textContent=state.challenge_name;$('[data-manual-dns-value]').textContent=state.challenge_value||'';return true;}return false;};
    const pollManual=async domain=>{for(let i=0;i<20;i++){if(await showManual(domain))return;await new Promise(r=>setTimeout(r,1500));}showError({title:'DNS challenge not ready',message:'Manual DNS challenge did not become ready in time. Check helper logs.'});};
    const showDelegation=async domain=>api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/delegation`);
    sslActions.run=async(trigger,action,domain,rowButtons=[])=>{
      if(action==='show-hosted')return showHostedCnameModal(domain,trigger);
      if(action==='show-delegation'){showLoading({title:'Loading delegation',message:domain,trigger});try{const d=await showDelegation(domain);showInfo({title:'ACME delegation',message:`${d.challenge_domain} → ${d.delegated_fqdn}`,detail:d.verified?'Verified':'Not verified',trigger});return d;}catch(err){showError({title:'Delegation unavailable',message:err.message,trigger});return null;}}
      if(action==='convert-cloudflare')return runAction({key:`ssl-cloudflare:${domain}`,title:'Converting provider',message:`Updating ${domain} to Cloudflare DNS-01.`,successTitle:'Provider converted',successMessage:`${domain} now uses Cloudflare DNS-01. Run Test renewal before enabling auto renew.`,trigger,controls:rowButtons,input:{title:'Convert to Cloudflare DNS-01',message:`Enter the Cloudflare API token for ${domain}.`,confirmLabel:'Convert',inputLabel:'Cloudflare API token',inputType:'password',inputPlaceholder:'API token'},request:token=>api(`/api/v1/ssl/settings/${encodeURIComponent(domain)}`,{method:'PUT',json:{provider:'cloudflare',api_token:token,auto_renew:false}}),onSuccess:loadSsl});
      const confirmMap={delete:{title:'Delete certificate?',message:`Delete SSL configuration for ${domain}? Certificate files will be preserved.`,confirmLabel:'Delete',danger:true},issue:{title:'Issue certificate?',message:`Issue certificate for ${domain}?`,confirmLabel:'Issue'},renew:{title:'Renew certificate?',message:`Renew certificate for ${domain}?`,confirmLabel:'Renew'},apply:{title:'Apply certificate?',message:`Apply the managed certificate for ${domain} to Nginx?`,confirmLabel:'Apply'},'manual-start':{title:'Start DNS challenge?',message:`Start manual DNS challenge for ${domain}?`,confirmLabel:'Start'},'reregister-hosted':{title:'Re-register Hosted ACME-DNS?',message:`Create a new Hosted ACME-DNS registration for ${domain}? You will need to update its CNAME.`,confirmLabel:'Re-register',danger:true},'convert-hosted':{title:'Convert provider?',message:`Convert ${domain} to Hosted ACME-DNS?`,confirmLabel:'Convert'},'enable-auto-renew':{title:'Enable auto renew?',message:`Enable automatic renewal for ${domain}?`,confirmLabel:'Enable'},'disable-auto-renew':{title:'Disable auto renew?',message:`Disable automatic renewal for ${domain}?`,confirmLabel:'Disable',danger:true}};
      const noConfirm=['verify-hosted','verify-delegation','test-renewal'].includes(action);const labels={'verify-hosted':'Verifying CNAME','verify-delegation':'Verifying delegation','test-renewal':'Testing certificate renewal','enable-auto-renew':'Enabling auto renew','disable-auto-renew':'Disabling auto renew','reregister-hosted':'Creating Hosted ACME-DNS registration','convert-hosted':'Creating Hosted ACME-DNS registration','manual-start':'Starting DNS challenge',delete:'Deleting certificate configuration',issue:'Issuing certificate',renew:'Renewing certificate',apply:'Applying certificate'};
      return runAction({key:`ssl:${action}:${domain}`,title:labels[action]||'Certificate action',message:domain,trigger,controls:rowButtons,confirm:noConfirm?null:confirmMap[action],successTitle:action==='test-renewal'?'Renewal test successful':'Certificate action completed',successMessage:action==='test-renewal'?`Renewal test completed for ${domain}. You can now enable auto renew.`:`${domain} completed successfully.`,silentSuccess:['convert-hosted','reregister-hosted','verify-hosted','verify-delegation'].includes(action),request:async()=>{if(action==='delete')return api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}`,{method:'DELETE'});if(action==='convert-hosted'||action==='reregister-hosted')return api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/hosted-acme/register`,{method:'POST'});if(action==='verify-hosted')return api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/hosted-acme/verify`,{method:'POST'});if(action==='verify-delegation')return api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/delegation/verify`,{method:'POST'});if(action==='enable-auto-renew'||action==='disable-auto-renew')return api(`/api/v1/ssl/settings/${encodeURIComponent(domain)}`,{method:'PUT',json:{auto_renew:action==='enable-auto-renew'}});if(action==='manual-start')return api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/manual-start`,{method:'POST'});return api(`/api/v1/ssl/certificates/${encodeURIComponent(domain)}/${action}`,{method:'POST'});},onSuccess:async result=>{if(action==='convert-hosted'||action==='reregister-hosted'){await loadSsl();await showHostedCnameModal(domain,trigger);return;}if(action==='verify-hosted'){showActionResult(result.verified?'success':'error',result.verified?'CNAME verified':'CNAME verification failed',result.verified?`Hosted CNAME verified for ${domain}.`:`Hosted CNAME verification failed for ${domain}.`);}else if(action==='verify-delegation'){showActionResult(result.verified?'success':'error',result.verified?'Delegation verified':'Delegation verification failed',result.verified?`Delegation verified for ${domain}.`:`Delegation verification failed for ${domain}.`);}else if(action==='manual-start'){pollManual(domain).catch(err=>showError({title:'DNS challenge error',message:err.message,trigger}));}await loadSsl();}});
    };
    sslActions.manualCheck=async(trigger,domain)=>runAction({key:`ssl-manual-check:${domain}`,title:'Checking TXT propagation',message:domain,trigger,successTitle:'DNS propagation checked',successMessage:r=>r.ready?'TXT found. Certbot is continuing.':'TXT value not visible yet.',request:()=>api(`/api/v1/ssl/manual-dns/${encodeURIComponent(domain)}/check`,{method:'POST'}),onSuccess:async r=>{if(r.ready){const panel=$('[data-manual-dns-panel]');if(panel)setTimeout(()=>{panel.hidden=true;loadSsl().catch(()=>{});},2500);}}});
    $('[data-action="ssl-refresh"]')?.addEventListener('click',async e=>{try{await loadSsl();}catch(err){showError({title:'SSL refresh failed',message:err.message,trigger:e.currentTarget});}});
    sslForm?.addEventListener('submit',async e=>{e.preventDefault();const fd=new FormData(sslForm),requested=fd.get('provider'),payload={domain:fd.get('domain'),provider:requested==='acme_dns_hosted'?'manual':requested,api_token:fd.get('api_token')||null,auto_renew:false,redirect_http:sslForm.elements.redirect_http.checked};const trigger=e.submitter||sslForm;await runAction({key:`ssl-add:${payload.domain}`,title:'Adding certificate',message:payload.domain,successTitle:'SSL configuration added',successMessage:`SSL configuration added for ${payload.domain}.`,trigger,silentSuccess:requested==='acme_dns_hosted',request:async()=>{let c=await api('/api/v1/ssl/certificates',{method:'POST',json:payload});if(requested==='acme_dns_hosted')c=await api(`/api/v1/ssl/certificates/${encodeURIComponent(c.domain)}/hosted-acme/register`,{method:'POST'});return c;},onSuccess:async c=>{sslForm.elements.api_token.value='';await loadSsl();if(requested==='acme_dns_hosted')await showHostedCnameModal(c.domain,trigger);}});sslForm.elements.api_token.value='';});
    $('[data-action="acme-verify"]')?.addEventListener('click',e=>{const panel=$('[data-acme-delegation-panel]'),domain=panel?.dataset.domain;if(domain)sslActions.run(e.currentTarget,'verify-delegation',domain);});
    sslTable?.addEventListener('click',e=>{const b=e.target.closest('[data-ssl-action]');if(!b)return;const row=b.closest('tr'),buttons=$$('button[data-ssl-action]',row||document);sslActions.run(b,b.dataset.sslAction,b.dataset.domain,buttons);});
    $('[data-action="ssl-manual-check"]')?.addEventListener('click',e=>{const panel=$('[data-manual-dns-panel]'),domain=panel?.dataset.domain;if(domain)sslActions.manualCheck(e.currentTarget,domain);});

    const backupsTable=$('[data-backups-table]');
    const formatBytes=n=>{if(n<1024)return `${n} B`;if(n<1024*1024)return `${(n/1024).toFixed(1)} KB`;return `${(n/1024/1024).toFixed(1)} MB`;};
    const loadBackups=async()=>{if(!backupsTable)return;const rows=await api('/api/v1/backups');backupsTable.innerHTML=rows.length?rows.map(b=>`<tr><td>${escapeHtml(new Date(b.created_at).toLocaleString())}</td><td><code>${escapeHtml(b.backup_id)}</code><div class="muted small">${escapeHtml(b.label||'manual')}</div></td><td>${escapeHtml(b.alembic_version||'unknown')}</td><td>${escapeHtml(formatBytes(Number(b.size_bytes||0)))}</td><td><div class="row-actions"><a class="btn btn-ghost" href="/api/v1/backups/${encodeURIComponent(b.backup_id)}/download">Download</a>${document.body.dataset.role==='super_admin'?`<button class="btn btn-danger" data-restore-backup="${escapeHtml(b.backup_id)}">Restore</button><button class="btn btn-danger" data-delete-backup="${escapeHtml(b.backup_id)}">Delete</button>`:''}</div></td></tr>`).join(''):'<tr><td colspan="5" class="muted">No backups yet.</td></tr>';};
    backupActions.create=async trigger=>runAction({key:'backup-create',title:'Creating backup',message:'Saving database and managed configuration.',successTitle:'Backup created',successMessage:b=>`Backup ${b.backup_id} created.`,trigger,request:()=>api('/api/v1/backups',{method:'POST'}),onSuccess:loadBackups});
    backupActions.upload=async(trigger,file,dialog,form)=>runAction({key:`backup-upload:${file.name}`,title:'Uploading backup',message:file.name,successTitle:'Backup uploaded',successMessage:b=>`Backup ${b.backup_id} uploaded.`,trigger,request:()=>api('/api/v1/backups/upload',{method:'POST',headers:{'Content-Type':'application/gzip','X-Backup-Filename':file.name},body:file}),onSuccess:async()=>{dialog.close();form.reset();await loadBackups();}});
    backupActions.restore=async(trigger,id)=>runAction({key:`backup-restore:${id}`,title:'Restoring backup',message:id,successTitle:'Backup restored',successMessage:'Backup restored. Sign in again to continue.',trigger,confirm:{title:'Restore backup?',message:`Restore backup ${id}? Current database and managed DNS/Nginx configuration will be replaced after an automatic safety backup is created.`,confirmLabel:'Restore',danger:true},request:()=>api(`/api/v1/backups/${encodeURIComponent(id)}/restore`,{method:'POST'}),onSuccess:async()=>{window.location.href='/login';}});
    backupActions.delete=async(trigger,id)=>runAction({key:`backup-delete:${id}`,title:'Deleting backup',message:id,successTitle:'Backup deleted',successMessage:'Backup deleted.',trigger,confirm:{title:'Delete backup?',message:`Delete backup ${id}? This cannot be undone.`,confirmLabel:'Delete',danger:true},request:()=>api(`/api/v1/backups/${encodeURIComponent(id)}`,{method:'DELETE'}),onSuccess:loadBackups});
    $('[data-action="backup-refresh"]')?.addEventListener('click',async e=>{try{await loadBackups();}catch(err){showError({title:'Backup refresh failed',message:err.message,trigger:e.currentTarget});}});$('[data-action="backup-create"]')?.addEventListener('click',e=>backupActions.create(e.currentTarget));const backupUploadDialog=$('[data-backup-upload-dialog]'),backupUploadForm=$('[data-backup-upload-form]');$('[data-action="backup-upload"]')?.addEventListener('click',()=>{backupUploadForm?.reset();backupUploadDialog?.showModal();});backupUploadForm?.addEventListener('submit',async e=>{e.preventDefault();const file=backupUploadForm.elements.backup.files?.[0];if(!file)return;await backupActions.upload(e.submitter||backupUploadForm,file,backupUploadDialog,backupUploadForm);});
    backupsTable?.addEventListener('click',e=>{const restore=e.target.closest('[data-restore-backup]'),del=e.target.closest('[data-delete-backup]');if(restore)backupActions.restore(restore,restore.dataset.restoreBackup);else if(del)backupActions.delete(del,del.dataset.deleteBackup);});
    await Promise.all([loadStatus(),loadPreview(),loadBackups(),loadSsl(),loadFirewall()]);
  }

  document.addEventListener('DOMContentLoaded', async () => {
    $$('[data-dialog-close]').forEach(button => button.addEventListener('click', () => button.closest('dialog')?.close()));
    actionModal()?.addEventListener('click',async e=>{const copy=e.target.closest('[data-copy-action-value]');if(!copy)return;try{await navigator.clipboard.writeText(copy.dataset.copyActionValue||'');const original=copy.textContent;copy.textContent='Copied';setTimeout(()=>{copy.textContent=original;},1200);}catch{copy.textContent='Copy failed';}});
    actionModal()?.addEventListener('keydown',trapActionModalFocus);
    actionModal()?.addEventListener('click',e=>{const modal=actionModal();if(e.target===modal && modal.dataset.blocking!=='true')closeActionModal();});
    actionModal()?.addEventListener('close',()=>{document.body.classList.remove('action-modal-open');const x=actionModalElements();if(x?.input)x.input.value='';restoreActionModalFocus();});
    $$('[data-action="logout"]').forEach(b => b.addEventListener('click', logout));
    if (page === 'login') return loginInit();
    refreshGlobalStatus();
    if (page === 'dashboard' || page === 'system') startHostMonitoring();
    try { if(page==='dashboard') await dashboardInit(); else if(page==='mappings') await mappingsInit(); else if(page==='users') await usersInit(); else if(page==='roles') await rolesInit(); else if(page==='audit') await auditInit(); else if(page==='system') await systemInit(); } catch (err) { flash(err.message || 'Unable to load page data.','error'); }
  });
})();
