"""Bounded read-only Linux host telemetry (no privileged subprocesses)."""
from __future__ import annotations

import os
import time
from pathlib import Path
from threading import Lock

ROOT = Path('/proc')
SYS_NET = Path('/sys/class/net')
CPU_LOCK = Lock()


def parse_cpu(text):
    fields = next((line.split()[1:] for line in text.splitlines() if line.startswith('cpu ')), [])
    values = [int(v) for v in fields]
    if len(values) < 4:
        raise ValueError('missing aggregate CPU counters')
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def cpu_usage(before, after):
    total = after[0] - before[0]
    idle = after[1] - before[1]
    return round(max(0, min(100, (total-idle)*100/total)), 1) if total > 0 and 0 <= idle <= total else None


def parse_memory(text):
    fields = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(':') and parts[1].isdigit():
            fields[parts[0][:-1]] = int(parts[1]) * 1024
    total = fields['MemTotal']
    available = max(0, min(total, fields['MemAvailable']))
    return {'total_bytes': total, 'used_bytes': total-available, 'available_bytes': available, 'usage_percent': round((total-available)*100/total,1) if total else None}


def read_network(root=SYS_NET):
    result = []
    for interface in sorted(root.iterdir(), key=lambda item: item.name):
        if interface.name == 'lo' or not interface.is_dir() or len(result) >= 64:
            continue
        try:
            state = (interface / 'operstate').read_text().strip()
            rx = int((interface / 'statistics/rx_bytes').read_text().strip())
            tx = int((interface / 'statistics/tx_bytes').read_text().strip())
            if rx < 0 or tx < 0: continue
            result.append({'name': interface.name, 'rx_bytes': rx, 'tx_bytes': tx, 'operstate': state})
        except (OSError, ValueError):
            continue
    return result


def service_states():
    # Read-only systemd status via /run/systemd units; unknown is never reported healthy.
    # Use a bounded systemctl invocation without shell or untrusted arguments.
    import subprocess
    names = ('dns-manager', 'dnsmasq', 'nginx', 'dns-manager-helper.service')
    statuses = {}
    for name in names:
        try:
            proc = subprocess.run(['systemctl','is-active',name], capture_output=True, text=True, timeout=0.7, check=False)
            state = proc.stdout.strip()
            statuses[name] = state if state in ('active','inactive','failed','activating','deactivating') else 'unknown'
        except (OSError, subprocess.TimeoutExpired):
            statuses[name] = 'unknown'
    return statuses


def collect_metrics(*, proc=ROOT, sys_net=SYS_NET, sample_seconds=0.12):
    warnings=[]
    sampled_at_ms=int(time.time()*1000)
    cpu={'usage_percent':None,'logical_cores':os.cpu_count() or 1,'load_1':None,'load_5':None,'load_15':None}
    memory={'total_bytes':None,'used_bytes':None,'available_bytes':None,'usage_percent':None}
    uptime={'seconds':None,'boot_time_ms':None}
    try:
        # Protect CPU sampling duration from concurrent requests inside each worker.
        with CPU_LOCK:
            before=parse_cpu((proc/'stat').read_text())
            if sample_seconds > 0: time.sleep(min(sample_seconds,0.25))
            after=parse_cpu((proc/'stat').read_text())
        cpu['usage_percent']=cpu_usage(before, after)
        loads=[float(v) for v in (proc/'loadavg').read_text().split()[:3]]
        cpu.update(zip(('load_1','load_5','load_15'),loads))
    except (OSError, ValueError, IndexError): warnings.append('CPU information unavailable')
    try: memory=parse_memory((proc/'meminfo').read_text())
    except (OSError, ValueError, KeyError): warnings.append('Memory information unavailable')
    try:
        uptime_seconds=float((proc/'uptime').read_text().split()[0]); uptime={'seconds':int(uptime_seconds),'boot_time_ms':int((time.time()-uptime_seconds)*1000)}
    except (OSError, ValueError, IndexError): warnings.append('Uptime unavailable')
    try: network={'interfaces':read_network(sys_net)}
    except OSError: network={'interfaces':[]}; warnings.append('Network information unavailable')
    disks=[]
    for mount in ('/', '/var/lib/dns-manager'):
        try:
            if mount != '/' and (not Path(mount).exists() or os.stat(mount).st_dev == os.stat('/').st_dev): continue
            st=os.statvfs(mount); total=st.f_blocks*st.f_frsize; available=st.f_bavail*st.f_frsize
            used=max(0, total-st.f_bfree*st.f_frsize)
            disks.append({'mount':mount,'total_bytes':total,'used_bytes':used,'available_bytes':available,'usage_percent':round(used*100/total,1) if total else None})
        except OSError: warnings.append('Disk information unavailable')
    services=service_states()
    if all(v is None for v in (cpu['usage_percent'], memory['total_bytes'],uptime['seconds'])):
        raise RuntimeError('System metrics collection unavailable')
    return {'sampled_at_ms':sampled_at_ms,'cpu':cpu,'memory':memory,'network':network,'disks':disks,'uptime':uptime,'services':services,'warnings':warnings}
