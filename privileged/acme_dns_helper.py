from __future__ import annotations

import json
import grp
import os
import re
import socket
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from app.config import AcmeDnsConfig, get_settings, load_acme_dns_config
from privileged.helper_lib import ensure_private_dir

# Outside the service-owned /var/lib/dns-manager tree: Knot serves whatever zone
# file it finds here, so the service user must not be able to swap the directory.
DEFAULT_STORAGE = Path('/var/lib/dns-manager-acme-dns')


def _local_ips() -> set[str]:
    ips = {'127.0.0.1', '::1'}
    try:
        for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
            if family in (socket.AF_INET, socket.AF_INET6):
                ips.add(sockaddr[0].split('%', 1)[0])
    except OSError:
        pass
    try:
        result = subprocess.run(['/usr/sbin/ip', '-j', 'addr'], text=True, capture_output=True, check=False)
        if result.returncode == 0:
            for iface in json.loads(result.stdout or '[]'):
                for addr in iface.get('addr_info', []):
                    if addr.get('local'):
                        ips.add(str(addr['local']))
    except Exception:
        pass
    return ips


def _port_available(ip: str, port: int, proto: str) -> bool:
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    kind = socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
    sock = socket.socket(family, kind)
    try:
        sock.bind((ip, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _default_runner(argv, **kwargs):
    return subprocess.run(list(argv), text=True, capture_output=True, check=False, **kwargs)


def _registered_in_db(hostname: str) -> bool:
    path = Path(get_settings().database_path)
    if not path.is_file():
        return False
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        try:
            row = con.execute('SELECT 1 FROM ssl_acme_delegations WHERE delegated_fqdn=? LIMIT 1', (hostname,)).fetchone()
            return row is not None
        finally:
            con.close()
    except sqlite3.Error:
        return False


class AcmeDnsHelperOps:
    def __init__(
        self,
        config: AcmeDnsConfig | None = None,
        *,
        local_ips: Callable[[], set[str]] = _local_ips,
        port_available: Callable[[str, str], bool] = _port_available,
        storage: Path | str = DEFAULT_STORAGE,
        registration_checker: Callable[[str], bool] = _registered_in_db,
        runner: Callable = _default_runner,
    ):
        self.config = config or load_acme_dns_config()
        self._local_ips = local_ips
        self._port_available = port_available
        self.storage = Path(storage)
        self.registration_checker = registration_checker
        self.runner = runner
        try:
            self.knot_gid = grp.getgrnam('knot').gr_gid
        except KeyError:
            self.knot_gid = os.getegid()
        self._records: dict[str, set[str]] | None = None

    def _storage_dir(self) -> Path:
        if not self.storage.exists():
            self.storage.mkdir(mode=0o750, parents=True)
            if os.geteuid() == 0:
                os.chown(self.storage, 0, self.knot_gid)
        return ensure_private_dir(self.storage)

    @property
    def zone_path(self) -> Path:
        return self.storage / f'{self.config.zone}.zone'

    def _run(self, argv: list[str]):
        result = self.runner(argv, check=False)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or 'Knot command failed').strip())
        return result

    def preflight(self) -> dict:
        if not self.config.listen_ip:
            raise RuntimeError('ACME DNS listen IP is not configured')
        if self.config.listen_ip not in self._local_ips():
            raise RuntimeError('ACME DNS listen IP is not present locally')
        for proto in ('tcp', 'udp'):
            if not self._port_available(self.config.listen_ip, self.config.listen_port, proto):
                raise RuntimeError(f'{proto.upper()} {self.config.listen_port} is already in use on ACME DNS listen IP')
        return {'safe': True, 'listen_ip': self.config.listen_ip, 'listen_port': self.config.listen_port, 'zone': self.config.zone}

    def render_knot_config(self) -> str:
        if not self.config.listen_ip:
            raise RuntimeError('ACME DNS listen IP is not configured')
        return (
            'server:\n'
            f'  listen: {self.config.listen_ip}@{self.config.listen_port}\n'
            'database:\n'
            '  storage: /var/lib/knot\n'
            'zone:\n'
            f'  - domain: {self.config.zone}\n'
            f'    storage: {self.storage}\n'
            f'    file: {self.config.zone}.zone\n'
        )

    def _validate_hostname(self, hostname: str) -> str:
        expected = rf'^dns-[0-9a-f]{{12}}\.{re.escape(self.config.zone)}$'
        if not isinstance(hostname, str) or not re.fullmatch(expected, hostname):
            raise ValueError('invalid ACME delegation hostname')
        if not self.registration_checker(hostname):
            raise ValueError('unregistered ACME delegation')
        return hostname

    @staticmethod
    def _validate_value(value: str) -> str:
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,512}', value):
            raise ValueError('invalid ACME TXT value')
        return value

    def _base_zone(self, serial: int) -> str:
        return (
            f'$ORIGIN {self.config.zone}.\n'
            f'$TTL {self.config.ttl}\n'
            f'@ IN SOA {self.config.nameserver}. hostmaster.{self.config.zone}. (\n'
            f'  {serial} 300 60 86400 {self.config.ttl}\n'
            ')\n'
            f'@ IN NS {self.config.nameserver}.\n'
        )

    def _load_records(self) -> dict[str, set[str]]:
        if self._records is not None:
            return {k: set(v) for k, v in self._records.items()}
        records: dict[str, set[str]] = {}
        self._storage_dir()
        if self.zone_path.is_file():
            for line in self.zone_path.read_text().splitlines():
                match = re.match(r'^(dns-[0-9a-f]{12})\s+30\s+IN\s+TXT\s+"([A-Za-z0-9_-]+)"$', line.strip())
                if match:
                    fqdn = f'{match.group(1)}.{self.config.zone}'
                    records.setdefault(fqdn, set()).add(match.group(2))
        self._records = records
        return {k: set(v) for k, v in records.items()}

    def _render_zone(self, records: dict[str, set[str]]) -> str:
        serial = int(__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y%m%d%H'))
        lines = [self._base_zone(serial).rstrip()]
        for fqdn in sorted(records):
            label = fqdn[:-(len(self.config.zone) + 1)]
            for value in sorted(records[fqdn]):
                lines.append(f'{label} {self.config.ttl} IN TXT "{value}"')
        return '\n'.join(lines) + '\n'

    def _atomic_write_validated(self, text: str) -> None:
        self._storage_dir()
        old = self.zone_path.read_bytes() if self.zone_path.is_file() else None
        fd, tmp_name = tempfile.mkstemp(prefix='.acme-zone.', dir=self.storage)
        try:
            with os.fdopen(fd, 'w') as fp:
                fp.write(text)
                fp.flush()
                os.fsync(fp.fileno())
            os.chmod(tmp_name, 0o640)
            if os.geteuid()==0:
                os.chown(tmp_name, 0, self.knot_gid)
            os.replace(tmp_name, self.zone_path)
            try:
                self._run(['/usr/sbin/knotc', 'zone-check', self.config.zone])
                self._run(['/usr/sbin/knotc', 'zone-reload', self.config.zone])
            except Exception:
                if old is None:
                    try: self.zone_path.unlink()
                    except FileNotFoundError: pass
                else:
                    self.zone_path.write_bytes(old)
                    os.chmod(self.zone_path, 0o640)
                    if os.geteuid()==0:
                        os.chown(self.zone_path, 0, self.knot_gid)
                raise
        finally:
            try: os.unlink(tmp_name)
            except FileNotFoundError: pass

    def txt_set(self, hostname: str, value: str) -> dict:
        hostname = self._validate_hostname(hostname)
        value = self._validate_value(value)
        records = self._load_records()
        records.setdefault(hostname, set()).add(value)
        self._atomic_write_validated(self._render_zone(records))
        self._records = records
        return {'updated': True}

    def txt_delete(self, hostname: str, value: str) -> dict:
        hostname = self._validate_hostname(hostname)
        value = self._validate_value(value)
        records = self._load_records()
        values = records.get(hostname, set())
        values.discard(value)
        if values:
            records[hostname] = values
        else:
            records.pop(hostname, None)
        self._atomic_write_validated(self._render_zone(records))
        self._records = records
        return {'deleted': True}

    def zone_check(self) -> dict:
        if not self.zone_path.is_file():
            return {'zone_loaded': False, 'zone': self.config.zone}
        self._run(['/usr/sbin/knotc', 'zone-check', self.config.zone])
        return {'zone_loaded': True, 'zone': self.config.zone}

    def status(self) -> dict:
        result = self.runner(['/usr/bin/systemctl', 'is-active', 'knot'], check=False)
        listen_ip=self.config.listen_ip
        return {
            'configured': bool(self.config.enabled),
            'service': (result.stdout or 'unknown').strip() or 'unknown',
            'zone': self.config.zone,
            'zone_loaded': self.zone_path.is_file(),
            'listen_ip': listen_ip,
            'listen_port': self.config.listen_port,
            'tcp_53': bool(listen_ip and not self._port_available(listen_ip, self.config.listen_port, 'tcp')),
            'udp_53': bool(listen_ip and not self._port_available(listen_ip, self.config.listen_port, 'udp')),
        }
