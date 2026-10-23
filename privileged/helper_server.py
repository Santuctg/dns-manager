from __future__ import annotations
import json, os, socket, threading
from contextlib import nullcontext
from typing import Callable
from privileged.helper_lib import HelperOps
from privileged.ssl_helper import SslHelperOps
from privileged.acme_dns_helper import AcmeDnsHelperOps
from privileged.firewall_helper import FirewallHelperOps

LEGACY={"validate","apply","rollback","status"}
SSL_FIELDS={
 "ssl_status":{"domain"}, "ssl_apply":{"domain","redirect_http","upstream"}, "ssl_delete":{"domain"},
 "ssl_issue":{"domain","provider","token"}, "ssl_renew":{"domain","provider","token","force"}, "ssl_test_renewal":{"domain","provider","token"}, "ssl_manual_continue":{"domain"}, "ssl_manual_status":{"domain"}
}
FIREWALL_FIELDS={"firewall_status":set(),"firewall_preview":{"policy"},"firewall_apply":{"policy"},"firewall_confirm":{"token"},"firewall_rollback":{"token"}}
ACME_FIELDS={"acme_dns_status":set(), "acme_zone_check":set(), "acme_txt_set":{"hostname","value"}, "acme_txt_delete":{"hostname","value"}}
MAX_REQUEST_BYTES=16384
REQUEST_READ_TIMEOUT=10.0
MAX_CONCURRENT_REQUESTS=16

# Requests are served concurrently so that a long certbot run cannot stall
# status checks, firewall confirmation (which races a 120 s rollback timer) or
# the ACME hooks certbot itself calls back into this helper. Commands that
# change the same state are still serialised by these locks.
_CONFIG_LOCK=threading.Lock()
_FIREWALL_LOCK=threading.Lock()
_SSL_LOCK=threading.Lock()
_ACME_LOCK=threading.Lock()
_COMMAND_LOCKS={
 # Everything that writes /etc/nginx/conf.d or reloads nginx/dnsmasq.
 "validate":_CONFIG_LOCK, "apply":_CONFIG_LOCK, "rollback":_CONFIG_LOCK, "ssl_apply":_CONFIG_LOCK, "ssl_delete":_CONFIG_LOCK,
 "firewall_preview":_FIREWALL_LOCK, "firewall_apply":_FIREWALL_LOCK, "firewall_confirm":_FIREWALL_LOCK, "firewall_rollback":_FIREWALL_LOCK,
 # certbot runs; these must not hold the ACME lock, which certbot's hooks need.
 "ssl_issue":_SSL_LOCK, "ssl_renew":_SSL_LOCK, "ssl_test_renewal":_SSL_LOCK,
 "acme_txt_set":_ACME_LOCK, "acme_txt_delete":_ACME_LOCK,
}

def _command_lock(request:str):
    if request in LEGACY: name=request
    else:
        try: payload=json.loads(request)
        except ValueError: return nullcontext()
        name=payload.get("command") if isinstance(payload,dict) else None
    lock=_COMMAND_LOCKS.get(name) if isinstance(name,str) else None
    return lock if lock is not None else nullcontext()

def handle_request(request:str, ops=None, acme_ops=None)->dict:
    with _command_lock(request):
        return _dispatch(request, ops, acme_ops)

def _dispatch(request:str, ops=None, acme_ops=None)->dict:
    try:
        if request in LEGACY:
            target=ops or HelperOps(); result=getattr(target,request)(); return {"ok":True,**result}
        payload=json.loads(request); command=payload.pop("command")
        if command in FIREWALL_FIELDS:
            if set(payload)-FIREWALL_FIELDS[command]: return {"ok":False,"error":"unsupported privileged helper command"}
            target=FirewallHelperOps()
            method={"firewall_status":"status","firewall_preview":"preview","firewall_apply":"apply","firewall_confirm":"confirm","firewall_rollback":"rollback"}[command]
            arg = payload.get("policy") if command in {"firewall_preview","firewall_apply"} else payload.get("token")
            result = getattr(target,method)() if command=="firewall_status" else getattr(target,method)(arg)
            return {"ok":True,**result}
        if command in ACME_FIELDS:
            if set(payload)-ACME_FIELDS[command]: return {"ok":False,"error":"unsupported privileged helper command"}
            target=acme_ops or AcmeDnsHelperOps()
            method={"acme_dns_status":"status","acme_zone_check":"zone_check","acme_txt_set":"txt_set","acme_txt_delete":"txt_delete"}[command]
            result=getattr(target,method)(**payload); return {"ok":True,**result}
        if command not in SSL_FIELDS or set(payload)-SSL_FIELDS[command]: return {"ok":False,"error":"unsupported privileged helper command"}
        target=ops or SslHelperOps(); result=getattr(target,command)(**payload); return {"ok":True,**result}
    except Exception as exc: return {"ok":False,"error":str(exc)}

def _read_request(conn:socket.socket)->str:
    data=bytearray()
    while b"\n" not in data:
        part=conn.recv(4096)
        if not part: break
        data.extend(part)
        if len(data)>MAX_REQUEST_BYTES:return ""
    try:return bytes(data).split(b"\n",1)[0].decode("utf-8",errors="strict")
    except UnicodeDecodeError:return ""

def systemd_listener()->socket.socket:
    if int(os.environ.get("LISTEN_FDS","0"))<1: raise RuntimeError("no systemd socket passed")
    listen_pid=int(os.environ.get("LISTEN_PID","0"))
    if listen_pid not in (0,os.getpid()): raise RuntimeError("systemd socket belongs to another process")
    return socket.fromfd(3,socket.AF_UNIX,socket.SOCK_STREAM)

def _serve_connection(conn:socket.socket, ops_factory:Callable[[],HelperOps])->None:
    with conn:
        # A client that connects and never sends a full line must not hold a worker forever.
        conn.settimeout(REQUEST_READ_TIMEOUT)
        try: request=_read_request(conn)
        except (socket.timeout, OSError): return
        payload=handle_request(request, ops_factory() if request in LEGACY else None)
        try:
            conn.sendall((json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n").encode())
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            return

def serve_once(listener:socket.socket,ops_factory:Callable[[],HelperOps]=HelperOps)->None:
    conn,_=listener.accept()
    _serve_connection(conn, ops_factory)

def serve_forever(listener=None,ops_factory=HelperOps,max_concurrent:int=MAX_CONCURRENT_REQUESTS)->None:
    listener=listener or systemd_listener()
    slots=threading.BoundedSemaphore(max_concurrent)
    def worker(conn):
        try: _serve_connection(conn, ops_factory)
        finally: slots.release()
    while True:
        slots.acquire()
        try: conn,_=listener.accept()
        except BaseException:
            slots.release(); raise
        threading.Thread(target=worker,args=(conn,),daemon=True).start()
