# -*- coding: utf-8 -*-
from __future__ import annotations
import base64, hashlib, json, re, socket, ssl, subprocess, time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

SENSITIVE_PATTERNS = {
    "password字段": re.compile(rb"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{4,}"),
    "token字段": re.compile(rb"(?i)(token|access_token|refresh_token)\s*[:=]\s*['\"]?[^'\"\s]{8,}"),
    "api_key字段": re.compile(rb"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[^'\"\s]{8,}"),
    "secret字段": re.compile(rb"(?i)(secret|client_secret)\s*[:=]\s*['\"]?[^'\"\s]{8,}"),
    "私钥头": re.compile(rb"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "AWS Access Key样式": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "IPv4地址": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}
AUTH_KEYWORDS = ["login","password","passwd","signin","sign in","用户名","用户登录","密码","登录","认证","鉴权"]
COMMON_PORT_HINTS = {21:"FTP/文件传输",22:"SSH/远程登录",23:"Telnet/明文远程登录",80:"HTTP/Web服务",443:"HTTPS/Web服务",502:"Modbus TCP",554:"RTSP/视频流",1883:"MQTT",2375:"Docker API/高风险明文端口",3306:"MySQL",5432:"PostgreSQL",5900:"VNC",6379:"Redis",8000:"HTTP/Web服务",8080:"HTTP/Web服务",8081:"HTTP/Web服务",8443:"HTTPS/Web服务",8883:"MQTT over TLS",9000:"常见调试/管理服务",27017:"MongoDB"}
DEFAULT_PORTS = sorted(COMMON_PORT_HINTS.keys())

def tcp_connect(ip: str, port: int, timeout: float = 2.0) -> Tuple[bool, Optional[float], Optional[str]]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout); start=time.time()
    try:
        s.connect((ip, port)); return True, round((time.time()-start)*1000,2), None
    except Exception as e:
        return False, None, str(e)
    finally:
        try: s.close()
        except Exception: pass

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    text=""
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout); s.connect((ip, port))
        try: text=s.recv(256).decode(errors="ignore").strip()
        except Exception: pass
        if not text and port in [80,8080,8081,8000,9000]:
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            text=s.recv(512).decode(errors="ignore").strip()
        s.close()
    except Exception: pass
    return text

def is_http_port(port:int)->bool: return port in [80,443,8000,8080,8081,8443,9000]
def url_for(ip:str, port:int)->str: return f"{'https' if port in [443,8443] else 'http'}://{ip}:{port}/"

def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for c in iter(lambda:f.read(1024*1024), b""): h.update(c)
    return h.hexdigest()

def scan_sensitive_bytes(data: bytes, max_hits:int=20)->List[Dict[str,Any]]:
    hits=[]
    for name, pat in SENSITIVE_PATTERNS.items():
        for m in pat.finditer(data):
            sample=m.group(0)[:120]
            hits.append({"type":name,"offset":m.start(),"sample_base64":base64.b64encode(sample).decode()})
            if len(hits)>=max_hits: return hits
    return hits

def tls_probe(ip:str, port:int, timeout:float=5.0)->Dict[str,Any]:
    out={"ip":ip,"port":port,"tls":False,"error":None}
    try:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        raw=socket.create_connection((ip,port),timeout=timeout); ss=ctx.wrap_socket(raw,server_hostname=ip)
        cert=ss.getpeercert()
        out.update({"tls":True,"tls_version":ss.version(),"cipher":ss.cipher(),"cert_subject":cert.get("subject") if cert else None,"cert_issuer":cert.get("issuer") if cert else None,"weak_tls_hint":ss.version() in ["SSLv2","SSLv3","TLSv1","TLSv1.1"]})
        ss.close()
    except Exception as e: out["error"]=str(e)
    return out

def run_command(cmd:str, timeout:int=120)->Dict[str,Any]:
    try:
        cp=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=timeout)
        return {"command":cmd,"returncode":cp.returncode,"stdout":cp.stdout[-8000:],"stderr":cp.stderr[-8000:]}
    except Exception as e: return {"command":cmd,"error":str(e)}

def add_query(url:str, params:Dict[str,str])->str:
    u=urlparse(url); q=dict(parse_qsl(u.query)); q.update(params)
    return urlunparse((u.scheme,u.netloc,u.path,u.params,urlencode(q),u.fragment))

def safe_json_load(path: Path) -> Dict[str,Any]:
    return json.loads(path.read_text(encoding="utf-8"))
