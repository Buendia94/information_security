# -*- coding: utf-8 -*-
from __future__ import annotations
import hashlib, os, platform, re, shutil, subprocess, time, zipfile
from pathlib import Path
from typing import Any, Dict, List
try:
    import requests
except Exception:
    requests=None
try:
    import paramiko
except Exception:
    paramiko=None

LOGIN_FAILURE_KEYWORDS = [
    "invalid",
    "failed",
    "incorrect",
    "unauthorized",
    "未授权",
    "失败",
    "错误",
    "密码错误",
    "登录失败",
    "用户名或密码"
]

from ..result import TestResult
from ..utils import AUTH_KEYWORDS, COMMON_PORT_HINTS, DEFAULT_PORTS, add_query, grab_banner, is_http_port, run_command, scan_sensitive_bytes, sha256_file, tcp_connect, tls_probe, url_for

class CoreTests:
    def __init__(self, config: Dict[str,Any], outdir: Path):
        self.config=config; self.outdir=outdir; self.results=[]
        self.session=None
        if requests:
            self.session=requests.Session(); self.session.verify=False
    def add(self,clause,name,method,status,evidence,suggestion=""):
        self.results.append(TestResult(clause,name,method,status,evidence,suggestion))
    def run(self):
        self.test_physical_debug_interface()
        self.test_storage_security_static()
        self.test_dolphin_attack_plan()
        self.test_ports_services_auth()
        self.test_http_auth_and_data_exposure()
        self.test_limited_invalid_login()
        self.test_tls_and_encryption()
        self.test_backup_restore_hooks()
        self.test_logs_sensitive_output()
        self.test_firmware_app_integrity_authenticity_hardcoding()
        self.test_replay_protection_from_http()
        self.test_system_monitoring_endpoints()
        self.test_input_validation()
        self.test_role_access_control()
        self.test_audit_log_hooks()
        self.test_secure_boot_trust_validation()
        self.test_update_rollback()
        self.test_storage_protection()
        self.test_wireless_security()
        self.test_mtls_authentication()
        return self.results

    def test_physical_debug_interface(self):
        serial=[]
        if platform.system().lower().startswith("win"):
            serial=[f"COM{i}" for i in range(1,33)]
        else:
            for pat in ["/dev/ttyUSB*","/dev/ttyACM*","/dev/ttyS*","/dev/serial/by-id/*"]:
                serial += [str(p) for p in Path("/").glob(pat.lstrip("/"))]
        self.add("8.1.1.1","物理接口安全-串口/USB调试接口枚举","枚举测试工装可见串口/USB调试接口；机器人壳体接口暴露情况需现场拍照核查。","INFO" if serial else "MANUAL",{"serial_candidates":serial[:64]},"若发现可访问调试串口，应确认是否禁用或配置授权访问。")
        findings=[]
        for t in self.config.get("targets",[]):
            ip=t["ip"]
            for p in [21,22,23,5555,5900,2375,9000]:
                ok,ms,err=tcp_connect(ip,p,self.config.get("timeout",2))
                if ok: findings.append({"ip":ip,"port":p,"service_hint":COMMON_PORT_HINTS.get(p,"调试/管理端口"),"banner":grab_banner(ip,p)})
        self.add("8.1.1.1","物理接口安全-网络调试/维护端口","扫描常见调试/维护端口，辅助判断硬件调试接口是否经网络暴露。","WARN" if findings else "PASS",{"open_debug_like_ports":findings},"开放调试/维护端口应确认是否为必要接口，并验证授权访问机制。")

    def test_storage_security_static(self):
        evid=[]
        for f in [Path(x) for x in self.config.get("firmware_files",[])+self.config.get("app_packages",[])]:
            if f.exists() and f.is_file(): evid.append({"file":str(f),"sha256":sha256_file(f),"size":f.stat().st_size})
        self.add("8.1.1.2","数据存储安全-固件/软件包哈希留证","对固件、应用包进行哈希留证；芯片级安全存储、访问控制、防篡改需结合芯片资料确认。","INFO" if evid else "MANUAL",{"hashes":evid},"建议补充主板芯片型号、安全存储/TEE/TPM/Secure Element资料、密钥存储策略。")

    def test_dolphin_attack_plan(self):
        gp=self.outdir/"generate_dolphin_test_wav.py"; gp.write_text(DOLPHIN_GENERATOR_CODE,encoding="utf-8")
        self.add("8.1.1.3","防海豚音攻击-测试信号生成脚本","生成正常频段、次声波和超声波测试信号；实际声场需用声源、换能器、声级计/频谱仪校准。","INFO",{"frequencies_hz":[10,15,20,1000,10000,20000,25000,30000,40000],"generator_script":str(gp)},"普通音箱难以可靠输出10/15Hz和25kHz以上信号，需低频声源或超声换能器。")

    def _run_local_command(self,cmd:str)->Dict[str,Any]:
        try:
            cp=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=int(self.config.get("command_timeout",30)))
            return {"command":cmd,"returncode":cp.returncode,"stdout":cp.stdout.strip(),"stderr":cp.stderr.strip()}
        except Exception as e:
            return {"command":cmd,"error":str(e)}

    def _path_mount_info(self,path:Path)->Dict[str,Any]:
        info={"path":str(path),"exists":path.exists()}
        if not path.exists(): return info
        info["is_file"] = path.is_file(); info["is_dir"] = path.is_dir()
        try:
            target=str(path.resolve())
            mount=None
            with open('/proc/mounts','r',encoding='utf-8',errors='ignore') as f:
                for line in f:
                    parts=line.split();
                    if len(parts) < 4: continue
                    mnt=parts[1]; opts=parts[3].split(',')
                    if target.startswith(mnt.rstrip('/')) and (mount is None or len(mnt) > len(mount[0])):
                        mount=(mnt,opts)
            if mount:
                info["mount_point"] = mount[0]
                info["mount_options"] = mount[1]
                info["mounted_readonly"] = 'ro' in mount[1]
        except Exception as e:
            info["mount_info_error"] = str(e)
        return info

    def _check_immutable_attr(self,path:Path)->Dict[str,Any]:
        out={"path":str(path),"immutable":False}
        if not self.config.get("allow_commands",False):
            out["skipped"] = "allow_commands=false"
            return out
        if shutil.which("lsattr") is None:
            out["skipped"] = "lsattr unavailable"
            return out
        try:
            cp=self._run_local_command(f"lsattr -d {str(path)}")
            if cp.get("stdout"):
                out["command_output"] = cp["stdout"]
                out["immutable"] = 'i' in cp["stdout"].split()[0]
            else:
                out["command_output"] = cp.get("stderr")
        except Exception as e:
            out["error"] = str(e)
        return out

    def _find_secure_boot_status(self)->Dict[str,Any]:
        out={}
        if self.config.get("secure_boot_check_command") and self.config.get("allow_commands",False):
            out["command"] = self.config["secure_boot_check_command"]
            out["result"] = self._run_local_command(out["command"])
            return out
        if platform.system().lower() != "linux":
            out["note"] = "仅支持本机 Linux EFI 安全启动检测，远端目标无法自动检查。"
            return out
        if shutil.which("mokutil"):
            out["mokutil"] = self._run_local_command("mokutil --sb-state")
            return out
        efidir=Path("/sys/firmware/efi/efivars")
        if efidir.exists():
            files=list(efidir.glob("SecureBoot-*"))
            if files:
                try:
                    data=files[0].read_bytes()
                    out["secure_boot_enabled"] = bool(data[4])
                    out["source"] = str(files[0])
                except Exception as e:
                    out["error"] = str(e)
                return out
        out["note"] = "未找到 EFI SecureBoot 状态或 Mokutil 工具。"
        return out

    def _http_form_wrong_password_test(self,ep:Dict[str,Any])->Dict[str,Any]:
        out={"service":"http_form","url":ep.get("url"),"username":ep.get("username","test"),"attempts":ep.get("attempts",1),"unexpected_success":False,"events":[]}
        if not requests:
            out["error"] = "requests未安装"
            return out
        wrong=ep.get("wrong_password","WrongPassword_For_GBT45502_Test_123!")
        username_field=ep.get("username_field","username")
        password_field=ep.get("password_field","password")
        for i in range(out["attempts"]):
            try:
                data={username_field:out["username"], password_field:wrong}
                resp=self.session.post(out["url"],data=data,timeout=self.config.get("http_timeout",5),allow_redirects=False)
                body=resp.text.lower()
                rejected=resp.status_code in [401,403] or any(k in body for k in LOGIN_FAILURE_KEYWORDS)
                success=resp.status_code in [200,302] and not rejected
                out["events"].append({"attempt":i+1,"status_code":resp.status_code,"rejected":rejected,"location":resp.headers.get("Location"),"failure_hints":[k for k in LOGIN_FAILURE_KEYWORDS if k in body][:5]})
                if success: out["unexpected_success"] = True
            except Exception as e:
                out["events"].append({"attempt":i+1,"error":str(e)})
        return out

    def test_ports_services_auth(self):
        expected=set(self.config.get("expected_open_ports",[])); allf=[]; unexp=[]
        for t in self.config.get("targets",[]):
            ip=t["ip"]; ports=t.get("ports") or self.config.get("ports") or DEFAULT_PORTS
            for p in ports:
                ok,ms,err=tcp_connect(ip,int(p),self.config.get("timeout",2))
                if ok:
                    item={"ip":ip,"port":int(p),"service_hint":COMMON_PORT_HINTS.get(int(p),"未知/需人工确认"),"connect_ms":ms,"banner":grab_banner(ip,int(p))}
                    allf.append(item)
                    if expected and int(p) not in expected: unexp.append(item)
        self.add("8.1.1.4 / 8.1.2.3 / 8.1.2.4 / 8.1.2.5","端口、服务、非必要接口与防火墙辅助检查","扫描目标开放端口，辅助判断通信方式、最少服务原则、防火墙过滤和非必要接口关闭情况。","WARN" if unexp else ("INFO" if allf else "PASS"),{"open_ports":allf,"unexpected_open_ports":unexp,"expected_open_ports":sorted(expected)},"开放端口应形成白名单；非业务端口关闭或限制来源IP；所有可访问接口应配置授权访问。")

    def test_http_auth_and_data_exposure(self):
        findings=[]
        for t in self.config.get("targets",[]):
            ip=t["ip"]; ports=t.get("ports") or self.config.get("ports") or DEFAULT_PORTS
            for p in ports:
                if is_http_port(int(p)) and requests: findings.append(self.http_probe(url_for(ip,int(p))))
        st="WARN" if any(x.get("possible_unauth_access") or x.get("sensitive_leak_in_response") for x in findings) else ("PASS" if findings else "MANUAL")
        self.add("8.1.1.4 / 8.1.2.1 / 8.1.3.5 / 8.2.1.2 / 8.2.2.3 / 8.3.3.1","HTTP/HTTPS身份验证与重要数据输出检查","访问HTTP/HTTPS首页，判断是否存在401/403、登录页、未鉴权访问和敏感字段明文输出。",st,{"http_findings":findings},"若管理页面、API、视频流或配置页无需登录即可访问，应判为风险；响应中不应明文返回密码、Token、API Key等。")
    def http_probe(self,url):
        r={"url":url,"error":None}
        try:
            resp=self.session.get(url,timeout=self.config.get("http_timeout",5),allow_redirects=True)
            text=resp.text[:20000]; lower=text.lower()
            auth_like=resp.status_code in [401,403] or any(k in lower for k in AUTH_KEYWORDS)
            sensitive=scan_sensitive_bytes(text.encode(errors="ignore"),max_hits=10)
            r.update({"status_code":resp.status_code,"final_url":resp.url,"server":resp.headers.get("Server"),"www_authenticate":resp.headers.get("WWW-Authenticate"),"auth_like":auth_like,"possible_unauth_access":resp.status_code==200 and not auth_like,"sensitive_leak_in_response":len(sensitive)>0,"sensitive_hits":sensitive})
        except Exception as e: r["error"]=str(e)
        return r

    def test_limited_invalid_login(self):
        attempts=min(int(self.config.get("auth_attempts",3)),5); findings=[]
        for t in self.config.get("targets",[]):
            ip=t["ip"]; ssh_user=t.get("ssh_user") or self.config.get("ssh_user")
            ok,_,_=tcp_connect(ip,22,self.config.get("timeout",2))
            if ok and ssh_user: findings.append(self.ssh_wrong_password_test(ip,22,ssh_user,attempts))
        for item in self.config.get("http_basic_tests",[]):
            findings.append(self.http_basic_wrong_password_test(item["url"],item["username"],attempts))
        for item in self.config.get("http_form_tests",[]):
            findings.append(self._http_form_wrong_password_test(item))
        self.add("8.1.1.4 / 8.1.2.1 / 8.2.2.2 / 8.3.1.2 / 8.3.3.1","身份验证抗暴力破解/错误口令有限验证","仅使用固定错误口令进行少量认证失败测试，观察拒绝、延迟、锁定等防护迹象。","WARN" if any(x.get("unexpected_success") for x in findings) else ("INFO" if findings else "MANUAL"),{"auth_test_findings":findings},"建议配合人工检查密码复杂度策略、失败次数限制、账户锁定、验证码、多因素认证、证书认证等配置。")
    def ssh_wrong_password_test(self,ip,port,username,attempts):
        out={"service":"ssh","ip":ip,"port":port,"username":username,"attempts":attempts,"unexpected_success":False,"events":[]}
        if not paramiko: out["error"]="paramiko未安装"; return out
        wrong="WrongPassword_For_GBT45502_Test_123!"; times=[]
        for i in range(attempts):
            c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy()); start=time.time()
            try:
                c.connect(ip,port=port,username=username,password=wrong,timeout=5,banner_timeout=5,auth_timeout=5,allow_agent=False,look_for_keys=False)
                elapsed=round(time.time()-start,2); out["unexpected_success"]=True; out["events"].append({"attempt":i+1,"result":"UNEXPECTED_LOGIN_SUCCESS","elapsed_sec":elapsed})
            except Exception as e:
                elapsed=round(time.time()-start,2); times.append(elapsed); out["events"].append({"attempt":i+1,"result":"rejected_or_error","elapsed_sec":elapsed,"message":str(e)[:200]})
            finally:
                try: c.close()
                except Exception: pass
            time.sleep(float(self.config.get("auth_delay",1)))
        out["delay_or_lockout_hint"]=len(times)>=2 and (max(times)-min(times)>=2.0)
        return out
    def http_basic_wrong_password_test(self,url,username,attempts):
        out={"service":"http_basic","url":url,"username":username,"attempts":attempts,"unexpected_success":False,"events":[]}
        if not requests: out["error"]="requests未安装"; return out
        wrong="WrongPassword_For_GBT45502_Test_123!"; times=[]
        for i in range(attempts):
            start=time.time()
            try:
                resp=self.session.get(url,auth=(username,wrong),timeout=5,allow_redirects=False); elapsed=round(time.time()-start,2); times.append(elapsed)
                if resp.status_code==200: out["unexpected_success"]=True
                out["events"].append({"attempt":i+1,"status_code":resp.status_code,"elapsed_sec":elapsed,"www_authenticate":resp.headers.get("WWW-Authenticate")})
            except Exception as e:
                elapsed=round(time.time()-start,2); times.append(elapsed); out["events"].append({"attempt":i+1,"error":str(e)[:200],"elapsed_sec":elapsed})
            time.sleep(float(self.config.get("auth_delay",1)))
        out["delay_or_lockout_hint"]=len(times)>=2 and (max(times)-min(times)>=2.0)
        return out

    def test_tls_and_encryption(self):
        findings=[]
        for t in self.config.get("targets",[]):
            ip=t["ip"]; ports=t.get("ports") or self.config.get("ports") or DEFAULT_PORTS
            for p in ports:
                p=int(p)
                if p in [443,8443,8883]: findings.append(tls_probe(ip,p))
                elif p in [80,8080,8081,1883]:
                    ok,_,_=tcp_connect(ip,p,self.config.get("timeout",2))
                    if ok: findings.append({"ip":ip,"port":p,"tls":False,"warning":"明文服务端口开放，需确认是否传输敏感数据"})
        self.add("8.1.3.1 / 8.1.3.2 / 8.2.1.1 / 8.3.2.1 / 8.3.2.3","通信加密、TLS与证书基础检查","检查HTTPS/MQTTS端口TLS版本、证书信息；标记HTTP/MQTT等明文端口。","WARN" if any((not x.get("tls",False)) or x.get("weak_tls_hint") for x in findings) else ("PASS" if findings else "MANUAL"),{"tls_findings":findings},"涉及控制指令、用户数据、配置数据的通信应优先采用TLS/安全通道；双向身份验证需结合客户端证书配置补充验证。")

    def test_backup_restore_hooks(self):
        evid={}; status="MANUAL"
        if self.config.get("backup_command"):
            if self.config.get("allow_commands",False):
                evid["backup"]=run_command(self.config["backup_command"]); status="PASS" if evid["backup"].get("returncode")==0 else "WARN"
            else: evid["backup"]={"command":self.config["backup_command"],"skipped":"未设置allow_commands=true，未执行外部命令"}
        if self.config.get("restore_check_command"):
            if self.config.get("allow_commands",False):
                evid["restore_check"]=run_command(self.config["restore_check_command"])
                if evid["restore_check"].get("returncode")!=0: status="WARN"
            else: evid["restore_check"]={"command":self.config["restore_check_command"],"skipped":"未设置allow_commands=true，未执行外部命令"}
        self.add("8.1.3.4 / 8.3.2.4","数据备份与恢复功能命令编排","执行用户配置的备份命令和恢复检查命令，仅作为自动化留证。",status,evid,"建议在隔离测试环境中模拟数据损坏或丢失，验证备份文件可用性、恢复时长和恢复后数据一致性。")

    def test_logs_sensitive_output(self):
        findings=[]; log_dirs=[Path(x) for x in self.config.get("log_dirs",[])]
        for d in log_dirs:
            if not d.exists(): findings.append({"path":str(d),"error":"not exists"}); continue
            for f in list(d.rglob("*"))[:5000]:
                if f.is_file() and f.stat().st_size<=20*1024*1024:
                    try:
                        hits=scan_sensitive_bytes(f.read_bytes(),max_hits=5)
                        if hits: findings.append({"file":str(f),"hits":hits})
                    except Exception: pass
        self.add("8.1.3.5 / 8.2.1.2","日志/输出文件重要数据明文检查","扫描日志目录中的密码、Token、API Key、私钥等敏感信息模式。","WARN" if findings else ("PASS" if log_dirs else "MANUAL"),{"sensitive_log_findings":findings[:100]},"日志中不应明文输出用户身份信息、系统配置、会话令牌、API密钥、证书私钥等重要数据。")

    def test_firmware_app_integrity_authenticity_hardcoding(self):
        findings=[]; files=[Path(x) for x in self.config.get("firmware_files",[])+self.config.get("app_packages",[])]
        for f in files:
            if not f.exists() or not f.is_file(): findings.append({"file":str(f),"error":"not exists"}); continue
            item={"file":str(f),"size":f.stat().st_size,"sha256":sha256_file(f),"sensitive_hits":[]}
            item["sidecar_signature_or_hash_files"]=[str(Path(str(f)+ext)) for ext in [".sig",".sign",".signature",".sha256",".md5",".crt",".pem"] if Path(str(f)+ext).exists()]
            try:
                if zipfile.is_zipfile(f):
                    with zipfile.ZipFile(f) as z:
                        names=z.namelist()[:2000]; item["archive_entries_sample"]=names[:50]; item["apk_signature_entries"]=[n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA",".DSA",".EC",".SF"))]
                        for n in names:
                            if len(item["sensitive_hits"])>=20: break
                            try:
                                info=z.getinfo(n)
                                if info.file_size<=2*1024*1024:
                                    hits=scan_sensitive_bytes(z.read(n),max_hits=3)
                                    if hits: item["sensitive_hits"].append({"entry":n,"hits":hits})
                            except Exception: pass
                elif f.stat().st_size<=100*1024*1024:
                    item["sensitive_hits"]=scan_sensitive_bytes(f.read_bytes(),max_hits=20)
            except Exception as e: item["error"]=str(e)
            findings.append(item)
        self.add("8.1.4.2 / 8.1.4.3 / 8.2.2.5 / 8.2.2.6 / 8.2.2.8","固件/软件完整性、真实性与防硬编码静态检查","计算SHA256，探测签名/哈希旁路文件，扫描固件或应用包中的敏感硬编码信息。","WARN" if any(x.get("sensitive_hits") for x in findings) else ("INFO" if findings else "MANUAL"),{"package_findings":findings},"完整性宜采用哈希/CRC/签名校验；真实性宜采用数字签名。发现硬编码密钥、Token、证书私钥时应整改。")

    def test_replay_protection_from_http(self):
        endpoints=self.config.get("replay_check_urls",[]); findings=[]; clause="8.1.4.5 / 8.3.2.2"
        if not endpoints: self.add(clause,"关键指令/后台请求防重放测试","未配置 replay_check_urls，无法执行重放测试。","MANUAL",{"replay_findings":[]},"建议配置只读查询接口或测试指令接口。"); return
        if not requests: self.add(clause,"关键指令/后台请求防重放测试","requests 未安装，无法执行 HTTP 重放测试。","ERROR",{"error":"requests未安装"},"请执行 pip install requests 后重试。"); return
        reject_keywords=["replay","duplicate","nonce","timestamp","expired","invalid signature","signature expired","request expired","csrf","token invalid","重放","重复","随机数","时间戳","过期","签名无效","令牌无效","请求已过期"]
        for ep in endpoints:
            if isinstance(ep,str): ep={"name":ep,"url":ep,"method":"GET","repeat":3,"interval_sec":1}
            item={"name":ep.get("name","未命名重放测试"),"url":ep.get("url"),"method":ep.get("method","GET").upper(),"repeat":min(int(ep.get("repeat",3)),10),"interval_sec":float(ep.get("interval_sec",1)),"events":[],"same_request_replayed":True,"replay_rejected_observed":False}
            for i in range(item["repeat"]):
                start=time.time()
                try:
                    method=item["method"]; url=item["url"]; headers=ep.get("headers",{}); params=ep.get("params")
                    if method=="GET": resp=self.session.get(url,headers=headers,params=params,timeout=5,allow_redirects=False)
                    elif method=="POST": resp=self.session.post(url,headers=headers,params=params,json=ep.get("json"),data=ep.get("data"),timeout=5,allow_redirects=False)
                    elif method=="PUT": resp=self.session.put(url,headers=headers,params=params,json=ep.get("json"),data=ep.get("data"),timeout=5,allow_redirects=False)
                    else: item["events"].append({"attempt":i+1,"error":f"暂不支持的method: {method}"}); break
                    text=resp.text[:5000]; body_hash=hashlib.sha256(text.encode("utf-8",errors="ignore")).hexdigest()
                    reject_hint=resp.status_code in [400,401,403,409,422,429] or any(k in text.lower() for k in reject_keywords)
                    if reject_hint and i>0: item["replay_rejected_observed"]=True
                    item["events"].append({"attempt":i+1,"status_code":resp.status_code,"elapsed_sec":round(time.time()-start,3),"body_sha256":body_hash,"body_sample":text[:300],"replay_reject_hint":reject_hint})
                except Exception as e: item["events"].append({"attempt":i+1,"elapsed_sec":round(time.time()-start,3),"error":str(e)})
                time.sleep(item["interval_sec"])
            codes=[e.get("status_code") for e in item["events"] if "status_code" in e]; hashes=[e.get("body_sha256") for e in item["events"] if "body_sha256" in e]
            item["all_responses_same_status"]=len(set(codes))==1 if codes else None; item["all_responses_same_body_hash"]=len(set(hashes))==1 if hashes else None
            if item["replay_rejected_observed"]: item["judgement"]="初步通过：重复请求过程中观察到拒绝、过期、重复请求或令牌异常等防重放迹象。"
            elif len(codes)>=2 and all(c in [200,201,202,204] for c in codes): item["judgement"]="疑似不通过：同一请求被多次成功接受，未观察到防重放拒绝迹象。"
            elif len(codes)>=2: item["judgement"]="需人工确认：多次请求未全部成功，但拒绝原因不明确。"
            else: item["judgement"]="未完成：有效响应次数不足。"
            findings.append(item)
        st="PASS" if any(x.get("replay_rejected_observed") for x in findings) else ("WARN" if any("疑似不通过" in str(x.get("judgement","")) for x in findings) else "MANUAL")
        self.add(clause,"关键指令/后台请求防重放测试","对配置的URL/API重复发送完全相同的请求，观察系统是否通过时间戳、随机数、序列号、令牌、签名等机制拒绝重放请求。",st,{"replay_findings":findings},"建议在隔离测试环境中使用无动作指令或只读接口；若同一关键指令可被多次成功执行，应补充 nonce、timestamp、sequence、签名校验或一次性Token机制。")

    def test_system_monitoring_endpoints(self):
        findings=[]
        for url in self.config.get("monitoring_urls",[]):
            if not requests: findings.append({"url":url,"error":"requests未安装"}); continue
            try:
                resp=self.session.get(url,timeout=5); text=resp.text[:5000].lower()
                findings.append({"url":url,"status":resp.status_code,"has_resource_keywords":any(k in text for k in ["cpu","memory","mem","disk","storage","network","prometheus","metrics"])})
            except Exception as e: findings.append({"url":url,"error":str(e)})
        self.add("8.3.1.5","系统资源监控接口检查","访问配置的监控URL，检查是否包含CPU、内存、存储、网络资源等监控信息。","PASS" if findings and any(x.get("has_resource_keywords") for x in findings) else ("WARN" if findings else "MANUAL"),{"monitoring_findings":findings},"后台管理系统应具备资源监控与报警功能；若无接口，应提供系统截图或日志证据。")

    def test_input_validation(self):
        endpoints=self.config.get("input_validation_tests",[]); payloads=["' OR '1'='1","\" OR \"1\"=\"1","1; whoami","$(whoami)","../../../etc/passwd","<script>alert(1)</script>"]; findings=[]
        for ep in endpoints:
            if not requests: findings.append({"endpoint":ep,"error":"requests未安装"}); continue
            item={"url":ep.get("url"),"method":ep.get("method","GET").upper(),"param":ep.get("param","q"),"events":[]}
            for p in payloads:
                try:
                    resp=self.session.get(add_query(item["url"],{item["param"]:p}),timeout=5,allow_redirects=False) if item["method"]=="GET" else self.session.post(item["url"],json={item["param"]:p},timeout=5,allow_redirects=False)
                    body=resp.text[:2000].lower(); item["events"].append({"payload":p,"status":resp.status_code,"reflected":p.lower() in body,"sql_error_hint":any(x in body for x in ["sql syntax","mysql","postgres","sqlite","ora-","odbc"]),"cmd_error_hint":any(x in body for x in ["uid=","gid=","root:","command not found"])})
                except Exception as e: item["events"].append({"payload":p,"error":str(e)})
            findings.append(item)
        risky=any(e.get("sql_error_hint") or e.get("cmd_error_hint") for f in findings for e in f.get("events",[]))
        self.add("8.3.3.2","API输入验证基础检查","对配置的API参数发送无害异常字符串，观察是否拒绝、报错或直接反射。","WARN" if risky else ("INFO" if findings else "MANUAL"),{"input_validation_findings":findings},"若出现SQL/命令执行报错、异常堆栈或未转义反射，应进一步进行授权渗透测试和代码修复。")

    def test_role_access_control(self):
        findings=[]
        for t in self.config.get("role_access_tests",[]):
            if not requests: findings.append({"test":t,"error":"requests未安装"}); continue
            try:
                resp=self.session.get(t["url"],headers=t.get("headers",{}),timeout=5,allow_redirects=False); forbidden=resp.status_code in [401,403]
                findings.append({"url":t["url"],"status":resp.status_code,"expected_forbidden":t.get("expected_forbidden",True),"actual_forbidden":forbidden})
            except Exception as e: findings.append({"url":t.get("url"),"error":str(e)})
        self.add("8.1.2.2 / 8.2.2.1 / 8.3.1.4 / 8.3.3.4","权限划分/越权访问检查","使用配置的低权限/非法Token访问受限资源，检查是否返回401/403。","PASS" if findings and all(x.get("actual_forbidden")==x.get("expected_forbidden") for x in findings if not x.get("error")) else ("WARN" if findings else "MANUAL"),{"role_access_findings":findings},"需准备普通用户、管理员、非法用户等测试账号/Token，逐项验证最小权限和越权拒绝。")

    def test_audit_log_hooks(self):
        findings=[]
        for url in self.config.get("audit_trigger_urls",[]):
            if not requests: findings.append({"url":url,"error":"requests未安装"}); continue
            try:
                resp=self.session.get(url,timeout=5,allow_redirects=False); findings.append({"url":url,"status":resp.status_code,"note":"已触发一次访问事件，请在审计日志中核查是否记录。"})
            except Exception as e: findings.append({"url":url,"error":str(e)})
        self.add("8.1.2.6 / 8.3.1.1","安全审计事件触发留证","访问配置的测试URL或错误登录接口，触发用户访问/异常事件；日志记录需在后台审计日志中人工核查。","INFO" if findings else "MANUAL",{"audit_trigger_findings":findings},"应核查日志是否记录用户、时间、来源IP、操作对象、操作结果、异常类型等关键字段。")

    def test_secure_boot_trust_validation(self):
        evidence = {"secure_boot_check_command": self.config.get("secure_boot_check_command")}
        result = self._find_secure_boot_status()
        evidence.update(result)
        if result.get("result"):
            status = "PASS" if result["result"].get("returncode") == 0 else "WARN"
        elif result.get("secure_boot_enabled") is True:
            status = "PASS"
        elif result.get("secure_boot_enabled") is False:
            status = "WARN"
        else:
            status = "MANUAL"
        self.add("8.1.2.8","可信验证","人工/半自动核查项","%s" % status,evidence,"检查Secure Boot/可信根/引导加载程序/应用可信验证配置；异常注入需在隔离环境人工执行。")

    def test_update_rollback(self):
        evidence={}
        status="MANUAL"
        if self.config.get("update_check_command"):
            if self.config.get("allow_commands",False):
                evidence["update_check"] = self._run_local_command(self.config["update_check_command"])
                status = "PASS" if evidence["update_check"].get("returncode") == 0 else "WARN"
            else:
                evidence["update_check"] = {"command":self.config["update_check_command"],"skipped":"未设置allow_commands=true，未执行外部命令"}
        if self.config.get("rollback_check_command"):
            if self.config.get("allow_commands",False):
                evidence["rollback_check"] = self._run_local_command(self.config["rollback_check_command"])
                if evidence["rollback_check"].get("returncode") != 0: status = "WARN"
                elif status == "MANUAL": status = "PASS"
            else:
                evidence["rollback_check"] = {"command":self.config["rollback_check_command"],"skipped":"未设置allow_commands=true，未执行外部命令"}
                if status == "MANUAL": status = "INFO"
        self.add("8.1.4.4 / 8.2.2.7","更新异常回滚","固件/软件更新中断电、断网、强制重启需现场安全执行，脚本仅记录版本和哈希。",status,evidence,"固件/软件更新中断电、断网、强制重启需现场安全执行，脚本仅记录版本和哈希。")

    def test_storage_protection(self):
        findings=[]; paths=[Path(x) for x in self.config.get("storage_protection_paths",[])]
        for p in paths:
            info=self._path_mount_info(p); info["immutable"] = None
            if p.exists() and p.is_file(): info["immutable"] = self._check_immutable_attr(p)
            elif p.exists() and p.is_dir(): info["immutable"] = self._check_immutable_attr(p)
            findings.append(info)
        if not paths:
            self.add("8.3.1.3","防格式化","需查看物理写保护、逻辑写保护、存储分区保护策略或虚拟化环境配置。","MANUAL",{"storage_protection_findings":findings},"需查看物理写保护、逻辑写保护、存储分区保护策略或虚拟化环境配置。")
            return
        warns=[f for f in findings if f.get("exists") and not f.get("mounted_readonly") and not (isinstance(f.get("immutable"),dict) and f["immutable"].get("immutable"))]
        status="PASS" if findings and not warns else ("WARN" if warns else "MANUAL")
        self.add("8.3.1.3","防格式化","需查看物理写保护、逻辑写保护、存储分区保护策略或虚拟化环境配置。",status,{"storage_protection_findings":findings},"需查看物理写保护、逻辑写保护、存储分区保护策略或虚拟化环境配置。")

    def test_wireless_security(self):
        findings=[]
        cmd=self.config.get("wireless_scan_command")
        if cmd:
            if self.config.get("allow_commands",False):
                findings.append(self._run_local_command(cmd))
            else:
                findings.append({"command":cmd,"skipped":"未设置allow_commands=true，未执行无线扫描命令"})
        if self.config.get("wireless_interfaces"):
            findings.append({"wireless_interfaces":self.config.get("wireless_interfaces")})
        if not findings:
            self.add("8.1.3.3","无线安全","WAPI/蓝牙/Zigbee安全配置需结合无线扫描仪、协议分析仪和设备配置界面核查。","MANUAL",{},"WAPI/蓝牙/Zigbee安全配置需结合无线扫描仪、协议分析仪和设备配置界面核查。")
            return
        status="PASS"
        if any(f.get("skipped") for f in findings): status="INFO"
        self.add("8.1.3.3","无线安全","WAPI/蓝牙/Zigbee安全配置需结合无线扫描仪、协议分析仪和设备配置界面核查。",status,{"wireless_security_findings":findings},"WAPI/蓝牙/Zigbee安全配置需结合无线扫描仪、协议分析仪和设备配置界面核查。")

    def test_mtls_authentication(self):
        tests=self.config.get("mtls_tests",[])
        findings=[]
        if not tests:
            self.add("8.1.3.2","双向身份验证","mTLS需准备客户端证书/无效证书分别访问验证，脚本TLS探测不能完全替代。","MANUAL",{},"mTLS需准备客户端证书/无效证书分别访问验证，脚本TLS探测不能完全替代。")
            return
        if not requests:
            self.add("8.1.3.2","双向身份验证","requests 未安装，无法执行 mTLS 测试。","ERROR",{"error":"requests未安装"},"请执行 pip install requests 后重试。")
            return
        for t in tests:
            item={"name":t.get("name",t.get("url","未命名mTLS测试")),"url":t.get("url"),"cert":t.get("cert"),"key":t.get("key"),"success_with_cert":False,"status_with_cert":None,"status_without_cert":None,"events":[]}
            try:
                resp=self.session.get(item["url"],cert=(item["cert"],item["key"]),timeout=self.config.get("http_timeout",5),verify=False,allow_redirects=False)
                item["status_with_cert"] = resp.status_code
                item["success_with_cert"] = resp.status_code in [200,201,204]
                item["events"].append({"with_cert":True,"status":resp.status_code})
            except Exception as e:
                item["events"].append({"with_cert":True,"error":str(e)})
            try:
                resp2=self.session.get(item["url"],timeout=self.config.get("http_timeout",5),verify=False,allow_redirects=False)
                item["status_without_cert"] = resp2.status_code
                item["events"].append({"with_cert":False,"status":resp2.status_code})
            except Exception as e:
                item["events"].append({"with_cert":False,"error":str(e)})
            findings.append(item)
        insecure = any((not x.get("success_with_cert")) or x.get("status_without_cert") in [200,201,204] for x in findings)
        status = "PASS" if findings and not insecure else ("WARN" if findings else "MANUAL")
        self.add("8.1.3.2","双向身份验证","mTLS需准备客户端证书/无效证书分别访问验证，脚本TLS探测不能完全替代。",status,{"mtls_tests":findings},"mTLS需准备客户端证书/无效证书分别访问验证，脚本TLS探测不能完全替代。")

DOLPHIN_GENERATOR_CODE=r"""# -*- coding: utf-8 -*-
import math, wave, struct
from pathlib import Path
def gen_sine_wav(freq,duration=5.0,sample_rate=192000,amp=0.2,out="out.wav"):
    n=int(duration*sample_rate); frames=bytearray()
    for i in range(n):
        v=amp*math.sin(2*math.pi*freq*i/sample_rate)
        frames += struct.pack("<h", int(max(-1,min(1,v))*32767))
    with wave.open(out,"w") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(sample_rate); w.writeframes(frames)
if __name__=="__main__":
    Path("dolphin_wavs").mkdir(exist_ok=True)
    for f in [10,15,20,1000,10000,20000,25000,30000,40000]:
        gen_sine_wav(f,out=f"dolphin_wavs/sine_{f}Hz.wav")
    print("已生成测试WAV。注意：能否真实输出取决于声卡、功放、扬声器/换能器能力。")
"""
