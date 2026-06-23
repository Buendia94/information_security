# -*- coding: utf-8 -*-
from __future__ import annotations
import shutil, subprocess
from pathlib import Path
from typing import Any, Dict, List
from ..result import TestResult

EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

class ThreatDetectionModule:
    def __init__(self,config:Dict[str,Any],outdir:Path):
        self.config=config; self.outdir=outdir; self.results=[]
    def add(self,clause,name,method,status,evidence,suggestion=""):
        self.results.append(TestResult(clause,name,method,status,evidence,suggestion))
    def run(self)->List[TestResult]:
        # import pdb;pdb.set_trace()
        if not self.config.get("enabled_modules",{}).get("threat_detection",False):
            self.add("8.3.1.6","威胁检测-EICAR安全样本","配置 enabled_modules.threat_detection=false，未启用。","MANUAL",{},"如需半自动验证威胁检测，可安装ClamAV或配置企业EDR/杀毒扫描命令，使用EICAR安全测试文件。"); return self.results
        cfg=self.config.get("threat_detection",{}); allow=bool(cfg.get("allow_create_eicar",False)); scanner=cfg.get("scanner_command","clamscan {file}"); eicar_path=self.outdir/cfg.get("eicar_filename","eicar_test_file.com"); evidence={"eicar_path":str(eicar_path),"scanner_command_template":scanner}
        if not allow:
            self.add("8.3.1.6","威胁检测-EICAR安全样本","未设置 threat_detection.allow_create_eicar=true，未生成EICAR测试文件。","MANUAL",evidence,"确认在授权隔离环境后，将allow_create_eicar设置为true；本模块不使用真实恶意样本。"); return self.results
        try:
            eicar_path.write_text(EICAR_STRING,encoding="ascii"); evidence["eicar_created"]=True
        except Exception as e:
            self.add("8.3.1.6","威胁检测-EICAR安全样本","生成EICAR测试文件。","ERROR",{"error":str(e)},"检查输出目录权限。"); return self.results
        command=scanner.format(file=str(eicar_path)); exe=command.split()[0]
        if shutil.which(exe) is None and not Path(exe).exists():
            self.add("8.3.1.6","威胁检测-EICAR安全样本","检查威胁检测扫描命令是否存在。","ERROR",{**evidence,"command":command,"error":"未找到扫描命令"},"Ubuntu可安装clamav并配置 scanner_command='clamscan {file}'；企业环境可替换为EDR/杀毒软件命令。"); return self.results
        try:
            cp=subprocess.run(command,shell=True,capture_output=True,text=True,timeout=int(cfg.get("timeout_sec",120)))
            text=cp.stdout+"\n"+cp.stderr
            detected=any(k.lower() in text.lower() for k in ["eicar","infected","found","virus","malware","detected","发现","病毒","木马","告警"])
            evidence.update({"command":command,"returncode":cp.returncode,"stdout_tail":cp.stdout[-8000:],"stderr_tail":cp.stderr[-4000:],"detected_hint":detected})
            self.add("8.3.1.6","威胁检测-EICAR安全样本","生成EICAR标准安全测试文件，并调用配置的杀毒/EDR扫描命令，检查是否检测和告警。","PASS" if detected else "WARN",evidence,"EICAR为反恶意软件响应测试文件，不是真实病毒；若未检测到，应确认病毒库、规则库、扫描路径和实时防护是否生效。")
        except Exception as e:
            self.add("8.3.1.6","威胁检测-EICAR安全样本","调用扫描命令。","ERROR",{**evidence,"command":command,"error":str(e)},"检查扫描命令和权限。")
        finally:
            if cfg.get("cleanup",True):
                try: eicar_path.unlink(missing_ok=True)
                except Exception: pass
        return self.results
