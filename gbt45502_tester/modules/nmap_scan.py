# -*- coding: utf-8 -*-
from __future__ import annotations
import shutil, subprocess, xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List
from ..result import TestResult

class NmapModule:
    def __init__(self,config:Dict[str,Any],outdir:Path):
        self.config=config; self.outdir=outdir; self.results=[]
    def add(self,clause,name,method,status,evidence,suggestion=""):
        self.results.append(TestResult(clause,name,method,status,evidence,suggestion))
    def run(self)->List[TestResult]:
        if not self.config.get("enabled_modules",{}).get("nmap",False):
            self.add("8.1.1.4 / 8.1.2.3 / 8.1.2.4 / 8.1.2.5 / 8.1.2.7","Nmap增强扫描","配置 enabled_modules.nmap=false，未启用。","MANUAL",{},"如需增强服务识别和NSE脚本留证，可安装nmap并启用该模块。"); return self.results
        cfg=self.config.get("nmap",{}); nmap_path=cfg.get("path","nmap")
        if shutil.which(nmap_path) is None:
            self.add("8.1.1.4 / 8.1.2.7","Nmap增强扫描","检查系统nmap命令是否可用。","ERROR",{"nmap_path":nmap_path,"error":"未找到nmap命令"},"请安装nmap，或在配置中填写nmap可执行文件完整路径。"); return self.results
        targets=[t["ip"] for t in self.config.get("targets",[])][:int(cfg.get("max_targets",20))]
        findings=[]
        for ip in targets:
            safe=ip.replace(":","_").replace("/","_"); xmlp=self.outdir/f"nmap_{safe}.xml"; txtp=self.outdir/f"nmap_{safe}.txt"
            cmd=[nmap_path]+cfg.get("args","-sV").split()
            if cfg.get("ports"): cmd += ["-p",str(cfg.get("ports"))]
            cmd += ["-oX",str(xmlp),"-oN",str(txtp),ip]
            
            try:
                cp=subprocess.run(cmd,capture_output=True,text=True,timeout=int(cfg.get("timeout_sec",600)))
                parsed=self.parse_xml(xmlp) if xmlp.exists() else {}
                findings.append({"target":ip,"command":" ".join(cmd),"returncode":cp.returncode,"stdout_tail":cp.stdout[-2000:],"stderr_tail":cp.stderr[-2000:],"xml_report":str(xmlp),"text_report":str(txtp),"parsed":parsed})
            except Exception as e: findings.append({"target":ip,"command":" ".join(cmd),"error":str(e)})
        warn=any(any(p.get("state")=="open" and p.get("service") in ["telnet","ftp"] for p in f.get("parsed",{}).get("ports",[])) for f in findings)
        self.add("8.1.1.4 / 8.1.2.3 / 8.1.2.4 / 8.1.2.5 / 8.1.2.7 / 8.3.1.1","Nmap端口、服务版本与NSE留证","调用nmap进行端口扫描、服务版本识别、OS识别或NSE脚本检测，并保存XML/TXT报告。","WARN" if warn else ("INFO" if findings else "MANUAL"),{"nmap_findings":findings},"Nmap可作为资产识别和部分漏洞初筛工具，不能替代NVD、CNVD、CNNVD漏洞库核查。")
        return self.results
    def parse_xml(self,xmlp:Path)->Dict[str,Any]:
        out={"ports":[],"os_matches":[]}
        try:
            root=ET.parse(xmlp).getroot(); host=root.find("host")
            if host is None: return out
            for port in host.findall(".//ports/port"):
                state=port.find("state"); service=port.find("service"); scripts=[]
                for sc in port.findall("script"): scripts.append({"id":sc.get("id"),"output":sc.get("output")})
                out["ports"].append({"protocol":port.get("protocol"),"port":int(port.get("portid")),"state":state.get("state") if state is not None else None,"service":service.get("name") if service is not None else None,"product":service.get("product") if service is not None else None,"version":service.get("version") if service is not None else None,"extrainfo":service.get("extrainfo") if service is not None else None,"cpe":[c.text for c in service.findall("cpe")] if service is not None else [],"scripts":scripts})
            for osm in host.findall(".//osmatch"): out["os_matches"].append({"name":osm.get("name"),"accuracy":osm.get("accuracy")})
        except Exception as e: out["parse_error"]=str(e)
        return out
