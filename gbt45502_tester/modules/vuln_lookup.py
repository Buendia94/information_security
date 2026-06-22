# -*- coding: utf-8 -*-
from __future__ import annotations
import json, subprocess, time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote
try:
    import requests
except Exception:
    requests=None
from ..result import TestResult

class VulnerabilityModule:
    def __init__(self,config:Dict[str,Any],outdir:Path):
        self.config=config; self.outdir=outdir; self.results=[]
    def add(self,clause,name,method,status,evidence,suggestion=""):
        self.results.append(TestResult(clause,name,method,status,evidence,suggestion))
    def run(self)->List[TestResult]:
        if not self.config.get("enabled_modules",{}).get("vulnerability_lookup",False):
            self.add("8.1.2.7 / 8.1.4.1 / 8.2.2.9 / 8.3.3.3","漏洞管理-联网查询","配置 enabled_modules.vulnerability_lookup=false，未启用。","MANUAL",{},"如需增强漏洞管理能力，可启用NVD/OSV/pip-audit查询；CNVD/CNNVD建议作为人工复核项。"); return self.results
        findings={"software_inventory":self.config.get("software_inventory",[]),"nvd":[],"osv":[],"pip_audit":None,"cnvd_cnnvd_note":"CNVD/CNNVD建议通过人工查询、企业漏洞库、商业漏洞管理平台或离线导出数据进行复核。"}
        vcfg=self.config.get("vulnerability_lookup",{})
        if vcfg.get("enable_nvd",True): findings["nvd"]=self.query_nvd_inventory()
        if vcfg.get("enable_osv",False): findings["osv"]=self.query_osv_packages()
        if vcfg.get("enable_pip_audit",False): findings["pip_audit"]=self.run_pip_audit()
        has=any(x.get("cve_count",0)>0 for x in findings["nvd"]) or any(x.get("vuln_count",0)>0 for x in findings["osv"])
        if findings["pip_audit"] and findings["pip_audit"].get("returncode") not in [0,None]: has=True
        self.add("8.1.2.7 / 8.1.4.1 / 8.2.2.9 / 8.3.3.3","漏洞管理-NVD/OSV/pip-audit联网辅助查询","根据software_inventory和配置的包清单查询NVD/OSV，并可调用pip-audit；结果为候选漏洞，需人工复核适用性。","WARN" if has else "INFO",findings,"若发现候选CVE/漏洞，应结合产品版本、配置、暴露面、补丁状态和CNVD/CNNVD结果进行复核闭环。")
        return self.results
    def query_nvd_inventory(self):
        import pdb;pdb.set_trace()
        if not requests: return [{"error":"requests未安装"}]
        out=[]; vcfg=self.config.get("vulnerability_lookup",{}); api_key=vcfg.get("nvd_api_key") or ""; maxr=int(vcfg.get("nvd_max_results_per_item",10)); delay=float(vcfg.get("nvd_delay_sec",6.5 if not api_key else 0.7)); headers={"apiKey":api_key} if api_key else {}
        for item in self.config.get("software_inventory",[]):
            name=item.get("name",""); version=item.get("version",""); keyword=item.get("nvd_keyword") or f"{name} {version}".strip()
            if not keyword: continue
            url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote(keyword)}&resultsPerPage={maxr}"
            one={"name":name,"version":version,"keyword":keyword,"url":url,"cves":[]}
            try:
                r=requests.get(url,headers=headers,timeout=20); one["status_code"]=r.status_code
                if r.status_code==200:
                    for v in r.json().get("vulnerabilities",[]):
                        c=v.get("cve",{}); metrics=c.get("metrics",{}); severity=None; score=None
                        for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                            if key in metrics and metrics[key]:
                                cvss=metrics[key][0].get("cvssData",{}); severity=metrics[key][0].get("baseSeverity") or cvss.get("baseSeverity"); score=cvss.get("baseScore"); break
                        one["cves"].append({"id":c.get("id"),"published":c.get("published"),"lastModified":c.get("lastModified"),"severity":severity,"score":score,"description":(c.get("descriptions") or [{}])[0].get("value","")[:500]})
                    one["cve_count"]=len(one["cves"])
                else: one["error"]=r.text[:500]
            except Exception as e: one["error"]=str(e)
            out.append(one); time.sleep(delay)
        return out
    def query_osv_packages(self):
        if not requests: return [{"error":"requests未安装"}]
        out=[]
        for p in self.config.get("vulnerability_lookup",{}).get("osv_packages",[]):
            body={"version":p.get("version"),"package":{"name":p.get("name"),"ecosystem":p.get("ecosystem","PyPI")}}
            one={"package":body["package"],"version":body["version"],"vulns":[]}
            try:
                r=requests.post("https://api.osv.dev/v1/query",json=body,timeout=20); one["status_code"]=r.status_code
                if r.status_code==200:
                    for v in r.json().get("vulns",[]): one["vulns"].append({"id":v.get("id"),"summary":v.get("summary"),"modified":v.get("modified"),"published":v.get("published")})
                    one["vuln_count"]=len(one["vulns"])
                else: one["error"]=r.text[:500]
            except Exception as e: one["error"]=str(e)
            out.append(one)
        return out
    def run_pip_audit(self):
        cmd=self.config.get("vulnerability_lookup",{}).get("pip_audit_command","python -m pip_audit -f json")
        try:
            cp=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=180)
            try: parsed=json.loads(cp.stdout)
            except Exception: parsed=None
            return {"command":cmd,"returncode":cp.returncode,"stdout_tail":cp.stdout[-12000:],"stderr_tail":cp.stderr[-4000:],"parsed":parsed}
        except Exception as e: return {"command":cmd,"error":str(e)}
