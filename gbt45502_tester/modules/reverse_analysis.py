# -*- coding: utf-8 -*-
from __future__ import annotations
import zipfile
from pathlib import Path
from typing import Any, Dict, List
from ..result import TestResult
from ..utils import scan_sensitive_bytes, sha256_file

class ReverseAnalysisModule:
    def __init__(self,config:Dict[str,Any],outdir:Path):
        self.config=config; self.outdir=outdir; self.results=[]
    def add(self,clause,name,method,status,evidence,suggestion=""):
        self.results.append(TestResult(clause,name,method,status,evidence,suggestion))
    def run(self)->List[TestResult]:
        if not self.config.get("enabled_modules",{}).get("reverse_analysis",False):
            self.add("8.2.2.4","防反汇编增强辅助分析","配置 enabled_modules.reverse_analysis=false，未启用。","MANUAL",{},"如需增强防反汇编辅助分析，可安装lief、androguard并启用本模块。"); return self.results
        findings=[self.analyze_file(Path(x)) for x in self.config.get("app_packages",[])]
        weak=any(x.get("debug_symbols_hint") or x.get("sensitive_hits") or x.get("archive_sensitive_hits") for x in findings)
        self.add("8.2.2.4 / 8.2.2.8","防反汇编/逆向分析辅助检查","对APK、ZIP、ELF、SO、可执行文件进行静态辅助分析，检查签名、DEX/SO、符号表、调试信息、敏感字符串和混淆迹象。","WARN" if weak else ("INFO" if findings else "MANUAL"),{"reverse_analysis_findings":findings},"该模块不能替代IDA Pro、Ghidra、apktool、JADX、dex2jar人工逆向评估；发现调试符号或敏感硬编码时应整改。")
        return self.results
    def analyze_file(self,f:Path)->Dict[str,Any]:
        item={"file":str(f),"exists":f.exists()}
        if not f.exists() or not f.is_file(): item["error"]="not exists"; return item
        item.update({"size":f.stat().st_size,"sha256":sha256_file(f)})
        if zipfile.is_zipfile(f): item.update(self.analyze_zip_apk(f))
        item.update(self.analyze_lief_optional(f))
        if f.stat().st_size <= 100*1024*1024:
            try: item["sensitive_hits"]=scan_sensitive_bytes(f.read_bytes(),max_hits=20)
            except Exception as e: item["sensitive_scan_error"]=str(e)
        return item
    def analyze_zip_apk(self,f:Path)->Dict[str,Any]:
        out={"archive_type":"zip/apk"}
        try:
            with zipfile.ZipFile(f) as z:
                names=z.namelist()
                out["entry_count"]=len(names); out["has_dex"]=any(n.endswith(".dex") for n in names); out["dex_files"]=[n for n in names if n.endswith(".dex")][:20]; out["has_native_so"]=any(n.endswith(".so") for n in names); out["so_files_sample"]=[n for n in names if n.endswith(".so")][:20]; out["apk_signature_entries"]=[n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA",".DSA",".EC",".SF"))]; out["possible_packer_or_obfuscation_hint"]=any(("jiagu" in n.lower() or "protect" in n.lower() or "sec" in n.lower() or "shell" in n.lower()) for n in names)
                hits=[]
                for n in names[:3000]:
                    if len(hits)>=20: break
                    try:
                        info=z.getinfo(n)
                        if info.file_size<=2*1024*1024:
                            h=scan_sensitive_bytes(z.read(n),max_hits=3)
                            if h: hits.append({"entry":n,"hits":h})
                    except Exception: pass
                out["archive_sensitive_hits"]=hits
        except Exception as e: out["zip_parse_error"]=str(e)
        out.update(self.analyze_androguard_optional(f))
        return out
    def analyze_androguard_optional(self,f:Path)->Dict[str,Any]:
        out={"androguard_available":False}
        try:
            from androguard.core.apk import APK
            # import pdb;pdb.set_trace()
            a=APK(str(f)); out.update({"androguard_available":True,"apk_package":a.get_package(),"apk_app_name":a.get_app_name(),"apk_permissions_sample":a.get_permissions()[:50],"apk_min_sdk":a.get_min_sdk_version(),"apk_target_sdk":a.get_target_sdk_version(),"apk_valid_apk":a.is_valid_APK()})
        except Exception as e: out["androguard_note"]=f"未使用androguard或解析失败：{e}"
        return out
    def analyze_lief_optional(self,f:Path)->Dict[str,Any]:
        out={"lief_available":False}
        try:
            import lief
            # import pdb;pdb.set_trace()
            binary=lief.parse(str(f)); out["lief_available"]=True
            if binary is None: out["lief_parse"]="not supported or parse failed"; return out
            out["binary_format"]=str(binary.format); out["binary_entrypoint"]=getattr(binary,"entrypoint",None)
            try: symbols=[s.name for s in binary.symbols if getattr(s,"name",None)]
            except Exception: symbols=[]
            out["symbol_count"]=len(symbols); out["symbols_sample"]=symbols[:50]; out["debug_symbols_hint"]=len(symbols)>50
            try: libs=list(binary.libraries)
            except Exception: libs=[]
            out["libraries_sample"]=libs[:50]
        except Exception as e: out["lief_note"]=f"未使用LIEF或解析失败：{e}"
        return out
