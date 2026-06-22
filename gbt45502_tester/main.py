# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .modules.core import CoreTests
from .modules.nmap_scan import NmapModule
from .modules.vuln_lookup import VulnerabilityModule
from .modules.reverse_analysis import ReverseAnalysisModule
from .modules.threat_detection import ThreatDetectionModule
from .reports import write_reports
from .utils import safe_json_load

def default_config():
    return json.loads(Path("configs/gbt45502_test_config.json").read_text(encoding="utf-8")) if Path("configs/gbt45502_test_config.json").exists() else {}

def main():
    parser=argparse.ArgumentParser(description="GB/T 45502-2025 服务机器人信息安全自动化/半自动化测试工具")
    parser.add_argument("--config",default="configs/gbt45502_test_config.json",help="测试配置JSON")
    parser.add_argument("--outdir",default="reports/gbt45502_report",help="报告输出目录")
    parser.add_argument("--init-config",action="store_true",help="重新生成默认配置模板")
    parser.add_argument("--confirm-authorized",action="store_true",help="确认已获得目标系统授权")
    args=parser.parse_args()
    cfg_path=Path(args.config)
    if args.init_config:
        cfg_path.parent.mkdir(parents=True,exist_ok=True)
        if Path("configs/gbt45502_test_config.json").exists() and cfg_path != Path("configs/gbt45502_test_config.json"):
            cfg_path.write_text(Path("configs/gbt45502_test_config.json").read_text(encoding="utf-8"),encoding="utf-8")
        print(f"[+] 配置文件位置：{cfg_path}")
        return
    if not args.confirm_authorized:
        print("[-] 请仅在授权测试环境中运行，并添加 --confirm-authorized")
        sys.exit(2)
    config=safe_json_load(cfg_path); outdir=Path(args.outdir); outdir.mkdir(parents=True,exist_ok=True)
    results=[]
    if config.get("enabled_modules",{}).get("core",True): results.extend(CoreTests(config,outdir).run())
    results.extend(NmapModule(config,outdir).run())
    results.extend(VulnerabilityModule(config,outdir).run())
    results.extend(ReverseAnalysisModule(config,outdir).run())
    results.extend(ThreatDetectionModule(config,outdir).run())
    paths=write_reports(outdir,config,results)
    print(f"[+] JSON报告：{paths['json']}")
    print(f"[+] Markdown报告：{paths['markdown']}")
    print("[+] 完成。")
if __name__=="__main__":
    main()
