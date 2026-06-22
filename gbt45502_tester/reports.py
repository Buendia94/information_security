# -*- coding: utf-8 -*-
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from .result import TestResult

def summarize(results: List[TestResult]) -> Dict[str,int]:
    out={}
    for r in results: out[r.status]=out.get(r.status,0)+1
    return out

def write_reports(outdir: Path, config: Dict[str,Any], results: List[TestResult]) -> Dict[str,str]:
    outdir.mkdir(parents=True,exist_ok=True)
    report={"tool":"gbt45502_robot_security_tester_project","time":datetime.now(timezone.utc).astimezone().isoformat(),"standard":"GB/T 45502-2025 服务机器人信息安全通用要求","note":"PASS/FAIL/WARN为脚本自动化判断；MANUAL为需人工或专用设备确认；INFO为留证信息。","config_summary":{"targets":config.get("targets",[]),"expected_open_ports":config.get("expected_open_ports",[]),"firmware_files":config.get("firmware_files",[]),"app_packages":config.get("app_packages",[]),"log_dirs":config.get("log_dirs",[]),"enabled_modules":config.get("enabled_modules",{})},"results":[r.asdict() for r in results],"summary":summarize(results)}
    jp=outdir/"gbt45502_security_report.json"; mp=outdir/"gbt45502_security_report.md"
    jp.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    mp.write_text(to_markdown(report),encoding="utf-8")
    return {"json":str(jp),"markdown":str(mp)}

def to_markdown(report: Dict[str,Any]) -> str:
    lines=["# GB/T 45502-2025 服务机器人信息安全自动化/半自动化测试报告","",f"- 生成时间：{report['time']}",f"- 说明：{report['note']}","","## 汇总"]
    for k,v in report["summary"].items(): lines.append(f"- {k}: {v}")
    lines += ["","## 结果明细"]
    for r in report["results"]:
        lines.append(f"### {r['clause']} {r['name']}")
        lines.append(f"- 方法：{r['method']}")
        lines.append(f"- 结果：**{r['status']}**")
        if r.get("suggestion"): lines.append(f"- 建议：{r['suggestion']}")
        lines += ["","```json",json.dumps(r["evidence"],ensure_ascii=False,indent=2)[:12000],"```",""]
    return "\n".join(lines)
