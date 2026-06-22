# GB/T 45502-2025 服务机器人信息安全测试工具

## 1. 项目结构

```text
gbt45502_tester_project/
├─ run_tester.py
├─ requirements.txt
├─ requirements_optional.txt
├─ configs/
│  ├─ gbt45502_test_config.json
│  ├─ local_test_config.json
│  └─ enhanced_example_config.json
├─ gbt45502_tester/
│  ├─ main.py
│  ├─ result.py
│  ├─ reports.py
│  ├─ utils.py
│  └─ modules/
│     ├─ core.py                 # 原基础测试：端口/认证/TLS/日志/重放/输入验证/权限等
│     ├─ nmap_scan.py            # Nmap增强：端口、服务版本、OS、NSE留证
│     ├─ vuln_lookup.py          # NVD/OSV/pip-audit联网漏洞辅助查询
│     ├─ reverse_analysis.py     # LIEF/Androguard防反汇编辅助分析
│     └─ threat_detection.py     # EICAR + ClamAV/EDR威胁检测
└─ samples/
```

## 2. 安装依赖

基础依赖：

```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

可选增强依赖：

```bash
pip install -r requirements_optional.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

Ubuntu 可安装 Nmap 和 ClamAV：

```bash
sudo apt update
sudo apt install -y nmap clamav clamav-daemon
sudo freshclam
```

Windows 需要安装 Nmap 并加入 PATH，或者在配置中填写 `nmap.path` 完整路径。

## 3. 本机完整跑一遍

第一个终端：

```bash
cd gbt45502_tester_project
mkdir -p samples/logs
echo "hello robot test" > index.html
echo "user=admin password=123456 token=abcdefg123456789" > samples/logs/robot.log
echo "fake firmware" > samples/firmware.bin
python - <<'PY'
import zipfile
with zipfile.ZipFile("samples/robot_app.zip", "w") as z:
    z.writestr("config.txt", "api_key=abcdefg123456789")
    z.writestr("classes.dex", "fake dex placeholder")
PY
python -m http.server 8080
```

第二个终端：

```bash
cd gbt45502_tester_project
python run_tester.py --config configs/local_test_config.json --outdir reports/local_test --confirm-authorized
```

报告：

```text
reports/local_test/gbt45502_security_report.md
reports/local_test/gbt45502_security_report.json
```

## 4. 测远程 Ubuntu 机器人主机

复制 `configs/enhanced_example_config.json`，修改目标 IP：

```json
"targets": [
  {
    "ip": "192.168.1.50",
    "ports": [22, 80, 443, 554, 1883, 8883, 8080, 8443, 9000],
    "ssh_user": "robot_test"
  }
],
"expected_open_ports": [22, 8080]
```

运行：

```bash
python run_tester.py --config configs/enhanced_example_config.json --outdir reports/robot_192_168_1_50 --confirm-authorized
```

## 5. 开启 Nmap 增强

配置：

```json
"enabled_modules": {
  "core": true,
  "nmap": true,
  "vulnerability_lookup": false,
  "reverse_analysis": false,
  "threat_detection": false
},
"nmap": {
  "path": "nmap",
  "args": "-sV",
  "ports": "1-10000",
  "timeout_sec": 600
}
```

需要 NSE 漏洞脚本初筛时，可改为：

```json
"args": "-sV --script vuln"
```

注意：Nmap 用于资产识别、端口识别、服务版本识别和部分漏洞脚本检测，不能替代 NVD、CNVD、CNNVD 漏洞库核查。

## 6. 开启 NVD/OSV/pip-audit 漏洞辅助查询

配置：

```json
"enabled_modules": {
  "core": true,
  "nmap": true,
  "vulnerability_lookup": true,
  "reverse_analysis": false,
  "threat_detection": false
},
"software_inventory": [
  {"name": "OpenSSH", "version": "8.9", "nvd_keyword": "OpenSSH 8.9"},
  {"name": "nginx", "version": "1.18.0", "nvd_keyword": "nginx 1.18.0"}
],
"vulnerability_lookup": {
  "enable_nvd": true,
  "nvd_api_key": "",
  "nvd_max_results_per_item": 10,
  "nvd_delay_sec": 6.5,
  "enable_osv": false,
  "osv_packages": [],
  "enable_pip_audit": false
}
```

说明：NVD/OSV结果是候选漏洞，需人工确认适用性。CNVD/CNNVD建议通过人工查询、企业漏洞库或商业漏洞管理平台补充。

## 7. 开启反汇编辅助分析

配置：

```json
"enabled_modules": {
  "reverse_analysis": true
},
"app_packages": [
  "/opt/robot/bin/robot_control",
  "/opt/robot/lib/librobot_control.so",
  "/opt/robot/app/robot_app.apk"
]
```

安装增强库：

```bash
pip install lief androguard -i https://pypi.tuna.tsinghua.edu.cn/simple
```

本模块只能做辅助分析，不能替代 IDA Pro、Ghidra、apktool、JADX、dex2jar。

## 8. 开启 EICAR 威胁检测

配置：

```json
"enabled_modules": {
  "threat_detection": true
},
"threat_detection": {
  "allow_create_eicar": true,
  "scanner_command": "clamscan {file}",
  "eicar_filename": "eicar_test_file.com",
  "timeout_sec": 120,
  "cleanup": true
}
```

运行时会生成 EICAR 安全测试文件，并调用 `clamscan` 或你配置的企业杀毒/EDR扫描命令。该文件不是实际病毒，不使用真实木马样本。

## 9. 安全要求

必须添加：

```bash
--confirm-authorized
```

请仅在授权环境中使用，不要对第三方系统或公网目标执行扫描。
