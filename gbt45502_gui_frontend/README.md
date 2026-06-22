# GB/T 45502-2025 服务机器人信息安全测试工具前端

## 界面说明

深蓝色科技风，适配 1920×1080。左侧为树状目录：

- 测试设置：JSON 全量配置界面，可加载、修改、保存配置文件；
- 测试主界面：模块开关、配置路径、输出目录、启动/停止测试、控制台输出；
- 测试结果：加载 JSON/Markdown 报告，查看汇总和明细；
- 关闭程序：退出软件。

素材全部在 `assets/` 目录，包括背景图、logo、图标等。

## 安装依赖

```bash
pip install PyQt6 -i https://pypi.tuna.tsinghua.edu.cn/simple
```

## 放置位置

推荐把本目录复制到你的后端项目根目录：

```text
gbt45502_tester_project/
├─ run_tester.py
├─ configs/
├─ gbt45502_tester/
└─ gui_frontend/
   ├─ app.py
   └─ assets/
```

也可以放到 `gbt45502_tester_project` 的上一级，程序会自动寻找 `run_tester.py`。

## 启动

```bash
cd gui_frontend
python app.py
```

## 使用流程

1. 进入“测试设置”，加载或修改 JSON 配置；
2. 进入“测试主界面”，勾选核心测试、Nmap、漏洞联网、反汇编辅助、威胁检测等模块；
3. 设置输出目录；
4. 点击“开始测试”；
5. 测试完成后进入“测试结果”，选择输出目录下的 `gbt45502_security_report.json` 查看结果。

## 打包建议

```bash
pip install pyinstaller -i https://pypi.tuna.tsinghua.edu.cn/simple
pyinstaller --onefile --windowed --name GBT45502SecurityTester --add-data "assets:assets" app.py
```

Windows 下 `--add-data` 使用分号：

```bash
pyinstaller --onefile --windowed --name GBT45502SecurityTester --add-data "assets;assets" app.py
```
