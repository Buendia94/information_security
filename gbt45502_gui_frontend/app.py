# -*- coding: utf-8 -*-
"""
GB/T 45502-2025 服务机器人信息安全测试工具 - 深蓝科技风前端界面
屏幕适配：1920×1080，左侧树状目录：测试设置、测试主界面、测试结果、关闭程序。
"""
from __future__ import annotations
import json, sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from PyQt6.QtCore import Qt, QProcess
from PyQt6.QtGui import QBrush, QColor, QFont, QIcon, QPixmap, QTextCursor
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QPlainTextEdit, QProgressBar, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget, QTabWidget
)

APP_DIR = Path(__file__).resolve().parent
ASSET_DIR = APP_DIR / "assets"

def find_backend_root() -> Path:
    candidates = [APP_DIR, APP_DIR.parent, APP_DIR.parent / "gbt45502_tester_project", Path.cwd()]
    for c in candidates:
        if (c / "run_tester.py").exists():
            return c
    return APP_DIR

BACKEND_ROOT = find_backend_root()
GUI_RUNTIME_SETTINGS = APP_DIR / "gui_runtime_settings.json"

def load_runtime_settings() -> Dict[str, Any]:
    if GUI_RUNTIME_SETTINGS.exists():
        try:
            return json.loads(GUI_RUNTIME_SETTINGS.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_runtime_settings(data: Dict[str, Any]) -> None:
    GUI_RUNTIME_SETTINGS.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def deep_get(data: Any, path: List[Any]) -> Any:
    cur = data
    for p in path:
        cur = cur[p]
    return cur

def deep_set(data: Any, path: List[Any], value: Any) -> None:
    cur = data
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value

def parse_value(text: str, old_value: Any) -> Any:
    if isinstance(old_value, bool):
        return text.strip().lower() in ["true", "1", "yes", "y", "是", "开"]
    if isinstance(old_value, int) and not isinstance(old_value, bool):
        try: return int(text)
        except Exception: return old_value
    if isinstance(old_value, float):
        try: return float(text)
        except Exception: return old_value
    if isinstance(old_value, (list, dict)):
        try: return json.loads(text)
        except Exception: return old_value
    if text == "null": return None
    return text

class CyberCard(QFrame):
    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("CyberCard")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 18, 20, 18)
        self.layout.setSpacing(12)
        if title:
            label = QLabel(title); label.setObjectName("CardTitle"); self.layout.addWidget(label)

class ConfigTreeEditor(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config: Dict[str, Any] = {}; self.current_path: List[Any] = []; self.file_path: Path | None = None
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0)
        top = QHBoxLayout()
        self.path_edit = QLineEdit(); self.path_edit.setPlaceholderText("配置文件路径")
        self.load_btn = QPushButton("载入JSON"); self.save_btn = QPushButton("保存JSON"); self.save_as_btn = QPushButton("另存为")
        top.addWidget(self.path_edit, 1); top.addWidget(self.load_btn); top.addWidget(self.save_btn); top.addWidget(self.save_as_btn)
        root.addLayout(top)
        splitter = QSplitter(); splitter.setOrientation(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["配置项", "类型", "值"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        right = QWidget(); right_layout = QVBoxLayout(right)
        self.key_label = QLabel("请选择左侧配置项"); self.key_label.setObjectName("SubTitle")
        self.value_editor = QPlainTextEdit(); self.value_editor.setPlaceholderText("这里显示/编辑当前配置项的值。dict/list 会以 JSON 显示。")
        self.apply_btn = QPushButton("应用到配置树")
        right_layout.addWidget(self.key_label); right_layout.addWidget(self.value_editor, 1); right_layout.addWidget(self.apply_btn)
        splitter.addWidget(self.tree); splitter.addWidget(right); splitter.setSizes([850, 550]); root.addWidget(splitter, 1)
        self.load_btn.clicked.connect(self.choose_and_load); self.save_btn.clicked.connect(self.save); self.save_as_btn.clicked.connect(self.save_as)
        self.tree.itemClicked.connect(self.on_item_clicked); self.apply_btn.clicked.connect(self.apply_value)
    def load_file(self, path: Path):
        self.file_path = path; self.path_edit.setText(str(path)); self.config = json.loads(path.read_text(encoding="utf-8")); self.populate()
    def choose_and_load(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择配置JSON", str(BACKEND_ROOT / "configs"), "JSON Files (*.json)")
        if path: self.load_file(Path(path))
    def populate(self):
        self.tree.clear(); self._add_node(self.tree.invisibleRootItem(), "root", self.config, []); self.tree.expandToDepth(2)
    def _add_node(self, parent, key, value, path):
        typ = type(value).__name__; val_text = f"{len(value)}项" if isinstance(value,(dict,list)) else str(value)
        item = QTreeWidgetItem([str(key), typ, val_text]); item.setData(0, Qt.ItemDataRole.UserRole, path); parent.addChild(item)
        if isinstance(value, dict):
            for k, v in value.items(): self._add_node(item, k, v, path+[k])
        elif isinstance(value, list):
            for i, v in enumerate(value): self._add_node(item, f"[{i}]", v, path+[i])
    def on_item_clicked(self, item):
        path = item.data(0, Qt.ItemDataRole.UserRole); self.current_path = path
        value = self.config if not path else deep_get(self.config, path)
        self.key_label.setText("当前配置项：" + ("root" if not path else ".".join(map(str,path))))
        self.value_editor.setPlainText(json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value,(dict,list)) else str(value))
    def apply_value(self):
        text = self.value_editor.toPlainText()
        if not self.current_path:
            try: self.config=json.loads(text); self.populate()
            except Exception as e: QMessageBox.warning(self,"JSON错误",str(e))
            return
        old=deep_get(self.config,self.current_path)
        if isinstance(old,(dict,list)):
            try: new=json.loads(text)
            except Exception as e: QMessageBox.warning(self,"JSON错误",str(e)); return
        else: new=parse_value(text,old)
        deep_set(self.config,self.current_path,new); self.populate()
    def save(self):
        if not self.file_path: self.save_as(); return
        self.file_path.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
        QMessageBox.information(self,"保存成功",f"已保存：{self.file_path}")
    def save_as(self):
        path,_=QFileDialog.getSaveFileName(self,"另存为JSON",str(BACKEND_ROOT/"configs"/"ui_config.json"),"JSON Files (*.json)")
        if path: self.file_path=Path(path); self.path_edit.setText(path); self.save()

class SettingsPage(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent); layout=QVBoxLayout(self)
        title=QLabel("测试设置 / JSON 全量配置"); title.setObjectName("PageTitle")
        desc=QLabel("左侧树状结构展示 JSON 全部内容；选择节点后可在右侧修改，支持 dict/list 原始 JSON 编辑。")
        desc.setObjectName("PageDesc"); layout.addWidget(title); layout.addWidget(desc)
        hero=QLabel(); hp=ASSET_DIR/"security_hero.png"
        if hp.exists():
            hero.setPixmap(QPixmap(str(hp)).scaledToHeight(140,Qt.TransformationMode.SmoothTransformation))
            layout.addWidget(hero)
        self.editor=ConfigTreeEditor(); layout.addWidget(self.editor,1)
        for p in [BACKEND_ROOT/"configs"/"enhanced_example_config.json", BACKEND_ROOT/"configs"/"local_test_config.json", BACKEND_ROOT/"configs"/"gbt45502_test_config.json"]:
            if p.exists(): self.editor.load_file(p); break

class TestPage(QWidget):
    def __init__(self, settings_page: SettingsPage, parent=None):
        super().__init__(parent); self.settings_page=settings_page; self.process:QProcess|None=None
        self.runtime_settings = load_runtime_settings()
        layout=QVBoxLayout(self); header=QHBoxLayout(); box=QVBoxLayout()
        title=QLabel("测试主界面"); title.setObjectName("PageTitle")
        desc=QLabel("执行 GB/T 45502-2025 自动化/半自动化测试；支持核心测试、Nmap、漏洞联网、反汇编辅助、EICAR威胁检测。")
        desc.setObjectName("PageDesc"); box.addWidget(title); box.addWidget(desc); header.addLayout(box,1)
        self.status_label=QLabel("待启动"); self.status_label.setObjectName("StatusPill"); header.addWidget(self.status_label); layout.addLayout(header)
        hero=QLabel(); hp=ASSET_DIR/"security_hero.png"
        if hp.exists():
            hero.setPixmap(QPixmap(str(hp)).scaledToWidth(900,Qt.TransformationMode.SmoothTransformation))
            layout.addWidget(hero)
        grid=QGridLayout(); self.cards={}
        modules=[
            ("core","核心测试","端口/认证/TLS/日志/重放/输入验证/权限","security_shield.png"),
            ("nmap","Nmap增强","服务版本、OS、NSE脚本留证","network_scan.png"),
            ("vulnerability_lookup","漏洞联网","NVD/OSV/pip-audit候选漏洞查询","vuln_radar.png"),
            ("reverse_analysis","反汇编辅助","LIEF/Androguard静态辅助分析","binary_reverse.png"),
            ("threat_detection","威胁检测","EICAR + ClamAV/EDR安全样本检测","malware_scan.png")
        ]
        for i,(key,name,sub,img) in enumerate(modules):
            c=CyberCard()
            ip=ASSET_DIR/img
            if ip.exists():
                pic=QLabel(); pic.setPixmap(QPixmap(str(ip)).scaledToWidth(260,Qt.TransformationMode.SmoothTransformation)); c.layout.addWidget(pic)
            cb=QCheckBox(name); cb.setObjectName("ModuleCheck"); tip=QLabel(sub); tip.setObjectName("CardText")
            c.layout.addWidget(cb); c.layout.addWidget(tip); self.cards[key]=cb; grid.addWidget(c,i//3,i%3)
        layout.addLayout(grid)
        path_card=CyberCard("运行路径配置")
        path_grid=QGridLayout()
        self.python_exec=QLineEdit(self.runtime_settings.get("python_exec", sys.executable)); self.python_exec.setPlaceholderText("Python执行文件，例如 /home/user/miniconda3/envs/gbt45502/bin/python")
        self.script_path=QLineEdit(self.runtime_settings.get("script_path", str(BACKEND_ROOT/"run_tester.py"))); self.script_path.setPlaceholderText("后端执行脚本路径，例如 /home/user/gbt45502_tester_project/run_tester.py")
        self.python_browse=QPushButton("选择Python"); self.script_browse=QPushButton("选择脚本"); self.save_runtime_btn=QPushButton("保存运行路径")
        path_grid.addWidget(QLabel("Python执行文件："),0,0); path_grid.addWidget(self.python_exec,0,1); path_grid.addWidget(self.python_browse,0,2)
        path_grid.addWidget(QLabel("执行脚本路径："),1,0); path_grid.addWidget(self.script_path,1,1); path_grid.addWidget(self.script_browse,1,2)
        path_grid.addWidget(self.save_runtime_btn,2,2)
        path_card.layout.addLayout(path_grid); layout.addWidget(path_card)
        mid=QHBoxLayout(); self.config_path=QLineEdit(); self.config_path.setPlaceholderText("配置JSON路径")
        self.outdir=QLineEdit(str(BACKEND_ROOT/"reports"/("ui_run_"+datetime.now().strftime("%Y%m%d_%H%M%S"))))
        self.refresh_btn=QPushButton("读取设置页配置"); self.start_btn=QPushButton("开始测试"); self.stop_btn=QPushButton("停止"); self.stop_btn.setEnabled(False)
        mid.addWidget(QLabel("配置：")); mid.addWidget(self.config_path,2); mid.addWidget(QLabel("输出：")); mid.addWidget(self.outdir,2); mid.addWidget(self.refresh_btn); mid.addWidget(self.start_btn); mid.addWidget(self.stop_btn); layout.addLayout(mid)
        self.command_preview=QLineEdit(); self.command_preview.setReadOnly(True); layout.addWidget(self.command_preview)
        self.progress=QProgressBar(); self.progress.setRange(0,0); self.progress.hide(); layout.addWidget(self.progress)
        self.console=QTextEdit(); self.console.setReadOnly(True); self.console.setObjectName("Console"); layout.addWidget(self.console,1)
        self.refresh_btn.clicked.connect(self.refresh_from_settings); self.start_btn.clicked.connect(self.start_test); self.stop_btn.clicked.connect(self.stop_test)
        self.python_browse.clicked.connect(self.choose_python); self.script_browse.clicked.connect(self.choose_script); self.save_runtime_btn.clicked.connect(self.save_runtime)
        self.python_exec.textChanged.connect(self.update_command_preview); self.script_path.textChanged.connect(self.update_command_preview); self.config_path.textChanged.connect(self.update_command_preview); self.outdir.textChanged.connect(self.update_command_preview)
        self.refresh_from_settings()
    def choose_python(self):
        path,_=QFileDialog.getOpenFileName(self,"选择Python执行文件",str(Path(self.python_exec.text()).parent if self.python_exec.text() else Path.home()),"All Files (*)")
        if path: self.python_exec.setText(path)

    def choose_script(self):
        path,_=QFileDialog.getOpenFileName(self,"选择后端执行脚本",str(BACKEND_ROOT),"Python Files (*.py);;All Files (*)")
        if path: self.script_path.setText(path)

    def save_runtime(self):
        save_runtime_settings({"python_exec":self.python_exec.text(),"script_path":self.script_path.text()})
        QMessageBox.information(self,"保存成功",f"已保存运行路径配置：{GUI_RUNTIME_SETTINGS}")

    def refresh_from_settings(self):
        cfg=self.settings_page.editor.config or {}; fp=self.settings_page.editor.file_path
        if fp: self.config_path.setText(str(fp))
        mods=cfg.get("enabled_modules",{})
        for k,cb in self.cards.items(): cb.setChecked(bool(mods.get(k,k=="core")))
        self.update_command_preview()
    def update_config_modules(self):
        cfg=self.settings_page.editor.config
        if not cfg: return
        cfg.setdefault("enabled_modules",{})
        for k,cb in self.cards.items(): cfg["enabled_modules"][k]=cb.isChecked()
        fp=self.settings_page.editor.file_path
        if fp: fp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    def update_command_preview(self):
        py=self.python_exec.text().strip() or sys.executable
        run=self.script_path.text().strip() or str(BACKEND_ROOT/"run_tester.py")
        cfg=self.config_path.text().strip() or str(BACKEND_ROOT/"configs"/"enhanced_example_config.json")
        out=self.outdir.text().strip()
        self.command_preview.setText(f'"{py}" "{run}" --config "{cfg}" --outdir "{out}" --confirm-authorized')
    def start_test(self):
        self.update_config_modules(); self.update_command_preview()
        py=Path(self.python_exec.text().strip() or sys.executable)
        run=Path(self.script_path.text().strip() or str(BACKEND_ROOT/"run_tester.py"))
        if not py.exists(): QMessageBox.warning(self,"Python不存在",f"Python执行文件不存在：{py}"); return
        if not run.exists(): QMessageBox.warning(self,"脚本不存在",f"执行脚本不存在：{run}\n请在运行路径配置中选择 run_tester.py。"); return
        cfg=Path(self.config_path.text())
        if not cfg.exists(): QMessageBox.warning(self,"配置不存在",f"配置文件不存在：{cfg}"); return
        save_runtime_settings({"python_exec":self.python_exec.text(),"script_path":self.script_path.text()})
        self.console.clear(); self.console.append(">>> 启动测试任务"); self.console.append(self.command_preview.text())
        self.status_label.setText("运行中"); self.progress.show(); self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.process=QProcess(self); self.process.setWorkingDirectory(str(run.parent))
        self.process.readyReadStandardOutput.connect(self.on_stdout); self.process.readyReadStandardError.connect(self.on_stderr); self.process.finished.connect(self.on_finished)
        self.process.start(str(py),[str(run),"--config",str(cfg),"--outdir",self.outdir.text(),"--confirm-authorized"])

    def on_stdout(self):
        if self.process:
            text=bytes(self.process.readAllStandardOutput()).decode(errors="ignore"); self.console.moveCursor(QTextCursor.MoveOperation.End); self.console.insertPlainText(text)
    def on_stderr(self):
        if self.process:
            text=bytes(self.process.readAllStandardError()).decode(errors="ignore"); self.console.moveCursor(QTextCursor.MoveOperation.End); self.console.insertPlainText(text)
    def on_finished(self,code,status):
        self.progress.hide(); self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False); self.status_label.setText("完成" if code==0 else "异常"); self.console.append(f"\n>>> 任务结束，返回码：{code}")
    def stop_test(self):
        if self.process: self.process.kill(); self.console.append("\n>>> 已请求停止任务")

class ResultsPage(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent); self.report_json=None; layout=QVBoxLayout(self)
        title=QLabel("测试结果"); title.setObjectName("PageTitle"); desc=QLabel("载入 JSON 报告后，可查看汇总、结果明细和 Markdown 报告内容。"); desc.setObjectName("PageDesc")
        layout.addWidget(title); layout.addWidget(desc)
        hero=QLabel(); hp=ASSET_DIR/"vuln_radar.png"
        if hp.exists(): hero.setPixmap(QPixmap(str(hp)).scaledToWidth(520,Qt.TransformationMode.SmoothTransformation)); layout.addWidget(hero)
        top=QHBoxLayout(); self.report_path=QLineEdit(); self.report_path.setPlaceholderText("选择 gbt45502_security_report.json")
        self.choose_btn=QPushButton("选择报告"); self.load_btn=QPushButton("载入"); top.addWidget(self.report_path,1); top.addWidget(self.choose_btn); top.addWidget(self.load_btn); layout.addLayout(top)
        self.summary_bar=QHBoxLayout(); layout.addLayout(self.summary_bar)
        tabs = QTabWidget()

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["条款", "测试项", "状态", "方法", "建议"])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(False)
        header.sectionDoubleClicked.connect(
            lambda index: self.table.resizeColumnToContents(index)
        )

        self.table.setColumnWidth(0, 190)
        self.table.setColumnWidth(1, 260)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 420)
        self.table.setColumnWidth(4, 520)

        self.table.setWordWrap(True)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self.markdown = QTextEdit()
        self.markdown.setReadOnly(True)

        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)

        tabs.addTab(self.table, "结果明细")
        tabs.addTab(self.markdown, "Markdown报告")
        tabs.addTab(self.raw, "JSON原文")
        layout.addWidget(tabs, 1)
        # self.markdown=QTextEdit(); self.markdown.setReadOnly(True); self.raw=QPlainTextEdit(); self.raw.setReadOnly(True)
        # tabs.addTab(self.table,"结果明细"); tabs.addTab(self.markdown,"Markdown报告"); tabs.addTab(self.raw,"JSON原文"); layout.addWidget(tabs,1)
        self.choose_btn.clicked.connect(self.choose_report); self.load_btn.clicked.connect(self.load_report)
    def choose_report(self):
        path,_=QFileDialog.getOpenFileName(self,"选择报告JSON",str(BACKEND_ROOT/"reports"),"JSON Files (*.json)")
        if path: self.report_path.setText(path)
    def load_report(self):
        path=Path(self.report_path.text())
        if not path.exists(): QMessageBox.warning(self,"文件不存在",str(path)); return
        self.report_json=json.loads(path.read_text(encoding="utf-8")); self.raw.setPlainText(json.dumps(self.report_json,ensure_ascii=False,indent=2))
        md=path.with_suffix(".md"); self.markdown.setPlainText(md.read_text(encoding="utf-8") if md.exists() else "未找到 Markdown 报告。")
        self.populate_summary(); self.populate_table()
    def populate_summary(self):
        while self.summary_bar.count():
            item=self.summary_bar.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        summary=self.report_json.get("summary",{}) if self.report_json else {}
        for k in ["PASS","WARN","MANUAL","INFO","ERROR","FAIL"]:
            c=CyberCard(); c.setMaximumHeight(110); num=QLabel(str(summary.get(k,0))); num.setObjectName("MetricNumber"); lab=QLabel(k); lab.setObjectName("MetricLabel"); c.layout.addWidget(num); c.layout.addWidget(lab); self.summary_bar.addWidget(c)
    def populate_table(self):
        results=self.report_json.get("results",[]) if self.report_json else []; self.table.setRowCount(len(results))
        cmap={"PASS":QColor(0,220,170),"WARN":QColor(255,190,70),"ERROR":QColor(255,90,120),"FAIL":QColor(255,60,90),"MANUAL":QColor(120,170,255),"INFO":QColor(90,220,255)}
        for r,item in enumerate(results):
            vals=[item.get("clause",""),item.get("name",""),item.get("status",""),item.get("method",""),item.get("suggestion","")]
            for c,v in enumerate(vals):
                tw=QTableWidgetItem(str(v)); tw.setForeground(QBrush(QColor(220,245,255)))
                if c==2: tw.setForeground(QBrush(cmap.get(str(v),QColor(220,245,255)))); tw.setFont(QFont("Microsoft YaHei",10,QFont.Weight.Bold))
                self.table.setItem(r,c,tw)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle("GB/T 45502-2025 服务机器人信息安全测试工具"); self.resize(1920,1080); self.setMinimumSize(1280,760)
        self.bg=QLabel(self); bg=ASSET_DIR/"background_1920x1080.png"
        if bg.exists(): self.bg.setPixmap(QPixmap(str(bg))); self.bg.setScaledContents(True); self.bg.lower()
        central=QWidget(); self.setCentralWidget(central); layout=QHBoxLayout(central); layout.setContentsMargins(18,18,18,18); layout.setSpacing(18)
        self.nav=QTreeWidget(); self.nav.setObjectName("NavTree"); self.nav.setHeaderHidden(True); self.nav.setFixedWidth(310)
        logo=QLabel(); lp=ASSET_DIR/"logo.png"
        if lp.exists(): logo.setPixmap(QPixmap(str(lp)).scaledToWidth(260,Qt.TransformationMode.SmoothTransformation))
        nav_img=QLabel(); shp=ASSET_DIR/"security_shield.png"
        if shp.exists(): nav_img.setPixmap(QPixmap(str(shp)).scaledToWidth(270,Qt.TransformationMode.SmoothTransformation))
        nav_box=QFrame(); nav_box.setObjectName("NavBox"); nav_layout=QVBoxLayout(nav_box); nav_layout.addWidget(logo); nav_layout.addWidget(nav_img); nav_layout.addWidget(self.nav,1); layout.addWidget(nav_box)
        self.stack=QStackedWidget(); layout.addWidget(self.stack,1)
        self.settings_page=SettingsPage(); self.test_page=TestPage(self.settings_page); self.results_page=ResultsPage()
        self.stack.addWidget(self.settings_page); self.stack.addWidget(self.test_page); self.stack.addWidget(self.results_page)
        self.build_nav(); self.nav.itemClicked.connect(self.on_nav_clicked); self.apply_style()
    def resizeEvent(self,event): super().resizeEvent(event); self.bg.resize(self.size())
    def build_nav(self):
        for text,icon,idx in [("测试设置","settings.svg",0),("测试主界面","run.svg",1),("测试结果","result.svg",2),("关闭程序","exit.svg",-1)]:
            it=QTreeWidgetItem([text]); ip=ASSET_DIR/icon
            if ip.exists(): it.setIcon(0,QIcon(str(ip)))
            it.setData(0,Qt.ItemDataRole.UserRole,idx); self.nav.addTopLevelItem(it)
        self.nav.setCurrentItem(self.nav.topLevelItem(0))
    def on_nav_clicked(self,item):
        idx=item.data(0,Qt.ItemDataRole.UserRole)
        if idx==-1: self.close(); return
        self.stack.setCurrentIndex(idx)
    def apply_style(self):
        self.setStyleSheet('''
        QMainWindow { background: #061426; }
        QWidget { color: #d9f7ff; font-family: "Microsoft YaHei", "Segoe UI"; font-size: 14px; }
        #NavBox { background: rgba(4,18,42,210); border: 1px solid rgba(0,210,255,150); border-radius: 18px; }
        #NavTree { background: transparent; border: none; outline: 0; font-size: 18px; }
        #NavTree::item { height: 58px; padding: 8px; margin: 6px 4px; border-radius: 12px; color: #bdeeff; }
        #NavTree::item:selected { background: rgba(0,170,255,80); color: white; border: 1px solid rgba(0,220,255,180); }
        #PageTitle { font-size: 30px; font-weight: 700; color: #ffffff; letter-spacing: 1px; }
        #PageDesc { font-size: 15px; color: #8edfff; padding-bottom: 8px; }
        #CyberCard, QGroupBox { background: rgba(6,24,58,210); border: 1px solid rgba(0,210,255,130); border-radius: 16px; }
        #CardTitle { font-size: 18px; font-weight: 700; color: #eafcff; }
        #CardText { color: #9adfff; line-height: 1.4; }
        #ModuleCheck { font-size: 18px; font-weight: 700; color: #eafcff; }
        QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0366b8, stop:1 #00b7ff); color: white; border: 1px solid rgba(0,230,255,180); border-radius: 10px; padding: 9px 16px; font-weight: 600; }
        QPushButton:hover { background: #00a9ff; } QPushButton:disabled { background: rgba(80,95,120,120); color: #8fa7bb; }
        QLineEdit, QPlainTextEdit, QTextEdit, QTableWidget, QTreeWidget { background: rgba(2,12,30,205); border: 1px solid rgba(0,180,255,110); border-radius: 10px; padding: 8px; selection-background-color: #008cff; }
        QHeaderView::section { background: rgba(0,92,150,180); color: white; border: none; padding: 8px; }
        QTabWidget::pane { border: 1px solid rgba(0,180,255,110); border-radius: 10px; }
        QTabBar::tab { background: rgba(4,20,48,210); color: #aeeeff; padding: 10px 18px; border-top-left-radius: 8px; border-top-right-radius: 8px; }
        QTabBar::tab:selected { background: rgba(0,130,220,190); color: white; }
        #Console { font-family: "Consolas", "Courier New"; color: #7df7ff; }
        #StatusPill { background: rgba(0,180,255,70); border: 1px solid rgba(0,220,255,180); border-radius: 16px; padding: 8px 18px; color: #ffffff; font-weight: 700; }
        #MetricNumber { font-size: 30px; font-weight: 800; color: #00e5ff; }
        #MetricLabel { color: #bdeeff; font-weight: 700; }
        QProgressBar { border: 1px solid rgba(0,220,255,180); border-radius: 8px; text-align: center; background: rgba(4,18,42,180); }
        QProgressBar::chunk { background: #00d9ff; border-radius: 8px; }
        ''')

def main():
    app=QApplication(sys.argv); app.setApplicationName("GB/T 45502 Robot Security Tester")
    w=MainWindow(); w.showMaximized(); sys.exit(app.exec())
if __name__=="__main__": main()
