import os
import sys
import json
import time
import hashlib
import threading
import requests
import subprocess
import shutil
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlparse
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor

# 导入 PySide6 组件
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QListWidget, QTextEdit, QProgressBar, QLabel, 
                             QLineEdit, QCheckBox, QGroupBox, QFormLayout, QSplitter, QMessageBox)
from PySide6.QtCore import Qt, QThread, Signal, Slot

# --- 路径兼容工具 ---
def get_base_dir():
    """获取程序运行的实际物理目录 (兼容脚本运行和 PyInstaller 打包后的 EXE)"""
    if getattr(sys, 'frozen', False):
        # 打包后的环境，sys.executable 是 EXE 的完整路径
        return os.path.dirname(sys.executable)
    else:
        # 脚本运行环境
        return os.path.dirname(os.path.abspath(__file__))

# --- 基础工具 ---
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except: return "ERROR"

# --- 外部脚本执行线程 ---
class ScriptRunner(QThread):
    output_signal = Signal(str)
    finished_signal = Signal()

    def __init__(self, command, cwd):
        super().__init__()
        self.command = command
        self.cwd = cwd

    def run(self):
        try:
            # 使用 GBK 编码读取子进程输出，并强制指定工作目录
            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                text=False,
                cwd=self.cwd
            )
            for line in iter(process.stdout.readline, b''):
                self.output_signal.emit(line.decode('gbk', errors='replace').strip())
            process.wait()
        except Exception as e:
            self.output_signal.emit(f"[错误] 执行脚本失败: {str(e)}")
        finally:
            self.finished_signal.emit()

# --- 限速器与读取器 ---
class GlobalRateLimiter:
    def __init__(self, limit_kb_s):
        self.limit_bps = limit_kb_s * 1024
        self.lock = threading.Lock()
        self.last_check = time.time()
        self.allowance = self.limit_bps if self.limit_bps > 0 else 0

    def request_limit(self, amount):
        if self.limit_bps <= 0: return
        with self.lock:
            while amount > 0:
                current = time.time()
                time_passed = current - self.last_check
                self.last_check = current
                self.allowance += time_passed * self.limit_bps
                if self.allowance > self.limit_bps: self.allowance = self.limit_bps
                if self.allowance >= amount:
                    self.allowance -= amount
                    amount = 0
                else:
                    needed = amount - self.allowance
                    time.sleep(needed / self.limit_bps)

class ThrottledFileReader:
    def __init__(self, file_path, limiter, callback=None):
        self.file_path = file_path
        self.limiter = limiter
        self.callback = callback

    def __iter__(self):
        chunk_size = 16384
        with open(self.file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                self.limiter.request_limit(len(chunk))
                if self.callback: self.callback(len(chunk))
                yield chunk

# --- 核心逻辑线程 ---
class SyncWorker(QThread):
    log_signal = Signal(str)
    progress_signal = Signal(int, str, float)
    ask_confirm_signal = Signal(str, str)
    confirm_res = None 
    confirm_lock = threading.Event()
    finished_signal = Signal(dict)

    def __init__(self, srv, full_config, mode="sync"):
        super().__init__()
        self.srv = srv
        self.full_config = full_config
        self.mode = mode

    def wait_for_confirm(self, title, msg):
        self.confirm_lock.clear()
        self.ask_confirm_signal.emit(title, msg)
        self.confirm_lock.wait()
        return self.confirm_res

    def run(self):
        stats = {"added": 0, "replaced": 0, "deleted": 0}
        try:
            if self.mode == "sync":
                self.execute_sync(stats)
        except Exception as e:
            self.log_signal.emit(f"[错误] 执行中断: {str(e)}")
        finally:
            self.finished_signal.emit(stats)

    def execute_sync(self, stats):
        base_dir = get_base_dir()
        target_root = os.path.dirname(base_dir) # 扫描程序上一级
        max_threads = self.srv.get('max_threads', 10)
        use_md5 = self.srv.get('use_md5', False)
        size_limit_gb = self.srv.get('max_file_size_gb', -1.0)
        size_limit_bytes = size_limit_gb * 1024**3 if size_limit_gb > 0 else -1
        
        session = requests.Session()
        session.mount("https://", HTTPAdapter(pool_connections=max_threads, pool_maxsize=max_threads*2))
        auth = HTTPBasicAuth(self.srv['user'], self.srv['passwd'])
        verify = self.srv.get('verify_ssl', True)
        base_url = self.srv['url'].rstrip('/')

        self.log_signal.emit("[*] 正在检索远程状态...")
        remote_actual = {}
        path_prefix = urlparse(base_url).path.rstrip('/')
        
        manifest_url = f"{base_url}/.zsync/files_info.json"
        has_manifest = False
        try:
            res_m = session.request("PROPFIND", manifest_url, auth=auth, verify=verify, headers={'Depth': '0'})
            has_manifest = (res_m.status_code == 207)
        except: pass

        dirs_to_scan = ["/"]
        while dirs_to_scan:
            curr_dir = dirs_to_scan.pop(0)
            try:
                res = session.request("PROPFIND", f"{base_url}{curr_dir.rstrip('/')}/", 
                                     auth=auth, verify=verify, headers={'Depth': '1'}, timeout=20)
                if res.status_code != 207: continue
                tree = ET.fromstring(res.content)
                for resp in tree.findall('{DAV:}response'):
                    href = unquote(resp.find('{DAV:}href').text)
                    rel = href[len(path_prefix):].lstrip('/') if href.startswith(path_prefix) else href.lstrip('/')
                    if not rel or rel == curr_dir.lstrip('/'): continue
                    prop = resp.find('{DAV:}propstat/{DAV:}prop')
                    if prop.find('{DAV:}resourcetype/{DAV:}collection') is not None:
                        dirs_to_scan.append(f"/{rel}")
                    else:
                        size = int(prop.findtext('{DAV:}getcontentlength') or 0)
                        remote_actual[rel] = {"size": size}
            except: pass

        if not has_manifest and len(remote_actual) > 0:
            msg = "服务器上未检测到同步清单并存在其他文件，是否执行镜像对齐？"
            if not self.wait_for_confirm("首扫安全警告", msg):
                self.log_signal.emit("[!] 用户取消了同步操作。")
                return

        local_cache = {}
        local_manifest_path = os.path.join(target_root, ".zsync", "files_info.json")
        if os.path.exists(local_manifest_path):
            try:
                with open(local_manifest_path, 'r', encoding='utf-8') as f:
                    for item in json.load(f): local_cache[item['relative_path']] = item
            except: pass

        local_files = {}
        ignore_dirs = self.full_config.get("ignore_local_dirs", [".zsync", ".git"])
        for root, dirs, files in os.walk(target_root):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for name in files:
                full_path = os.path.join(root, name)
                rel = os.path.relpath(full_path, target_root).replace(os.sep, '/')
                st = os.stat(full_path)
                if 0 < size_limit_bytes < st.st_size: continue
                
                f_info = {"size": st.st_size, "path": full_path, "mtime": int(st.st_mtime)}
                if use_md5:
                    c = local_cache.get(rel)
                    if c and c.get('size_bytes') == st.st_size and c.get('mtime') == int(st.st_mtime):
                        f_info["md5"] = c.get('md5')
                    else: f_info["md5"] = calculate_md5(full_path)
                local_files[rel] = f_info

        redundant = [p for p in remote_actual if p not in local_files and not p.startswith(".zsync")]
        for p in redundant:
            try:
                session.delete(f"{base_url}/{p}", auth=auth, verify=verify)
                self.log_signal.emit(f" [清理] {p}")
                stats["deleted"] += 1
            except: pass

        to_upload = []
        for p, l in local_files.items():
            if p not in remote_actual or l['size'] != remote_actual[p]['size']:
                to_upload.append((p, p in remote_actual))

        if to_upload:
            limiter = GlobalRateLimiter(self.srv.get('speed_limit_kb', -1.0))
            available_slots = list(range(max_threads))
            slot_lock = threading.Lock()

            def upload_one(item):
                rel_path, is_replace = item
                with slot_lock: slot = available_slots.pop(0)
                try:
                    total_size = local_files[rel_path]['size']
                    read_acc = 0
                    def prog(n):
                        nonlocal read_acc
                        read_acc += n
                        self.progress_signal.emit(slot, rel_path, (read_acc/total_size)*100 if total_size > 0 else 100)
                    
                    sub_dirs = os.path.dirname(rel_path).split('/')
                    curr = ""
                    for d in sub_dirs:
                        if not d: continue
                        curr += f"/{d}"
                        session.request("MKCOL", f"{base_url}{curr}", auth=auth, verify=verify)

                    stream = ThrottledFileReader(local_files[rel_path]['path'], limiter, prog)
                    session.put(f"{base_url}/{rel_path}", data=stream, auth=auth, verify=verify, timeout=300)
                    self.log_signal.emit(f" [↑] {'[替换]' if is_replace else '[新增]'} {rel_path}")
                    if is_replace: stats["replaced"] += 1
                    else: stats["added"] += 1
                except: self.log_signal.emit(f" [×] 失败: {rel_path}")
                finally:
                    self.progress_signal.emit(slot, "等待中...", 0)
                    with slot_lock: available_slots.append(slot)

            with ThreadPoolExecutor(max_threads) as pool: pool.map(upload_one, to_upload)

        # 清单上传
        manifest_data = [{"relative_path": k, "size_bytes": v["size"], "mtime": v["mtime"], 
                          **({"md5": v["md5"]} if use_md5 else {})} for k, v in local_files.items()]
        os.makedirs(os.path.dirname(local_manifest_path), exist_ok=True)
        js_bytes = json.dumps(manifest_data, indent=4, ensure_ascii=False).encode('utf-8')
        with open(local_manifest_path, 'wb') as f: f.write(js_bytes)
        try:
            session.request("MKCOL", f"{base_url}/.zsync", auth=auth, verify=verify)
            session.put(f"{base_url}/.zsync/files_info.json", data=js_bytes, auth=auth, verify=verify)
        except: pass

# --- GUI 主窗口 ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ZankyoSync GUI")
        self.resize(1100, 650) # 高度缩减
        self.config = self.load_config()
        self.setup_ui()
        self.refresh_server_list()

    def load_config(self):
        path = os.path.join(get_base_dir(), "push_config.json")
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f: return json.load(f)
            except: pass
        return {"servers": [], "ignore_local_dirs": [".zsync", ".git"]}

    def save_config(self):
        path = os.path.join(get_base_dir(), "push_config.json")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=4, ensure_ascii=False)

    def setup_ui(self):
        main_widget = QWidget(); self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)

        left_part = QWidget(); left_layout = QVBoxLayout(left_part)
        self.server_list = QListWidget(); self.server_list.currentRowChanged.connect(self.display_server_info)
        left_layout.addWidget(QLabel("服务器列表:"))
        left_layout.addWidget(self.server_list)
        btn_add = QPushButton("+ 新增服务器"); btn_add.clicked.connect(self.add_server); left_layout.addWidget(btn_add)
        btn_del = QPushButton("- 删除服务器"); btn_del.clicked.connect(self.delete_current_server); left_layout.addWidget(btn_del)
        left_layout.addStretch()
        
        self.btn_load_full = QPushButton("📂 加载完整清单"); self.btn_load_full.clicked.connect(self.load_full_manifest); left_layout.addWidget(self.btn_load_full)
        self.btn_rebuild = QPushButton("🔨 重建本地清单"); self.btn_rebuild.clicked.connect(self.rebuild_local_manifest); left_layout.addWidget(self.btn_rebuild)
        
        self.btn_sync = QPushButton("🚀 开始同步任务"); self.btn_sync.setFixedHeight(50); self.btn_sync.setStyleSheet("background-color: #0078d4; color: white; font-weight: bold;")
        self.btn_sync.clicked.connect(self.start_sync); left_layout.addWidget(self.btn_sync)
        layout.addWidget(left_part, 1)

        mid_part = QSplitter(Qt.Vertical)
        edit_group = QGroupBox("服务器配置"); form = QFormLayout(edit_group)
        self.edit_name = QLineEdit(); form.addRow("名称:", self.edit_name)
        self.edit_url = QLineEdit(); form.addRow("WebDAV URL:", self.edit_url)
        self.edit_user = QLineEdit(); form.addRow("用户名:", self.edit_user)
        self.edit_pass = QLineEdit(); self.edit_pass.setEchoMode(QLineEdit.Password); form.addRow("密码:", self.edit_pass)
        self.edit_threads = QLineEdit(); form.addRow("最大并发线程:", self.edit_threads)
        self.edit_limit = QLineEdit(); form.addRow("最大文件限制 (GB):", self.edit_limit)
        self.edit_speed = QLineEdit(); form.addRow("上传速率限制 (KB/s):", self.edit_speed)
        self.check_md5 = QCheckBox("启用 MD5 深度校验"); form.addRow(self.check_md5)
        self.check_ssl = QCheckBox("验证 SSL 证书"); form.addRow(self.check_ssl)
        btn_save = QPushButton("💾 保存当前配置"); btn_save.clicked.connect(self.save_current_edit); form.addRow(btn_save)
        mid_part.addWidget(edit_group)

        self.log_area = QTextEdit(); self.log_area.setReadOnly(True); self.log_area.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas';")
        mid_part.addWidget(self.log_area)
        layout.addWidget(mid_part, 3)

        self.prog_group = QGroupBox("线程监控"); self.prog_layout = QVBoxLayout(self.prog_group); self.prog_layout.addStretch()
        layout.addWidget(self.prog_group, 2)

    def refresh_server_list(self):
        self.server_list.clear()
        for s in self.config['servers']: self.server_list.addItem(s['name'])

    def display_server_info(self, row):
        if row < 0: return
        s = self.config['servers'][row]
        self.edit_name.setText(s['name']); self.edit_url.setText(s['url']); self.edit_user.setText(s['user'])
        self.edit_pass.setText(s['passwd']); self.edit_threads.setText(str(s.get('max_threads', 10)))
        self.edit_limit.setText(str(s.get('max_file_size_gb', -1.0))); self.edit_speed.setText(str(s.get('speed_limit_kb', -1.0)))
        self.check_md5.setChecked(s.get('use_md5', False)); self.check_ssl.setChecked(s.get('verify_ssl', True))

    def save_current_edit(self):
        row = self.server_list.currentRow()
        if row < 0: return
        s = self.config['servers'][row]
        s['name'] = self.edit_name.text(); s['url'] = self.edit_url.text(); s['user'] = self.edit_user.text(); s['passwd'] = self.edit_pass.text()
        try: s['max_threads'] = int(self.edit_threads.text()); s['max_file_size_gb'] = float(self.edit_limit.text()); s['speed_limit_kb'] = float(self.edit_speed.text())
        except: pass
        s['use_md5'] = self.check_md5.isChecked(); s['verify_ssl'] = self.check_ssl.isChecked()
        self.save_config(); self.refresh_server_list()
        self.log_area.append("[系统] 配置已保存。")

    def add_server(self):
        self.config['servers'].append({"name": "新服务器", "url": "https://", "user": "", "passwd": "", "max_threads": 10})
        self.save_config(); self.refresh_server_list()

    def delete_current_server(self):
        row = self.server_list.currentRow()
        if row >= 0: self.config['servers'].pop(row); self.save_config(); self.refresh_server_list()

    def load_full_manifest(self):
        target_root = os.path.dirname(get_base_dir())
        full_path = os.path.join(target_root, ".zsync", "files_info.json.full")
        target_path = os.path.join(target_root, ".zsync", "files_info.json")
        if os.path.exists(full_path):
            try:
                shutil.copy2(full_path, target_path)
                self.log_area.append("[系统] 已从 files_info.json.full 加载完整清单。")
            except Exception as e:
                self.log_area.append(f"[错误] 加载失败: {str(e)}")
        else:
            self.log_area.append("[错误] 未找到 files_info.json.full 文件。")

    def rebuild_local_manifest(self):
        base_dir = get_base_dir()
        exe_path = os.path.join(base_dir, "zscan_fast.exe")
        if not os.path.exists(exe_path):
            self.log_area.append(f"[错误] 未找到程序: {exe_path}")
            return
        self.btn_rebuild.setEnabled(False); self.btn_sync.setEnabled(False)
        self.log_area.append(f"[*] 启动重建程序，工作目录: {base_dir}")
        self.script_thread = ScriptRunner(f"\"{exe_path}\"", cwd=base_dir)
        self.script_thread.output_signal.connect(self.log_area.append)
        self.script_thread.finished_signal.connect(self.on_script_finished)
        self.script_thread.start()

    def on_script_finished(self):
        self.btn_rebuild.setEnabled(True); self.btn_sync.setEnabled(True)
        self.log_area.append("[系统] 重建程序运行结束。")

    @Slot(str, str)
    def handle_confirm(self, title, msg):
        res = QMessageBox.warning(self, title, msg, QMessageBox.Yes | QMessageBox.No)
        self.worker.confirm_res = (res == QMessageBox.Yes)
        self.worker.confirm_lock.set()

    def start_sync(self):
        row = self.server_list.currentRow()
        if row < 0: return
        srv = self.config['servers'][row]
        for i in reversed(range(self.prog_layout.count())): 
            w = self.prog_layout.itemAt(i).widget()
            if w: w.deleteLater()
        self.progress_bars = []
        for i in range(srv.get('max_threads', 10)):
            container = QWidget(); l = QVBoxLayout(container)
            txt = QLabel(f"线程 {i}: 空闲"); bar = QProgressBar(); bar.setFixedHeight(10)
            l.addWidget(txt); l.addWidget(bar); self.prog_layout.insertWidget(i, container)
            self.progress_bars.append((txt, bar))
        self.btn_rebuild.setEnabled(False); self.btn_sync.setEnabled(False)
        self.worker = SyncWorker(srv, self.config, mode="sync")
        self.worker.log_signal.connect(self.log_area.append)
        self.worker.progress_signal.connect(self.update_ui_progress)
        self.worker.ask_confirm_signal.connect(self.handle_confirm)
        self.worker.finished_signal.connect(self.on_worker_finished)
        self.worker.start()

    @Slot(int, str, float)
    def update_ui_progress(self, slot, name, val):
        if slot < len(self.progress_bars):
            txt, bar = self.progress_bars[slot]
            txt.setText(f"线程 {slot}: {name[-25:]}"); bar.setValue(int(val))

    def on_worker_finished(self, stats):
        self.btn_rebuild.setEnabled(True); self.btn_sync.setEnabled(True)
        if stats:
            self.log_area.append(f"\n[√] 同步统计: 新增:{stats['added']}, 替换:{stats['replaced']}, 清理:{stats['deleted']}")
        self.log_area.append("[系统] 任务已结束。")

if __name__ == "__main__":
    app = QApplication(sys.argv); window = MainWindow(); window.show(); sys.exit(app.exec())