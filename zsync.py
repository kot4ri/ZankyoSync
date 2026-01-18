import os
import sys
import json
import time
import requests
import unicodedata
import hashlib
import threading
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlparse
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

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

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def log(msg, color=None):
    if color == 'red':
        output = f"\033[91m{msg}\033[0m"
    else:
        output = msg
    tqdm.write(output)

def get_visual_width(s):
    width = 0
    for char in s:
        if unicodedata.east_asian_width(char) in ('W', 'F'): width += 2
        else: width += 1
    return width

def pad_string(s, target_width):
    s = str(s)
    return s + ' ' * (max(0, target_width - get_visual_width(s)))

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return "ERROR"

# --- 全局多线程限速器 ---

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
        chunk_size = 8192
        with open(self.file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                self.limiter.request_limit(len(chunk))
                if self.callback:
                    self.callback(len(chunk))
                yield chunk

# --- 配置管理逻辑 ---

def load_config():
    # 使用 get_base_dir() 确保在 EXE 同目录下寻找配置文件
    base_dir = get_base_dir()
    config_path = os.path.join(base_dir, "push_config.json")
    if not os.path.exists(config_path):
        default = {"servers": [], "ignore_local_dirs": [".zsync", ".git", "__pycache__"]}
        save_config(default)
        return default
    with open(config_path, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except:
            return {"servers": [], "ignore_local_dirs": [".zsync", ".git"]}

def save_config(config):
    base_dir = get_base_dir()
    config_path = os.path.join(base_dir, "push_config.json")
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

# --- 管理功能 (新增、编辑、删除服务器逻辑保持不变) ---
# ... (add_server, edit_server, delete_server, manage_ignores 函数内容与原文件一致，调用了 save_config 即可)

def add_server(config):
    clear_screen()
    log("=== 新增服务器配置 ===")
    name = input("服务器名称: ").strip() or "未命名服务器"
    url = input("WebDAV URL (如 https://example.com/dav/): ").strip()
    user = input("用户名: ").strip()
    passwd = input("密码: ").strip()
    ssl_input = input("验证 SSL 证书? (Y/N, 默认Y): ").strip().lower()
    threads_input = input("最大线程数 (默认10): ").strip()
    size_input = input("最大文件限制 (单位GB 默认不限制): ").strip()
    md5_input = input("开启MD5校验? (Y/N, 默认N): ").strip().lower()
    speed_input = input("上传限速 (KB/s, -1为不限速 默认-1): ").strip()

    config['servers'].append({
        "name": name, "url": url, "user": user, "passwd": passwd,
        "verify_ssl": (ssl_input != 'n'),
        "max_threads": int(threads_input) if threads_input.isdigit() else 10,
        "max_file_size_gb": float(size_input) if size_input else -1.0,
        "use_md5": (md5_input == 'y'),
        "speed_limit_kb": float(speed_input) if speed_input else -1.0
    })
    save_config(config)
    log("[√] 已添加服务器。")
    time.sleep(1)

def edit_server(config):
    if not config['servers']: return
    try:
        idx = int(input("\n请输入要编辑的服务器编号: ")) - 1
        if not (0 <= idx < len(config['servers'])): return
        srv = config['servers'][idx]
        clear_screen()
        log(f"=== 正在编辑: {srv['name']} (直接回车保持原值) ===")
        srv['name'] = input(f"服务器名称 [{srv.get('name', '')}]: ").strip() or srv['name']
        srv['url'] = input(f"WebDAV URL [{srv.get('url', '')}]: ").strip() or srv['url']
        srv['user'] = input(f"用户名 [{srv.get('user', '')}]: ").strip() or srv['user']
        srv['passwd'] = input(f"密码 [********]: ").strip() or srv['passwd']
        ssl_hint = "y" if srv.get('verify_ssl', True) else "n"
        ssl_input = input(f"验证 SSL 证书? (Y/N) [当前: {ssl_hint}]: ").strip().lower()
        if ssl_input: srv['verify_ssl'] = (ssl_input != 'n')
        thread_hint = srv.get('max_threads', 10)
        threads_input = input(f"最大线程数 [当前: {thread_hint}]: ").strip()
        if threads_input.isdigit(): srv['max_threads'] = int(threads_input)
        size_hint = srv.get('max_file_size_gb', -1.0)
        size_input = input(f"最大文件限制 (单位GB 不限制 -1) [当前: {size_hint}]: ").strip()
        if size_input: 
            try: srv['max_file_size_gb'] = float(size_input)
            except: pass
        md5_hint = "y" if srv.get('use_md5', False) else "n"
        md5_input = input(f"开启MD5校验? (Y/N) [当前: {md5_hint}]: ").strip().lower()
        if md5_input: srv['use_md5'] = (md5_input == 'y')
        
        speed_hint = srv.get('speed_limit_kb', -1.0)
        speed_input = input(f"上传限速 (KB/s, -1为不限速) [当前: {speed_hint}]: ").strip()
        if speed_input: srv['speed_limit_kb'] = float(speed_input)
        
        save_config(config)
        log("[√] 配置已更新。")
        time.sleep(1)
    except: pass

def delete_server(config):
    try:
        idx = int(input("\n请输入要删除的服务器编号: ")) - 1
        if 0 <= idx < len(config['servers']):
            removed = config['servers'].pop(idx)
            save_config(config)
            log(f"[√] 已删除服务器: {removed['name']}")
            time.sleep(1)
    except: pass

def manage_ignores(config):
    while True:
        clear_screen()
        log("═"*60)
        log(" 当前忽略的文件夹清单 (不扫描、不推送、不清理):")
        log("─"*60)
        ignores = config.get("ignore_local_dirs", [])
        for i, path in enumerate(ignores, 1):
            log(f" [{i}] {path}")
        log("─"*60)
        log(" [A] 新增忽略项    [D] 删除忽略项    [E] 返回主菜单")
        log("═"*60)
        choice = input("\n请选择指令: ").strip().lower()
        if choice == 'e': break
        elif choice == 'a':
            new_path = input("请输入文件夹名称: ").strip()
            if new_path and new_path not in ignores:
                ignores.append(new_path)
                save_config(config)
        elif choice == 'd':
            try:
                idx = int(input("请输入编号: ")) - 1
                if 0 <= idx < len(ignores):
                    ignores.pop(idx); save_config(config)
            except: pass

# --- WebDAV 执行逻辑 (保持不变) ---
# ... (WebDAVMirror 类内容与原文件一致)
class WebDAVMirror:
    def __init__(self, srv, session, limiter, max_threads):
        self.srv = srv
        self.base_url = srv['url'].rstrip('/')
        self.auth = HTTPBasicAuth(srv['user'], srv['passwd'])
        self.verify = srv.get('verify_ssl', True)
        self.session = session
        self.limiter = limiter
        self.completed_lock = threading.Lock()
        self.completed_files = set()
        self.max_threads = max_threads

    def get_remote_manifest(self):
        url = f"{self.base_url}/.zsync/files_info.json"
        try:
            res = self.session.get(url, auth=self.auth, verify=self.verify, timeout=20)
            if res.status_code == 200:
                data = res.json()
                return {item['relative_path']: item for item in data}
        except: pass
        return {}

    def check_manifest_exists(self):
        url = f"{self.base_url}/.zsync/files_info.json"
        try:
            res = self.session.request("PROPFIND", url, auth=self.auth, verify=self.verify, headers={'Depth': '0'})
            return res.status_code == 207
        except: return False

    def list_remote_actual(self):
        remote_files, remote_dirs = {}, set()
        path_prefix = urlparse(self.base_url).path.rstrip('/')
        dirs_to_scan = ["/"]
        log(f"[*] 深度实地扫描远程文件系统...")
        while dirs_to_scan:
            curr_dir = dirs_to_scan.pop(0)
            try:
                res = self.session.request("PROPFIND", f"{self.base_url}{curr_dir.rstrip('/')}/", 
                                         auth=self.auth, verify=self.verify, headers={'Depth': '1'}, timeout=20)
                if res.status_code != 207: continue
                tree = ET.fromstring(res.content)
                for resp in tree.findall('{DAV:}response'):
                    href = unquote(resp.find('{DAV:}href').text)
                    rel = href[len(path_prefix):].lstrip('/') if href.startswith(path_prefix) else href.lstrip('/')
                    if not rel or rel == curr_dir.lstrip('/'): continue
                    prop = resp.find('{DAV:}propstat/{DAV:}prop')
                    if prop.find('{DAV:}resourcetype/{DAV:}collection') is not None:
                        remote_dirs.add(rel); dirs_to_scan.append(f"/{rel}")
                    else:
                        size = int(prop.findtext('{DAV:}getcontentlength') or 0)
                        remote_files[rel] = {"size": size}
            except: pass
        return remote_files, remote_dirs

    def upload_file(self, local_path, rel_path, thread_slot):
        try:
            sub_dirs = os.path.dirname(rel_path).split('/')
            curr = ""
            for d in sub_dirs:
                if not d: continue
                curr += f"/{d}"
                self.session.request("MKCOL", f"{self.base_url}{curr}", auth=self.auth, verify=self.verify)
            
            f_size = os.path.getsize(local_path)
            
            pbar = tqdm(total=f_size, unit='B', unit_scale=True, 
                        desc=pad_string(f"  [↑] {rel_path[-25:]}", 32), 
                        position=thread_slot, leave=False, dynamic_ncols=True)

            def progress_callback(n):
                pbar.update(n)

            data_stream = ThrottledFileReader(local_path, self.limiter, progress_callback)
            res = self.session.put(f"{self.base_url}/{rel_path}", data=data_stream, auth=self.auth, verify=self.verify, timeout=300)
            pbar.close()

            if res.status_code in [200, 201, 204]:
                with self.completed_lock:
                    self.completed_files.add(rel_path)
                return True, res.status_code
            return False, res.status_code
        except: return False, "Error"

# --- 主同步流程 ---

def save_manifest_to_remote(mirror, local_files, use_md5, target_root):
    with mirror.completed_lock:
        current_completed = list(mirror.completed_files)
    
    manifest_data = []
    for k, v in local_files.items():
        if k in current_completed or k not in getattr(mirror, 'pending_uploads', []):
            item = {
                "relative_path": k, 
                "size_bytes": v["size"],
                "mtime": v.get("mtime")
            }
            if use_md5: item["md5"] = v["md5"]
            manifest_data.append(item)
    
    js_content = json.dumps(manifest_data, indent=4).encode('utf-8')
    
    # 写入远程
    try:
        mirror.session.put(f"{mirror.srv['url'].rstrip('/')}/.zsync/files_info.json", 
                          data=js_content, 
                          auth=mirror.auth, verify=mirror.srv['verify_ssl'], timeout=10)
    except: pass

    # 写入本地
    try:
        l_path = os.path.join(target_root, ".zsync")
        if not os.path.exists(l_path): os.makedirs(l_path)
        with open(os.path.join(l_path, "files_info.json"), "wb") as f:
            f.write(js_content)
    except: pass

def run_sync(srv, full_config):
    clear_screen()
    log(f"=== 开始同步至: {srv['name']} ===")
    
    # 路径对齐逻辑
    base_dir = get_base_dir()
    target_root = os.path.dirname(base_dir) # 扫描程序的上一级目录
    
    max_threads = srv.get('max_threads', 10)
    use_md5 = srv.get('use_md5', False)
    size_limit_bytes = srv.get('max_file_size_gb', -1) * 1024**3
    ignore_dirs = full_config.get("ignore_local_dirs", [".zsync"])

    stats = {"added": 0, "replaced": 0, "deleted": 0}
    session = requests.Session()
    session.trust_env = False
    session.mount("https://", HTTPAdapter(pool_connections=max_threads, pool_maxsize=max_threads*2))

    limiter = GlobalRateLimiter(srv.get('speed_limit_kb', -1.0))
    mirror = WebDAVMirror(srv, session, limiter, max_threads)
    
    remote_scan_result = mirror.list_remote_actual()
    remote_actual, remote_dirs = remote_scan_result[0], remote_scan_result[1]
    manifest_exists = mirror.check_manifest_exists()
    remote_manifest = mirror.get_remote_manifest() if use_md5 else {}

    # 加载本地缓存用于智能校验
    local_cache = {}
    local_manifest_path = os.path.join(target_root, ".zsync", "files_info.json")
    if os.path.exists(local_manifest_path):
        try:
            with open(local_manifest_path, 'r', encoding='utf-8') as f:
                for item in json.load(f):
                    local_cache[item['relative_path']] = item
        except: pass

    if not manifest_exists and len(remote_actual) > 0:
        log("\n" + "!"*60)
        log("[警告] 在服务器上未找到同步清单 (.zsync/files_info.json)")
        log(f"[警告] 探测到远程已存在 {len(remote_actual)} 个文件。")
        log("继续同步将删除所有与本地不一致的远程文件（即镜像对齐）。")
        log("!"*60)
        confirm = input("\n确定要继续吗? (Y/N): ").strip().upper()
        if confirm != 'Y': return

    log(f"[*] 扫描本地文件...")
    local_files = {}
    
    all_local_paths = []
    for root, dirs, files in os.walk(target_root):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for name in files:
            all_local_paths.append(os.path.join(root, name))

    total_files = len(all_local_paths)
    for i, full_path in enumerate(all_local_paths, 1):
        rel = os.path.relpath(full_path, target_root).replace(os.sep, '/')
        sys.stdout.write(f"\r    正在扫描 ({i}/{total_files}): {rel[:50]}...")
        sys.stdout.flush()
        
        try:
            st = os.stat(full_path)
            f_size = st.st_size
            f_mtime = int(st.st_mtime)
            
            if 0 < size_limit_bytes < f_size: continue
            
            f_info = {"size": f_size, "path": full_path, "mtime": f_mtime}
            if use_md5:
                # 智能验证逻辑
                cache_item = local_cache.get(rel)
                if cache_item and cache_item.get('size_bytes') == f_size and cache_item.get('mtime') == f_mtime:
                    f_info["md5"] = cache_item.get('md5')
                else:
                    f_info["md5"] = calculate_md5(full_path)
            local_files[rel] = f_info
        except: pass
    sys.stdout.write("\n")

    # (后续同步、上传、清单保存逻辑保持不变)
    # ... 

    to_upload = []
    for p, l in local_files.items():
        if p not in remote_actual: to_upload.append((p, False))
        elif l['size'] != remote_actual[p]['size']: to_upload.append((p, True))
        elif use_md5 and (p not in remote_manifest or l['md5'] != remote_manifest[p].get('md5')):
            to_upload.append((p, True))

    mirror.pending_uploads = [item[0] for item in to_upload]

    redundant = [p for p in remote_actual if p not in local_files and not p.startswith(".zsync")]
    if redundant:
        log(f"[*] 清理冗余文件 ({len(redundant)}个)...")
        for p in redundant:
            session.delete(f"{srv['url'].rstrip('/')}/{p}", auth=mirror.auth, verify=srv['verify_ssl'])
            log(f"    [删除] {p}"); stats["deleted"] += 1

    if to_upload:
        log(f"[*] 推送更新 ({len(to_upload)}个)...")
        
        stop_event = threading.Event()
        def manifest_updater():
            while not stop_event.is_set():
                for _ in range(60):
                    if stop_event.is_set(): return
                    time.sleep(1)
                save_manifest_to_remote(mirror, local_files, use_md5, target_root)
        
        updater_thread = threading.Thread(target=manifest_updater, daemon=True)
        updater_thread.start()

        slot_lock = threading.Lock()
        available_slots = list(range(max_threads))

        def upload_worker(item):
            p, is_rep = item
            with slot_lock:
                slot = available_slots.pop(0)
            
            res_tuple = mirror.upload_file(local_files[p]['path'], p, slot)
            ok_status = res_tuple[0]
            
            with slot_lock:
                available_slots.insert(0, slot)
                available_slots.sort()
            return ok_status, p, is_rep

        with ThreadPoolExecutor(max_threads) as pool:
            futures = [pool.submit(upload_worker, item) for item in to_upload]
            for f in as_completed(futures):
                ok, p, is_rep = f.result()
                if ok:
                    if is_rep: log(f"    [↑] {p} (被替换)", color='red'); stats["replaced"] += 1
                    else: log(f"    [↑] {p}"); stats["added"] += 1
                else: log(f"    [×] {p}")
        
        stop_event.set()
        tqdm.write("\n" * max_threads)

    p_del_dirs = sorted([d for d in remote_dirs if d not in [os.path.dirname(k) for k in local_files] and not d.startswith(".zsync")], key=len, reverse=True)
    for d in p_del_dirs:
        url = f"{srv['url'].rstrip('/')}/{d}/"
        try:
            res = session.request("PROPFIND", url, auth=mirror.auth, verify=srv['verify_ssl'], headers={'Depth': '1'})
            if res.status_code == 207 and len(ET.fromstring(res.content).findall('{DAV:}response')) <= 1:
                session.delete(url, auth=mirror.auth, verify=srv['verify_ssl'])
                log(f"    [清理目录] {d}")
        except: pass

    log("[*] 正在写入同步清单...")
    save_manifest_to_remote(mirror, local_files, use_md5, target_root)

    session.close()
    log("\n" + "─"*30 + f"\n 同步完成统计:\n  - 新增文件: {stats['added']}\n  - 替换文件: {stats['replaced']}\n  - 删除文件: {stats['deleted']}\n" + "─"*30)
    log(f"\n[√] 同步任务结束。")
    if len(sys.argv) == 1: input("\n按回车键返回主选单...")

# --- 程序入口 ---

def main():
    config = load_config()
    if len(sys.argv) > 1:
        try:
            idx = int(sys.argv[1]) - 1
            if 0 <= idx < len(config['servers']):
                run_sync(config['servers'][idx], config); return
        except: pass

    while True:
        config = load_config()
        clear_screen()
        log("═"*115)
        log(pad_string(" 编号", 8) + pad_string("服务器名称", 20) + pad_string("并发线程", 12) + pad_string("验证SSL", 12) + pad_string("校验MD5", 12) + pad_string("限速(KB/s)", 15) + "最大文件限制")
        log("─"*115)
        for i, s in enumerate(config['servers'], 1):
            limit = f"{s.get('max_file_size_gb',-1)}GB" if s.get('max_file_size_gb',-1) > 0 else "无"
            speed_val = s.get('speed_limit_kb', -1.0)
            log(pad_string(f" [{i}]", 8) + pad_string(s['name'], 20) + pad_string(str(s['max_threads']), 12) + pad_string("√" if s.get('verify_ssl', True) else "×", 12) + pad_string("√" if s.get('use_md5', False) else "×", 12) + pad_string(str(speed_val), 15) + limit)
        log("─"*115)
        log(" [A] 新增服务器    [E] 编辑服务器    [D] 删除服务器    [R] 管理忽略路径    [Q] 退出")
        log("═"*115)
        choice = input("\n请选择编号开始同步或输入指令: ").strip().lower()
        if choice == 'q': break
        elif choice == 'a': add_server(config)
        elif choice == 'e': edit_server(config)
        elif choice == 'd': delete_server(config)
        elif choice == 'r': manage_ignores(config)
        else:
            try: run_sync(config['servers'][int(choice)-1], config)
            except: pass

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)