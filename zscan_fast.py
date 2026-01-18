import os
import json
import hashlib
import time
import sys

# --- 路径兼容工具 ---

def get_base_dir():
    """
    获取程序运行的实际物理目录。
    如果被 PyInstaller 打包成 EXE，则返回 EXE 所在文件夹；
    如果是脚本运行，则返回脚本所在文件夹。
    """
    if getattr(sys, 'frozen', False):
        # 打包后的环境，sys.executable 是 EXE 的完整路径
        return os.path.dirname(sys.executable)
    else:
        # 脚本运行环境
        return os.path.dirname(os.path.abspath(__file__))

def calculate_md5(file_path):
    """计算文件的 MD5 值"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return "ERROR"

def run_fast_scan():
    # 1. 确定物理路径
    # base_dir 是 EXE 所在的文件夹（例如：D:/SyncTool/）
    base_dir = get_base_dir()
    
    # target_root 是要扫描的目标根目录。
    # 根据你的结构，如果脚本在子文件夹中，使用 os.path.dirname(base_dir)；
    # 如果脚本/EXE就在根目录下，则直接使用 base_dir。
    # 这里采用你之前的逻辑：扫描脚本所在目录的上一级。
    target_root = os.path.dirname(base_dir) 
    
    # 配置文件应与 EXE 放在同一目录下
    config_path = os.path.join(base_dir, "push_config.json")
    
    # 保存目录在目标根目录下的 .zsync
    save_dir = os.path.join(target_root, ".zsync")
    manifest_path = os.path.join(save_dir, "files_info.json.full")
    
    # 2. 读取配置获取忽略目录
    ignore_dirs = [".zsync", ".git", "__pycache__"] 
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                user_ignores = config.get("ignore_local_dirs", [])
                for d in user_ignores:
                    if d not in ignore_dirs:
                        ignore_dirs.append(d)
            print(f"[*] 已从 {config_path} 加载配置")
            print(f"[*] 忽略目录: {ignore_dirs}")
        except Exception as e:
            print(f"[!] 读取配置文件失败: {e}")
    else:
        print(f"[*] 未找到配置文件 {config_path}，使用默认忽略项。")

    # 3. 加载旧清单作为缓存
    old_cache = {}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    old_cache[item['relative_path']] = item
        except: 
            pass

    # 4. 开始递归扫描
    print(f"[*] 正在扫描目标目录: {target_root}")
    new_manifest = []
    all_files = []
    
    for root, dirs, files in os.walk(target_root):
        # 排除忽略目录
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for name in files:
            all_files.append(os.path.join(root, name))

    total = len(all_files)
    reused = 0
    hashed = 0

    for i, full_path in enumerate(all_files, 1):
        # 计算相对路径
        rel_path = os.path.relpath(full_path, target_root).replace(os.sep, '/')
        
        try:
            st = os.stat(full_path)
            f_size = st.st_size
            f_mtime = int(st.st_mtime)

            # 智能 MD5 缓存逻辑
            cache_item = old_cache.get(rel_path)
            if cache_item and cache_item.get('size_bytes') == f_size and cache_item.get('mtime') == f_mtime:
                f_md5 = cache_item.get('md5')
                reused += 1
            else:
                f_md5 = calculate_md5(full_path)
                hashed += 1

            new_manifest.append({
                "relative_path": rel_path,
                "size_bytes": f_size,
                "mtime": f_mtime,
                "md5": f_md5
            })

            # 打印进度 (确保 GUI 能捕获)
            if i % 50 == 0 or i == total:
                sys.stdout.write(f"\r[>] 进度: {i}/{total} ({reused}条缓存复用, {hashed}条新计算)")
                sys.stdout.flush()
        except: 
            pass

    # 5. 保存结果
    try:
        if not os.path.exists(save_dir):
            os.makedirs(save_dir, exist_ok=True)
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(new_manifest, f, indent=4, ensure_ascii=False)
        print(f"\n[√] 扫描完成。清单保存至: {manifest_path}")
    except Exception as e:
        print(f"\n[×] 保存清单失败: {e}")

if __name__ == "__main__":
    run_fast_scan()