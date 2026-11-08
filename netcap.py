#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetCap —— Wireshark 快速抓包助手（中文界面）

解决两个问题：
1. 抓包时机不同步 → 一键开始/停止，停止后自动打开 Wireshark
2. 过滤条件难写   → 中文表单生成 BPF / 显示过滤器

依赖：本机已装 Wireshark（用它的 dumpcap.exe / tshark.exe / capinfos.exe）
用法：python netcap.py            打开界面
      python netcap.py --selftest 无界面自检（抓 3 秒 + 事后筛选）
"""
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- 基础配置

def _app_dir():
    """打包成 exe 后，配置/相对路径以 exe 所在目录为准"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


NO_WINDOW = 0x08000000 if __import__('os').name == 'nt' else 0   # CREATE_NO_WINDOW，避免弹黑框
APP_DIR = _app_dir()
CONFIG = APP_DIR / "netcap_config.json"
CAP_DIR = Path(r"D:\NetCap\captures")

# Wireshark 路径：可从配置覆盖
DEFAULT_WS = r"E:\wireshark"


def find_wireshark():
    """找 Wireshark 安装目录（含 dumpcap.exe）"""
    cfg = load_config()
    if cfg.get("wireshark_dir"):
        p = Path(cfg["wireshark_dir"])
        if (p / "dumpcap.exe").exists():
            return p
    cands = [
        DEFAULT_WS,
        r"C:\Program Files\Wireshark",
        r"C:\Program Files (x86)\Wireshark",
        r"D:\Wireshark", r"D:\Program Files\Wireshark",
        r"E:\Wireshark", r"E:\Program Files\Wireshark",
    ]
    for c in cands:
        if (Path(c) / "dumpcap.exe").exists():
            return Path(c)
    return None


def load_config():
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(d):
    try:
        CONFIG.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------- 过滤器构造

PROTO_CHOICES = ["任意", "TCP", "UDP", "TCP 或 UDP", "ICMP", "ARP", "DNS"]


def build_bpf(src_ip="", dst_ip="", src_port="", dst_port="", proto="任意", host="", both=True):
    """把中文表单拼成 BPF 抓包过滤器（抓包前，只能到 IP/端口/协议层）

    注意：BPF 是 libpcap 语法，抓包时还没解析 TLS，所以**无法**按 TLS 字段过滤。
    """
    parts = []
    if both:
        # 双向（推荐）：只写 host / port，两个方向都能抓到
        # 只写 dst port 会漏掉对端回包 —— 这是抓包最常见的坑
        ips = [x.strip() for x in (src_ip, dst_ip) if x.strip()]
        if len(ips) == 1:
            parts.append(f"host {ips[0]}")
        elif len(ips) == 2:
            parts.append(f"(host {ips[0]} or host {ips[1]})")

        ports = []
        for v in (src_port, dst_port):
            if v.strip():
                ports.append(int(v))
        if len(ports) == 1:
            parts.append(f"port {ports[0]}")
        elif len(ports) == 2:
            if ports[0] == ports[1]:
                parts.append(f"port {ports[0]}")
            else:
                parts.append(f"(port {ports[0]} or port {ports[1]})")
    else:
        if src_ip.strip():
            parts.append(f"src host {src_ip.strip()}")
        if dst_ip.strip():
            parts.append(f"dst host {dst_ip.strip()}")
        if src_port.strip() and dst_port.strip():
            parts.append(f"portrange {min(int(src_port), int(dst_port))}-{max(int(src_port), int(dst_port))}")
        elif src_port.strip():
            parts.append(f"src port {int(src_port)}")
        elif dst_port.strip():
            parts.append(f"dst port {int(dst_port)}")

    p = proto.strip()
    if p in ("TCP", "UDP"):
        parts.append(p.lower())
    elif p == "TCP 或 UDP":
        parts.append("tcp or udp")
    elif p in ("ICMP", "ARP"):
        parts.append(p.lower())
    elif p == "DNS":
        parts.append("port 53")

    bpf = " and ".join(parts) if parts else ""
    # 语法自检：能用 tcpdump 语法解析即可，这里只做括号平衡检查
    if bpf.count("(") != bpf.count(")"):
        raise ValueError("括号不匹配")
    return bpf


def build_display_filter(proto="任意", method="", status="", domain="",
                         tls_ver="", src_port="", dst_port="", ip="",
                         contains=""):
    """生成 Wireshark 显示过滤器（抓包后，能按 TLS / HTTP 字段筛）"""
    parts = []
    p = proto.strip()
    if p == "HTTP":
        parts.append("http")
    elif p == "HTTP/2":
        parts.append("http2")
    elif p == "HTTPS/TLS":
        parts.append("tls")
    elif p == "DNS":
        parts.append("dns")
    elif p == "TCP":
        parts.append("tcp")
    elif p == "UDP":
        parts.append("udp")

    if method.strip():
        m = method.strip().upper()
        parts.append(f'(http.request.method == "{m}" || http2.headers.method == "{m}")')
    if status.strip():
        parts.append(f'(http.response.code == {int(status)} || http2.headers.status == "{int(status)}")')
    if domain.strip():
        d = domain.strip().replace('"', '')
        # 域名可能出现在 4 个地方，少一个就会漏：
        #   http.host                  普通 HTTP 的 Host 头
        #   http.request.uri           CONNECT 代理请求（CONNECT www.akb48.co.jp:443 HTTP/1.1）
        #   tls.handshake.extensions_server_name   TLS 的 SNI
        #   http2.headers.authority    HTTP/2 的 :authority
        dom = []
        if p in ("任意", "HTTP", "TCP", "UDP"):
            dom.append(f'http.host contains "{d}"')
            dom.append(f'http.request.uri contains "{d}"')
        if p in ("任意", "HTTP/2"):
            dom.append(f'http2.headers.authority contains "{d}"')
        if p in ("任意", "HTTPS/TLS", "TCP", "UDP"):
            dom.append(f'tls.handshake.extensions_server_name contains "{d}"')
        if not dom:      # 协议选的是 DNS 之类，仍然给一个兜底
            dom.append(f'http.request.uri contains "{d}"')
        parts.append("(" + " || ".join(dom) + ")")
    if tls_ver.strip():
        v = tls_ver.strip()
        mapping = {"TLS1.0": "0x0301", "TLS1.1": "0x0302", "TLS1.2": "0x0303", "TLS1.3": "0x0304"}
        if v in mapping:
            parts.append(f"(tls.record.version == {mapping[v]} || tls.handshake.version == {mapping[v]})")
    if src_port.strip():
        parts.append(f"tcp.srcport == {int(src_port)}")
    if dst_port.strip():
        parts.append(f"tcp.dstport == {int(dst_port)}")
    if ip.strip():
        parts.append(f'ip.addr == {ip.strip()}')
    if contains.strip():
        c = contains.strip().replace('"', '')
        parts.append(f'(frame contains "{c}" || http.file_data contains "{c}")')

    return " && ".join(parts) if parts else ""


# ---------------------------------------------------------------- 网卡枚举

def list_interfaces(dumpcap: Path):
    """返回 [(序号, 设备名, 友好名)]"""
    try:
        out = subprocess.run([str(dumpcap), "-D"], capture_output=True, text=True,
                             timeout=30, encoding="utf-8", errors="replace", creationflags=NO_WINDOW).stdout
    except Exception:
        return []
    result = []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\.\s+(\S+)\s+\((.*)\)\s*$", line)
        if m:
            result.append((int(m.group(1)), m.group(2), m.group(3)))
    return result


# ---------------------------------------------------------------- 抓包引擎

class Capture:
    """用 dumpcap 抓包

    实现要点（2026-11-07 定稿）：
    1) dumpcap 用 `-w -` 把 pcapng 写到标准输出，**由本程序自己落盘**。
       这样绕开了 dumpcap 直接创建文件时遇到的 "Permission denied"（某些目录会踩到）。
    2) 本程序是 GUI 进程，没有控制台，CTRL_BREAK 送不到子进程，
       所以停止统一用 terminate；实测 pcapng 仍可被 Wireshark/capinfos 正常读取。
    3) 包数从 dumpcap 的 stderr 里解析 "Packets: N"。
    """

    def __init__(self, dumpcap: Path, iface_index, bpf: str, outfile: Path,
                 ring_mb: int = 0, on_status=None):
        self.dumpcap = dumpcap
        # 允许传单个索引或索引列表（多网卡同时抓）
        if isinstance(iface_index, (list, tuple)):
            self.ifaces = [int(x) for x in iface_index]
        else:
            self.ifaces = [int(iface_index)]
        self.iface = self.ifaces[0]
        self.bpf = bpf
        self.outfile = outfile
        self.ring_mb = ring_mb
        self.on_status = on_status or (lambda s: None)
        self.proc = None
        self.packets = 0
        self.log = []
        self._over = False
        self._fh = None
        self._stop = False

    def _open_output(self):
        """确定能写的输出文件：首选用户选的目录，不可写则依次降级"""
        candidates = [self.outfile]
        home = Path(os.environ.get("USERPROFILE", str(Path.home())))
        candidates.append(home / "NetCap" / "captures" / self.outfile.name)
        candidates.append(Path(os.environ.get("TEMP", str(home))) / "NetCap" / self.outfile.name)
        last_err = None
        for cand in candidates:
            try:
                cand.parent.mkdir(parents=True, exist_ok=True)
                fh = open(cand, "wb")
                if cand != self.outfile:
                    self.log.append(f"目标目录不可写，改用: {cand}")
                    self.on_status(f"原目录不可写，已改存到 {cand.parent}")
                self.outfile = cand
                return fh
            except Exception as e:
                last_err = e
                continue
        raise last_err if last_err else RuntimeError("无法创建输出文件")

    def start(self):
        args = [str(self.dumpcap)]
        for i in self.ifaces:
            args += ["-i", str(i)]
        if len(self.ifaces) > 1:
            args += ["-B", "32"]      # 多网卡同时抓，加大缓冲减少丢包（单位 MB）
        args += ["-w", "-"]
        if self.bpf:
            args += ["-f", self.bpf]
        self._fh = self._open_output()
        self.log.append("CMD: " + " ".join(args))

        flags = (subprocess.CREATE_NEW_PROCESS_GROUP | NO_WINDOW) if os.name == "nt" else 0
        self.proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, creationflags=flags,
        )
        self.log.append(f"PID: {self.proc.pid}")
        threading.Thread(target=self._pump_data, daemon=True).start()
        threading.Thread(target=self._pump_status, daemon=True).start()

    def _pump_data(self):
        """把 dumpcap 的标准输出原样写进文件"""
        try:
            while True:
                chunk = self.proc.stdout.read(65536)
                if not chunk:
                    break
                self._fh.write(chunk)
        except Exception as e:
            self.log.append(f"data pump error: {e!r}")
        finally:
            try:
                self._fh.flush()
            except Exception:
                pass

    def _pump_status(self):
        """解析 stderr 里的进度信息"""
        try:
            for raw in iter(self.proc.stderr.readline, b""):
                s = raw.decode("utf-8", "replace").strip()
                if not s:
                    continue
                self.log.append(s)
                for m in re.finditer(r"Packets:\s*(\d+)", s):
                    self.packets = int(m.group(1))
                self.on_status(f"抓包中… 已抓 {self.packets} 个包")
                if self.ring_mb and not self._over:
                    try:
                        size = self._fh.tell()
                    except Exception:
                        size = 0
                    if size > self.ring_mb * 1000 * 1000:
                        self._over = True
                        self.on_status(f"已达 {self.ring_mb} MB 上限，自动停止")
                        threading.Thread(target=self.stop, daemon=True).start()
        except Exception as e:
            self.log.append(f"status pump error: {e!r}")

    def stop(self):
        self._stop = True
        if not self.proc:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=6)
            self.log.append("stopped via terminate")
        except Exception as e:
            self.log.append(f"terminate failed: {e!r}")
            try:
                self.proc.kill()
                self.log.append("stopped via kill")
            except Exception:
                pass
        time.sleep(0.2)          # 让 data pump 把最后一块写完
        try:
            self._fh.flush()
            self._fh.close()
        except Exception:
            pass
        self.on_status(f"已停止，共 {self.packets} 个包")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def last_output(self, n=6):
        return " | ".join(self.log[-n:])

class MultiCapture:
    """多网卡抓包：每块网卡一个 dumpcap 进程、一份 BPF、一个文件，最后合并"""

    def __init__(self, dumpcap: Path, jobs, ring_mb: int = 0, on_status=None):
        """jobs: [(网卡索引, BPF字符串), ...]"""
        self.dumpcap = dumpcap
        self.jobs = list(jobs)
        self.ring_mb = ring_mb
        self.on_status = on_status or (lambda s: None)
        self.caps = []
        self.outfile = None
        self._merging = False

    def start(self, base: Path):
        self.base = base
        for idx, bpf in self.jobs:
            f = base.with_name(f"{base.stem}_if{idx}.pcapng")
            cap = Capture(self.dumpcap, [idx], bpf, f, self.ring_mb,
                          lambda s, n=idx: self.on_status(f"[网卡{n}] {s}"))
            cap.start()
            self.caps.append(cap)
        self.on_status(f"已启动 {len(self.caps)} 块网卡抓包")

    @property
    def packets(self):
        return sum(c.packets for c in self.caps)

    def alive(self):
        return any(c.alive() for c in self.caps)

    def stop(self):
        for c in self.caps:
            try:
                c.stop()
            except Exception:
                pass
        # 合并
        files = [c.outfile for c in self.caps if c.outfile and Path(c.outfile).exists()]
        if len(files) >= 2:
            merged = self.base.with_name(self.base.stem + "_merged.pcapng")
            mergecap = self.dumpcap.with_name("mergecap.exe")
            try:
                r = subprocess.run([str(mergecap), "-w", str(merged)] + [str(x) for x in files],
                                   capture_output=True, text=True, timeout=300,
                                   encoding="utf-8", errors="replace",
                                   creationflags=NO_WINDOW)
                if r.returncode == 0:
                    self.outfile = merged
                    self.on_status(f"已合并 {len(files)} 块网卡 → {merged.name}")
                else:
                    self.outfile = files[0]
                    self.on_status(f"合并失败：{r.stderr.strip()[:80]}（保留分文件）")
            except Exception as e:
                self.outfile = files[0]
                self.on_status(f"合并异常：{e!r}")
        elif files:
            self.outfile = files[0]
        self.on_status(f"已停止，共 {self.packets} 个包")

    def last_output(self, n=6):
        parts = []
        for c in self.caps:
            parts.append(c.last_output(n))
        return " | ".join(parts)


def count_packets(capinfos: Path, path: Path):
    """从 capinfos -c 的输出里取包数（输出形如 'Number of packets: 42'）"""
    try:
        out = subprocess.run([str(capinfos), "-c", str(path)], capture_output=True,
                             text=True, timeout=30, encoding="utf-8", errors="replace", creationflags=NO_WINDOW).stdout
        m = re.search(r"(\d+)\s*$", out.strip())
        if m:
            return int(m.group(1))
        m = re.search(r"Number of packets:\s*(\d+)", out)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


def tshark_preview(tshark: Path, path: Path, dfilter: str, limit=50):
    """按显示过滤器预览：时间 / 源 / 目的 / 协议 / 信息"""
    args = [str(tshark), "-r", str(path), "-T", "fields",
            "-e", "frame.number", "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info", "-E", "separator=\t", "-E", "occurrence=f"]
    if dfilter:
        args += ["-Y", dfilter]
    args += ["-c", str(limit)]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120,
                       encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    rows = []
    for line in r.stdout.splitlines():
        cols = line.split("\t")
        rows.append(cols)
    return rows, r.stderr.strip()


def tshark_export(tshark: Path, src: Path, dst: Path, dfilter: str):
    args = [str(tshark), "-r", str(src), "-Y", dfilter, "-w", str(dst)]
    r = subprocess.run(args, capture_output=True, text=True, timeout=300,
                       encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    return r.returncode == 0, r.stderr.strip()


def tshark_stream_ids(tshark: Path, path: Path, dfilter: str):
    """找出匹配包所属的 TCP / UDP 流编号"""
    args = [str(tshark), "-r", str(path), "-Y", dfilter, "-T", "fields",
            "-e", "tcp.stream", "-e", "udp.stream"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=300,
                       encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    tcp, udp = set(), set()
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if parts and parts[0].strip().isdigit():
            tcp.add(int(parts[0].strip()))
        if len(parts) > 1 and parts[1].strip().isdigit():
            udp.add(int(parts[1].strip()))
    return sorted(tcp), sorted(udp), r.stderr.strip()


def tshark_export_streams(tshark: Path, src: Path, dst: Path, dfilter: str):
    """把命中包所在的【整条流】全部导出

    两步：
      ① 用显示过滤器找出命中的包 → 取它们的 tcp.stream / udp.stream 编号
      ② 按 "tcp.stream in {1,2,3}" 再导出这些流的全部报文
    """
    tcp, udp, err = tshark_stream_ids(tshark, src, dfilter)
    if not tcp and not udp:
        return False, f"没有匹配到任何 TCP/UDP 流。{err}".strip()
    exprs = []
    if tcp:
        exprs.append("tcp.stream in {%s}" % ",".join(str(x) for x in tcp))
    if udp:
        exprs.append("udp.stream in {%s}" % ",".join(str(x) for x in udp))
    expr = " || ".join(exprs)
    args = [str(tshark), "-r", str(src), "-Y", expr, "-w", str(dst)]
    r = subprocess.run(args, capture_output=True, text=True, timeout=600,
                       encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    if r.returncode != 0:
        return False, r.stderr.strip()
    return True, f"TCP 流 {len(tcp)} 条 / UDP 流 {len(udp)} 条"


# ---------------------------------------------------------------- 自检（无界面）

def selftest():
    ws = find_wireshark()
    if not ws:
        print("❌ 找不到 Wireshark（dumpcap.exe）")
        return 1
    print(f"✅ Wireshark: {ws}")
    dumpcap, tshark, capinfos = ws / "dumpcap.exe", ws / "tshark.exe", ws / "capinfos.exe"
    ifaces = list_interfaces(dumpcap)
    print(f"✅ 网卡 {len(ifaces)} 个:")
    for idx, dev, name in ifaces:
        print(f"   {idx:>2}. {name}")
    target = next((i for i, d, n in ifaces if n.strip() == "WLAN"), None)
    if target is None:
        target = ifaces[0][0] if ifaces else None
    if target is None:
        print("❌ 没有可用网卡")
        return 1
    print(f"\n— 用网卡 {target} 抓 3 秒，BPF='tcp port 443' —")
    CAP_DIR.mkdir(parents=True, exist_ok=True)
    out = CAP_DIR / f"selftest_{datetime.now():%Y%m%d_%H%M%S}.pcapng"
    cap = Capture(dumpcap, target, "tcp port 443", out, on_status=print)
    cap.start()
    time.sleep(3)
    cap.stop()
    print(f"✅ 文件: {out}  ({out.stat().st_size:,} 字节)")
    n = count_packets(capinfos, out)
    print(f"✅ capinfos 统计: {n} 个包")

    print("\n— 测试显示过滤器生成 —")
    cases = [
        dict(proto="HTTPS/TLS", domain="example.com", tls_ver="TLS1.3"),
        dict(proto="HTTP", method="GET", status="200", domain="bilibili.com"),
        dict(proto="任意", dst_port="443", ip="1.1.1.1"),
        dict(proto="DNS"),
    ]
    for c in cases:
        print(f"   {c}  →  {build_display_filter(**c)}")

    print("\n— 事后筛选：只保留 tls 握手 —")
    dst = out.with_name(out.stem + "_tls.pcapng")
    ok, err = tshark_export(tshark, out, dst, "tls.handshake")
    print(f"   {'✅' if ok else '❌'} {dst}  {err[:200]}")
    if ok:
        print(f"   筛选后包数: {count_packets(capinfos, dst)}")

    print("\n— 预览前 5 行 —")
    rows, err2 = tshark_preview(tshark, out, "tls", limit=5)
    for r in rows:
        print("   ", "\t".join(r))
    print("\n自检完成 ✅")
    return 0


# ---------------------------------------------------------------- GUI

def list_capture_interfaces(tshark: Path, path: Path):
    """列出一个 pcapng 文件里出现过的网卡名（多网卡合并后会有多个）"""
    try:
        r = subprocess.run([str(tshark), "-r", str(path), "-T", "fields",
                            "-e", "frame.interface_name"], capture_output=True, text=True,
                           timeout=120, encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
        names = []
        for line in r.stdout.splitlines():
            n = line.strip()
            if n and n not in names:
                names.append(n)
        return names
    except Exception:
        return []


def postfilter_dialog(root, tshark: Path, capinfos: Path, src: Path, on_applied):
    """抓包后的引导式后置过滤

    单网卡：一个表单
    多网卡：左列表选网卡 + 右边分别配条件；导出可「合并」或「按网卡分开」
    """
    import tkinter as tk
    from tkinter import ttk, messagebox

    ifaces = list_capture_interfaces(tshark, src)
    multi = len(ifaces) > 1

    win = tk.Toplevel(root)
    win.title(f"后置过滤 · {src.name}")
    win.geometry("980x700" if multi else "720x520")
    win.transient(root)
    try:
        win.grab_set()
    except Exception:
        pass

    ttk.Label(win, text="按 TLS / HTTP 字段筛选（留空表示不加该条件）",
              foreground="#555").pack(anchor="w", padx=10, pady=(10, 4))

    # 每块网卡一份配置（单网卡时只有一份，键用 "all"）
    keys = ifaces if multi else ["all"]
    cfg = {k: dict(src_ip="", dst_ip="", src_port="", dst_port="", proto="任意",
                   method="", status="", domain="", tls_ver="", contains="",
                   manual="", whole=True) for k in keys}

    def cond_of(k):
        c = cfg[k]
        if c["manual"].strip():
            return c["manual"].strip()
        return build_display_filter(proto=c["proto"], method=c["method"], status=c["status"],
                                    domain=c["domain"], tls_ver=c["tls_ver"],
                                    dst_port=c["dst_port"], ip=c["dst_ip"],
                                    contains=c["contains"])

    def short(name):
        return name.split("\\")[-1]

    body = ttk.Frame(win); body.pack(fill="both", expand=True, padx=10)
    cur = {"k": keys[0]}

    if multi:
        left = ttk.LabelFrame(body, text="网卡（● = 已配置）")
        left.pack(side="left", fill="y", padx=(0, 10))
        lb = tk.Listbox(left, width=42, height=9, exportselection=False,
                        font=("Microsoft YaHei UI", 9))
        lb.pack(fill="y", padx=6, pady=6)
        right = ttk.LabelFrame(body, text="该网卡的筛选条件")
        right.pack(side="left", fill="both", expand=True)
    else:
        lb = None
        right = ttk.LabelFrame(body, text="筛选条件")
        right.pack(fill="both", expand=True)

    form = ttk.Frame(right); form.pack(fill="x", padx=10, pady=8)

    def lab_ent(r, c, label, width=16):
        ttk.Label(form, text=label).grid(row=r, column=c, sticky="e", padx=2, pady=3)
        e = ttk.Entry(form, width=width)
        e.grid(row=r, column=c + 1, sticky="w", padx=4, pady=3)
        return e

    proto_var = tk.StringVar(value="任意")
    ttk.Label(form, text="协议").grid(row=0, column=0, sticky="e", padx=2, pady=3)
    ttk.Combobox(form, textvariable=proto_var,
                 values=["任意", "HTTP", "HTTP/2", "HTTPS/TLS", "DNS", "TCP", "UDP"],
                 state="readonly", width=15).grid(row=0, column=1, sticky="w", padx=4, pady=3)

    e_method = lab_ent(0, 2, "HTTP 方法", 18)

    e_domain = lab_ent(1, 0, "域名/SNI 含", 20)
    tls_var = tk.StringVar(value="")
    ttk.Label(form, text="TLS 版本").grid(row=1, column=2, sticky="e", padx=2, pady=3)
    ttk.Combobox(form, textvariable=tls_var, values=["", "TLS1.2", "TLS1.3"],
                 state="readonly", width=10).grid(row=1, column=3, sticky="w", padx=4, pady=3)

    e_port = lab_ent(2, 0, "目的端口", 20)
    e_ip = lab_ent(2, 2, "IP 地址", 18)

    e_contains = lab_ent(3, 0, "内容包含", 20)
    e_status = lab_ent(3, 2, "状态码", 18)

    ln = ttk.Frame(right); ln.pack(fill="x", padx=10, pady=4)
    ttk.Label(ln, text="显示过滤器：").pack(side="left")
    df_var = tk.StringVar()
    e_df = ttk.Entry(ln, textvariable=df_var, width=64)
    e_df.pack(side="left", padx=4)

    whole_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(right, text="导出整条流（命中包所在 TCP/UDP 连接的全部报文）",
                    variable=whole_var).pack(anchor="w", padx=12, pady=(0, 2))

    state = {"loading": False}

    def widgets_to_cfg(k):
        cfg[k].update(dict(proto=proto_var.get(), method=e_method.get().strip(),
                           status=e_status.get().strip(), domain=e_domain.get().strip(),
                           tls_ver=tls_var.get(), dst_port=e_port.get().strip(),
                           dst_ip=e_ip.get().strip(), contains=e_contains.get().strip(),
                           whole=whole_var.get()))

    def cfg_to_widgets(k):
        state["loading"] = True
        c = cfg[k]
        proto_var.set(c["proto"]); e_method.delete(0, "end"); e_method.insert(0, c["method"])
        e_status.delete(0, "end"); e_status.insert(0, c["status"])
        e_domain.delete(0, "end"); e_domain.insert(0, c["domain"])
        tls_var.set(c["tls_ver"])
        e_port.delete(0, "end"); e_port.insert(0, c["dst_port"])
        e_ip.delete(0, "end"); e_ip.insert(0, c["dst_ip"])
        e_contains.delete(0, "end"); e_contains.insert(0, c["contains"])
        whole_var.set(c["whole"])
        df_var.set(c["manual"] or cond_of(k))
        state["loading"] = False

    def refresh_labels():
        if lb is None:
            return
        sel = lb.curselection(); keep = sel[0] if sel else None
        for n, k in enumerate(keys):
            mark = "  ●" if cond_of(k) else ""
            lb.delete(n); lb.insert(n, f"{n+1}. {short(k)}{mark}")
        if keep is not None and keep < lb.size():
            lb.selection_set(keep); lb.activate(keep)

    def refresh_df(*_a):
        if state["loading"]:
            return
        k = cur["k"]
        c = cfg[k]
        if not c["manual"]:
            state["loading"] = True
            try:
                df_var.set(build_display_filter(proto=proto_var.get(), method=e_method.get().strip(),
                                                status=e_status.get().strip(), domain=e_domain.get().strip(),
                                                tls_ver=tls_var.get(), dst_port=e_port.get().strip(),
                                                ip=e_ip.get().strip(), contains=e_contains.get().strip()))
            finally:
                state["loading"] = False
        widgets_to_cfg(k)
        refresh_labels()

    def on_df_edit(_e=None):
        if state["loading"]:
            return
        k = cur["k"]
        cfg[k]["manual"] = df_var.get().strip()
        refresh_labels()

    for w in (e_method, e_status, e_domain, e_port, e_ip, e_contains):
        w.bind("<KeyRelease>", refresh_df)
    proto_var.trace_add("write", lambda *a: refresh_df())
    tls_var.trace_add("write", lambda *a: refresh_df())
    whole_var.trace_add("write", lambda *a: refresh_df())
    e_df.bind("<KeyRelease>", on_df_edit)

    def on_select(_e=None):
        if lb is None:
            return
        sel = lb.curselection()
        if not sel:
            return
        k = keys[sel[0]]
        if k == cur["k"]:
            return
        widgets_to_cfg(cur["k"])
        cur["k"] = k
        cfg_to_widgets(k)
        refresh_df()

    if lb is not None:
        lb.bind("<<ListboxSelect>>", on_select)
        lb.selection_set(0)
    cfg_to_widgets(keys[0])
    refresh_df()

    # 导出方式（多网卡才有）
    mode = tk.StringVar(value="merge")
    if multi:
        mf = ttk.LabelFrame(win, text="导出方式")
        mf.pack(fill="x", padx=10, pady=(4, 0))
        ttk.Radiobutton(mf, text="合并成一个文件（按时间戳交错，推荐）", value="merge",
                        variable=mode).pack(anchor="w", padx=12, pady=2)
        ttk.Radiobutton(mf, text="每块网卡分别导出一个文件", value="split",
                        variable=mode).pack(anchor="w", padx=12, pady=2)

    preview = tk.Text(win, height=8 if multi else 9, font=("Consolas", 9))
    preview.pack(fill="both", expand=True, padx=10, pady=4)

    def iface_expr(k):
        c = cond_of(k)
        if k == "all":
            return c
        return f'frame.interface_name contains "{short(k)}" && ({c})' if c else \
               f'frame.interface_name contains "{short(k)}"'

    def do_preview():
        widgets_to_cfg(cur["k"])
        out = []
        total = 0
        for k in keys:
            ex = iface_expr(k)
            rows, err = tshark_preview(tshark, src, ex, limit=5000)
            total += len(rows)
            label = "全部" if k == "all" else short(k)
            out.append(f"━━━ {label} ━━━  命中 {len(rows)} 条")
            out.append(f"    条件: {cond_of(k) or '(无条件)'}")
            if err:
                out.append(f"    tshark: {err}")
            for r in rows[:6]:
                # r = [帧号, 相对时间, 源, 目的, 协议, 信息]
                r = (r + [""] * 6)[:6]
                info = r[5][:70]
                out.append(f"    {r[0]:>6}  {r[1]:>10}  {r[2]:>15} → {r[3]:<15} {r[4]:<8} {info}")
            if len(rows) > 6:
                out.append(f"    … 其余 {len(rows)-6} 条")
            out.append("")
        out.insert(0, f"合计命中 {total} 条（每块网卡最多列 6 条样例）\n")
        preview.configure(state="normal")
        preview.delete("1.0", "end")
        preview.insert("end", "\n".join(out) + "\n")
        preview.configure(state="disabled")

    def do_apply():
        widgets_to_cfg(cur["k"])
        base = src.with_name(src.stem + "_final.pcapng")
        if not multi:
            df = iface_expr("all")
            if not df:
                on_applied(src, count_packets(capinfos, src)); win.destroy(); return
            ok, msg = (tshark_export_streams(tshark, src, base, df) if whole_var.get()
                       else tshark_export(tshark, src, base, df))
            if not ok:
                messagebox.showerror("NetCap", f"筛选失败：\n{msg}"); return
            cnt = count_packets(capinfos, base)
            win.destroy(); on_applied(base, cnt); return

        if mode.get() == "merge":
            parts = []
            for k in keys:
                c = cond_of(k)
                if c:
                    parts.append(f'(frame.interface_name contains "{short(k)}" && ({c}))')
            if not parts:
                on_applied(src, count_packets(capinfos, src)); win.destroy(); return
            df = " || ".join(parts)
            ok, msg = (tshark_export_streams(tshark, src, base, df) if whole_var.get()
                       else tshark_export(tshark, src, base, df))
            if not ok:
                messagebox.showerror("NetCap", f"筛选失败：\n{msg}"); return
            cnt = count_packets(capinfos, base)
            win.destroy(); on_applied(base, cnt)
        else:
            outs = []
            for i, k in enumerate(keys):
                c = cond_of(k)
                if not c:
                    continue
                out = src.with_name(f"{src.stem}_final_if{i+1}.pcapng")
                ok, msg = (tshark_export_streams(tshark, src, out, iface_expr(k)) if whole_var.get()
                           else tshark_export(tshark, src, out, iface_expr(k)))
                if ok:
                    outs.append((out, count_packets(capinfos, out)))
            win.destroy()
            if not outs:
                messagebox.showwarning("NetCap", "没有导出任何文件（可能条件为空或没命中）")
                return
            messagebox.showinfo("NetCap", "已分别导出：\n" + "\n".join(
                f"{p.name}  ·  {n} 个包" for p, n in outs))
            on_applied(outs[0][0], outs[0][1])

    btns = ttk.Frame(win); btns.pack(fill="x", padx=10, pady=(0, 10))
    ttk.Button(btns, text="预览命中结果", command=do_preview).pack(side="left", padx=3)
    ttk.Button(btns, text="生成成品 pcap", command=do_apply).pack(side="left", padx=3)
    ttk.Button(btns, text="跳过（用原文件）",
               command=lambda: (win.destroy(), on_applied(src, count_packets(capinfos, src)))
               ).pack(side="right", padx=3)

    root.wait_window(win)


def per_iface_dialog(root, idxs, iface_names, default_bpf="", cap_dir=None):
    """多网卡：左边选网卡，右边用表单配过滤条件，底部直接开始抓包

    返回 [(idx, bpf), ...]；取消返回 None
    """
    import tkinter as tk
    from tkinter import ttk

    name_of = {}
    for line in iface_names:
        try:
            num, nm = line.split(".", 1)
            name_of[int(num)] = nm.strip()
        except Exception:
            continue

    cfg = {}
    for n, i in enumerate(idxs):
        cfg[i] = {
            "src_ip": "", "dst_ip": "", "src_port": "", "dst_port": "", "proto": "任意",
            "manual": bool(n == 0 and default_bpf),
            "expr": default_bpf if n == 0 else "",
        }

    def auto_expr(c):
        return build_bpf(c["src_ip"], c["dst_ip"], c["src_port"], c["dst_port"],
                         c["proto"], both=c.get("both", True))

    def bpf_of(i):
        c = cfg[i]
        return c["expr"].strip() if c["manual"] else auto_expr(c)

    win = tk.Toplevel(root)
    win.title("每块网卡单独设置过滤条件")
    win.geometry("880x470")
    win.transient(root)
    try:
        win.grab_set()
    except Exception:
        pass

    ttk.Label(win, text="左边选网卡，右边填条件；每块卡分别保存。配完点底部「开始抓包」。",
              foreground="#333").pack(anchor="w", padx=12, pady=(10, 6))

    body = ttk.Frame(win); body.pack(fill="both", expand=True, padx=12)

    left = ttk.LabelFrame(body, text="网卡（● = 已配置）")
    left.pack(side="left", fill="y", padx=(0, 10))
    lb = tk.Listbox(left, width=36, height=12, exportselection=False,
                    font=("Microsoft YaHei UI", 9))
    lb.pack(fill="y", padx=6, pady=6)

    right = ttk.LabelFrame(body, text="该网卡的过滤条件")
    right.pack(side="left", fill="both", expand=True)
    form = ttk.Frame(right); form.pack(fill="x", padx=10, pady=8)

    # 用 StringVar，输入时 trace 直接触发，比绑 <KeyRelease> 可靠
    v_sip, v_dip = tk.StringVar(), tk.StringVar()
    v_sport, v_dport = tk.StringVar(), tk.StringVar()

    def lab_ent(r, label, var, c=0, width=18):
        ttk.Label(form, text=label).grid(row=r, column=c, sticky="e", padx=(0, 4))
        ttk.Entry(form, textvariable=var, width=width).grid(row=r, column=c + 1,
                                                            sticky="w", padx=4, pady=4)

    lab_ent(0, "源 IP", v_sip)
    lab_ent(0, "目的 IP", v_dip, c=2)
    lab_ent(1, "源端口", v_sport, width=10)
    lab_ent(1, "目的端口", v_dport, c=2, width=10)

    ttk.Label(form, text="协议").grid(row=2, column=0, sticky="e", padx=(0, 4))
    proto_var = tk.StringVar(value="任意")
    ttk.Combobox(form, textvariable=proto_var, values=PROTO_CHOICES,
                 state="readonly", width=14).grid(row=2, column=1, sticky="w", padx=4, pady=4)

    both_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(form, text="双向（推荐，能抓到对端回包）", variable=both_var
                    ).grid(row=2, column=2, columnspan=2, sticky="w", padx=4, pady=4)

    quick = ttk.Frame(right); quick.pack(fill="x", padx=10, pady=(0, 6))
    ttk.Label(quick, text="快捷：").pack(side="left")

    line = ttk.Frame(right); line.pack(fill="x", padx=10, pady=4)
    ttk.Label(line, text="生成表达式：").pack(side="left")
    bpf_var = tk.StringVar()
    e_bpf = ttk.Entry(line, textvariable=bpf_var, width=46)
    e_bpf.pack(side="left", padx=4)

    ttk.Label(right, text="（表达式可直接改；一改就以你填的为准，清空或点快捷按钮恢复自动生成）",
              foreground="#888").pack(anchor="w", padx=12)

    state = {"cur": idxs[0] if idxs else None, "loading": False}

    def refresh_labels():
        sel = lb.curselection()
        keep = sel[0] if sel else None
        for n, i in enumerate(idxs):
            mark = "  ●" if bpf_of(i) else ""
            lb.delete(n)
            lb.insert(n, f"{i}. {name_of.get(i, '网卡')}{mark}")
        if keep is not None and keep < lb.size():
            lb.selection_set(keep)
            lb.activate(keep)

    def collect():
        return {"src_ip": v_sip.get().strip(), "dst_ip": v_dip.get().strip(),
                "src_port": v_sport.get().strip(), "dst_port": v_dport.get().strip(),
                "proto": proto_var.get()}

    def store(i):
        if i is None:
            return
        cfg[i].update(collect())
        cfg[i]["expr"] = bpf_var.get().strip() if cfg[i]["manual"] else ""

    def load(i):
        state["loading"] = True
        c = cfg[i]
        v_sip.set(c["src_ip"]); v_dip.set(c["dst_ip"])
        v_sport.set(c["src_port"]); v_dport.set(c["dst_port"])
        proto_var.set(c["proto"])
        bpf_var.set(c["expr"] if c["manual"] else auto_expr(c))
        state["loading"] = False

    def on_change(*_a):
        if state["loading"]:
            return
        i = state["cur"]
        if i is None:
            return
        c = cfg[i]
        if not c["manual"]:
            c["expr"] = ""
            # 关键：程序化写 bpf_var 会触发它的 trace，必须用 loading 挡掉，
            # 否则会被误判成"用户手改"，之后就再也不自动重算了
            state["loading"] = True
            try:
                try:
                    expr = build_bpf(v_sip.get().strip(), v_dip.get().strip(),
                                     v_sport.get().strip(), v_dport.get().strip(),
                                     proto_var.get())
                except Exception:
                    expr = "（端口请填数字）"
                bpf_var.set(expr)
            finally:
                state["loading"] = False
        store(i)
        refresh_labels()

    v_sip.trace_add("write", on_change)
    v_dip.trace_add("write", on_change)
    v_sport.trace_add("write", on_change)
    v_dport.trace_add("write", on_change)
    proto_var.trace_add("write", on_change)
    bpf_var.trace_add("write", lambda *a: on_expr_change())

    def on_expr_change():
        if state["loading"]:
            return
        i = state["cur"]
        if i is None:
            return
        cfg[i]["manual"] = True
        cfg[i]["expr"] = bpf_var.get().strip()
        refresh_labels()

    def on_select(_evt=None):
        sel = lb.curselection()
        if not sel:
            return
        new_i = idxs[sel[0]]
        if new_i == state["cur"]:
            return
        store(state["cur"])
        state["cur"] = new_i
        load(new_i)
        refresh_labels()

    def set_quick(sp="", dp="", pr="任意"):
        i = state["cur"]
        if i is not None:
            cfg[i]["manual"] = False
            cfg[i]["expr"] = ""
        state["loading"] = True
        v_sport.set(sp); v_dport.set(dp); proto_var.set(pr)
        state["loading"] = False
        if i is not None:
            store(i)
            bpf_var.set(auto_expr(cfg[i]))
        refresh_labels()

    lb.bind("<<ListboxSelect>>", on_select)

    ttk.Button(quick, text="全部流量", command=lambda: set_quick("", "", "任意")).pack(side="left", padx=2)
    ttk.Button(quick, text="443", command=lambda: set_quick("", "443", "任意")).pack(side="left", padx=2)
    ttk.Button(quick, text="DNS", command=lambda: set_quick("", "", "DNS")).pack(side="left", padx=2)
    ttk.Button(quick, text="80+443", command=lambda: set_quick("", "", "TCP")).pack(side="left", padx=2)
    ttk.Button(quick, text="清空", command=lambda: (set_quick("", "", "任意"),
                                                    v_sip.set(""), v_dip.set(""))).pack(side="left", padx=8)

    if idxs:
        lb.selection_set(0)
        load(idxs[0])
        refresh_labels()

    result = {}

    def do_start():
        store(state["cur"])
        jobs = [(j, bpf_of(j)) for j in idxs]
        if any("（" in e for _j, e in jobs):
            messagebox.showerror("NetCap", "有网卡的过滤条件不合法（端口需填数字），请检查后重试。")
            return
        result["jobs"] = jobs
        win.destroy()

    btns = ttk.Frame(win); btns.pack(fill="x", padx=12, pady=12)
    ttk.Button(btns, text="开始抓包", command=do_start).pack(side="left", padx=4)
    ttk.Button(btns, text="取消", command=win.destroy).pack(side="left", padx=4)

    root.wait_window(win)
    return result.get("jobs")


def tls_report(tshark: Path, path: Path, stream: int = -1):
    """解析 TLS 握手，输出可读文本（含扩展清单）"""
    import tlsdetail as td

    base = [str(tshark), "-r", str(path), "-T", "fields",
            "-e", "frame.number", "-e", "tcp.stream",
            "-e", "tls.handshake.type", "-e", "tls.handshake.version",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "tls.handshake.extensions_alpn_str",
            "-e", "tls.handshake.extensions.supported_version",
            "-e", "tls.handshake.ciphersuite",
            "-e", "tls.handshake.extensions_key_share_group",
            "-e", "tls.handshake.extensions_key_share_selected_group",
            "-e", "tls.handshake.extensions_supported_group",
            "-e", "tls.handshake.extension.type",
            "-E", "separator=|"]
    flt = "tls.handshake"
    if stream >= 0:
        flt += f" && tcp.stream=={stream}"
    r = subprocess.run(base + ["-Y", flt], capture_output=True, text=True,
                       timeout=180, encoding="utf-8", errors="replace",
                       creationflags=NO_WINDOW)
    if r.returncode != 0:
        return f"解析失败：{r.stderr.strip()}"

    out = []
    for line in r.stdout.splitlines():
        cols = line.split("|")
        if len(cols) < 12:
            continue
        (fno, st, hstype, ver, sni, alpn, supver, cipher, ks_group,
         ks_sel, groups, exts) = cols[:12]
        out.append(f"━━━ 帧 {fno} · 流 {st} · {td.name_hs(hstype)} ━━━")
        if ver:
            out.append(f"  记录版本       : {td.name_version(ver)}")
        if sni:
            out.append(f"  SNI            : {sni}")
        if alpn:
            out.append(f"  ALPN           : {alpn}")
        if supver:
            out.append("  支持/协商版本  : " + ", ".join(td.name_version(x) for x in supver.split(",")))
        if cipher:
            out.append("  密码套件       : " + ", ".join(td.name_cipher(x) for x in cipher.split(",")))
        if ks_group:
            out.append("  key_share 组   : " + ", ".join(td.name_group(x) for x in ks_group.split(",")))
        if ks_sel:
            out.append("  服务端选定组   : " + ", ".join(td.name_group(x) for x in ks_sel.split(",")))
        if groups:
            out.append("  supported_groups: " + ", ".join(td.name_group(x) for x in groups.split(",")))
        if exts:
            names = [td.name_ext(x) for x in exts.split(",")]
            out.append(f"  扩展 {len(names)} 个    : " + ", ".join(names))
        out.append("")
    if not out:
        return "这个文件里没有 TLS 握手（可能是 HTTP，或只有加密数据）"
    return "\n".join(out)


def tls_extension_detail(tshark: Path, path: Path, keylog=None, stream=-1):
    """把每个 TLS 扩展的内容摊开（用 PDML 输出，能拿到全部扩展）

    keylog: 浏览器导出的 SSLKEYLOGFILE（可选）；有它才能解密 TLS 1.3 的
            EncryptedExtensions / Certificate 等内容
    """
    import xml.etree.ElementTree as ET
    import tlsdetail as td

    flt = "tls.handshake"
    if stream >= 0:
        flt += f" && tcp.stream=={stream}"
    args = [str(tshark), "-r", str(path), "-Y", flt, "-T", "pdml"]
    if keylog:
        args += ["-o", f"tls.keylog_file:{keylog}"]
    r = subprocess.run(args, capture_output=True, text=True, timeout=300,
                       encoding="utf-8", errors="replace", creationflags=NO_WINDOW)
    if r.returncode != 0:
        return f"解析失败：{r.stderr.strip()}"
    if not (r.stdout or "").strip():
        return "没有找到 TLS 握手包"
    try:
        root = ET.fromstring(r.stdout)
    except Exception as e:
        return f"PDML 解析失败：{e!r}"

    lines = []
    packets = root.findall("packet")
    if not packets:
        return "没有找到 TLS 握手包"

    for pkt in packets:
        base = {}
        for fld in pkt.iter("field"):
            n = fld.get("name")
            if n in ("frame.number", "tcp.stream", "tls.handshake.type",
                     "tls.handshake.version", "tls.handshake.extensions_server_name"):
                base.setdefault(n, fld.get("show"))
        exts = [f for f in pkt.iter("field") if f.get("name") == "tls.handshake.extension"]
        hs = td.name_hs(base.get("tls.handshake.type"))
        lines.append(f"━━━ 帧 {base.get('frame.number','?')} · 流 {base.get('tcp.stream','?')} · {hs} ━━━")
        if base.get("tls.handshake.extensions_server_name"):
            lines.append(f"   SNI: {base['tls.handshake.extensions_server_name']}")
        if base.get("tls.handshake.version"):
            lines.append(f"   记录版本: {td.name_version(base['tls.handshake.version'])}")
        for i, ext in enumerate(exts, 1):
            child = {c.get("name"): c.get("show") for c in ext.findall("field")}
            t = child.get("tls.handshake.extension.type")
            ln = child.get("tls.handshake.extension.len")
            lines.append(f"   [{i:02d}] {td.name_ext(t)}   (type={t}, len={ln})")
            for c in ext.findall("field"):
                n = c.get("name", "")
                if n in ("tls.handshake.extension.type", "tls.handshake.extension.len"):
                    continue
                showname = (c.get("showname") or n).split(":")[-1].strip()
                val = c.get("show") or ""
                if len(val) > 100:
                    val = val[:97] + "…"
                if val:
                    lines.append(f"        · {showname} = {val}")
        if not exts:
            lines.append("   （没有可解析的扩展）")
        lines.append("")

    if not keylog:
        lines.append("提示：TLS 1.3 的 EncryptedExtensions / Certificate 是加密的，"
                     "指定 keylog 文件后才能看到里面的扩展内容。")
    return "\n".join(lines)


def capture_test(seconds=3):
    """无界面抓包测试（验证打包后能否正常调 dumpcap）"""
    log = []

    def w(s):
        log.append(str(s))
        try:
            (APP_DIR / "capture_test.log").write_text("\n".join(log), encoding="utf-8")
        except Exception:
            pass

    ws = find_wireshark()
    w(f"frozen={getattr(sys, 'frozen', False)}")
    w(f"APP_DIR={APP_DIR}")
    if not ws:
        w("找不到 Wireshark")
        return 1
    dumpcap, capinfos = ws / "dumpcap.exe", ws / "capinfos.exe"
    ifaces = list_interfaces(dumpcap)
    w("网卡: " + ", ".join(f"{i}.{n}" for i, d, n in ifaces))
    idx = next((i for i, d, n in ifaces if n.strip() == "WLAN"), None)
    if idx is None:
        idx = ifaces[0][0] if ifaces else None
    out = CAP_DIR / f"captest_{datetime.now():%Y%m%d_%H%M%S}.pcapng"
    CAP_DIR.mkdir(parents=True, exist_ok=True)
    cap = Capture(dumpcap, idx, "port 443", out, on_status=lambda s: w("STATUS: " + s))
    try:
        cap.start()
    except Exception as e:
        w(f"启动失败: {e!r}")
        return 1
    time.sleep(seconds)
    w(f"运行中: alive={cap.alive()} packets={cap.packets}")
    cap.stop()
    w(f"文件: exists={out.exists()} size={out.stat().st_size if out.exists() else 0}")
    w(f"capinfos 包数: {count_packets(capinfos, out)}")
    w("dumpcap 输出尾部: " + cap.last_output(10))
    w("完成")
    return 0


def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    ws = find_wireshark()
    if not ws:
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("NetCap", "找不到 Wireshark 的 dumpcap.exe。\n"
                                       r"请在设置里指定 Wireshark 安装目录（默认 E:\wireshark）。")
        return

    dumpcap, tshark, capinfos = ws / "dumpcap.exe", ws / "tshark.exe", ws / "capinfos.exe"
    cfg = load_config()
    CAP_DIR.mkdir(parents=True, exist_ok=True)

    root = tk.Tk()
    root.title("NetCap · 抓包助手")
    root.geometry("1000x760")
    try:
        ttk.Style().theme_use("vista")
    except Exception:
        pass

    # ---------- 顶部横幅（背景美化） ----------
    def _bg_dir():
        """背景图可能来自 exe 同级目录，也可能被打进 _internal（--add-data）"""
        cands = [APP_DIR / "backgrounds"]
        mp = getattr(sys, "_MEIPASS", None)
        if mp:
            cands.append(Path(mp) / "backgrounds")
        for c in cands:
            if c.exists():
                return c
        return cands[0]

    BG_DIR = _bg_dir()
    banner_canvas = tk.Canvas(root, height=110, highlightthickness=0, bg="#e9eef2")
    banner_canvas.pack(fill="x")
    _banner_img = {"obj": None}

    def apply_banner(name):
        banner_canvas.delete("all")
        p = (BG_DIR / name) if name else None
        if p and p.exists():
            try:
                img = tk.PhotoImage(file=str(p))
                _banner_img["obj"] = img        # 必须保留引用，否则图片被回收变白
                banner_canvas.create_image(0, 0, anchor="nw", image=img)
                banner_canvas.create_rectangle(0, 0, 1200, 110, fill="#000000",
                                               stipple="gray25", outline="")
            except Exception:
                pass
        banner_canvas.create_text(24, 32, anchor="w", text="NetCap · 抓包助手",
                                  fill="#ffffff", font=("Microsoft YaHei UI", 16, "bold"))
        banner_canvas.create_text(24, 62, anchor="w", text="抓包 · 过滤 · TLS 解析",
                                  fill="#dcdcdc", font=("Microsoft YaHei UI", 9))

    apply_banner(cfg.get("banner", "nc2.png"))

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=8)

    state = {"cap": None, "last_file": None, "final_file": None}

    # ---------------- 标签页 1：快速抓包 ----------------
    t1 = ttk.Frame(nb); nb.add(t1, text=" ① 快速抓包 ")
    frm = ttk.LabelFrame(t1, text="网卡"); frm.pack(fill="x", padx=8, pady=6)

    ifaces = list_interfaces(dumpcap)
    iface_names = [f"{i}. {n}" for i, d, n in ifaces]
    default_idx = next((k for k, (i, d, n) in enumerate(ifaces) if n.strip() == "WLAN"), 0)

    ttk.Label(frm, text="可多选（Ctrl / Shift 点选，同时抓多块网卡）",
              foreground="#555").pack(anchor="w", padx=6, pady=(6, 0))
    iface_list = tk.Listbox(frm, selectmode="extended", height=5, width=62,
                            exportselection=False, font=("Microsoft YaHei UI", 9))
    iface_list.pack(side="left", padx=6, pady=6)
    for n in iface_names:
        iface_list.insert("end", n)
    if iface_names:
        iface_list.selection_set(default_idx)
        iface_list.see(default_idx)
    sb = ttk.Scrollbar(frm, orient="vertical", command=iface_list.yview)
    sb.pack(side="left", fill="y", pady=6)
    iface_list.configure(yscrollcommand=sb.set)

    def selected_ifaces():
        return [int(iface_names[i].split(".")[0]) for i in iface_list.curselection()]

    # 过滤表单
    ff = ttk.LabelFrame(t1, text="抓包前过滤（BPF，只看 IP / 端口 / 协议）")
    ff.pack(fill="x", padx=8, pady=6)
    grid = ttk.Frame(ff); grid.pack(fill="x", padx=6, pady=6)

    def lab(r, c, text):
        ttk.Label(grid, text=text).grid(row=r, column=c, sticky="e", padx=4, pady=3)

    def ent(r, c, width=18):
        w = ttk.Entry(grid, width=width); w.grid(row=r, column=c, sticky="w", padx=4, pady=3); return w

    lab(0, 0, "源 IP");   src_ip = ent(0, 1)
    lab(0, 2, "目的 IP"); dst_ip = ent(0, 3)
    lab(1, 0, "源端口");  src_pt = ent(1, 1, 10)
    lab(1, 2, "目的端口"); dst_pt = ent(1, 3, 10)
    lab(2, 0, "协议");    proto_var = tk.StringVar(value="任意")
    ttk.Combobox(grid, textvariable=proto_var, values=PROTO_CHOICES, state="readonly",
                 width=15).grid(row=2, column=1, sticky="w", padx=4, pady=3)

    bpf_var = tk.StringVar()
    line = ttk.Frame(ff); line.pack(fill="x", padx=6, pady=(0, 6))
    ttk.Label(line, text="生成的表达式：").pack(side="left")
    ttk.Entry(line, textvariable=bpf_var, width=62).pack(side="left", padx=4)

    both_var = tk.BooleanVar(value=True)

    def refresh_bpf(*_):
        if bpf_manual.get():
            return
        try:
            bpf_var.set(build_bpf(src_ip.get(), dst_ip.get(), src_pt.get(), dst_pt.get(),
                                  proto_var.get(), both=both_var.get()))
        except Exception as e:
            bpf_var.set(f"（表达式有误：{e}）")

    bpf_manual = tk.BooleanVar(value=False)

    def field_changed(_=None):
        bpf_manual.set(False)
        refresh_bpf()

    for w in (src_ip, dst_ip, src_pt, dst_pt):
        w.bind("<KeyRelease>", field_changed)
    proto_var.trace_add("write", lambda *a: field_changed())

    quick = ttk.Frame(ff); quick.pack(fill="x", padx=6, pady=(0, 8))
    ttk.Label(quick, text="快捷：").pack(side="left")

    ttk.Checkbutton(quick, text="双向（推荐）", variable=both_var,
                    command=lambda: (bpf_manual.set(False), refresh_bpf())).pack(side="left", padx=(8, 4))

    def set_quick(sp="", dp="", pr="任意"):
        # src_pt / dst_pt 是 Entry 控件，不是 StringVar，必须用 delete/insert
        bpf_manual.set(False)
        src_pt.delete(0, "end"); src_pt.insert(0, sp)
        dst_pt.delete(0, "end"); dst_pt.insert(0, dp)
        proto_var.set(pr)
        refresh_bpf()

    def set_manual(expr):
        bpf_manual.set(True)
        bpf_var.set(expr)

    for txt, (sp, dp, pr) in {
        "全部流量": ("", "", "任意"),
        "只看 443": ("", "443", "任意"),
        "只看 DNS": ("", "", "DNS"),
    }.items():
        ttk.Button(quick, text=txt, command=lambda a=sp, b=dp, c=pr: set_quick(a, b, c)).pack(side="left", padx=3)
    ttk.Button(quick, text="80+443", command=lambda: set_manual("tcp port 80 or tcp port 443")).pack(side="left", padx=3)
    ttk.Button(quick, text="清空", command=lambda: (src_ip.delete(0, "end"), dst_ip.delete(0, "end"),
                                                    src_pt.delete(0, "end"), dst_pt.delete(0, "end"),
                                                    proto_var.set("任意"), set_quick())).pack(side="left", padx=12)

    # 保存位置
    sf = ttk.LabelFrame(t1, text="保存")
    sf.pack(fill="x", padx=8, pady=6)
    dir_var = tk.StringVar(value=cfg.get("save_dir", str(CAP_DIR)))
    ttk.Entry(sf, textvariable=dir_var, width=58).pack(side="left", padx=6, pady=6)
    ttk.Button(sf, text="选择…", command=lambda: dir_var.set(
        filedialog.askdirectory(initialdir=dir_var.get()) or dir_var.get())).pack(side="left")
    ttk.Label(sf, text="单文件上限(MB)：").pack(side="left", padx=(12, 2))
    ring_var = tk.StringVar(value=str(cfg.get("ring_mb", 200)))
    ttk.Entry(sf, textvariable=ring_var, width=6).pack(side="left")

    # 控制
    cf = ttk.Frame(t1); cf.pack(fill="x", padx=8, pady=10)
    status_var = tk.StringVar(value="就绪")
    btn_start = ttk.Button(cf, text="▶ 开始抓包 (F9)")
    btn_stop = ttk.Button(cf, text="■ 停止并保存 (F9)", state="disabled")
    btn_open = ttk.Button(cf, text="用 Wireshark 打开")
    btn_iface_cfg = ttk.Button(cf, text="⚙ 各网卡单独设置过滤条件…")
    btn_start.pack(side="left", padx=4)
    btn_stop.pack(side="left", padx=4)
    btn_open.pack(side="left", padx=4)
    btn_decode = ttk.Button(cf, text="包解码…")
    btn_decode.pack(side="left", padx=4)
    ttk.Label(cf, textvariable=status_var).pack(side="left", padx=12)

    def update_iface_btn(*_):
        """选了 2 块以上网卡时，才显示「单独设置」按钮"""
        n = len(iface_list.curselection())
        if n >= 2 and not btn_iface_cfg.winfo_ismapped():
            btn_iface_cfg.pack(side="left", padx=4, before=cf.winfo_children()[-1])
        elif n < 2 and btn_iface_cfg.winfo_ismapped():
            btn_iface_cfg.pack_forget()

    iface_list.bind("<<ListboxSelect>>", update_iface_btn, add="+")

    def open_iface_cfg():
        idxs = selected_ifaces()
        if len(idxs) < 2:
            messagebox.showinfo("NetCap", "先选中 2 块以上网卡"); return
        jobs = per_iface_dialog(root, idxs, iface_names, bpf_var.get().strip())
        if jobs:
            start_cap(jobs=jobs)

    btn_iface_cfg.config(command=open_iface_cfg)

    def on_status(s):
        root.after(0, lambda: status_var.set(s))

    def start_cap(*_, jobs=None):
        if state["cap"] and state["cap"].alive():
            return
        idxs = [i for i, _b in jobs] if jobs else selected_ifaces()
        if not idxs:
            messagebox.showerror("NetCap", "请选择网卡（可多选）"); return
        bpf = bpf_var.get().strip()
        if bpf.startswith("（"):
            messagebox.showerror("NetCap", "过滤表达式有误，请检查"); return
        d = Path(dir_var.get()); d.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            ring = int(ring_var.get())
        except Exception:
            ring = 0

        if len(idxs) == 1:
            out = d / f"netcap_{stamp}.pcapng"
            cap = Capture(dumpcap, idxs[0], bpf, out, ring, on_status)
            try:
                cap.start()
            except Exception as e:
                messagebox.showerror("NetCap", f"启动 dumpcap 失败：\n{e}"); return
            state["cap"] = cap
            state["last_file"] = cap.outfile

            def check_one():
                if cap.alive():
                    status_var.set(f"正在抓包（1 块网卡）→ {Path(cap.outfile).name}")
                else:
                    rc = cap.proc.poll() if cap.proc else "?"
                    detail = cap.last_output()
                    state["cap"] = None
                    btn_start.config(state="normal"); btn_stop.config(state="disabled")
                    status_var.set("启动失败，见提示")
                    messagebox.showerror("NetCap",
                                         f"dumpcap 没能开始抓包。\n\n退出码：{rc}\n输出：\n{detail}\n\n"
                                         f"常见原因：\n· 网卡索引变了\n· Npcap 服务没启动")
            root.after(800, check_one)
        else:
            # 多网卡：先让用户为每块网卡单独设过滤条件
            if jobs is None:
                jobs = per_iface_dialog(root, idxs, iface_names, bpf)
            if not jobs:
                return
            base = d / f"netcap_{stamp}.pcapng"
            cap = MultiCapture(dumpcap, jobs, ring, on_status)
            try:
                cap.start(base)
            except Exception as e:
                messagebox.showerror("NetCap", f"启动失败：\n{e}"); return
            state["cap"] = cap
            state["last_file"] = base

            def check_multi():
                if cap.alive():
                    status_var.set(f"正在抓包（{len(cap.caps)} 块网卡，各自过滤）…")
                else:
                    detail = cap.last_output()
                    state["cap"] = None
                    btn_start.config(state="normal"); btn_stop.config(state="disabled")
                    status_var.set("启动失败，见提示")
                    messagebox.showerror("NetCap", f"dumpcap 没能开始抓包。\n\n输出：\n{detail}")
            root.after(1200, check_multi)

        btn_start.config(state="disabled"); btn_stop.config(state="normal")
        status_var.set(f"正在启动抓包…（{len(idxs)} 块网卡）")
        save_config({"wireshark_dir": str(ws), "save_dir": str(d), "ring_mb": ring})

    def stop_cap(*_):
        cap = state.get("cap")
        if cap and cap.alive():
            cap.stop()
        btn_start.config(state="normal"); btn_stop.config(state="disabled")
        # 多网卡时停完会合并，最终文件以 cap.outfile 为准
        f = Path(cap.outfile) if (cap and getattr(cap, "outfile", None)) else state["last_file"]
        if f:
            state["last_file"] = f
        if not (f and f.exists()):
            detail = cap.last_output() if cap else "(没有启动过)"
            status_var.set("没有抓到文件")
            messagebox.showerror("NetCap",
                                 f"没有生成抓包文件。\n\ndumpcap 输出：\n{detail}\n\n"
                                 f"说明抓包进程根本没跑起来，或者被系统/杀软拦了。")
            return
        n = count_packets(capinfos, f)
        size_kb = f.stat().st_size / 1024
        state["final_file"] = None
        if n == 0:
            status_var.set(f"抓到了文件但 0 个包：{f.name}")
            messagebox.showwarning("NetCap",
                                   f"文件生成了，但一个包都没抓到。\n\n文件：{f.name}\n\n"
                                   f"常见原因：\n"
                                   f"· 过滤条件太严（比如端口不对、IP 填错）\n"
                                   f"· 抓的网卡不是流量实际经过的那块\n"
                                   f"  （用 Wi-Fi 时选 WLAN，用网线时选以太网）\n"
                                   f"· 抓包期间没有任何匹配流量")
            return
        status_var.set(f"已抓包：{f.name}  ·  {n} 个包  ·  {size_kb:.0f} KB")

        if not messagebox.askyesno(
                "抓包完成 ✅",
                f"已成功抓包！\n\n文件：{f.name}\n包数：{n} 个\n大小：{size_kb:.0f} KB\n\n"
                f"是否继续设置【后置过滤条件】？\n（按 TLS / HTTP 字段筛选，生成最终成品）"):
            # 不做后置过滤 → 直接问是否打开
            if messagebox.askyesno("NetCap", "现在用 Wireshark 打开这个文件吗？"):
                open_in_wireshark(f)
            return

        def on_applied(dst, cnt):
            state["final_file"] = dst
            status_var.set(f"成品质检：{dst.name}  ·  {cnt} 个包  ·  {dst.stat().st_size/1024:.0f} KB")
            if cnt == 0:
                messagebox.showwarning("NetCap", "筛选后 0 个包，条件可能太严了。\n成品文件仍已保存。")
            if messagebox.askyesno("NetCap", f"成品已生成：\n{dst.name}\n共 {cnt} 个包\n\n现在用 Wireshark 打开吗？"):
                open_in_wireshark(dst)

        postfilter_dialog(root, tshark, capinfos, f, on_applied)

    def open_in_wireshark(path: Path):
        try:
            subprocess.Popen([str(ws / "Wireshark.exe"), str(path)])
        except Exception as e:
            messagebox.showerror("NetCap", f"打开 Wireshark 失败：{e}")

    def open_current(*_):
        target = state.get("final_file") or state.get("last_file")
        if target and Path(target).exists():
            open_in_wireshark(Path(target))
        else:
            messagebox.showinfo("NetCap", "还没有抓包文件。先点「开始抓包」。")

    btn_start.config(command=start_cap)
    btn_stop.config(command=stop_cap)
    btn_open.config(command=open_current)

    def open_decode():
        target = state.get("final_file") or state.get("last_file")
        try:
            import pktview
            pktview.open_viewer(root, tshark, target)
        except Exception as e:
            messagebox.showerror("NetCap", f"打开包解码失败：{e!r}")

    btn_decode.config(command=open_decode)

    # 热键 F9 切换（bind_all 保证焦点在任何控件上都能触发；400ms 防抖避免连发）
    _last_hotkey = {"t": 0.0}

    def hotkey(_evt=None):
        now = time.time()
        if now - _last_hotkey["t"] < 0.4:
            return "break"
        _last_hotkey["t"] = now
        if state["cap"] and state["cap"].alive():
            stop_cap()
        else:
            start_cap()
        return "break"

    root.bind_all("<F9>", hotkey)

    # ---------------- 标签页 2：抓后筛选 ----------------
    t2 = ttk.Frame(nb); nb.add(t2, text=" ② 抓后筛选（可筛 TLS/HTTP 字段） ")
    pf = ttk.LabelFrame(t2, text="选择抓包文件")
    pf.pack(fill="x", padx=8, pady=6)
    file_var = tk.StringVar()
    ttk.Entry(pf, textvariable=file_var, width=58).pack(side="left", padx=6, pady=6)

    def pick_file():
        f = filedialog.askopenfilename(initialdir=dir_var.get(),
                                       filetypes=[("抓包文件", "*.pcapng *.pcap"), ("全部", "*.*")])
        if f:
            file_var.set(f)
    ttk.Button(pf, text="浏览…", command=pick_file).pack(side="left")

    df_box = ttk.LabelFrame(t2, text="筛选条件（中文）")
    df_box.pack(fill="x", padx=8, pady=6)
    g2 = ttk.Frame(df_box); g2.pack(fill="x", padx=6, pady=6)
    lab2 = lambda r, c, s: ttk.Label(g2, text=s).grid(row=r, column=c, sticky="e", padx=4, pady=3)
    ent2 = lambda r, c, w=16: (lambda ww: (ww.grid(row=r, column=c, sticky="w", padx=4, pady=3), ww)[1])(ttk.Entry(g2, width=w))

    lab2(0, 0, "协议"); pf_proto = tk.StringVar(value="任意")
    ttk.Combobox(g2, textvariable=pf_proto, values=["任意", "HTTP", "HTTP/2", "HTTPS/TLS", "DNS", "TCP", "UDP"],
                 state="readonly", width=13).grid(row=0, column=1, sticky="w", padx=4, pady=3)
    lab2(0, 2, "HTTP 方法"); e_method = ent2(0, 3)
    lab2(0, 4, "状态码");    e_status = ent2(0, 5, 10)
    lab2(1, 0, "域名/SNI 含"); e_domain = ent2(1, 1, 26)
    lab2(1, 2, "TLS 版本");  pf_tls = tk.StringVar(value="")
    ttk.Combobox(g2, textvariable=pf_tls, values=["", "TLS1.2", "TLS1.3"],
                 state="readonly", width=10).grid(row=1, column=3, sticky="w", padx=4, pady=3)
    lab2(1, 4, "端口");      e_port = ent2(1, 5, 10)
    lab2(2, 0, "IP 地址");   e_ip = ent2(2, 1)
    lab2(2, 2, "内容包含");  e_contains = ent2(2, 3, 26)

    dfilter_var = tk.StringVar()
    ln2 = ttk.Frame(df_box); ln2.pack(fill="x", padx=6, pady=(0, 6))
    ttk.Label(ln2, text="显示过滤器：").pack(side="left")
    ttk.Entry(ln2, textvariable=dfilter_var, width=64).pack(side="left", padx=4)

    def refresh_df(*_):
        dfilter_var.set(build_display_filter(
            proto=pf_proto.get(), method=e_method.get(), status=e_status.get(),
            domain=e_domain.get(), tls_ver=pf_tls.get(), dst_port=e_port.get(),
            ip=e_ip.get(), contains=e_contains.get()))
    for w in (e_method, e_status, e_domain, e_port, e_ip, e_contains):
        w.bind("<KeyRelease>", refresh_df)
    pf_proto.trace_add("write", refresh_df)
    pf_tls.trace_add("write", refresh_df)

    act = ttk.Frame(t2); act.pack(fill="x", padx=8, pady=8)
    preview_txt = tk.Text(t2, height=14, font=("Consolas", 9))
    preview_txt.pack(fill="both", expand=True, padx=8, pady=6)

    def do_preview():
        f = file_var.get()
        if not f or not Path(f).exists():
            messagebox.showerror("NetCap", "请先选择抓包文件"); return
        rows, err = tshark_preview(tshark, Path(f), dfilter_var.get(), limit=100)
        preview_txt.delete("1.0", "end")
        preview_txt.insert("end", f"# 过滤器: {dfilter_var.get() or '(无)'}\n")
        preview_txt.insert("end", f"# 命中 {len(rows)} 条（最多显示 100 条）\n")
        if err:
            preview_txt.insert("end", f"# tshark: {err}\n")
        for r in rows:
            preview_txt.insert("end", "  ".join(x for x in r[:6]) + "\n")

    def do_export():
        f = file_var.get()
        if not f or not Path(f).exists():
            messagebox.showerror("NetCap", "请先选择抓包文件"); return
        df = dfilter_var.get().strip()
        if not df:
            messagebox.showerror("NetCap", "筛选条件为空"); return
        dst = Path(f).with_name(Path(f).stem + "_filtered.pcapng")
        ok, err = tshark_export(tshark, Path(f), dst, df)
        if ok:
            n = count_packets(capinfos, dst)
            messagebox.showinfo("NetCap", f"已导出：\n{dst}\n共 {n} 个包")
            if messagebox.askyesno("NetCap", "用 Wireshark 打开筛选结果吗？"):
                subprocess.Popen([str(ws / "Wireshark.exe"), str(dst)])
        else:
            messagebox.showerror("NetCap", f"导出失败：\n{err}")

    ttk.Button(act, text="预览结果", command=do_preview).pack(side="left", padx=4)
    ttk.Button(act, text="导出为新 pcap 并打开", command=do_export).pack(side="left", padx=4)

    # ---------------- 标签页 3：TLS 解析 ----------------
    t3 = ttk.Frame(nb); nb.add(t3, text=" ③ TLS 解析（学习用） ")
    tls_top = ttk.LabelFrame(t3, text="选择抓包文件")
    tls_top.pack(fill="x", padx=8, pady=6)
    tls_file = tk.StringVar()
    ttk.Entry(tls_top, textvariable=tls_file, width=56).pack(side="left", padx=6, pady=6)

    def pick_tls_file():
        f = filedialog.askopenfilename(initialdir=dir_var.get(),
                                       filetypes=[("抓包文件", "*.pcapng *.pcap"), ("全部", "*.*")])
        if f:
            tls_file.set(f)
    ttk.Button(tls_top, text="浏览…", command=pick_tls_file).pack(side="left")

    opt = ttk.Frame(t3); opt.pack(fill="x", padx=8, pady=(0, 4))
    ttk.Label(opt, text="只看某个流（留空=全部）：").pack(side="left")
    tls_stream = tk.StringVar()
    ttk.Entry(opt, textvariable=tls_stream, width=6).pack(side="left", padx=4)

    key_frame = ttk.LabelFrame(t3, text="解密用 Keylog（可选，TLS 1.3 的加密扩展需要它）")
    key_frame.pack(fill="x", padx=8, pady=4)
    tls_keylog = tk.StringVar()
    ttk.Entry(key_frame, textvariable=tls_keylog, width=56).pack(side="left", padx=6, pady=6)

    def pick_keylog():
        f = filedialog.askopenfilename(filetypes=[("keylog", "*.log *.txt"), ("全部", "*.*")])
        if f:
            tls_keylog.set(f)
    ttk.Button(key_frame, text="浏览…", command=pick_keylog).pack(side="left")
    ttk.Label(t3, text="怎么拿到 keylog：设环境变量 SSLKEYLOGFILE=D:\\sslkeys.log 再重启浏览器，"
                       "访问网页后该文件就会写入会话密钥",
              foreground="#555").pack(anchor="w", padx=12)

    tls_out = tk.Text(t3, wrap="none", font=("Consolas", 9))
    tls_out.pack(fill="both", expand=True, padx=8, pady=4)

    def _tls_run(fn):
        f = tls_file.get() or str(state.get("final_file") or state.get("last_file") or "")
        if not f or not Path(f).exists():
            messagebox.showerror("NetCap", "请先选择抓包文件"); return
        try:
            sidx = int(tls_stream.get()) if tls_stream.get().strip() else -1
        except Exception:
            sidx = -1
        tls_out.delete("1.0", "end")
        tls_out.insert("end", "解析中…\n")
        root.update_idletasks()

        def work():
            try:
                txt = fn(Path(f), sidx)
            except Exception as e:
                txt = f"解析异常：{e!r}"

            def show():
                tls_out.delete("1.0", "end")
                tls_out.insert("end", txt)
            root.after(0, show)
        threading.Thread(target=work, daemon=True).start()

    def do_tls_report():
        _tls_run(lambda p, s: tls_report(tshark, p, s))

    def do_tls_ext():
        kl = tls_keylog.get().strip() or None
        _tls_run(lambda p, s: tls_extension_detail(tshark, p, kl, s))

    tls_btns = ttk.Frame(t3); tls_btns.pack(fill="x", padx=8, pady=(0, 8))
    ttk.Button(tls_btns, text="解析握手摘要", command=do_tls_report).pack(side="left", padx=3)
    ttk.Button(tls_btns, text="解析扩展明细", command=do_tls_ext).pack(side="left", padx=3)
    ttk.Button(tls_btns, text="用当前抓包文件",
               command=lambda: tls_file.set(str(state.get("final_file") or state.get("last_file") or ""))
               ).pack(side="left", padx=3)

    # ---------------- 标签页 4：帮助 ----------------
    t4 = ttk.Frame(nb); nb.add(t4, text=" 说明 ")
    help_txt = tk.Text(t4, wrap="word", font=("Microsoft YaHei UI", 10))
    help_txt.pack(fill="both", expand=True, padx=8, pady=8)
    help_txt.insert("end", HELP_TEXT)
    help_txt.configure(state="disabled")

    # 背景选择（放在说明页底部）
    bgbar = ttk.Frame(t4)
    bgbar.pack(fill="x", padx=8, pady=(0, 8))
    ttk.Label(bgbar, text="顶部背景：").pack(side="left")
    bg_labels = {"（无）": "", "nc1 · 淡雅水波": "nc1.png", "nc2 · 森林": "nc2.png",
                 "nc3 · 街景": "nc3.png", "nc4 · 仙人掌": "nc4.png"}
    cur_label = next((k for k, v in bg_labels.items() if v == cfg.get("banner", "nc2.png")), "nc2 · 森林")
    bg_var = tk.StringVar(value=cur_label)
    ttk.Combobox(bgbar, textvariable=bg_var, state="readonly", width=18,
                 values=list(bg_labels.keys())).pack(side="left", padx=4)

    def apply_bg_choice(*_a):
        name = bg_labels.get(bg_var.get(), "")
        apply_banner(name)
        c2 = load_config()
        c2["banner"] = name
        save_config(c2)

    ttk.Button(bgbar, text="应用", command=apply_bg_choice).pack(side="left", padx=4)
    ttk.Label(bgbar, text="（只影响顶部横幅，不喜欢就选「无」）",
              foreground="#888").pack(side="left", padx=8)

    root.mainloop()


HELP_TEXT = """NetCap 使用说明

【两种过滤，分工不同】

1）抓包前过滤（BPF）—— 在「① 快速抓包」页
   只能按 网卡 / IP / 端口 / 协议 过滤。
   原因：抓包那一刻还没解析报文，TLS、HTTP 字段都不存在，无法作为抓包条件。

2）抓后筛选（显示过滤器）—— 在「② 抓后筛选」页
   能按 TLS / HTTP 的详细字段筛选，例如：
     · 域名 / SNI 包含
     · TLS 版本（1.2 / 1.3）
     · HTTP 方法、状态码
     · 报文内容包含某段文字

【引导式完整流程（推荐）】
   ① 快速抓包页：目的端口填 443，点「开始抓包」
   ② 去网页操作（随时可按 F9 起停）
   ③ 回来点「停止并保存」→ 弹出「已成功抓包，是否继续设置后置过滤条件？」
        · 选「是」→ 中文表单填 TLS/HTTP 条件 → 预览 → 生成成品 pcap
        · 选「否」→ 直接问是否用 Wireshark 打开
   ④ 成品文件名 = 原名 + _final.pcapng（前后过滤都生效）
   ⑤ 点「用 Wireshark 打开」→ 直接打开成品

【常用表达式对照】
   tcp.port == 443                 只保留 443 端口
   tls.handshake.type == 1         只看 Client Hello
   tls.handshake.extensions_server_name contains "bilibili"
   http.request.method == "POST"
   http.response.code >= 400       只看错误响应
   dns.qry.name contains "example"
   ip.addr == 1.1.1.1

【注意】
   · 抓 HTTPS 的明文内容需要浏览器提供密钥（SSLKEYLOGFILE），
     本工具默认不启用；当前版本筛的是「握手/元数据」层，
     即：连了谁、什么协议、什么 SNI、什么状态码、包多大、耗时多久。
   · 抓包需要管理员权限? —— 本机实测 dumpcap 可直接抓，无需提权。
   · 密码等敏感信息不会出现在 pcap 里（TLS 加密），但元数据可能在。
"""


if __name__ == "__main__":
    # Windows 控制台可能是 GBK，强制 UTF-8 输出，避免 emoji 崩溃
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    def _log_crash(exc_type, exc, tb):
        """打包成 windowed exe 后没有控制台，崩溃写文件"""
        import traceback
        try:
            (APP_DIR / "netcap_error.log").write_text(
                "".join(traceback.format_exception(exc_type, exc, tb)), encoding="utf-8")
        except Exception:
            pass

    sys.excepthook = _log_crash
    try:
        if "--selftest" in sys.argv:
            sys.exit(selftest())
        if "--capture-test" in sys.argv:
            sys.exit(capture_test())
        if "--tls-test" in sys.argv:
            _ws = find_wireshark()
            _files = (sorted(CAP_DIR.glob("*.pcapng"), key=lambda p: p.stat().st_mtime)
                      if CAP_DIR.exists() else [])
            _txt = (tls_report(_ws / "tshark.exe", _files[-1])
                    if (_ws and _files) else "没有可解析的文件")
            try:
                (APP_DIR / "tls_test.log").write_text(_txt, encoding="utf-8")
            except Exception:
                pass
            print(_txt)
            sys.exit(0)
        run_gui()
    except SystemExit:
        raise
    except Exception:
        import traceback
        _log_crash(*sys.exc_info())
        raise
