#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pktview —— 单包解码查看器（NetCap 的「包解码」窗口）

布局：
  左边上：抓包文件里的包列表（可筛选 / 跳转）
  左边下：选中包的 16 进制（太长可折叠）
  右边  ：从链路层到头部的全部字段（关键字段高亮）

数据来源全部是 tshark：
  · 包列表  -T fields
  · 包的字段树 -T pdml（唯一能保留完整嵌套结构的输出格式）
  · 16 进制 -x
"""
import os
import re
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# 这些字段用高亮显示（一眼能抓到的关键信息）
KEY_FIELDS = {
    "eth.dst", "eth.src", "eth.type",
    "ip.src", "ip.dst", "ip.proto", "ip.ttl", "ip.len", "ip.id", "ip.flags",
    "ipv6.src", "ipv6.dst", "ipv6.nxt", "ipv6.hlim",
    "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack", "tcp.len",
    "tcp.flags", "tcp.flags.str", "tcp.window_size_value", "tcp.stream",
    "udp.srcport", "udp.dstport", "udp.length", "udp.stream",
    "tls.handshake.type", "tls.handshake.extensions_server_name",
    "tls.handshake.ciphersuite", "tls.record.version", "tls.record.content_type",
    "http.request.method", "http.request.uri", "http.host", "http.response.code",
    "http.user_agent", "dns.qry.name", "dns.flags.response",
    "icmp.type", "icmp.code", "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
}

# 这些协议层之间的分隔在显示时加粗
LAYER_ORDER = ["frame", "eth", "ethertype", "vlan", "ip", "ipv6", "tcp", "udp",
               "icmp", "arp", "tls", "http", "http2", "dns", "quic"]


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=300,
                          encoding="utf-8", errors="replace", creationflags=NO_WINDOW)


# ---------------------------------------------------------------- 数据获取

def load_packets(tshark: Path, path: Path, dfilter: str = "", limit: int = 8000):
    """返回 [(帧号, 相对时间, 源, 目的, 协议, 长度, 概要), ...]"""
    fields = ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
              "_ws.col.Protocol", "frame.len", "_ws.col.Info"]
    args = [str(tshark), "-r", str(path), "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    args += ["-E", "separator=\t", "-E", "occurrence=f", "-c", str(limit)]
    if dfilter.strip():
        args += ["-Y", dfilter.strip()]
    r = _run(args)
    rows = []
    for line in r.stdout.splitlines():
        parts = (line.split("\t") + [""] * 7)[:7]
        rows.append(parts)
    return rows, r.stderr.strip()


def load_detail(tshark: Path, path: Path, frame_no: int):
    """返回 (pdml_xml, stderr)"""
    args = [str(tshark), "-r", str(path), "-Y", f"frame.number=={frame_no}", "-T", "pdml"]
    r = _run(args)
    return r.stdout, r.stderr.strip()


def load_hex(tshark: Path, path: Path, frame_no: int):
    args = [str(tshark), "-r", str(path), "-Y", f"frame.number=={frame_no}", "-x"]
    r = _run(args)
    return r.stdout, r.stderr.strip()


# ---------------------------------------------------------------- 解析

def parse_pdml(xml_text):
    """把 PDML 拆成 [(depth, proto_name, proto_title, [(field_name, showname, show), ...]), ...]"""
    import xml.etree.ElementTree as ET

    layers = []
    if not xml_text.strip():
        return layers
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return layers
    pkt = root.find("packet")
    if pkt is None:
        return layers

    def walk(elem, depth):
        for child in elem:
            if child.tag != "proto":
                continue
            name = child.get("name", "")
            title = child.get("showname") or name
            fields = []
            for f in child.findall("field"):
                if (f.get("hide") or "").lower() == "yes":
                    continue
                fn = f.get("name", "")
                showname = f.get("showname") or fn
                show = f.get("show") or ""
                fields.append((fn, showname, show))
            layers.append((depth, name, title, fields))
            walk(child, depth + 1)

    walk(pkt, 0)
    return layers


def quick_summary(layers):
    """从字段里挑出速览信息"""
    vals = {}
    for _d, _n, _t, fields in layers:
        for fn, _sn, show in fields:
            vals.setdefault(fn, show)
    out = []
    if "eth.src" in vals or "eth.dst" in vals:
        out.append(("二层 MAC", f"{vals.get('eth.src','?')} → {vals.get('eth.dst','?')}"))
    if "ip.src" in vals or "ipv6.src" in vals:
        out.append(("三层 IP", f"{vals.get('ip.src') or vals.get('ipv6.src','?')} → "
                              f"{vals.get('ip.dst') or vals.get('ipv6.dst','?')}"))
        if "ip.ttl" in vals:
            out.append(("TTL / 协议号", f"{vals['ip.ttl']} / {vals.get('ip.proto','?')}"))
    if "tcp.srcport" in vals:
        out.append(("四层 TCP", f"{vals['tcp.srcport']} → {vals.get('tcp.dstport','?')}"))
        extra = []
        for k, label in (("tcp.seq", "seq"), ("tcp.ack", "ack"), ("tcp.len", "len"),
                         ("tcp.window_size_value", "win"), ("tcp.flags.str", "flags")):
            if k in vals:
                extra.append(f"{label}={vals[k]}")
        if extra:
            out.append(("TCP 细节", "  ".join(extra)))
        if "tcp.stream" in vals:
            out.append(("TCP 流号", vals["tcp.stream"]))
    if "udp.srcport" in vals:
        out.append(("四层 UDP", f"{vals['udp.srcport']} → {vals.get('udp.dstport','?')}"))
    if "tls.handshake.extensions_server_name" in vals:
        out.append(("TLS SNI", vals["tls.handshake.extensions_server_name"]))
    if "tls.handshake.type" in vals:
        out.append(("TLS 握手类型", vals["tls.handshake.type"]))
    if "http.request.method" in vals:
        out.append(("HTTP 请求", f"{vals['http.request.method']} {vals.get('http.request.uri','')}"))
    if "http.response.code" in vals:
        out.append(("HTTP 状态", vals["http.response.code"]))
    if "dns.qry.name" in vals:
        out.append(("DNS 查询", vals["dns.qry.name"]))
    return out


# ---------------------------------------------------------------- 窗口

def open_viewer(root, tshark: Path, path=None):
    """打开「包解码」窗口；path 可先给一个 pcap"""
    win = tk.Toplevel(root)
    win.title("包解码 · 单包详情")
    win.geometry("1320x820")
    try:
        win.transient(root)
    except Exception:
        pass

    state = {"path": Path(path) if path else None, "rows": [], "hex_all": [],
             "hex_expanded": False, "frame": None}

    # ---------------- 顶部工具条 ----------------
    bar = ttk.Frame(win); bar.pack(fill="x", padx=8, pady=6)
    ttk.Button(bar, text="打开 pcap…", command=lambda: pick_file()).pack(side="left", padx=3)
    path_var = tk.StringVar(value=str(state["path"]) if state["path"] else "")
    ttk.Entry(bar, textvariable=path_var, width=34).pack(side="left", padx=4)

    ttk.Label(bar, text="过滤:").pack(side="left", padx=(10, 2))
    filt_var = tk.StringVar()
    filt_entry = ttk.Entry(bar, textvariable=filt_var, width=20)
    filt_entry.pack(side="left", padx=2)
    ttk.Button(bar, text="应用", command=lambda: reload_list()).pack(side="left", padx=2)

    ttk.Label(bar, text="跳到帧:").pack(side="left", padx=(10, 2))
    jump_var = tk.StringVar()
    jump_entry = ttk.Entry(bar, textvariable=jump_var, width=8)
    jump_entry.pack(side="left", padx=2)

    frame_meta = tk.BooleanVar(value=False)
    ttk.Checkbutton(bar, text="显示帧元信息", variable=frame_meta,
                    command=lambda: re_render()).pack(side="left", padx=8)

    status_var = tk.StringVar(value="就绪")
    status_bar = ttk.Label(win, textvariable=status_var, foreground="#666", anchor="w")
    status_bar.pack(side="bottom", fill="x", padx=10, pady=(0, 4))

    # ---------------- 主体：左（列表+hex） / 右（详情） ----------------
    paned = ttk.PanedWindow(win, orient="horizontal")
    paned.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    left = ttk.Frame(paned)
    right = ttk.Frame(paned)
    paned.add(left, weight=3)
    paned.add(right, weight=4)

    vpaned = ttk.PanedWindow(left, orient="vertical")
    vpaned.pack(fill="both", expand=True)

    # 包列表
    list_frame = ttk.LabelFrame(vpaned, text="抓包信息（点一行看详情）")
    cols = ("no", "time", "src", "dst", "proto", "len", "info")
    tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=14)
    widths = {"no": 55, "time": 85, "src": 118, "dst": 118, "proto": 58, "len": 52, "info": 210}
    for c in cols:
        tree.heading(c, text={"no": "帧号", "time": "时间", "src": "源", "dst": "目的",
                              "proto": "协议", "len": "长度", "info": "概要"}[c])
        tree.column(c, width=widths[c], anchor="w", stretch=(c == "info"))
    tree.pack(fill="both", expand=True, padx=4, pady=4)

    # 16 进制
    hex_frame = ttk.LabelFrame(vpaned, text="16 进制")
    vpaned.add(list_frame, weight=3)
    vpaned.add(hex_frame, weight=2)
    # 初始分隔位置（窗口映射后再设，单位像素）
    def _init_sash():
        try:
            w = win.winfo_width()
            if w > 200:
                paned.sashpos(0, int(w * 0.50))
            h = win.winfo_height()
            if h > 200:
                vpaned.sashpos(0, int(h * 0.52))
        except Exception:
            pass
    win.after(250, _init_sash)

    hex_bar = ttk.Frame(hex_frame); hex_bar.pack(fill="x", padx=4, pady=(4, 0))
    hex_btn = ttk.Button(hex_bar, text="展开全部")
    hex_btn.pack(side="left")
    ttk.Label(hex_bar, text="（内容多时默认只显示前 24 行）",
              foreground="#888").pack(side="left", padx=8)

    hex_wrap = ttk.Frame(hex_frame)
    hex_wrap.pack(fill="both", expand=True, padx=4, pady=4)
    hex_text = tk.Text(hex_wrap, height=10, font=("Consolas", 9), wrap="none")
    hex_xsb = ttk.Scrollbar(hex_wrap, orient="horizontal", command=hex_text.xview)
    hex_ysb = ttk.Scrollbar(hex_wrap, orient="vertical", command=hex_text.yview)
    hex_text.configure(xscrollcommand=hex_xsb.set, yscrollcommand=hex_ysb.set)
    hex_text.grid(row=0, column=0, sticky="nsew")
    hex_ysb.grid(row=0, column=1, sticky="ns")
    hex_xsb.grid(row=1, column=0, sticky="ew")
    hex_wrap.rowconfigure(0, weight=1)
    hex_wrap.columnconfigure(0, weight=1)

    # 右侧详情
    detail_frame = ttk.LabelFrame(right, text="该包全部头信息（从链路层到应用层）")
    detail_frame.pack(fill="both", expand=True)
    detail_text = tk.Text(detail_frame, wrap="word", font=("Microsoft YaHei UI", 9), width=1)
    dsb = ttk.Scrollbar(detail_frame, orient="vertical", command=detail_text.yview)
    detail_text.configure(yscrollcommand=dsb.set)
    detail_text.pack(side="left", fill="both", expand=True, padx=(4, 0), pady=4)
    dsb.pack(side="right", fill="y", pady=4)

    # 颜色标签
    detail_text.tag_configure("h1", font=("Microsoft YaHei UI", 11, "bold"),
                              foreground="#0b4f8a", spacing1=6, spacing3=3)
    detail_text.tag_configure("layer", font=("Microsoft YaHei UI", 10, "bold"),
                              foreground="#175c2c", spacing1=5)
    detail_text.tag_configure("key", foreground="#b00020", font=("Microsoft YaHei UI", 9, "bold"))
    detail_text.tag_configure("field", foreground="#222")
    detail_text.tag_configure("dim", foreground="#777")
    hex_text.tag_configure("off", foreground="#888")
    hex_text.tag_configure("ascii", foreground="#0b6b6b")
    hex_text.tag_configure("hexb", foreground="#111")

    # ---------------- 逻辑 ----------------
    def set_status(s):
        win.after(0, lambda: status_var.set(s))

    def pick_file():
        f = filedialog.askopenfilename(filetypes=[("抓包文件", "*.pcapng *.pcap"), ("全部", "*.*")])
        if f:
            state["path"] = Path(f)
            path_var.set(f)
            reload_list()

    def reload_list():
        if not state["path"] or not state["path"].exists():
            messagebox.showerror("包解码", "请先选择 pcap 文件")
            return
        set_status("读取包列表…")
        tree.delete(*tree.get_children())

        def work():
            rows, err = load_packets(tshark, state["path"], filt_var.get())
            def show():
                state["rows"] = rows
                for r in rows:
                    tree.insert("", "end", values=(r[0], r[1][:12], r[2], r[3], r[4], r[5], r[6]))
                set_status(f"共 {len(rows)} 个包" + (f"（{err[:60]}）" if err else ""))
            win.after(0, show)
        threading.Thread(target=work, daemon=True).start()

    def show_packet(frame_no):
        state["frame"] = frame_no
        set_status(f"解析帧 {frame_no}…")

        def work():
            pdml, e1 = load_detail(tshark, state["path"], frame_no)
            hx, e2 = load_hex(tshark, state["path"], frame_no)
            layers = parse_pdml(pdml)
            summary = quick_summary(layers)
            state["layers"] = layers
            state["summary"] = summary
            state["hex_raw"] = hx
            win.after(0, lambda: render(frame_no, layers, summary, hx))
        threading.Thread(target=work, daemon=True).start()

    def re_render():
        if state.get("layers") is not None:
            render(state["frame"], state["layers"], state["summary"], state.get("hex_raw", ""))

    def render(frame_no, layers, summary, hex_dump):
        detail_text.configure(state="normal")
        detail_text.delete("1.0", "end")
        detail_text.insert("end", f"帧 {frame_no}\n", "h1")
        if summary:
            detail_text.insert("end", "关键信息速览\n", "layer")
            for label, value in summary:
                detail_text.insert("end", f"  {label}：", "key")
                detail_text.insert("end", f"{value}\n", "field")
            detail_text.insert("end", "\n")
        if not layers:
            detail_text.insert("end", "（没有解析到协议层，可能是非标准封装）\n", "dim")
        for depth, name, title, fields in layers:
            if name in ("geninfo", "frame") and not frame_meta.get():
                continue
            indent = "    " * depth
            detail_text.insert("end", f"{indent}▣ {name}", "layer")
            if title and title != name:
                detail_text.insert("end", f" — {title}", "dim")
            detail_text.insert("end", "\n")
            for fn, showname, show in fields:
                tag = "key" if fn in KEY_FIELDS else "field"
                detail_text.insert("end", f"{indent}   • ", "dim")
                detail_text.insert("end", showname + "\n", tag)
        detail_text.configure(state="disabled")

        # 十六进制
        state["hex_all"] = parse_hex(hex_dump)
        render_hex()

    def parse_hex(text):
        rows = []
        for line in text.splitlines():
            m = re.match(r"^([0-9a-fA-F]{4,8})\s{2}(.*)$", line)
            if not m:
                if line.strip():
                    rows.append(("", line, ""))
                continue
            off, rest = m.group(1), m.group(2)
            if len(rest) >= 50:
                hexpart, asciipart = rest[:48], rest[49:]
            else:
                hexpart, asciipart = rest, ""
            rows.append((off, hexpart.rstrip(), asciipart.rstrip()))
        return rows

    def render_hex():
        hex_text.configure(state="normal")
        hex_text.delete("1.0", "end")
        rows = state["hex_all"]
        show = rows if state["hex_expanded"] else rows[:24]
        for off, hexpart, ascii in show:
            hex_text.insert("end", f"{off}  ", "off")
            hex_text.insert("end", hexpart + "  ", "hexb")
            hex_text.insert("end", ascii + "\n", "ascii")
        if not state["hex_expanded"] and len(rows) > 24:
            hex_text.insert("end", f"… 还有 {len(rows)-24} 行，点「展开全部」查看\n", "off")
        hex_text.configure(state="disabled")

    def toggle_hex():
        state["hex_expanded"] = not state["hex_expanded"]
        hex_btn.config(text="折叠" if state["hex_expanded"] else "展开全部")
        render_hex()

    def on_select(_e=None):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        try:
            show_packet(int(vals[0]))
        except Exception:
            pass

    def do_jump():
        if not jump_var.get().strip().isdigit():
            return
        target = int(jump_var.get().strip())
        for item in tree.get_children():
            if int(tree.item(item, "values")[0]) == target:
                tree.selection_set(item)
                tree.see(item)
                show_packet(target)
                return
        messagebox.showinfo("包解码", f"列表里没有帧 {target}（可能被过滤条件筛掉了）")

    hex_btn.config(command=toggle_hex)
    tree.bind("<<TreeviewSelect>>", on_select)
    jump_entry.bind("<Return>", lambda _e: do_jump())
    filt_entry.bind("<Return>", lambda _e: reload_list())

    if state["path"] and Path(state["path"]).exists():
        reload_list()
    return win
