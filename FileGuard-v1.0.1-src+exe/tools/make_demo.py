# -*- coding: utf-8 -*-
"""搭建演示环境：造一批模拟的共享文件、访问/删除记录与回收站数据，并启动服务。

仅用于展示 Web 界面效果，数据是模拟的（模拟一个公司共享盘被多台客户机访问）。

用法：
    python tools/make_demo.py            # 只造数据
    python tools/make_demo.py --serve    # 造数据并前台运行服务
"""
import datetime
import json
import os
import random
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import yamlconf  # noqa: E402

BASE = os.path.join(tempfile.gettempdir(), "fg_demo")
SHARE = os.path.join(BASE, "Share")
RECYCLE = os.path.join(BASE, "Recycle")
LOGS = os.path.join(BASE, "Logs")
CONF = os.path.join(BASE, "config.yaml")
PORT = 8899
REAL_TARGETS = []

USERS = ["CORP\\zhangsan", "CORP\\lisi", "CORP\\wangwu", "CORP\\zhaoliu",
         "CORP\\admin", "CORP\\finance01"]
IPS = ["192.168.1.23", "192.168.1.45", "192.168.1.78", "192.168.1.102",
       "10.0.8.12", "10.0.8.35"]

TREE = {
    "财务部": ["2026年Q3预算表.xlsx", "应收账款明细.xlsx", "费用报销单模板.docx",
             "税务申报材料.pdf"],
    "人事部": ["员工花名册.xlsx", "考勤统计_9月.xlsx", "劳动合同模板.docx"],
    "项目文档": ["需求规格说明书.docx", "项目排期表.xlsx", "验收报告.pdf",
              "架构设计图.png"],
    "技术资料": ["接口文档.md", "部署手册.docx", "故障处理流程.pdf"],
}

SIZES = {"xlsx": 24000, "docx": 58000, "pdf": 320000, "png": 180000, "md": 4200}


def build():
    shutil.rmtree(BASE, ignore_errors=True)
    for d in (SHARE, RECYCLE, LOGS):
        os.makedirs(d, exist_ok=True)

    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(yamlconf.dump({
            "monitor": {"paths": [SHARE], "seed_on_start": False, "log_changes": True},
            "protection": {"enabled": True, "strategy": "mirror",
                           "on_delete_action": "move_to_bin",
                           "actor_backfill_ms": 800, "debounce_seconds": 1.0},
            "recycle_bin": {"path": RECYCLE, "retention_days": 30, "max_size_gb": 10,
                            "auto_purge": True, "purge_interval_days": 1,
                            "purge_at_hour": 3,
                            "keep_versions_per_file": 5,
                            "remove_bin_copy_on_restore": True},
            "log": {"dir": LOGS, "max_size_mb": 50, "backup_count": 5},
            "audit": {"enabled": False, "auto_configure": False},
            "web": {"enabled": True, "host": "127.0.0.1", "port": PORT,
                    "username": "admin", "password": "",
                    "require_login": False,      # 演示环境直接进界面
                    "session_secret": "demo-secret", "page_size": 50},
            "app": {"max_gui_log_lines": 500},
        }, header="FileGuard 演示环境配置（YAML）"))

    os.environ["FILEGUARD_CONFIG"] = CONF
    from app.config import load_config
    from app.logger import LogManager
    cfg = load_config()
    logs = LogManager(cfg)
    from app.recycle import RecycleBin
    rb = RecycleBin(cfg)

    rnd = random.Random(20260930)
    files = []
    for folder, names in TREE.items():
        d = os.path.join(SHARE, folder)
        os.makedirs(d, exist_ok=True)
        for name in names:
            p = os.path.join(d, name)
            ext = name.rsplit(".", 1)[-1]
            with open(p, "wb") as f:
                f.write(b"DEMO CONTENT " * (SIZES.get(ext, 10000) // 13 + 1))
            files.append(p)
            rb.add_version(p, event="seed")

    # ---- 访问记录（跨 3 天，用于演示 access_yyyymmdd.log 按天分文件） ----
    now = time.time()
    ops = ["读取"] * 26 + ["写入"] * 5 + ["创建"] * 3 + ["重命名"] * 2
    rnd.shuffle(ops)
    step = int(2.5 * 86400 / max(1, len(ops) - 1))      # 最新一条到今天，最旧约 2.5 天前
    for i, op in enumerate(ops):
        p = rnd.choice(files)
        u = rnd.choice(USERS)
        ip = rnd.choice(IPS)
        off = (len(ops) - 1 - i) * step
        # 时间正序写入：日志页倒序读取，列表正好从新到旧
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - off))
        logs.access.write({
            "ts": ts + ".%03d+08:00" % rnd.randint(0, 999), "event": "access", "op": op,
            "path": p, "name": os.path.basename(p),
            "size": os.path.getsize(p), "size_text": _size(os.path.getsize(p)),
            "user": u, "ip": ip, "share": "\\\\*\\Share", "source": "share_audit",
            "event_id": 5145, "access_mask": "0x1",
            "access_list": "READ_CONTROL; SYNCHRONIZE; ReadData/ListDirectory; ReadAttributes",
            "port": str(rnd.randint(49152, 65535)),
        }, when=datetime.datetime.fromtimestamp(now - off))

    # ---- 删除记录（删除生效 + 内容移入回收站 files/） ----
    victims = rnd.sample(files, 6)
    VICTIM_SET = {os.path.normcase(p) for p in victims}
    del_recs = []

    def _ts(offset_sec):
        return (time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - offset_sec))
                + ".%03d+08:00" % rnd.randint(0, 999))

    # 一条目录删除 + 一条不可恢复（时间最早）
    del_recs.append({
        "ts": _ts(7200), "event": "delete", "op": "删除",
        "path": os.path.join(SHARE, "技术资料", "临时草稿.txt"),
        "name": "临时草稿.txt", "size": 812, "size_text": "812 B", "sha256": "",
        "version_id": None, "user": "CORP\\lisi", "ip": "", "client": "",
        "ip_source": "", "attribution": "unknown",
        "action": "move_to_bin", "bin_path": "", "source": "fs_event", "is_dir": False,
        "recoverable": False, "restored": False, "restore_path": "",
        "note": "删除前未形成存档，内容不可恢复",
    })
    del_recs.append({
        "ts": _ts(5400), "event": "delete", "op": "删除目录",
        "path": os.path.join(SHARE, "项目文档", "旧版本"),
        "name": "旧版本", "size": 3 * 24000, "size_text": _size(3 * 24000),
        "sha256": "", "version_id": None, "user": "CORP\\wangwu", "ip": "10.0.8.35",
        "client": "10.0.8.35", "ip_source": "user_cache",
        "attribution": "parent_dir", "source": "fs_event", "is_dir": True,
        "action": "move_to_bin", "bin_path": os.path.join(RECYCLE, "files"),
        "item_count": 3, "moved_count": 3, "recoverable": True, "restored": False,
        "restore_path": "",
    })

    for i, p in enumerate(victims):
        fsize = os.path.getsize(p)             # 删除前先取大小
        rec = rb.get_latest_active(p)
        u = rnd.choice(USERS)
        ip = rnd.choice(IPS)
        restored = i < 3                       # 前 3 条演示「已恢复」，其余停在回收站
        m = rb.mark_deleted(p, actor=u, actor_ip=ip,
                            materialize=True, action="move_to_bin")
        mid = m.get("id")
        bin_path = m.get("bin_path", "") or ""
        try:
            os.remove(p)                       # 模拟客户端删除（删除确实生效）
        except OSError:
            pass
        if restored and mid:
            rb.restore(mid)                    # 已还原：写回原路径，并按配置收回副本
        del_recs.append({
            "ts": _ts((len(victims) - 1 - i) * 900), "event": "delete", "op": "删除",
            "path": p, "name": os.path.basename(p), "size": fsize,
            "size_text": _size(fsize),
            "sha256": (rec or {}).get("sha256", ""), "version_id": (rec or {}).get("id"),
            "user": u, "ip": ip, "client": ip, "ip_source": "path_cache",
            "attribution": "exact", "source": "fs_event",
            "action": "move_to_bin",
            "bin_path": "" if restored else bin_path,   # 已还原的副本已被收回
            "is_dir": False, "recoverable": True, "restored": restored,
            "restore_path": p if restored else "",
        })

    # 按时间正序写入：日志页是倒序读取的，这样列表正好从新到旧
    for r in sorted(del_recs, key=lambda x: x["ts"]):
        logs.delete.write(r)

    st = rb.stats()
    print("演示环境已就绪")
    print("  监控目录 :", SHARE)
    print("  回收站   :", RECYCLE, "（blobs/ 去重存档 + files/ 可见副本）")
    print("  日志目录 :", LOGS, "（按天分文件：access_yyyymmdd.log / delete_yyyymmdd.log）")
    print("  日志文件 :", "、".join(
        os.path.basename(p) for p in logs.access.files() + logs.delete.files()))
    print(f"  自动清理 : 每 {cfg.purge_interval_days()} 天 "
          f"{cfg.purge_at_hour():02d}:00 清理一次"
          f"（保留 {cfg.get('recycle_bin.retention_days')} 天 / "
          f"上限 {cfg.get('recycle_bin.max_size_gb')} GB）")
    print("  配置文件 :", CONF)
    print(f"  回收站统计: 版本 {st['versions']} 个 / 已删除 {st['deleted']} 个 / "
          f"占用 {st['size_text']}"
          + (f" / 可见副本 {st['bin_files']} 个 {st.get('bin_size_text', '')}"
             if st.get("bin_files") else ""))
    print(f"  Web 地址 : http://127.0.0.1:{PORT}/   （演示环境未设密码）")
    rb.close()
    global REAL_TARGETS
    REAL_TARGETS = [p for p in files if os.path.normcase(p) not in VICTIM_SET][:2]
    return cfg


def _size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def serve(cfg):
    import queue
    from app.service import GuardService
    q = queue.Queue()
    svc = GuardService(cfg, ui_queue=q)

    import threading

    def drain():
        while True:
            r = q.get()
            print(f"[{r.get('ts')}] {r.get('text')}", flush=True)

    threading.Thread(target=drain, daemon=True).start()
    print(svc.start())

    def drive_real_ops():
        """真的删掉几个文件，让演示环境的计数与 delete.log 有真实数据。"""
        time.sleep(2.5)
        for p in REAL_TARGETS:
            if os.path.isfile(p):
                try:
                    os.remove(p)
                    print(f"[demo] 已删除（应移入回收站）：{p}", flush=True)
                except OSError as e:
                    print(f"[demo] 删除失败 {p}: {e}", flush=True)
                time.sleep(1.5)

    threading.Thread(target=drive_real_ops, daemon=True).start()
    print(f"\n>>> 打开 http://127.0.0.1:{PORT}/ 查看界面；Ctrl+C 停止")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        svc.stop()


if __name__ == "__main__":
    cfg = build()
    if "--serve" in sys.argv:
        serve(cfg)
