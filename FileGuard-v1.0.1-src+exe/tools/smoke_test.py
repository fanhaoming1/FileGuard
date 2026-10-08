# -*- coding: utf-8 -*-
"""FileGuard 端到端冒烟测试（不依赖 GUI，可无界面运行）。

覆盖：服务启停 / 镜像存档 / 删除后移入回收站（实体副本 + 索引）/ 删除动作三态
      （move_to_bin / restore / record）/ 日志按天分文件（access_yyyymmdd.log）/
      客户端 IP 字段 / 回收站手动恢复 / 目录删除批量入回收站 / 客户端 IP 归因 /
      系统托盘 / Web API + 鉴权 / 配置迁移。

用法： python tools/smoke_test.py
"""
import datetime
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import yamlconf  # noqa: E402
from app import logger as lgmod  # noqa: E402

BASE = os.path.join(tempfile.gettempdir(), "fg_smoke")
SHARE = os.path.join(BASE, "Share")
RECYCLE = os.path.join(BASE, "Recycle")
LOGS = os.path.join(BASE, "Logs")
CONF = os.path.join(BASE, "config.yaml")

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'[PASS]' if cond else '[FAIL]'} {name}{('  ' + str(extra)) if extra else ''}")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def build_config(port, action="move_to_bin", legacy_key=False):
    cfg = {
        "monitor": {"paths": [SHARE], "recursive": True, "log_changes": True,
                    "seed_on_start": True, "exclude_patterns": ["~$*", "*.tmp"]},
        "protection": {"enabled": True, "strategy": "mirror",
                       "on_delete_action": action,
                       "restore_conflict_policy": "rename", "debounce_seconds": 0.6,
                       "max_restore_per_10min": 10, "actor_backfill_ms": 0},
        "recycle_bin": {"path": RECYCLE, "retention_days": 30, "max_size_gb": 1,
                        "auto_purge": False, "keep_versions_per_file": 5},
        "log": {"dir": LOGS, "max_size_mb": 5, "backup_count": 3},
        "audit": {"enabled": False, "auto_configure": False},
        "web": {"enabled": True, "host": "127.0.0.1", "port": port,
                "username": "admin", "password": "test1234",
                "session_secret": "smoke-secret", "page_size": 20},
        "app": {"single_instance": False},
    }
    prot = cfg["protection"]
    if legacy_key:                       # 旧配置项应被自动忽略（升级兼容）
        prot.pop("on_delete_action", None)
        prot["auto_restore_on_delete"] = True
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(yamlconf.dump(cfg, header="FileGuard 冒烟测试用临时配置（YAML）"))


def read_jsonl(path):
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def log_files(kind):
    """按天分文件的日志切片列表（旧 -> 新），含升级前遗留的单文件。"""
    return lgmod.log_files(LOGS, f"{kind}_{{date}}.log")


def read_log(kind):
    """读取某类日志的全部记录（旧 -> 新），跨天 / 跨分片。"""
    out = []
    for p in log_files(kind):
        out.extend(read_jsonl(p))
    return out


class Client:
    """极简 Web 客户端，带 cookie 会话。"""

    def __init__(self, base):
        self.base = base
        self.cookie = ""

    def call(self, path, method="GET", body=None):
        url = self.base + urllib.parse.quote(path, safe="/?=&%")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json",
                                              "Cookie": self.cookie})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                sc = r.getheader("Set-Cookie")
                if sc:
                    self.cookie = sc.split(";")[0]
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))


def main():
    print("=" * 72)
    print("FileGuard 端到端冒烟测试")
    print("=" * 72)
    shutil.rmtree(BASE, ignore_errors=True)
    for d in (SHARE, RECYCLE, LOGS, os.path.join(SHARE, "sub")):
        os.makedirs(d, exist_ok=True)

    port = free_port()
    build_config(port)
    os.environ["FILEGUARD_CONFIG"] = CONF

    from app.config import load_config
    from app.service import GuardService

    cfg = load_config()

    # ---------- 1. 配置 ----------
    print("\n[1] 配置与校验")
    check("config.yaml 已生成", os.path.isfile(CONF), CONF)
    check("Web 密码已写入配置", cfg.get("web.password") == "test1234")
    v = cfg.validate()
    check("配置校验通过", v["ok"], v)

    # ---------- 2. 启动服务 ----------
    print("\n[2] 启动服务")
    ui_q = __import__("queue").Queue()
    svc = GuardService(cfg, ui_queue=ui_q)
    res = svc.start()
    check("服务启动成功", res.get("ok"), res.get("message"))
    wait_web(port)
    cli = Client(f"http://127.0.0.1:{port}")
    print("     Web 地址:", svc.web_url())

    # ---------- 3. 鉴权 ----------
    print("\n[3] Web 鉴权")
    sc, j = cli.call("/api/status")
    check("未登录访问被拒绝 (401)", sc == 401, sc)
    sc, j = cli.call("/api/login", "POST", {"username": "admin", "password": "wrong"})
    check("错误密码被拒绝 (401)", sc == 401, sc)
    sc, j = cli.call("/api/login", "POST", {"username": "admin", "password": "test1234"})
    check("正确密码登录成功", sc == 200 and j.get("ok"), j)
    sc, j = cli.call("/api/status")
    check("登录后可读取状态", sc == 200 and j["data"]["running"] is True)

    # ---------- 4. 镜像存档 + 修改 ----------
    print("\n[4] 镜像存档（mirror）")
    f1 = os.path.join(SHARE, "report.txt")
    write(f1, "v1: 原始内容\n")
    time.sleep(1.6)
    write(f1, "v2: 修改后的内容 —— 这是删除前的最新版本\n")
    time.sleep(2.2)
    st = svc.recycle.stats()
    check("文件已被存档", st["versions"] >= 2, st)
    head = open(f1, "r", encoding="utf-8").read()
    check("原文件内容正常", "v2" in head)

    # ---------- 5. 删除 -> 移入回收站（删除照常生效） ----------
    print("\n[5] 删除 -> 移入回收站（move_to_bin）")
    os.remove(f1)
    time.sleep(3.0)
    check("原路径文件已消失（客户端的删除正常生效）", not os.path.isfile(f1),
          "仍存在（不该出现）" if os.path.isfile(f1) else "已删除")
    binp = svc.recycle.bin_path_for(f1)
    check("内容被搬进回收站实体文件", os.path.isfile(binp), binp)
    if os.path.isfile(binp):
        bc = open(binp, "r", encoding="utf-8").read()
        check("回收站副本是删除前的最新内容", "v2" in bc, repr(bc[:40]))
        check("回收站副本保留原文件名", os.path.basename(binp) == os.path.basename(f1),
              os.path.basename(binp))

    dels = read_log("delete")
    rec = next((d for d in dels if d.get("path", "").endswith("report.txt")
                and d.get("source") == "fs_event" and not d.get("audit_only")), None)
    check("delete.log 记录了删除", rec is not None)
    if rec:
        check("记录 action=move_to_bin", rec.get("action") == "move_to_bin",
              rec.get("action"))
        check("记录标记为未还原且可恢复",
              rec.get("restored") is False and rec.get("recoverable") is True,
              {k: rec.get(k) for k in ("restored", "recoverable")})
        check("记录含回收站副本路径且与实际一致",
              rec.get("bin_path") == binp, rec.get("bin_path"))
        check("记录含版本号可再次恢复", bool(rec.get("version_id")), rec.get("version_id"))
        check("记录含大小", (rec.get("size") or 0) > 0, rec.get("size"))
        check("删除记录含客户端 IP 字段", "ip" in rec and "ip_source" in rec,
              {k: rec.get(k) for k in ("ip", "ip_source", "attribution")})

    acc = read_log("access")
    ops = {a.get("op") for a in acc}
    check("access.log 记录了文件变更", bool(acc) and ("创建" in ops or "修改" in ops), sorted(ops))
    check("访问记录含客户端 IP 字段", all("ip" in a for a in acc), len(acc))
    check("访问记录含 IP 来源字段", all("ip_source" in a for a in acc), len(acc))

    # ---------- 6. 回收站一键恢复 ----------
    print("\n[6] 回收站一键恢复（Web API）")
    sc, j = cli.call("/api/recycle?state=deleted&size=20")
    check("回收站 API 可用", sc == 200 and j["ok"], sc)
    items = j["data"]["items"] if sc == 200 else []
    target = next((i for i in items if i["orig_path"].endswith("report.txt")), None)
    check("回收站中存在该文件的已删除版本", target is not None, len(items))
    if target:
        check("回收站记录带 bin_path", bool(target.get("bin_path")), target.get("bin_path"))
        sc, j = cli.call("/api/recycle/restore", "POST", {"ids": [target["id"]]})
        d = j.get("data", {})
        check("一键恢复成功", d.get("ok") == 1, d)
        rp = (d.get("items") or [{}])[0].get("path", "")
        check("恢复的文件确实回到原路径", rp and os.path.isfile(rp), rp)
        check("恢复的是删除前的最新内容",
              "v2" in open(rp, encoding="utf-8").read() if rp and os.path.isfile(rp) else False)
        check("恢复后回收站实体副本已收回", not os.path.isfile(binp), binp)

        # 恢复后不应再出现在回收站（回收站只体现「已删除且可恢复」的数据）
        sc, j2 = cli.call("/api/recycle?state=deleted&size=200")
        del_items = j2["data"]["items"] if sc == 200 else []
        still = [i for i in del_items if i["id"] == target["id"]]
        check("已恢复的条目不再出现在回收站列表", not still, len(still))
        check("回收站条目均标注 in_bin/recoverable",
              all(i.get("in_bin") is True and "recoverable" in i for i in del_items),
              len(del_items))
        sc, j3 = cli.call("/api/recycle?state=restored&size=200")
        rst_items = j3["data"]["items"] if sc == 200 else []
        rst = [i for i in rst_items if i["id"] == target["id"]]
        check("可在「已还原」筛选中查到历史留痕", bool(rst), len(rst))
        st2 = j2["data"]["stats"] if sc == 200 else {}
        check("已删除存档口径 = 列表内的条目数（不含已恢复）",
              len(del_items) < 200 and st2.get("deleted") == len(del_items)
              and st2.get("restored", 0) >= 1, st2)

        # 恢复后再删除必须重新进回收站（回归：曾经因为恢复后没有 active 版本、
        # 且恢复的 8 秒抑制把删除事件一起吞掉，导致文件被彻底删除）
        check("恢复后重建了 active 镜像基线",
              bool(svc.recycle.get_latest_active(rp)), rp)
        os.remove(rp)
        time.sleep(3.5)
        sc, j4 = cli.call("/api/recycle?state=deleted&size=200")
        items4 = j4["data"]["items"] if sc == 200 else []
        again = [i for i in items4 if i["orig_path"].lower() == rp.lower()]
        check("【再次删除】重新出现在回收站", len(again) == 1, len(again))
        if again:
            a = again[0]
            check("【再次删除】标记为可恢复", a.get("recoverable") is True, a.get("recoverable"))
            check("【再次删除】实体副本已落回 files/",
                  bool(a.get("bin_path")) and os.path.isfile(a["bin_path"]), a.get("bin_path"))
        check("【再次删除】回收站不产生重复条目",
              len([i for i in items4 if i["orig_path"].lower() == rp.lower()]) == 1)

    # ---------- 7. 目录删除 -> 整个目录进回收站 ----------
    print("\n[7] 目录删除 -> 移入回收站（保留目录结构）")
    sub = os.path.join(SHARE, "sub")
    os.makedirs(sub, exist_ok=True)
    for i in range(3):
        write(os.path.join(sub, f"f{i}.txt"), f"dir-file-{i}\n")
    time.sleep(2.5)
    shutil.rmtree(sub, ignore_errors=True)
    time.sleep(3.0)
    check("目录本身已删除（未回填）", not os.path.isdir(sub))
    binsub = svc.recycle.bin_path_for(sub)
    got = sorted(os.listdir(binsub)) if os.path.isdir(binsub) else []
    check("回收站里保留了完整目录结构", got == ["f0.txt", "f1.txt", "f2.txt"], got)
    check("回收站副本内容正确",
          os.path.isfile(os.path.join(binsub, "f1.txt"))
          and "dir-file-1" in open(os.path.join(binsub, "f1.txt"), encoding="utf-8").read())
    dlog = read_log("delete")
    hit = [d for d in dlog if "\\sub\\" in d.get("path", "")
           or d.get("path", "").endswith("sub")]
    check("delete.log 记录了目录内的删除", len(hit) >= 1,
          f"命中 {len(hit)} 条：{[d.get('op') for d in hit][:5]}")
    check("目录内 3 个文件都有回收站副本",
          all(d.get("bin_path") for d in hit if not d.get("is_dir")) and len(hit) >= 4,
          [d.get("bin_path", "")[-24:] for d in hit])
    dirrec = next((d for d in hit if d.get("is_dir")), None)
    check("目录本身产生一条「删除目录」记录且计数正确",
          dirrec is not None and dirrec.get("item_count") == 3
          and dirrec.get("moved_count") == 3,
          dirrec and {k: dirrec.get(k) for k in ("op", "item_count", "moved_count")})
    check("目录记录带回收站目录位置",
          dirrec is not None and dirrec.get("bin_path") == binsub,
          dirrec and dirrec.get("bin_path"))

    # ---------- 7b. 目录删除分支：直接调用（确定性单元测试） ----------
    print("\n[7b] 目录删除分支单元测试（is_dir=True）")
    import queue as _q
    from app.logger import LogManager
    from app.recycle import RecycleBin
    from app.protector import Protector

    base2 = os.path.join(BASE, "unit")
    share2 = os.path.join(base2, "Share")
    os.makedirs(os.path.join(share2, "batch"), exist_ok=True)
    for i in range(4):
        write(os.path.join(share2, "batch", f"u{i}.dat"), f"unit-{i}\n" * 10)
    cfg_u = cfg
    cfg_u.set("monitor.paths", [share2])
    rb2 = RecycleBin(cfg_u)
    lg2 = LogManager(cfg_u)
    p2 = Protector(cfg_u, lg2, rb2)          # 不启动 observer，纯手工驱动
    archived = sum(1 for i in range(4)
                   if p2._archive(os.path.join(share2, "batch", f"u{i}.dat"), "create"))
    check("单元环境已归档 4 个文件", archived == 4, archived)
    shutil.rmtree(os.path.join(share2, "batch"), ignore_errors=True)
    p2.on_deleted(os.path.join(share2, "batch"), is_dir=True)
    binbatch = rb2.bin_path_for(os.path.join(share2, "batch"))
    inbin = sorted(os.listdir(binbatch)) if os.path.isdir(binbatch) else []
    check("目录删除后 4 个文件全部移入回收站", inbin == [f"u{i}.dat" for i in range(4)], inbin)
    check("原目录保持已删除（未被回填）", not os.path.isdir(os.path.join(share2, "batch")))
    drec = next((d for d in reversed(read_jsonl(lg2.delete.path))
                 if d.get("is_dir") and d.get("path", "").endswith("batch")), None)
    check("目录删除记录了 item_count / moved_count",
          drec is not None and drec.get("item_count") == 4,
          drec and {"item_count": drec.get("item_count"),
                    "moved_count": drec.get("moved_count")})
    cfg_u.set("monitor.paths", [SHARE])
    rb2.close()

    # ---------- 8. 其余删除动作：restore（旧行为）与 record ----------
    print("\n[8] 删除动作 restore：立即还原回原路径（旧行为，仍可配置）")
    svc.stop()
    time.sleep(0.6)
    build_config(port, action="restore")
    cfg2 = load_config()
    svc2 = GuardService(cfg2, ui_queue=ui_q)
    r2 = svc2.start()
    check("服务二次启动成功", r2.get("ok"), r2.get("message"))
    wait_web(port)
    f2 = os.path.join(SHARE, "keepme.txt")
    write(f2, "需要还原的内容\n")
    time.sleep(2.0)
    os.remove(f2)
    time.sleep(2.5)
    check("restore 模式下文件被自动还原回原路径", os.path.isfile(f2))
    dels2 = read_log("delete")
    rec2 = next((d for d in reversed(dels2)
                 if d.get("path", "").endswith("keepme.txt") and not d.get("audit_only")), None)
    check("delete.log 标记 action=restore 且已还原",
          rec2 is not None and rec2.get("action") == "restore"
          and rec2.get("restored") is True,
          rec2 and {"action": rec2.get("action"), "restored": rec2.get("restored")})

    print("\n[8b] 删除动作 record：只记录，不生成实体副本（靠 Web 恢复）")
    svc2.stop()
    time.sleep(0.6)
    build_config(port, action="record")
    cfg3 = load_config()
    svc3 = GuardService(cfg3, ui_queue=ui_q)
    r3 = svc3.start()
    check("服务三次启动成功", r3.get("ok"), r3.get("message"))
    wait_web(port)
    f3 = os.path.join(SHARE, "only_record.txt")
    write(f3, "只记录不落盘\n")
    time.sleep(2.0)
    os.remove(f3)
    time.sleep(2.5)
    check("文件已从目录消失", not os.path.isfile(f3))
    check("record 模式不生成回收站实体副本",
          not os.path.isfile(svc3.recycle.bin_path_for(f3)))
    rec3 = next((d for d in reversed(read_log("delete"))
                 if d.get("path", "").endswith("only_record.txt")
                 and not d.get("audit_only")), None)
    check("delete.log 标记 action=record", rec3 is not None
          and rec3.get("action") == "record", rec3 and rec3.get("action"))

    cli2 = Client(f"http://127.0.0.1:{port}")
    cli2.call("/api/login", "POST", {"username": "admin", "password": "test1234"})
    sc, j = cli2.call("/api/recycle?state=deleted&size=20")
    pend = [i for i in (j["data"]["items"] if sc == 200 else [])
            if i["orig_path"].endswith("only_record.txt")]
    check("回收站列出待恢复文件", bool(pend), len(pend))
    if pend:
        sc, j = cli2.call("/api/recycle/restore", "POST", {"ids": [pend[0]["id"]]})
        got = (j.get("data", {}).get("items") or [{}])[0].get("path", "")
        check("Web 一键恢复成功", os.path.isfile(got) and "只记录不落盘" in open(
            got, encoding="utf-8").read(), got)

    # ---------- 9. 日志接口 ----------
    print("\n[9] 日志查询与导出接口")
    sc, j = cli2.call("/api/logs/access?page=1&size=10")
    check("access 日志分页接口", sc == 200 and j["ok"] and j["data"]["items"], sc)
    sc, j = cli2.call("/api/logs/delete?page=1&size=10")
    check("delete 日志分页接口", sc == 200 and j["ok"] and j["data"]["items"], sc)
    sc, j = cli2.call("/api/logs/delete?q=report.txt")
    check("关键词过滤生效", sc == 200 and all(
        "report.txt" in (i.get("path") or "") for i in j["data"]["items"]),
        [i.get("path") for i in j["data"]["items"]][:3])
    sc, j = cli2.call("/api/logs/access?user=不存在的人")
    check("用户过滤生效", sc == 200 and j["data"]["items"] == [], j["data"]["items"])

    # ---------- 10. 配置接口（YAML） ----------
    print("\n[10] 配置读写接口（YAML）")
    sc, j = cli2.call("/api/config")
    check("读取配置成功", sc == 200 and "monitor" in j["data"]["config"], sc)
    check("接口附带 YAML 全文且带注释",
          sc == 200 and "#" in (j["data"].get("text") or ""),
          (j["data"].get("text") or "")[:30])
    newcfg = j["data"]["config"]
    newcfg["recycle_bin"]["retention_days"] = 7
    sc, j = cli2.call("/api/config", "POST", {"config": newcfg})
    check("保存配置成功", sc == 200 and j["data"]["validate"]["ok"], j.get("error"))
    check("配置已落盘为 YAML 且保留注释",
          yamlconf.load_file(CONF)["recycle_bin"]["retention_days"] == 7
          and "#" in open(CONF, encoding="utf-8").read())
    svc3.cfg.load()
    check("重新加载后生效", svc3.cfg.get("recycle_bin.retention_days") == 7)

    sc, j = cli2.call("/api/config/raw")
    ytxt = j["data"].get("text") or ""
    check("YAML 全文接口可用", sc == 200 and "monitor:" in ytxt, f"{len(ytxt)} 字符")
    sc, j = cli2.call("/api/config/raw", "POST",
                      {"text": ytxt.replace("retention_days: 7", "retention_days: 12")})
    check("按 YAML 文本保存成功",
          sc == 200 and j["data"]["validate"]["ok"]
          and svc3.cfg.get("recycle_bin.retention_days") == 12, j.get("error"))
    check("保存后注释自动补回", "#" in (j["data"].get("text") or ""))
    check("手写精简 YAML（无注释）也能加载",
          yamlconf.load_text(re.sub(r"(?m)^\s*#.*$", "", ytxt))
          ["web"]["port"] == port)
    check("路径含空格时被正确引用并读回",
          yamlconf.load_text(yamlconf.dump(
              {"monitor": {"paths": ["D:\\My Share\\子目录"]}}))
          ["monitor"]["paths"] == ["D:\\My Share\\子目录"])
    sc, j = cli2.call("/api/config/raw", "POST",
                      {"text": "monitor:\n\tpaths:\n\t  - x\n"})
    check("非法 YAML 被拒绝并给出行号",
          sc == 400 and "解析失败" in (j.get("error") or ""), j.get("error"))
    sc, j = cli2.call("/api/config/raw", "POST", {"text": "   "})
    check("空内容被拒绝", sc == 400, sc)
    sc, j = cli2.call("/api/config/raw", "POST", {"text": "- 1\n- 2\n"})
    check("顶层非映射被拒绝",
          sc == 400 and "映射" in (j.get("error") or ""), j.get("error"))

    # ---------- 11. 停止 ----------
    print("\n[11] 停止服务")
    r3 = svc3.stop()
    check("服务停止成功", r3.get("ok"), r3)
    time.sleep(0.5)
    check("Web 端口已释放", not port_open(port))
    check("监听已卸载", svc3.protector is not None and not svc3.protector.running)

    # ---------- 11b. 旧 config.json 自动迁移到 config.yaml ----------
    print("\n[11b] 旧 config.json 自动迁移")
    from app.config import Config
    mig = os.path.join(BASE, "migrate")
    shutil.rmtree(mig, ignore_errors=True)
    os.makedirs(mig, exist_ok=True)
    with open(os.path.join(mig, "config.json"), "w", encoding="utf-8") as f:
        json.dump({"recycle_bin": {"retention_days": 88}, "web": {"port": 1234}}, f)
    mcfg = Config(os.path.join(mig, "config.yaml")).load()
    check("自动生成 config.yaml", os.path.isfile(os.path.join(mig, "config.yaml")))
    check("旧配置的值被保留", mcfg.get("recycle_bin.retention_days") == 88,
          mcfg.get("recycle_bin.retention_days"))
    check("缺失项自动补默认值", mcfg.get("monitor.seed_on_start") is True)
    check("旧文件改名留存 .migrated",
          os.path.isfile(os.path.join(mig, "config.json.migrated")))
    check("给出迁移提示", "迁移" in mcfg.migration_note(), mcfg.migration_note())
    check("生成的 YAML 带注释",
          "#" in open(os.path.join(mig, "config.yaml"), encoding="utf-8").read())

    # ---------- 11c. YAML 损坏时的兜底 ----------
    print("\n[11c] 配置文件损坏时的兜底")
    bad = os.path.join(BASE, "badconf")
    shutil.rmtree(bad, ignore_errors=True)
    os.makedirs(bad, exist_ok=True)
    with open(os.path.join(bad, "config.yaml"), "w", encoding="utf-8") as f:
        f.write("monitor:\n  paths: [\n")     # 未闭合的 flow 序列
    bcfg = Config(os.path.join(bad, "config.yaml")).load()
    check("损坏配置回退默认值且服务可起", bcfg.get("monitor.recursive") is True)
    check("损坏文件被备份为 .broken",
          os.path.isfile(os.path.join(bad, "config.yaml.broken")))

    # ---------- 12. 回收站底层行为 ----------
    print("\n[12] 回收站：内容去重 / 保留期清理 / 容量上限")
    base3 = os.path.join(BASE, "unit2")
    share3 = os.path.join(base3, "Share")
    os.makedirs(share3, exist_ok=True)
    from app.recycle import RecycleBin
    cfg_r = load_config()
    cfg_r.set("monitor.paths", [share3])
    rb3 = RecycleBin(cfg_r)

    # 12.1 相同内容只存一份
    n_before = blob_count(rb3)
    for i in range(6):
        write(os.path.join(share3, f"dup{i}.txt"), "完全相同的内容\n" * 50)
    for i in range(6):
        rb3.add_version(os.path.join(share3, f"dup{i}.txt"), event="create")
    n_after = blob_count(rb3)
    check("相同内容只存一份 blob（去重生效）", n_after - n_before == 1,
          f"{n_before} -> {n_after}")
    check("6 个文件各自一条版本索引", rb3.query(path="dup", size=100)["total"] == 6,
          rb3.query(path="dup", size=100)["total"])
    st = rb3.stats()
    check("统计占用远小于原始总大小（6x）", st["size"] < 6 * 50 * 7,
          f"实际 {st['size']} 字节")

    # 12.2 每文件保留版本数上限
    f_ver = os.path.join(share3, "versions.txt")
    for v in range(8):
        write(f_ver, f"version-{v}\n" * (v + 1))
        rb3.add_version(f_ver, event="modify")
    keep_n = cfg_r.get("recycle_bin.keep_versions_per_file")
    got = rb3.query(path="versions.txt", size=100)["total"]
    check(f"每文件仅保留最近 {keep_n} 个版本", got == keep_n, got)

    # 12.3 保留期清理
    old = os.path.join(share3, "old.txt")
    write(old, "old content\n")
    rb3.add_version(old, event="create")
    rb3.mark_deleted(old)
    with rb3.conn:
        rb3.conn.execute("UPDATE versions SET stored_at=? WHERE orig_path=?",
                         (time.time() - 90 * 86400, old))
    removed = rb3.purge_expired()["removed"]
    check("超过保留期的已删除版本被清掉", removed >= 1, removed)

    # 12.4 容量上限（不会删掉每个路径的最新版本）
    cfg_r.set("recycle_bin.max_size_gb", 0.00001)      # 约 10KB
    cfg_r.set("recycle_bin.retention_days", 0)
    big_dir = os.path.join(base3, "big")
    os.makedirs(big_dir, exist_ok=True)
    for i in range(6):
        p = os.path.join(big_dir, f"big{i}.bin")
        with open(p, "wb") as f:
            f.write(bytes([i]) * 8000)
        rb3.add_version(p, event="create")
        if i < 4:
            rb3.mark_deleted(p)
    res = rb3.enforce_size()
    check("超容后触发清理", res["removed"] > 0, res)
    rows = rb3.query(size=500)["items"]
    newest = {}
    for r in rows:
        newest[r["orig_path"]] = max(newest.get(r["orig_path"], 0), r["id"])
    check("清理只保留各路径的最新版本（不会误删最新版本）",
          all(r["id"] == newest[r["orig_path"]] for r in rows),
          f"剩余 {len(rows)} 条")
    check("已删除的中间版本被优先清掉",
          all(r["state"] == "active" for r in rows),
          sorted({r["state"] for r in rows}))
    left = {r["orig_path"] for r in rows}
    check("每个路径至少保留最新版本",
          all(os.path.join(big_dir, f"big{i}.bin") in left for i in (4, 5)),
          sorted(os.path.basename(x) for x in left))
    cfg_r.set("recycle_bin.max_size_gb", 1)
    rb3.close()

    # ---------- 13. 客户端 IP 归因 ----------
    print("\n[13] 客户端 IP 归因（路径缓存 / 账号缓存 / 会话表）")
    from app.audit import ActorCache, SessionResolver, resolve_actor

    cache = ActorCache(ttl_seconds=600)
    p13 = os.path.join(SHARE, "sub", "x.txt")
    cache.remember(p13, "CORP\\zhangsan", "192.168.1.23", share="\\\\SRV\\Share")
    info = cache.lookup(p13)
    check("按路径命中账号与客户端 IP",
          info["user"] == "CORP\\zhangsan" and info["ip"] == "192.168.1.23"
          and info["attribution"] == "exact", info)
    check("IP 来源标记为路径缓存", info["ip_source"] == "path_cache", info)
    check("大小写 / 域名写法不同也能按账号命中",
          (cache.lookup_user("corp\\ZHANGSAN") or {}).get("ip") == "192.168.1.23")
    cache.remember(os.path.join(SHARE, "sub"), "CORP\\lisi", "10.0.8.12")
    deep = os.path.join(SHARE, "sub", "a", "b", "c.txt")
    hit = cache.lookup(deep)
    check("子目录沿用上级目录的访问者 IP",
          hit["ip"] == "10.0.8.12" and hit["attribution"] == "parent_dir", hit)
    check("完全不认识的路径返回 unknown 而非瞎猜",
          cache.lookup("D:\\Nope\\zzz.txt")["attribution"] in ("unknown", "recent"),
          cache.lookup("D:\\Nope\\zzz.txt")["attribution"])
    check("无采集器时回调安全返回空值", resolve_actor(None, p13)["ip"] == "")

    sr = SessionResolver(ttl_seconds=1)
    rows = sr.refresh()
    check("SMB 会话表可枚举（不抛异常）", isinstance(rows, dict), f"{len(rows)} 个账号")
    check("会话表查不到账号时返回空", sr.lookup("不存在\\nobody") == {})
    check("会话表快照含可用性 / 会话数",
          "available" in sr.snapshot() and "sessions" in sr.snapshot(),
          {k: sr.snapshot().get(k) for k in ("available", "sessions")})

    # ---------- 14. 系统托盘 ----------
    print("\n[14] 系统托盘（关闭窗口不停止服务的基础设施）")
    try:
        from app.tray import TrayIcon, tray_icon_path
        tray = TrayIcon("FileGuard 冒烟测试", icon_path=tray_icon_path())
        t_ok = tray.start(timeout=3)
        check("托盘图标可挂载", t_ok)
        check("托盘处于运行态", tray.running)
        tray.set_tooltip("FileGuard · 服务运行中")
        check("托盘动作队列初始为空", tray.poll() == [])
        tray.stop()
        check("托盘可正常卸载", not tray.running)
    except Exception as e:
        check("托盘图标可挂载", False, f"{type(e).__name__}: {e}")

    # ---------- 15. 旧配置项兼容 ----------
    print("\n[15] 旧配置项兼容（auto_restore_on_delete）")
    build_config(port, legacy_key=True)
    lcfg = load_config()
    check("旧键被剔除，不残留在配置里",
          "auto_restore_on_delete" not in lcfg.as_dict()["protection"],
          sorted(lcfg.as_dict()["protection"].keys()))
    check("升级后自动使用 move_to_bin", lcfg.delete_action() == "move_to_bin",
          lcfg.delete_action())
    lcfg.set("protection.on_delete_action", "bogus")
    check("非法删除动作被校验拦下",
          any("on_delete_action" in e for e in lcfg.validate()["errors"]),
          lcfg.validate()["errors"][:2])

    # ---------- 16. 日志按天分文件 ----------
    print("\n[16] 日志按天命名（access_yyyymmdd.log / delete_yyyymmdd.log）")
    from app.config import Config
    today = time.strftime("%Y%m%d")
    check("访问日志按天命名",
          os.path.isfile(os.path.join(LOGS, f"access_{today}.log")),
          f"access_{today}.log")
    check("删除日志按天命名",
          os.path.isfile(os.path.join(LOGS, f"delete_{today}.log")),
          f"delete_{today}.log")
    check("不再生成固定名 access.log / delete.log",
          not os.path.isfile(os.path.join(LOGS, "access.log"))
          and not os.path.isfile(os.path.join(LOGS, "delete.log")))
    check("日志记录跨文件读取完整",
          len(read_log("delete")) >= 4 and len(read_log("access")) >= 5,
          f"delete={len(read_log('delete'))} access={len(read_log('access'))}")

    d_unit = os.path.join(BASE, "logunit")
    shutil.rmtree(d_unit, ignore_errors=True)
    os.makedirs(d_unit, exist_ok=True)
    tpl = os.path.join(d_unit, "access_{date}.log")
    ulog = lgmod.JsonlLogger(tpl, max_size_mb=1, backup_count=2, retention_days=30)
    check("默认写入当天日期文件",
          os.path.basename(ulog.path) == f"access_{today}.log", ulog.path)
    ulog.write({"n": 0}, when=datetime.datetime.now() - datetime.timedelta(days=10))
    ulog.write({"n": 1}, when=datetime.datetime.now() - datetime.timedelta(days=1))
    ulog.write({"n": 2})
    names = [os.path.basename(p) for p in ulog.files()]
    check("跨天写入落到各自的日期文件", len(names) == 3, names)
    check("读取按时间从新到旧", [r["n"] for r in ulog.tail(10)] == [2, 1, 0],
          [r["n"] for r in ulog.tail(10)])
    check("日志统计给出文件数与天数",
          ulog.stat()["file_count"] == 3 and ulog.stat()["days"] == 3, ulog.stat())
    ulog.retention_days = 3                       # 只保留 3 天：10 天前的那份应被清掉
    check("按 retention_days 清掉过期日志",
          ulog.purge_old(force=True) == 1 and len(ulog.files()) == 2,
          [os.path.basename(p) for p in ulog.files()])
    for i in range(3000):                      # 单日超过 max_size_mb -> 当天内分片
        ulog.write({"n": 100 + i, "pad": "x" * 400})
    seg = [os.path.basename(p) for p in ulog.files()]
    check("单日超限后在当天内分片（_1.log）",
          any(re.match(rf"access_{today}_\d+\.log$", n) for n in seg), seg)
    check("分片后仍能读回最新记录", ulog.tail(1)[0]["n"] == 3099, ulog.tail(1)[0]["n"])
    check("跨天 + 跨分片读取严格从新到旧",
          [r["n"] for r in ulog.tail(3)] == [3099, 3098, 3097],
          [r["n"] for r in ulog.tail(3)])
    with open(os.path.join(d_unit, "access.log"), "a", encoding="utf-8") as f:
        f.write('{"n": -1, "legacy": true}\n')
    all_files = [os.path.basename(p) for p in lgmod.log_files(d_unit, tpl)]
    check("升级前遗留的 access.log 仍被读取（排在最旧）",
          all_files[0] == "access.log" and ulog.tail(9999)[-1].get("legacy") is True,
          all_files[:2])
    plain = lgmod.JsonlLogger(os.path.join(d_unit, "plain.log"), max_size_mb=1)
    plain.write({"a": 1})
    check("文件名不含 {date} 时回退为单文件模式",
          os.path.basename(plain.path) == "plain.log"
          and os.path.isfile(os.path.join(d_unit, "plain.log")))

    legacy_cfg = Config(os.path.join(BASE, "unit_logcfg", "config.yaml"))
    legacy_cfg.update({"log": {"dir": d_unit, "access_file": "access.log",
                               "delete_file": "delete.log"}})
    check("旧配置里的固定日志名自动升级为按天命名",
          legacy_cfg.get("log.access_file") == "access_{date}.log"
          and legacy_cfg.get("log.delete_file") == "delete_{date}.log",
          [legacy_cfg.get("log.access_file"), legacy_cfg.get("log.delete_file")])
    check("今天日志路径带日期",
          os.path.basename(legacy_cfg.today_log_path("delete")) == f"delete_{today}.log",
          legacy_cfg.today_log_path("delete"))

    # ---------- 17. 回收站自动清理周期 ----------
    print("\n[17] 回收站自动清理周期（按「天」配置）")
    from app.service import GuardService, next_purge_time
    pc = load_config()
    pc.set("monitor.paths", [SHARE])
    check("默认每 1 天清理一次、凌晨 3 点执行",
          pc.purge_interval_days() == 1 and pc.purge_at_hour() == 3,
          [pc.purge_interval_days(), pc.purge_at_hour()])
    base = datetime.datetime(2026, 9, 30, 12, 0, 0)
    check("每天一次：下次落在次日指定时点",
          next_purge_time(1, 3, base).strftime("%Y-%m-%d %H:%M") == "2026-10-01 03:00",
          next_purge_time(1, 3, base))
    check("当天时点还没到则落在当天",
          next_purge_time(1, 20, base).strftime("%Y-%m-%d %H:%M") == "2026-09-30 20:00",
          next_purge_time(1, 20, base))
    check("每 7 天一次：下次落在 7 天后",
          next_purge_time(7, 3, base).strftime("%Y-%m-%d") == "2026-10-07",
          next_purge_time(7, 3, base))
    check("每 30 天一次：下次落在 30 天后",
          next_purge_time(30, 2, base).strftime("%Y-%m-%d %H:%M") == "2026-10-30 02:00",
          next_purge_time(30, 2, base))
    check("purge_at_hour=-1 表示不指定时点（按当前时刻滚动）",
          next_purge_time(2, -1, base).strftime("%Y-%m-%d %H:%M") == "2026-10-02 12:00",
          next_purge_time(2, -1, base))
    pc.set("recycle_bin.purge_interval_days", 0)
    check("周期非法（0）被校验拦下",
          any("purge_interval_days" in e for e in pc.validate()["errors"]),
          pc.validate()["errors"][-1:])
    pc.set("recycle_bin.purge_interval_days", 1)
    pc.set("recycle_bin.purge_at_hour", 25)
    check("执行时点越界被校验拦下",
          any("purge_at_hour" in e for e in pc.validate()["errors"]),
          pc.validate()["errors"][-1:])
    pc.set("recycle_bin.purge_at_hour", 3)
    pc.update({"recycle_bin": {"purge_interval_minutes": 10, "purge_interval_days": 2}})
    check("旧的 purge_interval_minutes 被剔除，按天配置生效",
          "purge_interval_minutes" not in pc.as_dict()["recycle_bin"]
          and pc.purge_interval_days() == 2,
          sorted(pc.as_dict()["recycle_bin"].keys()))

    ps = GuardService(pc, ui_queue=ui_q)
    before = ps.purge_snapshot()
    check("未运行时不显示下次执行时间",
          before["schedule_text"] == "每 2 天 03:00 清理一次" and before["next_run"] == "",
          before)
    ps.recycle = RecycleBin(pc)
    ps._running = True
    ps._run_purge("测试")
    snap = ps.purge_snapshot()
    check("清理后记录上次执行结果与下次时间",
          bool(snap["last"].get("ts")) and bool(snap["next_run"]), snap)
    check("下次执行时间落在配置的时点",
          snap["next_run"].endswith(" 03:00"), snap["next_run"])
    ps.recycle.close()
    pc.set("recycle_bin.auto_purge", False)
    check("关闭自动清理时给出告警",
          any("auto_purge" in w for w in pc.validate()["warnings"]),
          pc.validate()["warnings"][-1:])
    pc.set("recycle_bin.auto_purge", True)

    # ---------- 18. 读取记录：去重 / 大小写还原 / 回环 / 4663 归因 ----------
    print("\n[18] 读取记录（去重、大小写还原、回环、4663 删除归因）")
    from app import audit as auditmod
    from app.config import Config

    class _StubLogs:
        def __init__(self):
            self.access, self.deletes = [], []

        def log_access(self, **kw):
            self.access.append(kw)

        def log_delete(self, **kw):
            self.deletes.append(kw)

    _rid = [900000]

    def _xml5145(mask, rel, ip="192.168.100.50", user="zhangsan",
                 when="2026-09-30T05:00:00.000Z"):
        _rid[0] += 1
        return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                f"<System><EventID>5145</EventID><EventRecordID>{_rid[0]}</EventRecordID>"
                f"<TimeCreated SystemTime='{when}'/></System><EventData>"
                f"<Data Name='SubjectUserName'>{user}</Data>"
                "<Data Name='SubjectDomainName'>CORP</Data>"
                f"<Data Name='IpAddress'>{ip}</Data>"
                "<Data Name='IpPort'>50000</Data>"
                "<Data Name='ShareName'>\\\\*\\Share</Data>"
                f"<Data Name='ShareLocalPath'>\\??\\{SHARE}</Data>"
                f"<Data Name='RelativeTargetName'>{rel}</Data>"
                f"<Data Name='AccessMask'>{mask}</Data>"
                "<Data Name='AccessList'>%%1537</Data>"
                "<Data Name='ObjectType'>File</Data></EventData></Event>")

    def _xml4663(mask, name, user="zhangsan", when="2026-09-30T05:00:00.000Z",
                 pid="0x4", proc=""):
        _rid[0] += 1
        return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                f"<System><EventID>4663</EventID><EventRecordID>{_rid[0]}</EventRecordID>"
                f"<TimeCreated SystemTime='{when}'/></System><EventData>"
                f"<Data Name='SubjectUserName'>{user}</Data>"
                "<Data Name='SubjectDomainName'>CORP</Data>"
                f"<Data Name='ObjectName'>{os.path.join(SHARE, name)}</Data>"
                f"<Data Name='ProcessName'>{proc}</Data>"
                f"<Data Name='ProcessId'>{pid}</Data>"
                f"<Data Name='AccessMask'>{mask}</Data>"
                "<Data Name='ObjectType'>File</Data></EventData></Event>")

    rcfg = Config(os.path.join(BASE, "audit_read.yaml"))
    rcfg.set("monitor.paths", [SHARE])
    rcfg.set("log.dir", LOGS)
    rcfg.set("audit.enabled", True)
    rcfg.set("audit.dedup_seconds", 2)
    rcfg.set("audit.skip_loopback", False)
    rcfg.set("audit.read_extensions", [])
    stub = _StubLogs()
    col = auditmod.AuditCollector(rcfg, stub)

    # 磁盘真实名字是全小写，SMB 会先按大写探测 —— 记录里的路径必须是真实名字
    real = os.path.join(SHARE, "ReadCase.txt")
    write(real, "read-case\n")
    for mask in ("0x100080", "0x120089", "0x100080"):
        col._handle_xml(_xml5145(mask, "READCASE.TXT"))
    check("同一次读取的多条 5145 只记一条", len(stub.access) == 1, len(stub.access))
    check("记录里的路径用磁盘真实大小写",
          stub.access and os.path.basename(stub.access[0]["path"]) == "ReadCase.txt",
          stub.access and stub.access[0]["path"])
    check("读取记录带 op/来源/客户端 IP",
          stub.access and stub.access[0]["op"] == "读取"
          and stub.access[0]["ip_source"] == "share_audit"
          and stub.access[0]["ip"] == "192.168.100.50",
          stub.access and {k: stub.access[0].get(k)
                           for k in ("op", "ip_source", "ip")})

    # 事件时间相隔 5 秒 -> 是两次独立读取，都要留下
    stub.access.clear()
    col._handle_xml(_xml5145("0x120089", "ReadCase.txt",
                             when="2026-09-30T05:00:10.000Z"))
    col._handle_xml(_xml5145("0x120089", "ReadCase.txt",
                             when="2026-09-30T05:00:15.000Z"))
    check("相隔超过去重窗口的两次读取各记一条", len(stub.access) == 2, len(stub.access))

    # 关掉去重 -> 原始事件全记
    col._dedup_ttl = 0
    stub.access.clear()
    for mask in ("0x100080", "0x120089"):
        col._handle_xml(_xml5145(mask, "ReadCase.txt"))
    check("dedup_seconds=0 时不去重", len(stub.access) == 2, len(stub.access))
    col._dedup_ttl = 2

    # 回环访问
    stub.access.clear()
    col._handle_xml(_xml5145("0x120089", "ReadCase.txt", ip="127.0.0.1",
                             when="2026-09-30T05:01:00.000Z"))
    check("回环访问默认也会记录（标注为本机）",
          len(stub.access) == 1
          and stub.access[0]["ip_source"] == "share_audit_loopback",
          stub.access and stub.access[0].get("ip_source"))
    check("回环访问不污染删除归因缓存",
          not col.actors.lookup_delete(os.path.join(SHARE, "ReadCase.txt")))
    col2 = auditmod.AuditCollector(rcfg, stub2 := _StubLogs())
    col2._skip_loopback = True
    col2._handle_xml(_xml5145("0x120089", "ReadCase.txt", ip="127.0.0.1"))
    check("skip_loopback=true 时回环访问被丢弃", not stub2.access)

    # 4663 删除 -> 回灌删除事件表（本机删除靠它显示操作者）
    col._handle_xml(_xml4663("0x10000", "ReadCase.txt"))
    hit = col.actors.lookup_delete(os.path.join(SHARE, "ReadCase.txt"))
    check("4663 删除事件回灌删除归因表",
          hit.get("user") == "CORP\\zhangsan" and hit.get("attribution") == "delete_event",
          hit)
    check("本机删除（内核 SMB 进程）不会被进程过滤丢掉",
          col._skip_process("", "0x4") is False
          and col._skip_process("System", "0x4") is False)
    check("自身进程产生的文件系统事件仍被过滤",
          col._skip_process(os.path.basename(sys.executable), hex(os.getpid())) is True)

    # read_extensions：只在白名单内的读取才写日志
    rcfg.set("audit.read_extensions", [".txt"])
    stub3 = _StubLogs()
    col3 = auditmod.AuditCollector(rcfg, stub3)
    col3._handle_xml(_xml4663("0x1", "ReadCase.txt"))
    col3._handle_xml(_xml4663("0x1", "no_ext.bin"))
    check("read_extensions 生效：只记白名单扩展名",
          len(stub3.access) == 1
          and stub3.access[0]["path"].endswith("ReadCase.txt"),
          [a.get("path") for a in stub3.access])
    check("开启 read_extensions 后 SACL 掩码自动加上读取权限",
          bool(col3._mask_value() & 0x1), hex(col3._mask_value()))
    for c in (col, col2, col3):
        c.stop()

    # 重命名只应写一条访问日志（早期版本 _archive 与 on_moved 各写一条 -> 重复）
    from app.protector import Protector
    from app.recycle import RecycleBin as _RB
    rcfg.set("recycle_bin.path", RECYCLE)
    plogs = _StubLogs()
    rbf = _RB(rcfg)
    prot = Protector(rcfg, plogs, rbf)
    r_src = os.path.join(SHARE, "ren_old.txt")
    r_dst = os.path.join(SHARE, "ren_new.txt")
    write(r_src, "rename-me\n")
    os.replace(r_src, r_dst)
    prot.on_moved(r_src, r_dst)
    check("重命名只写一条访问日志", len(plogs.access) == 1
          and plogs.access[0]["op"] == "重命名", len(plogs.access))
    check("重命名记录带来源路径 detail",
          plogs.access and "ren_old.txt" in str(plogs.access[0].get("detail")),
          plogs.access and plogs.access[0].get("detail"))
    check("重命名后内容已存档", bool(rbf.get_latest_active(r_dst)))
    plogs.access.clear()
    prot._archive(r_dst, "modify")            # 内容没变 -> 不该新增版本/日志
    check("内容未变的「修改」事件不重复记录",
          not plogs.access
          and len([v for v in rbf.query(state="active")["items"]
                   if v["orig_path"].endswith("ren_new.txt")]) == 1,
          len(plogs.access))

    # 「创建」日志必须等审计归因到位再写（5145 比文件系统事件晚约 1.5 秒，
    # 立即写的话一个路径上的第一条记录永远没有操作者）
    plogs.access.clear()
    prot.set_actor_resolver(lambda p: {"user": "CORP\\lisi", "ip": "10.0.0.9",
                                       "client": "", "ip_source": "share_audit",
                                       "attribution": "exact"})
    c_path = os.path.join(SHARE, "created_by_smb.txt")
    write(c_path, "hello\n")
    prot.on_created(c_path)
    check("创建时先存档、暂不记日志（等审计归因）",
          not plogs.access and bool(rbf.get_latest_active(c_path)), len(plogs.access))
    prot.flush_create_log(c_path)              # 审计归因就绪时由采集器回调
    check("归因就绪后补出「创建」记录并带上操作者",
          len(plogs.access) == 1 and plogs.access[0].get("op") == "创建"
          and plogs.access[0].get("user") == "CORP\\lisi"
          and plogs.access[0].get("ip") == "10.0.0.9", plogs.access)
    check("补记的「创建」记录用原始时间戳（不改写成写入时刻）",
          str(plogs.access[0].get("ts", "")).startswith("20")
          and "T" in str(plogs.access[0].get("ts")), plogs.access[0].get("ts"))

    # 托盘图标：文件与句柄都要拿得到（打包漏了 assets 就会退化成系统默认图标）
    from app import tray as traymod
    ico = traymod.tray_icon_path()
    check("能找到托盘图标文件 assets/fileguard.ico", bool(ico) and os.path.isfile(ico), ico)
    check("托盘图标能加载出有效句柄", bool(traymod._load_icon(ico)))
    rbf.close()

    # ---------- 汇总 ----------
    print("\n" + "=" * 72)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    for f in FAIL:
        print("  FAIL:", f)
    print("=" * 72)
    return 1 if FAIL else 0


def blob_count(rb):
    n = 0
    for _dp, _d, files in os.walk(rb.blob_root):
        n += len(files)
    return n


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def port_open(port):
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def wait_web(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port):
            return True
        time.sleep(0.2)
    return False


if __name__ == "__main__":
    sys.exit(main())
