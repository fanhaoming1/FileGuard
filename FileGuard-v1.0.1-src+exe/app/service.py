# -*- coding: utf-8 -*-
"""服务编排：把日志、回收站、保护器、审计采集、Web 服务串起来，支持反复启停。"""
import datetime
import os
import queue
import threading
import time
import webbrowser

from .audit import HAS_PYWIN32, AuditCollector, is_admin
from .logger import LogManager, fmt_size, now_iso
from .protector import Protector
from .recycle import RecycleBin

STARTUP_PURGE_DELAY = 60          # 启动后多久先跑一次清理（秒）


def next_purge_time(interval_days: int, at_hour: int, now: datetime.datetime = None):
    """计算下一次自动清理时刻。

    at_hour = 0~23：落在每天的该小时整点，且与当前时刻至少相隔 interval_days 天
                     （例：interval_days=1、at_hour=3 → 最近的一个凌晨 3 点）
    at_hour = -1   ：不指定时点，按「当前时刻 + interval_days 天」滚动
    """
    now = now or datetime.datetime.now()
    days = max(1, int(interval_days or 1))
    if int(at_hour) < 0:
        return now + datetime.timedelta(days=days)
    target = now.replace(hour=max(0, min(23, int(at_hour))), minute=0,
                         second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=days)
    return target


class GuardService:
    def __init__(self, cfg, ui_queue: queue.Queue = None, on_status=None):
        self.cfg = cfg
        self.ui_queue = ui_queue
        self.on_status = on_status or (lambda s: None)
        self._lock = threading.RLock()
        self._running = False
        self.started_at = 0.0

        self.logs = None
        self.recycle = None
        self.protector = None
        self.audit = None
        self.web = None
        self._purge_thread = None
        self._next_purge_at = 0.0             # 下一次自动清理时刻（epoch 秒）
        self._last_purge = {}                 # 上一次清理结果
        self._stop = threading.Event()
        self.events = []                      # 最近事件（供 Web 概览显示）
        self._events_lock = threading.Lock()

    # ---------------- 状态 ----------------
    @property
    def running(self) -> bool:
        return self._running

    def emit(self, text: str, level: str = "info") -> None:
        rec = {"ts": time.strftime("%H:%M:%S"), "text": text, "level": level}
        if self.ui_queue is not None:
            try:
                self.ui_queue.put_nowait(rec)
            except queue.Full:
                pass
        if level in ("warn", "error"):
            with self._events_lock:
                self.events.append({**rec, "full_ts": now_iso()})
                self.events[:] = self.events[-200:]

    def push_event(self, kind: str, payload=None) -> None:
        with self._events_lock:
            self.events.append({"ts": time.strftime("%H:%M:%S"), "kind": kind,
                                "payload": payload, "full_ts": now_iso()})
            self.events[:] = self.events[-200:]

    def recent_events(self, limit: int = 30) -> list:
        with self._events_lock:
            return list(reversed(self.events[-int(limit):]))

    # ---------------- 启动 ----------------
    def start(self) -> dict:
        with self._lock:
            if self._running:
                return {"ok": False, "message": "服务已在运行中"}
            v = self.cfg.validate()
            if not v["ok"]:
                for e in v["errors"]:
                    self.emit(f"[配置错误] {e}", "error")
                return {"ok": False, "message": "；".join(v["errors"])}
            for w in v["warnings"]:
                self.emit(f"[提示] {w}", "warn")

            self._stop.clear()
            self.emit("正在启动 FileGuard 服务 ...")
            try:
                self.logs = LogManager(self.cfg)
                self.recycle = RecycleBin(self.cfg)
                self.protector = Protector(self.cfg, self.logs, self.recycle,
                                           on_event=self.push_event, on_log=self.emit)

                if self.cfg.get("audit.enabled", True):
                    self.audit = AuditCollector(self.cfg, self.logs,
                                                on_log=self.emit, on_event=self.push_event)
                    pf = self.audit.preflight()
                    for issue in pf.get("issues", []):
                        self.emit(f"[审计] {issue}", "warn")
                    if pf["ok"] and self.cfg.get("audit.auto_configure", True):
                        res = self.audit.configure()
                        if not res.get("ok"):
                            self.emit(f"[审计] 配置失败：{res.get('message')}", "warn")
                    elif pf["ok"]:
                        self.emit("[审计] 已按配置跳过自动配置（audit.auto_configure=false）")
                    else:
                        self.emit("[审计] 审计功能降级：仅记录文件系统变更事件"
                                  "（读取/访问记录不可用）", "warn")
                        self.audit = None
                else:
                    self.emit("[审计] audit.enabled=false，仅记录文件系统变更事件")

                # 让保护器能从审计缓存/会话表里查出"谁删的、从哪个 IP 删的"
                if self.audit is not None:
                    collector = self.audit
                    # 关键：写删除日志前必须等够「审计轮询间隔 + 余量」，
                    # 否则 4663/5145 还没被采到，本机删除会显示「未知」。
                    poll_ms = int(self.cfg.get("audit.poll_interval_seconds", 2) or 2) * 1000
                    wait = self.cfg.actor_backfill_seconds(min_ms=poll_ms + 1500)
                    self.protector.set_actor_resolver(
                        lambda p: collector.actor_info(p), backfill_seconds=wait)
                    # 文件系统事件比安全事件先到：写「创建/修改」这类立即落盘的日志时，
                    # 若缓存还冷就催一次采集，否则一个路径上的第一条记录会丢操作者。
                    self.protector.set_actor_refresh(
                        lambda p: collector.actor_info(p, fresh=True))
                    # 审计刚拿到某路径归因时，立刻把挂起的「创建」记录补上，
                    # 这样它一定排在本次访问的「读取/写入」之前（顺序不倒挂）。
                    collector.set_actor_hook(self.protector.flush_create_log)
                    self.emit("[审计] 客户端 IP 归因已启用：删除事件(4663/5145)"
                              " → 路径/账号缓存 → SMB 会话表"
                              f"（删除日志延迟 {wait:.1f}s 落盘以等待归因；"
                              "创建/修改在归因缺失时即时补采一次）")

                self.protector.start()
                if self.audit is not None:
                    self.audit.start()

                if self.cfg.get("web.enabled", True):
                    from .web import WebServer
                    self.web = WebServer(self)
                    self.web.start()

                if self.cfg.auto_purge():
                    self._purge_thread = threading.Thread(target=self._purge_loop,
                                                          daemon=True, name="fg-purge")
                    self._purge_thread.start()
                    self.emit("[回收站] 自动清理已启用："
                              + self.purge_snapshot()["schedule_text"])
                else:
                    self.emit("[回收站] 自动清理已关闭（recycle_bin.auto_purge=false），"
                              "需手工点「清理回收站」", "warn")

                self._running = True
                self.started_at = time.time()
                info = self.status()
                self.emit(f"服务已启动 ✓ Web 界面：{info['web_url']}", "ok")
                self.emit(f"监控目录：{', '.join(self.cfg.monitor_paths())}")
                self.emit(f"回收站：{self.cfg.recycle_path()}")
                self.emit(f"日志：{self.cfg.log_dir()}")
                self.on_status(self.status())
                return {"ok": True, "message": "服务已启动", "web_url": info["web_url"]}
            except Exception as e:
                self.emit(f"[启动失败] {e}", "error")
                self._teardown()
                return {"ok": False, "message": f"启动失败：{e}"}

    # ---------------- 停止 ----------------
    def stop(self) -> dict:
        with self._lock:
            if not self._running:
                return {"ok": False, "message": "服务未在运行"}
            self.emit("正在停止服务 ...")
            self._teardown()
            self.emit("服务已停止", "ok")
            self.on_status(self.status())
            return {"ok": True, "message": "服务已停止"}

    def _teardown(self) -> None:
        """停止所有子模块。保留对象引用，方便停止后仍能查看统计。"""
        self._stop.set()
        for name in ("web", "audit", "protector"):
            obj = getattr(self, name, None)
            if obj is not None:
                try:
                    obj.stop()
                except Exception as e:
                    self.emit(f"[停止] {name} 异常：{e}", "warn")
        self._purge_thread = None
        self._next_purge_at = 0.0
        self._running = False
        self.started_at = 0.0

    def restart(self) -> dict:
        self.stop()
        time.sleep(0.4)
        return self.start()

    # ---------------- 后台清理 ----------------
    def _purge_loop(self) -> None:
        """按「每隔 purge_interval_days 天、落在 purge_at_hour 点」自动清理回收站。

        服务启动后先等 STARTUP_PURGE_DELAY 秒跑一次（避免频繁重启导致周期永远等不到）。
        """
        if not self._stop.wait(STARTUP_PURGE_DELAY):
            self._run_purge("启动时")
        while not self._stop.is_set():
            delay = self._seconds_until_next()
            if self._stop.wait(delay):
                return
            self._run_purge("定时")
        self._next_purge_at = 0.0

    def _seconds_until_next(self) -> float:
        if not self._next_purge_at:
            self._schedule_next_purge()
        return max(60.0, self._next_purge_at - time.time())

    def _schedule_next_purge(self) -> float:
        """算出距下一次清理的秒数，并记录下次时刻。"""
        days = self.cfg.purge_interval_days()
        hour = self.cfg.purge_at_hour()
        nxt = next_purge_time(days, hour)
        self._next_purge_at = nxt.timestamp()
        return max(60.0, (nxt - datetime.datetime.now()).total_seconds())

    def _run_purge(self, why: str) -> None:
        try:
            r = self.recycle.purge_now()
            removed = (r["expired"].get("removed", 0) +
                       r["size_limit"].get("removed", 0) +
                       r.get("orphans", {}).get("removed", 0))
            self._last_purge = {
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": why,
                "removed": removed,
                "size_text": fmt_size(r.get("total_size", 0) or 0),
                "expired": r["expired"].get("removed", 0),
                "size_limit": r["size_limit"].get("removed", 0),
            }
            if removed:
                self.emit(f"[回收站] {why}自动清理 {removed} 个历史版本", "info")
            else:
                self.emit(f"[回收站] {why}自动清理完成，无需清理的版本", "info")
        except Exception as e:
            self._last_purge = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "reason": why, "removed": 0, "error": str(e)}
            self.emit(f"[回收站] 清理异常：{e}", "warn")
        finally:
            self._schedule_next_purge()

    def purge_snapshot(self) -> dict:
        """自动清理的状态（供界面展示「下次清理时间」）。"""
        days = self.cfg.purge_interval_days()
        hour = self.cfg.purge_at_hour()
        nxt = (datetime.datetime.fromtimestamp(self._next_purge_at)
               if self._next_purge_at else next_purge_time(days, hour))
        hour_text = ("不指定时点（按启动时刻起算）" if hour < 0 else f"{hour:02d}:00")
        if days > 1:
            schedule_text = f"每 {days} 天 {hour_text} 清理一次"
        else:
            schedule_text = f"每天 {hour_text} 清理一次"
        return {
            "enabled": self.cfg.auto_purge(),
            "active": bool(self._running and self.cfg.auto_purge()),
            "interval_days": days,
            "at_hour": hour,
            "at_hour_text": hour_text,
            "schedule_text": schedule_text,
            "next_run": (nxt.strftime("%Y-%m-%d %H:%M") if self._running and
                         self.cfg.auto_purge() else ""),
            "last": dict(self._last_purge),
        }

    # ---------------- 状态快照 ----------------
    def status(self) -> dict:
        s = {
            "running": self._running,
            "started_at": (time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.localtime(self.started_at))
                           if self.started_at else ""),
            "uptime": int(time.time() - self.started_at) if self.started_at else 0,
            "monitor_paths": self.cfg.monitor_paths(),
            "log_dir": self.cfg.log_dir(),
            "recycle_path": self.cfg.recycle_path(),
            "bin_path": self.cfg.bin_files_dir(),
            "delete_action": self.cfg.delete_action(),
            "delete_action_text": self.cfg.get("protection.on_delete_action"),
            "admin": __import__("app.audit", fromlist=["is_admin"]).is_admin(),
            "host": self.cfg.get("web.host", "0.0.0.0"),
            "port": self.cfg.get("web.port", 8765),
            "web_url": self.web_url(),
            "audit": self.audit.snapshot() if self.audit else {
                "running": False,
                "available": HAS_PYWIN32,
                "enabled": bool(self.cfg.get("audit.enabled", True)),
                "reason": "" if not self.cfg.get("audit.enabled", True)
                else "审计采集未启动（通常是非管理员权限）",
                "collected": 0,
            },
            "protector": self.protector.snapshot() if self.protector else {"running": False},
            "recycle": self.recycle.stats() if self.recycle else None,
            "purge": self.purge_snapshot(),
            "logs": self.logs.stats() if self.logs else None,
            "config_ok": self.cfg.validate(),
        }
        return s

    def web_url(self) -> str:
        host = self.cfg.get("web.host", "0.0.0.0")
        port = self.cfg.get("web.port", 8765)
        show = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
        return f"http://{show}:{port}/"

    def open_web(self) -> None:
        try:
            webbrowser.open(self.web_url())
        except Exception as e:
            self.emit(f"打开浏览器失败：{e}", "warn")
