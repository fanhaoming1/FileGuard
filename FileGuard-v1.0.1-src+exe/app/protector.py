# -*- coding: utf-8 -*-
"""文件保护器：实时监听共享目录 → 镜像存档 → 删除时把文件搬进回收站。

设计要点
--------
* 纯 Python 无法在内核层拦截删除，因此采用「实时镜像存档 + 删除瞬间接管」：
  文件每次创建/修改都会把内容按 SHA-256 存入回收站（相同内容自动去重）；
  客户端删除文件后，程序立刻从存档把内容**搬进回收站目录下的实体文件**
  （``<回收站>/files/<盘符>/<原相对路径>``），原路径保持已删除状态 ——
  对客户端而言删除正常生效，数据完整留在回收站，可在 Web 界面一键恢复。
* 删除动作由 ``protection.on_delete_action`` 决定：
  ``move_to_bin``（默认，搬进回收站）/ ``restore``（原地回填，表现为删不掉）/ ``record``（只留内容库）。
* 自己写回文件会产生新的文件系统事件，用「自事件抑制窗口」避免死循环。
* 删除日志会稍等片刻再落盘（``protection.actor_backfill_ms``），
  以便把审计事件里的「谁删的 / 客户端 IP」一起写进去。
"""
import datetime
import fnmatch
import os
import threading
import time
from collections import defaultdict, deque

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .logger import fmt_size, now_iso


def norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


#: 「创建」记录至少延后这么久才写 —— 安全审计(5145)大约 1.5 秒后才落盘，
#: 立即写会拿不到操作者（一个路径上的第一条记录正是「创建」）。
CREATE_LOG_DELAY = 2.0


def _iso_age(ts_iso: str, now: float = None) -> float:
    """ISO 时间戳距现在多少秒；解析失败返回一个很大的值（当作早就该处理）。"""
    try:
        dt = datetime.datetime.fromisoformat(str(ts_iso))
        if dt.tzinfo is None:
            return 1e9
        return (now if now is not None else time.time()) - dt.timestamp()
    except (ValueError, TypeError, OSError):
        return 1e9


class Protector:
    def __init__(self, cfg, logs, recycle, on_event=None, on_log=None):
        self.cfg = cfg
        self.logs = logs
        self.recycle = recycle
        self.on_event = on_event or (lambda *a, **k: None)
        self.on_log = on_log or (lambda *a, **k: None)

        self._observer = None
        self._handler = None
        self._worker = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

        self._suppress = {}                    # normpath -> 抑制截止时间（存档噪声）
        self._del_suppress = {}                # normpath -> 删除抑制截止时间（仅内部动作）
        self._pending = {}                     # normpath -> (截止时间, 事件名)
        self._pending_logs = []                # [[截止时间, 删除日志记录]] 归因回填队列
        self._pending_create = {}              # normpath -> 待补记的「创建」时间戳
        self._restore_history = defaultdict(deque)
        self._actor_resolver = None
        self._actor_refresh = None             # 归因缺失时「即时补采一次审计」的钩子
        self._backfill_seconds = None
        self.stats = {"archived": 0, "deletes": 0, "restored": 0, "moved": 0,
                      "errors": 0, "skipped": 0, "last_event": "", "last_scan": ""}

    # ---------------- 生命周期 ----------------
    def set_actor_resolver(self, fn, backfill_seconds: float = None) -> None:
        """fn(path) -> {'user','ip','client','ip_source','attribution'}，由审计模块注入。

        :param backfill_seconds: 写删除日志前的等待时长（等审计事件到齐再写）。
                                 不给则用 ``protection.actor_backfill_ms``。
        """
        self._actor_resolver = fn
        self._backfill_seconds = backfill_seconds

    def set_actor_refresh(self, fn) -> None:
        """fn(path) -> 归因 dict；在写「文件系统事件」日志且归因缺失时即时补采审计事件。

        与 ``set_actor_resolver``（等审计到齐后再写删除日志）的区别：这里**不等待**，
        而是立刻催一次采集 —— 顺序敏感，不能为了等归因把日志写晚（会打乱日志时间序）。
        """
        self._actor_refresh = fn

    def _actor_now(self, path: str) -> dict:
        """取归因；缓存里没有就催一次审计采集再取，避免首条记录丢操作者。"""
        who = self._actor(path)
        if who.get("user") or who.get("ip") or not self._actor_refresh:
            return who
        try:
            fresh = self._actor_refresh(path) or {}
        except Exception:
            return who
        if not isinstance(fresh, dict):
            return who
        out = dict(who)
        for k in ("user", "ip", "client", "ip_source"):
            if fresh.get(k):
                out[k] = fresh[k]
        if fresh.get("attribution") and out.get("attribution") in ("", "unknown"):
            out["attribution"] = fresh["attribution"]
        return out

    @property
    def running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def start(self) -> None:
        if self.running:
            return
        roots = self.cfg.monitor_paths()
        recursive = bool(self.cfg.get("monitor.recursive", True))
        self._stop.clear()
        self._handler = _Handler(self)
        self._observer = Observer(timeout=1.0)
        for root in roots:
            if os.path.isdir(root):
                self._observer.schedule(self._handler, root, recursive=recursive)
                self.on_log(f"已挂载监听：{root}（递归={recursive}）")
            else:
                self.on_log(f"[警告] 监控目录不存在，已跳过：{root}", "warn")
        self._observer.start()

        self._worker = threading.Thread(target=self._debounce_loop, daemon=True,
                                        name="fg-debounce")
        self._worker.start()

        if self.cfg.get("monitor.seed_on_start", True):
            threading.Thread(target=self._seed, daemon=True, name="fg-seed").start()
        self.on_event("protector", "started")

    def stop(self) -> None:
        self._stop.set()
        obs, self._observer = self._observer, None
        if obs is not None:
            try:
                obs.stop()
                obs.join(timeout=5)
            except Exception:
                pass
        w, self._worker = self._worker, None
        if w is not None:
            w.join(timeout=3)
        self._pending.clear()
        self._flush_pending_creates(grace=0.0)   # 待补记的「创建」记录别丢
        self._flush_delete_logs()                # 把还没落盘的删除日志补写出去

    # ---------------- 过滤 ----------------
    def _accept(self, path: str) -> bool:
        if not os.path.basename(path):
            return False
        name = os.path.basename(path).lower()
        # 内部中转文件（回收站恢复写回时的 <目标>.fg_tmp_restore）永远不参与监控，
        # 不受用户 exclude_patterns 影响 —— 否则用户一旦自定义了排除表，恢复动作
        # 就会给这个临时文件留下垃圾版本和一条假的「删除」记录。
        if name.endswith(".fg_tmp_restore"):
            return False
        for pat in (self.cfg.get("monitor.exclude_patterns") or []):
            if fnmatch.fnmatch(name, str(pat).lower()):
                return False
        exts = self.cfg.get("monitor.include_extensions") or ["*"]
        if "*" in exts:
            return True
        ext = os.path.splitext(name)[1]
        for e in exts:
            e = str(e).lower().strip()
            if e and (e == ext or e == name or (e.startswith(".") and e == ext)):
                return True
        return False

    def _is_suppressed(self, path: str) -> bool:
        key = norm(path)
        with self._lock:
            exp = self._suppress.get(key, 0)
            if exp and exp > time.monotonic():
                return True
            if exp:
                self._suppress.pop(key, None)
        return False

    def _suppress_path(self, path: str, seconds: float = 6.0) -> None:
        with self._lock:
            self._suppress[norm(path)] = time.monotonic() + seconds

    # 删除事件单独一套抑制表：_suppress_path 的窗口较长（恢复后 8~12 秒），
    # 它的用途是压掉「自己回写文件」产生的创建/重命名噪声。若连删除事件一起吞掉，
    # 用户在恢复后不久删除该文件就会被完全忽略 —— 既没进回收站也没有删除日志，
    # 等同于「彻底删除」。因此删除只认这套短窗口抑制（仅用于恢复覆盖写时内部删旧文件）。
    def _is_delete_suppressed(self, path: str) -> bool:
        key = norm(path)
        with self._lock:
            exp = self._del_suppress.get(key, 0)
            if exp and exp > time.monotonic():
                return True
            if exp:
                self._del_suppress.pop(key, None)
        return False

    def _suppress_delete(self, path: str, seconds: float = 6.0) -> None:
        with self._lock:
            self._del_suppress[norm(path)] = time.monotonic() + seconds

    def _clear_delete_suppress(self, path: str) -> None:
        with self._lock:
            self._del_suppress.pop(norm(path), None)

    # ---------------- 初始播种 ----------------
    def _seed(self) -> None:
        if self.cfg.get("protection.strategy") != "mirror":
            return
        count = 0
        t0 = time.time()
        for root in self.cfg.monitor_paths():
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames
                               if d.lower() not in ("$recycle.bin", "system volume information")]
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    if not self._accept(full):
                        continue
                    if self.recycle.get_latest_active(full):
                        continue          # 已有存档，跳过，节省启动时间
                    r = self.recycle.add_version(full, event="seed")
                    if not r.get("error"):
                        count += 1
        self.stats["last_scan"] = now_iso()
        self.on_log(f"初始镜像完成：新增存档 {count} 个文件，耗时 {time.time() - t0:.1f}s")
        self.on_event("seed_done", count)

    # ---------------- 事件入口（watchdog 线程调用） ----------------
    def on_created(self, path: str) -> None:
        if not self._accept(path) or self._is_suppressed(path):
            return
        # 先立即存档：内容是刚诞生的，必须先保住（否则「创建后马上被删」将无档可回）。
        # 但**不**在这里记「创建」日志 —— 安全审计(5145)大约 1.5 秒后才写进事件日志，
        # 此刻记日志操作者一定是空的。日志改由 debounce 收尾阶段补记（见 _flush_pending_creates），
        # 并用这里保存的原始时间戳，保证 ts 列准确。
        self._archive(path, "create", log=False)
        with self._lock:
            self._pending_create[norm(path)] = now_iso()
        self._schedule(path, "modify")

    def on_modified(self, path: str) -> None:
        if not self._accept(path) or self._is_suppressed(path):
            return
        self._schedule(path, "modify")

    def on_moved(self, src: str, dest: str, is_dir: bool = False) -> None:
        if is_dir:
            return
        if self._is_suppressed(dest) and self._is_suppressed(src):
            return
        if not self._under_monitor(dest):
            # 移动到监控范围之外 —— 等价于一次删除
            self._handle_delete(src)
            return
        if not self._accept(dest):
            return
        # 只写一条「重命名」：_archive 内部就按 event="rename" 记日志，
        # 这里把来源路径作为 detail 传进去即可（早期版本在 _archive 之外又记了一条，导致重复）。
        self._archive(dest, "rename", detail=f"来自 {src}")

    def on_deleted(self, path: str, is_dir: bool = False) -> None:
        # 注意：这里刻意不用 _is_suppressed —— 删除必须能被如实处理，
        # 否则「恢复后短时间内再删除」会被静默丢弃（见 _is_delete_suppressed 注释）。
        if self._is_delete_suppressed(path):
            return
        if is_dir:
            self._handle_dir_delete(path)
            return
        if not self._accept(path):
            return
        self._handle_delete(path)

    def _under_monitor(self, path: str) -> bool:
        p = norm(path)
        return any(p == norm(r) or p.startswith(norm(r) + os.sep)
                   for r in self.cfg.monitor_paths())

    def _schedule(self, path: str, event: str, delay: float = None) -> None:
        delay = float(self.cfg.get("protection.debounce_seconds", 1.5) or 1.5) \
            if delay is None else float(delay)
        with self._lock:
            self._pending[norm(path)] = (time.monotonic() + delay, event, path)

    def _defer_for_create_log(self, path: str) -> bool:
        """刚创建的文件先别收尾：等 5145 安全事件落盘后再一起写日志。

        否则「创建」这条记录会因为没有操作者而变空（5145 比文件系统事件晚约 1.5 秒），
        而且「创建 → 修改」的先后顺序也会被写反。返回 True 表示已重新排期。
        """
        key = norm(path)
        with self._lock:
            ts = self._pending_create.get(key)
        if not ts:
            return False
        if _iso_age(ts, time.time()) >= CREATE_LOG_DELAY:
            return False
        self._schedule(path, "modify", delay=0.25)
        return True

    def _take_pending_create(self, path: str) -> str:
        with self._lock:
            return self._pending_create.pop(norm(path), "")

    def _debounce_loop(self) -> None:
        while not self._stop.is_set():
            now = time.monotonic()
            due = []
            with self._lock:
                for key, (deadline, event, orig) in list(self._pending.items()):
                    if deadline <= now:
                        due.append((orig, event))
                        self._pending.pop(key, None)
            for orig, event in due:
                if self._defer_for_create_log(orig):
                    continue                 # 刚创建，再等一会好把操作者写上
                ts = self._take_pending_create(orig)
                if ts:
                    self._write_create_log(orig, ts)   # 先记「创建」，再记后续变更
                self._archive(orig, event)
            self._drain_delete_logs()
            self._flush_pending_creates()
            self._stop.wait(0.25)

    # ---------------- 存档 ----------------
    def _archive(self, path: str, event: str, detail: str = "",
                 log: bool = True) -> bool:
        if not self._accept(path) or self._is_suppressed(path):
            return False
        if not os.path.isfile(path):
            return False
        who = self._actor_now(path)
        r = self.recycle.add_version(path, event=event, actor=who["user"],
                                     actor_ip=who["ip"])
        if r.get("error"):
            self.stats["errors"] += 1
            return False
        if r.get("unchanged"):
            # 内容与上一版完全一致（典型的「创建后又来一次修改事件」）：
            # 不新增版本、也不重复记一条访问日志，避免日志出现成对的重复行。
            self.stats["skipped"] += 1
            return True
        self.stats["archived"] += 1
        self.stats["last_event"] = now_iso()
        if log and self.cfg.get("monitor.log_changes", True):
            op = {"create": "创建", "modify": "修改", "seed": "初始镜像",
                  "rename": "重命名"}.get(event, event)
            if op != "初始镜像":
                self.logs.log_access(op=op, path=os.path.normpath(path),
                                     name=os.path.basename(path), size=r.get("size"),
                                     size_text=fmt_size(r.get("size")),
                                     user=who["user"], ip=who["ip"],
                                     client=who["client"], ip_source=who["ip_source"],
                                     attribution=who["attribution"], source="fs_event",
                                     detail=detail or None,
                                     version_id=r.get("id"))
        return True

    # ---------------- 「创建」日志延后补记 ----------------
    def _flush_pending_creates(self, grace: float = CREATE_LOG_DELAY) -> None:
        """补写「创建」记录：归因一可用就立刻写，最迟不超过 grace 秒。

        主路径是 debounce 收尾时连同存档一起写（见 _debounce_loop）；这里兜住
        「事件被抑制 / 内容未变导致收尾被跳过 / 文件很快被删」等情况，避免记录丢失。
        """
        now = time.time()
        out = []
        with self._lock:
            for key, ts in list(self._pending_create.items()):
                forced = _iso_age(ts, now) >= grace
                if forced or self._actor(key).get("user"):
                    out.append((key, ts))
                    self._pending_create.pop(key, None)
        for key, ts in out:
            self._write_create_log(key, ts)

    def _write_create_log(self, path: str, ts: str) -> None:
        if not path:
            return
        who = self._actor_now(path)
        self.logs.log_access(op="创建", path=os.path.normpath(path),
                             name=os.path.basename(path),
                             user=who.get("user", ""), ip=who.get("ip", ""),
                             client=who.get("client", ""),
                             ip_source=who.get("ip_source", ""),
                             attribution=who.get("attribution", ""),
                             source="fs_event", ts=ts)

    def flush_create_log(self, path: str) -> None:
        """审计刚拿到该路径的归因 —— 把挂起的「创建」记录立刻补上。

        由 AuditCollector 在归因写入缓存后回调，能保证「创建」行排在
        同一次访问产生的「读取 / 写入」行**之前**，不会出现顺序倒挂。
        """
        ts = self._take_pending_create(path)
        if ts:
            self._write_create_log(path, ts)

    # ---------------- 删除处理 ----------------
    _EMPTY_ACTOR = {"user": "", "ip": "", "client": "", "ip_source": "",
                    "attribution": "unknown"}

    def _actor(self, path: str) -> dict:
        """返回 {'user','ip','client','ip_source','attribution'}，由审计模块注入的回调解算。"""
        out = dict(self._EMPTY_ACTOR)
        if not self._actor_resolver:
            return out
        try:
            res = self._actor_resolver(path)
        except Exception:
            return out
        if isinstance(res, dict):
            for k in ("user", "ip", "client", "ip_source"):
                out[k] = str(res.get(k) or "")
            out["attribution"] = str(res.get("attribution") or "unknown")
            return out
        try:
            u, ip = res
            out["user"], out["ip"] = (u or ""), (ip or "")
            return out
        except Exception:
            return out

    @staticmethod
    def _who_text(entry: dict) -> str:
        who = entry.get("user") or ""
        ip = entry.get("ip") or ""
        attribution = entry.get("attribution") or ""
        # 兜底推断的身份信息不进入通知 / 运行日志，统一显示为“未知”
        if attribution in ("", "unknown", "parent_dir", "recent"):
            return "未知"
        if who and ip:
            return f"{who} @ {ip}"
        return who or ip or "未知"

    def _restore_budget_ok(self, path: str) -> bool:
        """同一路径反复被删时降级，避免死循环。"""
        key = norm(path)
        limit = int(self.cfg.get("protection.max_restore_per_10min", 10) or 0)
        if limit <= 0:
            return True
        now = time.time()
        with self._lock:
            q = self._restore_history[key]
            while q and now - q[0] > 600:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
        return True

    def _handle_delete(self, path: str) -> None:
        if os.path.exists(path):
            return                       # 已被重建，不算删除
        path = os.path.normpath(path)
        action = self.cfg.delete_action()
        who = self._actor(path)
        # watchdog 有时把「目录被删」也报成文件删除事件：该路径自己没有存档、
        # 但下面有历史版本 —— 那就是个被删掉的目录，转交目录分支处理。
        if not self.recycle.get_latest_active(path) \
                and self.recycle.count_versions_under(path):
            self._handle_dir_delete(path)
            return
        # 关键：删除动作由配置决定 —— 默认 move_to_bin（把存档内容搬进回收站目录的实体文件），
        #       原路径保持「已删除」状态，对客户端而言删除正常生效，数据留在回收站。
        rec = self.recycle.mark_deleted(
            path, actor=who["user"], actor_ip=who["ip"],
            materialize=(action == "move_to_bin"), action=action) or {}
        if not rec:
            # 同一次删除会先经目录分支处理过（重复事件），避免再写一条「不可恢复」的假记录
            recent = self.recycle.get_recent_deleted(path, 30.0)
            if recent:
                self.stats["skipped"] += 1
                return
            rec = self.recycle.get_latest_active(path) or {}
        self.stats["deletes"] += 1
        self.stats["last_event"] = now_iso()
        if action == "move_to_bin" and rec.get("bin_path"):
            self.stats["moved"] += 1

        entry = {
            "op": "删除", "path": path, "name": os.path.basename(path),
            "size": rec.get("size"), "size_text": fmt_size(rec.get("size")),
            "sha256": rec.get("sha256", ""), "version_id": rec.get("id"),
            "user": who["user"], "ip": who["ip"], "client": who["client"],
            "ip_source": who["ip_source"], "attribution": who["attribution"],
            "source": "fs_event", "is_dir": False,
            "action": action, "bin_path": rec.get("bin_path") or "",
            "bin_root": self.cfg.bin_files_dir(),
            "recoverable": bool(rec.get("sha256")),
            "restored": False, "restore_path": "", "auto_restore": action == "restore",
        }
        self._finalize_delete(entry, rec)
        self.on_event("delete", entry)

    def _handle_dir_delete(self, dirpath: str) -> None:
        if os.path.exists(dirpath):
            return
        if not self._under_monitor(dirpath):
            return
        dirpath = os.path.normpath(dirpath)
        action = self.cfg.delete_action()
        who = self._actor(dirpath)
        # 目录里的文件已经被各自的删除事件处理过了，这里把它们的记录归集回来
        rows = self.recycle.list_active_under(dirpath)
        pre_done = False
        if not rows:
            rows = self.recycle.list_deleted_under(dirpath, since=time.time() - 600)
            pre_done = bool(rows)
        moved, restored = [], []

        if not pre_done:
            for r in rows:
                self.recycle.mark_deleted(
                    r["orig_path"], actor=who["user"], actor_ip=who["ip"],
                    materialize=(action == "move_to_bin"), action=action)
        if action == "move_to_bin":
            for r in rows:
                rec = r if pre_done else (self.recycle.get(r["id"]) or {})
                if rec.get("bin_path"):
                    moved.append(rec["bin_path"])
            if moved:
                # 连目录本身也在回收站里建出来，保持结构直观
                try:
                    os.makedirs(self.recycle.bin_path_for(dirpath), exist_ok=True)
                except OSError:
                    pass
            self.stats["moved"] += len(moved)
        elif action == "restore" and not pre_done:
            for r in rows:
                if not self._restore_budget_ok(r["orig_path"]):
                    continue
                self._suppress_path(r["orig_path"], 12.0)
                res = self.recycle.restore(r["id"])
                if res.get("ok"):
                    restored.append(res["path"])
                    self._suppress_path(res["path"], 12.0)
            self.stats["restored"] += len(restored)

        self.stats["deletes"] += 1
        entry = {
            "op": "删除目录", "path": dirpath, "name": os.path.basename(dirpath),
            "size": sum((r.get("size") or 0) for r in rows),
            "sha256": "", "version_id": None, "user": who["user"], "ip": who["ip"],
            "client": who["client"], "ip_source": who["ip_source"],
            "attribution": who["attribution"],
            "source": "fs_event", "is_dir": True, "item_count": len(rows),
            "action": action,
            "bin_path": self.recycle.bin_path_for(dirpath) if moved else "",
            "bin_root": self.cfg.bin_files_dir(),
            "recoverable": len(rows) > 0, "restored": bool(restored),
            "restore_path": "", "auto_restore": action == "restore",
            "moved_count": len(moved),
        }
        entry["size_text"] = fmt_size(entry["size"])
        entry["restored_count"] = len(restored)
        if action == "move_to_bin":
            entry["bin_dir"] = self.recycle.bin_path_for(dirpath)
            self.on_log(f"[删除目录] {dirpath} —— 涉及 {len(rows)} 个文件，"
                        f"已全部移入回收站（{len(moved)} 个文件）", "warn")
            if len(rows) and not moved:
                self.on_log(f"[提示] {dirpath} 的子文件删除前没有存档，无法搬入回收站", "error")
        elif action == "restore" and restored:
            self.on_log(f"[删除目录] {dirpath} —— 涉及 {len(rows)} 个文件，"
                        f"已还原 {len(restored)} 个", "warn")
        else:
            self.on_log(f"[删除目录] {dirpath} —— 涉及 {len(rows)} 个文件（仅记录）", "warn")
        self._finalize_dir_delete(entry)
        self.on_event("delete", entry)

    def _finalize_delete(self, entry: dict, rec: dict) -> None:
        action = entry.get("action") or "record"
        if action == "restore" and rec.get("id"):
            if self._restore_budget_ok(entry["path"]):
                # 先抑制，再回填：避免还原过程自身产生的新事件被当成用户操作
                self._suppress_path(entry["path"], 10.0)
                res = self.recycle.restore(int(rec["id"]))
                if res.get("ok"):
                    entry["restored"] = True
                    entry["restore_path"] = res["path"]
                    self._suppress_path(res["path"], 8.0)
                    self.stats["restored"] += 1
                    self.on_log(f"[已还原] {entry['path']}（{entry['size_text']}）"
                                f"来自 {self._who_text(entry)}", "ok")
                else:
                    entry["restore_error"] = res.get("error", "")
                    self.on_log(f"[还原失败] {entry['path']}：{res.get('error')}", "error")
            else:
                entry["restore_error"] = "触发频率保护，已降级为仅入回收站"
                self.on_log(f"[限流] {entry['path']} 短时间内被反复删除，"
                            f"本次不再自动还原，请到 Web 回收站手动恢复", "warn")
        elif action == "move_to_bin":
            if entry.get("bin_path"):
                self.on_log(f"[已移入回收站] {entry['path']}（{entry['size_text']}）"
                            f"← {self._who_text(entry)}", "warn")
                self.on_log(f"             落地位置：{entry['bin_path']}", "muted")
            elif not entry.get("recoverable"):
                self.on_log(f"[无法搬入回收站] {entry['path']} —— 删除前没有存档，"
                            f"内容不可恢复", "error")
            else:
                self.on_log(f"[回收站落盘失败] {entry['path']} —— 内容仍在回收站内容库，"
                            f"可通过 Web 界面恢复", "error")
        else:
            self.on_log(f"[删除] {entry['path']}（{entry['size_text']}）"
                        f"← {self._who_text(entry)}　已记录", "warn")

        if not entry.get("recoverable"):
            entry.setdefault("note", "删除前未形成存档，内容不可恢复"
                                     "（可调整 protection.strategy=mirror）")
        self._queue_delete_log(entry)

    def _finalize_dir_delete(self, entry: dict) -> None:
        if not entry.get("recoverable"):
            entry.setdefault("note", "删除前未形成存档，内容不可恢复")
        self._queue_delete_log(entry)

    # ---------------- 删除日志（归因回填后写入） ----------------
    def _backfill_delay(self) -> float:
        if self._backfill_seconds is not None:
            return max(0.0, float(self._backfill_seconds))
        return float(self.cfg.actor_backfill_seconds() or 0.0)

    def _queue_delete_log(self, entry: dict) -> None:
        """审计事件总比文件系统事件晚到 1~3 秒，稍等片刻再写日志，
        才能把「谁删的 / 客户端 IP」补上。等待时长在服务装配时会按审计轮询间隔抬高。
        """
        if not self._actor_resolver:
            self._write_delete_log(entry)
            return
        if entry.get("user") and entry.get("ip"):
            self._write_delete_log(entry)          # 操作者与 IP 都齐了，不用等
            return
        delay = self._backfill_delay()
        if delay <= 0:
            self._write_delete_log(entry)
            return
        with self._lock:
            self._pending_logs.append([time.monotonic() + delay, dict(entry)])

    def _write_delete_log(self, entry: dict) -> None:
        self.logs.log_delete(**{k: v for k, v in entry.items()
                                if not str(k).startswith("_")})

    def _drain_delete_logs(self) -> None:
        now = time.monotonic()
        due = []
        with self._lock:
            for item in list(self._pending_logs):
                if item[0] <= now:
                    due.append(item)
                    self._pending_logs.remove(item)
        for _deadline, entry in due:
            self._resolve_actor_into(entry)
            self._write_delete_log(entry)

    def _resolve_actor_into(self, entry: dict) -> None:
        """把审计归因补进待写记录（只填空缺字段，不覆盖已有值）。"""
        if not self._actor_resolver:
            return
        if entry.get("user") and entry.get("ip"):
            return
        who = self._actor(entry.get("path", ""))
        for k in ("user", "ip", "client", "ip_source"):
            if who.get(k) and not entry.get(k):
                entry[k] = who[k]
        if who.get("attribution") and entry.get("attribution") in ("", "unknown"):
            entry["attribution"] = who["attribution"]

    def _flush_delete_logs(self) -> None:
        with self._lock:
            items = list(self._pending_logs)
            self._pending_logs = []
        for _deadline, entry in items:
            self._resolve_actor_into(entry)
            self._write_delete_log(entry)

    # ---------------- 供 Web 调用 ----------------
    def restore_now(self, version_id: int, target: str = "") -> dict:
        self._suppress_path(target, 8.0)
        res = self.recycle.restore(version_id, target=target)
        if res.get("ok"):
            self._suppress_path(res["path"], 8.0)
        return res

    def restore_many_safe(self, ids, policy: str = "") -> dict:
        ok, fail = [], []
        pol = policy or self.cfg.get("protection.restore_conflict_policy", "rename")
        for vid in (ids or []):
            try:
                rec = self.recycle.get(int(vid)) or {}
                tgt = rec.get("orig_path") or ""
                # 恢复动作会自己把文件写回磁盘、并重建该路径的 active 版本，
                # 所以先把该路径的「存档噪声」压掉：否则这次写回会被 watchdog 记成
                # 一次「重命名」访问，并多出一份重复的 active 版本。
                if tgt:
                    self._suppress_path(tgt, 12.0)
                # 覆盖写策略下 restore() 会先删掉目标位置上的旧文件，那是内部动作，
                # 不该被记成「用户删除了这个文件」，所以单独给它一个短删除抑制。
                if pol == "overwrite" and tgt and os.path.exists(tgt):
                    self._suppress_delete(tgt, 3.0)
                r = self.recycle.restore(int(vid), policy=policy)
                # 恢复并没有走「先删后改名」的退化分支，说明不会有内部删除事件，
                # 立刻撤掉删除抑制，别耽误用户随后对它的真实删除。
                if r.get("ok") and not r.get("removed_target") and tgt:
                    self._clear_delete_suppress(tgt)
            except Exception as e:
                r = {"ok": False, "error": str(e)}
            if r.get("ok"):
                self._suppress_path(r["path"], 8.0)
                self.stats["restored"] += 1
                ok.append(r)
            else:
                fail.append({**r, "id": vid})
        return {"ok": len(ok), "failed": len(fail), "items": ok, "errors": fail}

    def snapshot(self) -> dict:
        with self._lock:
            pending = len(self._pending)
        return {"running": self.running, **self.stats, "pending": pending,
                "roots": self.cfg.monitor_paths()}


class _Handler(FileSystemEventHandler):
    def __init__(self, owner: Protector):
        super().__init__()
        self.o = owner

    def on_created(self, event):
        if not event.is_directory:
            self.o.on_created(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.o.on_modified(event.src_path)

    def on_deleted(self, event):
        self.o.on_deleted(event.src_path, is_dir=event.is_directory)

    def on_moved(self, event):
        self.o.on_moved(event.src_path, event.dest_path, is_dir=event.is_directory)
