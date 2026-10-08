# -*- coding: utf-8 -*-
"""日志写入器：JSONL 格式 + 按天分文件 + 高效反向分页读取。

命名规则
--------
文件名取自 log.access_file / log.delete_file，其中的 `{date}` 占位符会被替换成
log.date_format 指定格式的日期（默认 %Y%m%d），因此默认产出：

    access_20260930.log   —— 访问操作（读取/写入/创建/打开，含客户端 IP）
    delete_20260930.log   —— 删除操作（含回收站版本号、是否已还原）

* 单日文件超过 log.max_size_mb 时在**当天内**继续分片：access_20260930_1.log、_2.log …
* 历史日期文件超过 log.retention_days 天会被自动清理（0 = 永久保留）。
* 文件名里若不写 `{date}`，则退化为「单文件 + 按大小轮转」的旧行为（access.log.1 ~ .N）。
* 升级前遗留的单个 access.log / delete.log 仍会被继续读取（排在最旧位置），不会丢历史。
"""
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta

DATE_TOKEN = "{date}"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def fmt_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------- 文件名解析
def _split_name(name: str):
    """把文件名模板拆成 (前缀, 后缀, 扩展名)；不含 {date} 时返回 (name, '', '')。"""
    if DATE_TOKEN not in name:
        return name, "", ""
    head, _, tail = name.partition(DATE_TOKEN)
    ext = tail[-4:] if tail.lower().endswith(".log") else ""
    return head, tail, ext


def legacy_name(template: str) -> str:
    """按天模板对应的旧单文件名：access_{date}.log -> access.log。"""
    name = os.path.basename(template)
    if DATE_TOKEN not in name:
        return ""
    return name.replace("_" + DATE_TOKEN, "").replace(DATE_TOKEN, "")


def scan_log_files(directory: str, template: str, date_format: str = "%Y%m%d") -> list:
    """列出模板对应的所有按天分片文件，返回 [(日期, 分片序号, 路径)]，旧 -> 新。

    同一天内分片序号越大内容越旧（超限时把当前文件整体挪成 _1，再继续往原文件写），
    因此排序按「日期升序、分片序号降序」，这样整体就是严格的旧 -> 新。
    """
    name = os.path.basename(template)
    if DATE_TOKEN not in name:
        p = os.path.join(directory, name)
        return [("", 0, p)] if os.path.isfile(p) else []
    head, tail, ext = _split_name(name)
    pat = re.compile("^" + re.escape(head) + r"(?P<date>\d+)"
                     + r"(?:_(?P<idx>\d+))?" + re.escape(tail) + "$")
    out = []
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    for fn in names:
        m = pat.match(fn)
        if not m:
            continue
        out.append((m.group("date"), int(m.group("idx") or 0),
                    os.path.join(directory, fn)))
    out.sort(key=lambda t: (t[0], -t[1]))
    return out


def log_files(directory: str, template: str, date_format: str = "%Y%m%d") -> list:
    """返回该日志模板涉及的全部文件路径（旧 -> 新），含升级前遗留的单文件。"""
    files = [p for _, _, p in scan_log_files(directory, template, date_format)]
    old = legacy_name(template)
    if old:
        legacy = os.path.join(directory, old)
        if os.path.isfile(legacy) and legacy not in files:
            files.insert(0, legacy)
    return files


# ---------------------------------------------------------------- 写入器
class JsonlLogger:
    """线程安全的 JSONL 追加日志：按天分文件，可选按大小分片。"""

    def __init__(self, path: str, max_size_mb: int = 50, backup_count: int = 5,
                 encoding: str = "utf-8", max_scan_lines: int = 200000,
                 retention_days: int = 90, date_format: str = "%Y%m%d"):
        self.template = path
        self.date_format = (str(date_format or "").strip() or "%Y%m%d")
        self.daily = DATE_TOKEN in os.path.basename(path)
        self.max_bytes = max(1, int(max_size_mb)) * 1024 * 1024
        self.backup_count = max(0, int(backup_count))
        self.retention_days = max(0, int(retention_days or 0))
        self.encoding = encoding
        self.max_scan_lines = max(1000, int(max_scan_lines))
        self._lock = threading.RLock()
        self._purged_day = ""
        self._dir = os.path.dirname(path) or "."
        os.makedirs(self._dir, exist_ok=True)

    # ---------- 路径 ----------
    @property
    def path(self) -> str:
        """当前正在写入的文件（按天模式下随日期自动变化）。"""
        return self.current_path()

    def current_path(self, when=None) -> str:
        if not self.daily:
            return self.template
        return self.template.replace(DATE_TOKEN, self._day(when))

    def _day(self, when=None) -> str:
        return (when or datetime.now()).strftime(self.date_format)

    def _segment_path(self, day: str, idx: int) -> str:
        """当天内的分片文件名：access_20260930_1.log。"""
        head, _tail, ext = _split_name(os.path.basename(self.template))
        return os.path.join(self._dir, f"{head}{day}_{idx}{ext}")

    def files(self) -> list:
        """本日志涉及的全部文件（旧 -> 新）。"""
        return log_files(self._dir, self.template, self.date_format)

    # ---------- 写入 ----------
    def write(self, record: dict, when=None) -> None:
        """追加一条记录；when（datetime）可指定归属日期，主要用于造演示数据。"""
        payload = json.dumps(record, ensure_ascii=False) + "\n"
        self.write_many([], when=when, _raw=payload)

    def write_many(self, records=None, when=None, _raw: str = "") -> None:
        records = list(records or [])
        payload = _raw
        if not payload:
            if not records:
                return
            payload = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
        with self._lock:
            target = self.current_path(when)
            if when is None:                     # 仅实时写入才做清理，避免回填历史时误删
                self.purge_old()
            self._rotate_if_needed(target, len(payload.encode(self.encoding, "ignore")))
            with open(target, "a", encoding=self.encoding, errors="replace") as f:
                f.write(payload)

    def _rotate_if_needed(self, target: str, incoming: int) -> None:
        try:
            size = os.path.getsize(target)
        except OSError:
            return
        if size + incoming <= self.max_bytes or size == 0:
            return
        if self.backup_count == 0:
            if self.daily:
                return                          # 按天模式且不分片：当天文件继续追加
            try:
                os.replace(target, target + ".old")
            except OSError:
                pass
            return
        if self.daily:
            self._rotate_daily(target)
            return
        oldest = f"{target}.{self.backup_count}"
        if os.path.exists(oldest):
            try:
                os.remove(oldest)
            except OSError:
                pass
        for i in range(self.backup_count - 1, 0, -1):
            src, dst = f"{target}.{i}", f"{target}.{i + 1}"
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except OSError:
                    pass
        try:
            os.replace(target, target + ".1")
        except OSError:
            pass

    def _rotate_daily(self, target: str) -> None:
        day = self._day()
        segs = [self._segment_path(day, i) for i in range(1, self.backup_count + 1)]
        if os.path.exists(segs[-1]):
            try:
                os.remove(segs[-1])
            except OSError:
                pass
        for i in range(len(segs) - 1, 0, -1):
            src, dst = segs[i - 1], segs[i]
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except OSError:
                    pass
        try:
            os.replace(target, segs[0])
        except OSError:
            pass

    def purge_old(self, force: bool = False) -> int:
        """清理超过 retention_days 的历史日期文件，返回删除数量。

        默认每个自然日最多执行一次（文件集本身也是每天新增一个，粒度足够）；
        force=True 可强制立即执行（服务启动、手工清理时使用）。
        """
        if not (self.daily and self.retention_days > 0):
            return 0
        day = self._day()
        if not force and self._purged_day == day:
            return 0
        self._purged_day = day
        cutoff = (datetime.now() - timedelta(days=self.retention_days)).strftime(self.date_format)
        removed = 0
        for date_str, _idx, path in scan_log_files(self._dir, self.template, self.date_format):
            if len(date_str) == len(cutoff) and date_str < cutoff:
                try:
                    os.remove(path)
                    removed += 1
                except OSError:
                    pass
        return removed

    # ---------- 读取 ----------
    def _iter_file_reversed(self, path: str, limit: int):
        """从单个文件尾部反向逐行产出（最多 limit 行），大文件也很快。"""
        if not os.path.isfile(path):
            return
        produced = 0
        chunk = 256 * 1024
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            tail = b""
            while pos > 0 and produced < limit:
                size = min(chunk, pos)
                pos -= size
                f.seek(pos)
                buf = f.read(size) + tail
                parts = buf.split(b"\n")
                tail = parts[0]
                for raw in reversed(parts[1:]):
                    raw = raw.strip()
                    if not raw:
                        continue
                    produced += 1
                    yield raw
                    if produced >= limit:
                        break
            if produced < limit and tail.strip():
                yield tail.strip()

    def _iter_lines_reversed(self, limit: int):
        """跨天 / 跨分片，从最新文件尾部反向逐行产出（最多 limit 行）。"""
        remaining = int(limit)
        for path in reversed(self.files()):
            if remaining <= 0:
                return
            for raw in self._iter_file_reversed(path, remaining):
                remaining -= 1
                yield raw

    def tail(self, n: int = 100) -> list:
        """返回最近 n 条记录（新的在前）。"""
        out = []
        for raw in self._iter_lines_reversed(int(n)):
            try:
                out.append(json.loads(raw.decode(self.encoding, "replace")))
            except (ValueError, UnicodeDecodeError):
                continue
        return out

    def query(self, page: int = 1, size: int = 50, keyword: str = "",
              user: str = "", op: str = "", start: str = "", end: str = "") -> dict:
        """分页 + 过滤查询（在最近 max_scan_lines 行内检索）。"""
        page = max(1, int(page))
        size = max(1, min(500, int(size)))
        keyword = (keyword or "").strip().lower()
        user = (user or "").strip().lower()
        op = (op or "").strip()
        start = (start or "").strip()
        end = (end or "").strip()

        matched = []
        scanned = 0
        need = page * size
        for raw in self._iter_lines_reversed(self.max_scan_lines):
            scanned += 1
            try:
                rec = json.loads(raw.decode(self.encoding, "replace"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not self._match(rec, keyword, user, op, start, end):
                continue
            matched.append(rec)
            if len(matched) >= need:
                break

        total_matched = len(matched)
        truncated = scanned >= self.max_scan_lines and len(matched) < need
        begin = (page - 1) * size
        items = matched[begin:begin + size]
        return {
            "items": items,
            "page": page,
            "size": size,
            "returned": len(items),
            "total": total_matched if len(matched) < need else None,
            "has_more": len(matched) >= need,
            "scanned": scanned,
            "truncated": truncated,
        }

    @staticmethod
    def _match(rec: dict, keyword: str, user: str, op: str, start: str, end: str) -> bool:
        if user and user not in str(rec.get("user", "")).lower():
            return False
        if op and op != str(rec.get("op", "")):
            return False
        ts = str(rec.get("ts", ""))
        if start and ts < start:
            return False
        if end and ts > end + "\uffff":
            return False
        if keyword:
            hay = " ".join(str(rec.get(k, "")) for k in
                           ("path", "user", "ip", "op", "share", "name", "access_list"))
            if keyword not in hay.lower():
                return False
        return True

    # ---------- 统计 ----------
    def count_lines(self) -> int:
        n = 0
        for path in self.files():
            try:
                with open(path, "rb") as f:
                    for _ in f:
                        n += 1
            except OSError:
                pass
        return n

    def stat(self) -> dict:
        cur = self.current_path()
        files = self.files()
        total = 0
        latest_m = 0.0
        for p in files:
            try:
                total += os.path.getsize(p)
                latest_m = max(latest_m, os.path.getmtime(p))
            except OSError:
                pass
        days = len({d for d, _i, _p in
                    scan_log_files(self._dir, self.template, self.date_format) if d})
        return {
            "path": cur,
            "name": os.path.basename(cur),
            "exists": bool(files),
            "today_exists": os.path.isfile(cur),
            "file_count": len(files),
            "days": days,
            "oldest": os.path.basename(files[0]) if files else "",
            "size": total,
            "size_text": fmt_size(total),
            "mtime": (datetime.fromtimestamp(latest_m).isoformat(timespec="seconds")
                      if latest_m else ""),
        }


class LogManager:
    """统一持有 access / delete 两个日志器。"""

    def __init__(self, cfg):
        self.cfg = cfg
        self._lock = threading.RLock()
        self._access = None
        self._delete = None
        self.reload()

    def reload(self) -> None:
        with self._lock:
            kw = dict(
                max_size_mb=self.cfg.get("log.max_size_mb", 50),
                backup_count=self.cfg.get("log.backup_count", 5),
                encoding=self.cfg.get("log.encoding", "utf-8"),
                max_scan_lines=self.cfg.get("log.max_scan_lines", 200000),
                retention_days=self.cfg.get("log.retention_days", 90),
                date_format=self.cfg.get("log.date_format", "%Y%m%d"),
            )
            self._access = JsonlLogger(self.cfg.access_log_template(), **kw)
            self._delete = JsonlLogger(self.cfg.delete_log_template(), **kw)
            # 启动 / 重载配置时顺手清理过期日志，避免长期无人写日志的日子里文件堆积
            for lg in (self._access, self._delete):
                try:
                    lg.purge_old(force=True)
                except Exception:
                    pass

    @property
    def access(self) -> JsonlLogger:
        return self._access

    @property
    def delete(self) -> JsonlLogger:
        return self._delete

    def log_access(self, **fields) -> None:
        rec = {"ts": now_iso(), "event": "access"}
        rec.update(fields)
        self._access.write(rec)

    def log_delete(self, **fields) -> None:
        rec = {"ts": now_iso(), "event": "delete"}
        rec.update(fields)
        self._delete.write(rec)

    def current_files(self) -> dict:
        """当前正在写入的两个日志文件（供界面 / 自检展示）。"""
        return {"access": self._access.current_path(),
                "delete": self._delete.current_path()}

    def stats(self) -> dict:
        return {"access": self._access.stat(), "delete": self._delete.stat()}
