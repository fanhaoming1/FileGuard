# -*- coding: utf-8 -*-
"""回收站：内容寻址（SHA-256）去重存档 + SQLite 版本索引 + 可见实体回收站目录。

目录结构
--------
* ``blobs/xx/yy/<sha256>.dat`` —— 内容去重存档（相同内容全盘只存一份），恢复的唯一数据源
* ``files/<盘符>/<原相对路径>`` —— **可见回收站**：文件被删除时落下的实体副本，
  保留原盘符与目录结构，管理员可以直接在资源管理器里翻找、取回
* ``index.db`` —— 每一次版本（原路径 / 大小 / 时间 / 谁删的 / 客户端 IP / 实体副本路径）

对客户端来说，删除操作照常生效（文件从共享目录消失）；数据没有丢，而是被搬到了回收站。
"""
import hashlib
import os
import re
import shutil
import sqlite3
import threading
import time
from datetime import datetime

from .logger import fmt_size

SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    orig_path     TEXT    NOT NULL,
    name          TEXT,
    size          INTEGER,
    sha256        TEXT    NOT NULL,
    mtime         REAL,
    stored_at     REAL    NOT NULL,
    event         TEXT,
    actor         TEXT,
    actor_ip      TEXT,
    state         TEXT    NOT NULL DEFAULT 'active',
    deleted_at    REAL,
    deleted_by    TEXT,
    deleted_ip    TEXT,
    restored_at   REAL,
    restore_target TEXT,
    bin_path      TEXT,
    delete_action TEXT,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS ix_orig  ON versions(orig_path);
CREATE INDEX IF NOT EXISTS ix_state ON versions(state);
CREATE INDEX IF NOT EXISTS ix_time  ON versions(stored_at);
CREATE INDEX IF NOT EXISTS ix_sha   ON versions(sha256);
"""

# 老版本 index.db 缺少的列：{列名: 建表 DDL 片段}
MIGRATE_COLUMNS = {
    "bin_path": "bin_path TEXT",
    "delete_action": "delete_action TEXT",
}


def sha256_file(path: str, block: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(block)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _unique_path(target: str, suffix: str = " (已恢复)") -> str:
    base, ext = os.path.splitext(target)
    i = 1
    while True:
        cand = f"{base}{suffix}{ext}" if i == 1 else f"{base}{suffix} ({i}){ext}"
        if not os.path.exists(cand):
            return cand
        i += 1


class RecycleBin:
    """回收站管理器（线程安全）。"""

    def __init__(self, cfg):
        self.cfg = cfg
        self.root = cfg.recycle_path()
        self.blob_root = os.path.join(self.root, "blobs")
        self.files_root = os.path.join(self.root, "files")   # 可见回收站（实体副本）
        self.db_path = os.path.join(self.root, "index.db")
        self._lock = threading.RLock()
        os.makedirs(self.blob_root, exist_ok=True)
        os.makedirs(self.files_root, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self._migrate_locked()
            self.conn.commit()

    def _migrate_locked(self) -> None:
        """老版本 index.db 自动补列（升级后无需手工删库）。"""
        try:
            cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(versions)")}
        except sqlite3.Error:
            return
        for name, ddl in MIGRATE_COLUMNS.items():
            if name not in cols:
                try:
                    self.conn.execute(f"ALTER TABLE versions ADD COLUMN {ddl}")
                except sqlite3.Error:
                    pass

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.commit()
                self.conn.close()
            except sqlite3.Error:
                pass

    # ---------------- 存储 ----------------
    def _blob_path(self, sha: str) -> str:
        return os.path.join(self.blob_root, sha[:2], sha[2:4], sha + ".dat")

    def _has_blob(self, sha: str) -> bool:
        return os.path.isfile(self._blob_path(sha))

    def _store_blob(self, src: str, sha: str) -> bool:
        """返回是否新写入（False 表示已有同样内容，直接复用）。"""
        dst = self._blob_path(sha)
        if os.path.isfile(dst):
            return False
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        tmp = dst + f".{os.getpid()}.{threading.get_ident()}.tmp"
        shutil.copyfile(src, tmp)
        try:
            os.replace(tmp, dst)
        except OSError:
            if os.path.isfile(tmp):
                os.remove(tmp)
            # 并发下别的线程已写入同名 blob，视为成功
            if not os.path.isfile(dst):
                raise
            return False
        return True

    def add_version(self, src_path: str, event: str = "modify", actor: str = "",
                    actor_ip: str = "", note: str = "") -> dict:
        """把文件内容存档为一个版本。返回版本记录 dict；失败返回 {'error': ...}。"""
        try:
            st = os.stat(src_path)
        except OSError as e:
            return {"error": f"文件不可读：{e}"}
        if not os.path.isfile(src_path):
            return {"error": "不是普通文件"}

        max_mb = self.cfg.get("monitor.max_file_size_mb", 0) or 0
        if max_mb and st.st_size > max_mb * 1024 * 1024:
            return {"error": f"超过 max_file_size_mb 限制（{fmt_size(st.st_size)}）"}

        try:
            sha = sha256_file(src_path)
        except OSError as e:
            return {"error": f"读取失败：{e}"}

        # 内容与同一路径最新的 active 版本完全一致 -> 不重复建版本。
        # 典型场景：文件刚创建就紧跟一次「修改」事件，内容其实没变；
        # 若照单全收，访问日志会出现成对的重复行，版本号也被无意义地消耗掉。
        if event in ("create", "modify"):
            prev = self.get_latest_active(src_path)
            if prev and prev.get("sha256") == sha and prev.get("size") == st.st_size:
                return {**prev, "unchanged": True}

        try:
            self._store_blob(src_path, sha)
        except OSError as e:
            return {"error": f"写入回收站失败：{e}"}

        row = (
            os.path.normpath(src_path), os.path.basename(src_path), st.st_size, sha,
            st.st_mtime, time.time(), event, actor, actor_ip, note or ""
        )
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO versions(orig_path,name,size,sha256,mtime,stored_at,event,"
                "actor,actor_ip,note,state) VALUES(?,?,?,?,?,?,?,?,?,?, 'active')", row)
            self.conn.commit()
            vid = cur.lastrowid
        self._trim_versions(os.path.normpath(src_path))
        return self.get(vid)

    def _trim_versions(self, orig_path: str) -> None:
        keep = int(self.cfg.get("recycle_bin.keep_versions_per_file", 5) or 5)
        if keep <= 0:
            return
        with self._lock:
            rows = self.conn.execute(
                "SELECT id FROM versions WHERE orig_path=? AND state='active' "
                "ORDER BY stored_at DESC", (orig_path,)).fetchall()
            extra = [r["id"] for r in rows[keep:]]
            for vid in extra:
                self._drop_row(vid)

    # ---------------- 删除事件 ----------------
    def mark_deleted(self, orig_path: str, actor: str = "", actor_ip: str = "",
                     note: str = "", materialize: bool = False,
                     action: str = "") -> dict:
        """把该路径最新的 active 版本标记为已删除，返回被标记的记录。

        :param materialize: 是否同时把内容落成回收站目录（files/）里的实体文件
        :param action:      本次删除动作（move_to_bin / restore / record），写入索引便于追溯
        """
        orig_path = os.path.normpath(orig_path)
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM versions WHERE orig_path=? AND state='active' "
                "ORDER BY stored_at DESC LIMIT 1", (orig_path,)).fetchone()
            if row is None:
                # 兜底：该路径没有 active 版本，但存在「曾被恢复回磁盘」的记录
                # （升级前用旧逻辑恢复过、只留 restored 状态的文件）。
                # 这类文件在磁盘上已被用户删掉，若不兜底就会被判成「不可恢复」而彻底丢失。
                # 必须先排除「刚刚已经入过回收站」的重复事件，否则同一次删除会记两条、
                # 在回收站里落两份副本 —— state 为 deleted 且没有 restored_at 的正常
                # 重复事件不在此列（下面只匹配 restored 语义的行）。
                if self.get_recent_deleted(orig_path, 30.0):
                    return {}
                row = self.conn.execute(
                    "SELECT * FROM versions WHERE orig_path=? AND "
                    "(state='restored' OR restored_at IS NOT NULL) "
                    "ORDER BY stored_at DESC LIMIT 1", (orig_path,)).fetchone()
                if row is not None and not self._has_blob(row["sha256"]):
                    row = None          # 内容已被清理，无从恢复
            if row is None:
                return {}
            # restored_at / restore_target 必须一并清掉：回收站列表的口径是
            # state='deleted' AND restored_at IS NULL，留着这两个字段这条记录就
            # 不会出现在回收站里，等于白删。
            self.conn.execute(
                "UPDATE versions SET state='deleted', restored_at=NULL, restore_target='', "
                "deleted_at=?, deleted_by=?, deleted_ip=?, note=?, delete_action=? WHERE id=?",
                (time.time(), actor, actor_ip, note or row["note"], action or "",
                 row["id"]))
            self.conn.commit()
            vid = row["id"]
        if materialize:
            res = self.materialize(vid, action=action)
            if res.get("error"):
                with self._lock:
                    self.conn.execute("UPDATE versions SET note=? WHERE id=?",
                                      ((note or row["note"] or "") +
                                       f" [回收站落盘失败：{res['error']}]", vid))
                    self.conn.commit()
        return self.get(vid)

    # ---------------- 可见回收站（实体副本） ----------------
    def bin_path_for(self, orig_path: str) -> str:
        """原路径 -> 回收站目录下的实体副本路径（保留盘符与目录层级）。"""
        p = os.path.abspath(orig_path)
        drive, rest = os.path.splitdrive(p)
        parts = [x for x in re.split(r"[\\/]+", rest) if x not in ("", ".", "..")]
        key = re.sub(r"[^0-9A-Za-z_\-]", "_", (drive or "").rstrip(":")) or "VOL"
        return os.path.join(self.files_root, key.upper(), *parts)

    @staticmethod
    def _unique_bin_path(target: str) -> str:
        """同名文件已存在且内容不同：加「.时间戳」后缀，绝不覆盖旧副本。"""
        base, ext = os.path.splitext(target)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        cand = f"{base}.{stamp}{ext}"
        i = 1
        while os.path.exists(cand):
            i += 1
            if i > 200:
                return f"{base}.{stamp}-{time.time_ns()}{ext}"
            cand = f"{base}.{stamp} ({i - 1}){ext}"
        return cand

    def materialize(self, version_id: int, action: str = "move_to_bin") -> dict:
        """把某个版本的内容落成回收站目录里的实体文件。

        同名且内容一致 -> 直接复用（天然去重）；同名但内容不同 -> 加时间戳后缀。
        """
        rec = self.get(version_id)
        if not rec:
            return {"ok": False, "error": f"版本不存在：{version_id}"}
        blob = self._blob_path(rec["sha256"])
        if not os.path.isfile(blob):
            return {"ok": False, "error": "回收站中的内容已丢失（已被清理或不存在）"}

        target = self.bin_path_for(rec["orig_path"])
        if os.path.isfile(target):
            try:
                if sha256_file(target) == rec["sha256"]:
                    self._set_bin(version_id, target, action)
                    return {"ok": True, "path": target, "reused": True}
            except OSError:
                pass
            target = self._unique_bin_path(target)
        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            tmp = target + ".fg_tmp_bin"
            shutil.copyfile(blob, tmp)
            os.replace(tmp, target)
            mt = rec.get("mtime") or time.time()
            try:
                os.utime(target, (mt, mt))
            except OSError:
                pass
        except OSError as e:
            return {"ok": False, "error": f"写入回收站目录失败：{e}"}
        self._set_bin(version_id, target, action)
        return {"ok": True, "path": target, "reused": False}

    def _set_bin(self, version_id: int, path: str, action: str = "") -> None:
        with self._lock:
            self.conn.execute(
                "UPDATE versions SET bin_path=?, delete_action=? WHERE id=?",
                (path, action or "", int(version_id)))
            self.conn.commit()

    def remove_bin_copy(self, bin_path: str) -> bool:
        """删除回收站目录里的实体副本（仅用于配套清理，不影响 blob 存档）。"""
        if not bin_path:
            return False
        p = os.path.abspath(bin_path)
        root = os.path.abspath(self.files_root)
        if not (p == root or p.startswith(root + os.sep)):
            return False                      # 只允许删回收站目录内部的文件
        ok = False
        if os.path.isfile(p):
            try:
                os.remove(p)
                ok = True
            except OSError:
                return False
        self._prune_empty_dirs(os.path.dirname(p), under=root)
        return ok

    # ---------------- 恢复 ----------------
    def restore(self, version_id: int, target: str = "", policy: str = "") -> dict:
        rec = self.get(version_id)
        if not rec:
            return {"ok": False, "error": f"版本不存在：{version_id}"}
        blob = self._blob_path(rec["sha256"])
        if not os.path.isfile(blob):
            return {"ok": False, "error": "回收站中的内容已丢失（已被清理或不存在）"}

        target = os.path.normpath(target or rec["orig_path"])
        policy = policy or self.cfg.get("protection.restore_conflict_policy", "rename")

        if os.path.exists(target):
            if os.path.isdir(target):
                return {"ok": False, "error": f"目标是目录，无法覆盖：{target}"}
            if policy == "skip":
                return {"ok": False, "error": f"目标已存在，按策略跳过：{target}"}
            if policy == "rename":
                target = _unique_path(target, self.cfg.get("protection.restore_suffix", " (已恢复)"))
            # overwrite 时直接覆盖
        removed_target = False
        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            tmp = target + ".fg_tmp_restore"
            shutil.copyfile(blob, tmp)
            try:
                # 优先让 os.replace 原子覆盖：这样「恢复覆盖已有文件」不会先删除旧文件，
                # 也就不会向监控抛出一个假的「删除」事件（否则被删除抑制挡住时，
                # 用户紧接着的真实删除也会一起被吞掉）。
                os.replace(tmp, target)
            except OSError:
                if os.path.exists(target):      # 目标只读/被占用：退化成先删后改名
                    os.remove(target)
                    removed_target = True
                os.replace(tmp, target)
            shutil.copystat(blob, target)
        except OSError as e:
            return {"ok": False, "error": f"恢复写入失败：{e}"}

        with self._lock:
            self.conn.execute(
                "UPDATE versions SET state='restored', restored_at=?, restore_target=? "
                "WHERE id=?", (time.time(), target, version_id))
            self.conn.commit()
        # 恢复成功后，默认把回收站目录里的那份实体副本收走（相当于「移回去」）
        if self.cfg.get("recycle_bin.remove_bin_copy_on_restore", True):
            bp = rec.get("bin_path") or ""
            if bp and os.path.normcase(os.path.abspath(bp)) != os.path.normcase(
                    os.path.abspath(target)):
                self.remove_bin_copy(bp)
                with self._lock:
                    self.conn.execute("UPDATE versions SET bin_path='' WHERE id=?",
                                      (version_id,))
                    self.conn.commit()

        # 恢复 = 文件重新回到磁盘，必须同时把「磁盘上的文件 ↔ 一个 active 版本」这条
        # 不变式建回来（上面只是把旧版本记成 restored，那条已不再是 active）。
        # 否则该路径下没有 active 版本，下次再删除时 mark_deleted 找不到可标记的版本，
        # 文件会被直接删掉而进不了回收站 —— 正是「恢复后再删除 = 彻底删除」的根因。
        new_id = None
        try:
            st = os.stat(target)
        except OSError:
            st = None
        if st is not None:
            with self._lock:
                cur = self.conn.execute(
                    "INSERT INTO versions(orig_path,name,size,sha256,mtime,stored_at,event,"
                    "actor,actor_ip,note,state) VALUES(?,?,?,?,?,?,?,?,?,?, 'active')",
                    (os.path.normpath(target), os.path.basename(target), st.st_size,
                     rec["sha256"], st.st_mtime, time.time(), "restore", "",
                     "", f"由版本 {version_id} 恢复"))
                self.conn.commit()
                new_id = cur.lastrowid
            self._trim_versions(os.path.normpath(target))
        return {"ok": True, "path": target, "id": version_id, "size": rec["size"],
                "active_id": new_id, "removed_target": removed_target,
                "bin_path": rec.get("bin_path") or ""}

    def restore_many(self, ids, policy: str = "") -> dict:
        ok, fail = [], []
        for vid in ids or []:
            r = self.restore(int(vid), policy=policy)
            (ok if r.get("ok") else fail).append(r if r.get("ok") else {**r, "id": vid})
        return {"ok": len(ok), "failed": len(fail), "items": ok, "errors": fail}

    # ---------------- 查询 ----------------
    def get(self, version_id: int):
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM versions WHERE id=?", (int(version_id),)).fetchone()
        return dict(row) if row else None

    def get_latest_active(self, orig_path: str):
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM versions WHERE orig_path=? AND state='active' "
                "ORDER BY stored_at DESC LIMIT 1", (os.path.normpath(orig_path),)).fetchone()
        return dict(row) if row else None

    def get_recent_deleted(self, orig_path: str, within_seconds: float = 30.0):
        """该路径刚刚是否已被处理成「已删除」（用于识别同一次删除的重复事件）。"""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM versions WHERE orig_path=? AND state='deleted' "
                "AND IFNULL(deleted_at, 0) >= ? ORDER BY deleted_at DESC LIMIT 1",
                (os.path.normpath(orig_path), time.time() - within_seconds)).fetchone()
        return dict(row) if row else None

    def list_active_under(self, prefix: str) -> list:
        """列出某个目录（含子目录）下所有 active 版本，用于整目录删除时批量处理。"""
        return self._list_under(prefix, "state='active'")

    def count_versions_under(self, prefix: str) -> int:
        """某个目录（含子目录）下是否有历史版本 —— 用来判断「被删掉的其实是个目录」。"""
        prefix = os.path.normpath(prefix)
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) c FROM versions WHERE orig_path LIKE ? OR orig_path LIKE ?",
                (prefix + os.sep + "%", prefix + "/%")).fetchone()
        return row["c"] if row else 0

    def list_deleted_under(self, prefix: str, since: float = 0.0) -> list:
        """列出某个目录下「最近被删除」的版本（用于目录删除事件的补充归集）。"""
        return self._list_under(prefix, "state='deleted'",
                                extra_args=(since,) if since else ())

    def _list_under(self, prefix: str, condition: str, extra_args=()) -> list:
        prefix = os.path.normpath(prefix)
        sql = (f"SELECT * FROM versions WHERE {condition} AND "
               "(orig_path LIKE ? OR orig_path LIKE ?)")
        args = [prefix + os.sep + "%", prefix + "/%"]
        if extra_args:
            sql += " AND deleted_at >= ?"
            args.append(extra_args[0])
        sql += " ORDER BY orig_path"
        with self._lock:
            rows = self.conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    # 回收站列表的状态口径
    #   delete   —— 已删除且**未恢复**（回收站的正经内容，可在 Web 一键恢复）
    #   restored —— 已恢复（历史留痕，不再属于回收站内容）
    #   active   —— 当前有效存档（尚未被删除）
    STATE_WHERE = {
        "delete": "state='deleted' AND restored_at IS NULL",
        "deleted": "state='deleted' AND restored_at IS NULL",
        "restored": "restored_at IS NOT NULL",
        "active": "state='active' AND restored_at IS NULL",
    }

    def _state_clause(self, state: str):
        st = (state or "").strip().lower()
        if not st:
            return None, []
        clause = self.STATE_WHERE.get(st)
        if clause is None:
            return "state=?", [state]
        return clause, []

    def query(self, page: int = 1, size: int = 50, state: str = "", keyword: str = "",
              path: str = "", actor: str = "") -> dict:
        page = max(1, int(page))
        size = max(1, min(500, int(size)))
        where, args = [], []
        clause, sargs = self._state_clause(state)
        if clause:
            where.append(clause)
            args.extend(sargs)
        if path:
            where.append("orig_path LIKE ?")
            args.append(f"%{path}%")
        if actor:
            where.append("(IFNULL(deleted_by,'') LIKE ? OR IFNULL(actor,'') LIKE ?)")
            args.extend([f"%{actor}%", f"%{actor}%"])
        if keyword:
            where.append("(orig_path LIKE ? OR IFNULL(note,'') LIKE ? OR sha256 LIKE ?)")
            args.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
        clause_sql = ("WHERE " + " AND ".join(where)) if where else ""
        with self._lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) c FROM versions {clause_sql}", args).fetchone()["c"]
            rows = self.conn.execute(
                f"SELECT * FROM versions {clause_sql} ORDER BY stored_at DESC, id DESC "
                f"LIMIT ? OFFSET ?", args + [size, (page - 1) * size]).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            # 只有「已删除 + 未恢复 + 内容还在」的条目才谈得上恢复
            d["recoverable"] = bool(d.get("state") == "deleted"
                                    and not d.get("restored_at")
                                    and self._has_blob(d.get("sha256") or ""))
            d["in_bin"] = bool(d.get("state") == "deleted" and not d.get("restored_at"))
            items.append(d)
        return {"items": items, "total": total, "page": page,
                "size": size, "pages": max(1, (total + size - 1) // size)}

    def deleted_list(self, **kw) -> dict:
        """回收站内容：已删除且尚未恢复的版本。"""
        kw["state"] = "delete"
        return self.query(**kw)

    # ---------------- 清理 ----------------
    def _drop_row(self, version_id: int) -> int:
        """删除索引行。返回实际释放的 blob 字节数（0 表示内容仍被其它版本引用）。"""
        with self._lock:
            row = self.conn.execute(
                "SELECT sha256, size, bin_path FROM versions WHERE id=?",
                (int(version_id),)).fetchone()
            if not row:
                return 0
            self.conn.execute("DELETE FROM versions WHERE id=?", (int(version_id),))
            self.conn.commit()
            left = self.conn.execute("SELECT COUNT(*) c FROM versions WHERE sha256=?",
                                     (row["sha256"],)).fetchone()["c"]
        # 实体副本只属于这一条版本记录，随索引一起清掉
        self.remove_bin_copy(row["bin_path"])
        if left > 0:
            return 0
        blob = self._blob_path(row["sha256"])
        freed = 0
        if os.path.isfile(blob):
            try:
                freed = os.path.getsize(blob)
                os.remove(blob)
            except OSError:
                freed = 0
        self._prune_empty_dirs(os.path.dirname(blob))
        return freed

    def _prune_empty_dirs(self, d: str, under: str = "") -> None:
        root = os.path.normcase(under or self.blob_root)
        d = os.path.normcase(d)
        while d.startswith(root) and d != root:
            try:
                if os.path.isdir(d) and not os.listdir(d):
                    os.rmdir(d)
                else:
                    break
            except OSError:
                break
            d = os.path.dirname(d)

    def purge_expired(self) -> dict:
        """清理超过保留期的历史版本（已删除的 + 已恢复的留痕）。"""
        days = float(self.cfg.get("recycle_bin.retention_days", 30) or 0)
        if days <= 0:
            return {"removed": 0, "reason": "retention_days<=0，跳过"}
        cutoff = time.time() - days * 86400
        with self._lock:
            rows = self.conn.execute(
                "SELECT id FROM versions WHERE (state='deleted' OR restored_at IS NOT NULL) "
                "AND stored_at < ?", (cutoff,)).fetchall()
        for r in rows:
            self._drop_row(r["id"])
        return {"removed": len(rows), "cutoff_days": days}

    def purge_orphans(self) -> dict:
        """清掉内容已经不在（blob 丢失）的索引行 —— 这类记录无法恢复，不该留在回收站。"""
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, sha256 FROM versions "
                "WHERE state='deleted' AND restored_at IS NULL").fetchall()
        gone = [r["id"] for r in rows if not self._has_blob(r["sha256"] or "")]
        for vid in gone:
            self._drop_row(vid)
        return {"removed": len(gone), "checked": len(rows)}

    def enforce_size(self) -> dict:
        """超出容量上限时，从最旧的历史版本开始清理，绝不删掉每个路径的最新版本。"""
        max_gb = float(self.cfg.get("recycle_bin.max_size_gb", 20) or 0)
        if max_gb <= 0:
            return {"removed": 0, "reason": "max_size_gb<=0，跳过"}
        limit = max_gb * 1024 ** 3
        total = self.total_size()          # 只统计一次，之后按释放量递减
        removed = 0
        while total > limit and removed < 100000:
            with self._lock:
                row = self.conn.execute(
                    "SELECT id FROM versions WHERE state='deleted' "
                    "OR restored_at IS NOT NULL "
                    "ORDER BY stored_at ASC LIMIT 1").fetchone()
                if row is None:
                    row = self.conn.execute(
                        "SELECT v.id FROM versions v WHERE v.state='active' AND v.id NOT IN "
                        "(SELECT MAX(v2.id) FROM versions v2 GROUP BY v2.orig_path) "
                        "ORDER BY v.stored_at ASC LIMIT 1").fetchone()
            if row is None:
                break
            total -= self._drop_row(row["id"])
            removed += 1
        return {"removed": removed, "limit_gb": max_gb, "total_size": total}

    def purge_now(self) -> dict:
        o = self.purge_orphans()
        a = self.purge_expired()
        b = self.enforce_size()
        return {"orphans": o, "expired": a, "size_limit": b,
                "total_size": self.total_size()}

    def empty(self) -> dict:
        """清空回收站（同时清掉可见目录里的实体副本）。"""
        with self._lock:
            n = self.conn.execute("SELECT COUNT(*) c FROM versions").fetchone()["c"]
            self.conn.execute("DELETE FROM versions")
            self.conn.commit()
        for sub in os.listdir(self.blob_root):
            p = os.path.join(self.blob_root, sub)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
        try:
            for sub in os.listdir(self.files_root):
                p = os.path.join(self.files_root, sub)
                if os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        except OSError:
            pass
        return {"removed": n}

    def delete_version(self, version_id: int) -> dict:
        rec = self.get(version_id)
        if not rec:
            return {"ok": False, "error": "版本不存在"}
        self._drop_row(int(version_id))
        return {"ok": True, "id": int(version_id)}

    # ---------------- 统计 ----------------
    def _dir_size(self, root: str) -> int:
        total = 0
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                try:
                    total += os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    pass
        return total

    def total_size(self) -> int:
        return self._dir_size(self.blob_root) + self._dir_size(self.files_root)

    def bin_stats(self) -> dict:
        """可见回收站目录（实体副本）的统计。"""
        n, size = 0, 0
        for dirpath, _dirs, files in os.walk(self.files_root):
            for fn in files:
                n += 1
                try:
                    size += os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    pass
        return {"path": self.files_root, "files": n, "size": size,
                "size_text": fmt_size(size)}

    def stats(self) -> dict:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) total, "
                "SUM(CASE WHEN state='deleted' AND restored_at IS NULL "
                "THEN 1 ELSE 0 END) deleted, "
                "SUM(CASE WHEN state='active' AND restored_at IS NULL "
                "THEN 1 ELSE 0 END) active, "
                "SUM(CASE WHEN restored_at IS NOT NULL THEN 1 ELSE 0 END) restored "
                "FROM versions").fetchone()
            paths = self.conn.execute(
                "SELECT COUNT(DISTINCT orig_path) c FROM versions").fetchone()["c"]
        size = self.total_size()
        bst = self.bin_stats()
        return {
            "path": self.root,
            "bin_path": bst["path"],
            "bin_files": bst["files"],
            "bin_size_text": bst["size_text"],
            "versions": row["total"] or 0,
            "active": row["active"] or 0,
            "deleted": row["deleted"] or 0,
            "restored": row["restored"] or 0,
            "paths": paths,
            "size": size,
            "size_text": fmt_size(size),
            "max_size_gb": self.cfg.get("recycle_bin.max_size_gb", 0),
            "retention_days": self.cfg.get("recycle_bin.retention_days", 0),
        }

    def recent(self, limit: int = 10) -> list:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM versions ORDER BY stored_at DESC LIMIT ?",
                (int(limit),)).fetchall()
        return [dict(r) for r in rows]
