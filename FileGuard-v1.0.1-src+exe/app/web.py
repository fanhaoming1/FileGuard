# -*- coding: utf-8 -*-
"""Web 服务：内置 Flask，提供访问/删除记录查看、回收站一键恢复与配置管理。"""
import csv
import hmac
import io
import json
import logging
import os
import threading
import time

from flask import (Flask, Response, jsonify, request, session)

from . import paths
from .logger import now_iso


def _ok(data=None, **kw):
    body = {"ok": True}
    if data is not None:
        body["data"] = data
    body.update(kw)
    return jsonify(body)


def _err(message, code=400, **kw):
    body = {"ok": False, "error": message}
    body.update(kw)
    return jsonify(body), code


class WebServer:
    def __init__(self, service):
        self.service = service
        self.cfg = service.cfg
        self.app = self._build_app()
        self._server = None
        self._thread = None
        self.state = {"running": False, "last_error": "", "requests": 0}
        self._html = self._load_html()

    # ---------------- 静态页面 ----------------
    @staticmethod
    def _load_html() -> str:
        path = paths.resource_path("app", "static", "index.html")
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ("<h1>FileGuard</h1><p>未找到界面文件 app/static/index.html，"
                    "请检查安装包是否完整。</p>")

    # ---------------- 鉴权 ----------------
    def _password_set(self) -> bool:
        """是否需要登录校验：require_login 关闭，或密码为空时都不校验。"""
        if not self.cfg.get("web.require_login", True):
            return False
        return bool(self.cfg.get("web.password"))

    def _authed(self) -> bool:
        if not self._password_set():
            return True
        return bool(session.get("fg_auth"))

    def _check_login(self):
        body = request.get_json(silent=True) or {}
        user = str(body.get("username", "")).strip()
        pwd = str(body.get("password", ""))
        want_user = str(self.cfg.get("web.username", "admin"))
        want_pwd = str(self.cfg.get("web.password", ""))
        if not self._password_set():
            return True
        return (hmac.compare_digest(user, want_user) and
                hmac.compare_digest(pwd, want_pwd))

    # ---------------- Flask 应用 ----------------
    def _build_app(self) -> Flask:
        app = Flask("fileguard")
        app.config["SECRET_KEY"] = self.cfg.get("web.session_secret") or "fileguard"
        app.config["JSON_AS_ASCII"] = False
        app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024

        @app.after_request
        def _no_cache(resp):
            if request.path.startswith("/api/"):
                resp.headers["Cache-Control"] = "no-store"
            self.state["requests"] += 1
            return resp

        @app.before_request
        def _guard():
            p = request.path
            if p == "/" or not p.startswith("/api/"):
                return None
            if p in ("/api/ping", "/api/login", "/api/logout"):
                return None
            if not self._authed():
                return _err("未登录或会话已过期", 401, need_login=True)
            return None

        # ---------- 页面 ----------
        @app.route("/")
        def index():
            return Response(self._html, mimetype="text/html; charset=utf-8")

        @app.route("/favicon.ico")
        def favicon():
            return Response(status=204)

        # ---------- 会话 ----------
        @app.route("/api/ping")
        def ping():
            return _ok({"need_login": self._password_set(), "auth": self._authed(),
                        "app": "FileGuard", "version": "1.0.0", "server_time": now_iso()})

        @app.route("/api/login", methods=["POST"])
        def login():
            if self._check_login():
                session["fg_auth"] = True
                session.permanent = True
                return _ok({"message": "登录成功"})
            time.sleep(0.4)
            return _err("用户名或密码错误", 401)

        @app.route("/api/logout", methods=["POST"])
        def logout():
            session.clear()
            return _ok({"message": "已退出登录"})

        # ---------- 状态 ----------
        @app.route("/api/status")
        def status():
            st = self.service.status()
            st["web"] = dict(self.state)
            return _ok(st)

        @app.route("/api/events")
        def events():
            limit = int(request.args.get("limit", 40))
            return _ok(self.service.recent_events(limit))

        # ---------- 日志 ----------
        def _log_query(which: str):
            logs = self.service.logs
            if logs is None:
                return _err("服务未运行，日志不可用", 409)
            lg = logs.access if which == "access" else logs.delete
            args = request.args
            res = lg.query(
                page=int(args.get("page", 1) or 1),
                size=int(args.get("size", self.cfg.get("web.page_size", 50)) or 50),
                keyword=args.get("q", ""),
                user=args.get("user", ""),
                op=args.get("op", ""),
                start=args.get("start", ""),
                end=args.get("end", ""),
            )
            res["log"] = lg.stat()
            return _ok(res)

        @app.route("/api/logs/access")
        def logs_access():
            return _log_query("access")

        @app.route("/api/logs/delete")
        def logs_delete():
            return _log_query("delete")

        @app.route("/api/logs/export")
        def logs_export():
            logs = self.service.logs
            if logs is None:
                return _err("服务未运行", 409)
            which = request.args.get("type", "access")
            lg = logs.access if which == "access" else logs.delete
            rows = lg.tail(20000)
            cols = ["ts", "op", "path", "name", "user", "ip", "client", "ip_source",
                    "size_text", "source", "event_id", "action", "bin_path",
                    "version_id", "restored", "restore_path", "sha256",
                    "share", "access_list", "detail", "note"]
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(cols)
            for r in rows:
                w.writerow([r.get(c, "") for c in cols])
            data = "\ufeff" + buf.getvalue()
            fn = f"{which}_log_{time.strftime('%Y%m%d_%H%M%S')}.csv"
            return Response(data, mimetype="text/csv; charset=utf-8",
                            headers={"Content-Disposition": f'attachment; filename="{fn}"'})

        # ---------- 回收站 ----------
        @app.route("/api/recycle")
        def recycle_list():
            rb = self.service.recycle
            if rb is None:
                return _err("服务未运行，回收站不可用", 409)
            a = request.args
            # 默认只列「已删除且未恢复」的内容 —— 回收站里只应该有可恢复的数据
            res = rb.query(page=int(a.get("page", 1) or 1),
                           size=int(a.get("size", self.cfg.get("web.page_size", 50)) or 50),
                           state=a.get("state", "deleted"), keyword=a.get("q", ""),
                           path=a.get("path", ""), actor=a.get("actor", ""))
            res["stats"] = rb.stats()
            return _ok(res)

        @app.route("/api/recycle/restore", methods=["POST"])
        def recycle_restore():
            rb = self.service.recycle
            if rb is None:
                return _err("服务未运行", 409)
            body = request.get_json(silent=True) or {}
            ids = body.get("ids") or ([body["id"]] if body.get("id") else [])
            if not ids:
                return _err("未指定要恢复的版本 id")
            prot = self.service.protector
            if prot is not None:
                res = prot.restore_many_safe(ids, policy=body.get("policy", ""))
            else:
                res = rb.restore_many(ids, policy=body.get("policy", ""))
            self.service.emit(f"[回收站] 恢复 {res.get('ok', 0)} 个文件，"
                              f"失败 {res.get('failed', 0)} 个",
                              "ok" if res.get("failed", 0) == 0 else "warn")
            return _ok(res)

        @app.route("/api/recycle/delete", methods=["POST"])
        def recycle_delete():
            rb = self.service.recycle
            if rb is None:
                return _err("服务未运行", 409)
            body = request.get_json(silent=True) or {}
            ids = body.get("ids") or []
            n = 0
            for vid in ids:
                if rb.delete_version(int(vid)).get("ok"):
                    n += 1
            return _ok({"removed": n})

        @app.route("/api/recycle/empty", methods=["POST"])
        def recycle_empty():
            rb = self.service.recycle
            if rb is None:
                return _err("服务未运行", 409)
            res = rb.empty()
            self.service.emit(f"[回收站] 已清空，移除 {res.get('removed', 0)} 个历史版本", "warn")
            return _ok(res)

        @app.route("/api/recycle/purge", methods=["POST"])
        def recycle_purge():
            rb = self.service.recycle
            if rb is None:
                return _err("服务未运行", 409)
            return _ok(rb.purge_now())

        # ---------- 配置 ----------
        @app.route("/api/config", methods=["GET"])
        def config_get():
            return _ok({"config": self.cfg.as_dict(), "text": self.cfg.yaml_text(),
                        "path": self.cfg.path, "format": "yaml",
                        "validate": self.cfg.validate()})

        @app.route("/api/config", methods=["POST"])
        def config_set():
            body = request.get_json(silent=True) or {}
            new = body.get("config")
            if not isinstance(new, dict):
                return _err("请求体需要包含 config 对象")
            old_port = self.cfg.get("web.port")
            self.cfg.update(new)
            need_restart = self.cfg.get("web.port") != old_port
            v = self.cfg.validate()
            self.service.emit(f"[配置] 配置已更新并保存到 {os.path.basename(self.cfg.path)}",
                              "ok" if v["ok"] else "warn")
            return _ok({"message": "已保存", "need_restart": need_restart, "validate": v})

        @app.route("/api/config/raw", methods=["GET"])
        def config_raw():
            """返回带注释的 YAML 全文，供配置页直接编辑。"""
            return _ok({"text": self.cfg.yaml_text(), "path": self.cfg.path,
                        "format": "yaml", "validate": self.cfg.validate()})

        @app.route("/api/config/raw", methods=["POST"])
        def config_save_raw():
            """接收 YAML 全文并保存（保存时会重新渲染注释）。"""
            body = request.get_json(silent=True) or {}
            text = body.get("text")
            if not isinstance(text, str) or not text.strip():
                return _err("请求体需要包含非空的 text 字段（YAML 全文）")
            old_port = self.cfg.get("web.port")
            try:
                self.cfg.save_text(text)
            except Exception as e:
                return _err(f"YAML 解析失败：{e}", 400)
            need_restart = self.cfg.get("web.port") != old_port
            v = self.cfg.validate()
            self.service.emit(
                f"[配置] 配置已保存到 {os.path.basename(self.cfg.path)}"
                + ("" if v["ok"] else "（存在校验错误，请检查）"), "ok" if v["ok"] else "warn")
            return _ok({"message": "已保存", "need_restart": need_restart,
                        "validate": v, "text": self.cfg.yaml_text()})

        # ---------- 服务控制 ----------
        @app.route("/api/service/<action>", methods=["POST"])
        def service_action(action):
            if action == "start":
                return _ok(self.service.start())
            if action == "stop":
                return _ok(self.service.stop())
            if action == "restart":
                return _ok(self.service.restart())
            return _err("未知操作")

        return app

    # ---------------- 启动 / 停止 ----------------
    def start(self) -> None:
        from werkzeug.serving import make_server
        # 请求日志由本程序自己的日志体系覆盖，避免 werkzeug 往无控制台环境刷屏
        wlog = logging.getLogger("werkzeug")
        wlog.setLevel(logging.WARNING)
        if not wlog.handlers:
            wlog.addHandler(logging.NullHandler())
        host = self.cfg.get("web.host", "0.0.0.0")
        port = int(self.cfg.get("web.port", 8765))
        try:
            self._server = make_server(host, port, self.app, threaded=True)
        except OSError as e:
            self.state["last_error"] = f"端口 {port} 无法监听：{e}"
            self.service.emit(f"[Web] 启动失败：{self.state['last_error']}", "error")
            raise
        self._thread = threading.Thread(target=self._serve, daemon=True, name="fg-web")
        self._thread.start()
        self.state["running"] = True
        self.state["last_error"] = ""

    def _serve(self) -> None:
        try:
            self._server.serve_forever()
        except Exception:
            pass

    def stop(self) -> None:
        srv, self._server = self._server, None
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        t, self._thread = self._thread, None
        if t is not None:
            t.join(timeout=5)
        self.state["running"] = False
