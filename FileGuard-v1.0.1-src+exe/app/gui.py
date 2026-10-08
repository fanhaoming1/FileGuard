# -*- coding: utf-8 -*-
"""tkinter 控制台：开始 / 停止按钮 + 运行状态 + 日志输出 + 系统托盘。

关闭行为（产品约定，不可配置）
----------------------------
* 点窗口右上角 ×、或托盘菜单「退出界面」：**只隐藏界面**，监控服务继续在后台运行；
* 只有点击「停止服务」按钮（或 Web 界面上的同名按钮）才会真正停止服务；
* 服务未运行时关闭窗口 = 结束进程（此时没有服务可停止）。
"""
import ctypes
import os
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from . import paths
from .audit import is_admin
from .service import GuardService
from .tray import TrayIcon, tray_icon_path

FONT = ("Microsoft YaHei UI", 9)
FONT_B = ("Microsoft YaHei UI", 9, "bold")
FONT_T = ("Microsoft YaHei UI", 15, "bold")
FONT_MONO = ("Consolas", 9)

BG = "#f4f6fa"
CARD = "#ffffff"
LINE = "#e4e8f0"
TEXT = "#1e2a3a"
MUTED = "#6b7a90"
OK = "#15803d"
OFF = "#96a1b3"
DANGER = "#b91c1c"


def _dpi_aware():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class GuardGUI:
    def __init__(self, cfg):
        _dpi_aware()
        self.cfg = cfg
        self.q = queue.Queue(maxsize=2000)
        self.service = GuardService(cfg, ui_queue=self.q, on_status=self._on_status)
        self._busy = False
        self._lines = 0
        self.max_lines = int(cfg.get("app.max_gui_log_lines", 500))
        self._tray = None              # 懒创建：第一次隐藏时才挂托盘图标
        self._tray_notified = False
        self._hidden = False

        self.root = tk.Tk()
        self.root.title("FileGuard · 文件访问监控与删除保护")
        self.root.configure(bg=BG)
        # 任务栏 / 标题栏图标：优先用随包 ico；打包后从 exe 内嵌资源取，
        # 保证「最小化到托盘」和任务栏显示的都是 FileGuard 自己的图标。
        _ico = tray_icon_path()
        if _ico:
            try:
                self.root.iconbitmap(default=_ico)
            except Exception:
                pass
        self.root.minsize(860, 620)
        self._center(920, 690)
        self._build()
        self.refresh_config_view()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        note = self.cfg.migration_note()
        if note:
            self.root.after(400, lambda: self._append(f"[配置] {note}", "warn"))
        self._tick()
        self._append("欢迎使用 FileGuard。请点击「开始服务」启动监控。", "muted")
        self._append("提示：关闭本窗口不会停止服务（会隐藏到系统托盘），"
                     "要停止监控请点「停止服务」。", "muted")
        if not is_admin():
            self._append("[警告] 当前非管理员权限运行：无法配置审计策略与读取安全日志，"
                         "客户端访问记录将不可用。请以管理员身份重新运行。", "error")
        self._append(f"配置文件：{self.cfg.path}")

    # ---------------- 布局 ----------------
    def _center(self, w, h):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")

    def _build(self):
        # 顶部标题
        head = tk.Frame(self.root, bg=CARD, height=66)
        head.pack(fill="x")
        head.pack_propagate(False)
        tk.Label(head, text="FileGuard", font=FONT_T, bg=CARD, fg=TEXT).pack(
            side="left", padx=(20, 8), pady=14)
        tk.Label(head, text="共享文件访问监控 · 删除拦截 · 一键恢复",
                 font=FONT, bg=CARD, fg=MUTED).pack(side="left", pady=(22, 14))
        self.badge = tk.Label(head, text="● 已停止", font=FONT_B, bg=CARD, fg=OFF)
        self.badge.pack(side="right", padx=20)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=14)

        # 控制区
        ctrl = tk.Frame(body, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        ctrl.pack(fill="x")
        inner = tk.Frame(ctrl, bg=CARD)
        inner.pack(fill="x", padx=18, pady=18)

        self.btn_start = tk.Button(inner, text="▶  开始服务", font=("Microsoft YaHei UI", 12, "bold"),
                                   bg="#2563eb", fg="white", activebackground="#1d4ed8",
                                   activeforeground="white", disabledforeground="#cfe0ff",
                                   relief="flat", cursor="hand2",
                                   padx=30, pady=12, command=self.on_start)
        self.btn_start.pack(side="left")
        self.btn_stop = tk.Button(inner, text="■  停止服务", font=("Microsoft YaHei UI", 12, "bold"),
                                  bg="#e9edf4", fg="#39465a", activebackground="#dbe2ec",
                                  disabledforeground="#b6bfcc",
                                  relief="flat", cursor="hand2", padx=30, pady=12,
                                  state="disabled", command=self.on_stop)
        self.btn_stop.pack(side="left", padx=(12, 0))

        right = tk.Frame(inner, bg=CARD)
        right.pack(side="right")
        self.lbl_state = tk.Label(right, text="服务未运行", font=FONT_B, bg=CARD, fg=OFF)
        self.lbl_state.pack(anchor="e")
        self.lbl_sub = tk.Label(right, text="点击左侧按钮开始监控", font=FONT, bg=CARD, fg=MUTED)
        self.lbl_sub.pack(anchor="e")

        # 信息区
        info = tk.Frame(body, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        info.pack(fill="x", pady=(12, 0))
        grid = tk.Frame(info, bg=CARD)
        grid.pack(fill="x", padx=18, pady=16)
        grid.columnconfigure(1, weight=1)

        self.rows = {}
        items = [
            ("web", "Web 管理界面"),
            ("monitor", "监控目录"),
            ("recycle", "回收站"),
            ("purge", "自动清理"),
            ("logs", "日志目录"),
            ("auth", "登录账号"),
            ("audit", "审计状态"),
            ("action", "删除动作"),
            ("conf", "配置文件"),
        ]
        for i, (key, label) in enumerate(items):
            tk.Label(grid, text=label, font=FONT, bg=CARD, fg=MUTED, width=14,
                     anchor="w").grid(row=i, column=0, sticky="w", pady=3)
            val = tk.Label(grid, text="—", font=FONT, bg=CARD, fg=TEXT, anchor="w",
                           justify="left", wraplength=560)
            val.grid(row=i, column=1, sticky="w", pady=3)
            self.rows[key] = val
        buttons = [
            ("打开 Web 界面", self.on_open_web),
            ("打开日志目录", lambda: self._open(self.cfg.log_dir())),
            ("打开回收站目录", lambda: self._open(self.cfg.recycle_path())),
            ("打开监控目录", lambda: self._open_first()),
            ("编辑 config.yaml", self.on_edit_config),
            ("重新加载配置", self.on_reload_config),
            ("隐藏到系统托盘", lambda: self._hide_to_tray()),
        ]
        btn_row = len(items) + 1
        for col, (label, cmd) in enumerate(buttons):
            tk.Button(grid, text=label, font=FONT, relief="flat", bg="#eef2f8",
                      activebackground="#e2e8f2", cursor="hand2", padx=12, pady=5,
                      command=cmd).grid(row=btn_row + col // 3, column=col % 3,
                                        sticky="w", padx=(0, 8), pady=(10, 0))
        tk.Label(grid, text="关闭窗口只隐藏界面，服务继续后台运行；停止监控请点「停止服务」",
                 font=FONT, bg=CARD, fg=MUTED, anchor="w").grid(
            row=btn_row + (len(buttons) + 2) // 3, column=0, columnspan=3,
            sticky="w", pady=(10, 0))

        # 日志区
        logcard = tk.Frame(body, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        logcard.pack(fill="both", expand=True, pady=(12, 0))
        lh = tk.Frame(logcard, bg=CARD)
        lh.pack(fill="x", padx=18, pady=(12, 0))
        tk.Label(lh, text="运行日志", font=FONT_B, bg=CARD, fg=TEXT).pack(side="left")
        tk.Button(lh, text="清空", font=FONT, relief="flat", bg="#eef2f8", cursor="hand2",
                  padx=10, command=self._clear_log).pack(side="right")
        wrap = tk.Frame(logcard, bg=CARD)
        wrap.pack(fill="both", expand=True, padx=18, pady=(8, 16))
        self.txt = tk.Text(wrap, font=FONT_MONO, bg="#0f1b2d", fg="#cfe0f5", relief="flat",
                           wrap="word", height=10, insertbackground="#cfe0f5")
        sb = ttk.Scrollbar(wrap, command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)
        for tag, color in (("info", "#cfe0f5"), ("ok", "#7ee2a8"), ("warn", "#f5cf6b"),
                           ("error", "#ff9b9b"), ("muted", "#7d93b0")):
            self.txt.tag_config(tag, foreground=color)
        self.txt.configure(state="disabled")

    # ---------------- 按钮回调 ----------------
    def on_start(self):
        if self._busy:
            return
        self._busy = True
        self.btn_start.configure(state="disabled")
        self.lbl_state.configure(text="正在启动 ...", fg="#b45309")
        self.refresh_config_view()

        def work():
            res = self.service.start()
            self.root.after(0, lambda: self._after_toggle(True, res))
        threading.Thread(target=work, daemon=True, name="fg-start").start()

    def on_stop(self):
        if self._busy:
            return
        self._busy = True
        self.btn_stop.configure(state="disabled")
        self.lbl_state.configure(text="正在停止 ...", fg="#b45309")

        def work():
            res = self.service.stop()
            self.root.after(0, lambda: self._after_toggle(False, res))
        threading.Thread(target=work, daemon=True, name="fg-stop").start()

    def _after_toggle(self, started, res):
        self._busy = False
        ok = bool(res.get("ok"))
        if started and not ok:
            self.btn_start.configure(state="normal")
            self._append(f"[启动失败] {res.get('message')}", "error")
            messagebox.showerror("启动失败", res.get("message", "未知错误"))
        elif not started and not ok:
            self.btn_stop.configure(state="normal")
            self._append(f"[提示] {res.get('message')}", "warn")
        self._on_status(self.service.status())

    def on_open_web(self):
        if not self.service.running:
            if not messagebox.askyesno("服务未运行", "服务尚未启动，Web 界面无法访问。现在启动服务吗？"):
                return
            self.on_start()
            return
        webbrowser.open(self.service.web_url())

    def on_edit_config(self):
        """用记事本打开 config.yaml（.yaml 在 Windows 上没有默认关联程序）。"""
        try:
            self.cfg.save()   # 确保文件存在且带完整注释
        except Exception:
            pass
        try:
            import subprocess
            subprocess.Popen(["notepad.exe", self.cfg.path])
        except Exception:
            try:
                os.startfile(self.cfg.path)
            except Exception as e:
                messagebox.showerror("打开失败", f"无法打开配置文件：{e}\n\n{self.cfg.path}")

    def on_reload_config(self):
        try:
            self.cfg.load()
            self.refresh_config_view()
            note = self.cfg.migration_note()
            self._append(f"[配置] 已重新加载 {os.path.basename(self.cfg.path)}"
                         "（监控目录等变更需重启服务生效）", "ok")
            if note:
                self._append(f"[配置] {note}", "warn")
        except Exception as e:
            self._append(f"[配置] 重新加载失败：{e}", "error")

    def _open(self, path):
        try:
            os.makedirs(path, exist_ok=True)
            os.startfile(path)
        except Exception as e:
            messagebox.showerror("打开失败", f"{path}\n{e}")

    def _open_first(self):
        p = self.cfg.monitor_paths()
        if not p:
            messagebox.showwarning("提示", "尚未配置监控目录，请编辑 config.yaml")
            return
        self._open(p[0])

    DELETE_ACTION_TEXT = {
        "move_to_bin": "删除后把文件移入回收站目录（Web 界面可一键恢复）",
        "restore": "删除后立即还原回原路径（对客户端表现为「删不掉」）",
        "record": "仅记录删除并保留回收站内容库（不落实体文件）",
    }

    def _delete_action_text(self) -> str:
        a = self.cfg.delete_action()
        return f"{a} —— {self.DELETE_ACTION_TEXT.get(a, '')}"

    # ---------------- 状态刷新 ----------------
    def _on_status(self, st):
        running = bool(st.get("running"))
        self.badge.configure(text="● 运行中" if running else "● 已停止",
                             fg=OK if running else OFF)
        self.lbl_state.configure(text="服务运行中" if running else "服务未运行",
                                 fg=OK if running else OFF)
        pr = st.get("protector", {}) or {}
        self.lbl_sub.configure(text=(f"已运行 {st.get('uptime', 0) // 60} 分钟，"
                                     f"归档 {pr.get('archived', 0)} 次，"
                                     f"删除 {pr.get('deletes', 0)} 次"
                                     f"（移入回收站 {pr.get('moved', 0)} 次）")
                               if running else "点击左侧按钮开始监控")
        self.btn_start.configure(state="disabled" if running or self._busy else "normal")
        self.btn_stop.configure(state="normal" if running and not self._busy else "disabled")
        if self._tray is not None and self._tray.running:
            try:
                self._tray.set_tooltip(self._tray_tip())
            except Exception:
                pass
        self.refresh_config_view(st)

    def refresh_config_view(self, st=None):
        st = st or self.service.status()
        url = st.get("web_url") or self.service.web_url()
        self.rows["web"].configure(text=url + ("（服务运行中）" if st.get("running") else "（启动服务后可用）"))
        self.rows["monitor"].configure(text="\n".join(st.get("monitor_paths") or ["未配置"]))
        rc = st.get("recycle") or {}
        if rc:
            self.rows["recycle"].configure(
                text=f"{rc.get('path')}　|　版本 {rc.get('versions')} 个，"
                     f"已删除 {rc.get('deleted')} 个，占用 {rc.get('size_text')}\n"
                     f"可见回收站：{rc.get('bin_path')}　|　"
                     f"{rc.get('bin_files', 0)} 个文件，{rc.get('bin_size_text', '-')}")
        else:
            self.rows["recycle"].configure(
                text=f"{self.cfg.recycle_path()}\n可见回收站：{self.cfg.bin_files_dir()}")
        self.rows["logs"].configure(text=str(self.cfg.log_dir()))
        pg = st.get("purge") or self.service.purge_snapshot()
        if not pg.get("enabled"):
            self.rows["purge"].configure(text="已关闭（recycle_bin.auto_purge = false）")
        else:
            txt = pg.get("schedule_text", "")
            if pg.get("next_run"):
                txt += f"\n下次清理：{pg['next_run']}"
            else:
                txt += "（服务停止中，启动后生效）"
            last = pg.get("last") or {}
            if last.get("ts"):
                txt += (f"　|　上次：{last['ts']} 清理 {last.get('removed', 0)} 个"
                        f"（{last.get('reason', '')}）")
            self.rows["purge"].configure(text=txt)
        self.rows["conf"].configure(text=str(self.cfg.path) + "（YAML 格式，点下方「编辑 config.yaml」打开）")
        self.rows["action"].configure(text=self._delete_action_text())
        self.rows["auth"].configure(
            text=f"{self.cfg.get('web.username')} / {self.cfg.get('web.password')}"
                 "　（浏览器登录用）")
        au = st.get("audit") or {}
        if not st.get("running"):
            txt = "待服务启动后生效"
        elif au.get("enabled") is False:
            txt = "已关闭（audit.enabled = false）"
        elif not is_admin():
            txt = "不可用：需以管理员身份运行"
        elif au.get("available") is False:
            txt = f"不可用：{au.get('reason')}"
        elif au.get("running"):
            txt = f"正常，已采集 {au.get('collected', 0)} 条安全事件"
        else:
            txt = "待服务启动后生效"
        self.rows["audit"].configure(text=txt)

    # ---------------- 日志输出 ----------------
    def _append(self, text, level="info"):
        self.txt.configure(state="normal")
        self.txt.insert("end", text + "\n", level)
        self._lines += 1
        if self._lines > self.max_lines:
            self.txt.delete("1.0", f"{self._lines - self.max_lines}.0")
            self._lines = self.max_lines
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def _clear_log(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")
        self._lines = 0

    def _tick(self):
        drained = 0
        while drained < 60:
            try:
                rec = self.q.get_nowait()
            except queue.Empty:
                break
            drained += 1
            self._append(f"[{rec.get('ts', '')}] {rec.get('text', '')}",
                         rec.get("level", "info"))
        if drained:
            self.refresh_config_view()
        # 托盘菜单动作由主线程消费（tkinter 不是线程安全的）
        if self._tray is not None:
            for action in self._tray.poll():
                self._on_tray_action(action)
        self.root.after(400, self._tick)

    # ---------------- 关闭 / 托盘 ----------------
    def _on_close(self):
        """窗口的 × ：只隐藏界面，绝不停止服务。"""
        if self.service.running:
            self._hide_to_tray()
            return
        # 服务没在跑，关掉窗口就等于结束程序
        self._really_exit()

    def _ensure_tray(self) -> bool:
        """按需创建托盘图标，返回是否可用。"""
        if self._tray is not None and self._tray.running:
            return True
        try:
            tray = TrayIcon(tooltip=self._tray_tip(), icon_path=tray_icon_path())
            if tray.start():
                self._tray = tray
                return True
            self._tray = tray
        except Exception as e:
            self._append(f"[提示] 系统托盘不可用：{e}", "warn")
            self._tray = None
        return False

    def _tray_tip(self) -> str:
        st = "运行中" if (self.service and self.service.running) else "已停止"
        return f"FileGuard · 服务{st}"

    def _hide_to_tray(self, quiet: bool = False):
        """隐藏主窗口，服务继续在后台运行。"""
        tray_ok = self._ensure_tray()
        if tray_ok:
            try:
                self.root.withdraw()
                self._hidden = True
                self._tray.set_tooltip(self._tray_tip())
                if not self._tray_notified:
                    self._tray_notified = True
                    self._tray.notify(
                        "FileGuard 仍在后台运行",
                        "监控服务没有被关闭，文件保护继续生效。\n"
                        "双击托盘图标可重新打开主界面；要停止监控请点「停止服务」。")
            except Exception as e:
                self._append(f"[提示] 隐藏窗口失败：{e}", "warn")
                return
        else:
            # 托盘不可用时退化为最小化，避免窗口消失后无法恢复
            try:
                self.root.iconify()
            except Exception:
                pass
        if not quiet:
            self._append("[提示] 主窗口已隐藏到系统托盘，服务继续在后台运行"
                         "（要停止监控请点「停止服务」）。", "muted")

    def _show_window(self):
        self._hidden = False
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass

    def _on_tray_action(self, action: str):
        if action == "show":
            self._show_window()
        elif action == "web":
            if self.service.running:
                try:
                    webbrowser.open(self.service.web_url())
                except Exception as e:
                    self._append(f"打开浏览器失败：{e}", "warn")
            else:
                self._show_window()
                messagebox.showinfo("服务未运行", "服务尚未启动，请先点击「开始服务」。")
        elif action == "exit":
            self._on_tray_exit()

    def _on_tray_exit(self):
        """托盘菜单「退出界面」：界面关闭，服务继续后台运行。"""
        if self.service.running:
            already_hidden = self._hidden
            self._hide_to_tray(quiet=already_hidden)
            if not already_hidden:
                self._append("[提示] 已关闭主界面，服务继续在后台运行"
                             "（托盘图标可重新打开界面；停止服务请点「停止服务」）。",
                             "muted")
            return
        self._really_exit()

    def _stop_tray(self):
        t, self._tray = self._tray, None
        if t is not None:
            try:
                t.stop()
            except Exception:
                pass

    def _really_exit(self):
        """真正结束程序（仅在服务未运行时调用）。"""
        self._stop_tray()
        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self):
        self.root.mainloop()


def main():
    from .config import load_config
    cfg = load_config()
    GuardGUI(cfg).run()
