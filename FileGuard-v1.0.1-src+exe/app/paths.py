# -*- coding: utf-8 -*-
"""路径工具：兼容开发态与 PyInstaller 打包态。"""
import os
import sys


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def base_dir() -> str:
    """配置文件 / 日志 / 回收站的基准目录（exe 所在目录，或项目根目录）。"""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_path(*parts) -> str:
    """读取随包分发的只读资源（静态文件等）。"""
    if is_frozen():
        root = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(sys.executable)))
    else:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, *parts)


def abspath(value: str) -> str:
    """相对路径统一挂到 base_dir 下，便于绿色部署。"""
    if not value:
        return value
    value = os.path.expandvars(os.path.expanduser(value))
    if not os.path.isabs(value):
        value = os.path.join(base_dir(), value)
    return os.path.normpath(value)


def ensure_dir(path: str) -> str:
    if path and not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
    return path
