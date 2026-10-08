# -*- coding: utf-8 -*-
"""YAML 读写工具：安全加载 + 带注释渲染。

为什么不用 ``yaml.dump`` 直接输出：PyYAML 不保留注释，而本项目要求配置文件
自带每一项的说明。因此这里采用「注释元数据写在代码里 + 每次保存整体重新渲染」
的方式，好处是：

* 注释永远不会丢（Web 界面改完配置再保存，注释依旧在）；
* 升级版本新增配置项时，新项自动出现在用户文件里且自带注释；
* 注释里的默认值直接取自代码，不会和 ``DEFAULT_CONFIG`` 脱节。

标量输出严格遵守 YAML 1.1 的隐式类型规则（``yes/no/on/off``、纯数字、
``2026-09-30`` 这类日期形态一律加引号），避免出现「读回来类型变了」的问题。
"""
import json
import re

try:
    import yaml
except ImportError:  # pragma: no cover - 运行环境缺依赖时给出明确提示
    yaml = None


# 裸标量首字符不能是这些（YAML 指示符）
_BAD_FIRST = set("-?:,[]{}#&*!|>'\"%@`")
# 保留字：裸输出会被解析成布尔 / 空值
_RESERVED = {
    "true", "false", "yes", "no", "on", "off", "y", "n", "null", "none",
    "~", "nan", "inf", "-inf", "+inf",
}
_NUM_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")
# 日期 / 时间形态：PyYAML 的 safe_load 会解析成 date/datetime 对象
_DATE_RE = re.compile(r"^\d{4}-\d{1,2}-\d{1,2}([Tt ].*)?$")
_KEY_OK_RE = re.compile(r"^[A-Za-z_\u4e00-\u9fff][A-Za-z0-9_\u4e00-\u9fff\-]*$")


class YamlUnavailable(RuntimeError):
    """缺少 PyYAML 依赖。"""


def _require_yaml():
    if yaml is None:
        raise YamlUnavailable(
            "缺少 PyYAML 依赖，无法读写 YAML 配置。请执行：uv pip install pyyaml")
    return yaml


def is_plain_safe(s: str) -> bool:
    """判断字符串能否不加引号直接输出（保证 safe_load 读回完全相同的值）。"""
    if s == "" or s.strip() != s:
        return False
    if s.lower() in _RESERVED:
        return False
    if _NUM_RE.match(s) or _DATE_RE.match(s):
        return False
    if s[0] in _BAD_FIRST:
        return False
    if any(ch in s for ch in "\n\r\t\x00"):
        return False
    # `#` 一律加引号（避免被当成注释），`: ` 与行尾 `:` 会被当成映射分隔
    if "#" in s or ": " in s or s.endswith(":"):
        return False
    return True


def scalar(v) -> str:
    """把 Python 标量渲染成 YAML 标量文本。"""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    s = str(v)
    return s if is_plain_safe(s) else json.dumps(s, ensure_ascii=False)


def _key(k) -> str:
    s = str(k)
    return s if _KEY_OK_RE.match(s) else json.dumps(s, ensure_ascii=False)


def _comment_lines(text: str, indent: str, out: list) -> None:
    for line in str(text).splitlines():
        line = line.rstrip()
        out.append(f"{indent}# {line}" if line else f"{indent}#")


def _dump_mapping(data: dict, docs: dict, known: set, path: list,
                  out: list, indent: str, level: int,
                  unknown_note: str = "") -> None:
    pad = indent * level
    for k, v in data.items():
        p = ".".join(list(path) + [str(k)])
        note = docs.get(p)
        if note is None and known and p not in known:
            if unknown_note and level == 0:
                _comment_lines(unknown_note, pad, out)
            _comment_lines("自定义项：程序不认识的配置会被忽略，可安全删除", pad, out)
        elif note:
            for para in (note if isinstance(note, (list, tuple)) else [note]):
                _comment_lines(para, pad, out)

        if isinstance(v, dict):
            if v:
                out.append(f"{pad}{_key(k)}:")
                _dump_mapping(v, docs, known, list(path) + [str(k)], out,
                              indent, level + 1, unknown_note)
            else:
                out.append(f"{pad}{_key(k)}: {{}}")
        elif isinstance(v, (list, tuple)):
            if not v:
                out.append(f"{pad}{_key(k)}: []")
            else:
                out.append(f"{pad}{_key(k)}:")
                for item in v:
                    if isinstance(item, (dict, list, tuple)):
                        # 嵌套结构用行内 JSON 输出（JSON 是 YAML 的子集）
                        body = json.dumps(item, ensure_ascii=False)
                        out.append(f"{pad}{indent}- {body}")
                    else:
                        out.append(f"{pad}{indent}- {scalar(item)}")
        else:
            out.append(f"{pad}{_key(k)}: {scalar(v)}")


def dump(data: dict, docs: dict = None, known: set = None,
         header: str = "", indent: str = "  ") -> str:
    """把配置字典渲染成带注释的 YAML 文本。

    :param data:   配置数据
    :param docs:   ``{"monitor.paths": "说明文字或说明列表"}`` 形式的注释元数据
    :param known:  已知配置项的路径集合，用于给未知项加提示注释
    :param header: 文件头注释
    :param indent: 缩进串，默认两个空格
    """
    out = []
    header = (header or "").strip("\n")
    if header:
        for line in header.splitlines():
            out.append(("# " + line).rstrip())
        out.append("")
    _dump_mapping(data, docs or {}, known or set(), [], out, indent, 0)
    return "\n".join(out).rstrip("\n") + "\n"


def load_text(text: str) -> dict:
    """解析 YAML 文本，返回字典。空文件返回 {}。"""
    y = _require_yaml()
    try:
        data = y.safe_load(text)
    except y.YAMLError as e:
        raise ValueError(_friendly_error(e)) from e
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("配置文件顶层必须是一个键值映射（mapping）")
    return data


def load_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8-sig") as f:
        return load_text(f.read())


def _friendly_error(e) -> str:
    """把 PyYAML 的报错整理成用户看得懂的一行。"""
    msg = str(e)
    mark = getattr(e, "problem_mark", None)
    problem = getattr(e, "problem", "") or ""
    ctx = getattr(e, "context", "") or ""
    detail = problem or ctx or msg
    alias = {"expected <block end>, but found '<block mapping start>'":
             "缩进不正确（同一层级的多行必须对齐）",
             "mapping values are not allowed here":
             "值里出现了未加引号的 `: `，请给该值加英文双引号"}
    detail = alias.get(detail.strip(), detail)
    if mark is not None:
        return f"第 {mark.line + 1} 行第 {mark.column + 1} 列：{detail}"
    return detail
