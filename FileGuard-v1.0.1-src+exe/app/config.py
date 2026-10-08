# -*- coding: utf-8 -*-
"""配置管理：默认配置、注释元数据、YAML 读写与校验。

配置文件为 exe 同目录下的 ``config.yaml``（可用环境变量 ``FILEGUARD_CONFIG``
覆盖，便于多实例 / 测试）。每次保存都会按 ``DEFAULT_CONFIG`` 的结构重新渲染
全文，因此每一项配置的注释永远存在、且默认值描述不会与代码脱节。
"""
import copy
import datetime
import json
import os
import secrets
import threading

from . import paths, yamlconf
from .logger import DATE_TOKEN

# 配置文件
CONFIG_NAME = "config.yaml"
LEGACY_NAMES = ("config.json", "config.json.bak")


def default_config_path() -> str:
    """支持通过环境变量 FILEGUARD_CONFIG 指定配置文件（便于多实例 / 测试）。"""
    return os.environ.get("FILEGUARD_CONFIG") or os.path.join(paths.base_dir(), CONFIG_NAME)


CONFIG_FILE = os.path.join(paths.base_dir(), CONFIG_NAME)

DEFAULT_CONFIG = {
    "monitor": {
        "paths": ["D:\\Share"],
        "recursive": True,
        "include_extensions": ["*"],
        "exclude_patterns": ["~$*", "*.tmp", "*.temp", "*.bak", "*.swp", "Thumbs.db",
                             "desktop.ini", ".~lock.*", "*.crdownload", "*.part",
                             "*.fg_tmp_restore"],
        "max_file_size_mb": 0,
        "seed_on_start": True,
        "log_changes": True
    },
    "protection": {
        "enabled": True,
        "strategy": "mirror",
        "on_delete_action": "move_to_bin",
        "restore_conflict_policy": "rename",
        "restore_suffix": " (已恢复)",
        "archive_on_create": True,
        "debounce_seconds": 1.5,
        "max_restore_per_10min": 10,
        "actor_backfill_ms": 2500
    },
    "recycle_bin": {
        "path": "D:\\FileGuardRecycle",
        "retention_days": 30,
        "max_size_gb": 20,
        "auto_purge": True,
        "purge_interval_days": 1,
        "purge_at_hour": 3,
        "keep_versions_per_file": 5,
        "remove_bin_copy_on_restore": True
    },
    "log": {
        "dir": "D:\\FileGuardLogs",
        "access_file": "access_" + DATE_TOKEN + ".log",
        "delete_file": "delete_" + DATE_TOKEN + ".log",
        "date_format": "%Y%m%d",
        "max_size_mb": 50,
        "backup_count": 5,
        "retention_days": 90,
        "encoding": "utf-8",
        "max_scan_lines": 200000
    },
    "audit": {
        "enabled": True,
        "auto_configure": True,
        "scopes": ["share", "delete"],
        "object_mask": ["DELETE", "FILE_DELETE_CHILD"],
        "principal": "Everyone",
        "poll_interval_seconds": 2,
        "overlap_seconds": 15,
        "batch_size": 500,
        "dedup_seconds": 2,
        "skip_loopback": False,
        "read_extensions": [],
        "ip_cache_minutes": 30,
        "session_lookup": True,
        "session_cache_seconds": 30
    },
    "web": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 8765,
        "open_browser_on_start": False,
        "username": "admin",
        "password": "",
        "require_login": True,
        "page_size": 50,
        "session_secret": ""
    },
    "app": {
        "log_level": "INFO",
        "single_instance": True,
        "max_gui_log_lines": 500
    }
}

# ---------------------------------------------------------------------------
# 配置项注释元数据：每个配置项的用途 / 取值范围 / 默认值。
# 文本中的 {default} 会在渲染时替换成 DEFAULT_CONFIG 里的真实默认值。
# 这些注释会被写入用户磁盘上的 config.yaml。
# ---------------------------------------------------------------------------
_NODE_DOC = {
    "monitor": [
        "监控设置：要盯住哪些共享目录、盯到什么程度",
    ],
    "monitor.paths": [
        "需要监控的共享文件夹（填服务器的本地绝对路径，不是 UNC 路径）",
        "取值：路径列表，可写多个；支持相对路径（相对于本程序所在目录）",
        "默认值：{default}",
    ],
    "monitor.recursive": [
        "是否递归监控子目录",
        "取值：true / false",
        "默认值：{default}",
    ],
    "monitor.include_extensions": [
        "只监控这些扩展名（白名单）",
        "取值：扩展名列表，支持 * 通配；[\"*\"] 表示全部文件",
        "默认值：{default}",
    ],
    "monitor.exclude_patterns": [
        "忽略这些文件名（黑名单，优先级高于白名单），避免把 Office 临时文件当成正式文件",
        "取值：文件名通配符列表，支持 * 与 ?",
        "默认值：{default}",
    ],
    "monitor.max_file_size_mb": [
        "单个文件超过该大小则只记录日志、不做镜像存档（保护磁盘）",
        "取值：整数 ≥ 0，单位 MB；0 表示不限制",
        "默认值：{default}",
    ],
    "monitor.seed_on_start": [
        "服务启动时对监控目录做一次全量初始镜像（建立基线，保证存量文件删除也能还原）",
        "取值：true / false；目录很大时首次启动会慢几分钟",
        "默认值：{default}",
    ],
    "monitor.log_changes": [
        "是否把本地文件系统变更（创建 / 修改 / 重命名）也写入访问日志",
        "取值：true / false；关闭后访问日志只保留来自 Windows 安全审计的访问记录",
        "默认值：{default}",
    ],

    "protection": [
        "文件保护：如何在文件被删除时保住数据",
    ],
    "protection.enabled": [
        "是否启用文件保护（关闭后只记录日志，不再接管删除、不再把内容搬进回收站）",
        "取值：true / false",
        "默认值：{default}",
    ],
    "protection.strategy": [
        "存档策略（决定「删除时能不能把文件搬进回收站」）",
        "mirror = 实时镜像存档：文件一创建/修改就存一份，删除时能 100% 搬进回收站（推荐）",
        "event  = 仅捕获删除事件：省磁盘，但创建后瞬间被删的文件无法保证被存档",
        "取值：mirror / event",
        "默认值：{default}",
    ],
    "protection.on_delete_action": [
        "文件被客户端删除时的处理动作",
        "move_to_bin = 删除照常生效，程序把该文件（最新存档版本）搬进回收站目录下的实体文件，Web 界面可一键恢复（推荐）",
        "restore     = 立即把文件还原回原路径，对使用者表现为「删不掉」（旧版本行为）",
        "record      = 只把内容留在回收站内容库里（blobs），不在回收站目录生成实体文件",
        "取值：move_to_bin / restore / record",
        "兼容说明：旧配置项 auto_restore_on_delete 已由本项取代，升级后该项自动失效",
        "默认值：{default}",
    ],
    "protection.restore_conflict_policy": [
        "还原时目标路径已存在同名文件怎么办（例如用户删掉后马上又建了一个新的）",
        "overwrite = 覆盖 | rename = 改名保存 | skip = 跳过不还原",
        "取值：overwrite / rename / skip",
        "默认值：{default}",
    ],
    "protection.restore_suffix": [
        "restore_conflict_policy=rename 时，给还原出来的文件加的后缀",
        "取值：任意字符串（允许为空）",
        "默认值：{default}",
    ],
    "protection.archive_on_create": [
        "文件一创建就先存档（配合 strategy=mirror 使用）",
        "取值：true / false",
        "默认值：{default}",
    ],
    "protection.debounce_seconds": [
        "同一路径连续变更后，等多久再存档（避免大文件边写边存产生大量版本）",
        "取值：0.5 ~ 30 的浮点数，单位秒；值越小越及时、磁盘写入越多",
        "默认值：{default}",
    ],
    "protection.max_restore_per_10min": [
        "同一路径 10 分钟内最多自动还原几次（仅 on_delete_action=restore 时有效，防还原-删除死循环）",
        "取值：整数 ≥ 0；0 表示不限制",
        "默认值：{default}",
    ],
    "protection.actor_backfill_ms": [
        "写入删除日志前，额外等待多久去把「是谁删的 / 客户端 IP」补全（安全审计事件总比文件系统事件晚到 1~3 秒）",
        "取值：整数 0 ~ 8000，单位毫秒；0 = 不等，立即写日志（本机删除显示「未知」）",
        "实际生效值会自动抬到「审计轮询间隔 + 1.5 秒」以上，保证审计事件来得及采到",
        "默认值：{default}",
    ],

    "recycle_bin": [
        "回收站：被删除文件的存放与恢复仓库",
        "目录结构：files/ 下是被删除文件的实体副本（保留原盘符与目录结构，可直接在资源管理器里翻找），",
        "          blobs/ 是内容寻址（SHA-256）去重存档，index.db 是版本索引",
    ],
    "recycle_bin.path": [
        "回收站数据存放目录（务必放在监控目录之外，且预留足够磁盘空间）",
        "取值：绝对路径或相对路径（相对于本程序所在目录）",
        "默认值：{default}",
    ],
    "recycle_bin.retention_days": [
        "历史版本保留天数，超期自动清理（同时清掉回收站目录里的实体副本）",
        "取值：整数 ≥ 0，单位天；0 表示永久保留（不按时间清理）",
        "默认值：{default}",
    ],
    "recycle_bin.max_size_gb": [
        "回收站容量上限，超出后从最旧的已删除版本开始清理",
        "取值：数字 ≥ 0，单位 GB；0 表示不限制容量",
        "默认值：{default}",
    ],
    "recycle_bin.auto_purge": [
        "是否按下面的保留天数 / 容量上限自动清理（建议保持 true，否则磁盘会持续增长）",
        "取值：true / false",
        "默认值：{default}",
    ],
    "recycle_bin.purge_interval_days": [
        "自动清理的周期：每隔多少天清理一次回收站",
        "清理内容 = 超过 recycle_bin.retention_days 的已删除版本 + 超出 max_size_gb 的旧版本",
        "取值：整数 ≥ 1，单位「天」（1 = 每天一次，7 = 每周一次）",
        "说明：服务每次启动后也会先清理一次；需要不等周期立即清理时，",
        "      点 Web 概览页的「立即清理」或 GUI 的「清理回收站」即可",
        "默认值：{default}",
    ],
    "recycle_bin.purge_at_hour": [
        "每天在几点执行自动清理（建议放在夜间低峰，减少对共享盘的影响）",
        "取值：0~23 的整数（小时，24 小时制）；-1 表示不指定时点，按启动时刻起算周期",
        "默认值：{default}",
    ],
    "recycle_bin.keep_versions_per_file": [
        "每个文件最多保留多少个历史版本，超出的最旧版本会被清理",
        "取值：整数 ≥ 1；不会清理该文件的最新版本",
        "默认值：{default}",
    ],
    "recycle_bin.remove_bin_copy_on_restore": [
        "在 Web 界面一键恢复成功后，是否删掉回收站目录里的那份实体副本",
        "取值：true / false；false 表示恢复后回收站里仍保留一份副本",
        "默认值：{default}",
    ],

    "log": [
        "日志：access_{date}.log 记录访问、delete_{date}.log 记录删除，",
        "均为一行一个 JSON 的 JSONL 格式；{date} 会替换成当天的日期（见 log.date_format）",
    ],
    "log.dir": [
        "日志目录（与回收站分开放，便于单独备份 / 归档）",
        "取值：绝对路径或相对路径（相对于本程序所在目录）",
        "默认值：{default}",
    ],
    "log.access_file": [
        "访问日志文件名模板，{date} 会被替换成当天日期",
        "例如默认值在 2026-09-30 这天产出 access_20260930.log",
        "取值：文件名（不含路径）；写死不带 {date} 则退化为单文件 + 按大小轮转",
        "默认值：{default}",
    ],
    "log.delete_file": [
        "删除日志文件名模板，{date} 会被替换成当天日期",
        "例如默认值在 2026-09-30 这天产出 delete_20260930.log",
        "取值：文件名（不含路径）",
        "默认值：{default}",
    ],
    "log.date_format": [
        "{date} 占位符的日期格式（Python strftime 语法）",
        "默认 %Y%m%d 即 20260930；改成 %Y-%m-%d 则产出 access_2026-09-30.log",
        "默认值：{default}",
    ],
    "log.max_size_mb": [
        "单个（当日）日志文件达到该大小后的处理",
        "按天模式：在当天内继续分片，如 access_20260930_1.log、_2.log …",
        "单文件模式：轮转为 access.log.1 ~ .N",
        "取值：整数 ≥ 1，单位 MB",
        "默认值：{default}",
    ],
    "log.backup_count": [
        "轮转后最多保留多少个分片文件（按天模式为当日分片数，单文件模式为 .1 ~ .N）",
        "取值：整数 ≥ 0；0 表示不分片（按天模式下当天文件持续追加）",
        "默认值：{default}",
    ],
    "log.retention_days": [
        "历史日志文件保留天数：超过该天数的 access_/delete_ 日志会被自动清理",
        "取值：整数 ≥ 0；0 表示永久保留（不自动清理）",
        "默认值：{default}",
    ],
    "log.encoding": [
        "日志文件编码",
        "取值：utf-8 或 gbk（老工具链才需要改成 gbk）",
        "默认值：{default}",
    ],
    "log.max_scan_lines": [
        "Web 界面查询日志时最多倒序扫描的行数（防止超大日志把内存吃满）",
        "取值：整数 ≥ 1000",
        "默认值：{default}",
    ],

    "audit": [
        "Windows 安全审计：用来回答「是哪个客户端 IP 的哪个账号访问/删除了文件」",
        "首次启动会自动执行 auditpol 配置并向共享目录写入 SACL，需要管理员权限",
    ],
    "audit.enabled": [
        "是否启用安全事件采集（关闭后仍可记录文件系统变更，但无法追溯到具体客户端账号）",
        "取值：true / false",
        "默认值：{default}",
    ],
    "audit.auto_configure": [
        "服务启动时自动配置 auditpol 审计策略与 SACL（幂等，可重复执行）",
        "取值：true / false；false 表示需要你手工配好审计策略",
        "默认值：{default}",
    ],
    "audit.scopes": [
        "要开启的审计子类别",
        "share  = 详细的文件共享（事件 5145，自带客户端 IP、账号、共享名）",
        "delete = 文件系统（事件 4663，用于删除归因）",
        "取值：列表，元素只能取 share / delete；数组越短日志量越小",
        "默认值：{default}",
    ],
    "audit.object_mask": [
        "写入 SACL 的访问权限掩码，掩码越小产生的日志越少（重要：不要加读权限）",
        "可选值：DELETE、FILE_DELETE_CHILD、FILE_WRITE_DATA、FILE_APPEND_DATA、"
        "FILE_READ_DATA、WRITE_DAC、WRITE_OWNER、FILE_WRITE_EA、FILE_WRITE_ATTRIBUTES",
        "默认值：{default}",
    ],
    "audit.principal": [
        "SACL 审计项针对哪个主体（账号 / 组）生效",
        "取值：Windows 账户名，Everyone 表示所有访问者",
        "默认值：{default}",
    ],
    "audit.poll_interval_seconds": [
        "读取安全事件日志的轮询间隔",
        "取值：整数 ≥ 1，单位秒；值越小越实时、CPU 占用略高",
        "默认值：{default}",
    ],
    "audit.overlap_seconds": [
        "每次轮询向前回看的重叠秒数，用于防止事件在两次轮询之间被漏读",
        "取值：整数 ≥ 0，单位秒；建议不小于 poll_interval_seconds",
        "默认值：{default}",
    ],
    "audit.batch_size": [
        "单次轮询最多处理多少条安全事件",
        "取值：整数 ≥ 1；繁忙服务器可调大",
        "默认值：{default}",
    ],
    "audit.dedup_seconds": [
        "访问记录去重窗口：同一路径（忽略大小写）+ 同一操作 + 同一账号 + 同一 IP 在此秒数内只记一条",
        "为什么需要：SMB 对「一次打开」会连发多条 5145（大小写探测、属性查询、真正读取），不去重会一条读取记成 3~7 条",
        "取值：整数 0 ~ 60，单位秒；0 = 不去重（原始事件全记）",
        "默认值：{default}",
    ],
    "audit.skip_loopback": [
        "是否忽略来自 127.0.0.1 / ::1 的共享访问（回环）",
        "false = 记录下来（标注为本机回环访问）；true = 丢弃",
        "注意：在本机用 \\\\127.0.0.1\\共享 或 \\\\localhost\\共享 自测时，只有 false 才能看到记录",
        "默认值：{default}",
    ],
    "audit.read_extensions": [
        "【可选｜重量级】用「文件系统(4663)」额外审计读取，覆盖 5145 抓不到的读取（本机直接打开、SMB 缓存命中、非网络途径）",
        "留空（默认）= 关闭，读取记录只来自 5145 共享审计（推荐）",
        "填扩展名（如 [\".xlsx\", \".docx\", \".pdf\"]）= 只把这些扩展名的读取写进 FileGuard 日志，其余读取事件丢弃",
        "⚠️ 代价：Windows 安全日志会把监控目录下【所有】读取都记下来（不受扩展名限制），繁忙服务器日志量与磁盘占用会显著上升",
        "建议：配合 monitor.paths 缩小到真正需要审计的目录；不要把整个数据盘加进来",
        "默认值：{default}",
    ],
    "audit.ip_cache_minutes": [
        "「文件路径 -> 客户端 IP/账号」映射的缓存分钟数，用于给 4663 删除事件补上来源信息",
        "取值：整数 ≥ 1，单位分钟",
        "默认值：{default}",
    ],
    "audit.session_lookup": [
        "当事件里查不到客户端 IP 时，是否反查服务器的 SMB 会话表（按账号找出该客户端 IP）",
        "取值：true / false；关闭后只依赖 5145 事件与缓存，个别记录无 IP",
        "默认值：{default}",
    ],
    "audit.session_cache_seconds": [
        "SMB 会话表的缓存秒数（会话表查询要走一次 RPC，不宜频繁调用）",
        "取值：整数 5 ~ 600，单位秒",
        "默认值：{default}",
    ],

    "web": [
        "Web 管理界面：查看访问 / 删除记录、一键恢复文件、在线编辑本配置",
    ],
    "web.enabled": [
        "是否启用 Web 管理界面",
        "取值：true / false",
        "默认值：{default}",
    ],
    "web.host": [
        "Web 服务监听地址",
        "取值：0.0.0.0 = 允许局域网内其它机器访问；127.0.0.1 = 仅本机可访问",
        "默认值：{default}",
    ],
    "web.port": [
        "Web 服务端口",
        "取值：1 ~ 65535 的整数；被占用时会启动失败并提示",
        "默认值：{default}",
    ],
    "web.open_browser_on_start": [
        "服务启动后是否自动用浏览器打开管理界面",
        "取值：true / false",
        "默认值：{default}",
    ],
    "web.username": [
        "Web 界面登录账号",
        "取值：任意字符串",
        "默认值：{default}",
    ],
    "web.password": [
        "Web 界面登录密码；留空时程序首次运行会自动生成随机强密码并写回本文件",
        "取值：任意字符串（建议不少于 8 位）",
        "默认值：为空，程序自动生成",
    ],
    "web.require_login": [
        "是否强制登录校验",
        "取值：true / false",
        "false 表示任何能访问该端口的人都能看记录、执行恢复，"
        "仅建议在完全可信的内网、且已用防火墙或反向代理限制来源时关闭",
        "默认值：{default}",
    ],
    "web.page_size": [
        "Web 列表每页显示条数",
        "取值：整数 10 ~ 500",
        "默认值：{default}",
    ],
    "web.session_secret": [
        "登录会话签名密钥；留空时程序首次运行自动生成（改了会导致已登录用户掉线）",
        "取值：随机字符串，一般不需要手工填写",
        "默认值：为空，程序自动生成",
    ],

    "app": [
        "程序自身设置",
    ],
    "app.log_level": [
        "程序自身运行日志级别（写入程序日志，非 access/delete 日志）",
        "取值：DEBUG / INFO / WARNING / ERROR",
        "默认值：{default}",
    ],
    "app.single_instance": [
        "是否只允许同时运行一个 FileGuard 实例（防止重复监控同一目录）",
        "取值：true / false",
        "默认值：{default}",
    ],
    "app.max_gui_log_lines": [
        "主界面运行日志区最多显示多少行",
        "取值：整数 ≥ 50",
        "默认值：{default}",
    ],
}

FILE_HEADER = r"""FileGuard 配置文件（YAML 格式）
================================================================
本文件由程序自动维护注释：每次保存都会按内置的默认结构重新渲染全文，
因此注释不会丢失、升级后新增的配置项也会自动出现并带说明。

  · 修改后需在程序里点「停止服务 → 启动服务」才会生效；
    监控目录、回收站路径、日志目录、端口等属于启动期配置。
  · Windows 路径可直接写，无需像 JSON 那样把反斜杠写成两个：
      log:
        dir: D:\FileGuardLogs
  · 值里含「冒号+空格」「井号 #」或首尾空格时，必须整体加引号：
      monitor:
        paths:
          - "D:\My Share"
  · 以 # 开头的内容是注释，程序不会读取；删掉注释不影响运行。
  · 校验结果会显示在主界面运行日志与 Web 界面的「系统配置」页。
================================================================
"""


# 掩码名称 -> ntsecuritycon 常量名
MASK_NAMES = {
    "DELETE": "DELETE",
    "FILE_DELETE_CHILD": "FILE_DELETE_CHILD",
    "FILE_WRITE_DATA": "FILE_WRITE_DATA",
    "FILE_APPEND_DATA": "FILE_APPEND_DATA",
    "FILE_READ_DATA": "FILE_READ_DATA",
    "WRITE_DAC": "WRITE_DAC",
    "WRITE_OWNER": "WRITE_OWNER",
    "FILE_WRITE_EA": "FILE_WRITE_EA",
    "FILE_WRITE_ATTRIBUTES": "FILE_WRITE_ATTRIBUTES",
}


def _deep_merge(base: dict, override: dict) -> dict:
    """override 覆盖 base，缺失项用 base 补齐（保证升级后新增配置自动出现）。"""
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


# 旧版本已被取代的配置项：读到就丢弃，避免残留的旧值影响新语义
LEGACY_KEYS = {
    # 旧：是否自动还原回原路径 —— 已由 protection.on_delete_action 取代
    "protection": ("auto_restore_on_delete",),
    # 旧：自动清理间隔（分钟）—— 已由 recycle_bin.purge_interval_days / purge_at_hour 取代
    "recycle_bin": ("purge_interval_minutes",),
}


def _strip_legacy(raw: dict) -> dict:
    """丢弃已被取代的旧配置项（不改动调用方传入的字典）。"""
    raw = dict(raw or {})
    for section, keys in LEGACY_KEYS.items():
        sec = raw.get(section)
        if isinstance(sec, dict):
            sec = dict(sec)
            for k in keys:
                sec.pop(k, None)
            raw[section] = sec
    return _upgrade_log_names(raw)


def _upgrade_log_names(raw: dict) -> dict:
    """把旧的固定日志名（access.log / delete.log）自动升级为按天命名。

    只处理**用户配置里显式写出**的普通 .log 文件名；已含 {date} 的不动。
    升级前的单个 access.log 仍会被日志读取器继续读取，历史记录不会丢。
    """
    sec = raw.get("log")
    if not isinstance(sec, dict):
        return raw
    sec = dict(sec)
    changed = False
    for key in ("access_file", "delete_file"):
        val = str(sec.get(key) or "").strip()
        if val and DATE_TOKEN not in val and val.lower().endswith(".log"):
            stem = val[:-4].rstrip()
            sep = "" if stem.endswith(("_", "-", ".")) else "_"
            sec[key] = f"{stem}{sep}{DATE_TOKEN}.log"
            changed = True
    if changed:
        raw = dict(raw)
        raw["log"] = sec
    return raw


def _get_path(data: dict, dotted: str):
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _all_paths(data: dict, prefix: str = "") -> set:
    out = set()
    for k, v in data.items():
        p = f"{prefix}{k}"
        out.add(p)
        if isinstance(v, dict):
            out |= _all_paths(v, p + ".")
    return out


def _fmt_default(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(yamlconf.scalar(x) for x in value) + "]"
    if isinstance(value, str) and value == "":
        return "(空)"
    return yamlconf.scalar(value)


def config_docs() -> dict:
    """渲染注释元数据（把 {default} 替换成真实默认值）。"""
    docs = {}
    for p, lines in _NODE_DOC.items():
        default_txt = _fmt_default(_get_path(DEFAULT_CONFIG, p))
        items = lines if isinstance(lines, (list, tuple)) else [lines]
        docs[p] = [str(x).replace("{default}", default_txt) for x in items]
    return docs


def render_config(data: dict) -> str:
    """把配置字典渲染成带完整注释的 YAML 文本。"""
    return yamlconf.dump(data, docs=config_docs(),
                         known=_all_paths(DEFAULT_CONFIG), header=FILE_HEADER)


def parse_config_text(text: str) -> dict:
    """解析 YAML 配置文本（供 Web 界面 / 手工编辑使用）。"""
    return yamlconf.load_text(text)


def _autodetect_share() -> str:
    """首次运行时尽量猜一个存在的共享目录，猜不到就用默认值。"""
    candidates = []
    for drive in "CDEFGH":
        for name in ("Share", "share", "共享", "Shares", "FileShare", "Public"):
            candidates.append(f"{drive}:\\{name}")
    for c in candidates:
        if os.path.isdir(c):
            return c
    return DEFAULT_CONFIG["monitor"]["paths"][0]


class Config:
    """线程安全的配置对象，支持点号路径访问。"""

    def __init__(self, path: str = None):
        self.path = path or default_config_path()
        self._lock = threading.RLock()
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        self.first_run = False
        self.migrated_from = ""

    # ---------- 读写 ----------
    def load(self) -> "Config":
        with self._lock:
            raw = {}
            self.first_run = False
            self.migrated_from = ""

            if os.path.isfile(self.path):
                raw = self._read(self.path)
            else:
                legacy = self._find_legacy()
                if legacy:
                    # 兼容旧版本：把 config.json 的内容迁移到 config.yaml
                    raw = self._read(legacy)
                    self.migrated_from = legacy
                else:
                    raw = {"monitor": {"paths": [_autodetect_share()]}}
                self.first_run = True

            self._data = _deep_merge(DEFAULT_CONFIG, _strip_legacy(raw))
            if not self.get("web.password"):
                self.set("web.password", secrets.token_urlsafe(9))
            if not self.get("web.session_secret"):
                self.set("web.session_secret", secrets.token_hex(16))
            if self.first_run:
                self._save_locked()
                if self.migrated_from:
                    self._park_legacy(self.migrated_from)
            return self

    def save(self) -> None:
        with self._lock:
            self._save_locked()

    def yaml_text(self) -> str:
        """返回当前配置对应的带注释 YAML 文本（Web 界面编辑器用）。"""
        with self._lock:
            return render_config(self._data)

    def update(self, parsed: dict) -> dict:
        """用解析后的字典整体替换配置（缺失项自动补默认值）并写盘。"""
        with self._lock:
            self._data = _deep_merge(DEFAULT_CONFIG, _strip_legacy(parsed or {}))
            if not self.get("web.password"):
                self.set("web.password", secrets.token_urlsafe(9))
            if not self.get("web.session_secret"):
                self.set("web.session_secret", secrets.token_hex(16))
            self._save_locked()
        return self.as_dict()

    def save_text(self, text: str) -> dict:
        """用 YAML 文本整体替换配置。解析失败抛 ValueError。"""
        return self.update(parse_config_text(text))

    def _read(self, path: str) -> dict:
        """按扩展名选择解析器；损坏时备份并回退默认值，避免服务起不来。"""
        try:
            if path.lower().endswith(".json"):
                with open(path, "r", encoding="utf-8-sig") as f:
                    return json.load(f) or {}
            return yamlconf.load_file(path)
        except Exception as e:
            try:
                os.replace(path, path + ".broken")
            except OSError:
                pass
            self.load_error = f"{os.path.basename(path)} 解析失败（已备份为 .broken）：{e}"
            return {}

    def _find_legacy(self) -> str:
        """查找同目录下可迁移的旧 config.json。"""
        base = os.path.dirname(self.path) or "."
        for name in LEGACY_NAMES:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
        return ""

    @staticmethod
    def _park_legacy(path: str) -> None:
        """迁移完成后把旧文件改名留存（不删除，便于回滚）。"""
        try:
            os.replace(path, path + ".migrated")
        except OSError:
            pass

    def _save_locked(self) -> None:
        dirname = os.path.dirname(self.path)
        if dirname:
            paths.ensure_dir(dirname)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_config(self._data))
        os.replace(tmp, self.path)

    # ---------- 访问 ----------
    def get(self, dotted: str, default=None):
        with self._lock:
            cur = self._data
            for part in dotted.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    return default
                cur = cur[part]
            return cur

    def set(self, dotted: str, value) -> None:
        with self._lock:
            parts = dotted.split(".")
            cur = self._data
            for part in parts[:-1]:
                cur = cur.setdefault(part, {})
            cur[parts[-1]] = value

    def as_dict(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    # ---------- 派生路径 ----------
    def monitor_paths(self) -> list:
        raw = self.get("monitor.paths") or []
        if isinstance(raw, str):
            raw = [raw]
        return [paths.abspath(p) for p in raw if p and str(p).strip()]

    def log_dir(self) -> str:
        return paths.ensure_dir(paths.abspath(self.get("log.dir")))

    def log_date_format(self) -> str:
        return str(self.get("log.date_format") or "%Y%m%d").strip() or "%Y%m%d"

    def log_template(self, kind: str = "access") -> str:
        """日志文件名模板（可能含 {date} 占位符，交由 JsonlLogger 解析成当天文件）。"""
        key = "log.delete_file" if kind == "delete" else "log.access_file"
        name = str(self.get(key) or DEFAULT_CONFIG["log"][key.split(".", 1)[1]]).strip()
        name = os.path.basename(name) or DEFAULT_CONFIG["log"][key.split(".", 1)[1]]
        return os.path.join(self.log_dir(), name)

    def access_log_template(self) -> str:
        return self.log_template("access")

    def delete_log_template(self) -> str:
        return self.log_template("delete")

    def today_log_path(self, kind: str = "access") -> str:
        """当前这一天的实际日志文件路径（供自检 / 界面展示使用）。"""
        tpl = self.log_template(kind)
        if DATE_TOKEN not in os.path.basename(tpl):
            return tpl
        return tpl.replace(DATE_TOKEN, datetime.datetime.now().strftime(self.log_date_format()))

    def recycle_path(self) -> str:
        return paths.ensure_dir(paths.abspath(self.get("recycle_bin.path")))

    def purge_interval_days(self) -> int:
        """回收站自动清理周期（天）；1 = 每天一次。非法值回退为 1。"""
        try:
            n = int(self.get("recycle_bin.purge_interval_days", 1) or 1)
        except (TypeError, ValueError):
            n = 1
        return max(1, min(365, n))

    def purge_at_hour(self) -> int:
        """自动清理落在每天的几点（0~23）；-1 表示不指定时点。"""
        try:
            h = int(self.get("recycle_bin.purge_at_hour", 3))
        except (TypeError, ValueError):
            h = 3
        return h if -1 <= h <= 23 else 3

    def auto_purge(self) -> bool:
        return bool(self.get("recycle_bin.auto_purge", True))

    def bin_files_dir(self) -> str:
        """回收站里的「可见回收站」目录：存放被删除文件的实体副本。"""
        return paths.ensure_dir(os.path.join(self.recycle_path(), "files"))

    def delete_action(self) -> str:
        """当前删除动作：move_to_bin / restore / record。

        protection.enabled=false（保护关闭）时一律降级为 record：只记录日志。
        """
        if not self.get("protection.enabled", True):
            return "record"
        action = str(self.get("protection.on_delete_action", "move_to_bin") or "")
        action = action.strip().lower()
        # 兼容几种写法：bin / move / move_to_recycle 都按「搬进回收站」处理
        if action in ("move_to_bin", "move_to_recycle", "bin", "move", "recycle"):
            return "move_to_bin"
        if action in ("restore", "auto_restore"):
            return "restore"
        return "record"

    def actor_backfill_seconds(self, min_ms: int = 0) -> float:
        """删除日志写入前的归因回填等待时长（秒）。

        :param min_ms: 由服务在装配时传入的下限（= 审计轮询间隔 + 余量），
                       保证审计事件来得及被采到，否则本机删除显示「未知」。
        """
        try:
            ms = int(self.get("protection.actor_backfill_ms", 2500) or 0)
        except (TypeError, ValueError):
            ms = 2500
        try:
            floor = max(0, int(min_ms or 0))
        except (TypeError, ValueError):
            floor = 0
        return max(0.0, min(8.0, max(ms, floor) / 1000.0))

    # ---------- 校验 ----------
    def validate(self) -> dict:
        """返回 {'ok': bool, 'errors': [...], 'warnings': [...]}"""
        errors, warnings = [], []
        mpaths = self.monitor_paths()
        if not mpaths:
            errors.append("monitor.paths 未配置任何监控目录")
        for p in mpaths:
            if not os.path.isdir(p):
                errors.append(f"监控目录不存在：{p}")

        if not isinstance(self.get("monitor.paths"), (list, str)):
            errors.append("monitor.paths 必须是路径列表")

        rpath = self.recycle_path()
        for p in mpaths:
            if rpath.lower().startswith(p.lower()):
                errors.append(f"回收站目录不能位于监控目录内部：{rpath}")

        rdays = self.get("recycle_bin.retention_days", 30)
        if not isinstance(rdays, (int, float)) or isinstance(rdays, bool) or rdays < 0:
            errors.append(f"recycle_bin.retention_days 必须是不小于 0 的数字：{rdays!r}")
        if not isinstance(self.get("recycle_bin.max_size_gb"), (int, float)) \
                or isinstance(self.get("recycle_bin.max_size_gb"), bool):
            errors.append("recycle_bin.max_size_gb 必须是数字（单位 GB）")
        pdays = self.get("recycle_bin.purge_interval_days", 1)
        if isinstance(pdays, bool) or not isinstance(pdays, int) or not (1 <= pdays <= 365):
            errors.append(f"recycle_bin.purge_interval_days 必须是 1~365 的整数（单位「天」）：{pdays!r}")
        phour = self.get("recycle_bin.purge_at_hour", 3)
        if isinstance(phour, bool) or not isinstance(phour, int) or not (-1 <= phour <= 23):
            errors.append(f"recycle_bin.purge_at_hour 必须是 -1~23 的整数（小时）：{phour!r}")
        if not self.get("recycle_bin.auto_purge", True):
            warnings.append("recycle_bin.auto_purge=false：回收站不会自动清理，"
                            "过期版本与超容数据会一直占用磁盘")

        strategy = self.get("protection.strategy")
        if strategy not in ("mirror", "event"):
            errors.append(f"protection.strategy 只能是 mirror 或 event：{strategy!r}")
        action = str(self.get("protection.on_delete_action") or "").strip().lower()
        if action not in ("move_to_bin", "restore", "record"):
            errors.append("protection.on_delete_action 只能是 move_to_bin / restore / record："
                          f"{self.get('protection.on_delete_action')!r}")
        policy = self.get("protection.restore_conflict_policy")
        if policy not in ("overwrite", "rename", "skip"):
            errors.append(
                f"protection.restore_conflict_policy 只能是 overwrite/rename/skip：{policy!r}")
        if self.get("protection.debounce_seconds", 1.5) is None or not isinstance(
                self.get("protection.debounce_seconds", 1.5), (int, float)):
            errors.append("protection.debounce_seconds 必须是数字（秒）")

        port = self.get("web.port", 8765)
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            errors.append(f"web.port 非法（需 1~65535 的整数）：{port!r}")
        if not str(self.get("web.host") or "").strip():
            errors.append("web.host 不能为空（本机使用填 127.0.0.1，允许外部访问填 0.0.0.0）")
        if not self.get("web.password"):
            warnings.append("Web 界面未设置密码，任何能访问该端口的人都能查看记录")
        if not self.get("web.require_login", True):
            warnings.append("web.require_login=false：Web 界面未启用登录校验，"
                            "仅建议在完全可信的内网使用")
        ps = self.get("web.page_size", 50)
        if isinstance(ps, bool) or not isinstance(ps, int) or not (10 <= ps <= 500):
            warnings.append(f"web.page_size 建议取 10~500 的整数，当前为 {ps!r}")

        if self.get("audit.enabled", True):
            for scope in self.get("audit.scopes") or []:
                if scope not in ("share", "delete"):
                    warnings.append(f"audit.scopes 中的未知项将被忽略：{scope!r}"
                                    "（只能是 share / delete）")
            for name in self.get("audit.object_mask") or []:
                if name not in MASK_NAMES:
                    warnings.append(f"audit.object_mask 中的未知权限将被忽略：{name!r}")
            ded = self.get("audit.dedup_seconds", 2)
            if isinstance(ded, bool) or not isinstance(ded, (int, float)) \
                    or not (0 <= ded <= 60):
                warnings.append(f"audit.dedup_seconds 建议取 0~60 的整数（秒）：{ded!r}")
            rex = self.get("audit.read_extensions") or []
            if rex:
                warnings.append(
                    "audit.read_extensions 已开启：Windows 安全日志会记录监控目录下"
                    "【所有】文件的读取（不加区分的），日志量与磁盘占用会明显上升，"
                    "请确认监控目录范围足够小")

        if self.get("log.encoding") not in ("utf-8", "utf8", "gbk", "gb2312"):
            warnings.append(f"log.encoding 取值不常见：{self.get('log.encoding')!r}"
                            "（建议 utf-8）")

        rdays = self.get("log.retention_days", 90)
        if isinstance(rdays, bool) or not isinstance(rdays, (int, float)) or rdays < 0:
            errors.append(f"log.retention_days 必须是不小于 0 的数字：{rdays!r}")
        for key in ("log.access_file", "log.delete_file"):
            name = str(self.get(key) or "").strip()
            if not name:
                errors.append(f"{key} 不能为空")
            elif name.lower().endswith(".log") is False:
                warnings.append(f"{key} 不以 .log 结尾（{name!r}），请确认这是有意为之")
            if os.path.basename(name) != name:
                warnings.append(f"{key} 只应是文件名（不含路径），当前为 {name!r}，"
                                "多余路径部分会被忽略")
        if DATE_TOKEN not in str(self.get("log.access_file") or ""):
            warnings.append("log.access_file 不含 {date}，访问日志不会按天分文件"
                            "（将退化为单文件 + 按大小轮转）")
        if DATE_TOKEN not in str(self.get("log.delete_file") or ""):
            warnings.append("log.delete_file 不含 {date}，删除日志不会按天分文件")
        if DATE_TOKEN in (str(self.get("log.access_file") or "")
                          + str(self.get("log.delete_file") or "")):
            try:
                datetime.datetime.now().strftime(self.log_date_format())
            except (ValueError, TypeError) as e:
                errors.append(f"log.date_format 不是合法的日期格式：{self.get('log.date_format')!r}（{e}）")

        lvl = str(self.get("app.log_level", "INFO")).upper()
        if lvl not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            warnings.append(f"app.log_level 取值不常见：{self.get('app.log_level')!r}"
                            "（建议 DEBUG/INFO/WARNING/ERROR）")

        return {"ok": not errors, "errors": errors, "warnings": warnings}

    # ---------- 迁移提示 ----------
    def migration_note(self) -> str:
        if not self.migrated_from:
            return ""
        return (f"已从旧配置 {os.path.basename(self.migrated_from)} 迁移到 "
                f"{os.path.basename(self.path)}（旧文件已改名为 .migrated 备份）")


def load_config() -> Config:
    cfg = Config()
    cfg.load()
    return cfg
