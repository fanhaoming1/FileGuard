# -*- coding: utf-8 -*-
"""用 Edge 无头模式给 Web 界面逐页截图。

用法： python tools/shots.py http://127.0.0.1:8899  <输出目录>
"""
import os
import subprocess
import sys
import time

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
NO_WINDOW = 0x08000000
PAGES = [
    ("", "01-概览.png"),
    ("#access", "02-访问记录.png"),
    ("#del", "03-删除记录.png"),
    ("#bin", "04-回收站.png"),
    ("#conf", "05-系统配置.png"),
]


def main():
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899").rstrip("/")
    outdir = sys.argv[2] if len(sys.argv) > 2 else "docs/screenshots"
    outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)
    profile = os.path.join(os.environ.get("TEMP", "."), "fg_edge_profile")
    ok = 0
    for frag, name in PAGES:
        out = os.path.join(outdir, name)
        if os.path.exists(out):
            os.remove(out)
        cmd = [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
               "--no-first-run", "--disable-extensions", "--no-default-browser-check",
               f"--user-data-dir={profile}",
               "--window-size=1560,1240", "--force-device-scale-factor=1",
               "--virtual-time-budget=7000",
               f"--screenshot={out}", base + "/" + frag]
        r = subprocess.run(cmd, capture_output=True, creationflags=NO_WINDOW, timeout=90)
        time.sleep(0.4)
        good = os.path.isfile(out) and os.path.getsize(out) > 8000
        print(f"  {'OK  ' if good else 'FAIL'} {name}  "
              f"{os.path.getsize(out) if os.path.isfile(out) else 0} bytes")
        if not good and r.stderr:
            print("       ", r.stderr.decode("utf-8", "replace")[-300:])
        ok += 1 if good else 0
    print(f"\n完成 {ok}/{len(PAGES)}，输出目录：{outdir}")
    return 0 if ok == len(PAGES) else 1


if __name__ == "__main__":
    sys.exit(main())
