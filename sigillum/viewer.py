"""System viewer launcher with best-effort window enlargement."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time


def open_file_large(path: str) -> None:
    sysname = platform.system()
    if sysname == "Windows":
        os.startfile(path)
        return
    if sysname == "Darwin":
        subprocess.run(["open", path])
        return

    subprocess.Popen(["xdg-open", path],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not shutil.which("wmctrl"):
        return
    try:
        time.sleep(0.8)
        subprocess.run(
            ["wmctrl", "-r", ":ACTIVE:", "-e", "0,50,50,1600,1000"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
        )
        subprocess.run(
            ["wmctrl", "-r", ":ACTIVE:", "-b", "add,maximized_vert,maximized_horz"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
        )
    except Exception:
        pass
