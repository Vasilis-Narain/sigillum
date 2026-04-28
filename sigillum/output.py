"""ANSI color helpers and status rendering."""
from __future__ import annotations

import os
import sys

from cryptography.x509.oid import NameOID

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def green(s):  return _c("32", s)
def red(s):    return _c("31", s)
def yellow(s): return _c("33", s)
def cyan(s):   return _c("36", s)
def bold(s):   return _c("1", s)
def dim(s):    return _c("2", s)


def mark(b):
    """Tri-state check mark: True/False/None (unknown/skipped)."""
    if b is True:
        return green("✓")
    if b is False:
        return red("✗")
    return yellow("?")


def status_line(label: str, ok, detail: str = "") -> str:
    tag = mark(ok)
    word = green("ok") if ok is True else red("FAIL") if ok is False else yellow("n/a")
    extra = f"  {dim(detail)}" if detail else ""
    return f"  {tag} {label:<22} {word}{extra}"


def cn_of(name) -> str:
    cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn:
        return cn[0].value
    return name.rfc4514_string()
