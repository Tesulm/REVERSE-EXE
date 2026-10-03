#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
revkit.py — Universal EXE Reverse Engineering Toolkit

  - Detects language (Go / Python / Rust / .NET / Delphi / AutoIt / Native)
  - Runs the right extractor pipeline automatically
  - Saves EVERYTHING to <binary>_reversed/
  - Writes REPORT.md — a single file you can paste back to the AI

Usage:
    python reverse.py                 # interactive — drag&drop
    python reverse.py target.exe      # direct
    python reverse.py target.exe --deep   # also disassemble every main.* (Go)
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path


# ══════════════════════════════════════════════════════════════════════════
# COLORS
# ══════════════════════════════════════════════════════════════════════════

class C:
    R = "\033[0m"; BOLD = "\033[1m"
    RED = "\033[1;31m"; GREEN = "\033[1;32m"; YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"; MAGENTA = "\033[1;35m"; CYAN = "\033[1;36m"
    GREY = "\033[1;30m"; WHITE = "\033[1;37m"


def _ensure(pkg, import_name=None):
    try:
        __import__(import_name or pkg)
    except ImportError:
        print(f"{C.YELLOW}[!]{C.R} Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])


_ensure("pefile")
import pefile


# ══════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════

def log(msg, kind="info"):
    prefix = {
        "info":  f"{C.CYAN}[*]{C.R}",
        "ok":    f"{C.GREEN}[+]{C.R}",
        "warn":  f"{C.YELLOW}[!]{C.R}",
        "err":   f"{C.RED}[-]{C.R}",
        "step":  f"{C.BOLD}{C.BLUE}▶{C.R}",
    }.get(kind, f"{C.CYAN}[*]{C.R}")
    print(f"{prefix} {msg}", flush=True)


def banner():
    print()
    print(f"{C.CYAN}{C.BOLD}  ╔══════════════════════════════════════════════════════════════╗{C.R}")
    print(f"{C.CYAN}{C.BOLD}  ║             REVKIT — UNIVERSAL RE TOOLKIT  @Tesulm                   ║{C.R}")
    print(f"{C.CYAN}{C.BOLD}  ║              Go · Python · Rust · .NET · Native              ║{C.R}")
    print(f"{C.CYAN}{C.BOLD}  ╚══════════════════════════════════════════════════════════════╝{C.R}")
    print()


def find_tool(*names, extra_paths=()):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    for base in extra_paths:
        for n in names:
            p = Path(base) / n
            if p.exists():
                return str(p)
    return None


def which_go():
    return find_tool(
        "go", "go.exe",
        extra_paths=(r"C:\Program Files\Go\bin", r"C:\Go\bin"),
    )


def which_goremsym(user_path=None):
    if user_path and os.path.isfile(user_path):
        return user_path
    return find_tool(
        "GoReSym", "GoReSym.exe", "goresym", "goresym.exe",
        extra_paths=(
            str(Path.home() / "Desktop"),
            str(Path.home() / "Downloads"),
            r"C:\tools", r"C:\go\bin",
        ),
    )


def which_ilspycmd(user_path=None):
    if user_path and os.path.isfile(user_path):
        return user_path
    return find_tool(
        "ilspycmd", "ilspycmd.exe",
        extra_paths=(str(Path.home() / ".dotnet" / "tools"),),
    )


def which_rustfilt():
    return find_tool(
        "rustfilt", "rustfilt.exe",
        extra_paths=(str(Path.home() / ".cargo" / "bin"),),
    )


def pe_timestamp(ts):
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        return "invalid"


# ══════════════════════════════════════════════════════════════════════════
# PE LAYER
# ══════════════════════════════════════════════════════════════════════════

class PEFile:
    def __init__(self, path):
        self.path = path
        self.pe = pefile.PE(path, fast_load=False)
        self.data = Path(path).read_bytes()
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = []
        for s in self.pe.sections:
            self.sections.append({
                "name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
                "vaddr": s.VirtualAddress,
                "vsize": s.Misc_VirtualSize,
                "raw_ptr": s.PointerToRawData,
                "raw_size": s.SizeOfRawData,
                "entropy": self._entropy(s.get_data()),
                "flags": self._flags(s.Characteristics),
            })

    @staticmethod
    def _entropy(data):
        if not data:
            return 0.0
        freq = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _flags(ch):
        f = ""
        if ch & 0x20000000: f += "X"
        if ch & 0x80000000: f += "W"
        if ch & 0x40000000: f += "R"
        return f

    def va_to_offset(self, va):
        rva = va - self.image_base
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
                return s["raw_ptr"] + (rva - s["vaddr"])
        return None

    def read_cstring(self, offset, max_len=1024):
        if offset is None or offset >= len(self.data):
            return None
        end = self.data.find(b"\x00", offset, offset + max_len)
        if end == -1:
            end = offset + max_len
        raw = self.data[offset:end]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except Exception:
                return None
        if not text:
            return None
        printable = sum(1 for c in text if c.isprintable() or c in "\t\n\r")
        if printable / max(len(text), 1) < 0.65:
            return None
        return text

    def imports(self):
        out = {}
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return out
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", "replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("ascii", "replace"))
                else:
                    funcs.append(f"ordinal_{imp.ordinal}")
            out[dll] = funcs
        return out

    def exports(self):                      # <-- METHOD
        out = []
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return out
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            out.append({
                "name": exp.name.decode("ascii", "replace") if exp.name else None,
                "ordinal": exp.ordinal,
                "address": hex(exp.address),
            })
        return out

    def debug_info(self):                   # <-- METHOD
        out = []
        if not hasattr(self.pe, "DIRECTORY_ENTRY_DEBUG"):
            return out
        for dbg in self.pe.DIRECTORY_ENTRY_DEBUG:
            entry = {
                "type": dbg.struct.Type,
                "size": dbg.struct.SizeOfData,
                "timestamp": pe_timestamp(dbg.struct.TimeDateStamp),
            }
            if dbg.struct.Type == 2:
                try:
                    raw = dbg.entry.data if hasattr(dbg, "entry") else b""
                    if b"RSDS" in raw:
                        idx = raw.find(b"RSDS")
                        guid = raw[idx+4:idx+20].hex()
                        rest = raw[idx+24:]
                        nul = rest.find(b"\x00")
                        pdb = rest[:nul].decode("ascii", "replace") if nul > 0 else ""
                        entry["pdb_guid"] = guid
                        entry["pdb_path"] = pdb
                except Exception:
                    pass
            out.append(entry)
        return out

    def clr_present(self):
        try:
            d = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            return d.VirtualAddress != 0 and d.Size != 0
        except Exception:
            return False

    def summary(self):
        oh = self.pe.OPTIONAL_HEADER
        fh = self.pe.FILE_HEADER
        return {
            "file": os.path.basename(self.path),
            "size_bytes": len(self.data),
            "machine": {
                0x014c: "i386", 0x8664: "x86-64", 0x01c0: "ARM",
                0xaa64: "ARM64",
            }.get(fh.Machine, f"0x{fh.Machine:04x}"),
            "subsystem": {
                1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
            }.get(oh.Subsystem, f"0x{oh.Subsystem:04x}"),
            "timestamp": pe_timestamp(fh.TimeDateStamp),
            "entry_point": hex(oh.AddressOfEntryPoint),
            "image_base": hex(oh.ImageBase),
            "linker": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
            "is_dll": bool(fh.Characteristics & 0x2000),
        }


# ══════════════════════════════════════════════════════════════════════════
# RAW STRING EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════

_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def raw_strings(data, min_len=5):
    ascii_s = [m.group().decode("ascii") for m in _ASCII_RE.finditer(data)
               if len(m.group()) >= min_len]
    utf16_s = []
    for m in _UTF16_RE.finditer(data):
        try:
            s = m.group().decode("utf-16-le")
            if len(s) >= min_len:
                utf16_s.append(s)
        except Exception:
            pass
    return ascii_s, utf16_s


# ══════════════════════════════════════════════════════════════════════════
# LANGUAGE DETECTION
# ══════════════════════════════════════════════════════════════════════════

class Detector:
    def __init__(self, pe_file):
        self.pe = pe_file
        self.imports = pe_file.imports()
        self.sec_names = [s["name"] for s in pe_file.sections]
        self.ascii_s, self.utf16_s = raw_strings(pe_file.data)
        self.all_s = self.ascii_s + self.utf16_s

    def _has(self, *needles):
        for n in needles:
            nl = n.lower()
            for s in self.all_s:
                if nl in s.lower():
                    return True
        return False

    def _count(self, needle):
        nl = needle.lower()
        return sum(1 for s in self.all_s if nl in s.lower())

    def _imp(self, *needles):
        hits = []
        for dll in self.imports:
            for n in needles:
                if n.lower() in dll.lower():
                    hits.append(dll)
        return hits

    def detect(self):
        scores = OrderedDict()
        evidence = {}

        def add(lang, score, ev):
            if score > 0:
                scores[lang] = scores.get(lang, 0) + score
                evidence.setdefault(lang, []).append(ev)

        # Go
        if self.pe.data.find(b"MEI\x0c\x0b\x0a\x0b\x0e") == -1:
            if self._has("go:buildid"):      add("go", 100, "string: go:buildid")
            if self._has("Go build ID:"):    add("go", 80, "string: Go build ID:")
            if self._has("runtime.main"):    add("go", 60, "string: runtime.main")
            if self._has("golang.org/"):     add("go", 40, "string: golang.org/")
            if self._has("runtime.gopanic"): add("go", 40, "string: runtime.gopanic")
            for s in self.sec_names:
                if s in (".symtab", ".pclntab") or "pclntab" in s.lower():
                    add("go", 30, f"section: {s}")

        # Python / PyInstaller
        if self.pe.data.find(b"MEI\x0c\x0b\x0a\x0b\x0e") != -1:
            add("python", 150, "PyInstaller CArchive magic")
        if self._has("PYZ-00.pyz"):    add("python", 80, "string: PYZ-00.pyz")
        if self._has("pyimod"):        add("python", 60, "string: pyimod")
        if self._has("_MEIPASS"):      add("python", 60, "string: _MEIPASS")
        for s in self.sec_names:
            if s.startswith("pyi-"):   add("python", 40, f"section: {s}")
        for dll in self._imp("python3", "python2"):
            add("python", 60, f"import: {dll}")
        if self._has("pyarmor"):       add("python", 100, "string: pyarmor (obfuscated)")
        if self._has("nuitka"):        add("python", 80, "string: nuitka (compiled python)")

        # Rust
        if self._has("rustc/"):               add("rust", 80, "string: rustc/")
        if self._has("Rust panic"):           add("rust", 60, "string: Rust panic")
        if self._has("panicked at"):          add("rust", 50, "string: panicked at")
        if self._has("core::panicking"):      add("rust", 50, "string: core::panicking")
        for s in self.sec_names:
            if s.startswith(".rustc"):        add("rust", 60, f"section: {s}")

        # .NET
        if self.pe.clr_present():
            add("dotnet", 150, "CLR data directory present")
        for dll in self._imp("mscoree", "coreclr"):
            add("dotnet", 60, f"import: {dll}")
        if self._has("mscorlib"):             add("dotnet", 60, "string: mscorlib")
        if self._has("System.Private.CoreLib"): add("dotnet", 60, "string: System.Private.CoreLib")

        # Delphi
        for dll in self._imp("rtl", "vcl", "borlndmm"):
            add("delphi", 40, f"import: {dll}")
        if self._has("Embarcadero"):         add("delphi", 50, "string: Embarcadero")

        # AutoIt
        if self._has("AU3!"):                add("autoit", 150, "string: AU3!")
        for s in self.sec_names:
            if s in (".a3x", "AutoIt"):      add("autoit", 60, f"section: {s}")

        # Native fallback
        for dll in self._imp("msvcp", "vcruntime", "msvcr", "ucrtbase"):
            add("native_c", 25, f"import: {dll}")
        for dll in self._imp("libstdc++", "libgcc_s", "libwinpthread"):
            add("native_c", 30, f"import: {dll}")
        for d in self.pe.debug_info():
            if d.get("pdb_path", "").lower().endswith(".pdb"):
                add("native_c", 20, f"PDB: {d['pdb_path']}")

        if not scores:
            return ("unknown", [], {})

        ranked = sorted(scores.items(), key=lambda x: -x[1])
        best = ranked[0][0]
        return (best, ranked, evidence)


# ══════════════════════════════════════════════════════════════════════════
# GO PIPELINE
# ══════════════════════════════════════════════════════════════════════════

_GO_BUILDID_RE  = re.compile(rb"Go build ID:\s*([^\s]+)")
_GO_VERSION_RE  = re.compile(rb"go1\.\d+(?:\.\d+)?(?:[a-z]+\d+)?")
_GO_PATH_RE     = re.compile(rb"path\t([^\s\x00]+)")
_GO_MOD_RE      = re.compile(rb"mod\t([^\s\x00]+)\t([^\s\x00]+)")
_GO_DEP_RE      = re.compile(rb"dep\t([^\s\x00]+)\t([^\s\x00]+)")
_GO_BUILDSET_RE = re.compile(rb"build\t(-[a-z]+=[^\s\x00]+)")
_GO_FILE_RE     = re.compile(rb"(?:[A-Za-z]:[\\/]|/)[^\x00-\x1f\"'<>|]{4,200}\.go")


class GoExtractor:
    def __init__(self, pe_file):
        self.pe = pe_file
        self.go_bin = which_go()

    def build_info(self):
        info = {
            "build_id": None, "go_version": None,
            "module_path": None, "dependencies": [], "build_flags": [],
        }
        d = self.pe.data
        m = _GO_BUILDID_RE.search(d)
        if m: info["build_id"] = m.group(1).decode("ascii", "replace")
        m = _GO_VERSION_RE.search(d)
        if m: info["go_version"] = m.group().decode("ascii", "replace")
        m = _GO_PATH_RE.search(d)
        if m: info["module_path"] = m.group(1).decode("utf-8", "replace")
        m = _GO_MOD_RE.search(d)
        if m:
            info["module_path"] = m.group(1).decode("utf-8", "replace")
        for m in _GO_DEP_RE.finditer(d):
            info["dependencies"].append({
                "path": m.group(1).decode("utf-8", "replace"),
                "version": m.group(2).decode("utf-8", "replace"),
            })
        for m in _GO_BUILDSET_RE.finditer(d):
            info["build_flags"].append(m.group(1).decode("ascii", "replace"))
        seen = set()
        deduped = []
        for dep in info["dependencies"]:
            key = (dep["path"], dep["version"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(dep)
        info["dependencies"] = deduped
        info["build_flags"] = list(dict.fromkeys(info["build_flags"]))
        return info

    def nm_symbols(self):
        if not self.go_bin:
            return []
        try:
            r = subprocess.run(
                [self.go_bin, "tool", "nm", self.pe.path],
                capture_output=True, text=True, timeout=300,
                encoding="utf-8", errors="replace",
            )
            if r.returncode != 0:
                return []
            syms = []
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    syms.append({"addr": parts[0], "type": parts[1], "name": parts[2]})
            return syms
        except Exception:
            return []

    def main_functions(self, symbols):
        out = []
        for s in symbols:
            if s["name"].startswith("main."):
                out.append(s["name"])
        return sorted(set(out))

    def objdump(self, func_name, timeout=120):
        if not self.go_bin:
            return ""
        try:
            r = subprocess.run(
                [self.go_bin, "tool", "objdump", f"-s={re.escape(func_name)}",
                 self.pe.path],
                capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    def source_files(self):
        out = set()
        for m in _GO_FILE_RE.finditer(self.pe.data):
            try:
                p = m.group().decode("utf-8", "replace")
                out.add(p)
            except Exception:
                pass
        return sorted(out)


_ASM_LINE_RE = re.compile(
    r"^\s*([^\s:]+\.go):(\d+)\s+(0x[0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(.+)$"
)
_LEAQ_IP_RE = re.compile(r"LEAQ\s+(-?0x[0-9a-fA-F]+)\(IP\),\s+\w+")
_MOVQ_IP_RE = re.compile(r"MOVQ\s+(-?0x[0-9a-fA-F]+)\(IP\),\s+\w+")


def go_asm_strings(asm_text, pe_file):
    hits = []
    for line in asm_text.splitlines():
        m = _ASM_LINE_RE.match(line)
        if not m:
            continue
        src_file, src_line, instr_hex, instr_bytes, instr_text = m.groups()
        src_line = int(src_line)
        instr_addr = int(instr_hex, 16)
        instr_len = len(instr_bytes) // 2
        next_addr = instr_addr + instr_len

        offset = None
        for rx in (_LEAQ_IP_RE, _MOVQ_IP_RE):
            m2 = rx.search(instr_text)
            if m2:
                offset = int(m2.group(1), 16)
                break
        if offset is None:
            continue
        if offset >= 0x80000000:
            offset -= 0x100000000
        target = (next_addr + offset) & 0xFFFFFFFFFFFFFFFF

        file_off = pe_file.va_to_offset(target)
        s = pe_file.read_cstring(file_off) if file_off is not None else None
        if s is None or len(s) < 2:
            continue
        hits.append({
            "file": src_file, "line": src_line,
            "addr": instr_addr, "target": target, "string": s,
        })
    return hits


# ══════════════════════════════════════════════════════════════════════════
# PYTHON PIPELINE
# ══════════════════════════════════════════════════════════════════════════

class PythonExtractor:
    def __init__(self, pe_file, out_dir):
        self.pe = pe_file
        self.out_dir = out_dir
        self.extracted_dir = out_dir / "pyextracted"
        self.pyc_dir = out_dir / "pyc"
        self.source_dir = out_dir / "pysource"

    def has_pyinstaller(self):
        return self.pe.data.find(b"MEI\x0c\x0b\x0a\x0b\x0e") != -1

    def try_pyinstxtractor(self):
        try:
            import pyinstxtractor  # noqa
        except ImportError:
            return None
        self.extracted_dir.mkdir(exist_ok=True)
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pyinstxtractor", self.pe.path],
                capture_output=True, text=True, timeout=300,
                cwd=str(self.out_dir), encoding="utf-8", errors="replace",
            )
            return r.stdout
        except Exception as e:
            return f"pyinstxtractor failed: {e}"

    def try_decompile(self):
        results = []
        if not self.extracted_dir.exists():
            return results
        self.pyc_dir.mkdir(exist_ok=True)
        self.source_dir.mkdir(exist_ok=True)
        for pyc in self.extracted_dir.rglob("*.pyc"):
            dst = self.source_dir / (pyc.stem + ".py")
            ok = self._decompile_one(pyc, dst)
            results.append({
                "pyc": str(pyc.relative_to(self.out_dir)),
                "decompiled": str(dst.relative_to(self.out_dir)) if ok else None,
                "size": pyc.stat().st_size,
            })
        return results

    @staticmethod
    def _decompile_one(pyc_path, out_path):
        tools = [
            ["decompyle3", "-o", str(out_path.parent), str(pyc_path)],
            ["uncompyle6", "-o", str(out_path.parent), str(pyc_path)],
        ]
        for cmd in tools:
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=60,
                                   text=True, encoding="utf-8", errors="replace")
                if r.returncode == 0:
                    return True
            except FileNotFoundError:
                continue
            except Exception:
                continue
        pycdc = find_tool("pycdc", "pycdc.exe")
        if pycdc:
            try:
                r = subprocess.run([pycdc, str(pyc_path)], capture_output=True,
                                   timeout=60, text=True, encoding="utf-8",
                                   errors="replace")
                if r.returncode == 0 and r.stdout.strip():
                    out_path.write_text(r.stdout, encoding="utf-8")
                    return True
            except Exception:
                pass
        return False

    def find_pyz_entries(self):
        entries = []
        for needle in [b"pyimod", b"PYZ-00", b"_MEIPASS", b"python3",
                       b"pyarmor", b"pytransform"]:
            if needle in self.pe.data:
                entries.append(needle.decode("ascii"))
        return entries


# ══════════════════════════════════════════════════════════════════════════
# RUST PIPELINE
# ══════════════════════════════════════════════════════════════════════════

class RustExtractor:
    def __init__(self, pe_file):
        self.pe = pe_file
        self.rustfilt = which_rustfilt()

    def mangled_symbols(self):
        syms = set()
        for s in self.pe.sections:
            if s["name"] not in (".rdata", ".data", ".text"):
                continue
            chunk = self.pe.data[s["raw_ptr"]:s["raw_ptr"] + s["raw_size"]]
            for m in re.finditer(rb"_R[NvMA][A-Za-z0-9_]{6,300}", chunk):
                syms.add(m.group().decode("ascii", "replace"))
        return sorted(syms)

    def demangle(self, symbols):
        if not self.rustfilt:
            return None
        try:
            proc = subprocess.Popen(
                [self.rustfilt],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True,
                encoding="utf-8", errors="replace",
            )
            out, _ = proc.communicate("\n".join(symbols), timeout=120)
            return out.splitlines()
        except Exception:
            return None


# ══════════════════════════════════════════════════════════════════════════
# .NET PIPELINE
# ══════════════════════════════════════════════════════════════════════════

class DotnetExtractor:
    def __init__(self, pe_file, out_dir):
        self.pe = pe_file
        self.out_dir = out_dir
        self.ilspy = which_ilspycmd()

    def run_ilspy(self):
        if not self.ilspy:
            return None
        dst = self.out_dir / "dotnet_decompiled"
        dst.mkdir(exist_ok=True)
        try:
            r = subprocess.run(
                [self.ilspy, self.pe.path, "-o", str(dst)],
                capture_output=True, text=True, timeout=600,
                encoding="utf-8", errors="replace",
            )
            return r.stdout + r.stderr
        except Exception as e:
            return f"ilspycmd failed: {e}"

    def scan_cs_files(self):
        dst = self.out_dir / "dotnet_decompiled"
        if not dst.exists():
            return []
        files = []
        for cs in dst.rglob("*.cs"):
            files.append({
                "path": str(cs.relative_to(self.out_dir)),
                "size": cs.stat().st_size,
            })
        return files


# ══════════════════════════════════════════════════════════════════════════
# REPORT BUILDER
# ══════════════════════════════════════════════════════════════════════════

class ReportBuilder:
    def __init__(self, out_dir, target):
        self.out_dir = out_dir
        self.target = target
        self.parts = []

    def add(self, text=""):
        self.parts.append(text)

    def save(self):
        path = self.out_dir / "REPORT.md"
        path.write_text("\n".join(self.parts), encoding="utf-8")
        return path


# ══════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════

def analyze(target_path, deep=False):
    target = Path(target_path).resolve()
    if not target.is_file():
        log(f"not a file: {target}", "err")
        return 1

    out_dir = target.parent / f"{target.stem}_reversed"
    out_dir.mkdir(exist_ok=True)

    log(f"Target : {target}")
    log(f"Output : {out_dir}")

    log("Parsing PE headers...", "step")
    try:
        pe = PEFile(str(target))
    except pefile.PEFormatError as e:
        log(f"Not a valid PE: {e}", "err")
        return 1

    sm = pe.summary()
    sections = pe.sections
    imports = pe.imports()
    exports = pe.exports()                 # <-- FIXED
    debug = pe.debug_info()                # <-- FIXED

    (out_dir / "sections.txt").write_text(
        "\n".join(
            f"{s['name']:<12} vaddr={hex(s['vaddr'])} vsize={s['vsize']:<10} "
            f"raw={s['raw_size']:<10} entropy={s['entropy']:.3f} flags={s['flags']}"
            for s in sections
        ),
        encoding="utf-8",
    )
    (out_dir / "imports.txt").write_text(
        "\n".join(
            f"{dll}\n" + "\n".join(f"    {f}" for f in funcs)
            for dll, funcs in sorted(imports.items())
        ),
        encoding="utf-8",
    )
    if exports:
        (out_dir / "exports.txt").write_text(
            "\n".join(
                f"{hex(e['ordinal'])} {e['name'] or '(ordinal only)'} @ {e['address']}"
                for e in exports
            ),
            encoding="utf-8",
        )

    log("Extracting raw strings...", "step")
    ascii_s, utf16_s = raw_strings(pe.data)
    all_s = ascii_s + utf16_s
    (out_dir / "strings_ascii.txt").write_text("\n".join(ascii_s), encoding="utf-8")
    (out_dir / "strings_utf16.txt").write_text("\n".join(utf16_s), encoding="utf-8")

    log("Detecting language...", "step")
    detector = Detector(pe)
    best_lang, ranked, evidence = detector.detect()
    log(f"Detected: {best_lang.upper()}", "ok")

    rep = ReportBuilder(out_dir, target)
    rep.add("# Reverse Engineering Report")
    rep.add("")
    rep.add(f"- **Target**: `{target.name}`")
    rep.add(f"- **Full path**: `{target}`")
    rep.add(f"- **Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    rep.add(f"- **SHA256**: `{hashlib.sha256(pe.data).hexdigest()}`")
    rep.add(f"- **Language**: **{best_lang.upper()}**")
    rep.add("")

    rep.add("## PE Header")
    rep.add("")
    rep.add("```")
    for k, v in sm.items():
        rep.add(f"{k:<16}: {v}")
    rep.add("```")
    rep.add("")

    rep.add("## Sections")
    rep.add("")
    rep.add("```")
    rep.add(f"{'Name':<12} {'VAddr':<12} {'VSize':<10} {'RawSize':<10} {'Entropy':<9} Flags")
    for s in sections:
        rep.add(f"{s['name']:<12} {hex(s['vaddr']):<12} {s['vsize']:<10} "
                f"{s['raw_size']:<10} {s['entropy']:<9.3f} {s['flags']}")
    rep.add("```")
    packed = [s["name"] for s in sections if s["entropy"] > 7.2]
    if packed:
        rep.add("")
        rep.add(f"**High-entropy (packed/encrypted):** {', '.join(packed)}")
    rep.add("")

    rep.add("## Language Detection")
    rep.add("")
    rep.add("| Language | Score |")
    rep.add("|---|---|")
    for lang, score in ranked:
        rep.add(f"| {lang} | {score} |")
    rep.add("")
    rep.add(f"**Best guess:** `{best_lang}`")
    rep.add("")
    if evidence.get(best_lang):
        rep.add("**Evidence:**")
        for e in evidence[best_lang]:
            rep.add(f"- {e}")
        rep.add("")

    rep.add("## Imports")
    rep.add("")
    if not imports:
        rep.add("_(no import table — packed or runtime-resolved)_")
    else:
        for dll, funcs in sorted(imports.items()):
            rep.add(f"- **{dll}** ({len(funcs)} functions)")
            for f in funcs[:20]:
                rep.add(f"  - `{f}`")
            if len(funcs) > 20:
                rep.add(f"  - ... +{len(funcs) - 20} more")
    rep.add("")

    if debug:
        rep.add("## Debug / PDB")
        rep.add("")
        for d in debug:
            rep.add(f"- Type {d['type']}, {d['size']} bytes, {d['timestamp']}")
            if "pdb_path" in d:
                rep.add(f"  - **PDB**: `{d['pdb_path']}`")
                rep.add(f"  - **GUID**: `{d['pdb_guid']}`")
        rep.add("")

    if best_lang == "go":
        go_pipeline(pe, out_dir, rep, deep)
    elif best_lang == "python":
        py_pipeline(pe, out_dir, rep)
    elif best_lang == "rust":
        rust_pipeline(pe, out_dir, rep)
    elif best_lang == "dotnet":
        dotnet_pipeline(pe, out_dir, rep)
    else:
        native_pipeline(pe, out_dir, rep, all_s)

    report_path = rep.save()
    log(f"Report saved: {report_path}", "ok")

    print()
    print(f"{C.BOLD}{C.CYAN}══════════════════════════════════════════════════════════════{C.R}")
    print(f"{C.BOLD}{C.CYAN}  DONE — next step{C.R}")
    print(f"{C.BOLD}{C.CYAN}══════════════════════════════════════════════════════════════{C.R}")
    print()
    print(f"  Paste this file back to the AI:")
    print(f"    {C.GREEN}{report_path}{C.R}")
    print()
    print(f"  Full output folder:")
    print(f"    {C.GREEN}{out_dir}{C.R}")
    print()
    print(f"  Files in output folder:")
    for f in sorted(out_dir.iterdir()):
        if f.is_file():
            size_kb = f.stat().st_size / 1024
            print(f"    {f.name:<30} {size_kb:>10.1f} KB")
        else:
            print(f"    {f.name}/")
    print()

    return 0


# ══════════════════════════════════════════════════════════════════════════
# LANGUAGE PIPELINES
# ══════════════════════════════════════════════════════════════════════════

def go_pipeline(pe, out_dir, rep, deep):
    log("Go pipeline: extracting build info...", "step")
    go = GoExtractor(pe)

    bi = go.build_info()
    (out_dir / "go_build_info.txt").write_text(json.dumps(bi, indent=2),
                                                encoding="utf-8")

    rep.add("## Go Build Info")
    rep.add("")
    rep.add("```")
    for k, v in bi.items():
        if k in ("dependencies", "build_flags"):
            continue
        rep.add(f"{k:<16}: {v}")
    if bi["build_flags"]:
        rep.add(f"{'build_flags':<16}: {' '.join(bi['build_flags'])}")
    rep.add("```")
    rep.add("")

    if bi["dependencies"]:
        rep.add(f"### Dependencies ({len(bi['dependencies'])})")
        rep.add("")
        for d in bi["dependencies"]:
            rep.add(f"- `{d['path']}` {d['version']}")
        rep.add("")

    src_files = go.source_files()
    if src_files:
        (out_dir / "go_source_files.txt").write_text("\n".join(src_files),
                                                      encoding="utf-8")
        rep.add(f"### Source Files ({len(src_files)})")
        rep.add("")
        for f in src_files[:80]:
            rep.add(f"- `{f}`")
        if len(src_files) > 80:
            rep.add(f"- ... +{len(src_files) - 80} more")
        rep.add("")

    log("Go pipeline: running go tool nm...", "step")
    symbols = go.nm_symbols()
    if symbols:
        nm_lines = [f"{s['addr']} {s['type']} {s['name']}" for s in symbols]
        (out_dir / "go_symbols.txt").write_text("\n".join(nm_lines),
                                                 encoding="utf-8")

        main_fns = go.main_functions(symbols)
        (out_dir / "go_main_functions.txt").write_text("\n".join(main_fns),
                                                        encoding="utf-8")

        rep.add(f"### main.* Functions ({len(main_fns)})")
        rep.add("")
        for fn in main_fns:
            rep.add(f"- `{fn}`")
        rep.add("")

        if go.go_bin:
            disasm_dir = out_dir / "disasm"
            disasm_dir.mkdir(exist_ok=True)
            log(f"Go pipeline: disassembling {len(main_fns)} main functions...", "step")

            all_strings = []
            for fn in main_fns:
                asm = go.objdump(fn)
                if not asm:
                    continue
                safe = re.sub(r"[^\w]", "_", fn)
                (disasm_dir / f"{safe}.asm").write_text(asm, encoding="utf-8")

                hits = go_asm_strings(asm, pe)
                for h in hits:
                    h["func"] = fn
                    all_strings.append(h)

            if all_strings:
                lines = []
                by_func = OrderedDict()
                for h in all_strings:
                    by_func.setdefault(h["func"], []).append(h)
                for fn, hits in by_func.items():
                    lines.append(f"=== {fn} ===")
                    seen = set()
                    for h in hits:
                        key = (h["file"], h["line"], h["string"])
                        if key in seen:
                            continue
                        seen.add(key)
                        preview = h["string"].replace("\n", "\\n").replace("\r", "\\r")
                        if len(preview) > 160:
                            preview = preview[:157] + "..."
                        lines.append(f"  {h['file']}:{h['line']}  \"{preview}\"")
                    lines.append("")
                (out_dir / "go_asm_strings.txt").write_text("\n".join(lines),
                                                             encoding="utf-8")

                rep.add("### Recovered String Literals (from asm)")
                rep.add("")
                for fn in main_fns:
                    if fn not in by_func:
                        continue
                    uniq = []
                    seen = set()
                    for h in by_func[fn]:
                        if h["string"] in seen:
                            continue
                        seen.add(h["string"])
                        uniq.append(h)
                    if not uniq:
                        continue
                    rep.add(f"#### `{fn}` ({len(uniq)} strings)")
                    rep.add("")
                    for h in uniq[:30]:
                        preview = h["string"].replace("\n", "\\n").replace("\r", "\\r")
                        if len(preview) > 160:
                            preview = preview[:157] + "..."
                        rep.add(f"- `{h['file']}:{h['line']}` → \"{preview}\"")
                    if len(uniq) > 30:
                        rep.add(f"- ... +{len(uniq) - 30} more")
                    rep.add("")
        else:
            rep.add("### Disassembly")
            rep.add("")
            rep.add("_Go toolchain not found — install Go to get asm dumps_")
            rep.add("")
    else:
        rep.add("### Symbols")
        rep.add("")
        rep.add("_`go tool nm` returned nothing — Go toolchain missing or binary stripped_")
        rep.add("")

    goremsym = which_goremsym()
    if goremsym:
        log("Go pipeline: running GoReSym...", "step")
        try:
            r = subprocess.run(
                [goremsym, "-t", "-d", "-p", pe.path],
                capture_output=True, text=True, timeout=300,
                encoding="utf-8", errors="replace",
            )
            if r.stdout:
                (out_dir / "goremsym.json").write_text(r.stdout, encoding="utf-8")
                try:
                    js = json.loads(r.stdout)
                    files = js.get("Files") or []
                    if files:
                        rep.add(f"### Original Source Files (from GoReSym) ({len(files)})")
                        rep.add("")
                        for f in files[:60]:
                            rep.add(f"- `{f}`")
                        if len(files) > 60:
                            rep.add(f"- ... +{len(files) - 60} more")
                        rep.add("")
                except Exception:
                    pass
        except Exception as e:
            log(f"GoReSym failed: {e}", "warn")


def py_pipeline(pe, out_dir, rep):
    log("Python pipeline: extracting PyInstaller archive...", "step")
    py = PythonExtractor(pe, out_dir)

    rep.add("## Python / PyInstaller")
    rep.add("")
    rep.add(f"- PyInstaller CArchive magic present: **{py.has_pyinstaller()}**")
    markers = py.find_pyz_entries()
    if markers:
        rep.add(f"- Internal markers: {', '.join(markers)}")
    rep.add("")

    log("Trying pyinstxtractor...", "step")
    result = py.try_pyinstxtractor()
    if result:
        (out_dir / "pyinstaller_extract.txt").write_text(result, encoding="utf-8")
        rep.add("### pyinstxtractor output")
        rep.add("")
        rep.add("```")
        rep.add(result[:3000])
        rep.add("```")
        rep.add("")

        log("Attempting decompilation...", "step")
        decomp = py.try_decompile()
        if decomp:
            rep.add(f"### Decompiled .pyc files ({sum(1 for d in decomp if d['decompiled'])})")
            rep.add("")
            for d in decomp:
                if d["decompiled"]:
                    rep.add(f"- `{d['pyc']}` → `{d['decompiled']}`")
            rep.add("")
    else:
        rep.add("### pyinstxtractor")
        rep.add("")
        rep.add("Not installed. Install with:")
        rep.add("")
        rep.add("```")
        rep.add("pip install pyinstxtractor")
        rep.add("```")
        rep.add("")

    decomp = py.try_decompile()
    if decomp:
        rep.add(f"### Decompiled .pyc files ({sum(1 for d in decomp if d['decompiled'])})")
        rep.add("")
        for d in decomp:
            if d["decompiled"]:
                rep.add(f"- `{d['pyc']}` → `{d['decompiled']}`")
        rep.add("")


def rust_pipeline(pe, out_dir, rep):
    log("Rust pipeline: extracting mangled symbols...", "step")
    rs = RustExtractor(pe)

    syms = rs.mangled_symbols()
    (out_dir / "rust_mangled.txt").write_text("\n".join(syms), encoding="utf-8")

    rep.add("## Rust")
    rep.add("")
    rep.add(f"- Mangled symbols found: **{len(syms)}**")
    rep.add(f"- rustfilt available: **{rs.rustfilt is not None}**")
    rep.add("")

    if syms:
        demangled = rs.demangle(syms)
        if demangled:
            (out_dir / "rust_demangled.txt").write_text(
                "\n".join(demangled), encoding="utf-8"
            )
            rep.add("### Demangled symbols (first 100)")
            rep.add("")
            for s in demangled[:100]:
                rep.add(f"- `{s}`")
            if len(demangled) > 100:
                rep.add(f"- ... +{len(demangled) - 100} more")
            rep.add("")
        else:
            rep.add("### Mangled symbols (first 100)")
            rep.add("")
            rep.add("Install rustfilt for demangling: `cargo install rustfilt`")
            rep.add("")
            for s in syms[:100]:
                rep.add(f"- `{s}`")
            rep.add("")


def dotnet_pipeline(pe, out_dir, rep):
    log(".NET pipeline: running ilspycmd...", "step")
    dn = DotnetExtractor(pe, out_dir)

    rep.add("## .NET")
    rep.add("")
    rep.add(f"- ilspycmd available: **{dn.ilspy is not None}**")
    rep.add("")

    if dn.ilspy:
        log("Running ilspycmd (this may take a while)...", "step")
        result = dn.run_ilspy()
        if result:
            (out_dir / "ilspy_output.txt").write_text(result, encoding="utf-8")

        cs_files = dn.scan_cs_files()
        if cs_files:
            rep.add(f"### Decompiled .cs files ({len(cs_files)})")
            rep.add("")
            for f in cs_files[:100]:
                rep.add(f"- `{f['path']}` ({f['size']} bytes)")
            if len(cs_files) > 100:
                rep.add(f"- ... +{len(cs_files) - 100} more")
            rep.add("")
    else:
        rep.add("### Install ilspycmd")
        rep.add("")
        rep.add("```")
        rep.add("dotnet tool install -g ilspycmd")
        rep.add("```")
        rep.add("")


def native_pipeline(pe, out_dir, rep, all_s):
    rep.add("## Native Binary")
    rep.add("")
    rep.add("_Detected as native C/C++ or unknown. Recommended tools:_")
    rep.add("")
    rep.add("- **Ghidra** (free) — best decompiler")
    rep.add("- **IDA Pro / Hex-Rays** (paid) — best for C++")
    rep.add("- **Binary Ninja** (paid)")
    rep.add("- **RetDec** (free, older)")
    rep.add("")

    interesting = []
    patterns = ("http://", "https://", "/api/", ".dll", ".exe",
                "error", "Error", "ERROR", "password", "username",
                "login", "token", "secret", "api_key", "Authorization")
    for s in all_s:
        for p in patterns:
            if p in s and 3 < len(s) < 250:
                interesting.append(s)
                break
        if len(interesting) > 300:
            break

    if interesting:
        rep.add(f"### Interesting Strings ({len(interesting)})")
        rep.add("")
        for s in interesting[:150]:
            preview = s.replace("\n", "\\n").replace("\r", "\\r")
            if len(preview) > 140:
                preview = preview[:137] + "..."
            rep.add(f"- `{preview}`")
        if len(interesting) > 150:
            rep.add(f"- ... +{len(interesting) - 150} more")
        rep.add("")


# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

def interactive():
    banner()
    print(f"  Drag & drop your .exe here, or type the full path.")
    print()
    raw = input(f"{C.CYAN}[?]{C.R} EXE path: ").strip().strip('"').strip("'")
    if not raw or not os.path.isfile(raw):
        log(f"not a file: {raw}", "err")
        return 1
    print()
    deep = input(f"  Deep disassembly of all main.* functions? (y/N): ").strip().lower()
    return analyze(raw, deep=deep in ("y", "yes", "1"))


def main():
    if len(sys.argv) < 2:
        try:
            return interactive()
        except KeyboardInterrupt:
            print()
            return 130

    ap = argparse.ArgumentParser(description="Universal EXE reverse engineering toolkit")
    ap.add_argument("target", nargs="?")
    ap.add_argument("--deep", action="store_true",
                    help="Disassemble all main.* functions (Go)")
    args = ap.parse_args()

    if args.target:
        return analyze(args.target, deep=args.deep)
    return interactive()


if __name__ == "__main__":
    sys.exit(main())