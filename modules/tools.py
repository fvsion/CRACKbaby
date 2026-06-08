"""External tool management for CRACKbaby: discovery, status, and downloads.

Covers hashcat and the hashcat combinator utility (the combo_rules fallback when the
rule-convert threshold is exceeded), plus stdlib-only downloaders for wordlists and
combinator.

  _find_combinator_bin   — locate the combinator binary (installed_tools / hashcat / PATH)
  _preflight_check       — lightweight status check (called by cmd_tools)
  download_wordlist      — fetch a named wordlist (or URL) into <install>/wordlists
  build_combinator_bin   — download + compile combinator into <install>/installed_tools
"""

import gzip
import logging
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Optional

from . import CRACKBABY_ROOT

logger = logging.getLogger(__name__)


# ── Wordlist downloader ───────────────────────────────────────────────────────

# Named wordlist sources. Extensible: add entries here, or pass a raw http(s) URL.
_WORDLIST_SOURCES = {
    "rockyou": {
        "url": "https://weakpass.com/download/90/rockyou.txt.gz",
        "filename": "rockyou.txt",
        "gz": True,
        "desc": "rockyou (~14.3M passwords) — the standard baseline wordlist",
    },
}


def default_wordlists_dir() -> str:
    """Directory crackbaby downloads wordlists into by default — ``<install>/wordlists``.

    This repo-local ``wordlists/`` dir is on ``phases._WORDLIST_SEARCH_PATHS`` and is a
    ``_find_default_wordlists`` fallback, so anything dropped here is auto-discovered by
    ``init``. (``~/wordlists``, ``/opt/wordlists`` and ``/usr/share/wordlists`` are still
    searched too.)
    """
    return os.path.join(CRACKBABY_ROOT, "wordlists")


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def download_wordlist(source: str = "rockyou", dest_dir: Optional[str] = None,
                      force: bool = False) -> Optional[str]:
    """Download a wordlist by registry name (e.g. ``"rockyou"``) or a raw http(s) URL.

    Standard library only (urllib + gzip). ``.gz`` sources are decompressed. The file is
    written atomically into ``dest_dir`` (default ``<install>/wordlists``), where ``init``
    auto-discovers it. Returns the final wordlist path, or ``None`` on failure (after
    printing a clear error and the URL for manual download).
    """
    src = _WORDLIST_SOURCES.get(source)
    if src:
        url, filename, is_gz = src["url"], src["filename"], src.get("gz", False)
    else:
        # Treat `source` as a raw URL (lets callers fetch arbitrary wordlists).
        url = source
        if not (url.startswith("http://") or url.startswith("https://")):
            print(f"  ERROR: unknown wordlist '{source}'. Known names: "
                  f"{', '.join(sorted(_WORDLIST_SOURCES))} — or pass a http(s) URL.")
            return None
        filename = os.path.basename(url.split("?")[0]) or "wordlist.txt"
        is_gz = filename.endswith(".gz")
        if is_gz:
            filename = filename[:-3]

    dest_dir = os.path.abspath(os.path.expanduser(dest_dir or default_wordlists_dir()))
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as e:
        print(f"  ERROR: cannot create wordlist directory {dest_dir}: {e}")
        return None

    dest = os.path.join(dest_dir, filename)
    if os.path.isfile(dest) and os.path.getsize(dest) > 0 and not force:
        print(f"  [✓] {filename} already present: {dest}")
        print( "      Pass --force to re-download.")
        return dest

    print(f"  Downloading {filename}")
    print(f"    from {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "crackbaby/1.0"})
    tmp = dest + ".part"
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(),
                                    timeout=60) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            done, last = 0, 0.0
            with open(tmp, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)   # 1 MiB
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    now = time.time()
                    if now - last > 0.2 or done == total:
                        if total:
                            sys.stdout.write(f"\r    {done / total * 100:5.1f}%  "
                                             f"({_fmt_bytes(done)} / {_fmt_bytes(total)})")
                        else:
                            sys.stdout.write(f"\r    {_fmt_bytes(done)} downloaded")
                        sys.stdout.flush()
                        last = now
            sys.stdout.write("\n")
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as e:
        print(f"\n  ERROR: download failed: {e}")
        print(f"  Fetch it manually into {dest_dir}:")
        print(f"    curl -L -o '{dest}{'.gz' if is_gz else ''}' '{url}'"
              + (f" && gunzip '{dest}.gz'" if is_gz else ""))
        try:
            os.path.exists(tmp) and os.unlink(tmp)
        except OSError:
            pass
        return None

    # Decompress (if gzipped) and put the file in place atomically.
    try:
        if is_gz:
            print(f"  Decompressing → {filename} …")
            with gzip.open(tmp, "rb") as gz, open(dest + ".out", "wb") as out:
                shutil.copyfileobj(gz, out, 1 << 20)
            os.replace(dest + ".out", dest)
            os.unlink(tmp)
        else:
            os.replace(tmp, dest)
    except (OSError, gzip.BadGzipFile) as e:
        print(f"  ERROR: could not unpack the download: {e}")
        for p in (tmp, dest + ".out"):
            try:
                os.path.exists(p) and os.unlink(p)
            except OSError:
                pass
        return None

    if not (os.path.isfile(dest) and os.path.getsize(dest) > 0):
        print("  ERROR: the downloaded wordlist is empty.")
        return None

    print(f"  [✓] {filename} ready: {dest}  ({_fmt_bytes(os.path.getsize(dest))})")
    return dest


# ── combinator (hashcat-utils) ────────────────────────────────────────────────

_HCUTILS_RAW = "https://raw.githubusercontent.com/hashcat/hashcat-utils/master/src/"
# combinator.c is a unity build: it `#include "utils.c"`, so both files are fetched and
# combinator.c (the one with main()) is the compile target.
_COMBINATOR_SRCS = ("utils.c", "combinator.c")
_COMBINATOR_MAIN = "combinator.c"
_COMBINATOR_LEN_MAX = 512   # hashcat-utils Makefile COMBINATOR_LEN_MAX (compile-time -DLEN_MAX)


def installed_tools_dir() -> str:
    """Repo-local ``installed_tools/`` dir where crackbaby builds helper binaries."""
    return os.path.join(CRACKBABY_ROOT, "installed_tools")


def _safe_unlink(*paths) -> None:
    for p in paths:
        try:
            if p and os.path.exists(p):
                os.unlink(p)
        except OSError:
            pass


def build_combinator_bin(force: bool = False) -> Optional[str]:
    """Download hashcat-utils' combinator source and compile it into ``installed_tools/``.

    combinator is the combo_rules fallback. hashcat-utils ships it only as source or a .7z
    (which the stdlib can't unpack), so we fetch combinator.c and compile it with the system
    C compiler. Portable: produces combinator.exe on Windows, combinator.bin on Linux/macOS;
    if no compiler is present, prints platform guidance and returns None. Skips when
    combinator is already found (unless ``force``). Returns the built path, or None.
    """
    out_name = "combinator.exe" if os.name == "nt" else "combinator.bin"
    dest_dir = installed_tools_dir()
    dest = os.path.join(dest_dir, out_name)

    if not force:
        existing = _find_combinator_bin()
        if existing:
            print(f"  [✓] combinator already present: {existing}")
            print( "      Pass --force to rebuild.")
            return existing

    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not cc:
        print("  ERROR: no C compiler (cc/clang/gcc) found — cannot build combinator.")
        if os.name == "nt":
            print("  combinator.exe ships in hashcat-utils releases:")
            print("    https://github.com/hashcat/hashcat-utils/releases")
            print(f"  Download it and drop combinator.exe into {dest_dir}")
        else:
            print("  Install a C compiler (Xcode CLT / build-essential), then retry — or:")
            print("    • brew install hashcat-utils                 (macOS)")
            print(f"    • copy combinator.bin from your hashcat install into {dest_dir}")
        return None

    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as e:
        print(f"  ERROR: cannot create {dest_dir}: {e}")
        return None

    print(f"  Building combinator from source (compiler: {cc})")
    print(f"    src: {_HCUTILS_RAW}{{{', '.join(_COMBINATOR_SRCS)}}}")
    tmp_out = dest + ".part"
    src_paths = []
    try:
        for name in _COMBINATOR_SRCS:
            req = urllib.request.Request(_HCUTILS_RAW + name,
                                         headers={"User-Agent": "crackbaby/1.0"})
            with urllib.request.urlopen(req, context=ssl.create_default_context(),
                                        timeout=60) as resp:
                data = resp.read()
            if not data:
                print(f"  ERROR: downloaded {name} is empty.")
                _safe_unlink(*src_paths)
                return None
            p = os.path.join(dest_dir, name)
            with open(p, "wb") as f:
                f.write(data)
            src_paths.append(p)
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as e:
        print(f"\n  ERROR: could not download combinator sources: {e}")
        print(f"  Source: {_HCUTILS_RAW}")
        _safe_unlink(*src_paths)
        return None

    # combinator.c #includes utils.c, so compile from dest_dir (the relative include resolves).
    try:
        proc = subprocess.run([cc, "-O2", "-std=gnu99",
                               f"-DLEN_MAX={_COMBINATOR_LEN_MAX}",
                               "-o", tmp_out, _COMBINATOR_MAIN],
                              cwd=dest_dir, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  ERROR: compiler invocation failed: {e}")
        _safe_unlink(*src_paths, tmp_out)
        return None
    if proc.returncode != 0:
        print("  ERROR: compiling combinator failed:")
        for ln in (proc.stderr or proc.stdout or "").splitlines()[-8:]:
            print(f"    {ln}")
        _safe_unlink(*src_paths, tmp_out)
        return None

    try:
        os.replace(tmp_out, dest)
        if os.name != "nt":
            os.chmod(dest, 0o755)
    except OSError as e:
        print(f"  ERROR: finalizing the combinator build failed: {e}")
        _safe_unlink(*src_paths, tmp_out)
        return None
    _safe_unlink(*src_paths)

    if not (os.path.isfile(dest) and os.path.getsize(dest) > 0):
        print("  ERROR: the build produced an empty binary.")
        return None
    print(f"  [✓] combinator ready: {dest}")
    return dest


def _find_combinator_bin(campaign=None, hashcat_bin: Optional[str] = None) -> Optional[str]:
    """Locate hashcat's combinator.bin utility, or None if not found.

    combinator is used as the fallback strategy for combo_rules phases when the smaller
    wordlist exceeds max_rule_convert_words. It ships with hashcat, or crackbaby can build
    it (`tools --download combinator`) into installed_tools/.

    Search order (platform-correct names: combinator.bin on Linux/macOS, .exe on Windows):
      1. crackbaby's installed_tools/  (where `tools --download combinator` builds it)
      2. Same directory as the campaign's hashcat binary
      3. PATH lookup
    """
    if campaign is not None and hashcat_bin is None:
        hashcat_bin = getattr(campaign, "hashcat_bin", None)

    names = (["combinator.exe", "combinator64.exe"] if os.name == "nt"
             else ["combinator.bin", "combinator64.bin", "combinator"])

    # 1. crackbaby's own build in installed_tools/
    it_dir = installed_tools_dir()
    for name in names:
        candidate = os.path.join(it_dir, name)
        if os.path.isfile(candidate) and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return candidate

    # 2. Same directory as hashcat binary
    if hashcat_bin:
        hc_dir = os.path.dirname(os.path.abspath(hashcat_bin))
        for name in names:
            candidate = os.path.join(hc_dir, name)
            if os.path.isfile(candidate) and (os.name == "nt" or os.access(candidate, os.X_OK)):
                return candidate

    # PATH lookup
    for name in names:
        hit = shutil.which(name)
        if hit:
            return hit

    return None


def _preflight_check(campaign=None) -> None:
    """Display tool status for cmd_tools. Shows hashcat and combinator.bin."""
    import sys

    hashcat_bin = getattr(campaign, "hashcat_bin", None) if campaign else None
    combo_bin   = _find_combinator_bin(campaign=campaign)

    print("\n  ── CRACKbaby Tool Status ─────────────────────────────────────────")

    # hashcat
    if hashcat_bin and os.path.isfile(hashcat_bin):
        print(f"  [✓] hashcat         : {hashcat_bin}")
    elif hashcat_bin and shutil.which(hashcat_bin):
        print(f"  [✓] hashcat         : {shutil.which(hashcat_bin)}")
    else:
        hc = shutil.which("hashcat") or shutil.which("hashcat.bin")
        if hc:
            print(f"  [✓] hashcat         : {hc}")
        else:
            print("  [✗] hashcat         : NOT FOUND  (required)")
            print("       Install from https://hashcat.net/hashcat/")

    # combinator.bin
    if combo_bin:
        print(f"  [✓] combinator.bin  : {combo_bin}")
    else:
        print("  [!] combinator.bin  : not found  (combo_rules fallback)")
        print("       Build it with:  crackbaby tools --download combinator")
        print("       (it also ships with hashcat — combinator.bin in your hashcat dir)")

    # default wordlist (rockyou)
    rockyou = None
    for d in (default_wordlists_dir(), os.path.expanduser("~/wordlists"),
              "/usr/share/wordlists", "/opt/wordlists"):
        p = os.path.join(d, "rockyou.txt")
        if os.path.isfile(p) and os.path.getsize(p) > 0:
            rockyou = p
            break
    if rockyou:
        print(f"  [✓] rockyou.txt     : {rockyou}")
    else:
        print("  [!] rockyou.txt     : not found  (default wordlist)")
        print("       Download it with:  crackbaby tools --download rockyou")

    print()
