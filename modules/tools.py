"""External tool management for Crackbaby: discovery, status, and wordlist download.

Covers hashcat and the hashcat combinator.bin utility (the combo_rules fallback when the
rule-convert threshold is exceeded), plus a stdlib-only wordlist downloader.

  _find_combinator_bin   — locate combinator.bin relative to hashcat binary
  _preflight_check       — lightweight status check (called by cmd_tools)
  download_wordlist      — fetch a named wordlist (or URL) into ~/wordlists
"""

import gzip
import logging
import os
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Optional

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
    """Directory crackbaby downloads wordlists into by default (``~/wordlists``).

    This path is one of ``phases._WORDLIST_SEARCH_PATHS`` and a fallback in
    ``_find_default_wordlists``, so anything dropped here is auto-discovered by ``init``.
    """
    return os.path.expanduser("~/wordlists")


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
    written atomically into ``dest_dir`` (default ``~/wordlists``), where ``init``
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


def _find_combinator_bin(campaign=None, hashcat_bin: Optional[str] = None) -> Optional[str]:
    """Locate hashcat's combinator.bin utility, or None if not found.

    combinator.bin ships alongside hashcat and is used as the fallback strategy
    for combo_rules phases when the smaller wordlist exceeds max_rule_convert_words.

    Search order:
      1. Same directory as the campaign's hashcat binary
      2. Platform-specific expected names: combinator.bin (Linux/macOS), combinator.exe (Windows)
      3. PATH lookup
    """
    if campaign is not None and hashcat_bin is None:
        hashcat_bin = getattr(campaign, "hashcat_bin", None)

    names = (["combinator.exe", "combinator64.exe"] if os.name == "nt"
             else ["combinator.bin", "combinator64.bin", "combinator"])

    # Check same directory as hashcat binary first
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
        print("  [!] combinator.bin  : not found  (needed for combo_rules fallback)")
        if hashcat_bin:
            hc_dir = os.path.dirname(os.path.abspath(hashcat_bin))
            print(f"       Expected at: {hc_dir}/combinator.bin")
            print("       combinator.bin ships with hashcat — check your hashcat install directory.")

    # default wordlist (rockyou)
    rockyou = None
    for d in (default_wordlists_dir(), "/usr/share/wordlists", "/opt/wordlists"):
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
