#!/usr/bin/env python3
"""
CRACKbaby — NTLM Password Recovery Tool
========================================
Wraps hashcat for systematic, resumable NTLM cracking campaigns.

Run `crackbaby --help` (or `crackbaby <command> --help`) for usage.
"""

import argparse
import functools
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional

# ── Make the bundled `modules/` package importable from any CWD / symlink ─────
# Resolve this script's real location (realpath follows symlinks, e.g. a
# /usr/local/bin/crackbaby -> /opt/crackbaby/crackbaby.py symlink) and put the
# install root on sys.path so `modules.*` imports succeed no matter where
# crackbaby is invoked from or how it was launched.
_ROOT = os.path.dirname(os.path.realpath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from modules import CRACKBABY_ROOT as _CRACKBABY_DIR, CONFIG_DIR as _CONFIG_DIR
from modules.campaign import Campaign, Phase
from modules.runner import HashcatRunner
from modules.phases import (build_initial_phases, _new_id,
                            reset_counter, _RULE_SEARCH_PATHS, _WORDLIST_SEARCH_PATHS,
                            _BUNDLED_RULES_DIR, _resolve_no_opt)
from modules.reporter import Reporter
from modules.speed import (
    _SPEED_FACTORS_FILE,
    _effective_speed_ghs, _estimate_eta,
    _fmt_speed, _parse_speed_hps, _run_per_type_benchmark, _phase_estimated_hours,
    _phase_speed_ghs, _phase_speed_key,
)
from modules.tools import (_find_combinator_bin, _preflight_check,
                           download_wordlist, _WORDLIST_SOURCES)

# ── CRACKbaby directories ─────────────────────────────────────────────────────
# _CRACKBABY_DIR → install root (bundled assets: rules/).
# _CONFIG_DIR    → config/ subdir (speed_factors.json, crackbaby.json).
# Speed/timing model (factors, history, ETA, gating, benchmark) → modules/speed.py.

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Version ─────────────────────────────────────────────────────────────────
# Single source of truth for the release version. Update here on every release;
# the banner and `crackbaby --version` both read this. (README.md and USER_GUIDE.md
# headers track this value but cannot import it — bump manually per the release checklist.)
__version__ = "1.0.0"

# Compact labels for the phases-list "Feed" column.
_FEED_ABBR = {
    "rule_convert": "rule", "combinator_bin": "combo.bin",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

class _GroupedSubcommandHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Top-level help formatter that renders the subcommands as titled groups.

    argparse has no native way to put headings *between* groups of subcommands, so
    we intercept the single ``_SubParsersAction`` and emit its choice pseudo-actions
    grouped under the ``command_groups`` titles — reusing the parent's per-action
    formatting so each command line keeps argparse's native colouring/alignment
    (Python 3.14+). On older Pythons there is no ``_theme``; headings render plain.
    """

    def __init__(self, prog, *, command_groups=(), **kwargs):
        self._command_groups = command_groups   # [(title, [name, ...]), ...]
        super().__init__(prog, **kwargs)

    def _format_action(self, action):
        if not isinstance(action, argparse._SubParsersAction):
            return super()._format_action(action)
        subs = {sa.dest: sa for sa in action._get_subactions()}
        theme = getattr(self, "_theme", None)        # None on Python < 3.14
        h = getattr(theme, "heading", "") if theme else ""
        r = getattr(theme, "reset", "") if theme else ""
        parts, seen = [], set()
        for title, names in self._command_groups:
            shown = [n for n in names if n in subs]
            if not shown:
                continue
            parts.append(f"{h}{title}:{r}\n")
            for n in shown:
                parts.append(super()._format_action(subs[n]))  # colored + aligned
                seen.add(n)
            parts.append("\n")
        for n, sa in subs.items():                   # safety: any ungrouped command
            if n not in seen:
                parts.append(super()._format_action(sa))
        return self._join_parts(parts)


def _print_banner():
    left = [
        "                                        :*@@%-",
        "                                     =@@@@@@@@@#",
        "                                    *@@@@@@@@@@@@*",
        "                                   :@@@#..:-.-%@@@=",
        "                                   =@@*.=%%=*@@@@@@",
        "                                   *@@%#@@@@@@@@@@@",
        "                            .:=*#%%#@@@@@@%@@@@@@@+",
        "                      .:=*#%%%%%%%%*=#@@@%==++*%#-",
        "                  .::-=+%%%%%*=-::----:#@@@%%#=:.",
        "                .:-====+*=:::::::-===-=*+%@@%+:",
        "               :=****=::+=-::...:--:=:=#+:...",
        "               =%%*+===--#:-::. :==+=.=%*:",
        "              .+%=-::::-.*%@@@@@@@*#*+-%%=",
        "     .=#%*+*@@@%%=....:-.-@@@@@@#@*%=%-*@*:",
        "  :#@%@@@@%@%%@@#:  ..-=:*+     :@*#=%@-##-",
        " %@@@@@#+%@+.:-:: ..-+=+**:     .%#=#*#.=%*:",
        " @@@@@@%#+===+*=:-::==*#*=.      =%--.=*:+@%@%#+:",
        " @@@@@@@@@@%#*#%***#%@%*=-.      :+*%%@%%=-:::==-",
    ]
    right = [
        " _____ ______  ___  _____  _   __",
        "/  __ \\| ___ \\/ _ \\/  __ \\| | / /",
        "| /  \\/| |_/ / /_\\ \\ /  \\/| |/ / ",
        "| |    |    /|  _  | |    |    \\ ",
        "| \\__/\\| |\\ \\| | | | \\__/\\| |\\  \\",
        " \\____/\\_| \\_\\_| |_/\\____/\\_| \\_/",
        "          b  a  b  y",
    ]
    print()
    W = 52  # pad left column to this width before appending right column
    for i, line in enumerate(left):
        ri = i - (len(left) - len(right))  # right index: only positive for last len(right) rows
        if ri >= 0:
            print(line.ljust(W) + "  " + right[ri])
        else:
            print(line)
    print(f"\n  CRACKbaby v{__version__}  —  NTLM Password Recovery\n")


def _tail_log(log_path: str, n: int = 15) -> str:
    """Return the last n lines of a log file."""
    try:
        with open(log_path) as f:
            lines = f.readlines()
        return "".join(lines[-n:]).rstrip()
    except Exception:
        return ""


_RULE_CONVERT_MAX_WORD_LEN = 120


# Max characters allowed in a small-side word for rule conversion. Each char
# becomes a 2-char rule token ($x or ^x); hashcat's rule line buffer caps near
# 256 bytes, so 120 chars → 240 token chars stays safely under the limit.
_RULE_CONVERT_MAX_WORD_LEN = 120


def _wordlist_to_rules(src_path: str, out_path: str, mode: str):
    """Convert a wordlist into a hashcat rule file that appends/prepends each
    word, so a wl1×wl2 combination can run fully on-GPU as
    `hashcat -a 0 <base> -r <this> -r <best66>`.

    mode="suffix": word "acme" → rule "$a$c$m$e"   (append: base + word)
    mode="prefix": word "acme" → rule "^e^m^c^a"   (prepend: word + base;
                   '^' inserts at front, so chars are emitted in reverse)

    Only printable-ASCII words ≤ _RULE_CONVERT_MAX_WORD_LEN are converted; any
    word with non-ASCII bytes or excessive length is skipped. Returns (written, skipped).
    """
    written = 0
    skipped = 0
    op = "$" if mode == "suffix" else "^"
    with open(src_path, "rb") as fin, open(out_path, "w", encoding="ascii",
                                           errors="strict") as fout:
        _batch = []
        for raw in fin:
            w = raw.rstrip(b"\r\n")
            if not w:
                continue
            if len(w) > _RULE_CONVERT_MAX_WORD_LEN or any(b < 0x20 or b > 0x7E for b in w):
                skipped += 1
                continue
            s = w.decode("ascii")
            chars = s if mode == "suffix" else s[::-1]
            _batch.append("".join(op + c for c in chars))
            written += 1
            if len(_batch) >= 10000:
                fout.write("\n".join(_batch) + "\n")
                _batch.clear()
        if _batch:
            fout.write("\n".join(_batch) + "\n")
    return written, skipped


def _convert_small_side_to_rules(campaign, small_path: str, mode: str):
    """Generate a rule file from a small wordlist side.

    Writes the rule file to the campaign's wordlists directory.
    Returns the rule-file path, or None on failure.
    """
    import hashlib
    cache_dir = os.path.join(campaign.wordlists_dir, "rules_cache")
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError as _e:
        print(f"  [WARN] cannot create rules cache dir {cache_dir}: {_e}")
        return None

    a = os.path.abspath(small_path)
    sz = os.path.getsize(small_path)
    key = hashlib.sha1(f"rules|{a}|{sz}|{mode}".encode()).hexdigest()[:16]
    rule_path = os.path.join(cache_dir, f"{key}.rule")

    if os.path.exists(rule_path) and os.path.getsize(rule_path) > 0:
        print(f"  [rules_cache] reusing {rule_path}")
        return rule_path

    try:
        written, skipped = _wordlist_to_rules(small_path, rule_path, mode)
    except Exception as e:
        print(f"  [WARN] rule conversion failed: {e}")
        try: os.unlink(rule_path)
        except OSError: pass
        return None

    if written == 0:
        print(f"  [WARN] rule conversion produced 0 usable rules "
              f"(all {skipped} words skipped) — cannot use rules strategy")
        try: os.unlink(rule_path)
        except OSError: pass
        return None

    msg = f"  [rules] converted {written:,} word(s) → {mode} rules: {rule_path}"
    if skipped:
        msg += f"  ({skipped:,} skipped: non-ASCII or >{_RULE_CONVERT_MAX_WORD_LEN} chars)"
    print(msg)
    return rule_path


def _find_hashcat() -> str:
    import shutil
    # Standard release binary names first, then the bare "hashcat" (distro packages)
    _bin = "hashcat.exe" if sys.platform == "win32" else "hashcat.bin"
    for name in (_bin, "hashcat"):
        found = shutil.which(name)
        if found:
            return os.path.abspath(found)
    candidates = [
        # Linux / macOS
        "/usr/bin/hashcat", "/usr/local/bin/hashcat",
        "/opt/hashcat/hashcat.bin", "/opt/hashcat/hashcat",
        os.path.expanduser("~/tools/hashcat/hashcat.bin"),
        os.path.expanduser("~/tools/hashcat/hashcat"),
        os.path.expanduser("~/hashcat/hashcat.bin"),
        # Windows
        os.path.join("C:\\", "hashcat", "hashcat.exe"),
        os.path.join("C:\\", "tools", "hashcat", "hashcat.exe"),
        os.path.expanduser(os.path.join("~", "hashcat", "hashcat.exe")),
        os.path.join("C:\\", "Users", os.environ.get("USERNAME", ""), "hashcat", "hashcat.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    # Fallback: use platform-appropriate binary name — will fail clearly at verify_binary()
    return _bin


# Extensions treated as plaintext wordlists during auto-discovery.  hashcat -a 0
# cannot read .gz, so it is intentionally excluded.
_WORDLIST_EXTS = (".txt", ".lst", ".dict", ".wordlist", ".words")
# Crackbaby's own generated/auxiliary files that live in a campaign dir, not real
# input wordlists — skipped if a search dir happens to point at a campaign.
_WORDLIST_SKIP_SUBSTRINGS = ("org_words", "lm_cracked", "cracked.txt", "_as_rules")


def _find_default_wordlists() -> List[str]:
    """Auto-discover wordlists when --wordlists is not given.

    Scans every directory in phases._WORDLIST_SEARCH_PATHS (which the crackbaby.json
    ``wordlists_dirs`` key replaces) for plaintext wordlist files, so pointing
    crackbaby at a wordlist collection just works.  Falls back to the well-known
    rockyou/seclists absolute paths so default behaviour without any config still
    finds rockyou.  Skips crackbaby-generated artifacts and zero-byte files; returns
    a de-duplicated, name-sorted list of absolute paths.
    """
    from modules.phases import _WORDLIST_SEARCH_PATHS

    found: List[str] = []
    seen: set = set()

    def _add(path: str) -> None:
        ap = os.path.abspath(path)
        if ap in seen:
            return
        try:
            if os.path.isfile(ap) and os.path.getsize(ap) > 0:
                seen.add(ap)
                found.append(ap)
        except OSError:
            pass

    # 1. Scan configured / default wordlist directories for wordlist files.
    for d in _WORDLIST_SEARCH_PATHS:
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name.lower())
        except OSError:
            continue  # dir missing / unreadable
        for entry in entries:
            name_lower = entry.name.lower()
            if not name_lower.endswith(_WORDLIST_EXTS):
                continue
            if any(s in name_lower for s in _WORDLIST_SKIP_SUBSTRINGS):
                continue
            try:
                if not entry.is_file():
                    continue
            except OSError:
                continue
            _add(entry.path)

    # 2. Well-known absolute fallbacks (covers default installs whose rockyou lives
    #    outside the listed dirs).  .gz is omitted — hashcat -a 0 can't read it.
    for c in (
        "/usr/share/wordlists/rockyou.txt",
        os.path.expanduser("~/wordlists/rockyou.txt"),
        "/opt/wordlists/rockyou.txt",
        "./wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    ):
        _add(c)

    return found


def _count_unique_hashes(hash_file: str, username_mode: bool) -> tuple:
    """Returns (total_lines, unique_hashes)."""
    total = 0
    hashes = set()
    with open(hash_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            if username_mode:
                # format: user:hash — skip to hash field
                parts = line.split(":")
                if len(parts) >= 2:
                    hashes.add(parts[-1].lower())
                else:
                    hashes.add(line.lower())
            else:
                hashes.add(line.lower())
    return total, len(hashes)


# ── PREP ──────────────────────────────────────────────────────────────────────

_NULL_LM = "aad3b435b51404eeaad3b435b51404ee"

_SYSTEM_ACCOUNTS = {
    "guest", "krbtgt", "defaultaccount", "helpassistant",
    "wdagutilityaccount",
}
_SYSTEM_PREFIXES = ("healthmailbox", "support_", "iwam_", "iusr_", "aspnet")


def _bare_account(username: str) -> str:
    """Return the account name without any DOMAIN\\ or DOMAIN/ prefix.

    NTDS dumps use ``DOMAIN\\username`` (e.g. ``ASFC\\krbtgt``); the system- and
    machine-account checks must match on the bare name, not the prefixed form.
    """
    u = username.strip()
    for sep in ("\\", "/"):
        if sep in u:
            u = u.rsplit(sep, 1)[-1]
    return u


def _is_machine_account(username: str) -> bool:
    return _bare_account(username).endswith("$")


def _is_system_account(username: str) -> bool:
    low = _bare_account(username).lower()
    if low in _SYSTEM_ACCOUNTS:
        return True
    return any(low.startswith(p) for p in _SYSTEM_PREFIXES)


def cmd_prep(args: argparse.Namespace) -> None:
    """Extract NT hashes from an NTDS dump with optional account filtering."""
    ntds = args.ntds
    out = args.output
    lm_out = getattr(args, "lm_file", None)

    enabled_only   = getattr(args, "enabled_only", False)
    no_machines    = getattr(args, "no_machines", False)
    no_system      = getattr(args, "no_system", False)

    print(f"  Parsing NTDS dump: {ntds}")
    if enabled_only:
        print("  Filter: enabled accounts only")
    if no_machines:
        print("  Filter: machine accounts excluded")
    if no_system:
        print("  Filter: system/built-in accounts excluded")

    total = 0
    written = 0
    skip_disabled = 0
    skip_machine  = 0
    skip_system   = 0
    users = []
    lm_hashes: List[str] = []

    _hex = set("0123456789abcdefABCDEF")
    with open(ntds, errors="replace") as f, open(out, "w") as out_f:
        for line in f:
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue

            # Enabled-account filter: line must contain "Enabled" (secretsdump adds status)
            if enabled_only and "enabled" not in line.lower():
                skip_disabled += 1
                continue

            # Format: username:RID:LMhash:NThash:::
            parts = line.split(":")
            if len(parts) < 4:
                continue

            username = parts[0].strip()
            total += 1

            if no_machines and _is_machine_account(username):
                skip_machine += 1
                continue
            if no_system and _is_system_account(username):
                skip_system += 1
                continue

            lm_hash = parts[2].strip().lower() if len(parts) > 2 else ""
            nt_hash  = parts[3].strip()

            if len(nt_hash) == 32 and all(c in _hex for c in nt_hash):
                if args.username:
                    out_f.write(f"{username}:{nt_hash}\n")
                else:
                    out_f.write(nt_hash + "\n")
                users.append((username, nt_hash.lower()))
                written += 1

            # Collect non-null LM hashes
            if lm_out and len(lm_hash) == 32 and all(c in _hex for c in lm_hash):
                if lm_hash != _NULL_LM:
                    lm_hashes.append(lm_hash)

    skipped = skip_disabled + skip_machine + skip_system
    if skipped:
        print(f"  Filtered out:  {skipped} accounts total")
        if skip_disabled: print(f"    Disabled:    {skip_disabled}")
        if skip_machine:  print(f"    Machine ($): {skip_machine}")
        if skip_system:   print(f"    System:      {skip_system}")
    print(f"  NT hashes written: {written}  →  {out}")

    if lm_out:
        # Deduplicate LM hashes
        unique_lm = sorted(set(lm_hashes))
        with open(lm_out, "w") as lf:
            for h in unique_lm:
                lf.write(h + "\n")
        print(f"  LM hashes:   {len(unique_lm)} non-null  →  {lm_out}")

    if args.unique:
        unique_hashes = set(h for _, h in users)
        # Derive "<output>_unique<ext>" robustly via splitext so the unique file is
        # ALWAYS distinct from --output. (A naive out.replace(".txt", …) is a no-op
        # when --output has no .txt extension, which would overwrite the main file.)
        _root, _ext = os.path.splitext(out)
        uniq_path = f"{_root}_unique{_ext or '.txt'}"
        with open(uniq_path, "w") as uf:
            for h in sorted(unique_hashes):
                uf.write(h + "\n")
        print(f"  Unique NT:   {len(unique_hashes)}  →  {uniq_path}")


# ── INIT helpers ─────────────────────────────────────────────────────────────

def _resolve_hashcat_bin(path: str) -> str:
    """
    Accept either a full path to the hashcat binary OR a directory containing it.
    If path is a directory, auto-selects:
      • hashcat.bin  (Linux / macOS — standard hashcat release layout)
      • hashcat      (Linux — some distro packages)
      • hashcat.exe  (Windows)
    If path is a bare name (not absolute, not a directory), tries shutil.which() to
    resolve it to an absolute path so campaigns never store fragile relative names.
    Returns the resolved path; may not exist yet — caller validates existence.
    """
    import shutil as _shutil
    if os.path.isdir(path):
        if sys.platform == "win32":
            names = ["hashcat.exe", "hashcat"]
        else:
            names = ["hashcat.bin", "hashcat"]
        for name in names:
            candidate = os.path.join(path, name)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
        # Fallback: return the most-expected name even if absent (error surfaces later)
        return os.path.join(path, "hashcat.exe" if sys.platform == "win32" else "hashcat.bin")
    # Not a directory — resolve bare/relative names to absolute via PATH
    if not os.path.isabs(path):
        found = _shutil.which(path)
        if found:
            return os.path.abspath(found)
    return path


def _phase_key(phase) -> tuple:
    """Stable deduplication key for a phase across add / rebuild operations.

    combo_rules phases are keyed by their two wordlist paths because the args field
    only stores the rule file, not the wordlists.  All other phases key on
    (type, args, generator_cmd).
    """
    if phase.type == "combo_rules":
        return (phase.type, tuple(phase.args),
                phase.combo_wl1 or "", phase.combo_wl2 or "")
    return (phase.type, tuple(phase.args), tuple(phase.generator_cmd or []))


def _generate_new_phases(campaign) -> list:
    """Build the full phase set and return only phases not already in the campaign.

    Advances the ID counter past all existing phase IDs before generating so new
    phases never collide with existing ones.  Callers do not manage the counter.
    """
    from modules.phases import build_initial_phases, reset_counter

    _max_n = max(
        (int(p.id[1:]) for p in campaign.phases if p.id[1:].isdigit()),
        default=0,
    )
    reset_counter(_max_n)
    candidates = build_initial_phases(campaign)
    existing_keys = {_phase_key(p) for p in campaign.phases}
    return [p for p in candidates if _phase_key(p) not in existing_keys]


# ── TOOLS ─────────────────────────────────────────────────────────────────────

def cmd_tools(args: argparse.Namespace) -> None:
    """Show tool status, or download a wordlist."""
    # --download NAME|URL → fetch a wordlist and exit.
    if getattr(args, "download", None):
        path = download_wordlist(args.download,
                                 dest_dir=getattr(args, "dest", None),
                                 force=getattr(args, "force", False))
        sys.exit(0 if path else 1)

    # Try to load an existing campaign for context (so we know hashcat path)
    campaign = None
    campaign_arg = getattr(args, "campaign", None)
    if campaign_arg and os.path.isfile(os.path.join(campaign_arg, "campaign.json")):
        try:
            campaign = Campaign.load(os.path.abspath(campaign_arg))
        except Exception:
            pass
    _preflight_check(campaign=campaign)


# ── INIT ──────────────────────────────────────────────────────────────────────

def cmd_init(args: argparse.Namespace) -> None:
    """Initialize a new campaign directory and generate phase pipeline."""
    out_dir = os.path.abspath(args.campaign)
    if os.path.exists(os.path.join(out_dir, "campaign.json")):
        print(f"  ERROR: Campaign already exists at {out_dir}")
        print("  Use 'python crackbaby.py run' to continue it, or delete the directory to restart.")
        print("  Use 'python crackbaby.py add --wordlists ...' to add new wordlists.")
        print("  Use 'python crackbaby.py rebuild' to update settings or regenerate the phase list.")
        sys.exit(1)

    # --hashes is required for new campaigns
    if not args.hashes:
        print("  ERROR: --hashes is required when initializing a new campaign.")
        sys.exit(1)

    os.makedirs(out_dir, exist_ok=True)
    for sub in ("sessions", "wordlists", "masks", "logs"):
        os.makedirs(os.path.join(out_dir, sub), exist_ok=True)

    hash_file = os.path.abspath(args.hashes)
    if not os.path.exists(hash_file):
        print(f"  ERROR: Hash file not found: {hash_file}")
        sys.exit(1)

    hashcat_bin = _resolve_hashcat_bin(args.hashcat or _find_hashcat())
    wordlists = []
    if args.wordlists:
        for w in args.wordlists:
            if os.path.exists(w):
                wordlists.append(os.path.abspath(w))
            else:
                print(f"  WARNING: wordlist not found, skipping: {w}")
    if not wordlists:
        wordlists = _find_default_wordlists()
        if wordlists:
            from modules.phases import _WORDLIST_SEARCH_PATHS
            print(f"  Wordlists: {len(wordlists)} auto-discovered "
                  f"(dirs: {', '.join(_WORDLIST_SEARCH_PATHS)})")
            for _w in wordlists[:10]:
                print(f"             • {_w}")
            if len(wordlists) > 10:
                print(f"             … and {len(wordlists) - 10} more")

    if not wordlists:
        print("  No wordlists found.")
        # rockyou is the default — offer to fetch it when running interactively.
        if sys.stdin.isatty():
            try:
                _ans = input("  Download rockyou now (~53 MB)? [Y/n] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                _ans = "n"
                print()
            if _ans in ("", "y", "yes"):
                _rk = download_wordlist("rockyou")
                if _rk:
                    wordlists = [_rk]
        if not wordlists:
            print("  WARNING: no wordlist — wordlist/rule/hybrid phases will be skipped.")
            print("  Get one with:  python crackbaby.py tools --download rockyou")
            print("  or pass --wordlists /path/to/list.txt (or set wordlists_dirs in crackbaby.json).")

    total, unique = _count_unique_hashes(hash_file, args.username)
    print(f"  Hash file: {total} total lines, {unique} unique NT hashes")

    phase_timeout_secs = None
    if args.phase_timeout:
        phase_timeout_secs = int(args.phase_timeout * 3600)

    skip_threshold_hours = args.skip_slow

    lm_hash_file = None
    if getattr(args, "lm_hashes", None):
        lm_hash_file = os.path.abspath(args.lm_hashes)
        if not os.path.exists(lm_hash_file):
            print(f"  WARNING: LM hash file not found: {lm_hash_file} — LM phases skipped")
            lm_hash_file = None

    # ── Org context: parse from --org-config JSON file ─────────────────────
    org_name = org_short = org_location = ""
    org_custom_words: list = []
    if getattr(args, "org_config", None):
        org_cfg_path = os.path.abspath(args.org_config)
        if not os.path.exists(org_cfg_path):
            print(f"  ERROR: org-config file not found: {org_cfg_path}")
            sys.exit(1)
        with open(org_cfg_path) as _f:
            _cfg = json.load(_f)
        org_name         = _cfg.get("org_name", "").strip()
        org_short        = _cfg.get("org_name_short", "").strip()
        org_location     = _cfg.get("org_location", "").strip()
        org_custom_words = _cfg.get("custom_words", [])
        if not isinstance(org_custom_words, list):
            org_custom_words = []
        print(f"  Org config:  {org_cfg_path}")
        if org_name:     print(f"               name:     {org_name}")
        if org_short:    print(f"               short:    {org_short}")
        if org_location: print(f"               location: {org_location}")
        if org_custom_words:
            print(f"               custom words: {', '.join(org_custom_words[:8])}"
                  + (" …" if len(org_custom_words) > 8 else ""))

    # Resolve global_potfile: CLI flag wins, then ~/.crackbaby.json config.
    # Note: _cfg here is the org-config JSON dict, only defined when --org-config was
    # passed. The ~/.crackbaby.json value is already injected as an argparse default via
    # _cfg_map in main() → p_init.set_defaults(), so args.global_potfile already holds
    # the user-config value — no need to reference _cfg again.
    global_potfile = getattr(args, "global_potfile", None)
    if global_potfile:
        global_potfile = os.path.expanduser(global_potfile)
        print(f"  Global potfile: {global_potfile}")

    campaign = Campaign(
        name=args.name or os.path.basename(out_dir),
        hash_file=hash_file,
        hash_type=1000,  # NTLM
        output_dir=out_dir,
        hashcat_bin=hashcat_bin,
        username_mode=args.username,
        devices=args.devices,
        workload=args.workload,
        wordlists=wordlists,
        custom_rules_dir=args.custom_rules_dir,
        total_hashes=total,
        unique_hashes=unique,
        phase_timeout_secs=phase_timeout_secs,
        expected_speed_ghs=args.expected_speed,
        skip_threshold_hours=skip_threshold_hours,
        status_interval=args.status_interval,
        lm_hash_file=lm_hash_file,
        org_name=org_name,
        org_name_short=org_short,
        org_location=org_location,
        org_custom_words=org_custom_words,
        default_rule_depth=getattr(args, "default_rule_depth", "A") or "A",
        global_potfile=global_potfile,
        max_combinator_pairs_ks=getattr(args, "max_combinator_pairs_ks", 500_000_000),
        max_rule_convert_words=getattr(args, "max_rule_convert_words", 50_000),
    )

    # ── Speed calibration (benchmark prompt) ──────────────────────────────
    if args.expected_speed == 68.0 and not getattr(args, "no_benchmark", False):
        print("\n  ── Speed calibration ─────────────────────────────────────────────")
        print(f"  No --expected-speed set. Default is 68 GH/s (single RTX 3090).")
        print(f"  An accurate speed is needed for time-gating and ETA estimates.")
        try:
            ans = input("  Run a quick benchmark now? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
            print()
        if ans in ("", "y", "yes"):
            from modules.runner import HashcatRunner as _BenchRunner
            _bench_runner = _BenchRunner(
                hashcat_bin=hashcat_bin,
                hash_file=hash_file,
                hash_type=1000,
                potfile=campaign.potfile,
                cracked_file=campaign.cracked_file,
                sessions_dir=campaign.sessions_dir,
                username_mode=campaign.username_mode,
                devices=campaign.devices,
                workload=campaign.workload,
                status_interval=campaign.status_interval,
            )
            ghs = _bench_runner.benchmark_speed()
            if ghs:
                campaign.expected_speed_ghs = ghs
                unit, val = ("GH/s", ghs) if ghs >= 1 else ("MH/s", ghs * 1000)
                print(f"  ✓ Measured: {val:.1f} {unit} — will use for time-gating\n")
            else:
                print("  Benchmark failed. Using 68 GH/s default.")
                print("  Run 'python crackbaby.py benchmark --update' before skip decisions.\n")
        else:
            print("  Skipping. Run 'python crackbaby.py benchmark --campaign "
                  f"{out_dir} --update' before using skip/over-hours.\n")

    # ── Check combinator.bin availability ────────────────────────────────────
    if not _find_combinator_bin(campaign=campaign):
        print("  [INFO] combinator.bin not found alongside hashcat.")
        print("         combo_rules phases will use rule-convert only when possible.")
        print("         combinator.bin ships with hashcat — check your hashcat install dir.")

    # ── Build initial phase pipeline ──────────────────────────────────────
    print("  Building attack pipeline...")
    reset_counter(0)   # fresh campaign — IDs start at P0001
    phases = build_initial_phases(campaign)
    for p in phases:
        campaign.add_phase(p)

    campaign.save()

    total_phases = len(phases)
    skipped_at_init = sum(1 for p in phases if p.status == "skipped")
    active_phases = total_phases - skipped_at_init
    print(f"\n  Campaign '{campaign.name}' initialized at: {out_dir}")
    print(f"  {total_phases} phases built"
          + (f"  ({skipped_at_init} time-gated / pre-skipped)" if skipped_at_init else ""))
    print(f"  {active_phases} phases will run")
    print(f"  Wordlists: {len(wordlists)}")
    _print_phase_list(campaign, limit=20)
    print(f"\n  Run with:  python crackbaby.py run {out_dir}\n")


# ── RUN ───────────────────────────────────────────────────────────────────────

_runner_ref: Optional[HashcatRunner] = None
_stop_requested = False


def _sigint_handler(sig, frame):
    global _stop_requested
    if _stop_requested:
        print("\n  Force-stopping...")
        sys.exit(1)
    _stop_requested = True
    print("\n  Stop requested — waiting for hashcat to checkpoint (Ctrl+C again to force)")
    if _runner_ref:
        _runner_ref.stop()


# ── Phase dispatch helpers ────────────────────────────────────────────────────
# Shared setup / progress / teardown used by every phase branch in cmd_run.
# Extracting these eliminates ~370 lines of copy-pasted boilerplate and ensures
# all phase types (generic hashcat, combo_rules, combinator rule-conversion,
# piped/generator, lm_brute) behave consistently.

def _make_on_line(prev_block_lines: list):
    """Return an on_line callback that clears the last status block then prints the line."""
    def _cb(line, _pb=prev_block_lines):
        if _pb[0]:
            sys.stdout.write(f"\033[{_pb[0]}A\033[J")
            _pb[0] = 0
        print(f"  {line}", flush=True)
    return _cb


def _make_on_progress(phase, prev_block_lines: list):
    """Return a standard on_progress callback that renders the live status block.

    Uses phase.estimated_keyspace for the progress percentage when available
    (important for piped/stream phases where hashcat reports 0% keyspace).
    Synthesises ETA from parsed speed when hashcat emits "(0 secs)" or similar
    unusable values — necessary for stream/stdin-based combo_rules phases.
    """
    def _cb(info, _pb=prev_block_lines, _ph=phase):
        if _pb[0]:
            sys.stdout.write(f"\033[{_pb[0]}A\033[J")
        _ks = _ph.estimated_keyspace or 0
        _prog_suffix = ""
        if info.progress_pct > 0:
            # hashcat reported a valid progress % (done and total both known)
            _pct = info.progress_pct
        elif _ks > 0 and info.progress_done > 0:
            # stdin-piped phases (combinator.bin combo stream): hashcat has no total,
            # so compute % from estimated_keyspace. A wl×wl product can be enormous, so
            # also show the raw candidate count — guarantees the readout visibly
            # advances even when the percentage rounds to 0.00%.
            _pct = min(info.progress_done / _ks * 100, 99.9)
            _prog_suffix = f"  ({info.progress_done:,} tried)"
        else:
            _pct = 0.0
        rec_str = (
            f"{info.recovered}/{info.total} ({info.recovered/info.total*100:.1f}%)"
            if info.total else str(info.recovered)
        )
        elapsed_secs = int(time.time() - _ph.start_time) if _ph.start_time else 0
        eh, rem = divmod(elapsed_secs, 3600)
        em, es = divmod(rem, 60)
        elapsed_str = (f"{eh}h {em}m {es}s" if eh else
                       f"{em}m {es}s" if em else f"{es}s")
        # ETA: prefer hashcat's value; synthesise from speed when unavailable
        _raw_eta = info.eta or ""
        _eta_str = "" if _raw_eta in ("0 secs", "0s", "0") else _raw_eta
        if not _eta_str and _ks > 0 and info.speed:
            _hps = _parse_speed_hps(info.speed)
            if _hps > 0:
                _rem = int(max(0, _ks - info.progress_done) / _hps)
                _eh2, _r2 = divmod(_rem, 3600)
                _em2, _es2 = divmod(_r2, 60)
                _eta_str = f"{_eh2}h {_em2}m" if _eh2 else f"{_em2}m {_es2}s"
        if not _eta_str:
            _eta_str = "calculating..."
        now = datetime.now().strftime("%H:%M:%S")
        block = [
            f"  ┌─ {now} {'─'*44}",
            f"  │  Status:    {info.status}",
            f"  │  Speed:     {info.speed or 'measuring...'}",
            f"  │  Progress:  {_pct:.2f}%{_prog_suffix}",
            f"  │  Recovered: {rec_str}",
            f"  │  ETA:       {_eta_str}",
            f"  │  Elapsed:   {elapsed_str}",
            f"  └{'─'*52}",
        ]
        print("\n".join(block), flush=True)
        _pb[0] = len(block)
    return _cb


def _sync_cracked_file(runner: "HashcatRunner", campaign: "Campaign") -> None:
    """Pre-populate cracked.txt from the active NTLM potfile if the file is empty.

    Hashcat's ``-o cracked.txt --outfile-format 2`` appends plaintexts only when
    it cracks new hashes in the *current* run.  Hashes that were already present
    in the potfile from a prior campaign (or from a shared global potfile) are
    silently skipped — their plaintexts never appear in cracked.txt.  This leaves
    the file empty or stale even though the potfile may have dozens of entries,
    so the human-readable list of recovered passwords looks empty even though those
    hashes are already cracked.

    This function cross-references the campaign's hash file against the active
    potfile (pure-Python, no subprocess) and writes unique, deduplicated
    plaintexts to cracked.txt.  It fires only when cracked.txt is empty or
    absent — a non-empty file is never clobbered, so in-progress runs are not
    disrupted.
    """
    cracked_path = campaign.cracked_file
    if os.path.exists(cracked_path) and os.path.getsize(cracked_path) > 0:
        return  # already has content — leave untouched

    active_pot = runner._active_potfile
    if not os.path.exists(active_pot):
        return  # potfile absent — nothing to sync

    # Build a lookup set of the campaign's hashes.
    # In --username mode the hash file lines are "user:HASH"; strip the prefix.
    try:
        hash_set: set = set()
        with open(runner.hash_file, errors="replace") as _hf:
            for _ln in _hf:
                _ln = _ln.strip()
                if not _ln:
                    continue
                if runner.username_mode and ":" in _ln:
                    _ln = _ln.split(":", 1)[1]
                hash_set.add(_ln.upper())
    except OSError:
        return  # hash file unreadable — skip silently

    # Extract matching plaintexts from the potfile.
    # NTLM potfile format: <32-hex-char-hash>:plaintext
    try:
        _seen: set = set()
        _pts: list = []
        with open(active_pot, errors="replace") as _pf:
            for _ln in _pf:
                _ln = _ln.rstrip("\n")
                if not _ln:
                    continue
                if len(_ln) > 33 and _ln[32] == ":":
                    _ph, _pt = _ln[:32].upper(), _ln[33:]
                elif ":" in _ln:
                    _ph, _pt = _ln.split(":", 1)
                    _ph = _ph.upper()
                else:
                    continue
                if _ph in hash_set and _pt not in _seen:
                    _seen.add(_pt)
                    _pts.append(_pt)
        if _pts:
            os.makedirs(os.path.dirname(cracked_path) or ".", exist_ok=True)
            with open(cracked_path, "w", encoding="utf-8", errors="ignore") as _cf:
                for _pt in _pts:
                    _cf.write(_pt + "\n")
            print(f"  [cracked.txt] Pre-populated from potfile: "
                  f"{len(_pts)} unique plaintexts")
    except OSError as _e:
        logger.warning("cracked.txt sync failed: %s", _e)


def _phase_start(phase, campaign, runner, logs_dir: str):
    """Mark a phase as running and return (log_path, prev_block_lines).

    Must be called before runner.run() / runner.run_piped() for every phase branch.
    """
    phase.status = "running"
    phase.start_time = time.time()
    phase.cracked_start = runner.count_cracked()
    campaign.save()
    log_path = os.path.join(logs_dir, f"{phase.id}.log")
    return log_path, [0]


def _phase_finish(phase, campaign, runner, total: int, log_path: str,
                  status_str: str, args, prev_block_lines: list,
                  dry_run_previewed: list, result_msg: str = None):
    """All post-phase teardown: set end state, print result, save.

    Handles:
    - Clearing the last ANSI status block
    - Setting phase.end_time / cracked_end / status
    - Printing the → COMPLETED / FAILED result line (or custom result_msg)
    - Printing the last log lines on failure
    - Dry-run status restore + save
    """
    if prev_block_lines[0]:
        print()  # leave blank line after last status block

    phase.end_time = time.time()
    phase.cracked_end = runner.count_cracked() if not args.dry_run else phase.cracked_start
    phase.status = status_str

    if result_msg:
        print(result_msg)
    else:
        delta = phase.cracked_delta
        new_total = phase.cracked_end
        new_pct = new_total / total * 100 if total else 0
        print(f"  → {status_str.upper()}  +{delta} cracked  "
              f"Running total: {new_total}/{total} ({new_pct:.1f}%)  "
              f"Time: {phase.duration_str}")

    if status_str == "failed":
        tail = _tail_log(log_path)
        if tail:
            print("  [hashcat output (last lines)]:")
            for ln in tail.splitlines()[-12:]:
                print(f"    {ln}")

    if args.dry_run:
        _mem_status, phase.status = phase.status, "pending"
        campaign.save()
        phase.status = _mem_status
        dry_run_previewed.append(phase)
    else:
        campaign.save()


def _run_lm_brute_phase(phase: Phase, campaign: Campaign, runner: HashcatRunner,
                        args: argparse.Namespace, total: int,
                        target_phase: Optional[str], run_opt: bool,
                        dry_run_previewed: list) -> str:
    """Run an LM brute-force phase (hash-type 3000) against the campaign's LM hashes.

    Loop control mirrors every other phase handler via _loop_signal(target_phase):
    a forced single --phase runs exactly once and breaks, a normal run advances to
    the next phase, and an interrupt breaks."""
    if not campaign.lm_hash_file or not os.path.exists(campaign.lm_hash_file):
        print("  LM hash file missing — skipping")
        phase.status = "skipped"
        campaign.save()
        return "continue"

    # lm_cracked_raw.txt receives the uppercase 7-char LM half-passwords hashcat
    # cracks during the brute phase (-o flag).  It is a disposable artifact used
    # only for inspection; the LM potfile (crackbaby_3000.potfile / global_3000.potfile) is
    # the authoritative source for the LM toggle phase.  Critically this must NOT
    # be campaign.cracked_file (cracked.txt) — that file holds the recovered NTLM
    # plaintexts for the report, and writing LM half-password garbage there would
    # pollute it.
    _lm_cracked_raw = os.path.join(campaign.wordlists_dir, "lm_cracked_raw.txt")
    lm_runner = HashcatRunner(
        hashcat_bin=campaign.hashcat_bin,
        hash_file=campaign.lm_hash_file,
        hash_type=3000,
        potfile=campaign.lm_potfile,         # crackbaby_3000.potfile — distinct from NTLM
        cracked_file=_lm_cracked_raw,        # LM halves go here, NOT cracked.txt
        sessions_dir=campaign.sessions_dir,
        username_mode=False,
        devices=campaign.devices,
        workload=campaign.workload,
        status_interval=campaign.status_interval,
        global_potfile=campaign.global_potfile,  # runner resolves → global_3000.potfile
    )

    log_path, _prev_block_lines = _phase_start(phase, campaign, runner,
                                               campaign.logs_dir)
    # lm_brute uses a self-computed speed estimate when hashcat's \r overwrite
    # doesn't propagate through the pipe (piped mode, no TTY).
    _speed_samples: list = []

    def on_progress(info, _pb=_prev_block_lines, _ph=phase):
        nonlocal _speed_samples
        if _pb[0]:
            sys.stdout.write(f"\033[{_pb[0]}A\033[J")
        elapsed_secs = int(time.time() - _ph.start_time) if _ph.start_time else 0
        eh, rem = divmod(elapsed_secs, 3600); em, es = divmod(rem, 60)
        elapsed_str = f"{eh}h {em}m {es}s" if eh else f"{em}m {es}s" if em else f"{es}s"
        now = datetime.now().strftime("%H:%M:%S")
        speed_display = info.speed or ""
        if not any(c.isdigit() for c in speed_display):
            _speed_samples.append((info.progress_pct, time.time()))
            if len(_speed_samples) > 8:
                del _speed_samples[:-8]
            if len(_speed_samples) >= 2 and _ph.estimated_keyspace:
                dt = _speed_samples[-1][1] - _speed_samples[0][1]
                dpct = _speed_samples[-1][0] - _speed_samples[0][0]
                if dt > 1.0 and dpct > 0:
                    hps = (dpct / 100.0 * _ph.estimated_keyspace) / dt
                    speed_display = _fmt_speed(hps / 1e9) + " ~"
        block = [
            f"  ┌─ {now} {'─'*44}",
            f"  │  Status:    {info.status}",
            f"  │  Speed:     {speed_display or 'measuring...'}",
            f"  │  Progress:  {info.progress_pct:.2f}%",
            f"  │  Recovered: {info.recovered}/{info.total}",
            f"  │  ETA:       {info.eta or 'calculating...'}",
            f"  │  Elapsed:   {elapsed_str}",
            f"  └{'─'*52}",
        ]
        print("\n".join(block), flush=True)
        _pb[0] = len(block)

    _lm_timeout = campaign.phase_timeout_secs
    if hasattr(args, "phase_timeout") and args.phase_timeout:
        _lm_timeout = int(args.phase_timeout * 3600)
    # Point the SIGINT handler at this phase's dedicated lm_runner (not the main
    # NTLM runner) so a Ctrl-C calls lm_runner.stop() and the run is classified
    # "interrupted" rather than "failed". Restore the main runner afterward.
    global _runner_ref
    _prev_runner_ref = _runner_ref
    _runner_ref = lm_runner
    try:
        rc, status_str = lm_runner.run(
            phase.args, phase.session_name, log_path,
            on_progress=on_progress, on_line=_make_on_line(_prev_block_lines),
            dry_run=args.dry_run,
            timeout_secs=_lm_timeout,
            optimize_kernel=run_opt and not phase.no_optimize,
        )
    finally:
        _runner_ref = _prev_runner_ref
    # Stamp end_time before building the message so duration_str is populated here
    # (_phase_finish re-stamps it microseconds later when it records the phase).
    phase.end_time = time.time()
    delta = phase.cracked_delta
    _lm_msg = (f"  → {status_str.upper()}  "
               f"LM cracked, NTLM delta: +{delta}  Time: {phase.duration_str}")
    _phase_finish(phase, campaign, runner, total, log_path, status_str,
                  args, _prev_block_lines, dry_run_previewed,
                  result_msg=_lm_msg)
    return _loop_signal(target_phase)


def _run_combo_rules_phase(phase: Phase, campaign: Campaign, runner: HashcatRunner,
                           args: argparse.Namespace, total: int,
                           target_phase: Optional[str], run_opt: bool,
                           dry_run_previewed: list) -> str:
    """Run a combo_rules phase via rule_convert (GPU) or combinator.bin pipe (fallback).

    Strategy:
      1. Rule-convert: if smaller wordlist side <= max_rule_convert_words, convert
         it to a hashcat rules file and run as a standard GPU wordlist attack.
      2. combinator.bin pipe: feed combinator.bin wl1 wl2 to hashcat stdin.
         Requires combinator.bin alongside the hashcat binary.

    Returns the loop-control signal "break" or "continue".
    """
    _gc_wl1 = phase.combo_wl1 or ""
    _gc_wl2 = phase.combo_wl2 or ""

    if not _gc_wl1 or not _gc_wl2:
        print("  [ERROR] combo_rules phase missing wordlist paths — skipping")
        phase.status = "skipped"
        campaign.save()
        return "continue"

    _missing = [p for p in (_gc_wl1, _gc_wl2) if not os.path.exists(p)]
    if _missing:
        print(f"  [ERROR] combo_rules wordlist not found: {_missing[0]} — skipping")
        phase.status = "skipped"
        campaign.save()
        return "continue"

    # Phase timeout
    _timeout = campaign.phase_timeout_secs
    if hasattr(args, "phase_timeout") and args.phase_timeout:
        _timeout = int(args.phase_timeout * 3600)

    _combo_no_opt = _resolve_no_opt(_gc_wl1, _gc_wl2, campaign)
    _opt = run_opt and not _combo_no_opt

    # Extract any existing rule args from phase.args (e.g. ["-a", "0", "-r", "best66.rule"])
    _extra_rules: list = []
    _i = 0
    while _i < len(phase.args):
        if phase.args[_i] == "-r" and _i + 1 < len(phase.args):
            _extra_rules += ["-r", phase.args[_i + 1]]
            _i += 2
        else:
            _i += 1

    from modules.phases import _count_file_lines

    _sz1 = os.path.getsize(_gc_wl1)
    _sz2 = os.path.getsize(_gc_wl2)
    if _sz1 <= _sz2:
        _small_path, _base_path, _rule_mode = _gc_wl1, _gc_wl2, "prefix"
    else:
        _small_path, _base_path, _rule_mode = _gc_wl2, _gc_wl1, "suffix"

    _small_lines = _count_file_lines(_small_path)
    _rule_limit  = int(getattr(campaign, "max_rule_convert_words", 50_000))

    on_progress, on_line = _make_on_progress(phase, [0]), _make_on_line([0])

    # ── Strategy 1: rule-convert (GPU-native, fastest) ────────────────
    if 0 < _small_lines <= _rule_limit:
        _small_rule = None if args.dry_run else _convert_small_side_to_rules(
            campaign, _small_path, _rule_mode)
        if args.dry_run or _small_rule:
            _rule_args = (["-a", "0"] + _extra_rules
                          + (["-r", _small_rule] if _small_rule else ["-r", "<generated>"])
                          + [_base_path])
            if args.dry_run:
                print(f"  [DRY-RUN] rule-convert  "
                      f"{os.path.basename(_small_path)}({_small_lines:,}) → rules "
                      f"× {os.path.basename(_base_path)}")
            else:
                print(f"  [strategy] rule-convert  "
                      f"{os.path.basename(_small_path)}({_small_lines:,} ≤ {_rule_limit:,}) → rules")
            log_path, _prev = _phase_start(phase, campaign, runner, campaign.logs_dir)
            rc, status_str = runner.run(
                _rule_args, phase.session_name, log_path,
                on_progress=on_progress, on_line=on_line,
                dry_run=args.dry_run, timeout_secs=_timeout, optimize_kernel=_opt,
            )
            phase.combo_strategy = "rule_convert"
            _phase_finish(phase, campaign, runner, total, log_path, status_str,
                          args, _prev, dry_run_previewed)
            if _stop_requested or target_phase:
                return "break"
            return "continue"

    # ── Strategy 2: combinator.bin pipe (fallback) ────────────────────
    _combo_bin = _find_combinator_bin(campaign=campaign)
    if not _combo_bin:
        print("  [ERROR] combinator.bin not found and rule-convert not eligible "
              f"({_small_lines:,} lines > {_rule_limit:,} limit) — skipping phase")
        print("         Install combinator.bin alongside hashcat, or raise "
              "max_rule_convert_words in crackbaby.json to use rule-convert.")
        phase.status = "skipped"
        campaign.save()
        return "continue"

    _piped_args = (["-a", "0"] + _extra_rules
                   + ["--stdin-timeout-abort", "86400"])
    if args.dry_run:
        print(f"  [DRY-RUN] combinator.bin pipe  "
              f"{os.path.basename(_gc_wl1)} × {os.path.basename(_gc_wl2)}")
    else:
        print(f"  [strategy] combinator.bin pipe  "
              f"{os.path.basename(_gc_wl1)} × {os.path.basename(_gc_wl2)}")
    log_path, _prev = _phase_start(phase, campaign, runner, campaign.logs_dir)
    rc, status_str = runner.run_piped(
        [_combo_bin, _gc_wl1, _gc_wl2], _piped_args,
        phase.session_name, log_path,
        on_progress=on_progress, on_line=on_line,
        dry_run=args.dry_run, timeout_secs=_timeout,
        optimize_kernel=_opt,
    )
    phase.combo_strategy = "combinator_bin"
    _phase_finish(phase, campaign, runner, total, log_path, status_str,
                  args, _prev, dry_run_previewed)

    if _stop_requested or target_phase:
        return "break"
    return "continue"


def _loop_signal(target_phase: Optional[str]) -> str:
    """Loop-control after a phase ran: stop on interrupt or a single forced --phase,
    otherwise advance to the next phase."""
    if _stop_requested:
        return "break"
    if target_phase:
        return "break"
    return "continue"


def _run_lm_toggle_phase(phase: Phase, campaign: Campaign, runner: HashcatRunner,
                         args: argparse.Namespace, dry_run_previewed: list) -> str:
    """Prepare an LM-toggle phase: extract cracked LM plaintexts → lm_cracked.txt
    (which phase.args already references). Returns "continue" to skip this phase, or
    "proceed" to fall through to the standard hashcat handler."""
    if args.dry_run:
        print("  [DRY-RUN] LM toggle: would extract LM plaintexts → NTLM toggle attack")
        # In-memory preview advance (save is a no-op in dry-run) so next_phase()
        # does not re-select this still-pending phase forever.
        phase.status = "running"
        dry_run_previewed.append(phase)
        return "continue"
    if not campaign.lm_hash_file:
        phase.status = "skipped"
        campaign.save()
        return "continue"

    # Generate lm_cracked.txt lazily from the LM potfile.
    # campaign.active_lm_potfile resolves to the LM-specific potfile path —
    # either the global potfile variant (e.g. ~/.crackbaby.global_3000.potfile)
    # when global_potfile is set, or the campaign-local crackbaby_3000.potfile.
    # Passing it explicitly is required: the main runner uses the NTLM potfile
    # (hash type 1000), which never contains LM hash results.
    lm_words = runner.get_lm_cracked_words(campaign.lm_hash_file,
                                            lm_potfile=campaign.active_lm_potfile)
    if not lm_words:
        print("  No LM hashes cracked yet — skipping toggle phase")
        phase.status = "skipped"
        campaign.save()
        return "continue"

    lm_wl_path = os.path.join(campaign.wordlists_dir, "lm_cracked.txt")
    with open(lm_wl_path, "w") as lf:
        for w in sorted(set(lm_words)):
            lf.write(w + "\n")
    print(f"  LM plaintexts: {len(lm_words)} words → {lm_wl_path}")
    # phase.args already has the correct path baked in from build_initial_phases
    return "proceed"


def _run_standard_phase(phase: Phase, campaign: Campaign, runner: HashcatRunner,
                        args: argparse.Namespace, total: int,
                        target_phase: Optional[str], run_opt: bool,
                        dry_run_previewed: list) -> str:
    """Default hashcat phase path: pre-flight keyspace/auto-skip, the combinator
    rule-conversion fast path, then a plain hashcat run. Used by wordlist, rules,
    mask, hybrid, brute, combinator, and prepared lm_toggle phases."""
    # ── Pre-flight: keyspace check + auto-skip ─────────────────────────
    if not args.dry_run:
        from modules.phases import _fmt_keyspace
        ks = runner.get_keyspace(phase.args)
        if ks is not None:
            phase.estimated_keyspace = ks
            # Use per-type speed for accurate ETA (brute=full speed, rules=0.16×, etc.)
            _spd_for_eta = _effective_speed_ghs(phase, campaign)
            eta = _estimate_eta(ks, _spd_for_eta)

            # Determine effective timeout for this phase
            timeout_secs = campaign.phase_timeout_secs
            if hasattr(args, "phase_timeout") and args.phase_timeout:
                timeout_secs = int(args.phase_timeout * 3600)

            if timeout_secs:
                _th, _tr = divmod(int(timeout_secs), 3600)
                _tm, _ts = divmod(_tr, 60)
                _tstr = (f"{_th}h {_tm}m" if _th else
                         f"{_tm}m {_ts}s" if _tm else f"{_ts}s")
                timeout_str = f"  timeout: {_tstr}"
            else:
                timeout_str = ""
            skip_note = ""

            # Auto-skip if estimated time exceeds threshold (use per-type speed).
            # Bypassed when --phase is explicitly given: user intent overrides everything.
            if not target_phase and campaign.skip_threshold_hours and ks > 0 and _spd_for_eta > 0:
                est_h = ks / (_spd_for_eta * 1e9) / 3600
                if est_h > campaign.skip_threshold_hours:
                    skip_note = f"  → AUTO-SKIP (est. {eta} > {campaign.skip_threshold_hours}h limit)"

            spd_str = _fmt_speed(_spd_for_eta)
            print(f"     Keyspace: {_fmt_keyspace(ks)}  ETA @ {spd_str}: {eta}{timeout_str}{skip_note}")

            if skip_note:
                phase.status = "skipped"
                campaign.save()
                return "continue"
        else:
            timeout_secs = campaign.phase_timeout_secs
            if hasattr(args, "phase_timeout") and args.phase_timeout:
                timeout_secs = int(args.phase_timeout * 3600)
    else:
        timeout_secs = None

    # ── Combinator rule-conversion fast path ───────────────────────────
    # For type="combinator" (-a 1 wl1 wl2) phases, when one side is small
    # (≤ max_rule_convert_words), convert it to hashcat prefix/suffix rules
    # and run as -a 0 large_side -r small_as_rules.  The rule strategy keeps
    # the GPU fully occupied and achieves ~10-30× better throughput than plain
    # -a 1, which generates one hash per pair with no GPU amortisation.
    if phase.type == "combinator" and len(phase.args) >= 4:
        _cb_wl1 = phase.args[2] if len(phase.args) > 2 else ""
        _cb_wl2 = phase.args[3] if len(phase.args) > 3 else ""
        if _cb_wl1 and _cb_wl2 and os.path.exists(_cb_wl1) and os.path.exists(_cb_wl2):
            from modules.phases import _count_file_lines
            _cb_sz1, _cb_sz2 = os.path.getsize(_cb_wl1), os.path.getsize(_cb_wl2)
            if _cb_sz1 <= _cb_sz2:
                _cb_small, _cb_base, _cb_mode = _cb_wl1, _cb_wl2, "prefix"
            else:
                _cb_small, _cb_base, _cb_mode = _cb_wl2, _cb_wl1, "suffix"
            _cb_small_lines = _count_file_lines(_cb_small)
            _cb_rule_limit  = int(getattr(campaign, "max_rule_convert_words", 50_000))
            if 0 < _cb_small_lines <= _cb_rule_limit:
                _cb_small_rule = None
                if not args.dry_run:
                    _cb_small_rule = _convert_small_side_to_rules(
                        campaign, _cb_small, _cb_mode)
                if args.dry_run or _cb_small_rule:
                    _cb_no_opt = _resolve_no_opt(_cb_wl1, _cb_wl2, campaign)
                    _cb_rule_disp = _cb_small_rule or "<small_as_rules.rule>"
                    print(f"  [combo] {os.path.basename(_cb_wl1)} × {os.path.basename(_cb_wl2)}  "
                          f"(small side {os.path.basename(_cb_small)}: {_cb_small_lines:,} lines)")
                    print(f"  [strategy] rules → on-GPU  "
                          f"(-a 0 {os.path.basename(_cb_base)} -r {os.path.basename(_cb_rule_disp)})  "
                          f"[{_cb_mode} of {os.path.basename(_cb_small)}, "
                          f"{_cb_small_lines:,} words]")
                    _cb_args = ["-a", "0", "-r", _cb_rule_disp, _cb_base]
                    _cb_log, _cb_pb = _phase_start(phase, campaign, runner,
                                                    campaign.logs_dir)
                    rc, status_str = runner.run(
                        _cb_args, phase.session_name, _cb_log,
                        on_progress=_make_on_progress(phase, _cb_pb),
                        on_line=_make_on_line(_cb_pb),
                        dry_run=args.dry_run, timeout_secs=timeout_secs,
                        optimize_kernel=run_opt and not _cb_no_opt,
                    )
                    _phase_finish(phase, campaign, runner, total, _cb_log,
                                  status_str, args, _cb_pb, dry_run_previewed)
                    return _loop_signal(target_phase)

    # ── Plain hashcat phase ────────────────────────────────────────────
    log_path, _prev_block_lines = _phase_start(phase, campaign, runner,
                                                campaign.logs_dir)
    rc, status_str = runner.run(
        phase.args,
        phase.session_name,
        log_path,
        on_progress=_make_on_progress(phase, _prev_block_lines),
        on_line=_make_on_line(_prev_block_lines),
        dry_run=args.dry_run,
        timeout_secs=timeout_secs,
        optimize_kernel=run_opt and not phase.no_optimize,
    )
    _phase_finish(phase, campaign, runner, total, log_path, status_str,
                  args, _prev_block_lines, dry_run_previewed)
    return _loop_signal(target_phase)


@dataclass
class _RunContext:
    """Everything `cmd_run` needs after setup, threaded through the loop + teardown."""
    campaign: Campaign
    runner: HashcatRunner
    total: int
    target_phase: Optional[str]
    run_opt: bool
    dry_run_previewed: list
    is_resume: bool
    orig_save: Optional[Callable[[], None]]   # original campaign.save (dry-run only)
    campaign_dir: str


def _prepare_run(args: argparse.Namespace) -> _RunContext:
    """Load + repair the campaign, regenerate static assets, build the runner, print
    the starting state, and (for dry-run) patch out campaign.save. Returns a
    _RunContext. Exits the process on a missing campaign or unverified binary."""
    global _runner_ref

    campaign_dir = os.path.abspath(args.campaign)
    if not os.path.exists(os.path.join(campaign_dir, "campaign.json")):
        print(f"  ERROR: No campaign found at {campaign_dir}")
        print("  Run 'python crackbaby.py init ...' first.")
        sys.exit(1)

    campaign = Campaign.load(campaign_dir)
    signal.signal(signal.SIGINT, _sigint_handler)

    # ── Re-apply user config for values that may be missing in older campaigns ──
    # Load once and use for all attribute checks below.
    _run_user_cfg, _ = _load_user_config()

    # hashcat binary: may be stale ("hashcat") if the binary wasn't on PATH at init.
    # Non-absolute paths are fragile — they only work when run from the right CWD.
    # Always try to upgrade to an absolute path.
    _stored_hc = campaign.hashcat_bin
    _resolved_hc = _resolve_hashcat_bin(_stored_hc)
    _needs_update = (
        not os.path.isabs(_resolved_hc)
        or not os.path.isfile(_resolved_hc)
        or not os.access(_resolved_hc, os.X_OK)
    )
    if _needs_update:
        # Try user config first (most authoritative)
        _cfg_hc = _run_user_cfg.get("hashcat_bin")
        if _cfg_hc:
            _cfg_resolved = _resolve_hashcat_bin(os.path.expanduser(_cfg_hc))
            if os.path.isfile(_cfg_resolved) and os.access(_cfg_resolved, os.X_OK):
                if _cfg_resolved != _stored_hc:
                    print(f"  hashcat binary updated: {_stored_hc!r} → {_cfg_resolved!r}")
                campaign.hashcat_bin = _cfg_resolved
                campaign.save()
        else:
            # No user config — try resolving bare name to absolute via PATH
            import shutil as _shutil
            _which = _shutil.which(_stored_hc)
            if _which:
                _abs = os.path.abspath(_which)
                if _abs != _stored_hc:
                    print(f"  hashcat binary resolved: {_stored_hc!r} → {_abs!r}")
                    campaign.hashcat_bin = _abs
                    campaign.save()
        # If still not resolved, leave it as-is — verify_binary() will error below
    elif _resolved_hc != _stored_hc:
        # Directory was given at init; update stored path to the resolved binary
        campaign.hashcat_bin = _resolved_hc
        campaign.save()

    # global_potfile: may be unset if campaign was created before this config key existed.
    if not campaign.global_potfile:
        _cfg_gp = _run_user_cfg.get("global_potfile")
        if _cfg_gp:
            _cfg_gp = os.path.expanduser(_cfg_gp)
            print(f"  Global potfile applied from config: {_cfg_gp}")
            campaign.global_potfile = _cfg_gp
            campaign.save()

    # Regenerate static asset files so campaigns created by older builds
    # automatically pick up any content updates on the next run.
    from modules.phases import _write_enterprise_mask_file as _regen_enterprise
    from modules.phases import _write_suffix_wordlist as _regen_suffixes
    from modules.phases import _write_common_words_wordlist as _regen_common_words
    from modules.phases import _write_org_wordlist as _regen_org_words
    _regen_enterprise(campaign.masks_dir,
                      campaign.expected_speed_ghs,
                      campaign.skip_threshold_hours or 6.0)
    _regen_suffixes(campaign.wordlists_dir)
    _regen_common_words(campaign.wordlists_dir)
    _regen_org_words(campaign)  # no-op if no org context set

    is_resume = campaign.started_at is not None
    if not campaign.started_at:
        campaign.started_at = time.time()
        campaign.save()

    runner = HashcatRunner(
        hashcat_bin=campaign.hashcat_bin,
        hash_file=campaign.hash_file,
        hash_type=campaign.hash_type,
        potfile=campaign.potfile,
        cracked_file=campaign.cracked_file,
        sessions_dir=campaign.sessions_dir,
        username_mode=campaign.username_mode,
        devices=campaign.devices,
        workload=args.workload if args.workload else campaign.workload,
        status_interval=campaign.status_interval,
        global_potfile=campaign.global_potfile,
    )
    _runner_ref = runner

    if not args.dry_run:
        if not runner.verify_binary():
            print(f"  ERROR: hashcat not found or not executable: {campaign.hashcat_bin}")
            sys.exit(1)

    total = _count_basis_total(campaign)
    if is_resume:
        _print_run_summary(campaign, runner)
    else:
        cracked = runner.count_cracked()
        # Sync cracked.txt from the potfile when the file is empty but the potfile
        # already has entries — handles the global-potfile scenario where hashes were
        # cracked in a prior campaign and never written to this campaign's cracked.txt.
        if cracked > 0 and not args.dry_run:
            _sync_cracked_file(runner, campaign)
        print(f"\n  Campaign: {campaign.name}")
        print(f"  Starting state: {cracked}/{total} cracked ({cracked/total*100:.1f}%)" if total else
              f"  Starting state: {cracked} cracked")

    # Dry-run: suppress all campaign.save() calls during the loop so phase
    # status changes don't get persisted.  Phases are kept in-memory at their
    # "completed"/"dry_run" status so next_phase() advances through them;
    # after the loop we restore every previewed phase to "pending" and do
    # one final save so campaign.json is unchanged by the dry-run.
    _orig_save: Optional[Callable[[], None]] = None
    if args.dry_run:
        _orig_save = campaign.save
        campaign.save = lambda: None  # no-op during dry-run loop

    return _RunContext(
        campaign=campaign,
        runner=runner,
        total=total,
        target_phase=args.phase,
        run_opt=not getattr(args, "no_optimize", False),
        dry_run_previewed=[],
        is_resume=is_resume,
        orig_save=_orig_save,
        campaign_dir=campaign_dir,
    )


def _run_phase_loop(ctx: _RunContext, args: argparse.Namespace) -> None:
    """The phase dispatch loop: select the next phase and route it to its handler."""
    campaign = ctx.campaign
    runner = ctx.runner
    total = ctx.total
    target_phase = ctx.target_phase
    _run_opt = ctx.run_opt
    _dry_run_previewed = ctx.dry_run_previewed

    _forced_done = False  # one-shot guard for an explicit --phase run
    while True:
        if _stop_requested:
            break

        if target_phase:
            # Run exactly one named phase — do NOT iterate through next_phase() which
            # would permanently mark every earlier-priority phase as "skipped".
            # When --phase is explicitly given, bypass ALL status checks: the user's
            # intent overrides skipped/failed/interrupted/etc.
            #
            # A handler may early-skip and return "continue" (e.g. lm_toggle with no
            # cracked LM halves yet, or combo_rules/lm_brute with a missing input);
            # that sends control back here, where the status!="pending" branch would
            # reset the phase to pending and re-dispatch it — forever. Dispatch the
            # forced phase exactly once, then exit no matter how the handler returned.
            if _forced_done:
                break
            _forced_done = True
            phase = campaign.get_phase(target_phase)
            if phase is None:
                print(f"\n  ERROR: Phase {target_phase} not found in campaign.")
                break
            if phase.status != "pending":
                print(f"  [force] Phase {phase.id} status was '{phase.status}' — "
                      f"resetting to pending (explicit --phase override)")
                phase.status = "pending"
                campaign.save()
        else:
            phase = campaign.next_phase()
            if phase is None:
                print("\n  All phases complete!")
                break

        print(f"\n  ── Phase {phase.id}: {phase.name} ──")
        print(f"     Priority: {phase.priority}  Type: {phase.type}")

        # ── LM brute phase ─────────────────────────────────────────────────
        if phase.type == "lm_brute":
            if _run_lm_brute_phase(phase, campaign, runner, args, total,
                                   target_phase, _run_opt, _dry_run_previewed) == "break":
                break
            continue

        # ── LM toggle phase (prepares lm_cracked.txt, then runs as standard) ─
        if phase.type == "lm_toggle":
            _sig = _run_lm_toggle_phase(phase, campaign, runner, args,
                                        _dry_run_previewed)
            if _sig == "continue":
                continue
            # "proceed" → fall through to the standard handler below

        # ── combo_rules: rule-convert (on-GPU) → combinator.bin pipe fallback ─
        elif phase.type == "combo_rules":
            if _run_combo_rules_phase(phase, campaign, runner, args, total,
                                      target_phase, _run_opt, _dry_run_previewed) == "break":
                break
            continue

        # ── Standard hashcat phase (wordlist/rules/mask/hybrid/brute/
        #    combinator/prepared-lm_toggle): pre-flight + combinator-conv + run ─
        if _run_standard_phase(phase, campaign, runner, args, total,
                               target_phase, _run_opt, _dry_run_previewed) == "break":
            break



def _finalize_run(ctx: _RunContext, args: argparse.Namespace) -> None:
    """Dry-run restore, run summary, and the final report when all phases are done."""
    campaign = ctx.campaign
    # Dry-run cleanup: restore save, reset all previewed phases to "pending",
    # do one authoritative save so campaign.json is unchanged by the dry-run.
    if args.dry_run:
        campaign.save = ctx.orig_save
        for _p in ctx.dry_run_previewed:
            _p.status = "pending"
        campaign.save()

    _print_run_summary(campaign, ctx.runner)

    if _stop_requested:
        print(f"  Run paused. Resume with:\n"
              f"    python crackbaby.py run {ctx.campaign_dir}\n")
    else:
        if not args.dry_run and not any(p.status == "pending" for p in campaign.phases):
            print("  All phases complete — generating final report...")
            reporter = Reporter(campaign)
            report_text = reporter.generate()
            print(report_text[:3000])
            report_path = os.path.join(campaign.output_dir, "report.txt")
            print(f"\n  Full report: {report_path}")


def cmd_run(args: argparse.Namespace) -> None:
    """Orchestrator: prepare the run context, dispatch phases, then finalize."""
    ctx = _prepare_run(args)
    _run_phase_loop(ctx, args)
    _finalize_run(ctx, args)


# ── STATUS ────────────────────────────────────────────────────────────────────

# ── REPORT ────────────────────────────────────────────────────────────────────

def cmd_report(args: argparse.Namespace) -> None:
    campaign_dir = os.path.abspath(args.campaign)
    campaign = Campaign.load(campaign_dir)
    reporter = Reporter(campaign)
    out = getattr(args, "out", None)
    report_text = reporter.generate(output_path=out)
    print(report_text)
    if not out:
        out = os.path.join(campaign.output_dir, "report.txt")
    print(f"\n  Report saved to: {out}")


# ── ANALYZE ───────────────────────────────────────────────────────────────────

_PHASE_RANGE_RE = re.compile(r'^P(\d+)-P?(\d+)$', re.IGNORECASE)


def _expand_phase_ids(tokens: List[str]) -> List[str]:
    """
    Expand phase ID tokens into a flat list, supporting range syntax.

      P0042            → ["P0042"]
      P0001-P0005      → ["P0001", "P0002", "P0003", "P0004", "P0005"]
      P0001-0005       → same (P prefix on first token only)
      P0010 P0020-P0025 P0030  → mixed list + range, all expanded
    """
    result = []
    for token in tokens:
        m = _PHASE_RANGE_RE.match(token)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            result.extend(f"P{n:04d}" for n in range(a, b + 1))
        else:
            result.append(token)
    return result


def _existing_combos(campaign):
    """Return set of (wl_path, rule_path_or_None) for all phases in the campaign."""
    combos = set()
    for p in campaign.phases:
        if p.type == "wordlist":
            wl = p.args[-1] if p.args else None
            combos.add((wl, None))
        elif p.type == "rules":
            try:
                ri = p.args.index("-r")
                rule = p.args[ri + 1]
                wl = p.args[ri + 2]
                combos.add((wl, rule))
            except (ValueError, IndexError):
                pass
    return combos


def _next_priority(campaign, band: int, step: int = 1) -> int:
    """Return the next available priority in a band (max existing + step)."""
    existing = [p.priority for p in campaign.phases
                if p.priority is not None and band <= p.priority < band + 900]
    return (max(existing) + step) if existing else band


def cmd_benchmark(args: argparse.Namespace) -> None:
    """Run hashcat --benchmark or manually set campaign speed / time-gate threshold."""
    campaign_dir = os.path.abspath(args.campaign)
    campaign = Campaign.load(campaign_dir)

    speed_changed     = getattr(args, "set_speed",      None) is not None
    threshold_changed = getattr(args, "set_threshold",  None) is not None

    # ── Manual overrides (--set and/or --set-threshold) ────────────────────────
    if speed_changed or threshold_changed:
        if speed_changed:
            ghs = args.set_speed
            unit, val = ("GH/s", ghs) if ghs >= 1 else ("MH/s", ghs * 1000)
            print(f"\n  Manual speed override: {val:.1f} {unit}")
            print(f"  Previous setting:      {campaign.expected_speed_ghs:.1f} GH/s")
            campaign.expected_speed_ghs = ghs

        if threshold_changed:
            new_t   = args.set_threshold or None   # 0 → None (remove threshold)
            old_t   = campaign.skip_threshold_hours
            old_lbl = f"{old_t}h" if old_t is not None else "none"
            new_lbl = f"{new_t}h" if new_t is not None else "none"
            print(f"\n  Threshold updated: {old_lbl} → {new_lbl}")
            campaign.skip_threshold_hours = new_t

        campaign.save()

        if speed_changed:
            print(f"  ✓ campaign.expected_speed_ghs set to {ghs:.4f} GH/s")
        print()
        _print_phase_list(campaign, pending_only=True)
        ks_missing = sum(
            1 for p in campaign.phases
            if p.status == "pending" and p.estimated_keyspace is None
        )
        if ks_missing:
            print(f"  {ks_missing} pending phase(s) show '?' — run:")
            print(f"    python crackbaby.py phases --campaign {campaign_dir} --pending --compute-keyspace\n")
        return

    # ── Hashcat benchmark ──────────────────────────────────────────────────────
    runner = HashcatRunner(
        hashcat_bin=campaign.hashcat_bin,
        hash_file=campaign.hash_file,
        hash_type=campaign.hash_type,
        potfile=campaign.potfile,
        cracked_file=campaign.cracked_file,
        sessions_dir=campaign.sessions_dir,
        username_mode=campaign.username_mode,
        devices=campaign.devices,
        global_potfile=campaign.global_potfile,
    )

    mode_name = {1000: "NTLM", 1001: "NTLMv2", 5600: "NetNTLMv2"}.get(
        campaign.hash_type, f"mode {campaign.hash_type}"
    )
    print(f"\n  Benchmarking {mode_name} (mode {campaign.hash_type})…")
    print(f"  Binary: {campaign.hashcat_bin}")
    if campaign.devices:
        print(f"  Devices: {campaign.devices}")
    print()

    ghs = runner.benchmark_speed()

    if ghs is None:
        print("  ERROR: Could not parse benchmark output. Check the hashcat binary path.")
        print("  Set speed manually with:  python crackbaby.py benchmark --campaign DIR --set <GH/s>")
        sys.exit(1)

    unit, val = ("GH/s", ghs) if ghs >= 1 else ("MH/s", ghs * 1000)
    print(f"  Measured speed:  {val:.1f} {unit}")
    print(f"  Current setting: {campaign.expected_speed_ghs:.1f} GH/s")

    update = args.update
    if not update:
        try:
            ans = input(f"\n  Update campaign speed to {val:.1f} {unit}? [y/N] ").strip().lower()
            update = ans in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            update = False

    if update:
        campaign.expected_speed_ghs = ghs
        campaign.save()
        print(f"  ✓ campaign.expected_speed_ghs set to {ghs:.4f} GH/s")
        print()
        _print_phase_list(campaign, pending_only=True)
        ks_missing = sum(
            1 for p in campaign.phases
            if p.status == "pending" and p.estimated_keyspace is None
        )
        if ks_missing:
            print(f"  {ks_missing} pending phase(s) show '?' — run:")
            print(f"    python crackbaby.py phases --campaign {campaign_dir} --pending --compute-keyspace\n")
    else:
        print("  No change made. Pass --update to skip the prompt.\n")

    # ── Per-type benchmark (--update-all) ─────────────────────────────────────
    if getattr(args, "update_all", False):
        _run_per_type_benchmark(campaign, runner, ghs)


def cmd_add(args: argparse.Namespace) -> None:
    """Add a wordlist or rule file to an existing campaign."""
    campaign_dir = os.path.abspath(args.campaign)
    campaign = Campaign.load(campaign_dir)

    wordlists = [os.path.abspath(w) for w in (getattr(args, "wordlists", None) or [])]
    rules     = [os.path.abspath(r) for r in (getattr(args, "rules",     None) or [])]

    if not wordlists and not rules:
        print("  ERROR: specify --wordlists, --rules, or both.")
        sys.exit(1)

    # ── Validate all paths before making any changes ──────────────────────
    for path, label in ([(w, "wordlist") for w in wordlists]
                        + [(r, "rule") for r in rules]):
        if not os.path.exists(path):
            print(f"  ERROR: {label} not found: {path}")
            sys.exit(1)

    added: list = []

    # ── Register new wordlists and regenerate full phase set ──────────────
    # build_initial_phases produces combo_rules, hybrid, combinator, rules, etc.
    # for all registered wordlists, so a single call covers all new phases.
    if wordlists:
        for wl in wordlists:
            if wl not in campaign.wordlists:
                campaign.wordlists.append(wl)
                print(f"  Registered wordlist: {os.path.basename(wl)}")
            else:
                print(f"  Already registered:  {os.path.basename(wl)}")

        new_phases = _generate_new_phases(campaign)
        for p in new_phases:
            campaign.phases.append(p)
        added.extend(new_phases)

    # ── Rule files: pair with all registered wordlists ─────────────────────
    # Rule files are added manually (they aren't in a rules directory so
    # build_initial_phases wouldn't discover them automatically).
    if rules:
        from modules.phases import _make_rule_phase, reset_counter as _rc
        _max_n = max(
            (int(p.id[1:]) for p in campaign.phases if p.id[1:].isdigit()),
            default=0,
        )
        _rc(_max_n)
        existing = _existing_combos(campaign)
        for rule in rules:
            for wl in campaign.wordlists:
                if (wl, rule) not in existing:
                    priority = _next_priority(campaign, band=200, step=1)
                    p = _make_rule_phase(wl, rule, priority, campaign)
                    campaign.phases.append(p)
                    existing.add((wl, rule))   # prevent intra-call dupes
                    added.append(p)

    campaign.save()

    if added:
        print(f"\n  Added {len(added)} phase(s):")
        for p in sorted(added, key=lambda x: x.priority):
            tag = "  [SKIPPED — time-gated]" if p.status == "skipped" else ""
            print(f"    [{p.id}]  pri={p.priority:<6}  {p.name}{tag}")
    else:
        print("\n  No new phases — all requested combos already exist in this campaign.")
    print()


def cmd_rebuild(args: argparse.Namespace) -> None:
    """Update campaign settings and/or regenerate the pending phase list."""
    from modules.phases import build_initial_phases, reset_counter

    campaign_dir = os.path.abspath(args.campaign)
    if not os.path.exists(os.path.join(campaign_dir, "campaign.json")):
        print(f"  ERROR: No campaign found at {campaign_dir}")
        sys.exit(1)

    campaign = Campaign.load(campaign_dir)
    print(f"  Loaded: {campaign.name}  ({len(campaign.phases)} phases, "
          f"{sum(1 for p in campaign.phases if p.status == 'pending')} pending)")

    # ── Apply setting overrides ──────────────────────────────────────────────
    changed = []

    if getattr(args, "from_config", False):
        _cfg, _ = _load_user_config()
        _rebuild_cfg_map = [
            ("max_combinator_pairs_ks", "max_combinator_pairs_ks"),
            ("max_rule_convert_words",  "max_rule_convert_words"),
            ("expected_speed_ghs",      "expected_speed_ghs"),
            ("default_rule_depth",      "default_rule_depth"),
            ("status_interval",         "status_interval"),
        ]
        for cfg_key, attr in _rebuild_cfg_map:
            if cfg_key in _cfg:
                old = getattr(campaign, attr, None)
                setattr(campaign, attr, _cfg[cfg_key])
                if old != _cfg[cfg_key]:
                    changed.append(f"{attr}: {old} → {_cfg[cfg_key]}")
        if "skip_threshold_hours" in _cfg:
            old = campaign.skip_threshold_hours
            campaign.skip_threshold_hours = _cfg["skip_threshold_hours"] or None
            if old != campaign.skip_threshold_hours:
                changed.append(f"skip_threshold_hours: {old} → {campaign.skip_threshold_hours}")

    if args.max_combinator_pairs is not None:
        old = campaign.max_combinator_pairs_ks
        campaign.max_combinator_pairs_ks = args.max_combinator_pairs
        changed.append(f"max_combinator_pairs_ks: {old:,} → {args.max_combinator_pairs:,}")

    if getattr(args, "max_rule_convert_words", None) is not None:
        old = campaign.max_rule_convert_words
        campaign.max_rule_convert_words = args.max_rule_convert_words
        changed.append(f"max_rule_convert_words: {old} → {args.max_rule_convert_words}")

    if args.skip_slow is not None:
        old = campaign.skip_threshold_hours
        campaign.skip_threshold_hours = args.skip_slow if args.skip_slow > 0 else None
        changed.append(f"skip_threshold_hours: {old} → {campaign.skip_threshold_hours}")

    if args.expected_speed is not None:
        old = campaign.expected_speed_ghs
        campaign.expected_speed_ghs = args.expected_speed
        changed.append(f"expected_speed_ghs: {old} → {args.expected_speed}")

    if args.rule_depth is not None:
        old = campaign.default_rule_depth
        campaign.default_rule_depth = args.rule_depth
        changed.append(f"default_rule_depth: {old} → {args.rule_depth}")

    # ── Register any new wordlists ───────────────────────────────────────────
    for wl_path in (getattr(args, "wordlists", None) or []):
        wl_abs = os.path.abspath(wl_path)
        if not os.path.exists(wl_abs):
            print(f"  WARNING: wordlist not found, skipping: {wl_abs}")
            continue
        if wl_abs not in campaign.wordlists:
            campaign.wordlists.append(wl_abs)
            changed.append(f"wordlists: added {os.path.basename(wl_abs)}")

    if changed:
        print("  Settings updated:")
        for c in changed:
            print(f"    {c}")
    else:
        print("  No settings changed.")

    # ── Save updated settings immediately ────────────────────────────────────
    if not args.dry_run:
        campaign.save()

    # ── Regenerate phase list ────────────────────────────────────────────────
    # Advance ID counter past all existing phase IDs to avoid collisions
    _max_n = 0
    for p in campaign.phases:
        try:
            _max_n = max(_max_n, int(p.id[1:]))
        except (ValueError, IndexError):
            pass
    reset_counter(_max_n)

    print("  Building candidate phase set...")
    candidate_phases = build_initial_phases(campaign)


    TERMINAL = {"completed", "skipped", "failed", "interrupted", "timed_out", "running"}
    non_pending = [p for p in campaign.phases if p.status in TERMINAL]
    pending     = [p for p in campaign.phases if p.status == "pending"]
    done_keys   = {_phase_key(p) for p in non_pending}

    new_phases = [p for p in candidate_phases if _phase_key(p) not in done_keys]

    keep_pending = getattr(args, "keep_pending", False)
    if keep_pending:
        # Additive only: keep existing pending, append phases that don't already exist
        existing_pending_keys = {_phase_key(p) for p in pending}
        new_phases = [p for p in new_phases if _phase_key(p) not in existing_pending_keys]
        dropped = 0
    else:
        dropped = len(pending)

    print(f"  Phases: {len(non_pending)} kept (non-pending)  |  "
          f"{dropped} pending dropped  |  {len(new_phases)} new added")

    # Per-new-wordlist summary: for each wordlist the user just registered,
    # report how many new phases reference it. Surfaces cases where the
    # keyspace limit (max_combinator_pairs_ks) silently drops combo_rules
    # phases for big new lists × existing big lists.
    _new_wl_paths = []
    for _w in (getattr(args, "wordlists", None) or []):
        _wa = os.path.abspath(_w)
        if _wa in campaign.wordlists and os.path.exists(_wa):
            _new_wl_paths.append(_wa)

    if _new_wl_paths:
        for _wl_abs in _new_wl_paths:
            _n_combo_rules = sum(
                1 for p in new_phases
                if p.type == "combo_rules"
                and _wl_abs in (p.combo_wl1 or "", p.combo_wl2 or "")
            )
            _n_combinator = sum(
                1 for p in new_phases
                if p.type == "combinator" and _wl_abs in (p.args or [])
            )
            _n_other = sum(
                1 for p in new_phases
                if p.type in ("wordlist", "rules", "hybrid")
                and _wl_abs in (p.args or [])
            )
            _total = _n_combo_rules + _n_combinator + _n_other
            print(f"    new wordlist {os.path.basename(_wl_abs)}: "
                  f"{_total} new phase(s)  "
                  f"(combo_rules={_n_combo_rules}, "
                  f"combinator={_n_combinator}, other={_n_other})")

    if args.dry_run:
        if new_phases:
            for p in sorted(new_phases, key=lambda x: x.priority):
                print(f"    [+] {p.id}  pri={p.priority:<5}  {p.name}")
        else:
            print("    (no new phases would be added)")
        print("  [DRY-RUN] No changes written.")
        return

    if keep_pending:
        campaign.phases = campaign.phases + new_phases
    else:
        campaign.phases = non_pending + new_phases

    campaign.save()
    print(f"  Campaign saved → {campaign.state_file}")
    print(f"\n  Run with:  python crackbaby.py run {campaign_dir}\n")


def cmd_clean(args: argparse.Namespace) -> None:
    """Delete campaign logs and/or rules cache files.

    Scopes (any combination; --all = logs + rules-cache):
      --logs         *.log under <campaign>/logs (requires --campaign)
      --rules-cache  *.rule files under <campaign>/wordlists/rules_cache/
    """
    import glob, shutil as _sh

    _all       = getattr(args, "all", False)
    want_logs  = args.logs       or _all
    want_rules = getattr(args, "rules_cache", False) or _all

    if not (want_logs or want_rules):
        print("  Nothing requested. Pass --logs, --rules-cache, or --all.")
        return

    if not args.campaign:
        print("  --campaign DIR is required.")
        return

    campaign_dir = os.path.abspath(args.campaign)
    if not os.path.exists(os.path.join(campaign_dir, "campaign.json")):
        print(f"  ERROR: No campaign found at {campaign_dir}")
        return

    targets = []  # list[(path, bytes, is_dir)]

    def _too_new(p):
        if args.older_than is None:
            return False
        try:
            return (time.time() - os.path.getmtime(p)) / 86400.0 < args.older_than
        except OSError:
            return True

    def _add(p, is_dir=False):
        if _too_new(p):
            return
        try:
            sz = sum(
                os.path.getsize(os.path.join(r, f))
                for r, _, fs in os.walk(p) for f in fs
            ) if is_dir else os.path.getsize(p)
        except OSError:
            return
        targets.append((p, sz, is_dir))

    if want_logs:
        log_dir = os.path.join(campaign_dir, "logs")
        print(f"  campaign logs dir: {log_dir}")
        if os.path.isdir(log_dir):
            for p in glob.glob(os.path.join(log_dir, "*.log")):
                _add(p)
        else:
            print("    (directory does not exist — nothing to clean)")

    if want_rules:
        rules_cache = os.path.join(campaign_dir, "wordlists", "rules_cache")
        print(f"  rules cache dir: {rules_cache}")
        if os.path.isdir(rules_cache):
            for p in glob.glob(os.path.join(rules_cache, "*.rule")):
                _add(p)
        else:
            print("    (directory does not exist — nothing to clean)")

    if not targets:
        print("  Nothing to clean.")
        return

    total = sum(s for _, s, _ in targets)
    print(f"\n  Found {len(targets)} item(s) / {total/(1<<20):.1f} MB")

    if args.dry_run:
        for p, s, _ in targets[:25]:
            print(f"    {s:>12,} bytes  {p}")
        if len(targets) > 25:
            print(f"    ... and {len(targets)-25} more")
        print("  [DRY-RUN] No files deleted.")
        return

    if not args.y:
        try:
            ans = input("  Delete these items? [y/N] ").strip().lower()
        except EOFError:
            print("  Non-interactive — pass -y to confirm.")
            return
        if ans != "y":
            print("  Aborted.")
            return

    deleted = freed = 0
    for p, s, is_dir in targets:
        try:
            if is_dir:
                _sh.rmtree(p)
            else:
                os.unlink(p)
            deleted += 1
            freed += s
        except OSError as e:
            print(f"  WARN: failed to delete {p}: {e}")
    print(f"  Deleted {deleted} item(s); freed {freed/(1<<20):.1f} MB.")


def cmd_phases(args: argparse.Namespace) -> None:
    campaign_dir = os.path.abspath(args.campaign)
    campaign = Campaign.load(campaign_dir)

    # ── Display options ─────────────────────────────────────────────────────────
    dry_run    = getattr(args, "dry_run",    False)
    compute_ks = getattr(args, "compute_keyspace", False)
    sort_by    = getattr(args, "sort_by",    "priority")
    _wide      = getattr(args, "wide",       False)
    _name_w    = getattr(args, "name_width", None)
    name_width = _name_w if _name_w is not None else (80 if _wide else 50)

    # ── Delete phases ───────────────────────────────────────────────────────────
    delete_ids = _expand_phase_ids(getattr(args, "delete_ids", None) or [])
    if delete_ids:
        id_map = {p.id: p for p in campaign.phases}
        any_found = False
        for i in delete_ids:
            if i in id_map:
                print(f"  Deleted  {i}  {id_map[i].name}")
                any_found = True
            else:
                print(f"  WARNING: {i} not found — skipped")
        if any_found and not dry_run:
            keep_set = {i for i in delete_ids if i in id_map}
            campaign.phases = [p for p in campaign.phases if p.id not in keep_set]
            campaign.save()
            print(f"  {len(keep_set)} phase(s) deleted.")
        elif any_found and dry_run:
            print(f"  Dry run — no changes made. Remove --dry-run to apply.")
        campaign = Campaign.load(campaign_dir)  # reload for list view

    # ── Skip / unskip mutation ──────────────────────────────────────────────────
    skip_ids   = _expand_phase_ids(getattr(args, "skip_ids",  None) or [])
    unskip_ids = _expand_phase_ids(getattr(args, "unskip",    None) or [])
    skip_type  = getattr(args, "skip_type",  None)
    over_hours = getattr(args, "over_hours", None)

    if skip_ids or unskip_ids or skip_type or over_hours is not None:
        affected: list = []

        if unskip_ids:
            for pid in unskip_ids:
                p = campaign.get_phase(pid)
                if not p:
                    print(f"  [WARNING] Phase {pid} not found")
                    continue
                if p.status in ("completed", "running"):
                    print(f"  [WARNING] Phase {pid} is {p.status} — cannot unskip")
                    continue
                affected.append((p, "pending"))
            action_label = "UNSKIP → pending"
        else:
            candidates = [p for p in campaign.phases if p.status == "pending"]
            if skip_ids:
                candidates = [p for p in candidates if p.id in set(skip_ids)]
            if skip_type:
                candidates = [p for p in candidates if p.type == skip_type]
            if over_hours is not None:
                if compute_ks:
                    from modules.phases import _fmt_keyspace as _fmtks, _compute_keyspace_native
                    needs_ks = [p for p in candidates if p.estimated_keyspace is None]
                    if needs_ks:
                        print(f"  Computing keyspace for {len(needs_ks)} phase(s)…")
                        for i, p in enumerate(needs_ks, 1):
                            print(f"    [{i}/{len(needs_ks)}] {p.id}  {p.name[:55]}",
                                  end="  ", flush=True)
                            ks = _compute_keyspace_native(p)
                            if ks is not None:
                                p.estimated_keyspace = ks
                                print(f"→  {_fmtks(ks)}", flush=True)
                            else:
                                print("→  (not computable)", flush=True)
                            if i % 25 == 0:
                                campaign.save()
                        campaign.save()
                        print()
                # Use per-type speed (same as _time_gate and phases-list display)
                # so --skip-over-hours matches the ETA shown in the phases table.
                candidates = [
                    p for p in candidates
                    if (_hrs := _phase_estimated_hours(p, campaign)) is not None
                    and _hrs > over_hours
                ]
            affected = [(p, "skipped") for p in candidates]
            action_label = "SKIP"

        if not affected:
            print("  No phases matched the given criteria.")
        else:
            from modules.phases import _fmt_keyspace
            speed = campaign.expected_speed_ghs
            print(f"\n  {'Action':<10} {'ID':<8} {'Type':<12} {'ETA':>8}  Name")
            print(f"  {'-'*9} {'-'*7} {'-'*11} {'-'*8}  {'-'*40}")
            for p, new_status in affected:
                ks = p.estimated_keyspace
                eta_str = _estimate_eta(ks, speed) if ks else "?"
                print(f"  {action_label:<10} {p.id:<8} {p.type:<12} {eta_str:>8}  {p.name[:50]}")
            if dry_run:
                print(f"\n  Dry run — no changes made. Remove --dry-run to apply.")
            else:
                for p, new_status in affected:
                    p.status = new_status
                campaign.save()
                print(f"\n  {len(affected)} phase(s) updated.")

        campaign = Campaign.load(campaign_dir)  # reload for the list view

    # ── List view ────────────────────────────────────────────────────────────────
    runner = HashcatRunner(
        hashcat_bin=campaign.hashcat_bin,
        hash_file=campaign.hash_file,
        hash_type=campaign.hash_type,
        potfile=campaign.potfile,
        cracked_file=campaign.cracked_file,
        sessions_dir=campaign.sessions_dir,
        username_mode=campaign.username_mode,
        global_potfile=campaign.global_potfile,
    )

    _print_run_summary(campaign, runner)
    _print_phase_list(
        campaign,
        show_all=True,
        pending_only=getattr(args, "pending", False),
        type_filter=getattr(args, "type", None),
        runner=runner,
        compute_keyspace=compute_ks,
        sort_by=sort_by,
        name_width=name_width,
    )


# ── Utilities ─────────────────────────────────────────────────────────────────

def _fmt_elapsed(start_ts: Optional[float]) -> str:
    """Human-readable elapsed time from a Unix timestamp to now."""
    if not start_ts:
        return "unknown"
    secs = int(time.time() - start_ts)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _count_basis_total(campaign: Campaign) -> int:
    """Denominator that matches runner.count_cracked().

    In --username mode ``hashcat --show`` emits one line per cracked *account*, so
    count_cracked() returns accounts and must be paired with the total account count.
    Otherwise it returns unique cracked hashes, paired with the unique-hash total.
    Keeping the two on the same basis avoids the nonsensical "accounts / unique"
    percentage (e.g. 775/1794) the live readout used to show.
    """
    if campaign.username_mode:
        return campaign.total_hashes or campaign.unique_hashes
    return campaign.unique_hashes or campaign.total_hashes


def _print_run_summary(campaign: Campaign, runner: HashcatRunner):
    """Print a concise campaign status snapshot — cracked count, elapsed, phases."""
    total = _count_basis_total(campaign)
    cracked = runner.count_cracked()
    pct = cracked / total * 100 if total else 0

    summary = campaign.phase_summary()
    elapsed = _fmt_elapsed(campaign.started_at)

    print(f"\n  ╔══ Campaign Status: {campaign.name} {'═' * max(0, 37 - len(campaign.name))}╗")
    print(f"  ║  Cracked:   {cracked}/{total} ({pct:.1f}%)")
    print(f"  ║  Elapsed:   {elapsed}")
    done   = summary.get("completed", 0)
    skip   = summary.get("skipped", 0)
    run    = summary.get("running", 0)
    intr   = summary.get("interrupted", 0) + summary.get("timed_out", 0)
    pend   = summary.get("pending", 0)
    fail   = summary.get("failed", 0)
    run_str = f"  {run} running" if run else ""
    print(f"  ║  Phases:    {done} done  {skip} skipped{run_str}  {intr} interrupted  "
          f"{pend} pending  {fail} failed")

    # Currently running phase (saved as "running" in campaign.json between status polls)
    running_phases = [p for p in campaign.phases if p.status == "running"]
    if running_phases:
        print(f"  ║")
        print(f"  ║  Running now:")
        for p in running_phases:
            elapsed_secs = (time.time() - p.start_time) if p.start_time else None
            elapsed_str = f"  {_fmt_elapsed(p.start_time)}" if elapsed_secs else ""
            cracked_so_far = (runner.count_cracked() - p.cracked_start) if p.cracked_start else 0
            crack_str = f"  +{cracked_so_far} so far" if cracked_so_far else ""
            _rn = (p.name[:49] + "…") if len(p.name) > 50 else p.name
            print(f"  ║  ► {p.id}  {_rn:<50}{elapsed_str}{crack_str}")

    # Last few finished phases
    finished = [p for p in campaign.phases
                if p.status in ("completed", "skipped", "interrupted", "timed_out", "failed")]
    if finished:
        print(f"  ║")
        print(f"  ║  Recent phases:")
        for p in finished[-5:]:
            delta_str = f"  +{p.cracked_delta} cracked" if p.cracked_delta else ""
            dur_str = f"  {p.duration_str}" if p.duration_secs else ""
            tag = {"completed": "✓", "skipped": "–", "interrupted": "⏸",
                   "timed_out": "⏱", "failed": "✗"}.get(p.status, "?")
            _rn = (p.name[:44] + "…") if len(p.name) > 45 else p.name
            print(f"  ║    {tag} {p.id}  {_rn:<45}{delta_str}{dur_str}")

    # Next pending phase
    nxt = campaign.next_phase()
    if nxt:
        eta_str = ""
        if nxt.estimated_keyspace:
            eta_str = f"  ({_estimate_eta(nxt.estimated_keyspace, campaign.expected_speed_ghs)} @ {_fmt_speed(campaign.expected_speed_ghs)})"
        print(f"  ║")
        print(f"  ║  Next:  {nxt.id}  {nxt.name}{eta_str}")

    print(f"  ╚{'═' * 58}╝\n")


def _print_phase_list(
    campaign: Campaign,
    limit: int = 0,
    show_all: bool = False,
    pending_only: bool = False,
    type_filter: Optional[str] = None,
    runner: Optional["HashcatRunner"] = None,
    compute_keyspace: bool = False,
    sort_by: str = "priority",
    name_width: int = 50,
):
    from modules.phases import _fmt_keyspace  # _phase_speed_* now imported from modules.speed (top level)

    phases = campaign.phases

    # Apply filters
    if pending_only:
        phases = [p for p in phases if p.status == "pending"]
    if type_filter:
        phases = [p for p in phases if p.type == type_filter]
    if not show_all and not pending_only and limit:
        pending = [p for p in phases if p.status == "pending"][:limit]
        running = [p for p in phases if p.status == "running"]
        completed = [p for p in phases if p.status in ("completed", "skipped")][-5:]
        phases = completed + running + pending

    # Apply sort
    _sort_keys = {
        "id":       lambda p: p.id,
        "priority": lambda p: (p.priority, p.id),
        "status":   lambda p: (p.status, p.priority, p.id),
        "name":     lambda p: p.name.lower(),
    }
    phases = sorted(phases, key=_sort_keys.get(sort_by, _sort_keys["priority"]))

    # Optionally compute keyspace for phases that don't have it (Python-native, no GPU init)
    if compute_keyspace:
        from modules.phases import _fmt_keyspace as _fmtks, _compute_keyspace_native
        to_compute = [p for p in phases
                      if p.status == "pending" and p.estimated_keyspace is None]
        if to_compute:
            print(f"  Computing keyspace for {len(to_compute)} phase(s)…")
            for i, p in enumerate(to_compute, 1):
                print(f"    [{i}/{len(to_compute)}] {p.id}  {p.name[:55]}", end="  ", flush=True)
                ks = _compute_keyspace_native(p)
                if ks is not None:
                    p.estimated_keyspace = ks
                    print(f"→  {_fmtks(ks)}", flush=True)
                else:
                    print("→  (not computable)", flush=True)
                if i % 25 == 0:
                    campaign.save()  # incremental saves — Ctrl+C won't lose progress
            campaign.save()
            print()

    status_tag = {
        "pending":     "     ",
        "running":     "[RUN]",
        "completed":   "[OK] ",
        "failed":      "[ERR]",
        "skipped":     "[SKP]",
        "interrupted": "[INT]",
        "timed_out":   "[TMO]",
        "dry_run":     "[DRY]",
    }

    _benchmark_ghs = campaign.expected_speed_ghs
    if _benchmark_ghs > 0:
        spd_note = "set via --expected-speed or benchmark" if _benchmark_ghs != 68.0 else "default — run benchmark to calibrate"
        print(f"\n  ETA estimates @ {_fmt_speed(_benchmark_ghs)} benchmark  ({spd_note})")
        print(f"  Per-type ratios from speed_factors.json; combo_rules uses sub-strategy key.")
    else:
        print(f"\n  ETA estimates: speed not set — run: python crackbaby.py benchmark {campaign.output_dir} --update")
    print(f"  Completed phases show actual runtime in the Time column.\n")

    _N = name_width
    print(f"  {'ID':<8} {'St':<5} {'Pri':>5}  {'Name':<{_N}} {'Type':<12} {'Feed':<9} {'Keyspace':>10}  {'Time':>8}  Cracked")
    print(f"  {'-'*8} {'-'*5} {'-'*5}  {'-'*_N} {'-'*12} {'-'*9} {'-'*10}  {'-'*8}  {'-'*8}")

    for p in phases:
        tag = status_tag.get(p.status, "     ")
        auto = "*" if p.auto_generated else ""

        ks = p.estimated_keyspace
        ks_str = _fmt_keyspace(ks) if ks else "?"

        # Time column:
        #   completed/failed/interrupted/timed_out → actual duration
        #   running → elapsed time so far
        #   pending → ETA estimate (or "?" if no keyspace)
        if p.status in ("completed", "failed", "interrupted", "timed_out"):
            time_str = p.duration_str if p.duration_secs else "?"
        elif p.status == "running":
            time_str = _fmt_elapsed(p.start_time) if p.start_time else "running"
        else:
            # Use per-type (+ combo_rules sub-strategy) speed for accurate ETA.
            _phase_hrs = _phase_estimated_hours(p, campaign)
            if _phase_hrs is None:
                time_str = "N/A" if p.type == "analysis" else "?"
            elif ks:
                time_str = _estimate_eta(ks, _phase_speed_ghs(
                    _phase_speed_key(p, campaign), campaign))
            else:
                time_str = "?"

        # Cracked column
        if p.status == "running":
            cracked_so_far = (runner.count_cracked() - p.cracked_start) if (runner and p.cracked_start) else 0
            cracked_str = f"+{cracked_so_far}"
        else:
            cracked_str = f"+{p.cracked_delta}" if p.cracked_delta else ""

        # Name: truncate with … indicator if it doesn't fit, append auto-flag
        max_name = _N - len(auto)
        if len(p.name) > max_name:
            name_trunc = p.name[:max_name - 1] + "…" + auto
        else:
            name_trunc = p.name + auto

        # Feed column: the strategy driving this phase's ETA — predicted (~) for
        # pending/skipped, actual for ones that have run; blank for plain GPU phases.
        _feed_lbl = ""
        if p.type == "combo_rules":
            _key = _phase_speed_key(p, campaign)
            _strat = _key.removeprefix("combo_rules_")
            _feed_lbl = _FEED_ABBR.get(_strat, _strat)
            if _feed_lbl and p.status in ("pending", "skipped"):
                _feed_lbl += "~"

        print(f"  {p.id:<8} {tag} {p.priority:>5}  {name_trunc:<{_N}} {p.type:<12} "
              f"{_feed_lbl:<9} {ks_str:>10}  {time_str:>8}  {cracked_str}")
    print()


# ── User config ───────────────────────────────────────────────────────────────

def _load_user_config() -> tuple:
    """
    Load the crackbaby user config from the first of:
      1. $CRACKBABY_CONFIG env var
      2. config/crackbaby.json  (in the install root's config/ directory)
      3. ~/.config/crackbaby/config.json

    All keys are optional.  Returns (config_dict, loaded_path).
    loaded_path is '' if no config file was found or it failed to parse.
    The caller is responsible for printing — this function is silent.

    Supported keys:
      hashcat_bin          str   — path to hashcat binary (or its parent directory)
      custom_rules_dir     str   — your own .rule files directory; ALL rules admitted, no tier filter
      default_rules_dirs   list  — overrides built-in search paths for hashcat's bundled rules
      wordlists_dirs       list  — overrides built-in _WORDLIST_SEARCH_PATHS
      expected_speed_ghs   float — default --expected-speed
      default_rule_depth   str   — tier depth for hashcat's bundled rules only ("none"|"A"|"AB"|"ABC")
      workload             int   — default --workload (1-4)
      max_rule_convert_words  int — threshold for rule-convert strategy in combo_rules
    """
    candidates = []
    env_path = os.environ.get("CRACKBABY_CONFIG")
    if env_path:
        candidates.append(env_path)
    candidates += [
        os.path.join(_CONFIG_DIR, "crackbaby.json"),    # config/crackbaby.json (install-local)
        os.path.expanduser("~/.config/crackbaby/config.json"),
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path) as _f:
                    cfg = json.load(_f)
                if isinstance(cfg, dict):
                    return cfg, path
            except Exception as _e:
                print(f"  WARNING: config file found but failed to parse ({path}): {_e}")
    return {}, ""


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    _print_banner()

    # ── Load user config (before argparse so values become defaults) ──────────
    _cfg, _cfg_path = _load_user_config()
    if _cfg_path:
        print(f"  Config: {_cfg_path}")

    # Apply search-path overrides immediately — they affect phases module state
    # before build_initial_phases is ever called.
    if _cfg.get("default_rules_dirs"):
        # Override where HASHCAT's bundled rules are found, but always keep
        # crackbaby's own bundled critical-rules dir as a final fallback so
        # best66.rule / toggles1.rule remain findable (find_rule guarantees this
        # too; appended here to keep _RULE_SEARCH_PATHS honest for diagnostics).
        _dirs = list(_cfg["default_rules_dirs"])
        if _BUNDLED_RULES_DIR not in _dirs:
            _dirs.append(_BUNDLED_RULES_DIR)
        _RULE_SEARCH_PATHS[:] = _dirs
    if _cfg.get("wordlists_dirs"):
        _WORDLIST_SEARCH_PATHS[:] = _cfg["wordlists_dirs"]

    # No Layer 1.5 speed factor override in crackbaby — kept simple.

    # Bootstrap speed_factors.json if it doesn't exist yet (e.g. fresh install).
    # speed._phase_speed_ghs() also does this lazily, but doing it at startup
    # means the user sees the file immediately after first run.
    if not os.path.exists(_SPEED_FACTORS_FILE):
        try:
            os.makedirs(_CONFIG_DIR, exist_ok=True)
            with open(_SPEED_FACTORS_FILE, "w") as _sf:
                import json as _json
                _json.dump(_speed_mod._SPEED_FACTORS_BOOTSTRAP, _sf, indent=2)
            print(f"  Created config/speed_factors.json with default ratios — edit to tune for your rig.")
        except OSError:
            pass  # read-only install — silent; in-memory bootstrap takes over

    # ── Command groups — single source of truth for command ordering, the grouped
    #    --help listing, and the dispatch table. (name, handler). Per-command
    #    summaries live on each subparser's help= (rendered natively by the
    #    grouped formatter so they pick up argparse's colouring).
    COMMAND_GROUPS = [
        ("Setup", [
            ("tools",     cmd_tools),
        ]),
        ("Core Campaign Commands", [
            ("prep",      cmd_prep),
            ("init",      cmd_init),
            ("phases",    cmd_phases),
            ("run",       cmd_run),
            ("report",    cmd_report),
            ("benchmark", cmd_benchmark),
        ]),
        ("Campaign Modification Commands", [
            ("add",        cmd_add),
            ("rebuild",    cmd_rebuild),
        ]),
        ("Temp File Cleanup", [
            ("clean", cmd_clean),
        ]),
    ]
    _fmt_groups = [(title, [n for n, _ in cmds]) for title, cmds in COMMAND_GROUPS]

    parser = argparse.ArgumentParser(
        prog="crackbaby",
        description="Enterprise NTLM password recovery orchestrator.",
        epilog="Run 'crackbaby <command> --help' for command-specific options.",
        formatter_class=functools.partial(_GroupedSubcommandHelpFormatter,
                                          command_groups=_fmt_groups),
    )
    parser.add_argument("--version", action="version",
                        version=f"crackbaby {__version__}")
    # Suppress the redundant "positional arguments:" heading — the subparsers action
    # is the only top-level positional, and the formatter renders it as titled groups.
    parser._positionals.title = argparse.SUPPRESS
    sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    # tools
    p_tools = sub.add_parser("tools",
        help="Show tool status, or download a wordlist",
        description="Show the status of the external tools crackbaby uses:\n"
                    "  • hashcat        — required\n"
                    "  • combinator.bin — optional; hashcat's combinator utility, used as the\n"
                    "                     combo_rules fallback when a wordlist side is too large\n"
                    "                     to convert to GPU rules.\n"
                    "  • rockyou.txt    — the default wordlist (download with --download)\n\n"
                    "Can be run at any time, before or after init.",
        epilog="Examples:\n"
               "  crackbaby tools                     # show tool + wordlist status\n"
               "  crackbaby tools --download rockyou  # fetch the default wordlist → ~/wordlists\n"
               "  crackbaby tools --download <URL>    # fetch any wordlist (.gz auto-decompressed)\n"
               "  crackbaby tools --download rockyou --dest /mnt/wordlists --force",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_tools.add_argument("--status", action="store_true",
                         help="Print tool status (this is the default behaviour)")
    p_tools.add_argument("--download", nargs="?", const="rockyou", metavar="NAME|URL",
                         help="Download a wordlist into ~/wordlists and exit. "
                              f"Known names: {', '.join(sorted(_WORDLIST_SOURCES))} "
                              "(default: rockyou); or pass any http(s) URL (.gz is "
                              "auto-decompressed).")
    p_tools.add_argument("--dest", metavar="DIR",
                         help="Directory to download into (default: ~/wordlists)")
    p_tools.add_argument("--force", action="store_true",
                         help="Re-download even if the wordlist is already present")

    # prep
    p_prep = sub.add_parser("prep",
        help="Extract NT hashes from an NTDS dump",
        description="Extract NT hashes from a secretsdump-format NTDS dump, ready for hashcat.",
        epilog="Example:\n"
               "  crackbaby prep --ntds secretsdump.out --output acme.hashes \\\n"
               "               --enabled-only --no-machines --lm-file acme.lm",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_prep.add_argument("--ntds", required=True, help="Path to ntds.dit dump")
    p_prep.add_argument("--output", required=True, help="Output hash file")
    p_prep.add_argument("--username", action="store_true",
                        help="Write user:hash format (for hashcat --username)")
    p_prep.add_argument("--unique", action="store_true",
                        help="Also write a deduplicated hash file")
    p_prep.add_argument("--enabled-only", action="store_true",
                        help="Only include accounts with 'Enabled' in the NTDS line")
    p_prep.add_argument("--no-machines", action="store_true",
                        help="Exclude machine accounts (usernames ending in $)")
    p_prep.add_argument("--no-system", action="store_true",
                        help="Exclude built-in system accounts (Guest, krbtgt, etc.)")
    p_prep.add_argument("--lm-file", metavar="FILE",
                        help="Also extract non-null LM hashes to this file (for --lm-hashes in init)")

    # init
    p_init = sub.add_parser("init",
        usage="%(prog)s CAMPAIGN --hashes FILE [options]",
        help="Initialize a new campaign",
        description="Initialize a new campaign: detect hashcat/wordlists/rules, build the "
                    "phase pipeline, and (optionally) benchmark the GPU for accurate ETAs.",
        epilog="Example:\n"
               "  crackbaby init /campaigns/acme --hashes acme.hashes \\\n"
               "               --org-config acme.org.json --skip-slow 24",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_init.add_argument("campaign", metavar="CAMPAIGN",
                        help="Campaign output directory")
    p_init.add_argument("--hashes", default=None,
                        help="Hash file (NT hashes, one per line). Required for new campaigns.")
    p_init.add_argument("--name", help="Campaign name")
    p_init.add_argument("--hashcat", help="Path to hashcat binary (auto-detected if omitted)")
    p_init.add_argument("--wordlists", nargs="+", metavar="WL",
                        help="Wordlist files (auto-detected if omitted)")
    p_init.add_argument("--custom-rules-dir",
                        help="Directory of your own .rule files. ALL rules here are always "
                             "admitted — no tier filter. Takes precedence over the same "
                             "filename in the default hashcat rules directory.")
    p_init.add_argument("--username", action="store_true",
                        help="Hash file has user:hash format")
    p_init.add_argument("--devices", metavar="DEV",
                        help="GPU devices (e.g. 1,2,3,4,5,6,7,8). Default: all")
    p_init.add_argument("--workload", type=int, default=3, choices=[1, 2, 3, 4],
                        help="Hashcat workload profile (default: 3)")
    p_init.add_argument("--default-rule-depth", choices=["none", "A", "AB", "ABC"], default="A",
                        help="Tier depth for rules auto-discovered in the DEFAULT hashcat rules "
                             "directory (e.g. /opt/hashcat/rules). Does NOT affect --custom-rules-dir "
                             "(those are always admitted). "
                             "none=disable default-dir discovery entirely; "
                             "A=Tier A only (best66, unix-ninja-leet, generated, "
                             "d3ad0ne, rockyou-30000, T0XlC-year-insert); "
                             "AB=+Tier B (T0XlC, toggles3, combinator); "
                             "ABC=+Tier C pre-analysis (dive, generated2, OneRuleToRuleThemAll). "
                             "Default: A")

    _g_combo = p_init.add_argument_group("Combinator tuning")
    _g_combo.add_argument("--max-combinator-pairs-ks", type=int, default=500_000_000,
                        dest="max_combinator_pairs_ks", metavar="N",
                        help="Max wl×wl pair count for auto-combinator/combo+rules phases "
                             "(default 500M). Raise to include larger wordlist pairs.")
    _g_combo.add_argument("--max-rule-convert-words", type=int, default=50_000,
                        dest="max_rule_convert_words", metavar="N",
                        help="For combo_rules phases, if the smaller wordlist side has ≤ N "
                             "lines, convert it to GPU rules and run fully on-GPU (fastest). "
                             "Falls back to combinator.bin pipe if larger. Default 50000.")

    _g_eta = p_init.add_argument_group("ETA & time-gating")
    _g_eta.add_argument("--phase-timeout", type=float, metavar="HOURS",
                        help="Max wall-clock hours per phase; hashcat checkpoints and moves on")
    _g_eta.add_argument("--expected-speed", type=float, default=68.0, metavar="GH/S",
                        help="Expected GH/s for ETA estimates (default: 68 — single RTX 3090; run benchmark to calibrate)")
    _g_eta.add_argument("--skip-slow", type=float, metavar="HOURS",
                        help="Auto-skip phases estimated to take longer than this many hours")
    _g_eta.add_argument("--status-interval", type=int, default=5, metavar="SECS",
                        help="How often hashcat reports status in seconds (default: 5)")
    _g_eta.add_argument("--no-benchmark", action="store_true",
                        help="Skip the benchmark prompt at init. ETAs use --expected-speed "
                             "(default 68 GH/s). Useful for scripted init or when no GPU is "
                             "available at init time.")

    _g_target = p_init.add_argument_group("Targeting & dedup")
    _g_target.add_argument("--lm-hashes", metavar="FILE",
                        help="LM hash file (from prep --lm-file); adds LM brute+toggle phases")
    _g_target.add_argument("--org-config", metavar="FILE",
                        help="Path to org JSON config file. Generates a targeted org_words.txt "
                             "wordlist used at top priority across all rule phases. "
                             "Keys: org_name, org_name_short, org_location, custom_words (list). "
                             "Example: {\"org_name\": \"Acme Corp\", \"org_name_short\": \"acme\", "
                             "\"org_location\": \"Dallas, TX\", \"custom_words\": [\"cowtown\"]}")
    _g_target.add_argument("--global-potfile", metavar="BASE",
                        help="Shared potfile BASE path used across campaigns. A base "
                             "prefix (e.g. ~/.crackbaby.global → ~/.crackbaby.global_1000.potfile) "
                             "or a directory ending in '/' (uses the default 'crackbaby' base, "
                             "e.g. ~/potfiles/ → ~/potfiles/crackbaby_1000.potfile). crackbaby "
                             "appends _<hash_type>.potfile so NTLM and LM never mix. Hashcat "
                             "skips hashes already cracked in previous campaigns, dramatically "
                             "speeding up repeat-hash engagements. Can also be set via "
                             "global_potfile in config/crackbaby.json.")
    # Apply config/crackbaby.json values as argparse defaults for init (CLI args always win)
    _init_defaults: dict = {}
    _cfg_map = [
        ("hashcat_bin",              "hashcat"),
        ("custom_rules_dir",         "custom_rules_dir"),
        ("expected_speed_ghs",       "expected_speed"),
        ("default_rule_depth",       "default_rule_depth"),
        ("workload",                 "workload"),
        ("global_potfile",           "global_potfile"),
        ("max_combinator_pairs_ks",  "max_combinator_pairs_ks"),
        ("max_rule_convert_words",   "max_rule_convert_words"),
        ("status_interval",          "status_interval"),
    ]
    for cfg_key, arg_dest in _cfg_map:
        if cfg_key in _cfg:
            _init_defaults[arg_dest] = _cfg[cfg_key]
    if _init_defaults:
        p_init.set_defaults(**_init_defaults)

    # run
    p_run = sub.add_parser("run",
        usage="%(prog)s CAMPAIGN [options]",
        help="Run the campaign (resumable)",
        description="Run the campaign's phases in priority order, checkpointing after each. "
                    "Stop with Ctrl-C and re-run the same command to resume.",
        epilog="Examples:\n"
               "  crackbaby run /campaigns/acme                 # run (or resume) all phases\n"
               "  crackbaby run /campaigns/acme --phase P0042   # run one phase only\n"
               "  crackbaby run /campaigns/acme --dry-run       # print commands, run nothing",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_run.add_argument("campaign", metavar="CAMPAIGN",
                       help="Campaign directory")
    p_run.add_argument("--phase", help="Run a specific phase ID only")
    p_run.add_argument("--dry-run", action="store_true",
                       help="Print commands without executing")
    p_run.add_argument("--phase-timeout", type=float, metavar="HOURS",
                       help="Override per-phase timeout for this run (hours)")
    p_run.add_argument("--workload", type=int, choices=[1, 2, 3, 4], metavar="{1-4}",
                       help="Override hashcat workload profile for this run (1=low … 4=nightmare; "
                            "default: campaign setting)")
    p_run.add_argument("--no-optimize", action="store_true", dest="no_optimize",
                       help="Disable hashcat -O (optimized kernel) for this run. "
                            "Use when targeting passwords > 31 chars — -O silently truncates longer candidates.")

    # report
    p_report = sub.add_parser("report",
        usage="%(prog)s CAMPAIGN [--out FILE]",
        help="Generate the final report",
        description="Generate the final pentest report (text + JSON) for a campaign.")
    p_report.add_argument("campaign", metavar="CAMPAIGN",
                          help="Campaign directory")
    p_report.add_argument("--out", help="Output file (default: campaign/report.txt)")

    # phases
    _PHASE_TYPE_CHOICES = ["wordlist", "rules", "mask", "hybrid", "brute",
                           "combinator", "combo_rules",
                           "lm_brute", "lm_toggle"]
    p_phases = sub.add_parser("phases",
        usage="%(prog)s CAMPAIGN [options]",
        help="List, skip, unskip, or delete phases",
        description="View the campaign status and phase list, or manage phases "
                    "(skip / unskip / delete). With no management flags it prints the status "
                    "summary and phase table.",
        epilog="Examples:\n"
               "  crackbaby phases /campaigns/acme --pending\n"
               "  crackbaby phases /campaigns/acme --skip-over-hours 24 --dry-run\n"
               "  crackbaby phases /campaigns/acme --skip P0050-P0075\n"
               "  crackbaby phases /campaigns/acme --unskip P0042",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_phases.add_argument("campaign", metavar="CAMPAIGN",
                          help="Campaign directory")

    _g_ph_list = p_phases.add_argument_group("Listing & filtering")
    _g_ph_list.add_argument("--pending", action="store_true",
                          help="Show only pending phases")
    _g_ph_list.add_argument("--type", metavar="TYPE", choices=_PHASE_TYPE_CHOICES,
                          help="Filter the displayed list by phase type")
    _g_ph_list.add_argument("--sort", metavar="FIELD", dest="sort_by",
                          choices=["id", "priority", "status", "name"],
                          default="priority",
                          help="Sort order for the phase list: id|priority|status|name (default: priority)")
    _g_ph_list.add_argument("--wide", action="store_true",
                          help="Expand the Name column to 80 chars (equivalent to --name-width 80)")
    _g_ph_list.add_argument("--name-width", type=int, metavar="N", dest="name_width",
                          help="Set Name column width to N chars (overrides --wide)")
    _g_ph_list.add_argument("--compute-keyspace", action="store_true",
                          help="Compute keyspace for pending phases that don't have one yet "
                               "(Python-native — fast; stores results in campaign.json for accurate ETAs)")

    _g_ph_mgmt = p_phases.add_argument_group("Phase management (skip / unskip / delete)")
    _g_ph_mgmt.add_argument("--skip", nargs="+", metavar="ID", dest="skip_ids",
                          help="Mark phase ID(s) as skipped (accepts ranges, e.g. P0010-P0025)")
    _g_ph_mgmt.add_argument("--unskip", nargs="+", metavar="ID",
                          help="Restore phase ID(s) to pending (overrides any status)")
    _g_ph_mgmt.add_argument("--skip-type", metavar="TYPE", choices=_PHASE_TYPE_CHOICES,
                          dest="skip_type",
                          help="Skip all pending phases of this type")
    _g_ph_mgmt.add_argument("--skip-over-hours", type=float, metavar="N",
                          dest="over_hours",
                          help="Skip pending phases estimated to take longer than N hours")
    _g_ph_mgmt.add_argument("--delete", nargs="+", metavar="ID", dest="delete_ids",
                          help="Delete phase ID(s) permanently (supports ranges, e.g. P0010-P0020)")
    _g_ph_mgmt.add_argument("--dry-run", action="store_true",
                          help="With --skip / --unskip / --skip-* / --delete: print what would change without writing")

    # benchmark
    p_bench = sub.add_parser("benchmark",
        usage="%(prog)s CAMPAIGN [options]",
        help="Measure GPU speed; calibrate ETAs",
        description="Measure the GPU's actual hashcat speed for this campaign's hash type, "
                    "then update the campaign's ETA/time-gating speed.")
    p_bench.add_argument("campaign", metavar="CAMPAIGN",
                         help="Campaign directory")
    p_bench.add_argument("--update", action="store_true",
                         help="Automatically update campaign.expected_speed_ghs (skip prompt)")
    p_bench.add_argument("--set", type=float, dest="set_speed", metavar="GH/S",
                         help="Manually set campaign speed (GH/s) without running a benchmark")
    p_bench.add_argument("--set-threshold", type=float, dest="set_threshold", metavar="HOURS",
                         help="Update the campaign's auto-skip threshold (hours) and re-evaluate "
                              "all time gates immediately. Pass 0 to remove the threshold entirely. "
                              "Can be combined with --set.")
    p_bench.add_argument("--update-all", action="store_true", dest="update_all",
                         help="After the NTLM benchmark, run 5-second calibration attacks for each "
                              "phase type (brute, wordlist, rules) and write config/speed_factors.json. "
                              "Used by all campaigns for accurate per-type ETAs.")

    # add
    p_add = sub.add_parser("add",
        usage="%(prog)s CAMPAIGN --wordlists PATH [PATH ...] [--rules PATH [PATH ...]]",
        help="Add wordlists or rule files; auto-generate phases",
        description="Add wordlists and/or rule files to an existing campaign and auto-generate "
                    "all resulting phases (the campaign must come BEFORE --wordlists/--rules).",
        epilog="Examples:\n"
               "  crackbaby add /campaigns/acme --wordlists rockyou.txt new.txt\n"
               "  crackbaby add /campaigns/acme --rules custom.rule",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_add.add_argument("campaign", metavar="CAMPAIGN",
                       help="Campaign directory (must come BEFORE --wordlists/--rules)")
    p_add.add_argument("--wordlists", nargs="+", metavar="PATH",
                       help="One or more wordlist files to add; all phase types "
                            "(rules, combo_rules, hybrid, etc.) are auto-generated")
    p_add.add_argument("--rules", nargs="+", metavar="PATH",
                       help="One or more rule files to add; paired with all registered wordlists")

    # rebuild
    p_rebuild = sub.add_parser("rebuild",
        usage="%(prog)s CAMPAIGN [options]",
        help="Change settings and regenerate the phase list",
        description="Update campaign settings and regenerate the pending phase list. "
                    "By default pending phases are replaced; use --keep-pending to only add new ones.",
        epilog="Examples:\n"
               "  crackbaby rebuild /campaigns/acme --max-combinator-pairs 50000000000\n"
               "  crackbaby rebuild /campaigns/acme --wordlist new.txt --keep-pending\n"
               "  crackbaby rebuild /campaigns/acme --from-config --dry-run",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_rebuild.add_argument("campaign", metavar="CAMPAIGN",
                           help="Campaign directory")
    p_rebuild.add_argument("--skip-slow", type=float, metavar="HOURS",
        dest="skip_slow",
        help="Update auto-skip threshold in hours (0 = remove threshold)")
    p_rebuild.add_argument("--expected-speed", type=float, metavar="GH/S",
        dest="expected_speed",
        help="Update expected GPU speed used for ETA and time-gating")
    p_rebuild.add_argument("--rule-depth", choices=["none", "A", "AB", "ABC"],
        dest="rule_depth",
        help="Update default rule tier depth")
    p_rebuild.add_argument("--wordlist", nargs="+", metavar="PATH",
        dest="wordlists",
        help="Add wordlist(s) to the campaign registry before rebuilding phases")
    p_rebuild.add_argument("--from-config", action="store_true",
        dest="from_config",
        help="Re-read config/crackbaby.json and apply any updated values before rebuilding")
    p_rebuild.add_argument("--keep-pending", action="store_true",
        dest="keep_pending",
        help="Additive only — keep existing pending phases, only add new ones")
    p_rebuild.add_argument("--dry-run", action="store_true",
        help="Show what would change without writing anything")

    _g_rb_combo = p_rebuild.add_argument_group("Combinator tuning")
    _g_rb_combo.add_argument("--max-combinator-pairs", type=int, metavar="N",
        dest="max_combinator_pairs",
        help="Update max_combinator_pairs_ks (e.g. 50000000000 for 50B)")
    _g_rb_combo.add_argument("--max-rule-convert-words", type=int, metavar="N",
        dest="max_rule_convert_words",
        help="Update max_rule_convert_words (default 50000). Smaller wl side ≤ N "
             "lines → converted to GPU rules (fastest path for asymmetric combos).")

    # clean — delete campaign logs and rules_cache
    p_clean = sub.add_parser("clean",
        help="Delete campaign logs and rules cache files",
        description="Reclaim disk space by deleting crackbaby's scratch artifacts. "
                    "Always preview with --dry-run first.",
        epilog="Examples:\n"
               "  crackbaby clean --all --campaign /campaigns/acme --dry-run\n"
               "  crackbaby clean --logs --campaign /campaigns/acme -y",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    _g_cl_what = p_clean.add_argument_group("What to clean")
    _g_cl_what.add_argument("--logs", action="store_true",
        help="Delete .log files in <campaign>/logs/  (requires --campaign)")
    _g_cl_what.add_argument("--rules-cache", action="store_true",
        dest="rules_cache",
        help="Delete cached .rule files in <campaign>/wordlists/rules_cache/")
    _g_cl_what.add_argument("--all", action="store_true",
        help="Shorthand for --logs --rules-cache")

    _g_cl_scope = p_clean.add_argument_group("Scope & options")
    _g_cl_scope.add_argument("--campaign", default=None, metavar="DIR",
        help="Campaign directory (required)")
    _g_cl_scope.add_argument("--older-than", type=float, default=None, metavar="DAYS",
        dest="older_than",
        help="Only delete files older than this many days (by mtime)")
    _g_cl_scope.add_argument("--dry-run", action="store_true",
        help="List files that would be deleted and total size; delete nothing")
    _g_cl_scope.add_argument("-y", action="store_true",
        help="Skip the interactive confirmation prompt")

    # Bare invocation → show help instead of erroring on a required positional:
    #   `crackbaby`         → top-level help
    #   `crackbaby <cmd>`   → that command's help
    # (-h / --help / --version / unknown commands fall through to argparse.)
    # `tools` is excluded: it takes no required args and its no-arg form is the
    # status check, so `crackbaby tools` should run, not print help.
    _NO_ARG_OK = {"tools"}
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    if len(sys.argv) == 2 and sys.argv[1] in sub.choices and sys.argv[1] not in _NO_ARG_OK:
        sub.choices[sys.argv[1]].print_help()
        sys.exit(0)

    args = parser.parse_args()

    dispatch = {name: fn for _, cmds in COMMAND_GROUPS for name, fn in cmds}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
