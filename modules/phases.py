"""
Phase generation — initial attack pipeline for crackbaby.

Attack pipeline order (priority bands):
  100–199      Wordlist (straight)
  200–999      Wordlist + rules (light → heavy; steps 1–4 per rule)
  1000–1099    Enterprise mask patterns (6–10 char shapes)
  1100–1199    Two-word / passphrase pre-analysis (common-word combinator + rules)
               + org_words×suffixes (1155)
  1200–19999   Hybrid (wordlist+mask, mask+wordlist) + combinator + combo_rules attacks
               18 800 slots at step 5 = 3 760 phases — handles 50+ wordlists without overflow
  60000–69999  Brute force (6–10 char, ordered by keyspace ascending)

Crackbaby builds only direct hashcat attack phases — no separate analysis or
candidate-generator passes.
Priority bands are wide enough to accommodate any realistic number of
wordlists (up to ~50) and rule files (up to ~60 admitted) without overflow.
"""

import json
import os
import re
import subprocess
import time
from collections import Counter
from typing import List, Optional, Tuple

from .campaign import Campaign, Phase

# ── Install roots (single source of truth in modules/__init__.py) ─────────────
# _CRACKBABY_DIR → install root (bundled assets: rules/)
# _CONFIG_DIR    → config/ subdir (speed_factors.json, crackbaby.json)
from . import CRACKBABY_ROOT as _CRACKBABY_DIR, CONFIG_DIR as _CONFIG_DIR

# ── Phase ID counter ──────────────────────────────────────────────────────────

_COUNTER = 0


def _new_id() -> str:
    global _COUNTER
    _COUNTER += 1
    return f"P{_COUNTER:04d}"


def reset_counter(start: int = 0) -> None:
    global _COUNTER
    _COUNTER = start


# Speed/timing model lives in modules/speed.py — phases consumes these.
from .speed import _phase_speed_ghs, _time_gate


# ── Path resolution helpers ───────────────────────────────────────────────────

# crackbaby ships its own critical rules (best66.rule, toggles1.rule) here so the
# Tier-A rule attack and the LM→NTLM toggle phase always work, even on a host with
# no hashcat rules directory.  This dir is ALWAYS searched as a guaranteed final
# fallback (see find_rule / _find_rules_dir) — a user config that overrides
# _RULE_SEARCH_PATHS via default_rules_dirs replaces where *hashcat's* rules are
# found but can never hide crackbaby's own bundled rules.
_BUNDLED_RULES_DIR = os.path.join(_CRACKBABY_DIR, "rules")

_RULE_SEARCH_PATHS = [
    "/usr/share/hashcat/rules",
    "/opt/hashcat/rules",
    "/usr/local/share/hashcat/rules",
    os.path.expanduser("~/hashcat/rules"),
    os.path.expanduser("~/tools/hashcat/rules"),
    # NOTE: no CWD-relative "./rules" here — it made rule resolution depend on the
    # shell's working directory (e.g. silently picking up a sibling project's rules/).
    # crackbaby's own bundled rules are referenced by absolute path below instead.
    _BUNDLED_RULES_DIR,
]

# Known rulesets: filename → (tier, priority_step, use_loopback)
# Tier A: run against all wordlists pre-analysis (always admitted).
# Tier B: medium-weight; admitted when default_rule_depth >= "AB".
# Tier C: post-analysis ONLY by default; admitted to 200-band only when default_rule_depth == "ABC".
#         Always used for rule-based attacks against small targeted wordlists.
# Ordered within each tier by value/speed ratio (lighter/faster first).
#
# Steps are intentionally small (1–4) so even large rule sets stay within the
# 200–499 band without overflowing into the enterprise mask band (1000+).
_RULE_PRIORITY: dict = {
    # ── Tier A ────────────────────────────────────────────────────────────────
    "best66.rule":      ("A", 2, True),   #   66 rules  — primary Tier A ruleset
    "unix-ninja-leetspeak.rule": ("A", 1, True),   # 3.1K — superior leet; replaces leetspeak.rule
    "T0XlC-insert_00-99_1950-2050_toprules_0_F.rule": ("A", 2, True),  # 5.6K — internal year/num
    "T0XlC-insert_space_and_special_0_F.rule":        ("A", 2, True),  # space+special insertion
    "generated.rule":        ("A", 2, True),  # 14.3K — empirically highest-value mid-size ruleset
    "d3ad0ne.rule":          ("A", 3, True),  # 34.1K — comprehensive multi-op; proven on NTLM
    "rockyou-30000.rule":    ("A", 3, True),  # 30.0K — statistically validated on largest leaked set

    # ── Tier B ────────────────────────────────────────────────────────────────
    "T0XlC.rule":       ("B", 2, True),   #  4.1K — case manip + append/prepend combos
    "toggles3.rule":    ("B", 1, False),  #   690 — practical case-toggle; 4/5 too slow pre-analysis
    "combinator.rule":  ("B", 1, True),   #    51 — combinator rules

    # ── Tier C: post-analysis only (200-band admission requires default_rule_depth="ABC") ───
    "dive.rule":                 ("C", 4, True),  # 98.7K — pair with small wordlists only
    "generated2.rule":           ("C", 3, True),  # 55.3K — extended generated; use post-analysis
    "OneRuleToRuleThemAll.rule": ("C", 4, True),  # ~52K  — compiled community ruleset

    # ── Compatibility ─────────────────────────────────────────────────────────
    "leetspeak.rule":            ("B", 1, True),   #   17 — fallback if unix-ninja unavailable
    "Hob0Rules.rule":            ("B", 3, True),   # community enterprise-focused rule
    "InsidePro-HashManager.rule":  ("B", 1, True),  # legacy; superseded by generated
    "InsidePro-PasswordsPro.rule": ("B", 1, True),  # legacy; superseded by generated
    "toggles1.rule": ("B", 1, False),
    "toggles2.rule": ("B", 1, False),
    "toggles4.rule": ("B", 1, False),
    "toggles5.rule": ("B", 1, False),
}

_WORDLIST_SEARCH_PATHS = [
    "/usr/share/wordlists",
    "/opt/wordlists",
    os.path.expanduser("~/wordlists"),
    "./wordlists",
]


def find_rule(rules_dir: Optional[str], name: str) -> Optional[str]:
    candidates = []
    if rules_dir:
        candidates.append(os.path.join(rules_dir, name))
    candidates.extend(os.path.join(p, name) for p in _RULE_SEARCH_PATHS)
    # Guaranteed final fallback: crackbaby's own bundled critical rules, which a
    # default_rules_dirs config override must never be able to hide.
    bundled = os.path.join(_BUNDLED_RULES_DIR, name)
    if bundled not in candidates:
        candidates.append(bundled)
    for p in candidates:
        if os.path.exists(p):
            return os.path.abspath(p)
    return None


def find_wordlist(name: str) -> Optional[str]:
    for base in _WORDLIST_SEARCH_PATHS:
        p = os.path.join(base, name)
        if os.path.exists(p):
            return os.path.abspath(p)
    return None


def _find_rules_dir(rules_dir: Optional[str]) -> Optional[str]:
    """Return the first accessible rules directory."""
    if rules_dir and os.path.isdir(rules_dir):
        return rules_dir
    for p in _RULE_SEARCH_PATHS:
        if os.path.isdir(p):
            return p
    # Guaranteed final fallback: crackbaby's bundled rules dir.
    if os.path.isdir(_BUNDLED_RULES_DIR):
        return _BUNDLED_RULES_DIR
    return None


# ── Keyspace / line-count helpers ─────────────────────────────────────────────

_LINE_COUNT_CACHE: dict = {}


_EXACT_LIMIT      = 64 << 20   # 64 MB  — read fully for exact count
_SAMPLE_CHUNK     = 1  << 20   # 1 MB per sample position
_SAMPLE_POSITIONS = 5           # evenly-distributed positions across the file


def _count_file_lines(path: str) -> int:
    """
    Count (or estimate) lines in a wordlist file.

    Files ≤ 64 MB are read fully for an exact count (< 0.1 s on any modern disk).
    Larger files are estimated by sampling _SAMPLE_POSITIONS evenly-distributed
    1 MB windows across the file, averaging their newline density, then scaling to
    the full file size.  Sampling from the beginning only is deliberately avoided:
    files like rockyou2024 start with very short passwords (~4 bytes/line) but
    average ~16 bytes/line overall, causing a 3-4× overestimate with a
    beginning-only sample.  Distributed sampling keeps the error under ~2×.
    Cached by path.  Returns 0 if the file cannot be read.
    """
    if path in _LINE_COUNT_CACHE:
        return _LINE_COUNT_CACHE[path]
    try:
        size = os.path.getsize(path)
        if size == 0:
            _LINE_COUNT_CACHE[path] = 0
            return 0
        with open(path, "rb") as f:
            if size <= _EXACT_LIMIT:
                count = max(f.read().count(b"\n"), 1)
            else:
                stride = max(size // _SAMPLE_POSITIONS, _SAMPLE_CHUNK)
                total_nl   = 0
                total_read = 0
                for i in range(_SAMPLE_POSITIONS):
                    offset = i * stride
                    if offset >= size:
                        break
                    f.seek(offset)
                    chunk = f.read(_SAMPLE_CHUNK)
                    if chunk:
                        total_nl   += chunk.count(b"\n")
                        total_read += len(chunk)
                count = max(int(total_nl * size / total_read), 1) if total_read else 1
        _LINE_COUNT_CACHE[path] = count
    except OSError:
        _LINE_COUNT_CACHE[path] = 0
    return _LINE_COUNT_CACHE[path]


_MAX_LEN_CACHE: dict = {}   # path → max observed line length (for no_optimize decisions)


def _max_line_length_sample(path: str) -> int:
    """Sample a file to find the maximum line length.

    Small files (≤ EXACT_LIMIT) are read fully for an exact value.
    Larger files use the same 5-position distributed sampling as
    _count_file_lines() — 5 × 1 MB chunks spread evenly across the file.
    Returns 999 on any error (conservatively forces no_optimize=True).
    Cached by path.
    """
    if path in _MAX_LEN_CACHE:
        return _MAX_LEN_CACHE[path]
    try:
        size = os.path.getsize(path)
        if size == 0:
            _MAX_LEN_CACHE[path] = 0
            return 0
        max_len = 0
        with open(path, "rb") as f:
            if size <= _EXACT_LIMIT:
                for line in f:
                    max_len = max(max_len, len(line.rstrip(b"\r\n")))
            else:
                stride = max(size // _SAMPLE_POSITIONS, _SAMPLE_CHUNK)
                for i in range(_SAMPLE_POSITIONS):
                    offset = i * stride
                    if offset >= size:
                        break
                    f.seek(offset)
                    chunk = f.read(_SAMPLE_CHUNK)
                    for line in chunk.split(b"\n"):
                        max_len = max(max_len, len(line.rstrip(b"\r\n")))
        _MAX_LEN_CACHE[path] = max_len
    except OSError:
        _MAX_LEN_CACHE[path] = 999   # unknown — assume long, force pure kernel
    return _MAX_LEN_CACHE[path]


_OPT_MAX_LEN = 27   # NTLM optimized-kernel max password length (with -O)


def _no_opt_for_combo(wl1: str, wl2: str) -> bool:
    """Return True (no_optimize) when the max combined candidate length could exceed
    the optimized-kernel limit.  False → use -O for a 50-100× speed boost.
    Conservative: returns True on any file-read error.
    """
    return (_max_line_length_sample(wl1) + _max_line_length_sample(wl2)) > _OPT_MAX_LEN


def _resolve_no_opt(wl1: str, wl2: str, campaign: Campaign) -> bool:
    """no_optimize decision for TWO-wordlist phases (combinator, combo_rules).

    Returns False (use -O) unless campaign.long_passwords=True AND sampling
    shows max combined length > _OPT_MAX_LEN.  Default: always -O (fast).
    """
    if not getattr(campaign, "long_passwords", False):
        return False   # default: always optimized
    return _no_opt_for_combo(wl1, wl2)


def _resolve_single_wl_no_opt(wl: str, campaign: Campaign) -> bool:
    """no_optimize decision for SINGLE-wordlist phases (wordlist, rules).

    Returns False (use -O) unless campaign.long_passwords=True AND sampling
    shows max line length > _OPT_MAX_LEN.  Default: always -O (fast).
    """
    if not getattr(campaign, "long_passwords", False):
        return False   # default: always optimized
    return _max_line_length_sample(wl) > _OPT_MAX_LEN


def _count_rule_lines(path: str) -> int:
    """
    Count active rules in a .rule file (non-empty, non-comment lines). Cached.
    A rule comment starts with '#'. Returns 0 on error.
    """
    cache_key = f"\x00rules:{path}"   # distinct namespace from wordlist paths
    if cache_key in _LINE_COUNT_CACHE:
        return _LINE_COUNT_CACHE[cache_key]
    try:
        count = 0
        with open(path, errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    count += 1
        _LINE_COUNT_CACHE[cache_key] = max(count, 1)
    except OSError:
        _LINE_COUNT_CACHE[cache_key] = 0
    return _LINE_COUNT_CACHE[cache_key]


# ── Rule tier / admission helpers ─────────────────────────────────────────────

def _rule_tier(display_name: str) -> str:
    """Return "A", "B", "C", or "custom" for a rule filename."""
    entry = _RULE_PRIORITY.get(display_name)
    if entry:
        return entry[0]
    return "custom"


def _admit_rule(display_name: str, is_custom: bool, rule_depth: str) -> bool:
    """
    Return True if this rule should be included in the initial 200-band.

    Custom-dir rules are always admitted (the operator explicitly chose them;
    time-gating handles excess runtime).  Default-dir rules are tier-filtered:
      rule_depth="A"   → Tier A only
      rule_depth="AB"  → Tier A + B
      rule_depth="ABC" → Tier A + B + C
    Rules not listed in _RULE_PRIORITY are treated as custom-tier (admitted).
    """
    if is_custom:
        return True
    tier = _rule_tier(display_name)
    if tier == "custom":
        return True   # unknown rule in default dir — admit (operator added it)
    depth_tiers = {"A": {"A"}, "AB": {"A", "B"}, "ABC": {"A", "B", "C"}}
    return tier in depth_tiers.get(rule_depth, {"A"})


def _discover_rules(rules_dir: str) -> List[Tuple[str, str]]:
    """
    Collect all .rule files in rules_dir, recursing one level into subdirectories.
    Returns [(display_name, full_path)].
    display_name = "filename.rule" for top-level, "subdir/filename.rule" for subdir files.
    """
    results: List[Tuple[str, str]] = []
    try:
        entries = os.listdir(rules_dir)
    except OSError:
        return results
    for entry in sorted(entries):
        full = os.path.join(rules_dir, entry)
        if os.path.isfile(full) and entry.lower().endswith(".rule"):
            results.append((entry, os.path.abspath(full)))
        elif os.path.isdir(full):
            # one level deep
            try:
                for sub in sorted(os.listdir(full)):
                    sub_full = os.path.join(full, sub)
                    if os.path.isfile(sub_full) and sub.lower().endswith(".rule"):
                        results.append((f"{entry}/{sub}", os.path.abspath(sub_full)))
            except OSError:
                pass
    return results


def _make_rule_phase(wl_path: str, rule_path: str, priority: int,
                     campaign, loopback: bool = True) -> "Phase":
    """Build a wordlist+rule Phase for use by cmd_add (mirrors 200-band logic)."""
    args = ["-a", "0"]
    if loopback:
        args.append("--loopback")
    args += ["-r", rule_path, wl_path]
    p = Phase(
        id=_new_id(),
        name=f"Rules: {os.path.basename(wl_path)} + {os.path.basename(rule_path)}",
        type="rules",
        args=args,
        priority=priority,
        estimated_keyspace=_count_file_lines(wl_path) * _count_rule_lines(rule_path),
        notes=rule_path,
    )
    _time_gate(p, campaign, campaign.skip_threshold_hours)
    return p


# ── Mask keyspace helper ─────────────────────────────────────────────────────

def _hcmask_keyspace(hcmask_line: str,
                     charset: Optional["HashcatCharset"] = None) -> int:
    """Compute candidate count for an hcmask line.

    Handles both bare masks ('?u?l?l?l?l?d') and the inline charset-prefix
    format used in .hcmask files ('escaped_charset,,,,mask').  Correct charset
    size is derived from the HashcatCharset object when provided, falling back
    to counting the unescaped characters in the prefix string.
    """
    parts = hcmask_line.split(",")
    if len(parts) < 5:
        # No custom charset prefix — bare mask
        cs = {"1": charset.size} if charset else None
        return _mask_keyspace_simple(hcmask_line, cs)
    # Inline .hcmask format: charset1,charset2,charset3,charset4,mask
    mask = parts[-1]
    if charset:
        cs: Optional[dict] = {"1": charset.size}
    else:
        raw = parts[0].replace("??", "?")   # unescape literal ?
        cs  = {"1": len(raw)} if raw else None
    return _mask_keyspace_simple(mask, cs)


def _brute_ks(mask: str,
              charset: Optional["HashcatCharset"] = None) -> int:
    """Compute keyspace for a brute-force mask with an optional custom charset.

    Wrapper around `_mask_keyspace_simple` for use in `_BRUTE_MASKS` tuple
    definitions, keeping the keyspace expression next to the mask it describes.
    """
    cs = {"1": charset.size} if charset else None
    return _mask_keyspace_simple(mask, cs)


def _mask_keyspace_simple(mask: str, custom_charsets: Optional[dict] = None) -> int:
    """
    Compute keyspace for a hashcat mask string.
    Handles ?l ?u ?d ?s ?a and custom charsets ?1-?4.
    Pass custom_charsets={key: charset_string} to resolve ?1-?4
    (e.g. {"1": "!@#$%^&*-_+?"} → ?1 = 12 chars).
    Literal characters contribute 1 to the product.
    """
    _size = {'l': 26, 'u': 26, 'd': 10, 's': 33, 'a': 95}
    if custom_charsets:
        for k, v in custom_charsets.items():
            if isinstance(v, int):
                _size[str(k)] = v
            elif hasattr(v, "size"):        # HashcatCharset — use .size (logical count)
                _size[str(k)] = v.size
            else:
                _size[str(k)] = len(v)     # raw string fallback
    ks = 1
    i = 0
    while i < len(mask):
        if mask[i] == '?' and i + 1 < len(mask):
            ks *= _size.get(mask[i + 1], 1)
            i += 2
        else:
            i += 1   # literal char
    return ks


# ── Python-native keyspace computation for any phase type ────────────────────

def _compute_keyspace_native(phase: "Phase") -> Optional[int]:
    """
    Compute estimated_keyspace for a phase entirely in Python — no hashcat
    subprocess, no GPU init.  Uses cached binary line counts.

    Returns None for phase types that can't be computed this way (mask/brute
    phases already have keyspace set at init from constants) or if required
    files are missing.
    """
    args = phase.args
    try:
        if phase.type in ("wordlist", "lm_toggle"):
            # args: [..., wl_path]  — wordlist is the last arg
            wl = args[-1]
            return _count_file_lines(wl) if os.path.exists(wl) else None

        elif phase.type == "rules":
            # args: [-a, 0, [--loopback,] -r, rule_path, wl_path]
            r_idx = args.index("-r")
            rule_path = args[r_idx + 1]
            wl_path   = args[r_idx + 2]
            if os.path.exists(rule_path) and os.path.exists(wl_path):
                return _count_file_lines(wl_path) * _count_rule_lines(rule_path)

        elif phase.type == "hybrid":
            # -a 6: [..., wl, suffix_mask]   keyspace = wl_lines × mask_ks
            # -a 7: [..., prefix_mask, wl]   keyspace = mask_ks × wl_lines
            # Optional prefix: -1 CHARSET (placed before -a; a_idx+2/+3 still work)
            custom_charsets: dict = {}
            for ci in range(len(args) - 1):
                if args[ci] in ("-1", "-2", "-3", "-4"):
                    custom_charsets[args[ci][1]] = args[ci + 1]
            a_idx = args.index("-a")
            mode  = args[a_idx + 1]
            if mode == "6":
                wl   = args[a_idx + 2]
                mask = args[a_idx + 3]
                if os.path.exists(wl):
                    return _count_file_lines(wl) * _mask_keyspace_simple(mask, custom_charsets or None)
            elif mode == "7":
                mask = args[a_idx + 2]
                wl   = args[a_idx + 3]
                if os.path.exists(wl):
                    return _mask_keyspace_simple(mask, custom_charsets or None) * _count_file_lines(wl)

        elif phase.type == "combinator":
            # args: [-a, 1, wl1_path, wl2_path]
            a_idx = args.index("-a")
            wl1 = args[a_idx + 2]
            wl2 = args[a_idx + 3]
            if os.path.exists(wl1) and os.path.exists(wl2):
                return _count_file_lines(wl1) * _count_file_lines(wl2)

        elif phase.type == "combo_rules":
            # wordlists stored in combo_wl1 / combo_wl2; rule path in args after -r
            wl1 = phase.combo_wl1 or ""
            wl2 = phase.combo_wl2 or ""
            rule_path = ""
            for ci in range(len(args) - 1):
                if args[ci] == "-r":
                    rule_path = args[ci + 1]
                    break
            if (wl1 and wl2 and rule_path
                    and os.path.exists(wl1) and os.path.exists(wl2)
                    and os.path.exists(rule_path)):
                return (_count_file_lines(wl1)
                        * _count_file_lines(wl2)
                        * _count_rule_lines(rule_path))

    except (ValueError, IndexError, OSError):
        pass
    return None


# ── Custom charset abstraction ───────────────────────────────────────────────


class HashcatCharset:
    """Encapsulates a hashcat custom character set (slots -1 through -4).

    Single source of truth for: the raw characters, the hashcat-escaped value,
    the size (for keyspace math), and both output formats (CLI args and .hcmask
    inline prefix).  All callers use the class API — no scattered string literals.

    hashcat escaping rule: '?' must be written as '??' inside any charset value
    because '?' is hashcat's escape prefix (e.g. '?l' = lowercase charset).
    """

    def __init__(self, chars: str, slot: int = 1) -> None:
        if not 1 <= slot <= 4:
            raise ValueError(f"Charset slot must be 1-4, got {slot}")
        self._chars = chars   # raw characters — no hashcat escaping
        self.slot   = slot

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def size(self) -> int:
        """Number of distinct characters (used for keyspace calculations)."""
        return len(self._chars)

    @property
    def escaped(self) -> str:
        """Charset value with '?' escaped as '??' per hashcat syntax rules."""
        return self._chars.replace("?", "??")

    @property
    def flag(self) -> str:
        """The hashcat flag string for this slot: '-1', '-2', etc."""
        return f"-{self.slot}"

    @property
    def placeholder(self) -> str:
        """The mask placeholder for this slot: '?1', '?2', etc."""
        return f"?{self.slot}"

    # ── Output format helpers ───────────────────────────────────────────────

    def cli_args(self) -> list:
        """Subprocess args for command-line usage: ['-1', 'escaped_value'].

        Use when constructing Phase.args for -a 3 / -a 6 / -a 7 attacks.
        No shell quoting needed — subprocess.Popen passes args directly to
        the OS without shell interpretation.
        """
        return [self.flag, self.escaped]

    def hcmask_prefix(self) -> str:
        """Inline prefix for .hcmask file lines: 'escaped_value,,,,'.

        hashcat's mask file format embeds charsets as comma-separated fields
        before the mask pattern: charset1,charset2,charset3,charset4,mask.
        Empty slots are represented by adjacent commas.
        """
        slots_before = "," * (self.slot - 1)    # empty slots before this one
        empty_after  = "," * (4 - self.slot)    # empty slots after this one
        return f"{slots_before}{self.escaped}{empty_after},"

    def __repr__(self) -> str:
        return f"HashcatCharset({self._chars!r}, slot={self.slot})"


# Pre-defined enterprise charsets used across mask, brute, and hybrid phases.
SPECIAL_8  = HashcatCharset("!@#$%^&*")       # 8 most common enterprise specials
SPECIAL_12 = HashcatCharset("!@#$%^&*-_+?")  # 12-char full enterprise policy set


# ── Built-in enterprise masks ─────────────────────────────────────────────────
#
# Each entry: (hcmask_line, description, approx_keyspace)
# hcmask_line format: "[cs1],[cs2],[cs3],[cs4],[mask]" or just "[mask]"
# Entries with custom charsets use HashcatCharset.hcmask_prefix() to generate
# the inline format required by hashcat's .hcmask file reader.
# ?l=lower(26) ?u=upper(26) ?d=digit(10) ?s=special(33) ?a=all(95)

_ENTERPRISE_MASKS: List[Tuple[str, str, int]] = [
    # ── All-digit PINs ──
    # 4/5/6-digit removed — trivial length, covered by wordlist+rules passes.
    (m := "?d?d?d?d?d?d?d",         "7-digit",                     _hcmask_keyspace(m)),
    (m := "?d?d?d?d?d?d?d?d",       "8-digit (DOB/date)",          _hcmask_keyspace(m)),
    (m := "?d?d?d?d?d?d?d?d?d?d",   "10-digit (phone)",            _hcmask_keyspace(m)),

    # ── Pure lowercase ──
    # 6-lower removed (length ≤ 6, trivial). 11-lower removed (10.4 h, unrealistic).
    (m := "?l?l?l?l?l?l?l",         "7-lower",                     _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?l?l",       "8-lower",                     _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?l?l?l",     "9-lower",                     _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?l?l?l?l",   "10-lower",                    _hcmask_keyspace(m)),

    # ── Capitalized word (Xxxxxxx) ──
    # 6-Cap removed (length ≤ 6, trivial).
    (m := "?u?l?l?l?l?l?l",         f"7-Cap  [{m}]",                  _hcmask_keyspace(m)),
    (m := "?u?l?l?l?l?l?l?l",       f"8-Cap  [{m}]",                  _hcmask_keyspace(m)),
    (m := "?u?l?l?l?l?l?l?l?l",     f"9-Cap  [{m}]",                  _hcmask_keyspace(m)),

    # ── Word + year (Word2024) — max 10 chars ──
    (m := "?u?l?l?l?l?d?d?d?d",     f"5-Cap+year  [{m}]",             _hcmask_keyspace(m)),
    (m := "?u?l?l?l?l?l?d?d?d?d",   f"6-Cap+year (Summer2024)  [{m}]",   _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?d?d?d?d",   f"6-lower+year  [{m}]",           _hcmask_keyspace(m)),

    # ── Word + 1-3 digits ──
    # 6-Cap+1/2/3d removed (base word ≤ 6, trivial total keyspace; wordlist+rules covers these).
    (m := "?u?l?l?l?l?l?l?d",       f"7-Cap+1d (Welcome1)  [{m}]",    _hcmask_keyspace(m)),
    (m := "?u?l?l?l?l?l?l?l?d",     f"8-Cap+1d (Password1)  [{m}]",   _hcmask_keyspace(m)),
    (m := "?u?l?l?l?l?l?l?d?d",     f"7-Cap+2d (Welcome12)  [{m}]",   _hcmask_keyspace(m)),
    (m := "?u?l?l?l?l?l?l?l?d?d",   f"8-Cap+2d (Password12)  [{m}]",  _hcmask_keyspace(m)),
    (m := "?u?l?l?l?l?l?l?d?d?d",   f"7-Cap+3d (Welcome123)  [{m}]",  _hcmask_keyspace(m)),
    # 8-Cap+3d removed (11 chars > 10 limit)
    (m := "?l?l?l?l?l?l?l?d",       "7-lower+1d",                  _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?l?l?d",     "8-lower+1d",                  _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?l?d?d",     "7-lower+2d",                  _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?l?l?d?d",   "8-lower+2d",                  _hcmask_keyspace(m)),
    (m := "?l?l?l?l?l?l?l?d?d?d",   "7-lower+3d",                  _hcmask_keyspace(m)),
    # 8-lower+3d removed (11 chars > 10 limit)

    # ── Enterprise pattern: Word + special (Password!, Welcome!) — ≤10 chars ──
    # SPECIAL_8 (8-char charset) — .hcmask inline format: charset,,,,mask
    (m := SPECIAL_8.hcmask_prefix() + "?u?l?l?l?l?l?l?d?1",         f"7-Cap+1d+special  [{m.split(',')[-1]}]",          _hcmask_keyspace(m, SPECIAL_8)),
    (m := SPECIAL_8.hcmask_prefix() + "?u?l?l?l?l?l?l?l?d?1",       f"8-Cap+1d+special  [{m.split(',')[-1]}]",          _hcmask_keyspace(m, SPECIAL_8)),
    (m := SPECIAL_8.hcmask_prefix() + "?u?l?l?l?l?l?l?d?d?1",       f"7-Cap+2d+special  [{m.split(',')[-1]}]",          _hcmask_keyspace(m, SPECIAL_8)),
    # 8-Cap+2d+special removed (11 chars), 7-Cap+year+special removed (12 chars)
    # 8-Cap+year+special removed (13 chars)
    (m := SPECIAL_8.hcmask_prefix() + "?l?l?l?l?l?l?l?l?1",         f"8-lower+special  [{m.split(',')[-1]}]",           _hcmask_keyspace(m, SPECIAL_8)),
    (m := SPECIAL_8.hcmask_prefix() + "?l?l?l?l?l?l?l?l?d?1",       f"8-lower+1d+special  [{m.split(',')[-1]}]",        _hcmask_keyspace(m, SPECIAL_8)),

    # ── Mixed case + digits — 10 chars max ──
    (m := "?u?l?l?l?l?l?l?l?l?d",   f"9-Cap+1d  [{m}]",             _hcmask_keyspace(m)),
    # 9-Cap+2d removed (11 chars). 12-char targets section removed.

    # ── Word + special only (Password!, Welcome!, password!) ──
    # SPECIAL_12 (12-char charset) — .hcmask inline format: charset,,,,mask
    # Replaces ?s (33 chars): 7.5× faster on 2-special combos (12²=144 vs 33²=1089).
    # 6-Cap+special and 6-Cap+2special removed (base word ≤ 6).
    (m := SPECIAL_12.hcmask_prefix() + "?u?l?l?l?l?l?l?1",     f"7-Cap+special (Welcome!)   [{m.split(',')[-1]}]",  _hcmask_keyspace(m, SPECIAL_12)),
    (m := SPECIAL_12.hcmask_prefix() + "?u?l?l?l?l?l?l?l?1",   f"8-Cap+special (Password!)  [{m.split(',')[-1]}]",  _hcmask_keyspace(m, SPECIAL_12)),
    (m := SPECIAL_12.hcmask_prefix() + "?u?l?l?l?l?l?l?1?1",   f"7-Cap+2special (Welcome!!) [{m.split(',')[-1]}]",  _hcmask_keyspace(m, SPECIAL_12)),
    (m := SPECIAL_12.hcmask_prefix() + "?u?l?l?l?l?l?l?l?1?1", f"8-Cap+2special (Password!!)[{m.split(',')[-1]}]",  _hcmask_keyspace(m, SPECIAL_12)),
    (m := SPECIAL_12.hcmask_prefix() + "?l?l?l?l?l?l?l?1",     f"7-lower+special  [{m.split(',')[-1]}]",            _hcmask_keyspace(m, SPECIAL_12)),
    (m := SPECIAL_12.hcmask_prefix() + "?l?l?l?l?l?l?l?l?1",   f"8-lower+special  [{m.split(',')[-1]}]",            _hcmask_keyspace(m, SPECIAL_12)),
    (m := SPECIAL_12.hcmask_prefix() + "?l?l?l?l?l?l?l?1?1",   f"7-lower+2special  [{m.split(',')[-1]}]",           _hcmask_keyspace(m, SPECIAL_12)),
    (m := SPECIAL_12.hcmask_prefix() + "?l?l?l?l?l?l?l?l?1?1", f"8-lower+2special  [{m.split(',')[-1]}]",           _hcmask_keyspace(m, SPECIAL_12)),
]


# ── Brute-force escalation masks (6–10 chars, sorted ascending by keyspace) ──
# Crackbaby: limited to 6-10 chars with basic charsets only.
# All-charset masks (6-8 chars) + 9-lower+1d (10 total).

_BRUTE_MASKS: List[Tuple[Optional["HashcatCharset"], str, str, int]] = [
    # (charset_or_None, mask_pattern, description, keyspace)
    # charset=None → no custom charset; the mask uses only built-in placeholders.
    # Phase construction uses charset.cli_args() + [mask] for the -1 flag format.
    # Keyspace is derived from the mask via _brute_ks — never hardcoded by hand.
    # Crackbaby: limited to 6–10 chars; basic charsets only (?l, ?a, ?d).

    # ── All-charset exhaustive (6-8 chars) ────────────────────────────────────
    (None,       "?a?a?a?a?a?a",                 "6-any",           _brute_ks("?a?a?a?a?a?a")),
    (None,       "?a?a?a?a?a?a?a",               "7-any",           _brute_ks("?a?a?a?a?a?a?a")),
    (None,       "?a?a?a?a?a?a?a?a",             "8-any",           _brute_ks("?a?a?a?a?a?a?a?a")),

    # ── 9-char base + 1 digit (10 total) ─────────────────────────────────────
    (None,       "?l?l?l?l?l?l?l?l?l?d",         "9-lower+1d",      _brute_ks("?l?l?l?l?l?l?l?l?l?d")),
]
_YEAR_SUFFIXES = [str(y) for y in range(2010, 2027)]
_SPECIAL_SUFFIXES = ["!", "!!", "!@", "@", "#", "1!", "2!", "1!!", "123!", "1234!",
                     "@1", "$1", "#1", "0!", "00!", "000!", "123!!", "1234!!",
                     "12345!", "12345!!", "!1", "!2", "!3"]
# Year + common special chars: "2024!", "2025!!", "2024@", etc.
# These are not reachable by pure hybrid (word+?d?d?d?d+?1) without a combinator stage.
# 8 years × 10 symbols = 80 entries covering all enterprise policy specials.
_YEAR_SPECIAL_SUFFIXES = [
    f"{y}{s}"
    for y in range(2019, 2027)
    for s in ("!", "!!", "@", "#", "$", "*", "?", "-", "_", "!@#")
]
_SEASON_WORDS = [
    "spring", "summer", "fall", "winter", "autumn",
    "Spring", "Summer", "Fall", "Winter", "Autumn",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]


# ── Public builders ───────────────────────────────────────────────────────────

def _predict_combo_strategy(phase: Phase, campaign: Campaign) -> str:
    """Predict which dispatch strategy a combo_rules phase will use, for display
    and ETA before the phase runs.

    Mirrors the decision in crackbaby._run_combo_rules_phase: convert the smaller
    wordlist side to GPU rules when it has <= max_rule_convert_words lines
    ("rule_convert", fully on-GPU); otherwise fall back to the combinator.bin
    pipe ("combinator_bin"). The actual strategy is re-recorded at dispatch time.

    Returns a value compatible with speed._phase_speed_key (which compares against
    "rule_convert"): either "rule_convert" or "combinator_bin".
    """
    wl1, wl2 = phase.combo_wl1, phase.combo_wl2
    if not wl1 or not wl2:
        return "rule_convert"
    try:
        small = wl1 if os.path.getsize(wl1) <= os.path.getsize(wl2) else wl2
        small_lines = _count_file_lines(small)
    except OSError:
        return "rule_convert"
    limit = int(getattr(campaign, "max_rule_convert_words", 50_000))
    return "rule_convert" if 0 < small_lines <= limit else "combinator_bin"


def build_initial_phases(campaign: Campaign) -> List[Phase]:
    """Build the full initial attack pipeline for a campaign.

    The caller is responsible for calling reset_counter() BEFORE invoking this
    function to set the correct starting ID:
      • cmd_init:    reset_counter(0)       → IDs start at P0001
      • cmd_rebuild: reset_counter(max_n)   → IDs continue past existing phases
    The caller should set
    the counter offset.  NOT resetting here prevents rebuild from re-using IDs
    that already belong to completed/failed phases.
    """
    # Determine phase counter offset so auto-generated phases come later
    phases: List[Phase] = []

    custom_rules_dir = campaign.custom_rules_dir

    # Resolve available wordlists
    wordlists = [w for w in campaign.wordlists if os.path.exists(w)]
    if not wordlists:
        print("  [WARNING] No wordlists found — wordlist phases will be skipped")

    # ── 50: LM hash cracking (if lm_hash_file provided) ──────────────────
    if campaign.lm_hash_file and os.path.exists(campaign.lm_hash_file):
        lm_count = sum(1 for _ in open(campaign.lm_hash_file) if _.strip())
        lm_cracked_path = os.path.join(campaign.wordlists_dir, "lm_cracked.txt")

        # Phase 1: Brute-force all 7-char halves (LM is case-insensitive, ?a covers all)
        phases.append(Phase(
            id=_new_id(),
            name="LM brute force (7-char halves, mode 3000)",
            type="lm_brute",
            args=["-a", "3", "--increment", "--increment-min", "1", "?a?a?a?a?a?a?a"],
            priority=50,
            estimated_keyspace=sum(95**i for i in range(1, 8)),
            notes=campaign.lm_hash_file,
        ))
        print(f"  LM hashes:    {lm_count} hashes → LM brute phase added at priority 50")

        # Phase 2: Feed LM plaintexts back through NTLM with toggle rules
        toggle_path = find_rule(custom_rules_dir, "toggles1.rule")
        if toggle_path:
            phases.append(Phase(
                id=_new_id(),
                name="LM plaintexts → NTLM via toggle rules",
                type="lm_toggle",
                args=["-a", "0", "--loopback", "-r", toggle_path, lm_cracked_path],
                priority=60,
                notes=lm_cracked_path,
            ))
            print(f"  LM toggle:    NTLM recovery via toggles1 → priority 60")
        else:
            print("  [WARNING] toggles1.rule not found — LM toggle phase skipped")
    elif campaign.lm_hash_file:
        print(f"  [WARNING] LM hash file not found: {campaign.lm_hash_file}")

    # ── 95: Org-targeted wordlist ─────────────────────────────────────────────
    # Generate from org_name / org_name_short / org_location (if set).
    # Runs before the general wordlists so org-specific hits surface immediately.
    org_wl = _write_org_wordlist(campaign)
    if org_wl:
        p = Phase(
            id=_new_id(),
            name="Org: org_words (straight)",
            type="wordlist",
            args=["-a", "0", org_wl],
            priority=95,
            estimated_keyspace=_count_file_lines(org_wl),
            notes=org_wl,
            no_optimize=_resolve_single_wl_no_opt(org_wl, campaign),
        )
        _time_gate(p, campaign, campaign.skip_threshold_hours)
        phases.append(p)
        # Prepend to wordlists so org_words gets first slot in every rule phase too
        wordlists = [org_wl] + wordlists

    # ── 200: Wordlist + rules (dual-source discovery) ─────────────────────
    # custom_rules_dir: user's own rules — ALL admitted, no tier filter.
    # default_rule_depth: controls tier admission for hashcat's bundled rules only.
    default_rule_depth = getattr(campaign, "default_rule_depth", "A")

    # Collect rules from the custom dir — no tier filter; operator explicitly chose these.
    custom_rules: dict = {}   # display_name → full_path
    if custom_rules_dir:
        for dname, fpath in _discover_rules(custom_rules_dir):
            custom_rules[dname] = fpath

    # Collect rules from the auto-discovered default dir — tier-filtered by default_rule_depth.
    # Skipped entirely when default_rule_depth="none" (use only --custom-rules-dir).
    default_rules: dict = {}  # display_name → full_path
    if default_rule_depth != "none":
        found_default_dir = _find_rules_dir(None)   # None → skip custom, find default
        if found_default_dir:
            for dname, fpath in _discover_rules(found_default_dir):
                if dname not in custom_rules:   # custom wins on collision
                    default_rules[dname] = fpath
    else:
        found_default_dir = None

    # Build ordered rule list: [(display_name, full_path, step, loopback)]
    # Priority order: known rules per _RULE_PRIORITY, then unknown custom, then unknown default.
    ordered_rules: list = []
    seen: set = set()   # all known-rule names handled (admitted OR explicitly excluded)

    for name, (tier, step, loopback) in _RULE_PRIORITY.items():
        if name in custom_rules:
            seen.add(name)
            if _admit_rule(name, True, default_rule_depth):
                ordered_rules.append((name, custom_rules[name], step, loopback))
        elif name in default_rules:
            seen.add(name)   # mark seen even if excluded by tier — prevents unknown fallthrough
            if _admit_rule(name, False, default_rule_depth):
                ordered_rules.append((name, default_rules[name], step, loopback))

    for name in sorted(set(custom_rules) - seen):
        ordered_rules.append((name, custom_rules[name], 1, True))
        seen.add(name)

    for name in sorted(set(default_rules) - seen):
        ordered_rules.append((name, default_rules[name], 1, True))

    # ── Init-time rules summary ────────────────────────────────────────────
    all_rule_names = set(custom_rules) | set(default_rules)
    known_found  = [n for n in _RULE_PRIORITY if n in all_rule_names]
    known_miss   = [n for n in _RULE_PRIORITY if n not in all_rule_names]
    c3_excluded  = [n for n in _RULE_PRIORITY
                    if n in default_rules and not _admit_rule(n, False, default_rule_depth)]
    custom_unknown = sorted(set(custom_rules) - set(_RULE_PRIORITY))
    default_unknown = sorted(set(default_rules) - set(_RULE_PRIORITY))

    if custom_rules_dir:
        print(f"  Custom rules: {custom_rules_dir}  ({len(custom_rules)} files, always admitted)")
    if found_default_dir and found_default_dir != custom_rules_dir:
        print(f"  Default rules: {found_default_dir}  ({len(default_rules)} files, depth={default_rule_depth})")
    if not custom_rules_dir and not found_default_dir:
        print("  [WARNING] No rules directory found — rule phases skipped")
        print(f"  Searched: {', '.join(_RULE_SEARCH_PATHS)}")
    if known_found:
        print(f"  Rules matched: {len(known_found)} known"
              + (f" + {len(custom_unknown + default_unknown)} unknown" if custom_unknown or default_unknown else ""))
    if c3_excluded:
        print(f"  Tier C excluded (default_rule_depth={default_rule_depth}): {', '.join(c3_excluded)}"
              f" — use --default-rule-depth ABC to include pre-analysis")
    if known_miss:
        absent_important = [n for n in known_miss if _RULE_PRIORITY[n][0] == "A"]
        if absent_important:
            print(f"  Tier A absent: {', '.join(absent_important)}")

    # ── 100: Straight wordlist ─────────────────────────────────────────────
    # If any rules are available, every wordlist will be amplified by those
    # rules in the 200-band (including best66 which alone covers most of what
    # a bare wordlist pass would find).  A plain -a 0 pass without rules runs
    # the same candidates at lower coverage and clogs the queue — skip it.
    # When NO rules are found at all, keep the bare pass as the only option.
    _has_rules = bool(ordered_rules)
    if _has_rules:
        print("  Straight wordlist phases skipped — rules available "
              f"({', '.join(n for n, *_ in ordered_rules[:3])}"
              + (" …" if len(ordered_rules) > 3 else "") + ")")
    else:
        print("  No rules found — keeping straight wordlist phases")
    priority = 100
    for wl in wordlists:
        if wl == org_wl:
            continue   # already added at 95
        if _has_rules:
            continue   # rules 200-band covers this wordlist with amplification
        p = Phase(
            id=_new_id(),
            name=f"Wordlist: {os.path.basename(wl)}",
            type="wordlist",
            args=["-a", "0", wl],
            priority=priority,
            estimated_keyspace=_count_file_lines(wl),
            notes=wl,
            no_optimize=_resolve_single_wl_no_opt(wl, campaign),
        )
        _time_gate(p, campaign, campaign.skip_threshold_hours)
        phases.append(p)
        priority += 5

    priority = 200
    for rule_display, rule_path, step, loopback in ordered_rules:
        rule_lines = _count_rule_lines(rule_path)
        for wl in wordlists:
            args = ["-a", "0"]
            if loopback:
                args.append("--loopback")
            args += ["-r", rule_path, wl]
            p = Phase(
                id=_new_id(),
                name=f"Rules: {os.path.basename(wl)} + {rule_display}",
                type="rules",
                args=args,
                priority=priority,
                estimated_keyspace=_count_file_lines(wl) * rule_lines,
                notes=rule_path,
                no_optimize=_resolve_single_wl_no_opt(wl, campaign),
            )
            _time_gate(p, campaign, campaign.skip_threshold_hours)
            phases.append(p)
        priority += step

    # ── 1000: Enterprise masks (fast batch + dynamic tiering) ───────────────
    # All enterprise masks run in the 1000-band (time-gate skips any that are too slow).
    _ent_limit  = campaign.skip_threshold_hours or 6.0
    _ent_speed  = _phase_speed_ghs("brute", campaign)   # masks run at brute-force speed

    priority = 1000
    if _ENTERPRISE_MASKS:
        mask_file = _write_enterprise_mask_file(campaign.masks_dir, _ent_speed, _ent_limit)
        p = Phase(
            id=_new_id(),
            name="Enterprise masks (built-in patterns)",
            type="mask",
            args=["-a", "3", mask_file],
            priority=priority,
            estimated_keyspace=sum(ks for _, _, ks in _ENTERPRISE_MASKS),
            notes=mask_file,
        )
        # No _time_gate here — the batch already contains only fast masks.
        phases.append(p)

    # ── 1200: Hybrid attacks (wordlist + mask / mask + wordlist) ───────────
    # Suffix masks use ?1 (12-char enterprise charset) instead of ?s (33 chars)
    # for 7.5× faster coverage on special-char combos while staying relevant.
    # The -1 CHARSET arg is prepended BEFORE -a so a_idx+2/a_idx+3 indexing
    # in _compute_keyspace_native stays correct.
    _HYBRID_SUFFIX_MASKS = [
        # Digits only (no custom charset needed)
        "?d",               # summer1, admin1
        "?d?d",             # summer12, pass99
        "?d?d?d",           # summer123
        "?d?d?d?d",         # summer2024, pass1234
        # Enterprise specials via ?1 = !@#$%^&*-_+? (12 chars; ?? in charset arg)
        "?1",               # password!  (12 combos per word)
        "?1?1",             # password!! (144 combos per word)
        "?d?1",             # summer1!   (120 combos per word)
        "?d?d?1",           # welcome12! (1,200 combos per word)
        "?d?d?d?d?1",       # password2024!  (120,000 combos per word)
        "?d?d?d?d?1?1",     # password2024!! (1,440,000 combos per word) — NEW
    ]
    _cs = {"1": SPECIAL_12.size}   # int → correct count of 12 for keyspace math
    priority = 1200
    for wl in wordlists:
        wl_base = os.path.basename(wl)
        wl_lines = _count_file_lines(wl)
        for suffix_mask in _HYBRID_SUFFIX_MASKS:
            uses_cs = SPECIAL_12.placeholder in suffix_mask
            if uses_cs:
                phase_args = SPECIAL_12.cli_args() + ["-a", "6", wl, suffix_mask]
            else:
                phase_args = ["-a", "6", wl, suffix_mask]
            p = Phase(
                id=_new_id(),
                name=f"Hybrid: {wl_base} + {suffix_mask}",
                type="hybrid",
                args=phase_args,
                priority=priority,
                estimated_keyspace=wl_lines * _mask_keyspace_simple(suffix_mask, _cs if uses_cs else None),
            )
            _time_gate(p, campaign, campaign.skip_threshold_hours)
            phases.append(p)
            priority += 2
        # Symbol-prepend: !Admin, @Security, #Password (SPECIAL_12.size combos × wl_lines)
        p = Phase(
            id=_new_id(),
            name=f"Hybrid: ?1 + {wl_base}",
            type="hybrid",
            args=SPECIAL_12.cli_args() + ["-a", "7", SPECIAL_12.placeholder, wl],
            priority=priority,
            estimated_keyspace=SPECIAL_12.size * wl_lines,
        )
        _time_gate(p, campaign, campaign.skip_threshold_hours)
        phases.append(p)
        priority += 2
        # Prepend year: 2024password, 2023welcome
        p = Phase(
            id=_new_id(),
            name=f"Hybrid: ?d?d?d?d + {wl_base}",
            type="hybrid",
            args=["-a", "7", "?d?d?d?d", wl],
            priority=priority,
            estimated_keyspace=10_000 * wl_lines,
        )
        _time_gate(p, campaign, campaign.skip_threshold_hours)
        phases.append(p)
        priority += 2

    # Combinator: wordlist × year/number suffixes — continues from hybrid (no reset)
    # priority is now at 1200 + (n_suffix_masks+1)*2*n_wordlists
    suffix_file = _write_suffix_wordlist(campaign.wordlists_dir)
    season_file = _write_season_wordlist(campaign.wordlists_dir)
    suffix_lines = _count_file_lines(suffix_file)
    season_lines = _count_file_lines(season_file)
    for wl in wordlists:
        wl_lines = _count_file_lines(wl)
        p = Phase(
            id=_new_id(),
            name=f"Combinator: {os.path.basename(wl)} × years/nums",
            type="combinator",
            args=["-a", "1", wl, suffix_file],
            priority=priority,
            estimated_keyspace=wl_lines * suffix_lines,
            no_optimize=_resolve_no_opt(wl, suffix_file, campaign),
        )
        _time_gate(p, campaign, campaign.skip_threshold_hours)
        phases.append(p)
        priority += 5
    p = Phase(
        id=_new_id(),
        name="Combinator: seasons × years",
        type="combinator",
        args=["-a", "1", season_file, suffix_file],
        priority=priority,
        estimated_keyspace=season_lines * suffix_lines,
        no_optimize=_resolve_no_opt(season_file, suffix_file, campaign),
    )
    _time_gate(p, campaign, campaign.skip_threshold_hours)
    phases.append(p)
    priority += 5

    # ── Wordlist × wordlist (auto-threshold pairs) ─────────────────────────
    # For each ordered pair of user-provided wordlists, generate a combinator
    # phase when lines(wl1) × lines(wl2) ≤ max_combinator_pairs_ks.
    # Both orderings are independent (A×B → "passwordadmin"; B×A → "adminpassword").
    # Self-pairs (same file) are skipped.  Large pairs are skipped and reported.
    _combo_ks_limit = getattr(campaign, "max_combinator_pairs_ks", 500_000_000)
    _wl_line_cache = {wl: _count_file_lines(wl) for wl in wordlists}
    _skipped_wl_pairs: List[str] = []

    for _i, _wl1 in enumerate(wordlists):
        for _j, _wl2 in enumerate(wordlists):
            if _i == _j:
                continue   # no self-pairs
            _ks = _wl_line_cache[_wl1] * _wl_line_cache[_wl2]
            _b1, _b2 = os.path.basename(_wl1), os.path.basename(_wl2)
            if _ks > _combo_ks_limit:
                _skipped_wl_pairs.append(f"{_b1}×{_b2} ({_fmt_keyspace(_ks)})")
                continue
            _p = Phase(
                id=_new_id(),
                name=f"Combinator: {_b1} × {_b2}",
                type="combinator",
                args=["-a", "1", _wl1, _wl2],
                priority=priority,
                estimated_keyspace=_ks,
                no_optimize=_resolve_no_opt(_wl1, _wl2, campaign),
            )
            _time_gate(_p, campaign, campaign.skip_threshold_hours)
            phases.append(_p)
            priority += 5

    if _skipped_wl_pairs:
        print(f"  WL×WL pairs skipped (over {_fmt_keyspace(_combo_ks_limit)} threshold): "
              + ", ".join(_skipped_wl_pairs[:6])
              + (" …" if len(_skipped_wl_pairs) > 6 else ""))

    # ── Combinator × best66 ───────────────────────────────────────────────
    # Same ordered pairs as plain combinator, with best66 applied via generator pipe.
    # Generator: hashcat -a 1 wl1 wl2 --stdout --quiet  →  produces wl1×wl2 candidates
    # Cracker:   hashcat -a 0 --stdin -r best66.rule     →  applies 66 rules to each
    # Total keyspace: wl1_lines × wl2_lines × n_rules
    # Wordlist paths stored in combo_wl1/combo_wl2; Python feeder generates candidates.
    _combo_rule_path = find_rule(campaign.custom_rules_dir, "best66.rule")
    if not _combo_rule_path:
        print("  [INFO] Combo+rules phases skipped: best66.rule not found")
    else:
        _n_rules   = _count_rule_lines(_combo_rule_path)
        _rule_name = os.path.basename(_combo_rule_path)
        _combo_rules_added = 0
        _combo_rules_skipped: List[str] = []
        for _i, _wl1 in enumerate(wordlists):
            for _j, _wl2 in enumerate(wordlists):
                if _i == _j:
                    continue
                _ks_pairs = _wl_line_cache[_wl1] * _wl_line_cache[_wl2]
                _b1, _b2 = os.path.basename(_wl1), os.path.basename(_wl2)
                if _ks_pairs > _combo_ks_limit:
                    _combo_rules_skipped.append(
                        f"{_b1}×{_b2} ({_fmt_keyspace(_ks_pairs)})")
                    continue   # same pair filter as plain combinator above
                _ks = _ks_pairs * _n_rules
                _p = Phase(
                    id=_new_id(),
                    name=f"Combo+rules: {_b1} × {_b2} | {_rule_name}",
                    type="combo_rules",
                    args=["-a", "0", "-r", _combo_rule_path],
                    combo_wl1=_wl1,
                    combo_wl2=_wl2,
                    priority=priority,
                    estimated_keyspace=_ks,
                    notes=f"combo: {_b1}×{_b2}  rule: {_rule_name}  ({_n_rules} rules)",
                    no_optimize=_resolve_no_opt(_wl1, _wl2, campaign),
                )
                # Predicted feed/strategy (visible + drives ETA); dispatch records actual on run.
                _p.combo_strategy = _predict_combo_strategy(_p, campaign)
                _time_gate(_p, campaign, campaign.skip_threshold_hours)
                phases.append(_p)
                priority += 5
                _combo_rules_added += 1
        if _combo_rules_added:
            print(f"  Combo+rules: {_combo_rules_added} phase(s) ({_rule_name})")
        if _combo_rules_skipped:
            print(f"  Combo+rules pairs skipped "
                  f"(over {_fmt_keyspace(_combo_ks_limit)} threshold; "
                  f"raise --max-combinator-pairs-ks to include): "
                  + ", ".join(_combo_rules_skipped[:6])
                  + (f" … (+{len(_combo_rules_skipped)-6} more)"
                     if len(_combo_rules_skipped) > 6 else ""))

    # ── 1100: Two-word passphrase / common-word (combinator) attacks ──
    # Catches patterns like WinterRain, BlueSky, AdminUser, Summer2024!, ChangeMe!
    # that aren't in standard wordlists but are common under 12-char policies.
    # The common-words list is small (~120 base × 2 cases = ~240 entries) so
    # common×common is trivially fast (~57,600 candidates).
    priority = 1100
    common_wl = _write_common_words_wordlist(campaign.wordlists_dir)
    common_lines = _count_file_lines(common_wl)

    # Two-word combinator: WinterRain, BlueSky, AdminUser, DragonBall
    p = Phase(
        id=_new_id(),
        name="Passphrase: common×common",
        type="combinator",
        args=["-a", "1", common_wl, common_wl],
        priority=priority,
        estimated_keyspace=common_lines * common_lines,
        no_optimize=True,
    )
    _time_gate(p, campaign, campaign.skip_threshold_hours)
    phases.append(p)
    priority += 5

    # Common word × suffix combinator: Winter2024!, Blue123!
    p = Phase(
        id=_new_id(),
        name="Passphrase: common×suffixes",
        type="combinator",
        args=["-a", "1", common_wl, suffix_file],
        priority=priority,
        estimated_keyspace=common_lines * suffix_lines,
        no_optimize=True,
    )
    _time_gate(p, campaign, campaign.skip_threshold_hours)
    phases.append(p)
    priority += 5

    # Common words + best66 rules: Winter!, winter2024, WINTER1, etc.
    _common_rule = find_rule(custom_rules_dir, "best66.rule")
    if _common_rule:
        _best_name = os.path.basename(_common_rule)
        p = Phase(
            id=_new_id(),
            name=f"Passphrase: common+{_best_name}",
            type="rules",
            args=["-a", "0", "--loopback", "-r", _common_rule, common_wl],
            priority=priority,
            estimated_keyspace=common_lines * _count_rule_lines(_common_rule),
        )
        _time_gate(p, campaign, campaign.skip_threshold_hours)
        phases.append(p)
        priority += 5

    # If an external passphrases.txt exists in standard wordlist paths, attack it
    _ext_phrase_wl = find_wordlist("passphrases.txt")
    if _ext_phrase_wl:
        _ext_lines = _count_file_lines(_ext_phrase_wl)
        for _phr_rule in ("best66.rule", "dive.rule"):
            _phr_rpath = find_rule(custom_rules_dir, _phr_rule)
            if _phr_rpath:
                p = Phase(
                    id=_new_id(),
                    name=f"Ext passphrases+{_phr_rule}",
                    type="rules",
                    args=["-a", "0", "--loopback", "-r", _phr_rpath, _ext_phrase_wl],
                    priority=priority,
                    estimated_keyspace=_ext_lines * _count_rule_lines(_phr_rpath),
                )
                _time_gate(p, campaign, campaign.skip_threshold_hours)
                phases.append(p)
                priority += 5

    # ── 5000: Brute force (ordered by keyspace) ───────────────────────────
    priority = 60000
    for charset, mask_pattern, desc, keyspace in sorted(_BRUTE_MASKS, key=lambda x: x[3]):
        _brute_args = ["-a", "3"]
        if charset:
            _brute_args.extend(charset.cli_args())   # e.g. ["-1", "!@#$%^&*-_+??"]
        _brute_args.append(mask_pattern)
        p = Phase(
            id=_new_id(),
            name=f"Brute: {desc}",
            type="brute",
            args=_brute_args,
            priority=priority,
            estimated_keyspace=keyspace,
        )
        _time_gate(p, campaign, campaign.skip_threshold_hours)
        phases.append(p)
        priority += 5

    return phases

def _write_enterprise_mask_file(masks_dir: str,
                                speed_ghs: float = 0,
                                threshold_hours: Optional[float] = None) -> str:
    """Write enterprise.hcmask containing only masks that fit within the time threshold.

    Masks exceeding the threshold are omitted here and expected to run as
    individual ExtMask phases in the 2500-band after Analysis Pass 1.
    When speed_ghs is 0 (or threshold_hours is None) all masks are included.
    """
    os.makedirs(masks_dir, exist_ok=True)
    limit = threshold_hours or 6.0
    path = os.path.join(masks_dir, "enterprise.hcmask")
    with open(path, "w") as f:
        f.write("# Crackbaby enterprise mask file — built-in patterns\n")
        for mask_line, desc, ks in sorted(_ENTERPRISE_MASKS, key=lambda x: x[2]):
            if speed_ghs > 0 and ks / (speed_ghs * 1e9) / 3600 > limit:
                continue   # too slow — handled as individual ExtMask at 2500-band
            # Comments MUST be on their own line — hashcat reads inline # as literal
            f.write(f"# {desc}  (~{_fmt_keyspace(ks)})\n")
            f.write(f"{mask_line}\n")
    return path


def _write_suffix_wordlist(wordlists_dir: str) -> str:
    os.makedirs(wordlists_dir, exist_ok=True)
    path = os.path.join(wordlists_dir, "suffixes.txt")
    entries = (
        _YEAR_SUFFIXES
        + [str(n) for n in range(1, 101)]
        + ["123", "1234", "12345", "123456", "1!", "2!", "1!!", "123!"]
        + _SPECIAL_SUFFIXES
        + _YEAR_SPECIAL_SUFFIXES      # 2024!, 2024!!, 2024@, … 2026*
    )
    with open(path, "w") as f:
        for e in sorted(set(entries), key=lambda s: (len(s), s)):
            f.write(e + "\n")
    return path


_COMMON_WORDS = [
    # Colors
    "red", "blue", "green", "black", "white", "silver", "gold", "purple",
    "orange", "yellow", "pink", "brown", "grey", "gray",
    # Seasons / weather
    "spring", "summer", "fall", "winter", "snow", "rain", "storm", "cloud",
    # Animals
    "dragon", "tiger", "eagle", "falcon", "wolf", "bear", "lion", "hawk",
    "shark", "fox", "monkey", "panther", "phoenix",
    # Enterprise words
    "admin", "welcome", "password", "login", "secure", "access", "network",
    "server", "support", "change", "update", "manage", "system", "portal",
    "office", "desktop", "remote", "backup", "master", "secret", "user",
    "guest", "temp", "test", "prod", "corp", "domain",
    # Common adjectives / nouns
    "happy", "lucky", "smart", "strong", "bright", "super", "great",
    "power", "magic", "rocket", "ninja", "shadow", "thunder", "matrix",
    "omega", "alpha", "delta", "sigma", "cyber", "turbo", "ultra",
    # Nouns / places / sports
    "batman", "spider", "ranger", "hunter", "warrior", "knight",
    "wizard", "captain", "soccer", "football", "hockey", "baseball",
    "dallas", "cowboys", "eagles", "chicago", "boston", "denver", "austin",
]


def _write_common_words_wordlist(wordlists_dir: str) -> str:
    """
    Write a small built-in wordlist of high-frequency enterprise password words.
    Includes both lowercase and Capitalized forms so combinator and rule attacks
    cover `WinterRain`, `DragonBall`, `AdminUser`, `Summer2024!` etc. without
    needing an external wordlist.
    """
    os.makedirs(wordlists_dir, exist_ok=True)
    path = os.path.join(wordlists_dir, "common_words.txt")
    with open(path, "w") as f:
        for w in sorted(set(_COMMON_WORDS)):
            f.write(w + "\n")
            cap = w.capitalize()
            if cap != w:
                f.write(cap + "\n")
    return path


# ── Org-context wordlist ──────────────────────────────────────────────────────

_US_STATES: dict = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas",
    "CA": "California", "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware",
    "FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho",
    "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas",
    "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi",
    "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
    "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York",
    "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah",
    "VT": "Vermont", "VA": "Virginia", "WA": "Washington", "WV": "West Virginia",
    "WI": "Wisconsin", "WY": "Wyoming", "DC": "District of Columbia",
}

_ORG_STRIP_RE = re.compile(
    r'\s+(corp(?:oration)?|inc(?:orporated)?|llc|ltd|limited|co(?:mpany)?|'
    r'group|holdings|services?|solutions?|technologies|tech|systems?|'
    r'enterprises?|global|international|national|associates?|partners?|'
    r'consulting|management|industries)\.*$',
    re.IGNORECASE,
)

_ORG_IT_SUFFIXES = [
    "it", "pw", "pass", "password", "admin", "corp",
    "help", "helpdesk", "vpn", "wifi", "net",
]


def _org_case_variants(word: str, out: set) -> None:
    """Add lowercase, Capitalized, and UPPER (≤ 6 chars) variants of *word*."""
    if not word or len(word) < 2:
        return
    out.add(word.lower())
    out.add(word.capitalize())
    if len(word) <= 6:
        out.add(word.upper())


def _write_org_wordlist(campaign: Campaign) -> Optional[str]:
    """
    Build a targeted wordlist from campaign.org_name, org_name_short, org_location.

    Strategy
    ────────
    1. Case variants of each supplied field and its whitespace/hyphen-split parts.
    2. Corporate-suffix stripping: "Acme Corporation" → bare brand "Acme".
    3. IT department naming patterns: acmeit, acmeadmin, acmevpn …
    4. Location parsing: city + US state expansion (TX → Texas).

    Returns the file path, or None if no org context is configured.
    """
    org_name  = getattr(campaign, "org_name",       "").strip()
    org_short = getattr(campaign, "org_name_short",  "").strip()
    org_loc   = getattr(campaign, "org_location",    "").strip()

    if not any([org_name, org_short, org_loc]):
        return None

    words: set = set()

    # 1. org_name
    if org_name:
        _org_case_variants(org_name, words)
        for part in re.split(r"[\s\-_]+", org_name):
            _org_case_variants(part, words)
        # Stripped brand name (remove Corp/Inc/LLC etc.)
        bare = _ORG_STRIP_RE.sub("", org_name).strip()
        if bare and bare.lower() != org_name.lower():
            _org_case_variants(bare, words)
            for part in re.split(r"[\s\-_]+", bare):
                _org_case_variants(part, words)
        # First word of bare name → IT naming patterns
        first = re.split(r"[\s\-_]+", (bare or org_name))[0].lower()
        if len(first) >= 3:
            for sfx in _ORG_IT_SUFFIXES:
                words.add(first + sfx)
                words.add(first.capitalize() + sfx.capitalize())

    # 2. org_short (e.g. "acme", "ACM")
    if org_short:
        _org_case_variants(org_short, words)
        for part in re.split(r"[\s\-_]+", org_short):
            _org_case_variants(part, words)
        first_short = re.split(r"[\s\-_]+", org_short)[0].lower()
        if len(first_short) >= 3:
            for sfx in _ORG_IT_SUFFIXES:
                words.add(first_short + sfx)

    # 3. Location
    if org_loc:
        for token in re.split(r"[,\s]+", org_loc):
            token = token.strip().rstrip(".")
            if not token:
                continue
            up = token.upper()
            if up in _US_STATES:               # state abbreviation → full name
                _org_case_variants(_US_STATES[up], words)
                words.add(up)
                words.add(token.lower())
            else:
                _org_case_variants(token, words)
            # Multi-word state names ("New York") get their components too
            if up in _US_STATES:
                for part in _US_STATES[up].split():
                    _org_case_variants(part, words)

    # 4. Custom words from org config (free-form; may be multi-word entries)
    for w in getattr(campaign, "org_custom_words", []):
        if not w or not isinstance(w, str):
            continue
        _org_case_variants(w, words)
        for part in re.split(r"[\s\-_]+", w):   # split multi-word entries
            _org_case_variants(part, words)

    # Filter: keep only words ≥ 3 chars (no single letters or 2-char noise)
    words = {w for w in words if len(w) >= 3}
    if not words:
        return None

    os.makedirs(campaign.wordlists_dir, exist_ok=True)
    path = os.path.join(campaign.wordlists_dir, "org_words.txt")
    with open(path, "w") as f:
        for w in sorted(words):
            f.write(w + "\n")
    print(f"  Org wordlist: {len(words)} entries → org_words.txt")
    return path


def _write_season_wordlist(wordlists_dir: str) -> str:
    os.makedirs(wordlists_dir, exist_ok=True)
    path = os.path.join(wordlists_dir, "seasons.txt")
    with open(path, "w") as f:
        for w in _SEASON_WORDS:
            f.write(w + "\n")
    return path


def _fmt_keyspace(ks: int) -> str:
    if ks < 1e6:
        return f"{ks:.0f}"
    if ks < 1e9:
        return f"{ks/1e6:.1f}M"
    if ks < 1e12:
        return f"{ks/1e9:.1f}B"
    if ks < 1e15:
        return f"{ks/1e12:.1f}T"
    if ks < 1e18:
        return f"{ks/1e15:.1f}P"
    return f"{ks:.2e}"
