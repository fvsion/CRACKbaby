"""Campaign state management — persistent JSON schema for all phases and metadata.

Potfile names and session names use the crackbaby brand.
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict, fields as dc_fields
from typing import List, Optional


def global_potfile_for_type(base_path: str, hash_type: int) -> str:
    """Derive a per-hash-type potfile path from a user-supplied global base path.

    The config value is a *base*, never a full filename — crackbaby always appends
    ``_<hash_type>.potfile`` so each mode gets its own file and types never mix:

        ~/potfiles/                  + 1000  →  ~/potfiles/crackbaby_1000.potfile   (dir → 'crackbaby' base)
        ~/potfiles/acme              + 1000  →  ~/potfiles/acme_1000.potfile
        ~/.crackbaby.global          + 3000  →  ~/.crackbaby.global_3000.potfile
        ~/.crackbaby.global.potfile  + 1000  →  ~/.crackbaby.global_1000.potfile    (stray ext stripped)

    A trailing slash (or an existing directory) uses the default base name
    ``crackbaby`` inside it; any ``.pot`` / ``.potfile`` extension the user
    mistakenly included is stripped before the type suffix is applied.  The
    single source of truth shared by Campaign's potfile properties and
    HashcatRunner so both always resolve to the identical path.
    """
    expanded = os.path.expanduser(base_path)
    if expanded.endswith(("/", os.sep)) or os.path.isdir(expanded):
        expanded = os.path.join(expanded, "crackbaby")   # directory → default base name
    for ext in (".potfile", ".pot"):                   # tolerate a user-included extension
        if expanded.endswith(ext):
            expanded = expanded[: -len(ext)]
            break
    return f"{expanded}_{hash_type}.potfile"


@dataclass
class Phase:
    id: str
    name: str
    type: str          # wordlist | rules | mask | hybrid | combinator | analysis | brute
    args: List[str]    # hashcat args appended after base args (not including hash file)
    priority: int = 0
    status: str = "pending"   # pending | running | completed | failed | skipped | interrupted
    cracked_start: int = 0
    cracked_end: int = 0
    cracked_recorded: int = 0   # cumulative cracks attributed to this phase across ALL its
                                # runs; accumulated per run so interrupt→resume is additive
                                # and a clean re-run doesn't zero a completed phase
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    auto_generated: bool = False
    estimated_keyspace: Optional[int] = None
    notes: str = ""
    generator_cmd: Optional[List[str]] = None  # set for stdin-pipe phases (e.g. combinator.bin); None = direct hashcat
    no_optimize: bool = False  # disable -O for this phase (combinator/combo_rules: wl1+wl2 may exceed 31 chars)
    combo_wl1: Optional[str] = None  # combo_rules: left-side wordlist path (wl1 × wl2 cartesian product)
    combo_wl2: Optional[str] = None  # combo_rules: right-side wordlist path
    combo_strategy: Optional[str] = None  # combo_rules: strategy used/predicted for speed lookup
                                          # values: "rule_convert" (small side → GPU rules)
                                          #         or "combinator_bin" (combinator.bin stdin pipe)

    @property
    def duration_secs(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None

    @property
    def duration_str(self) -> str:
        s = self.duration_secs
        if s is None:
            return "N/A"
        h, rem = divmod(int(s), 3600)
        m, sec = divmod(rem, 60)
        if h:
            return f"{h}h {m}m {sec}s"
        if m:
            return f"{m}m {sec}s"
        return f"{sec}s"

    @property
    def cracked_delta(self) -> int:
        """New cracks from the most recent run only (this segment)."""
        return max(0, self.cracked_end - self.cracked_start)

    @property
    def cracked_total(self) -> int:
        """Cumulative cracks attributed to this phase across all of its runs."""
        return self.cracked_recorded

    @property
    def session_name(self) -> str:
        return f"crackbaby_{self.id}"


@dataclass
class Campaign:
    name: str
    hash_file: str
    hash_type: int
    output_dir: str
    hashcat_bin: str
    username_mode: bool
    devices: Optional[str]
    workload: int
    wordlists: List[str]
    custom_rules_dir: Optional[str]
    phases: List[Phase] = field(default_factory=list)
    total_hashes: int = 0
    unique_hashes: int = 0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    phase_timeout_secs: Optional[int] = None    # wall-clock limit per phase; None = unlimited
    expected_speed_ghs: float = 68.0            # estimated GH/s for ETA calculations (default: single RTX 3090)
    skip_threshold_hours: Optional[float] = None  # auto-skip phases estimated over this many hours
    status_interval: int = 5                    # hashcat --status-timer value in seconds
    lm_hash_file: Optional[str] = None         # path to LM hash file; enables LM cracking phases

    default_rule_depth: str = "A"  # "A" | "AB" | "ABC" — tier depth for default hashcat rules dirs only
    global_potfile: Optional[str] = None  # shared potfile across campaigns; None = use campaign-local
    max_combinator_pairs_ks: int = 500_000_000  # auto-threshold for wl×wl combinator pairs (default 500M)

    # combo_rules dispatch — rule-convert threshold
    max_rule_convert_words: int = 50_000      # if the smaller wl side has ≤ this many lines,
                                              # convert it to GPU rules (fully on-GPU, no pipe);
                                              # fastest path for asymmetric combos.
                                              # Falls back to combinator.bin pipe otherwise.

    # ── Org context (optional — improves targeted attacks) ───────────────────
    # Provide at init time via --org-config FILE; crackbaby generates a targeted
    # org_words.txt wordlist.  All fields sourced from the JSON config.
    org_name: str = ""                       # full legal name, e.g. "Acme Corporation"
    org_name_short: str = ""                 # common abbreviation / ticker, e.g. "acme"
    org_location: str = ""                   # city + state/country, e.g. "Dallas, TX"
    org_custom_words: List[str] = field(default_factory=list)  # extra words from custom_words key

    # ── Derived paths (not stored) ──────────────────────────────────────────

    @property
    def potfile(self) -> str:
        """Campaign-local potfile for the primary hash type (e.g. crackbaby_1000.potfile)."""
        return os.path.join(self.output_dir, f"crackbaby_{self.hash_type}.potfile")

    @property
    def lm_potfile(self) -> str:
        """Campaign-local potfile for LM hashes (mode 3000 — always distinct)."""
        return os.path.join(self.output_dir, "crackbaby_3000.potfile")

    @property
    def active_potfile(self) -> str:
        """Potfile passed to hashcat for the primary hash type.
        When a global potfile is configured the path is made type-specific so
        NTLM, LM, and any future hash types never share the same file.
        """
        if self.global_potfile:
            return global_potfile_for_type(self.global_potfile, self.hash_type)
        return self.potfile

    @property
    def active_lm_potfile(self) -> str:
        """Potfile passed to hashcat for LM hashes (mode 3000).
        Mirrors active_potfile but always resolves for hash type 3000.
        """
        if self.global_potfile:
            return global_potfile_for_type(self.global_potfile, 3000)
        return self.lm_potfile

    @property
    def cracked_file(self) -> str:
        return os.path.join(self.output_dir, "cracked.txt")

    @property
    def sessions_dir(self) -> str:
        return os.path.join(self.output_dir, "sessions")

    @property
    def wordlists_dir(self) -> str:
        return os.path.join(self.output_dir, "wordlists")

    @property
    def masks_dir(self) -> str:
        return os.path.join(self.output_dir, "masks")

    @property
    def logs_dir(self) -> str:
        return os.path.join(self.output_dir, "logs")

    @property
    def state_file(self) -> str:
        return os.path.join(self.output_dir, "campaign.json")

    # ── Persistence ─────────────────────────────────────────────────────────

    def save(self):
        data = asdict(self)
        with open(self.state_file, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, output_dir: str) -> "Campaign":
        state_file = os.path.join(output_dir, "campaign.json")
        with open(state_file) as f:
            data = json.load(f)
        phases_data = data.pop("phases", [])
        # Migrate renamed fields from older campaign.json files.
        if "rules_dir" in data and "custom_rules_dir" not in data:
            data["custom_rules_dir"] = data.pop("rules_dir")
        if "rule_depth" in data and "default_rule_depth" not in data:
            data["default_rule_depth"] = data.pop("rule_depth")
        # Filter to known fields so old campaign.json files load cleanly
        # even when new fields have been added since they were created.
        known_c = {f.name for f in dc_fields(cls)}
        known_p = {f.name for f in dc_fields(Phase)}
        c = cls(**{k: v for k, v in data.items() if k in known_c})
        c.phases = [Phase(**{k: v for k, v in p.items() if k in known_p})
                    for p in phases_data]
        # Migrate old combo_rules phases that stored wordlist paths inside generator_cmd
        # as a fake hashcat subprocess call [hc_bin, "-a", "1", wl1, wl2, "--stdout", "--quiet"].
        # Extract them into the dedicated combo_wl1/combo_wl2 fields and clear generator_cmd.
        for _p in c.phases:
            if _p.type == "combo_rules" and _p.combo_wl1 is None and _p.generator_cmd:
                _gc = _p.generator_cmd
                _p.combo_wl1 = _gc[3] if len(_gc) > 3 else None
                _p.combo_wl2 = _gc[4] if len(_gc) > 4 else None
                _p.generator_cmd = None
        # Migrate hybrid phases that still carry the old unescaped '?' in the -1 charset arg.
        # The bare '?' caused hashcat "Syntax error in mask" — '??' is the correct escape for
        # a literal '?'. Re-queue any phase that was failed solely because of this bug.
        _OLD_CS = "!@#$%^&*-_+?"
        _NEW_CS = "!@#$%^&*-_+??"
        for _p in c.phases:
            if _p.type == "hybrid" and _OLD_CS in _p.args:
                _p.args = [_NEW_CS if a == _OLD_CS else a for a in _p.args]
                if _p.status == "failed":
                    _p.status = "pending"  # re-queue: failed due to charset bug, now fixed
        # Migrate brute/mask phases whose inline charset still uses unescaped '?'.
        # hashcat's comma-separated inline format (charset,,,,mask) requires '??' for
        # a literal '?' — same rule as the -1 flag, but a different code path.
        for _p in c.phases:
            if _p.type in ("brute", "mask") and any(
                    "!@#$%^&*-_+?,,,," in a and "!@#$%^&*-_+??,,,," not in a
                    for a in _p.args):
                _p.args = [
                    a.replace("!@#$%^&*-_+?,,,,", "!@#$%^&*-_+??,,,,")
                    for a in _p.args
                ]
                if _p.status == "failed":
                    _p.status = "pending"  # re-queue: failed due to charset bug, now fixed
        # Migrate brute/mask phases from inline charset format to explicit -1 flag.
        # Old (broken): args = ["-a", "3", "!@#$%^&*-_+??,,,,?u?l?l?l?l?l?l?l?l?1"]
        # New (correct): args = ["-a", "3", "-1", "!@#$%^&*-_+??", "?u?l?l?l?l?l?l?l?l?1"]
        # Detection: last arg contains commas and does not start with '?' (a mask placeholder).
        for _p in c.phases:
            if _p.type in ("brute", "mask") and _p.args and "," in _p.args[-1]:
                _inline = _p.args[-1]
                _parts  = _inline.split(",")
                # inline format: "charset,,,,mask" — first part is charset, last is mask
                if len(_parts) >= 2 and _parts[0] and not _parts[0].startswith("?"):
                    _charset = _parts[0]   # e.g. "!@#$%^&*-_+??"
                    _mask    = _parts[-1]  # e.g. "?u?l?l?l?l?l?l?l?l?1"
                    _p.args  = _p.args[:-1] + ["-1", _charset, _mask]
                    if _p.status == "failed":
                        _p.status = "pending"  # re-queue: failed due to wrong format
        # Migrate seasons×years combinator phases: max combined length is ~13 chars
        # (seasons ≤ 6 chars, suffixes ≤ 7 chars), always within the -O limit of 27.
        # These were incorrectly given no_optimize=True; reset so they use optimized kernels.
        for _p in c.phases:
            if (_p.type == "combinator"
                    and _p.no_optimize
                    and "seasons" in _p.name.lower() and "year" in _p.name.lower()
                    and _p.status in ("pending", "failed")):
                _p.no_optimize = False
        # Recover phases left "running" by a previous process that died unexpectedly
        # (hard kill / SIGKILL / crash / power loss — anything that bypassed the
        # graceful SIGINT handler that would have set "interrupted"). A phase can
        # only legitimately be "running" while its owning run is alive, so on load
        # any "running" phase is stale: re-queue it as pending so next_phase()
        # picks it up again (hashcat --restore resumes mid-keyspace where possible).
        for _p in c.phases:
            if _p.status == "running":
                _p.status = "pending"
        return c

    # ── Phase accessors ─────────────────────────────────────────────────────

    def next_phase(self) -> Optional[Phase]:
        pending = [p for p in self.phases if p.status == "pending"]
        if not pending:
            return None
        return min(pending, key=lambda p: (p.priority, p.id))

    def add_phase(self, phase: Phase):
        self.phases.append(phase)

    def get_phase(self, pid: str) -> Optional[Phase]:
        return next((p for p in self.phases if p.id == pid), None)

    def cracked_count(self) -> int:
        """Most recently recorded cracked count from completed/running phases."""
        best = 0
        for p in self.phases:
            best = max(best, p.cracked_end, p.cracked_start)
        return best

    def phase_summary(self) -> dict:
        counts = {"pending": 0, "running": 0, "completed": 0,
                  "failed": 0, "skipped": 0, "interrupted": 0, "timed_out": 0}
        for p in self.phases:
            counts[p.status] = counts.get(p.status, 0) + 1
        return counts
