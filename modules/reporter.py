"""
Final report generation — pentest-quality password audit output.

Produces both a machine-readable JSON and a human-readable text report covering:
  - Overall crack rate
  - Phase-by-phase breakdown
  - Password length/complexity distribution
  - Policy compliance analysis
  - Top cracked patterns (sanitized)
  - Recommendations
"""

import json
import os
import time
from collections import Counter
from datetime import datetime
from typing import Dict, Iterator, List, Optional, Tuple

from .campaign import Campaign


# ── Char-class helpers (moved from analyzer.py) ───────────────────────────────

def charset_flags(pw: str) -> str:
    has_upper   = any(c.isupper() for c in pw)
    has_lower   = any(c.islower() for c in pw)
    has_digit   = any(c.isdigit() for c in pw)
    has_special = any(not c.isalnum() for c in pw)
    flags = ""
    if has_upper:   flags += "U"
    if has_lower:   flags += "L"
    if has_digit:   flags += "D"
    if has_special: flags += "S"
    return flags or "?"


def password_to_mask(pw: str) -> str:
    def _c(c):
        if c.islower(): return "?l"
        if c.isupper(): return "?u"
        if c.isdigit(): return "?d"
        return "?s"
    return "".join(_c(c) for c in pw)


def _charset_label(flags: str) -> str:
    parts = []
    if "U" in flags: parts.append("upper")
    if "L" in flags: parts.append("lower")
    if "D" in flags: parts.append("digit")
    if "S" in flags: parts.append("special")
    return "+".join(parts) if parts else "unknown"


# ── Policy definitions ────────────────────────────────────────────────────────

_POLICIES = {
    "min_8_any": {
        "description": "Minimum 8 characters (any)",
        "check": lambda pw: len(pw) >= 8,
    },
    "min_12_any": {
        "description": "Minimum 12 characters (any)",
        "check": lambda pw: len(pw) >= 12,
    },
    "complexity_3of4": {
        "description": "3 of 4 complexity (upper, lower, digit, special)",
        "check": lambda pw: sum([
            any(c.isupper() for c in pw),
            any(c.islower() for c in pw),
            any(c.isdigit() for c in pw),
            any(not c.isalnum() for c in pw),
        ]) >= 3,
    },
    "min_12_complexity": {
        "description": "12+ chars AND 3-of-4 complexity",
        "check": lambda pw: (
            len(pw) >= 12 and
            sum([
                any(c.isupper() for c in pw),
                any(c.islower() for c in pw),
                any(c.isdigit() for c in pw),
                any(not c.isalnum() for c in pw),
            ]) >= 3
        ),
    },
}


class Reporter:
    def __init__(self, campaign: Campaign):
        self.campaign = campaign

    def generate(self, output_path: Optional[str] = None) -> str:
        """Generate and write the full report. Returns the report text."""
        c = self.campaign

        # Read all cracked plaintexts
        plaintexts = self._read_plaintexts()

        # Two distinct — and often very different — quantities:
        #   • unique passwords cracked: distinct NT hashes recovered (potfile rows)
        #   • accounts compromised:     hash-file lines whose hash is one of those.
        # In --username mode passwords are heavily reused, so accounts_cracked is
        # typically far larger than unique_cracked; reporting both keeps the headline
        # honest and reconciles with the per-phase "+N" deltas (which are accounts).
        cracked_hashes   = set(self._read_unique_hashes())
        unique_total     = c.unique_hashes or c.total_hashes
        unique_cracked   = len(cracked_hashes)
        uniq_pct         = unique_cracked / unique_total * 100 if unique_total else 0

        total_accounts   = c.total_hashes or unique_total
        accounts_cracked = self._count_cracked_accounts(cracked_hashes)
        acct_pct         = accounts_cracked / total_accounts * 100 if total_accounts else 0

        lines = []
        _h = lines.append  # shorthand

        _h("=" * 72)
        _h("  CRACKBABY — Enterprise NTLM Password Recovery Report")
        _h("=" * 72)
        _h(f"  Campaign:      {c.name}")
        _h(f"  Hash file:     {c.hash_file}")
        _h(f"  Generated:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if c.started_at:
            elapsed = time.time() - c.started_at
            _h(f"  Elapsed:       {_fmt_duration(elapsed)}")
        _h("")

        # ── Overall stats ───────────────────────────────────────────────────
        _h("─" * 72)
        _h("  OVERALL RESULTS")
        _h("─" * 72)
        _h(f"  Total accounts:        {total_accounts:,}")
        _h(f"  Unique NT hashes:      {unique_total:,}")
        _h(f"  Accounts compromised:  {accounts_cracked:,}  ({acct_pct:.1f}%)")
        _h(f"  Unique passwords:      {unique_cracked:,}  ({uniq_pct:.1f}%)")
        _h(f"  Remaining accounts:    {total_accounts - accounts_cracked:,}  ({100 - acct_pct:.1f}%)")
        _h("")

        # ── Phase breakdown ─────────────────────────────────────────────────
        _h("─" * 72)
        _h("  PHASE BREAKDOWN")
        _h("─" * 72)
        _h("  ('Cracked' counts accounts unlocked by each phase, not unique passwords)")
        _h(f"  {'ID':<8} {'Name':<45} {'Status':<12} {'Cracked':<10} {'Time'}")
        _h(f"  {'-'*7} {'-'*44} {'-'*11} {'-'*9} {'-'*12}")
        for p in c.phases:
            if p.status in ("completed", "failed", "skipped", "interrupted"):
                _h(f"  {p.id:<8} {p.name[:44]:<45} {p.status:<12} "
                   f"{'+'+str(p.cracked_delta):<10} {p.duration_str}")
        _h("")

        # ── Analysis ────────────────────────────────────────────────────────
        if plaintexts:
            _h("─" * 72)
            _h("  PASSWORD ANALYSIS")
            _h("─" * 72)

            # Length distribution
            lengths = Counter(len(p) for p in plaintexts)
            _h("  Length distribution:")
            for length in sorted(lengths):
                count = lengths[length]
                pct = count / len(plaintexts) * 100
                bar = "█" * min(40, int(pct * 0.8))
                _h(f"    {length:3d} chars: {count:6,}  ({pct:5.1f}%)  {bar}")
            _h("")

            # Charset distribution
            csets = Counter(charset_flags(p) for p in plaintexts)
            _h("  Charset distribution:")
            for flags, count in csets.most_common():
                pct = count / len(plaintexts) * 100
                label = _charset_label(flags)
                _h(f"    {flags:6s}  {label:35s}  {count:6,}  ({pct:5.1f}%)")
            _h("")

            # Policy compliance
            _h("─" * 72)
            _h("  POLICY COMPLIANCE (of cracked passwords)")
            _h("─" * 72)
            for policy_id, policy in _POLICIES.items():
                meets = sum(1 for p in plaintexts if policy["check"](p))
                pct = meets / len(plaintexts) * 100
                _h(f"  {policy['description']}")
                _h(f"    → {meets:,} of {len(plaintexts):,} cracked ({pct:.1f}%) meet this policy")
                _h(f"    → {len(plaintexts)-meets:,} passwords are BELOW this threshold")
            _h("")

            # Top masks
            masks = Counter(password_to_mask(p) for p in plaintexts)
            _h("  Top password patterns:")
            for mask, count in masks.most_common(20):
                pct = count / len(plaintexts) * 100
                _h(f"    {mask:45s}  {count:5,}  ({pct:.1f}%)")
            _h("")

            # Common suffixes/endings (last 1-4 chars)
            endings = Counter()
            for pw in plaintexts:
                for n in (1, 2, 3, 4):
                    if len(pw) >= n + 4:  # password has a real base word
                        tail = pw[-n:]
                        if all(c.isdigit() for c in tail) or tail in ("!", "!!", "!@", "@"):
                            endings[tail] += 1
            if endings:
                _h("  Common password endings (digits/symbols):")
                for ending, count in endings.most_common(15):
                    pct = count / len(plaintexts) * 100
                    _h(f"    {repr(ending):15s}  {count:5,}  ({pct:.1f}%)")
                _h("")

        # ── Recommendations ─────────────────────────────────────────────────
        _h("─" * 72)
        _h("  RECOMMENDATIONS")
        _h("─" * 72)
        _h(self._recommendations(acct_pct, plaintexts))
        _h("")
        _h("=" * 72)
        _h(f"  Report generated by Crackbaby — {datetime.now().isoformat()}")
        _h("=" * 72)

        report_text = "\n".join(ln for ln in lines if ln is not None)

        if output_path is None:
            output_path = os.path.join(self.campaign.output_dir, "report.txt")
        with open(output_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(report_text + "\n")

        # Also write JSON summary
        json_path = output_path.replace(".txt", ".json")
        self._write_json(json_path, total_accounts, unique_total,
                         accounts_cracked, unique_cracked, acct_pct, uniq_pct,
                         plaintexts)

        return report_text

    def _recommendations(self, crack_pct: float, plaintexts: List[str]) -> str:
        lines = []
        if crack_pct > 50:
            lines.append("  CRITICAL: Over half of account passwords were cracked. Enforce immediate")
            lines.append("  password resets for all accounts and implement stronger policy controls.")
        elif crack_pct > 20:
            lines.append("  HIGH: A significant portion of passwords were cracked. Consider mandatory")
            lines.append("  resets for affected accounts and a staged rollout for remaining accounts.")
        else:
            lines.append("  MODERATE: Password policy is showing some effectiveness.")

        if plaintexts:
            short = sum(1 for p in plaintexts if len(p) < 12)
            if short / len(plaintexts) > 0.4:
                lines.append("")
                lines.append("  → Enforce minimum 12-character password length.")
            no_complexity = sum(
                1 for p in plaintexts
                if not _POLICIES["complexity_3of4"]["check"](p)
            )
            if no_complexity / len(plaintexts) > 0.3:
                lines.append("")
                lines.append("  → Enforce complexity requirements (upper + lower + digit + special).")

            lines.append("")
            lines.append("  → Implement a banned-password list blocking common words and patterns")
            lines.append("    (seasons, years, company name, keyboard walks, etc.).")
            lines.append("")
            lines.append("  → Consider passphrase policy (4+ random words) as an alternative to")
            lines.append("    complex short passwords — harder to crack, easier to remember.")
            lines.append("")
            lines.append("  → Enable MFA on all domain accounts, especially privileged ones.")
            lines.append("    Cracked NTLM hashes can be used for pass-the-hash attacks regardless")
            lines.append("    of password strength.")

        return "\n".join(lines)

    def _load_campaign_hashes(self) -> Optional[set]:
        """Return a set of lowercase NT hashes from the campaign hash file.

        Used to filter a global potfile down to only this campaign's hashes,
        preventing over-counting when multiple campaigns share a potfile.
        Returns None when global potfile is not in use (no filtering needed).
        """
        if not self.campaign.global_potfile:
            return None  # not using global potfile — no filter needed
        hashes: set = set()
        try:
            with open(self.campaign.hash_file, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if ":" in line:
                        # user:hash format — hash is the last colon-separated field
                        hashes.add(line.split(":")[-1].lower())
                    elif len(line) == 32:
                        hashes.add(line.lower())
        except Exception:
            pass
        return hashes

    def _iter_potfile_pairs(self) -> "Iterator[Tuple[str, str]]":
        """Yield (lowercase_hash, plaintext) for each line of the active potfile.

        Single source of truth for potfile parsing used by both _read_plaintexts
        and _read_unique_hashes. Applies the global-potfile campaign filter so
        hashes from other campaigns sharing the potfile are never counted.

        NT hashes are exactly 32 hex chars, so when the 33rd char is the ':'
        separator we split at the fixed position — this keeps plaintexts that
        themselves contain ':' intact.
        """
        potfile = self.campaign.active_potfile
        if not os.path.exists(potfile):
            return
        campaign_hashes = self._load_campaign_hashes()
        with open(potfile, errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if ":" not in line:
                    continue
                if len(line) > 33 and line[32] == ":":
                    h, pt = line[:32].lower(), line[33:]
                else:
                    parts = line.split(":", 1)
                    h, pt = parts[0].lower(), parts[1]
                if campaign_hashes is not None and h not in campaign_hashes:
                    continue   # belongs to a different campaign in the global potfile
                yield h, pt

    def _read_plaintexts(self) -> List[str]:
        return [pt for _h, pt in self._iter_potfile_pairs()]

    def _read_cracked_lines(self) -> List[str]:
        path = self.campaign.cracked_file
        if not os.path.exists(path):
            return []
        with open(path, errors="replace") as f:
            return [l.rstrip() for l in f if l.strip()]

    def _read_unique_hashes(self) -> List[str]:
        return list({h for h, _pt in self._iter_potfile_pairs()})

    def _count_cracked_accounts(self, cracked_hashes: set) -> int:
        """Count hash-file lines (accounts) whose NT hash was cracked.

        ``cracked_hashes`` holds lowercase-hex NT hashes from the potfile. In
        --username mode the hash file is ``DOMAIN\\user:hash`` and many accounts may
        share one password, so this is typically far larger than the number of unique
        cracked hashes. In non-username mode it equals the count of cracked unique
        hashes present in the file. Returns 0 if the hash file is unreadable.
        """
        if not cracked_hashes:
            return 0
        hf = self.campaign.hash_file
        if not hf or not os.path.exists(hf):
            return 0
        username_mode = self.campaign.username_mode
        n = 0
        try:
            with open(hf, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    h = line.rsplit(":", 1)[-1] if username_mode else line
                    if h.lower() in cracked_hashes:
                        n += 1
        except OSError:
            return 0
        return n

    def _write_json(self, path: str, total_accounts: int, unique_total: int,
                    accounts_cracked: int, unique_cracked: int,
                    acct_pct: float, uniq_pct: float, plaintexts: List[str]):
        data = {
            "campaign": self.campaign.name,
            "generated": datetime.now().isoformat(),
            "total_accounts": total_accounts,
            "unique_hashes": unique_total,
            "accounts_cracked": accounts_cracked,
            "accounts_pct": round(acct_pct, 2),
            "unique_passwords_cracked": unique_cracked,
            "unique_pct": round(uniq_pct, 2),
            # Legacy keys (unique-hash basis) retained for back-compatibility.
            "total_hashes": unique_total,
            "cracked": unique_cracked,
            "crack_pct": round(uniq_pct, 2),
            "length_distribution": dict(Counter(len(p) for p in plaintexts)),
            "charset_distribution": dict(Counter(charset_flags(p) for p in plaintexts)),
            "policy_compliance": {
                pid: {
                    "meets": sum(1 for p in plaintexts if pol["check"](p)),
                    "total": len(plaintexts),
                }
                for pid, pol in _POLICIES.items()
            },
            "phases": [
                {
                    "id": p.id,
                    "name": p.name,
                    "type": p.type,
                    "status": p.status,
                    "cracked_delta": p.cracked_delta,
                    "duration_secs": p.duration_secs,
                    "auto_generated": p.auto_generated,
                }
                for p in self.campaign.phases
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


def _fmt_duration(secs: float) -> str:
    h, rem = divmod(int(secs), 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"
