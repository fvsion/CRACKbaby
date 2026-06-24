"""Speed & timing model for crackbaby.

  * speed-factor persistence      (config/speed_factors.json — shipped ratios)
  * per-type speed resolution      (_phase_speed_ghs — static ratio × expected_speed_ghs)
  * ETA estimation & speed format  (_estimate_eta / _fmt_speed)
  * time-gating                    (_time_gate — evaluated once at init; no auto-reapply)
  * benchmark calibration          (_run_per_type_benchmark)

ETAs are purely static: every estimate is expected_speed_ghs scaled by a fixed per-type
ratio from speed_factors.json. Nothing auto-adjusts from measured run speed — the only way
to change ETAs is the `benchmark` command (--set / --update / --update-all).
"""

import json
import logging
import os
import re
import subprocess
from typing import Optional

from . import CONFIG_DIR as _CONFIG_DIR
from .campaign import Campaign, Phase
from .console import Console, ACCENT, INFO, MUTED

_con = Console()

logger = logging.getLogger(__name__)


# ── Speed factors (shipped per-type ratios) ───────────────────────────────────

_SPEED_FACTORS_FILE = os.path.join(_CONFIG_DIR, "speed_factors.json")

_SPEED_FACTORS_CACHE: Optional[dict] = None   # loaded once per process

# Bootstrap ratios — written to config/speed_factors.json on first run if absent.
# Values are fractions of campaign.expected_speed_ghs.
# Use 'crackbaby benchmark --update-all' to replace with measured GH/s values.
_SPEED_FACTORS_BOOTSTRAP: dict = {
    "_note": (
        "Per-type speed ratios (fraction of expected_speed_ghs). "
        "Edit to tune for your rig. "
        "Run 'crackbaby benchmark --update-all' to overwrite with measured values."
    ),
    "brute":              1.00,
    "mask":               1.00,
    "wordlist":           0.90,
    "rules":              0.16,
    "hybrid":             0.80,
    "combinator":         0.95,
    "combo_rules_rule":   0.65,   # rule-convert strategy — fully on GPU
    "combo_rules_combinator_bin": 0.08,  # combinator.bin pipe — stdin-limited fallback
    "lm_brute":           1.00,
    "lm_toggle":          0.16,
}


def _load_speed_factors() -> dict:
    """Load per-type ratios or absolute GH/s from speed_factors.json.

    Returns an empty dict when the file does not exist (first run / no calibration).
    Bootstraps the file if absent.
    """
    global _SPEED_FACTORS_CACHE
    if _SPEED_FACTORS_CACHE is not None:
        return _SPEED_FACTORS_CACHE
    try:
        with open(_SPEED_FACTORS_FILE) as _f:
            data = json.load(_f)
        if isinstance(data, dict):
            _SPEED_FACTORS_CACHE = data
            return _SPEED_FACTORS_CACHE
    except (OSError, json.JSONDecodeError):
        pass
    # Bootstrap on first run
    _SPEED_FACTORS_CACHE = dict(_SPEED_FACTORS_BOOTSTRAP)
    try:
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        with open(_SPEED_FACTORS_FILE, "w") as _f:
            json.dump(_SPEED_FACTORS_CACHE, _f, indent=2)
    except OSError:
        pass
    return _SPEED_FACTORS_CACHE


def _save_speed_factors(factors: dict):
    """Write speed_factors.json to the config directory."""
    global _SPEED_FACTORS_CACHE
    _SPEED_FACTORS_CACHE = None   # invalidate cache so next lookup reloads
    try:
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        with open(_SPEED_FACTORS_FILE, "w") as _f:
            json.dump(factors, _f, indent=2)
    except OSError as _e:
        logger.warning("Could not save speed_factors.json: %s", _e)


# ── Speed sample parsing ──────────────────────────────────────────────────────

def _parse_speed_hps(speed_str: str) -> float:
    """Parse a hashcat speed string (e.g. '20.0 GH/s', '500 MH/s') to hashes/second.
    Returns 0.0 on parse failure."""
    m = re.match(r"([\d.]+)\s*(TH|GH|MH|kH|H)/s", speed_str.strip(), re.I)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = m.group(2).upper()
    return val * {"TH": 1e12, "GH": 1e9, "MH": 1e6, "KH": 1e3, "H": 1.0}.get(unit, 1.0)


# ── Per-type speed resolution ─────────────────────────────────────────────────

def _phase_speed_key(phase: Phase, campaign: Campaign) -> str:
    """Return the speed_factors lookup key for a phase.

    combo_rules encodes the strategy: 'combo_rules_rule' or
    'combo_rules_combinator_bin' based on phase.combo_strategy.
    All other phases return phase.type unchanged.
    """
    if phase.type == "combo_rules":
        strategy = phase.combo_strategy or "rule_convert"
        if strategy == "rule_convert":
            return "combo_rules_rule"
        return "combo_rules_combinator_bin"
    return phase.type


def _phase_speed_ghs(phase_type: str, campaign: Campaign) -> float:
    """Return the static GH/s estimate for a given phase type.

    Single source of truth: speed_factors.json in the config dir. Each entry is either
    a ratio (≤ 1000, multiplied by campaign.expected_speed_ghs) or an absolute GH/s value
    (> 1000, written by `benchmark --update-all`). Unknown types fall back to 10% of
    expected speed. No measured-run history feeds back in — ETAs change only when
    `benchmark` updates expected_speed_ghs or speed_factors.json.
    """
    factors = _load_speed_factors()
    if phase_type in factors and isinstance(factors[phase_type], (int, float)):
        val = float(factors[phase_type])
        # Values > 1000 are assumed to be absolute GH/s (written by benchmark);
        # values ≤ 1000 are ratios multiplied by expected_speed_ghs.
        return val if val > 1000 else campaign.expected_speed_ghs * val

    # Fallback: 10% of expected speed for unrecognised types
    return campaign.expected_speed_ghs * 0.10


def _effective_speed_ghs(phase: Phase, campaign: Campaign) -> float:
    """Return the best available GH/s estimate for a phase."""
    return _phase_speed_ghs(_phase_speed_key(phase, campaign), campaign)


# ── ETA & speed formatting ────────────────────────────────────────────────────

def _estimate_eta(keyspace: int, speed_ghs: float) -> str:
    if not speed_ghs or speed_ghs <= 0:
        return "?"
    secs = keyspace / (speed_ghs * 1e9)
    if secs < 60:
        return "<1m"
    if secs < 3600:
        return f"~{secs/60:.0f}m"
    if secs < 86400:
        return f"~{secs/3600:.1f}h"
    return f"~{secs/86400:.1f}d"


def _fmt_speed(ghs: float) -> str:
    """Format a GH/s value for display. Sub-1 GH/s shown as MH/s."""
    if ghs <= 0:
        return "? GH/s (run benchmark)"
    if ghs >= 1.0:
        return f"{ghs:.1f} GH/s"
    return f"{ghs * 1000:.0f} MH/s"


def _phase_estimated_hours(phase, campaign) -> "Optional[float]":
    """Estimate wall-clock hours to complete a phase using per-type GPU speed."""
    if not phase.estimated_keyspace:
        return None
    spd = _phase_speed_ghs(_phase_speed_key(phase, campaign), campaign)
    if spd <= 0:
        return None
    return phase.estimated_keyspace / (spd * 1_000_000_000) / 3_600


# ── Time gating ───────────────────────────────────────────────────────────────

def _time_gate(phase: Phase, speed_ghs_or_campaign, threshold_hours: Optional[float]) -> None:
    """Pre-skip a phase at init time if its estimated runtime exceeds threshold_hours.

    `speed_ghs_or_campaign` may be a float GH/s OR a Campaign object.
    When a Campaign is passed, the per-type speed is resolved via _phase_speed_ghs.
    Modifies phase.status and phase.notes in place.
    No-op when threshold_hours is None or estimated_keyspace is unset.
    """
    if not threshold_hours or not phase.estimated_keyspace:
        return
    if isinstance(speed_ghs_or_campaign, (int, float)):
        speed_ghs = float(speed_ghs_or_campaign)
    else:
        speed_ghs = _phase_speed_ghs(
            _phase_speed_key(phase, speed_ghs_or_campaign), speed_ghs_or_campaign
        )
    if speed_ghs <= 0:
        return
    est_hours = phase.estimated_keyspace / (speed_ghs * 1e9) / 3600
    if est_hours > threshold_hours:
        phase.status = "skipped"
        phase.notes = (
            f"Time-gated at init: est. {est_hours:.1f}h "
            f"> {threshold_hours}h threshold @ {speed_ghs:.1f} GH/s. "
            f"Restore with: python crackbaby.py skip --unskip {phase.id}"
        )


# ── Benchmark calibration ─────────────────────────────────────────────────────

def _run_per_type_benchmark(campaign, runner, benchmark_ghs: float):
    """Run 20-second test attacks for each phase type and write speed_factors.json.

    Called by `crackbaby benchmark --update-all`.  Requires a valid hash file and
    hashcat binary.  Writes absolute GH/s values per type so ETA calculations
    don't depend on the raw benchmark anymore.
    """
    import shutil as _sh

    _BENCH_SECS = 20

    factors = _load_speed_factors()
    factors["_benchmark_ghs"] = round(benchmark_ghs, 4)

    _con.blank()
    _con.rule("Per-type speed calibration")
    _con.note(f"Running {_BENCH_SECS}-second test attacks for each phase type…")

    from .phases import find_rule
    _best66 = find_rule(campaign.custom_rules_dir, "best66.rule")

    _bench_wl = next((w for w in campaign.wordlists if os.path.exists(w)), None)
    _td = None
    if not _bench_wl:
        import tempfile as _tmp
        _td = _tmp.mkdtemp(prefix="crackbaby_bench_")
        _bench_wl = os.path.join(_td, "tiny.txt")
        with open(_bench_wl, "w") as _f:
            for _w in ["password", "Password1!", "Summer2024", "admin", "letmein",
                       "Welcome1", "Monday1!", "Qwerty123", "dragon", "iloveyou"]:
                _f.write(_w + "\n")

    _type_tests: list = [
        ("brute",    ["-a", "3", "?a?a?a?a?a?a"]),
        ("wordlist", ["-a", "0", _bench_wl]),
    ]
    if _best66:
        _type_tests += [
            ("rules", ["-a", "0", "-r", _best66, _bench_wl]),
        ]

    try:
        for _type, _args in _type_tests:
            try:
                _result = subprocess.run(
                    [campaign.hashcat_bin, "-m", str(campaign.hash_type),
                     "--potfile-disable", "--status", "--status-timer", "2",
                     "--runtime", str(_BENCH_SECS),
                     campaign.hash_file] + _args,
                    capture_output=True, text=True, timeout=_BENCH_SECS + 15,
                    cwd=os.path.dirname(campaign.hashcat_bin) or None,
                )
                _out = _result.stdout + _result.stderr
                _sp_ghs = None
                for _line in _out.splitlines():
                    if "Speed.#" in _line or "Speed.:" in _line or "Speed " in _line:
                        _m = re.search(r"([\d.]+)\s*(GH|MH|kH|H)/s", _line)
                        if _m:
                            _v, _u = float(_m.group(1)), _m.group(2).upper()
                            if _u == "GH":   _sp_ghs = _v
                            elif _u == "MH": _sp_ghs = _v / 1_000
                            elif _u == "KH": _sp_ghs = _v / 1_000_000
                            else:            _sp_ghs = _v / 1_000_000_000
                            break
                if _sp_ghs and _sp_ghs > 0:
                    factors[_type] = round(_sp_ghs, 4)
                    _u2, _v2 = ("GH/s", _sp_ghs) if _sp_ghs >= 1 else ("MH/s", _sp_ghs * 1000)
                    _con.print(f"  {_con.paint('  ' + _type.ljust(12), MUTED)} "
                               f"{_con.paint(f'{_v2:.1f} {_u2}', ACCENT)}")
                else:
                    _con.print(f"  {_con.paint('  ' + _type.ljust(12), MUTED)} "
                               f"{_con.paint('(could not parse speed — keeping default)', MUTED)}")
            except Exception as _e:
                _con.print(f"  {_con.paint('  ' + _type.ljust(12), MUTED)} "
                           f"{_con.paint(f'(error: {_e})', MUTED)}")

    finally:
        if _td:
            try:
                _sh.rmtree(_td)
            except Exception:
                pass

    _save_speed_factors(factors)
    _con.blank()
    _con.ok(f"speed_factors.json written to: {_con.paint(_SPEED_FACTORS_FILE, INFO)}")
    _con.note("These values are now used for ETA calculations across all campaigns.")
