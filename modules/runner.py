"""Hashcat subprocess wrapper — execution, progress parsing, restore, graceful stop."""

import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import logging
from typing import Callable, List, Optional, Tuple

from .campaign import global_potfile_for_type
from .console import Console, MUTED, INFO

_con = Console()

logger = logging.getLogger(__name__)

# Charset flag args whose values should be single-quoted in display output.
_CHARSET_FLAGS = frozenset(("-1", "-2", "-3", "-4"))


def _cmd_for_display(cmd: list) -> str:
    """Format a subprocess args list for human-readable logging.

    Single-quotes the value immediately following any charset flag (-1 through -4)
    so the logged command is safe to copy-paste into a shell.  The actual
    subprocess call is always list-based and never needs shell quoting.
    """
    parts: List[str] = []
    i = 0
    while i < len(cmd):
        arg = str(cmd[i])
        if arg in _CHARSET_FLAGS and i + 1 < len(cmd):
            parts.append(arg)
            i += 1
            parts.append(f"'{cmd[i]}'")   # single-quote the charset value
        else:
            parts.append(arg)
        i += 1
    return " ".join(parts)


def _save_console_mode() -> Optional[int]:
    """Windows only: snapshot the current stdin console input mode flags.

    Returns the mode integer, or None on non-Windows / any error.
    Called before launching any hashcat subprocess so the mode can be
    restored afterward even if hashcat exits abnormally without restoring it.
    """
    try:
        import ctypes, ctypes.wintypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-10)   # STD_INPUT_HANDLE
        mode = ctypes.wintypes.DWORD()
        if k32.GetConsoleMode(h, ctypes.byref(mode)):
            return mode.value
    except Exception:
        pass
    return None


def _restore_console_mode(saved: Optional[int]) -> None:
    """Windows only: restore a previously saved console input mode.

    No-op when `saved` is None (non-Windows or save failed).
    Always swallows exceptions so cleanup never raises.
    """
    if saved is None:
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.GetStdHandle(-10)   # STD_INPUT_HANDLE
        k32.SetConsoleMode(h, saved)
    except Exception:
        pass


def _graceful_stop(proc: subprocess.Popen) -> None:
    """
    Ask hashcat to stop gracefully so it can write its restore checkpoint.

    On Windows, SIGTERM maps to TerminateProcess() — immediate kill, no checkpoint.
    Instead, send Ctrl+C via GenerateConsoleCtrlEvent so hashcat's own signal
    handler fires and writes the restore file before exiting.

    On Linux/macOS, SIGTERM is the standard graceful stop signal for hashcat.
    """
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, proc.pid)  # CTRL_C_EVENT=0
        except Exception:
            proc.terminate()   # fallback
    else:
        proc.send_signal(signal.SIGTERM)

_RECOVERED_RE = re.compile(r"Recovered\.+:\s*(\d+)/(\d+)")
_BENCH_SPEED_TOTAL_RE = re.compile(r"Speed\.#\*\.+:\s*([\d.]+)\s*(GH|MH|kH|H)/s", re.I)
_BENCH_SPEED_GPU_RE   = re.compile(r"Speed\.#\d+\.+:\s*([\d.]+)\s*(GH|MH|kH|H)/s", re.I)
_SPEED_RE = re.compile(r"Speed\.#\*\.+:\s*(.+)")
_SPEED_SINGLE_RE = re.compile(r"Speed\.#\d+\.+:\s*(.+)")
_STATUS_RE = re.compile(r"Status\.+:\s*(\w+)")
_ETA_RE = re.compile(r"Time\.Estimated\.+:.*?\(([^)]+)\)")
_PROGRESS_RE = re.compile(r"Progress\.+:\s*(\d+)/(\d+)")
# Stdin/pipe phases emit "Progress.........: N" with no total — fallback for that format
_PROGRESS_ABS_RE = re.compile(r"Progress\.+:\s*(\d+)")
# Marks the first line of a hashcat status block
_BLOCK_START_RE = re.compile(r"^Session\.+")

# Allow-list: only these lines are worth showing to the user
_SHOW_PATTERNS = [
    re.compile(r"^hashcat \(v"),                            # version line
    re.compile(r"^Hashes:\s+\d+"),                         # "Hashes: 104 digests; ..."
    re.compile(r"^\s*\* (Filename|Passwords|Keyspace|Runtime)"),  # cache summary
    re.compile(r"^All hashes found in potfile"),
    re.compile(r"^Approaching final keyspace"),
    re.compile(r"^(ERROR|WARNING|ATTENTION|NOTICE)", re.I),
    re.compile(r"^[0-9a-fA-F]{32}:"),                      # cracked hash:plain
]

def _should_show(line: str) -> bool:
    return any(p.search(line) for p in _SHOW_PATTERNS)



class ProgressInfo:
    __slots__ = ("recovered", "total", "speed", "status", "eta",
                 "progress_pct", "progress_done")

    def __init__(self):
        self.recovered = 0
        self.total = 0
        self.speed = ""
        self.status = "Starting"
        self.eta = ""
        self.progress_pct = 0.0
        self.progress_done = 0   # absolute candidate count; always populated

    def update_from_line(self, line: str):
        m = _RECOVERED_RE.search(line)
        if m:
            self.recovered = int(m.group(1))
            self.total = int(m.group(2))
        m = _SPEED_RE.search(line) or _SPEED_SINGLE_RE.search(line)
        if m:
            self.speed = m.group(1).strip()
        m = _STATUS_RE.search(line)
        if m:
            self.status = m.group(1)
        m = _ETA_RE.search(line)
        if m:
            self.eta = m.group(1).strip()
        m = _PROGRESS_RE.search(line)
        if m:
            done, total = int(m.group(1)), int(m.group(2))
            self.progress_done = done
            if total > 0:
                self.progress_pct = done / total * 100
        else:
            m = _PROGRESS_ABS_RE.search(line)
            if m:
                self.progress_done = int(m.group(1))
                # progress_pct left at 0.0; caller computes from estimated_keyspace


class HashcatRunner:
    def __init__(
        self,
        hashcat_bin: str,
        hash_file: str,
        hash_type: int,
        potfile: str,
        cracked_file: str,
        sessions_dir: str,
        username_mode: bool = False,
        devices: Optional[str] = None,
        workload: int = 3,
        status_interval: int = 5,
        global_potfile: Optional[str] = None,
    ):
        self.hashcat_bin = hashcat_bin
        # cwd for all hashcat subprocesses — on Windows, hashcat must run from
        # its own directory to find OpenCL kernels and backend DLLs.
        self._hashcat_cwd = os.path.dirname(os.path.abspath(hashcat_bin))
        self.hash_file = hash_file
        self.hash_type = hash_type
        self.potfile = potfile
        self.cracked_file = cracked_file
        self.sessions_dir = sessions_dir
        self.username_mode = username_mode
        self.devices = devices
        self.workload = workload
        self.status_interval = status_interval

        # global_potfile: when set, hashcat uses a shared potfile for cross-campaign
        # deduplication.  The path is made type-specific so NTLM (1000), LM (3000),
        # and any future hash types never share the same file — e.g.
        #   ~/.crackbaby.global  +  hash_type=1000  →  ~/.crackbaby.global_1000.potfile
        #   ~/.crackbaby.global  +  hash_type=3000  →  ~/.crackbaby.global_3000.potfile
        # Derivation is shared with Campaign (global_potfile_for_type) so both
        # always resolve to the identical path.
        self.global_potfile = global_potfile
        if global_potfile:
            self._active_potfile = global_potfile_for_type(global_potfile, hash_type)
        else:
            self._active_potfile = potfile
        self._proc: Optional[subprocess.Popen] = None
        self._stop_requested = False
        self._timed_out = False
        self._line_cache: dict = {}  # path → line count cache, avoids re-reading large files

    # ── Base args ───────────────────────────────────────────────────────────

    def _base_args(self, session: str, optimize_kernel: bool = True) -> List[str]:
        restore_path = os.path.join(self.sessions_dir, f"{session}.restore")
        args = [
            self.hashcat_bin,
            "-m", str(self.hash_type),
            "--potfile-path", self._active_potfile,
            "-o", self.cracked_file,
            "--outfile-format", "2",
            "--session", session,
            "--restore-file-path", restore_path,
            "-w", str(self.workload),
            "--status",
            "--status-timer", str(self.status_interval),
        ]
        if optimize_kernel:
            args.append("-O")
        if self.username_mode:
            args.append("--username")
        if self.devices:
            args.extend(["-d", self.devices])
        return args

    # ── Counting ────────────────────────────────────────────────────────────

    def count_hashes(self) -> int:
        """Count total hashes (lines) in the hash file."""
        try:
            with open(self.hash_file) as f:
                return sum(1 for ln in f if ln.strip())
        except Exception:
            return 0

    def _count_via_hashcat(self, mode_flag: str) -> int:
        """Run hashcat (--show or --left) against the hash file and count the
        non-empty output lines. Raises on failure so callers can apply their own
        fallback; shared by count_cracked and count_left."""
        cmd = [
            self.hashcat_bin, "-m", str(self.hash_type),
            "--potfile-path", self._active_potfile,
            mode_flag, self.hash_file,
        ]
        if self.username_mode:
            cmd.append("--username")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                cwd=self._hashcat_cwd)
        return sum(1 for ln in result.stdout.splitlines() if ln.strip())

    def count_cracked(self) -> int:
        """Ask hashcat how many hashes are cracked (via --show)."""
        if not os.path.exists(self._active_potfile):
            return 0
        try:
            return self._count_via_hashcat("--show")
        except Exception as e:
            logger.warning("count_cracked failed: %s", e)
            return 0

    def count_left(self) -> int:
        """Count remaining uncracked hashes (via --left)."""
        try:
            return self._count_via_hashcat("--left")
        except Exception:
            return self.count_hashes() - self.count_cracked()

    # ── Keyspace estimation ─────────────────────────────────────────────────

    def get_keyspace(self, phase_args: List[str]) -> Optional[int]:
        """
        Compute candidate keyspace for a hashcat phase entirely in Python.

        Covers modes -a 0/1/3/6/7 without subprocess overhead and without
        hashcat --keyspace limitations:
          - -a 1 (combinator): hashcat returns only |wl1|, not |wl1 × wl2|
          - -a 6 (hybrid wl+mask): hashcat returns only |wl|, not |wl × mask_ks|
          - -a 7 (hybrid mask+wl): hashcat returns only mask_ks, not |mask_ks × wl|

        Falls back to hashcat --keyspace for unknown modes or --increment
        (hashcat correctly sums increment lengths for that case).
        """
        from .phases import _mask_keyspace_simple as _mask_keyspace
        _UINT64_MAX = (1 << 64) - 1

        _skip_args = {"--loopback", "--username"}
        filtered = [a for a in phase_args if a not in _skip_args]

        # --increment mode: delegate to hashcat (it sums each length correctly)
        if "--increment" in filtered:
            return self._hashcat_keyspace(filtered)

        # Custom charset definitions (-1..-4): needed to size ?1-?4 in any mask.
        # Values may be hashcat-escaped (e.g. '!@#$%^&*-_+??'); _mask_keyspace
        # resolves them via phases._charset_size.
        custom_charsets = {filtered[i][1]: filtered[i + 1]
                           for i in range(len(filtered) - 1)
                           if filtered[i] in ("-1", "-2", "-3", "-4")} or None

        attack_mode, positionals, rule_files = self._parse_phase_args(filtered)
        if attack_mode is None:
            return None

        try:
            if attack_mode == "0":
                # Wordlist [+ rules]
                if not positionals:
                    return None
                wl = positionals[-1]  # wordlist is always the last positional
                ks = self._count_lines(wl)
                for r in rule_files:
                    ks *= self._count_rules(r)
                return ks

            elif attack_mode == "1":
                # Combinator: wl1 × wl2
                if len(positionals) < 2:
                    return None
                return self._count_lines(positionals[0]) * self._count_lines(positionals[1])

            elif attack_mode == "3":
                # Mask attack or .hcmask file
                if not positionals:
                    return None
                mask_arg = positionals[0]
                if os.path.exists(mask_arg):
                    return self._hcmask_keyspace(mask_arg)  # sum all masks in file
                return _mask_keyspace(mask_arg, custom_charsets)   # inline mask string

            elif attack_mode == "6":
                # Hybrid: wordlist + mask — positionals = [wl, mask]
                if len(positionals) < 2:
                    return None
                wl_count = self._count_lines(positionals[0])
                mask_ks  = _mask_keyspace(positionals[1], custom_charsets)
                return min(wl_count * mask_ks, _UINT64_MAX + 1)

            elif attack_mode == "7":
                # Hybrid: mask + wordlist — positionals = [mask, wl]
                if len(positionals) < 2:
                    return None
                mask_ks  = _mask_keyspace(positionals[0], custom_charsets)
                wl_count = self._count_lines(positionals[1])
                return min(mask_ks * wl_count, _UINT64_MAX + 1)

            else:
                logger.debug("get_keyspace: unknown mode %s, falling back to hashcat", attack_mode)
                return self._hashcat_keyspace(filtered)

        except Exception as e:
            logger.debug("get_keyspace (python) failed: %s — falling back to hashcat", e)
            return self._hashcat_keyspace(filtered)

    def _parse_phase_args(self, args: List[str]) -> Tuple[Optional[str], List[str], List[str]]:
        """
        Parse phase args into (attack_mode, positionals, rule_files).

        positionals are non-flag arguments (wordlists, mask strings, mask files).
        Their meaning is mode-dependent:
          mode 0: [wordlist]
          mode 1: [wl1, wl2]
          mode 3: [mask_or_hcmask_file]
          mode 6: [wordlist, mask]
          mode 7: [mask, wordlist]
        """
        # Flags that consume their next token as a value
        _consuming = {
            "-a", "-r", "--rules-file",
            "--increment-min", "--increment-max",
            "--loopback-wordlists-file",
            "--markov-hcstat2",   # Markov stats file path — not a positional (mask/wordlist)
            "-1", "-2", "-3", "-4",  # custom-charset definitions — value is the charset, not a positional
        }
        attack_mode = None
        rule_files   = []
        positionals  = []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-a" and i + 1 < len(args):
                attack_mode = args[i + 1]
                i += 2
            elif a in ("-r", "--rules-file") and i + 1 < len(args):
                rule_files.append(args[i + 1])
                i += 2
            elif a in _consuming and i + 1 < len(args):
                i += 2  # skip flag + value
            elif a.startswith("-"):
                i += 1  # standalone flag (--loopback, --increment, -O, …)
            else:
                positionals.append(a)
                i += 1
        return attack_mode, positionals, rule_files

    def _count_lines(self, path: str) -> int:
        """
        Count lines in a file using fast binary chunk scan. Cached per instance.

        Uses the same approach as phases._count_file_lines — reads 1 MB chunks
        and counts newline bytes.  Orders of magnitude faster than line-by-line
        text iteration for large wordlists (rockyou2024, crackstation, etc.).
        """
        if path in self._line_cache:
            return self._line_cache[path]
        try:
            count = 0
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    count += chunk.count(b"\n")
            self._line_cache[path] = max(count, 1)
        except OSError:
            self._line_cache[path] = 1
        return self._line_cache[path]

    def _hcmask_keyspace(self, mask_file: str) -> int:
        """
        Sum the keyspaces of every non-comment mask in an .hcmask file.
        Returns the total (capped at _UINT64_MAX + 1 if it overflows).
        Falls back to hashcat --keyspace if the file cannot be parsed.
        """
        # Use the phases helper per line: it splits the inline "cs,,,,mask" prefix
        # and sizes ?1 from it, so custom-charset masks are counted correctly
        # (a bare "_mask_keyspace(line)" would treat the prefix as literals).
        from .phases import _hcmask_keyspace as _line_keyspace
        _UINT64_MAX = (1 << 64) - 1
        try:
            total = 0
            with open(mask_file, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    total += _line_keyspace(line)
                    if total > _UINT64_MAX:
                        return _UINT64_MAX + 1
            return total if total > 0 else 0
        except Exception as e:
            logger.debug("_hcmask_keyspace failed for %s: %s — using hashcat", mask_file, e)
            return self._hashcat_keyspace(["-a", "3", mask_file]) or 0

    def _hashcat_keyspace(self, filtered_args: List[str]) -> Optional[int]:
        """Fallback: run hashcat --keyspace and parse the integer result."""
        cmd = [self.hashcat_bin, "--keyspace", "-m", str(self.hash_type)] + filtered_args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                                    cwd=self._hashcat_cwd)
            for line in (result.stdout + result.stderr).splitlines():
                line = line.strip()
                if line.isdigit():
                    return int(line)
        except Exception as e:
            logger.debug("_hashcat_keyspace failed: %s", e)
        return None

    def _count_rules(self, rule_path: str) -> int:
        """Count effective rules in a hashcat rule file (excludes blank lines and comments)."""
        try:
            count = 0
            with open(rule_path, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        count += 1
            return max(count, 1)
        except Exception:
            return 1  # unreadable → assume 1 rule (no change to estimate)

    # ── Execution ───────────────────────────────────────────────────────────

    def run(
        self,
        phase_args: List[str],
        session: str,
        log_path: str,
        on_progress: Optional[Callable[[ProgressInfo], None]] = None,
        on_line: Optional[Callable[[str], None]] = None,
        dry_run: bool = False,
        timeout_secs: Optional[int] = None,
        optimize_kernel: bool = True,
    ) -> Tuple[int, str]:
        """
        Execute one hashcat phase.  Resumes automatically if a restore file
        exists for this session.  Returns (exit_code, status_string).

        on_progress is called once per complete status block (every --status-timer secs).
        on_line is called for every non-status line (startup info, cracked notifications).
        optimize_kernel controls whether -O is passed to hashcat.  Disable for phases
        whose candidates may exceed 31 chars (combinators, combo_rules, passphrases).
        """
        os.makedirs(self.sessions_dir, exist_ok=True)
        restore_path = os.path.join(self.sessions_dir, f"{session}.restore")

        if os.path.exists(restore_path):
            cmd = [
                self.hashcat_bin,
                "--restore",
                "--session", session,
                "--restore-file-path", restore_path,
                "--status", "--status-timer", str(self.status_interval),
            ]
            _con.note(f"Resuming session {session}")
        else:
            cmd = self._base_args(session, optimize_kernel=optimize_kernel) + [self.hash_file] + phase_args

        logger.debug("CMD: %s", _cmd_for_display(cmd))

        if dry_run:
            _con.print(f"  {_con.paint('[dry-run]', MUTED)} "
                       f"{_con.paint(' '.join(str(a) for a in cmd), INFO)}")
            return 0, "dry_run"

        self._stop_requested = False
        self._timed_out = False
        info = ProgressInfo()

        _timer = None
        if timeout_secs:
            def _on_timeout():
                self._timed_out = True
                logger.info("Phase timeout reached (%ds) — stopping", timeout_secs)
                self.stop()
            _timer = threading.Timer(timeout_secs, _on_timeout)
            _timer.start()

        _saved_console = _save_console_mode()
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "w", encoding="utf-8", errors="replace") as log_f:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    cwd=self._hashcat_cwd,
                )
                self._proc = proc

                in_block = False
                try:
                    for raw_line in proc.stdout:
                        # Split on \r: hashcat uses carriage returns for in-place
                        # progress (cache building, autotune) so one read() chunk
                        # can contain many "frames". We want the last non-empty
                        # frame for logging, and parse all of them for status data.
                        parts = raw_line.decode("utf-8", errors="replace").split("\r")
                        parts = [p.rstrip("\n") for p in parts]

                        # Log the last non-empty frame (final state of any \r line)
                        log_line = next((p for p in reversed(parts) if p.strip()), "")
                        if log_line:
                            log_f.write(log_line + "\n")
                            log_f.flush()

                        for line in parts:
                            line = line.strip()
                            if not line:
                                continue

                            info.update_from_line(line)

                            if _BLOCK_START_RE.match(line):
                                in_block = True

                            if in_block:
                                # Blank line signals end of status block — but we
                                # stripped blanks above, so detect block end when
                                # we see the next non-block line after block starts.
                                # Actually rely on the outer empty-part check below.
                                pass
                            else:
                                if _should_show(line) and on_line:
                                    on_line(line)

                        # A genuine blank line (no \r frames, just "\n") ends the block
                        if in_block and not any(p.strip() for p in parts):
                            in_block = False
                            if on_progress:
                                on_progress(info)

                        if self._stop_requested:
                            _graceful_stop(proc)
                            try:
                                proc.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                            break

                except KeyboardInterrupt:
                    # On Windows (and in rare POSIX race conditions), Ctrl+C raises
                    # KeyboardInterrupt in the main thread during blocking I/O before
                    # the SIGINT signal handler has a chance to run.  Catch it here,
                    # stop hashcat cleanly, and fall through to the normal return path
                    # so that _phase_finish (speed history recording, phase state save)
                    # always executes in the calling phase handler.
                    self._stop_requested = True
                    _graceful_stop(proc)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()

                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()

                self._proc = None

        except Exception as e:
            logger.error("run() exception: %s", e)
            return -1, "error"
        finally:
            if _timer:
                _timer.cancel()
            _restore_console_mode(_saved_console)

        rc = proc.returncode
        # hashcat exit codes: 0=ok/cracked, 1=no candidates cracked, 2=quit,
        # 3=fatal, 255=error
        if self._timed_out:
            return rc, "timed_out"
        if self._stop_requested:
            return rc, "interrupted"
        if rc in (0, 1):
            return rc, "completed"
        if rc == 2:
            return rc, "interrupted"
        return rc, "failed"

    def run_piped(
        self,
        generator_cmd: Optional[List[str]],
        phase_args: List[str],
        session: str,
        log_path: str,
        on_progress: Optional[Callable[[ProgressInfo], None]] = None,
        on_line: Optional[Callable[[str], None]] = None,
        dry_run: bool = False,
        timeout_secs: Optional[int] = None,
        python_feeder: Optional[Callable] = None,
        optimize_kernel: bool = True,
    ) -> Tuple[int, str]:
        """
        Execute a piped phase: generator stdout → hashcat stdin.

        Two modes:
          generator_cmd  — launch an external process; its stdout is piped to hashcat stdin.
                           Used for combinator.bin (hashcat's wl×wl combinator) and
                           similar pipe-based generators.
          python_feeder  — a callable(writable_binary_pipe) that writes candidates and
                           returns when done.  hashcat uses stdin=PIPE; a daemon thread
                           runs the feeder.  generator_cmd must be None in this mode.
                           Used for combo_rules (Python cartesian product, avoids
                           `hashcat -a 1 --stdout` which segfaults on large wordlists).

        Returns (exit_code, status_string) same as run().
        The generator/feeder is cleaned up when hashcat exits or the phase is stopped.
        """
        # Exactly one candidate source must be supplied. Guard here so a misuse
        # surfaces as a clear error rather than an opaque Popen(None) crash later.
        if (generator_cmd is None) == (python_feeder is None):
            raise ValueError(
                "run_piped requires exactly one of generator_cmd or python_feeder"
            )

        # hashcat v7 replaced --stdin with --stdin-timeout-abort <secs>.
        # --stdin is a prefix of --stdin-timeout-abort, so GNU getopt matches it to
        # the new flag and then errors "requires an argument" when nothing follows.
        # Translate for backward compat with existing campaign.json phases.
        _patched_args = []
        for _a in phase_args:
            if _a == "--stdin":
                _patched_args.extend(["--stdin-timeout-abort", "86400"])
            else:
                _patched_args.append(_a)
        phase_args = _patched_args

        if dry_run:
            gen_str = (" ".join(str(a) for a in generator_cmd)
                       if generator_cmd else "[python generator]")
            hc_str  = " ".join(str(a) for a in
                                self._base_args(session, optimize_kernel=optimize_kernel)
                                + phase_args + [self.hash_file])
            _con.print(f"  {_con.paint('[dry-run]', MUTED)} "
                       f"{_con.paint(f'{gen_str} | {hc_str}', INFO)}")
            return 0, "dry_run"

        os.makedirs(self.sessions_dir, exist_ok=True)
        # Hash file comes LAST so hashcat sees attack-mode and stdin flags before
        # the positional hash-file argument — required for correct v7 argument parsing.
        cmd = self._base_args(session, optimize_kernel=optimize_kernel) + phase_args + [self.hash_file]
        gen_desc = (" ".join(str(a) for a in generator_cmd)
                    if generator_cmd else "[python generator]")
        logger.debug("PIPED CMD: %s | %s", gen_desc, _cmd_for_display(cmd))

        self._stop_requested = False
        self._timed_out = False
        info = ProgressInfo()

        _timer = None
        if timeout_secs:
            def _on_timeout():
                self._timed_out = True
                logger.info("Phase timeout reached (%ds) — stopping piped phase", timeout_secs)
                self.stop()
            _timer = threading.Timer(timeout_secs, _on_timeout)
            _timer.start()

        gen_proc = None
        _feeder_thread = None
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "w", encoding="utf-8", errors="replace") as log_f:
                if python_feeder is not None:
                    proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        cwd=self._hashcat_cwd,
                    )
                    def _feeder_fn(_pipe=proc.stdin, _fn=python_feeder):
                        try:
                            _fn(_pipe)
                        except BrokenPipeError:
                            pass  # hashcat exited early (cracked all, timeout, stop)
                        except Exception as _fe:
                            logger.warning("python_feeder error: %s", _fe)
                        finally:
                            try:
                                _pipe.close()
                            except OSError:
                                pass
                    _feeder_thread = threading.Thread(target=_feeder_fn, daemon=True)
                    _feeder_thread.start()
                else:
                    gen_proc = subprocess.Popen(
                        generator_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    )
                    proc = subprocess.Popen(
                        cmd,
                        stdin=gen_proc.stdout,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        cwd=self._hashcat_cwd,
                    )
                    # Allow gen_proc to receive SIGPIPE if proc exits early
                    gen_proc.stdout.close()
                self._proc = proc

                in_block = False
                try:
                    for raw_line in proc.stdout:
                        parts = raw_line.decode("utf-8", errors="replace").split("\r")
                        parts = [p.rstrip("\n") for p in parts]

                        log_line = next((p for p in reversed(parts) if p.strip()), "")
                        if log_line:
                            log_f.write(log_line + "\n")
                            log_f.flush()

                        for line in parts:
                            line = line.strip()
                            if not line:
                                continue
                            info.update_from_line(line)
                            if _BLOCK_START_RE.match(line):
                                in_block = True
                            if not in_block:
                                if _should_show(line) and on_line:
                                    on_line(line)

                        if in_block and not any(p.strip() for p in parts):
                            in_block = False
                            if on_progress:
                                on_progress(info)

                        if self._stop_requested:
                            _graceful_stop(proc)
                            try:
                                proc.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                            break

                except KeyboardInterrupt:
                    # Ctrl+C on Windows (and rare POSIX races) raises KeyboardInterrupt
                    # during blocking I/O before the signal handler runs.  Catch here so
                    # _phase_finish always executes and speed history is recorded.
                    self._stop_requested = True
                    _graceful_stop(proc)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()

                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()

                self._proc = None

        except Exception as e:
            logger.error("run_piped() exception: %s", e)
            return -1, "error"
        finally:
            if _timer:
                _timer.cancel()
            if _feeder_thread is not None:
                # hashcat is done/killed; closing stdin unblocks the feeder if it's
                # still writing, causing BrokenPipeError which the thread catches.
                try:
                    proc.stdin.close()
                except OSError:
                    pass
                _feeder_thread.join(timeout=2.0)
            elif gen_proc is not None and gen_proc.poll() is None:
                # Kill the subprocess generator if still running
                try:
                    gen_proc.kill()
                except Exception:
                    pass

        rc = proc.returncode
        if self._timed_out:
            return rc, "timed_out"
        if self._stop_requested:
            return rc, "interrupted"
        if rc in (0, 1):
            return rc, "completed"
        if rc == 2:
            return rc, "interrupted"
        return rc, "failed"

    def stop(self):
        """Request a graceful stop of the currently running phase."""
        self._stop_requested = True
        if self._proc and self._proc.poll() is None:
            _graceful_stop(self._proc)

    # ── Potfile helpers ─────────────────────────────────────────────────────

    def get_lm_cracked_words(self, lm_hash_file: str,
                             lm_potfile: Optional[str] = None) -> List[str]:
        """
        Run `hashcat --show -m 3000` against the LM hash file and return the
        cracked plaintext halves.  Returns an empty list if nothing cracked yet.

        ``lm_potfile`` must point to the LM-specific potfile (e.g.
        ``campaign.active_lm_potfile`` → ``crackbaby_3000.potfile`` or the global
        ``~/.crackbaby.global_3000.potfile``).  LM results are NEVER stored in the
        NTLM potfile, so callers must always supply this argument — the default
        (``self._active_potfile``) is retained only for backward compatibility.
        """
        _pot = lm_potfile or self._active_potfile
        if not os.path.exists(_pot):
            return []
        try:
            cmd = [
                self.hashcat_bin, "-m", "3000",
                "--potfile-path", _pot,
                "--show", lm_hash_file,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                    cwd=self._hashcat_cwd)
            words: set = set()
            for line in result.stdout.splitlines():
                if ":" in line:
                    pt = line.split(":", 1)[1].strip()
                    # Skip partially-cracked LM passwords: hashcat prints "[notfound]"
                    # for an uncracked 7-char half, which is not a usable plaintext.
                    if pt and "[notfound]" not in pt:
                        words.add(pt)
            return list(words)
        except Exception as e:
            logger.warning("get_lm_cracked_words failed: %s", e)
            return []

    def _campaign_hash_filter(self) -> Optional[set]:
        """Return a set of lowercase NT hashes for this campaign, or None.

        Used to scope a shared global potfile down to only this campaign's hashes
        so cracks from other campaigns sharing the file never leak into analysis.
        Returns None when no global potfile is in use — the campaign-local potfile
        already contains only this campaign's hashes, so no filtering is needed.
        (Mirrors reporter._load_campaign_hashes.)

        Username-mode lines (``user:HASH`` / pwdump ``user:rid:LM:NT:::``) are
        normalized to the LAST colon-separated field — the same rule hashcat
        applies under --username — and lowercased for case-insensitive matching.
        """
        if not self.global_potfile:
            return None
        hashes: set = set()
        try:
            with open(self.hash_file, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    hashes.add(line.split(":")[-1].lower() if ":" in line
                               else line.lower())
        except OSError:
            return None  # hash file unreadable — fall back to no filtering
        return hashes

    def read_plaintexts(self) -> List[str]:
        """Return plaintext passwords from the potfile.

        When a global potfile is in use the results are filtered to this
        campaign's own hashes (see _campaign_hash_filter); otherwise every
        plaintext in the campaign-local potfile is returned.
        """
        if not os.path.exists(self._active_potfile):
            return []
        hash_filter = self._campaign_hash_filter()
        plaintexts = []
        with open(self._active_potfile, errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if ":" not in line:
                    continue
                # NT hash is 32 hex chars; split at position 32 if possible
                # otherwise split on first colon (keeps ':' inside plaintexts intact).
                if len(line) > 33 and line[32] == ":":
                    nt_hash, plaintext = line[:32], line[33:]
                else:
                    nt_hash, plaintext = line.split(":", 1)
                if hash_filter is not None and nt_hash.lower() not in hash_filter:
                    continue  # belongs to another campaign in the shared global potfile
                plaintexts.append(plaintext)
        return plaintexts

    def benchmark_speed(self) -> Optional[float]:
        """
        Run `hashcat --benchmark -m {hash_type}` and return measured GH/s.
        Returns None on failure or if speed cannot be parsed.
        """
        cmd = [self.hashcat_bin, "--benchmark", "-m", str(self.hash_type)]
        if self.devices:
            cmd.extend(["-d", self.devices])
        logger.debug("Benchmark CMD: %s", _cmd_for_display(cmd))
        _saved_console = _save_console_mode()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                                    cwd=self._hashcat_cwd)
            output = result.stdout + result.stderr

            def _to_ghs(value: str, unit: str) -> float:
                v = float(value)
                u = unit.upper()
                if u == "GH":  return v
                if u == "MH":  return v / 1_000
                if u == "KH":  return v / 1_000_000
                return v / 1_000_000_000  # H/s

            # Prefer the combined Speed.#* line
            m = _BENCH_SPEED_TOTAL_RE.search(output)
            if m:
                return _to_ghs(m.group(1), m.group(2))

            # Fall back to summing per-GPU lines
            total = 0.0
            found = False
            for m in _BENCH_SPEED_GPU_RE.finditer(output):
                total += _to_ghs(m.group(1), m.group(2))
                found = True
            if found:
                return total

        except Exception as e:
            logger.warning("benchmark_speed failed: %s", e)
        finally:
            _restore_console_mode(_saved_console)
        return None

    def verify_binary(self) -> bool:
        """Return True if hashcat binary is executable."""
        _saved_console = _save_console_mode()
        try:
            r = subprocess.run(
                [self.hashcat_bin, "--version"],
                capture_output=True, text=True, timeout=10,
                cwd=self._hashcat_cwd,
            )
            return r.returncode == 0
        except Exception:
            return False
        finally:
            _restore_console_mode(_saved_console)
