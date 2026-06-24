"""Terminal output styling for CRACKbaby.

A single, stdlib-only place for everything CRACKbaby draws to the terminal:
colour, section rules, key/value blocks, bullet lists, status badges, bordered
panels, aligned tables, and the in-place live-status redraw used during runs.

Design rules (keep these intact when extending):

* **Stdlib only.**  Colour is raw ANSI SGR — no ``rich``/``colorama``.  Works on
  Python 3.8+.
* **Portable 16-colour palette.**  Roles map to the 16 standard ANSI colours so
  the user's own terminal theme remaps them; output looks right on light *and*
  dark backgrounds.
* **Colour auto-degrades.**  A :class:`Console` only emits colour when its stream
  is a TTY *and* ``NO_COLOR`` is unset *and* ``TERM`` isn't ``dumb`` *and* colour
  wasn't disabled with :func:`set_color_enabled`.  ``FORCE_COLOR`` /
  ``CLICOLOR_FORCE`` force it on (useful for screen recordings).  A console bound
  to a file is therefore plain automatically — no ANSI ever lands in
  ``report.txt``.
* **Layout before paint.**  All width / truncation maths is done on *plain* text;
  colour is applied last and painted strings are treated as atomic (never sliced).
  :func:`visible_len` measures display width by stripping SGR codes.
"""

import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple, Union

# Standard 2-space left margin every block uses (matches CRACKbaby's house style).
IND = "  "

# ── Colour roles → ANSI SGR codes (portable 16-colour set) ───────────────────
# Each role is a tuple of SGR parameter strings; paint() joins them with ";".
RESET = "\033[0m"

ACCENT = ("92",)   # bright green  — commands, recovered values, highlights
INFO   = ("96",)   # bright cyan   — informational values, paths
MUTED  = ("90",)   # bright black  — labels, secondary text, borders
WARN   = ("93",)   # bright yellow — warnings
ERR    = ("91",)   # bright red    — errors
OK     = ("92",)   # bright green  — success
BOLD   = ("1",)    # bold          — titles (combine with a colour)
TITLE  = ("1", "96")  # bold cyan  — section / panel titles

_SGR_RE = re.compile(r"\033\[[0-9;]*m")


def visible_len(s: str) -> int:
    """Display width of ``s`` ignoring any ANSI SGR escape sequences."""
    return len(_SGR_RE.sub("", s))


def strip_ansi(s: str) -> str:
    """Return ``s`` with all ANSI SGR escape sequences removed."""
    return _SGR_RE.sub("", s)


# ── Global colour gate ────────────────────────────────────────────────────────
# ``None`` = auto-detect per stream; True/False = forced (e.g. --no-color).
_COLOR_OVERRIDE: Optional[bool] = None


def set_color_enabled(enabled: Optional[bool]) -> None:
    """Force colour on/off globally, or pass ``None`` to restore auto-detection."""
    global _COLOR_OVERRIDE
    _COLOR_OVERRIDE = enabled


def _stream_auto_color(stream) -> bool:
    """Stream-based colour decision (env + isatty), ignoring the global override."""
    if os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE"):
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


# ── Status badges (single source of truth) ───────────────────────────────────

@dataclass(frozen=True)
class Badge:
    """Display attributes for a phase status: a fixed-width tag, a glyph, a role."""
    tag: str           # fixed 5-char tag for table columns, e.g. "[OK] "
    symbol: str        # single glyph for compact lines, e.g. "✓"
    role: Tuple[str, ...]  # colour role


# Maps Phase.status → Badge.  Replaces the formerly-duplicated dicts in
# crackbaby.py (_print_phase_list, _print_run_summary) and reporter.py.
STATUS = {
    "pending":     Badge("     ", "·", MUTED),
    "running":     Badge("[RUN]", "►", ACCENT),
    "completed":   Badge("[OK] ", "✓", OK),
    "failed":      Badge("[ERR]", "✗", ERR),
    "skipped":     Badge("[SKP]", "–", MUTED),
    "interrupted": Badge("[INT]", "⏸", WARN),
    "timed_out":   Badge("[TMO]", "⏱", WARN),
    "dry_run":     Badge("[DRY]", "·", MUTED),
}

_DEFAULT_BADGE = Badge("     ", "·", MUTED)


def badge_for(status: str) -> Badge:
    """Return the :class:`Badge` for a phase status (never raises)."""
    return STATUS.get(status, _DEFAULT_BADGE)


# ── Box-drawing character sets ────────────────────────────────────────────────

@dataclass(frozen=True)
class _BoxChars:
    tl: str; tr: str; bl: str; br: str; h: str; v: str


_LIGHT = _BoxChars("┌", "┐", "└", "┘", "─", "│")
_HEAVY = _BoxChars("╔", "╗", "╚", "╝", "═", "║")


# A cell is either plain text (uses the column's default role) or a
# (text, role) pair that overrides the colour for that one cell.
Cell = Union[str, Tuple[str, Tuple[str, ...]]]


class Console:
    """The single surface CRACKbaby prints through.

    Owns an output stream, a colour gate (derived from that stream), and a
    detected terminal width.  Bind one to ``sys.stdout`` for interactive output,
    or to a file handle to get guaranteed-plain text (e.g. ``report.txt``).
    """

    def __init__(self, stream=None, *, width: Optional[int] = None):
        self.stream = stream if stream is not None else sys.stdout
        self._auto_color = _stream_auto_color(self.stream)
        try:
            self.is_tty = bool(self.stream.isatty())
        except Exception:
            self.is_tty = False
        if width is not None:
            self.width = width
        else:
            cols = shutil.get_terminal_size((100, 24)).columns
            self.width = max(80, min(cols, 120))

    @property
    def color(self) -> bool:
        """Whether this console emits ANSI colour right now.

        Consults the global override (set by ``--no-color`` / ``set_color_enabled``)
        live, so toggling it affects already-constructed consoles without a rebuild;
        otherwise falls back to the cached stream-based decision.
        """
        if _COLOR_OVERRIDE is not None:
            return _COLOR_OVERRIDE
        return self._auto_color

    # ── core paint / emit ────────────────────────────────────────────────────

    def paint(self, text: str, *roles: Tuple[str, ...]) -> str:
        """Wrap ``text`` in the SGR codes for ``roles`` (no-op when colour off).

        Each role is a *tuple* of SGR code strings (e.g. ``ACCENT`` or ``TITLE``);
        pass roles as whole tuples — never splat one with ``*`` (that would feed
        the individual characters of a code in as separate roles).
        """
        if not self.color:
            return text
        codes = ";".join(code for role in roles for code in role)
        if not codes:
            return text
        return f"\033[{codes}m{text}{RESET}"

    def print(self, text: str = "") -> None:
        """Write one already-styled line (caller owns any indent)."""
        self.stream.write(text + "\n")

    def blank(self) -> None:
        self.stream.write("\n")

    def flush(self) -> None:
        try:
            self.stream.flush()
        except Exception:
            pass

    # ── section rule ─────────────────────────────────────────────────────────

    def rule(self, title: str = "", *, role: Tuple[str, ...] = TITLE) -> None:
        """Print a section divider, optionally with an inline title."""
        inner = self.width - len(IND)
        if title:
            label = f"── {title} "
            dashes = "─" * max(3, inner - visible_len(label))
            self.print(IND + self.paint(label, role) + self.paint(dashes, MUTED))
        else:
            self.print(IND + self.paint("─" * inner, MUTED))

    # ── key / value ──────────────────────────────────────────────────────────

    def kv(self, label: str, value: str, *, value_role: Tuple[str, ...] = ACCENT,
           label_width: int = 0) -> None:
        """Print ``label: value`` with a muted label and a coloured value."""
        lbl = f"{label}:".ljust(label_width) if label_width else f"{label}:"
        self.print(IND + self.paint(lbl, MUTED) + " " + self.paint(value, value_role))

    def kv_block(self, pairs: Sequence[Tuple[str, str]], *,
                 value_role: Tuple[str, ...] = ACCENT) -> None:
        """Print aligned ``label: value`` lines (labels share one column width)."""
        if not pairs:
            return
        width = max(len(label) for label, _ in pairs) + 1  # +1 for the colon
        for label, value in pairs:
            self.kv(label, value, value_role=value_role, label_width=width)

    # ── bullet list ──────────────────────────────────────────────────────────

    def bullet(self, items: Sequence[str], *, more: int = 0, marker: str = "•",
               role: Tuple[str, ...] = (), indent: int = 2) -> None:
        """Print a vertical bullet list, with an optional ``… and N more`` tail.

        ``items`` are already-truncated callers' choice; ``more`` (if > 0) adds a
        trailing muted summary line.  Replaces the old ``", ".join(x[:6])`` style.
        """
        pad = IND + " " * indent
        for item in items:
            self.print(pad + self.paint(marker, MUTED) + " " + self.paint(item, role))
        if more > 0:
            self.print(pad + self.paint(f"… and {more} more", MUTED))

    # ── status-tagged note lines ─────────────────────────────────────────────

    def note(self, text: str) -> None:
        """Informational line (muted ``i`` marker)."""
        self.print(IND + self.paint("·", MUTED) + " " + text)

    def ok(self, text: str) -> None:
        self.print(IND + self.paint("✓", OK) + " " + text)

    def warn(self, text: str) -> None:
        self.print(IND + self.paint("!", WARN) + " " + self.paint(text, WARN))

    def error(self, text: str) -> None:
        self.print(IND + self.paint("✗", ERR) + " " + self.paint(text, ERR))

    # ── factories ────────────────────────────────────────────────────────────

    def panel(self, title: str = "", *, heavy: bool = False,
              title_role: Tuple[str, ...] = TITLE) -> "Panel":
        return Panel(self, title=title, heavy=heavy, title_role=title_role)

    def table(self, columns: Sequence["Column"]) -> "Table":
        return Table(self, columns)

    def live(self) -> "LiveBlock":
        return LiveBlock(self)


# ── Panel ─────────────────────────────────────────────────────────────────────

class Panel:
    """A bordered, optionally-titled box whose width matches the console.

    Build the body with :meth:`line`, :meth:`kv`, :meth:`section`, :meth:`blank`,
    then :meth:`render` to a list of strings or :meth:`print` straight out.
    Content strings may already be painted — width maths uses :func:`visible_len`,
    so colour never throws off the borders.
    """

    def __init__(self, console: Console, *, title: str = "", heavy: bool = False,
                 title_role: Tuple[str, ...] = TITLE):
        self.c = console
        self.title = title
        self.box = _HEAVY if heavy else _LIGHT
        self.title_role = title_role
        self._rows: List[str] = []                 # painted body lines (no border)
        self.inner = console.width - len(IND) - 4  # minus indent, 2 borders, 2 pad spaces

    # body builders ---------------------------------------------------------
    def line(self, text: str = "", *roles: Tuple[str, ...]) -> "Panel":
        self._rows.append(self.c.paint(text, *roles) if roles else text)
        return self

    def kv(self, label: str, value: str, *,
           value_role: Tuple[str, ...] = ACCENT, label_width: int = 0) -> "Panel":
        lbl = f"{label}:".ljust(label_width) if label_width else f"{label}:"
        self._rows.append(self.c.paint(lbl, MUTED) + " " + self.c.paint(value, value_role))
        return self

    def section(self, title: str) -> "Panel":
        self._rows.append(self.c.paint(title, MUTED))
        return self

    def blank(self) -> "Panel":
        self._rows.append("")
        return self

    # render ----------------------------------------------------------------
    def _border_row(self, left: str, right: str) -> str:
        return IND + self.c.paint(left + self.box.h * (self.inner + 2) + right, MUTED)

    def _top(self) -> str:
        if not self.title:
            return self._border_row(self.box.tl, self.box.tr)
        label = f" {self.title} "
        fill = self.box.h * max(1, self.inner + 2 - len(label) - 1)
        return (IND
                + self.c.paint(self.box.tl + self.box.h, MUTED)
                + self.c.paint(label, self.title_role)
                + self.c.paint(fill + self.box.tr, MUTED))

    def render(self) -> List[str]:
        v = self.c.paint(self.box.v, MUTED)
        out = [self._top()]
        for row in self._rows:
            pad = self.inner - visible_len(row)
            if pad < 0:
                pad = 0
            out.append(f"{IND}{v} {row}{' ' * pad} {v}")
        out.append(self._border_row(self.box.bl, self.box.br))
        return out

    def print(self) -> None:
        for ln in self.render():
            self.c.print(ln)


# ── Table ─────────────────────────────────────────────────────────────────────

@dataclass
class Column:
    """One table column.

    ``width`` is ``"auto"`` (size to content), ``"flex"`` (absorb leftover
    terminal width — at most one column), or a fixed int.  ``align`` is ``"<"``,
    ``">"`` or ``"^"``.  ``role`` colours every cell unless a cell overrides it;
    ``header_role`` colours the heading.
    """
    header: str
    align: str = "<"
    width: Union[str, int] = "auto"
    role: Tuple[str, ...] = ()
    header_role: Tuple[str, ...] = MUTED


class Table:
    """Column-aligned table with a header rule and per-cell colour.

    Rows are sequences of :data:`Cell` (plain ``str`` or ``(text, role)``).
    Resolves ``"auto"``/``"flex"`` widths against the console width, truncates
    over-long cells with ``…``, and paints after sizing.
    """

    def __init__(self, console: Console, columns: Sequence[Column]):
        self.c = console
        self.columns = list(columns)
        self._rows: List[List[Cell]] = []

    def row(self, *cells: Cell) -> "Table":
        self._rows.append(list(cells))
        return self

    @staticmethod
    def _cell_text(cell: Cell) -> str:
        return cell[0] if isinstance(cell, tuple) else cell

    def _resolve_widths(self) -> List[int]:
        ncol = len(self.columns)
        widths: List[int] = [0] * ncol
        flex_idx = -1
        for i, col in enumerate(self.columns):
            if col.width == "flex":
                flex_idx = i
                widths[i] = len(col.header)
            elif isinstance(col.width, int):
                widths[i] = col.width
            else:  # auto
                natural = len(col.header)
                for r in self._rows:
                    if i < len(r):
                        natural = max(natural, len(self._cell_text(r[i])))
                widths[i] = natural
        if flex_idx >= 0:
            gaps = ncol - 1                     # single space between columns
            used = sum(w for j, w in enumerate(widths) if j != flex_idx)
            avail = (self.c.width - len(IND)) - used - gaps
            longest = len(self.columns[flex_idx].header)
            for r in self._rows:
                if flex_idx < len(r):
                    longest = max(longest, len(self._cell_text(r[flex_idx])))
            widths[flex_idx] = max(8, min(avail, longest))
        return widths

    def _fmt(self, text: str, width: int, align: str) -> str:
        """Truncate (plain) then pad ``text`` to ``width`` with ``align``."""
        if len(text) > width:
            text = text[:width - 1] + "…" if width >= 1 else text[:width]
        if align == ">":
            return text.rjust(width)
        if align == "^":
            return text.center(width)
        return text.ljust(width)

    def render(self) -> List[str]:
        widths = self._resolve_widths()
        out: List[str] = []

        # header
        hcells = [self.c.paint(self._fmt(col.header, widths[i], col.align),
                               col.header_role)
                  for i, col in enumerate(self.columns)]
        out.append(IND + " ".join(hcells))
        out.append(IND + self.c.paint(
            " ".join("─" * widths[i] for i in range(len(self.columns))), MUTED))

        # body
        for r in self._rows:
            cells = []
            for i, col in enumerate(self.columns):
                raw = self._cell_text(r[i]) if i < len(r) else ""
                role = r[i][1] if (i < len(r) and isinstance(r[i], tuple)) else col.role
                cells.append(self.c.paint(self._fmt(raw, widths[i], col.align), role))
            out.append(IND + " ".join(cells))
        return out

    def print(self) -> None:
        for ln in self.render():
            self.c.print(ln)


# ── LiveBlock (in-place run-status redraw) ────────────────────────────────────

class LiveBlock:
    """In-place redraw of a multi-line status block during a run.

    Encapsulates the ``\\033[NA\\033[J`` cursor dance formerly hand-rolled in
    ``_make_on_progress`` / ``_make_on_line``.  Cursor moves only happen on a TTY;
    when output is redirected each update is just appended (log-friendly).
    """

    def __init__(self, console: Console):
        self.c = console
        self._lines = 0

    def _erase(self) -> None:
        if self._lines and self.c.is_tty:
            self.c.stream.write(f"\033[{self._lines}A\033[J")
        self._lines = 0

    def redraw(self, lines: Sequence[str]) -> None:
        """Replace the previous block with ``lines``."""
        self._erase()
        self.c.stream.write("\n".join(lines) + "\n")
        self.c.flush()
        self._lines = len(lines)

    def emit(self, line: str) -> None:
        """Clear the live block (if any) then print a normal scrolling line."""
        self._erase()
        self.c.print(line)
        self.c.flush()

    @property
    def active(self) -> bool:
        return self._lines > 0

    def reset(self) -> None:
        """Forget the tracked block without erasing (caller already moved on)."""
        self._lines = 0


# A module-level console bound to stdout for convenient one-off use.
console = Console()


def _self_demo() -> None:
    """Render every component so the styling can be eyeballed: ``python -m
    modules.console`` (colour) or ``NO_COLOR=1 python -m modules.console`` (plain)."""
    c = Console()
    c.blank()
    c.rule("Console self-demo")
    c.blank()
    c.kv_block([("hashcat", "/usr/bin/hashcat"),
                ("wordlists", "2 auto-discovered"),
                ("unique NT hashes", "2,998")])
    c.blank()
    c.note("Straight wordlist phases skipped — rules available")
    c.ok("Measured: 102.4 GH/s")
    c.warn("toggles1.rule not found — LM toggle phase skipped")
    c.error("hashcat not found (required)")
    c.blank()
    c.rule("Rules matched")
    c.bullet(["best66.rule", "dive.rule", "OneRuleToRuleThemAll.rule"], more=4)
    c.blank()

    p = c.panel("Campaign Status: crkb_demo")
    p.kv("Cracked", "939/2998 (31.3%)")
    p.kv("Elapsed", "0h 14m 02s")
    p.blank()
    p.section("Recent phases:")
    p.line("  " + c.paint("✓", OK) + " P0003  Org: org_words (straight)   +12  3s")
    p.print()
    c.blank()

    t = c.table([
        Column("ID", width=6),
        Column("St", width=5),
        Column("Pri", align=">", width=4),
        Column("Name", width="flex"),
        Column("Keyspace", align=">", width=10, role=INFO),
        Column("Time", align=">", width=8),
    ])
    for pid, st, pri, name, ks, tm in [
        ("P0001", "completed", 50, "LM brute force (7-char halves)", "70.6T", "12m"),
        ("P0003", "completed", 95, "Org: org_words (straight)", "63", "3s"),
        ("P0015", "running", 1216, "Hybrid: org_words.txt + ?d?d?d?d?1", "7.6M", "5s"),
        ("P0006", "skipped", 1000, "Enterprise masks (built-in patterns)", "386.6T", "1.1h"),
    ]:
        b = badge_for(st)
        t.row(pid, (b.tag, b.role), str(pri), name, ks, tm)
    t.print()
    c.blank()


if __name__ == "__main__":
    _self_demo()
