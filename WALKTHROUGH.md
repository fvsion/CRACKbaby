# CRACKbaby — Example Campaign Walkthrough

This is a hands-on, end-to-end tutorial that runs a complete engagement against the
**bundled sample dump** (`samples/crkb_ntds.dit`). Every command and every block of output
below is real — copy-paste along and you'll see the same thing.

> The sample is a **synthetic** domain ("CrackBaby Corp") generated for practice. There are
> no real credentials in it — it's safe to crack. Outputs (banner removed for brevity) come
> from a laptop GPU with a 60-second cap on the run; **your exact crack counts will be higher
> the longer you let the campaign run.**

For the *why* behind each command, see **[USER_GUIDE.md](USER_GUIDE.md)**. This file is the
*how*, start to finish.

---

## The scenario

`samples/crkb_ntds.dit` is a secretsdump-format dump of a fictional Windows domain:

- **~4,000 entries**: ~3,000 user accounts + ~1,000 machine accounts.
- A realistic password mix: **org-aware** passwords (company/location + year + symbol,
  e.g. `CrackBaby2023!`, `Austin#2023!`), **generic-weak** rockyou-style passwords
  (`Password1!`, `Welcome1!`), and a stubborn **~20% truly-complex** tail (12–20 chars,
  symbols mid-string) that resists wordlist attacks.
- A small pool of **LM hashes** (legacy), some **pre-2000 machine** accounts, and **shared
  password clusters** (dozens of accounts reusing one password) — exactly the reuse you
  want to surface in a report.

`samples/crkb_ntds_legend.txt` is the answer key if you want to check your work, and
`samples/crkb_org.json` is the matching org-context file we'll use.

Throughout, `python crackbaby.py` is the tool and `/tmp/crkb` is our campaign directory.

---

## 0. Verify tooling and get a wordlist

```bash
python crackbaby.py tools
```

```
  ── CRACKbaby Tool Status ─────────────────────────────────────────
  [✓] hashcat         : /opt/homebrew/bin/hashcat
  [!] combinator.bin  : not found  (needed for combo_rules fallback)
  [!] rockyou.txt     : not found  (default wordlist)
       Download it with:  crackbaby tools --download rockyou
```

`hashcat` is **required**. `combinator.bin` is **optional** — it ships with hashcat and is
only used as a fallback for very large wordlist × wordlist phases; ignore the `[!]` unless
you hit one.

Grab the default wordlist (one time, ~133 MB — built-in downloader, no extra tools):

```bash
python crackbaby.py tools --download rockyou
```

```
  Downloading rockyou.txt
    from https://weakpass.com/download/90/rockyou.txt.gz
    100.0%  (50.9 MB / 50.9 MB)
  Decompressing → rockyou.txt …
  [✓] rockyou.txt ready: crackbaby/wordlists/rockyou.txt  (133.4 MB)
```

It lands in `crackbaby/wordlists/`, which `init` searches automatically — so we won't pass
`--wordlists` at all below. (`~/wordlists`, `/opt/wordlists` and `/usr/share/wordlists` are
searched too, if you keep wordlists there.)

---

## 1. prep — build the hash file

We extract NT hashes for **user** accounts only (drop machine and built-in accounts), keep
the `DOMAIN\user` prefix so the report can count accounts, and pull the LM hashes into a
separate file.

```bash
python crackbaby.py prep \
    --ntds samples/crkb_ntds.dit \
    --output /tmp/crkb.hashes \
    --username --no-machines --no-system \
    --lm-file /tmp/crkb.lm
```

```
  Parsing NTDS dump: samples/crkb_ntds.dit
  Filter: machine accounts excluded
  Filter: system/built-in accounts excluded
  Filtered out:  1002 accounts total
    Machine ($): 1000
    System:      2
  NT hashes written: 2998  →  /tmp/crkb.hashes
  LM hashes:   30 non-null  →  /tmp/crkb.lm
```

What happened:

- **`--no-machines`** dropped 1,000 `$`-suffixed machine accounts (random, uncrackable).
- **`--no-system`** dropped 2 built-ins (e.g. `krbtgt`, `Guest`) you can't act on.
- **`--username`** wrote `DOMAIN\user:hash` lines (try `head -2 /tmp/crkb.hashes`), so the
  report counts *accounts* and can show password reuse.
- **`--lm-file`** found 30 non-null LM hashes — a fast, high-value side-channel (Step 5).
- **Disabled accounts were kept.** CRACKbaby keeps every account unless you pass
  `--enabled-only`; disabled accounts still reveal reused/soon-to-be-re-enabled passwords.
  Add `--unique` if you also want a deduplicated bare-hash file.

---

## 2. init — create the campaign and build the pipeline

```bash
python crackbaby.py init /tmp/crkb \
    --hashes /tmp/crkb.hashes --username \
    --org-config samples/crkb_org.json \
    --lm-hashes /tmp/crkb.lm \
    --expected-speed 50 --no-benchmark --skip-slow 24
```

(No `--wordlists` — crackbaby auto-discovers the rockyou we downloaded in Step 0.)

```
  Wordlists: 1 auto-discovered  (dirs: crackbaby/wordlists, /usr/share/wordlists, /opt/wordlists, ~/wordlists)
             • crackbaby/wordlists/rockyou.txt
  Hash file: 2998 total lines, 1196 unique NT hashes
  Org config:  samples/crkb_org.json   (name: CrackBaby Corp / short: CRKB / Austin, TX)
  LM hashes:    30 hashes → LM brute phase added at priority 50
  LM toggle:    NTLM recovery via toggles1 → priority 60
  Org wordlist: 63 entries → org_words.txt
  Default rules: .../crackbaby/rules  (2 files, depth=A)
  ...
  40 phases built
  40 phases will run

  ID       St      Pri  Name                                       Type       Keyspace   Time
  P0001          50  LM brute force (7-char halves, mode 3000)     lm_brute      70.6T    ~24m
  P0002          60  LM plaintexts → NTLM via toggle rules         lm_toggle         ?       ?
  P0003          95  Org: org_words (straight)                     wordlist         63     <1m
  P0004         200  Rules: org_words.txt + best66.rule            rules          4158     <1m
  P0005         200  Rules: rockyou.txt + best66.rule              rules        960.6M     <1m
  P0006        1000  Enterprise masks (built-in patterns)          mask         386.6T    ~2.1h
  P0007        1200  Hybrid: org_words.txt + ?d                    hybrid          630     <1m
  ...
  Run with:  python crackbaby.py run /tmp/crkb
```

Reading this:

- **1,196 unique** NT hashes across **2,998** accounts already hints at heavy reuse.
- The **LM phases** (P0001/P0002) were added at priority 50/60 because we passed
  `--lm-hashes` — they run first.
- The **org wordlist** (`org_words.txt`, 63 entries) was generated from `crkb_org.json` and
  runs at priority 95.
- **Priority is what matters, not the ID number** — phases run in ascending *priority*. The
  `Time` column is the ETA at 50 GH/s (`--expected-speed 50`); `--skip-slow 24` would
  pre-skip anything over 24 h (nothing here qualifies).
- *Note:* this machine only has crackbaby's two **bundled** rules (`best66`, `toggles1`), so
  depth `A` matched 2 files. On a full hashcat install, depth `A` admits more Tier-A rules
  (see USER_GUIDE §9) — more rule phases, more cracks.

### The same run from the config file

Prefer not to retype flags? Put defaults in `config/crackbaby.json`
(copy `config/crackbaby.json.sample`):

```json
{
  "expected_speed_ghs": 50.0,
  "default_rule_depth": "A",
  "wordlists_dirs": ["/path/to/wordlists"],
  "skip_threshold_hours": 24
}
```

Then `--expected-speed`, `--default-rule-depth`, `--wordlists` (auto-discovered from
`wordlists_dirs`), and `--skip-slow` are all optional — the config supplies them, and any
CLI flag you do pass still wins. The org context stays a file you pass with `--org-config`
(it's per-engagement). Every config key is documented inline in the sample, and a full
flag ⇄ key table is at the end of this file.

---

## 3. phases — inspect and tune the plan

List what's pending:

```bash
python crackbaby.py phases /tmp/crkb --pending
```

Filter by type, or skip an expensive phase you don't want this run:

```bash
python crackbaby.py phases /tmp/crkb --type hybrid          # only hybrid phases
python crackbaby.py phases /tmp/crkb --skip P0006           # skip the big mask phase
python crackbaby.py phases /tmp/crkb --skip-over-hours 1    # skip anything ETA > 1h
python crackbaby.py phases /tmp/crkb --unskip P0006         # ...change your mind
```

Skips are reversible and ranges work (`--skip P0007-P0018`). This is how you keep a
campaign focused on the high-yield phases.

---

## 4. benchmark — make the ETAs real

The ETAs above used the default-ish 50 GH/s we passed. Measure your actual GPU so the ETAs
and time-gating mean something:

```bash
python crackbaby.py benchmark /tmp/crkb --update      # measure NTLM, apply automatically
python crackbaby.py benchmark /tmp/crkb --set 120     # or set it by hand (GH/s)
```

```
  Manual speed override: 120.0 GH/s
  ✓ campaign.expected_speed_ghs set to 120.0000 GH/s
  ETA estimates @ 120.0 GH/s benchmark
```

ETAs are **static** — they're `keyspace ÷ (speed × per-type ratio)` and only ever change
when *you* run `benchmark` (or `--set`). Bump the speed and every ETA scales down
proportionally; nothing drifts on its own mid-run. You can also set the time-gate here:
`benchmark /tmp/crkb --set-threshold 24`.

---

## 5. run — crack

```bash
python crackbaby.py run /tmp/crkb
```

Phases execute in priority order, checkpointing after each. A live block shows progress:

```
  ── Phase P0005: Rules: rockyou.txt + best66.rule ──
  ┌─ 11:21:16 ────────────────────────────────────────────
  │  Status:    Exhausted
  │  Speed:     1345.9 MH/s (0.38ms) @ Accel:256 Loops:64 Thr:256 Vec:1
  │  Progress:  100.00%
  │  Recovered: 24/1196 (2.0%)
  │  ETA:       0m 0s
  │  Elapsed:   2s
  └────────────────────────────────────────────────────
```

Here's the campaign sweeping through phases (trimmed to the interesting ones):

```
  ── Phase P0001: LM brute force (7-char halves, mode 3000) ──
  → TIMED_OUT  LM cracked, NTLM delta: +0  Time: 9s
  ── Phase P0002: LM plaintexts → NTLM via toggle rules ──
  No LM hashes cracked yet — skipping toggle phase
  ── Phase P0003: Org: org_words (straight) ──
  → COMPLETED  +0 cracked  Running total: 0/2998 (0.0%)  Time: 1s
  ── Phase P0004: Rules: org_words.txt + best66.rule ──
  → COMPLETED  +0 cracked  Running total: 0/2998 (0.0%)  Time: 1s
  ── Phase P0005: Rules: rockyou.txt + best66.rule ──
  → COMPLETED  +254 cracked  Running total: 254/2998 (8.5%)  Time: 3s
  ── Phase P0006: Enterprise masks (built-in patterns) ──
  → TIMED_OUT  +0 cracked  Running total: 254/2998 (8.5%)  Time: 9s
  ── Phase P0035: Passphrase: common×suffixes ──
  → COMPLETED  +584 cracked  Running total: 838/2998 (28.0%)  Time: 1s
  ── Phase P0036: Passphrase: common+best66.rule ──
  → COMPLETED  +47 cracked  Running total: 885/2998 (29.5%)  Time: 2s
  ── Phase P0011: Hybrid: org_words.txt + ?1 ──
  → COMPLETED  +27 cracked  Running total: 912/2998 (30.4%)  Time: 2s
  ── Phase P0013: Hybrid: org_words.txt + ?d?1 ──
  → COMPLETED  +27 cracked  Running total: 939/2998 (31.3%)  Time: 2s
```

Things to notice:

- **`rockyou + best66` (P0005) cracked +254** in 3 seconds — the generic-weak passwords.
- The **passphrase combinator (P0035) cracked +584** — two-word/common-word patterns; the
  single biggest haul here.
- **LM brute (P0001) timed out at +0** because we capped each phase at 9 seconds for this
  demo. The full 7-char LM keyspace takes *hours* — let it run on a real engagement and it
  recovers the entire LM pool **regardless of complexity** (then `lm_toggle` restores the
  correct case). That's how you get the truly-complex accounts that wordlists never touch.
- **Ctrl-C** prints `Stop requested — waiting for hashcat to checkpoint` and exits cleanly.
  Re-run `python crackbaby.py run /tmp/crkb` and it resumes from the next phase. Run a
  single phase with `--phase P0005`, or preview commands with `--dry-run`.

After ~1 minute we're at **939 / 2,998 accounts (31.3%)** with most of the pipeline still
pending.

---

## 6. report — read the results

```bash
python crackbaby.py report /tmp/crkb
```

```
  OVERALL RESULTS
  Total accounts:        2,998
  Unique NT hashes:      1,196
  Accounts compromised:  939  (31.3%)
  Unique passwords:      114  (9.5%)
  Remaining accounts:    2,059  (68.7%)
```

This is the headline finding, and the two numbers tell different stories:

- **114 unique passwords** were cracked, but they unlock **939 accounts** — roughly **8
  accounts per cracked password**. That gap *is* the finding: rampant password reuse and
  shared-cluster passwords across the domain.
- The per-phase `+N` deltas (e.g. `P0035 +584`) count **accounts**, so they reconcile with
  the 939, not the 114.

The report continues with the analysis you'd paste into a pentest writeup:

```
  Length distribution:   8:3  9:22  10:24  11:36  12:20  13:9   (chars : count)
  Charset:  97.4% upper+lower+digit+special
  POLICY COMPLIANCE
    Minimum 12 characters:        29 of 114 (25.4%) meet  → 85 below
    12+ chars AND 3-of-4 classes: 29 of 114 (25.4%) meet  → 85 below
  Top patterns:  ?u?l?l?l?l?l?d?d?d?d?s (24%) ...   Endings: '!', '2023', ...
```

Interpretation for this domain: the generic-weak and org-aware passwords (`Word####!`
shapes) fell fast; three-quarters of what we cracked is **under 12 characters**, so the
headline recommendation writes itself — **enforce 12+ char passphrases, ban the org
name/season/year patterns, and require MFA**. The truly-complex tail is still in
`Remaining` — that's where you'd let the LM brute and mask/brute phases run to completion.

`report.txt` and `report.json` are written to the campaign dir; `report.json` carries both
bases (`accounts_cracked`, `unique_passwords_cracked`, …) for tooling.

---

## 7. Iterating on a live campaign

Add a wordlist you found mid-engagement (e.g. previously-breached passwords) and crackbaby
auto-generates every new phase for it:

```bash
python crackbaby.py add /tmp/crkb --wordlists /tmp/extra.txt
#   → Added 22 phase(s):  Hybrid: extra.txt + ?d, Combo+rules: ... × extra.txt | best66.rule, ...
```

Change settings and regenerate the pending plan (preview first with `--dry-run`):

```bash
python crackbaby.py rebuild /tmp/crkb --expected-speed 100 --skip-slow 12 --dry-run
#   skip_threshold_hours: 24.0 → 12.0
#   expected_speed_ghs:   50.0 → 100.0
#   Phases: 16 kept (non-pending) | 46 pending dropped | 46 new added
#   [DRY-RUN] No changes written.
```

Reclaim disk after a big run (logs + the rule-convert cache):

```bash
python crackbaby.py clean --campaign /tmp/crkb --all --dry-run   # preview
#   Found 18 item(s) / 0.1 MB
python crackbaby.py clean --campaign /tmp/crkb --all -y          # actually delete
```

---

## Flag ⇄ config cross-reference

Everything you can pass on the command line has a home in `config/crackbaby.json` (CLI wins):

| CLI flag (init) | config key | what it sets |
|---|---|---|
| `--hashcat` | `hashcat_bin` | path to hashcat |
| `--expected-speed` | `expected_speed_ghs` | GPU speed for ETAs |
| `--workload` | `workload` | hashcat `-w` 1–4 |
| `--custom-rules-dir` | `custom_rules_dir` | your always-on rules |
| `--default-rule-depth` | `default_rule_depth` | `none`/`A`/`AB`/`ABC` |
| *(auto-discovery)* | `wordlists_dirs` | where to find wordlists |
| `--global-potfile` | `global_potfile` | shared potfile base |
| `--max-combinator-pairs-ks` | `max_combinator_pairs_ks` | wl×wl pair cap |
| `--max-rule-convert-words` | `max_rule_convert_words` | rule-convert threshold |
| `--skip-slow` | `skip_threshold_hours` | time-gate threshold |
| `--status-interval` | `status_interval` | hashcat status seconds |

`--org-config` and `--lm-hashes` stay per-engagement files you pass at init; `--hashes`,
`--username`, and `--devices` are campaign-specific too.

---

## Cleanup

The whole campaign is self-contained, so teardown is just:

```bash
rm -rf /tmp/crkb /tmp/crkb.hashes /tmp/crkb.lm /tmp/extra.txt
```

That's the full loop: **prep → init → run → report**, plus tuning. Re-run any step against
the sample until the flags feel natural, then point it at a real engagement. See
**[USER_GUIDE.md](USER_GUIDE.md)** for the strategy behind each decision.
