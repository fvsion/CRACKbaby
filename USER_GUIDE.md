# CRACKbaby — User Guide (v1.0.1)

> Operational guide for running NTLM password-recovery engagements with crackbaby.
> For a quick overview and install steps, see **[README.md](README.md)**.

---

## Contents

1. [What crackbaby is](#1-what-crackbaby-is)
2. [Prerequisites](#2-prerequisites)
3. [Step 1 — prep: the hash file & account strategy](#3-step-1--prep-the-hash-file--account-strategy)
4. [Step 2 — init: the campaign & attack pipeline](#4-step-2--init-the-campaign--attack-pipeline)
5. [Step 3 — run](#5-step-3--run)
6. [Step 4 — report: reading the results](#6-step-4--report-reading-the-results)
7. [Strategy — LM hashes](#7-strategy--lm-hashes)
8. [Strategy — org context](#8-strategy--org-context-targeted-wordlist)
9. [Rule depth](#9-rule-depth)
10. [Time-gating & the static ETA model](#10-time-gating--the-static-eta-model)
11. [benchmark — calibrating ETAs](#11-benchmark--calibrating-etas)
12. [combo_rules & combinator strategy](#12-combo_rules--combinator-strategy)
13. [Repeat engagements — the global potfile](#13-repeat-engagements--the-global-potfile)
14. [Command reference](#14-command-reference)
15. [Configuration file](#15-configuration-file)
16. [Worked example](#16-worked-example)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. What crackbaby is

CRACKbaby is a single-file, standard-library-only Python orchestrator around **hashcat**.
You point it at a set of NTLM hashes from an Active Directory dump and it builds and runs
a prioritised pipeline of hashcat attacks — wordlists, rules, masks, hybrids, combinators,
and LM cracking — checkpointing after every phase so the whole campaign is **resumable**.
At the end it produces a pentest-quality audit report.

The whole tool is four steps:

```
prep  →  init  →  run  →  report
```

- **prep** — turn a secretsdump/NTDS dump into a clean hash file (with account filtering).
- **init** — create a campaign directory and generate the attack pipeline.
- **run** — execute the phases in priority order (resumable; Ctrl-C to pause).
- **report** — generate the text + JSON audit report.

### The campaign directory

`init` creates a self-contained directory you can stop, resume, or move at will:

```
campaign/
  campaign.json            # all state: phases, settings, progress
  crackbaby_1000.potfile   # hashcat potfile (NTLM) — hash:plaintext
  crackbaby_3000.potfile   # LM potfile (only when --lm-hashes is used)
  cracked.txt              # recovered NTLM plaintexts (human-readable)
  report.txt / report.json # written by `report`
  logs/    P0001.log …     # per-phase hashcat output
  sessions/                # hashcat --restore files (resume state)
  wordlists/               # generated: org_words.txt, lm_cracked.txt, rules_cache/
  masks/   enterprise.hcmask
```

Because all state lives in `campaign.json` + the potfile + the restore files, you can
Ctrl-C mid-run and re-run `crackbaby run <campaign>` days later — it resumes exactly where
it left off.

---

## 2. Prerequisites

- **Python 3.8+** — standard library only, nothing to `pip install`.
- **hashcat 6.x or 7.x** on your `PATH` (or pass `--hashcat /path/to/hashcat` at init).
- **A wordlist** — **rockyou is the default**; fetch it with one command (below).
- *Optional:* **combinator.bin** (ships with hashcat) — only needed for the combinator
  fallback on very large wordlist × wordlist phases.

Check what crackbaby can see:

```bash
python crackbaby.py tools
```

This reports the hashcat binary, combinator.bin, and whether the default wordlist
(`rockyou.txt`) is present. It does not install anything on its own.

### Getting wordlists

CRACKbaby has a built-in, dependency-free downloader. Fetch the default wordlist:

```bash
python crackbaby.py tools --download rockyou      # → crackbaby/wordlists/rockyou.txt (~133 MB)
```

- It downloads (and decompresses) into `crackbaby/wordlists/` (a repo-local, gitignored
  dir on crackbaby's default search path) — so `init` **auto-discovers** it and you never
  need `--wordlists`. `~/wordlists`, `/opt/wordlists` and `/usr/share/wordlists` are
  searched too.
- `--dest DIR` downloads elsewhere; `--force` re-downloads.
- You can also pass **any http(s) URL** (a `.gz` is decompressed automatically), e.g.
  `python crackbaby.py tools --download https://example.com/lists/weakpass.txt.gz`.

Already have wordlists? Drop them in any of those search dirs (or set `wordlists_dirs` in
your config) and `init` finds them automatically; or point `--wordlists` at them directly.

**combinator** (the combo_rules fallback) can be built the same way — it downloads the
hashcat-utils source and compiles it into `crackbaby/installed_tools/`:

```bash
python crackbaby.py tools --download combinator   # needs a C compiler (cc/clang/gcc)
```

On Windows (no compiler), grab `combinator.exe` from the
[hashcat-utils releases](https://github.com/hashcat/hashcat-utils/releases) and drop it in
`installed_tools/`. combinator also ships with hashcat, so this is only needed if it isn't
already alongside your hashcat binary.

---

## 3. Step 1 — prep: the hash file & account strategy

`prep` reads a secretsdump / NTDS dump in the standard impacket format —

```
DOMAIN\username:RID:LMhash:NThash:::
```

— and writes the NT hashes hashcat will attack. The important decision is **which
accounts you keep**, because a raw domain dump is full of accounts not worth GPU time.

### Account types and why you filter them

| Account type | How it's detected | Flag to drop it | Why |
|---|---|---|---|
| **Machine accounts** | username ends in `$` (e.g. `WS01$`) | `--no-machines` | Random 120-char passwords — uncrackable noise. (Exception: pre-2000 machines, below.) |
| **System / built-in** | name in `{Guest, krbtgt, defaultaccount, helpassistant, wdagutilityaccount}` or prefix `healthmailbox`/`support_`/`iwam_`/`iusr_`/`aspnet` | `--no-system` | Built-in/service accounts you can't act on; `krbtgt` is a random 64-hex value — never crackable. |
| **Disabled** | line carries an `Enabled`/`Disabled` status (secretsdump `-user-status`) | `--enabled-only` (opt-in) | **Usually keep them — see below.** |

**Keep disabled accounts by default.** CRACKbaby includes every account unless you tell it
not to; `--enabled-only` is opt-in. Disabled ≠ worthless:

- **Password reuse** — a disabled user's password is frequently shared by an active
  account or an admin's secondary account. Cracking a "dead" account can hand you a
  credential that still works elsewhere.
- **Re-enablement** — disabled is not deleted. Seasonal staff, returning employees,
  break-glass accounts, and service accounts get toggled back on; a weak password sitting
  on one becomes a live risk the moment it is re-enabled.
- **Policy & pattern intelligence** — every cracked password (active or not) widens the
  corpus behind the report's length/charset/pattern findings and the reuse analysis,
  making the audit's conclusions stronger.
- It costs almost nothing extra — same hashes, same wordlists.

Reach for `--enabled-only` only when the engagement scope is explicitly limited to active
accounts, or when you need to trim a very large dump.

A typical engagement prep:

```bash
python crackbaby.py prep \
    --ntds secretsdump.out \
    --output target.hashes \
    --username --no-machines --no-system \
    --lm-file target.lm
```

### Key prep flags

- `--username` — write `DOMAIN\user:hash` instead of bare hashes. **Recommended:** it
  lets the report count *accounts* (and surface password reuse) and map a cracked hash
  back to its owner. hashcat then runs in `--username` mode.
- `--unique` — also write a deduplicated bare-hash file (`<output>_unique.txt`).
- `--lm-file FILE` — also extract the non-null **LM** hashes to a separate file, which you
  feed to `init --lm-hashes` to enable the LM fast-path (§7). Null LM hashes
  (`aad3b435…`) are skipped automatically.
- `--enabled-only`, `--no-machines`, `--no-system` — the filters above.

### Pre-2000 machine accounts — a special case

Machine accounts are normally uncrackable, but **pre-Windows-2000 / pre-staged** machine
accounts are often created with the password equal to the machine name, **lowercased and
truncated to 14 characters** (e.g. `WS-DEV-01$` → `ws-dev-01`). If you suspect pre2k
machines, run a separate small campaign using those machine names (no `$`, lowercased) as
a custom wordlist, rather than excluding all machines.

---

## 4. Step 2 — init: the campaign & attack pipeline

`init` detects hashcat/wordlists/rules, optionally benchmarks your GPU, and builds the
phase pipeline:

```bash
python crackbaby.py init /campaigns/acme \
    --hashes target.hashes --username \
    --wordlists crackbaby/wordlists/rockyou.txt \
    --org-config acme.org.json \
    --lm-hashes target.lm \
    --expected-speed 120 --skip-slow 24
```

### How the pipeline is ordered

Phases run cheapest / highest-yield first. CRACKbaby assigns each phase a **priority** and
runs ascending:

| Priority | Band | What runs |
|---|---|---|
| 50 / 60 | LM | `lm_brute` then `lm_toggle` (only with `--lm-hashes`) |
| 95 | Org | the generated `org_words.txt`, straight |
| 100–199 | Wordlist | straight dictionary runs |
| 200–999 | Wordlist + rules | each wordlist × admitted rule files (light → heavy) |
| 1000–1099 | Masks | enterprise mask shapes (6–10 char patterns) |
| 1100–1199 | Passphrase | two-word / common-word combinator + rules |
| 1200–19999 | Hybrid / combinator / combo_rules | wordlist+mask, wl×wl, wl×wl×rules |
| 60000–69999 | Brute | 6–10 char exhaustive (ordered by keyspace) |

The intent: the org wordlist and `rockyou + best66` crack the bulk of weak and org-aware
passwords in seconds; masks/hybrids/brute mop up the long tail at higher GPU cost (which
is why time-gating exists — §10).

### Key init flags

- `--hashes FILE` (required); `--username` (match your prep choice).
- `--wordlists WL...` — your wordlists. **Optional** — if omitted, crackbaby
  auto-discovers wordlists from `crackbaby/wordlists/` and the other search dirs (rockyou is the
  default). If none are found on an interactive run, it offers to download rockyou for you.
- `--org-config FILE` — generate a targeted org wordlist (§8).
- `--lm-hashes FILE` — add the LM fast-path phases (§7).
- `--default-rule-depth none|A|AB|ABC` — how many bundled rules to admit (§9).
- `--expected-speed GH/S` — your GPU's NTLM speed, for ETAs (or run `benchmark`, §11).
- `--skip-slow HOURS` — auto-skip phases estimated to exceed N hours (§10).
- `--workload 1–4` — hashcat workload profile (default 3); `--devices 1,2,3` — restrict GPUs.

At the end, `init` prints the phase list with per-phase keyspace + ETA and how many phases
were pre-skipped by time-gating.

---

## 5. Step 3 — run

```bash
python crackbaby.py run /campaigns/acme              # run / resume the whole pipeline
python crackbaby.py run /campaigns/acme --phase P0042  # one phase only
python crackbaby.py run /campaigns/acme --dry-run      # print the hashcat commands, run nothing
```

- Phases execute in priority order; after each, crackbaby checkpoints (`campaign.json` +
  hashcat restore file). **Ctrl-C** asks hashcat to checkpoint and stops cleanly — re-run
  the same command to resume.
- A live status block shows speed, progress, recovered count, ETA, and elapsed time.
- `--phase-timeout HOURS` caps each phase (fractions are fine: `0.5` = 30 min); the phase
  checkpoints and the pipeline moves on.
- `--phase ID` runs exactly one phase (and overrides skip/gating for it).
- `--workload {1-4}` and `--no-optimize` override settings for this run only.

---

## 6. Step 4 — report: reading the results

```bash
python crackbaby.py report /campaigns/acme
```

Writes `report.txt` + `report.json`. The headline distinguishes two numbers that are easy
to conflate:

- **Accounts compromised** — how many *accounts* use a password you cracked. This is the
  business-impact number, and it is what the per-phase `+N` deltas sum to.
- **Unique passwords** — how many *distinct* NT hashes you cracked.

In `--username` mode these diverge whenever passwords are reused. For example, cracking
**28 unique passwords** can compromise **232 accounts** — heavy reuse across the domain,
which is itself a finding.

The report also covers:

- **Phase breakdown** — which attack landed which accounts (`+N` = accounts).
- **Length / charset distribution** of cracked passwords.
- **Policy compliance** — % of cracked passwords meeting 8-char, 12-char, 3-of-4-class,
  and "12+ chars AND 3-of-4" policies.
- **Top patterns** (hashcat masks) and **common endings** (`!`, `1`, `2024`, …).
- **Recommendations**, keyed to the account-compromise rate.

`report.json` carries both bases: `accounts_cracked` / `accounts_pct`,
`unique_passwords_cracked` / `unique_pct`, plus `total_accounts` / `unique_hashes` and the
per-phase deltas.

---

## 7. Strategy — LM hashes

LM (LAN Manager) is the legacy Windows hash — and when it's present, it's the single
**highest-value target in the dump**, because it bypasses password complexity entirely.

How it breaks: the password is upper-cased, split into **two independent 7-character
halves**, and each half is hashed with no salt. So any password ≤14 characters collapses
into two 7-char, uppercase, **case-insensitive** problems, and the whole LM keyspace is
GPU-exhaustible in hours. That means:

- **The crack is guaranteed** for any ≤14-char password — *regardless of length or
  symbols*. A "complex" `Tr0ub4dor&3!` that no wordlist or rule set would ever reach falls
  trivially through its LM halves.
- LM therefore turns the **truly-complex passwords** — the ones that resist every NTLM
  wordlist / rule / hybrid attack — into certain cracks. It is often the *only* way to
  recover them.
- The mere **presence** of LM hashes is itself a finding: it means the legacy "store LM
  hash" policy is still enabled, which you should flag.
- Even a handful of LM hashes can unlock high-value accounts that resist everything else —
  so always extract them at prep time (`--lm-file`).

CRACKbaby exploits this with two phases, added automatically when you pass `--lm-hashes`:

1. **`lm_brute`** (priority 50, hashcat mode 3000) — brute-forces both halves
   (`?a` incrementing 1→7 chars). This recovers the **upper-case** password.
2. **`lm_toggle`** (priority 60) — feeds the cracked upper-case LM plaintexts back against
   the **NTLM** hashes with `toggles1.rule`, trying case variations
   (`PASSWORD` → `Password`, `pAssword`, …) to recover the case-correct NTLM password.

Workflow:

```bash
python crackbaby.py prep --ntds dump.out --output nt.hashes --lm-file lm.hashes  --no-machines --no-system
python crackbaby.py init /campaigns/acme --hashes nt.hashes --lm-hashes lm.hashes
```

Only non-null LM hashes are useful; modern accounts store the null LM, which prep skips.
LM is mostly found on older accounts, pre2k machines, and domains that left "store LM
hash" enabled.

---

## 8. Strategy — org context (targeted wordlist)

Enterprise passwords are overwhelmingly *org-aware*: the company name, location, and local
flavour with a year and a symbol (`Acme2024!`, `Dallas#2023`, `acmevpn1`). Give crackbaby
an org JSON and it generates a high-value `org_words.txt`, run at top priority:

```bash
python crackbaby.py init /campaigns/acme --hashes nt.hashes --org-config acme.org.json
```

From the fields it derives:

- **org_name / org_name_short** — case variants of the full name and each word; strips
  corporate suffixes (Corp, Inc, LLC, Ltd…) to the bare brand; and IT-department patterns
  from the brand (`acmeit`, `acmeadmin`, `acmevpn`, `acmenet`, `acmehelpdesk`).
- **org_location** — case variants; US state abbreviations are expanded (`TX` ↔ `Texas`).
- **custom_words** — engagement-specific terms (project names, mascots, teams, landmarks,
  prior-breach passwords); multi-word entries are split so each piece gets variants.

See **`config/org.json.sample`** for a fully commented template. The org list is small,
but combined with rules and hybrids (digits/years/symbols) it punches far above its weight.

---

## 9. Rule depth

`--default-rule-depth` controls how many of hashcat's bundled rule files crackbaby admits
to the broad wordlist+rules band. Heavier tiers mean more candidates — more cracks, but
more GPU time.

| Depth | Admits | Representative rules |
|---|---|---|
| `none` | only your `--custom-rules-dir` | — |
| `A` *(default)* | Tier A | best66, unix-ninja-leetspeak, T0XlC-insert*, generated, d3ad0ne, rockyou-30000 |
| `AB` | + Tier B | T0XlC, toggles3, combinator (and toggles1/2…) |
| `ABC` | + Tier C | dive, generated2, OneRuleToRuleThemAll |

Notes:

- Only rules actually **present in your hashcat rules dir** are used. CRACKbaby bundles
  `best66.rule` and `toggles1.rule` as guaranteed fallbacks (in `crackbaby/rules/`), so the
  org/rockyou rule phases and LM toggle work even on a bare install.
- Your own rules in `--custom-rules-dir` are **always** admitted, regardless of depth.

---

## 10. Time-gating & the static ETA model

Every pending phase shows an **ETA**, computed from a fixed model:

```
ETA = keyspace ÷ (expected_speed_ghs × per-type ratio)
```

`expected_speed_ghs` is your GPU's NTLM speed; the per-type ratios live in
`config/speed_factors.json` (rules are slower per candidate than masks, etc.). **The ETA
is static** — it never drifts based on observed run speed. The *only* way to change it is
the `benchmark` command (§11). This keeps gating decisions deterministic and repeatable.

**Time-gating** auto-skips phases whose ETA exceeds a threshold, so a campaign doesn't sit
on a 200-hour brute-force:

```bash
python crackbaby.py init /campaigns/acme --hashes nt.hashes --skip-slow 24   # at init
python crackbaby.py benchmark /campaigns/acme --set-threshold 24             # later
python crackbaby.py phases /campaigns/acme --skip-over-hours 24              # one-off
```

Gating applies both at init (pre-skip) and at run-time (a still-pending over-threshold
phase is skipped when reached). Skipped phases show as `skipped`; restore any of them with:

```bash
python crackbaby.py phases /campaigns/acme --unskip P0042
```

---

## 11. benchmark — calibrating ETAs

ETAs are only as good as `expected_speed_ghs`. The default (68 GH/s ≈ a single RTX 3090)
is a guess — measure your rig:

```bash
python crackbaby.py benchmark /campaigns/acme               # measure NTLM, prompt to apply
python crackbaby.py benchmark /campaigns/acme --update      # measure + apply, no prompt
python crackbaby.py benchmark /campaigns/acme --set 240     # set manually (GH/s)
python crackbaby.py benchmark /campaigns/acme --update-all  # per-type calibration → speed_factors.json
python crackbaby.py benchmark /campaigns/acme --set-threshold 24   # also set the time-gate
```

`--update-all` runs short per-type test attacks and writes measured per-type GH/s to
`config/speed_factors.json`, so ETAs across **all** campaigns reflect your hardware.

---

## 12. combo_rules & combinator strategy

**Combinator** phases concatenate two wordlists (`wl1 × wl2` — every word of one appended
to every word of the other), good for two-word passphrases (`SummerRain`, `BlueDragon`).
**combo_rules** phases additionally apply a rule file to that product.

These products explode fast, so crackbaby caps which pairs it even creates with
`max_combinator_pairs_ks` (default 500M pairs). For the pairs it keeps, combo_rules picks a
strategy automatically:

1. **rule-convert** *(default, fully on-GPU)* — if the *smaller* wordlist side has ≤
   `max_rule_convert_words` lines (default 50,000), crackbaby converts that side into a
   hashcat rule file and runs `-a 0 big_side -r small_as_rules -r best66` entirely on the
   GPU. Fastest path.
2. **combinator.bin pipe** *(fallback)* — if the small side is larger, crackbaby pipes
   `combinator.bin wl1 wl2` into hashcat's stdin. Requires `combinator.bin` — it ships with
   hashcat, or build it with `crackbaby tools --download combinator` (check `crackbaby tools`).

Tune the thresholds:

```bash
python crackbaby.py rebuild /campaigns/acme --max-rule-convert-words 100000
python crackbaby.py rebuild /campaigns/acme --max-combinator-pairs 50000000000
```

---

## 13. Repeat engagements — the global potfile

If you re-test the same client (or share results across campaigns), point campaigns at a
shared potfile so already-cracked hashes are skipped instantly:

```bash
python crackbaby.py init /campaigns/acme --hashes nt.hashes --global-potfile ~/potfiles/acme
#   → ~/potfiles/acme_1000.potfile (NTLM)  and  ~/potfiles/acme_3000.potfile (LM)
```

(Or set `global_potfile` in `config/crackbaby.json`.) CRACKbaby appends
`_<hashtype>.potfile` so NTLM and LM results never mix.

---

## 14. Command reference

### prep — extract NT hashes from an NTDS dump
| Flag | Meaning |
|---|---|
| `--ntds FILE` | input secretsdump/NTDS file (required) |
| `--output FILE` | NT hash output file (required) |
| `--username` | write `DOMAIN\user:hash` (enables account-level reporting) |
| `--unique` | also write a deduplicated bare-hash file |
| `--enabled-only` | keep only `Enabled` accounts |
| `--no-machines` | drop machine accounts (`$`) |
| `--no-system` | drop built-in/system accounts |
| `--lm-file FILE` | also extract non-null LM hashes |

### init — create a campaign
| Flag | Meaning |
|---|---|
| `CAMPAIGN` | output directory (positional) |
| `--hashes FILE` | NT hash file (required) |
| `--username` | hash file is `user:hash` |
| `--wordlists WL...` | wordlist files (auto-discovered if omitted) |
| `--org-config FILE` | generate a targeted org wordlist |
| `--lm-hashes FILE` | add LM brute + toggle phases |
| `--custom-rules-dir DIR` | your rules (always admitted) |
| `--default-rule-depth none\|A\|AB\|ABC` | bundled-rule tier depth (default A) |
| `--expected-speed GH/S` | GPU speed for ETAs (default 68) |
| `--skip-slow HOURS` | auto-skip phases over N hours |
| `--no-benchmark` | skip the init benchmark prompt |
| `--workload {1-4}` / `--devices` | hashcat workload / GPU selection |
| `--global-potfile BASE` | shared potfile across campaigns |
| `--max-combinator-pairs-ks N` / `--max-rule-convert-words N` | combo tuning |

### run — run or resume
| Flag | Meaning |
|---|---|
| `CAMPAIGN` | campaign directory |
| `--phase ID` | run one phase only |
| `--dry-run` | print hashcat commands, run nothing |
| `--phase-timeout HOURS` | cap each phase (fractions OK) |
| `--workload {1-4}` / `--no-optimize` | per-run overrides |

### phases — list / skip / unskip / delete
| Flag | Meaning |
|---|---|
| `--pending` | show only pending phases |
| `--type TYPE` | filter by phase type |
| `--compute-keyspace` | fill in missing keyspace/ETA |
| `--skip ID...` / `--unskip ID...` | skip / restore (ranges like `P0010-P0025` OK) |
| `--skip-type TYPE` / `--skip-over-hours N` | bulk skip |
| `--delete ID...` | remove phases permanently |

### report — generate the audit report
| Flag | Meaning |
|---|---|
| `CAMPAIGN` | campaign directory |
| `--out FILE` | output path (default `<campaign>/report.txt`) |

### benchmark — calibrate ETAs
| Flag | Meaning |
|---|---|
| `--update` | measure NTLM speed and apply without prompting |
| `--set GH/S` | set speed manually |
| `--update-all` | per-type calibration → `speed_factors.json` |
| `--set-threshold HOURS` | set the time-gate threshold |

### add — add wordlists/rules to an existing campaign
`crackbaby add CAMPAIGN --wordlists PATH... [--rules PATH...]` (campaign comes first).

### rebuild — change settings & regenerate phases
| Flag | Meaning |
|---|---|
| `--from-config` | re-read `config/crackbaby.json` |
| `--expected-speed` / `--skip-slow` / `--rule-depth` | update settings |
| `--max-combinator-pairs N` / `--max-rule-convert-words N` | combo tuning |
| `--keep-pending` | additive only (don't replace pending phases) |
| `--dry-run` | preview changes |

### tools — show tool status / download wordlists & combinator
| Flag | Meaning |
|---|---|
| *(none)* | status of hashcat, combinator.bin, and the default wordlist |
| `--download [NAME\|URL]` | download a wordlist into `crackbaby/wordlists/` (default `rockyou`; or any http(s) URL, `.gz` auto-decompressed) |
| `--download combinator` | download + compile the combinator binary into `crackbaby/installed_tools/` |
| `--dest DIR` | download a wordlist into `DIR` instead of `crackbaby/wordlists/` |
| `--force` | re-download / rebuild even if already present |

### clean — delete scratch artifacts
| Flag | Meaning |
|---|---|
| `--campaign DIR` | campaign directory (required) |
| `--logs` / `--rules-cache` / `--all` | what to delete |
| `--older-than DAYS` | only files older than N days |
| `--dry-run` / `-y` | preview / skip confirmation |

---

## 15. Configuration file

`config/crackbaby.json` (or the path in `$CRACKBABY_CONFIG`) sets defaults so you don't
repeat flags. **CLI flags always win.** Copy the self-documenting sample:

```bash
cp config/crackbaby.json.sample config/crackbaby.json
```

| Key | Purpose | Matching flag |
|---|---|---|
| `hashcat_bin` | path to the hashcat binary | `--hashcat` |
| `expected_speed_ghs` | GPU NTLM speed for ETAs (static; change via `benchmark`) | `--expected-speed` |
| `workload` | hashcat `-w` profile, 1–4 | `--workload` |
| `custom_rules_dir` | your rules, always admitted | `--custom-rules-dir` |
| `default_rule_depth` | `none`/`A`/`AB`/`ABC` | `--default-rule-depth` |
| `wordlists_dirs` | dirs auto-scanned for wordlists | (auto-discovery) |
| `default_rules_dirs` | where hashcat's bundled rules live | — |
| `global_potfile` | shared potfile base path | `--global-potfile` |
| `max_combinator_pairs_ks` | cap on wl×wl pair count | `rebuild --max-combinator-pairs` |
| `max_rule_convert_words` | small-side rule-convert threshold | `--max-rule-convert-words` |
| `skip_threshold_hours` | time-gate threshold | `--skip-slow` |
| `status_interval` | hashcat status interval (seconds) | `--status-interval` |

---

## 16. Worked example

A full small engagement against the bundled sample dump (`samples/crkb_ntds.dit`, a
synthetic "CrackBaby Corp" domain):

```bash
# 1. Prep — keep real user accounts; grab LM hashes
python crackbaby.py prep \
    --ntds samples/crkb_ntds.dit --output crkb.hashes \
    --username --no-machines --no-system --lm-file crkb.lm
#   → ~2,998 user NT hashes, ~30 non-null LM hashes

# 2. Init — org-aware, LM-enabled (calibrate speed later)
python crackbaby.py init /campaigns/crkb \
    --hashes crkb.hashes --username \
    --wordlists crackbaby/wordlists/rockyou.txt \
    --org-config samples/crkb_org.json \
    --lm-hashes crkb.lm \
    --expected-speed 50 --no-benchmark --skip-slow 24
#   → org_words.txt (~63 words) + LM phases; ~40 phases total

# 3. Run (resume-safe; Ctrl-C any time)
python crackbaby.py run /campaigns/crkb

# 4. Report
python crackbaby.py report /campaigns/crkb
```

A representative result on this dataset: the `rockyou + best66` rules phase alone recovers
a large block of generic-weak passwords (`Password1`, `Welcome1!`, `P@ssw0rd1`), and the
org-aware hybrids recover `CrackBaby2023!`-style passwords. Because passwords are heavily
reused, the **accounts compromised** count comes out several times the **unique
passwords** count — exactly the reuse story you want in the report.

---

## 17. Troubleshooting

| Symptom | Fix |
|---|---|
| `hashcat not found` | put hashcat on `PATH`, or `init --hashcat /path`; verify with `crackbaby tools` |
| `combinator.bin: not found` | only needed for huge wl×wl combos; copy it next to hashcat (it ships with hashcat) |
| Phases show `?` keyspace / ETA | `crackbaby phases <campaign> --pending --compute-keyspace` |
| 0 cracked on org/straight phases | expected when passwords are long/complex; the rockyou+rules and hybrid phases do the heavy lifting |
| ETAs look wrong | `crackbaby benchmark <campaign> --update` (or `--update-all` for per-type) |
| Resume after Ctrl-C / reboot | just re-run `crackbaby run <campaign>` |
| Reclaim disk after a big run | `crackbaby clean --all --campaign <campaign> --dry-run` then `-y` |
