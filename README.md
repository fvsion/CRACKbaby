# CRACKbaby

```
                                        :*@@%-
                                     =@@@@@@@@@#
                                    *@@@@@@@@@@@@*
                                   :@@@#..:-.-%@@@=
                                   =@@*.=%%=*@@@@@@
                                   *@@%#@@@@@@@@@@@
                            .:=*#%%#@@@@@@%@@@@@@@+
                      .:=*#%%%%%%%%*=#@@@%==++*%#-
                  .::-=+%%%%%*=-::----:#@@@%%#=:.
                .:-====+*=:::::::-===-=*+%@@%+:
               :=****=::+=-::...:--:=:=#+:...
               =%%*+===--#:-::. :==+=.=%*:             _____ ______  ___  _____  _   __
              .+%=-::::-.*%@@@@@@@*#*+-%%=            /  __ \| ___ \/ _ \/  __ \| | / /
     .=#%*+*@@@%%=....:-.-@@@@@@#@*%=%-*@*:           | /  \/| |_/ / /_\ \ /  \/| |/ /
  :#@%@@@@%@%%@@#:  ..-=:*+     :@*#=%@-##-           | |    |    /|  _  | |    |    \
 %@@@@@#+%@+.:-:: ..-+=+**:     .%#=#*#.=%*:          | \__/\| |\ \| | | | \__/\| |\  \
 @@@@@@%#+===+*=:-::==*#*=.      =%--.=*:+@%@%#+:      \____/\_| \_\_| |_/\____/\_| \_/
 @@@@@@@@@@%#*#%***#%@%*=-.      :+*%%@%%=-:::==-               b  a  b  y
```

**CRACKbaby** is a single-file, standard-library-only Python orchestrator around
[hashcat](https://hashcat.net/hashcat/) for systematic, **resumable** NTLM password-recovery
engagements. Point it at the NTLM hashes from an Active Directory dump and it builds and
runs a prioritised pipeline of hashcat attacks — wordlists, rules, masks, hybrids,
combinators, and LM cracking — checkpointing after every phase, then produces a
pentest-quality audit report.

It does the campaign bookkeeping you'd otherwise do by hand: account filtering, attack
ordering, ETAs and time-gating, per-phase resume, potfile management, and reporting.

---

## Features

- **prep → init → run → report** workflow with everything stored in one campaign directory.
- **Resumable** — Ctrl-C any time; re-run to pick up exactly where you left off (per-phase
  hashcat restore files).
- **Account-aware prep** — filter machine, system/built-in, and disabled accounts; extract
  LM hashes.
- **LM fast-path** — brute-force the 7-char LM halves, then recover the case-correct NTLM
  password via toggle rules.
- **Org-targeted wordlists** — generate a high-value list from company name, location, and
  custom terms.
- **Static, benchmark-calibrated ETAs** and time-gating to skip phases that would take too
  long.
- **Pentest report** (text + JSON): accounts compromised vs unique passwords, length/charset
  and policy analysis, top patterns, and recommendations.
- **Pure stdlib** — no `pip install`, just Python + hashcat.

---

## Requirements

- Python 3.8+ (standard library only)
- hashcat 6.x or 7.x
- One or more wordlists (e.g. rockyou)
- Optional: `combinator.bin` (ships with hashcat) — only for very large wordlist×wordlist phases

---

## Installation

```bash
git clone https://github.com/fvsion/CRACKbaby crackbaby
cd crackbaby

# Make sure python3 and hashcat are on your PATH, then verify what crackbaby sees:
python3 crackbaby.py tools

# Fetch the default wordlist (rockyou, ~133 MB) into ~/wordlists:
python3 crackbaby.py tools --download rockyou
```

There is nothing to build or `pip install`. Optionally copy the config sample to set
defaults: `cp config/crackbaby.json.sample config/crackbaby.json`.

---

## Usage

```bash
# 1. Prep — extract NT hashes from a secretsdump/NTDS dump, dropping machine and
#    system accounts and grabbing LM hashes. --username enables account-level reporting.
python3 crackbaby.py prep \
    --ntds secretsdump.out --output target.hashes \
    --username --no-machines --no-system --lm-file target.lm

# 2. Init — create a campaign and build the attack pipeline. rockyou is the default
#    wordlist (auto-discovered from ~/wordlists), so --wordlists is optional. Add
#    --org-config for a targeted wordlist and --lm-hashes to enable the LM fast-path.
python3 crackbaby.py init /campaigns/acme \
    --hashes target.hashes --username \
    --org-config acme.org.json \
    --lm-hashes target.lm \
    --expected-speed 120 --skip-slow 24

# 3. Run — execute (or resume) the pipeline. Ctrl-C checkpoints cleanly.
python3 crackbaby.py run /campaigns/acme

# 4. Report — generate the audit report (report.txt + report.json).
python3 crackbaby.py report /campaigns/acme
```

Measure your GPU to get accurate ETAs/time-gating: `python3 crackbaby.py benchmark /campaigns/acme --update`.

Run any command with `--help` for its full options. See **[USER_GUIDE.md](USER_GUIDE.md)**
for the complete workflow and strategy.

---

## Commands

| Command     | Description                                       |
|-------------|---------------------------------------------------|
| `prep`      | Extract NT hashes from an NTDS/secretsdump dump   |
| `init`      | Create a new cracking campaign                    |
| `run`       | Run (or resume) a campaign                        |
| `phases`    | List, skip, unskip, or delete phases              |
| `report`    | Generate the password-audit report               |
| `benchmark` | Measure GPU speed and calibrate ETAs              |
| `add`       | Add wordlists/rules to an existing campaign       |
| `rebuild`   | Change settings and regenerate the phase list     |
| `tools`     | Show tool status (hashcat, combinator.bin)        |
| `clean`     | Delete campaign logs and the rules cache          |

---

## Configuration

Defaults live in `config/crackbaby.json` (or the path in `$CRACKBABY_CONFIG`); CLI flags
always override them. Every key is documented inline in
[`config/crackbaby.json.sample`](config/crackbaby.json.sample), and the org-wordlist
template in [`config/org.json.sample`](config/org.json.sample).

---

## Documentation

- **[USER_GUIDE.md](USER_GUIDE.md)** — full operational guide: account-filtering strategy,
  the attack pipeline, LM cracking, org wordlists, rule depth, time-gating, reading the
  report, and the command reference.
- **[WALKTHROUGH.md](WALKTHROUGH.md)** — a hands-on, end-to-end example campaign against
  the bundled sample dump, with real command output.

---

## License

See [LICENSE](LICENSE).

---

<sub>_Donations (optional):_ ETH `0xb95bB92446CB7beDF93520800F1b050191A37f28` · BTC `bc1qcjr4wy0gcymd05ndek4nhjd4auq2clam8v7e3t` · SOL `Gp9hD1ar8MWKs2kino4ZNiVJ8HPuLHDRCigbXtgNzpxq`</sub>
