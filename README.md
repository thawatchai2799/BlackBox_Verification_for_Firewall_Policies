# Query complexity of black-box firewall verification — reproducibility package

Archived on Zenodo: concept DOI 10.5281/zenodo.21983101 (all versions; https://doi.org/10.5281/zenodo.21983101). This is release v1.4.

Code, data and experiment drivers accompanying the manuscript *"The price of auditing a firewall"*
(anonymised for review). The package reproduces every number, table and figure of the manuscript.

Everything is deterministic (fixed seeds); all results reproduced bit-for-bit on Windows 11 / Python 3.12 (PowerShell)
and Linux / Python 3.12 (WSL2 Ubuntu 24.04).

## Files
| file | purpose |
|---|---|
| `a1sim.py` | simulation library: header space, Tree-Rule / listed-rule policies, counting oracles (MQ, IDQ), learners for Theorems 2a, 2a″, 2b, 4, 6, the certificate of Theorem 3, tree reduction |
| `run_experiments.py` | E1–E6 (Sections 9.1–9.6): `python run_experiments.py` (≈ 3 min; `--quick` ≈ 1 min) |
| `make_figures.py` | regenerates all figures from `results/*.csv` |
| `e5b_side_information.py` | E5 supplement (Section 9.6): the same single-box policy probed with no side information, with a service-inventory prior, and from one witness (≈ 1 s) |
| `e7_realworld.py` | E7 (Section 9.7): 16 real iptables rule sets (embedded third-party data — see DATA_LICENSES.md), canonical Tree-Rule, reconstruction, certificates (≈ 5 min) |
| `e7b_redundancy.py` | E7 supplement (Section 9.7): classifies every rule of the 16 rule sets as shadowed, redundant or essential; `--check` verifies the classification by deleting each effective rule and rebuilding the policy (≈ 30 s; `--check` ≈ 2 min) |
| `e8_partial.py` | E8 (Section 9.8, Theorem 6): witnesses from sampled traffic (≈ 1 min) |
| `e9_sensitivity.py` | E9 (Section 9.9): wrong witnesses, noisy IDQ, non-reduced specifications (≈ 1 min) |
| `e10_overlap.py` | E10 (Section 9.10, Theorem 2a″): overlapping listed rules (≈ 1 min) |
| `e11_testbed.py` | E11 (Section 9.11): REAL iptables firewall in Linux network namespaces (Linux + root; ≈ 20–25 min) |
| `results/` | CSV tables and logs produced by the scripts (as used in the manuscript); `E11_testbed*.log/.csv` hold the real-firewall runs on two independent machines (Linux sandbox; WSL2 Ubuntu 24.04) |

## Requirements
Python ≥ 3.10; `pip install -r requirements.txt` (numpy, matplotlib; scapy only for E11).
E11 additionally needs Linux (WSL2 Ubuntu works), `iproute2`, `iptables`, the kernel modules `br_netfilter`,
`xt_iprange`, `xt_u32` (the script probes for them and falls back or explains), and root.

## Run the simulation experiments (any OS, ≈ 10 min total)
```
python run_experiments.py
python make_figures.py
python e5b_side_information.py
python e7_realworld.py
python e7b_redundancy.py --check
python e8_partial.py
python e9_sensitivity.py
python e10_overlap.py
```
On first run `e7_realworld.py` extracts the embedded rule sets to `data/realworld/`.

## Run the real-firewall testbed (Linux, root)
```
sudo apt install -y iptables iproute2 python3-scapy
sudo python3 e11_testbed.py --selftest      # 3-rule sanity check, ≈ 10 s, must print "selftest PASSED"
sudo python3 e11_testbed.py                 # 4 real policies, ≈ 20–25 min
```
The script creates and removes three network namespaces (`a1cl`, `a1fw`, `a1sv`); nothing else on the host is touched.

## Expected outcome
Every experiment reports `equiv=True` for all reconstructions; E5 reports 0 hits in 5×10^8 random probes; E11 reports
200/200 consistency for each chain, `equivalent=True`, 0 false alarms, all injected faults detected and 0 transcript
differences for the shadowed rule. Reference outputs are in `results/`.

## Mapping to the manuscript
E1 → Thm 2a/2b (Figure 2) · E2 → Thm 2b (Figure 1) · E3 → Thm 4 (Fig. 5) · E4 → Thm 3 (Fig. 4) · E5, E5b → Thm 1 and Section 9.6 · E6 → dimension
dependence (Fig. 3) · E7 → Table 3, Fig. 6 · E7b → shadowed/redundant/essential counts in Section 9.7 · E8 → Thm 6 (Fig. 7) · E9 → sensitivity · E10 → Thm 2a″ · E11 → Table 4 ·
all experiments → Table 5. Section and table numbers follow the revised manuscript (Sections 9.1–9.11 are the experiment subsections).

## Changes in v1.4
Figures only; no script other than `make_figures.py` changed and no measurement or CSV changed.
`make_figures.py` now typesets the axis labels and legend entries of all seven figures (`fig_E1`–`fig_E4`,
`fig_E6`–`fig_E8`) in mathematical notation (matplotlib mathtext, e.g. $2n\cdot\Sigma_j\lceil\log W_j\rceil+n$ instead
of `2n*sum(ceil(log W_j))+n`), matching the re-typeset manuscript; the PNG files in `results/` were regenerated at
600 dpi from the unchanged CSV files.

## Changes in v1.3
Two supplementary experiments were added for the revised manuscript; no existing measurement changed.
* `e7b_redundancy.py` → `results/E7b_redundancy.csv`: for each of the 16 rule sets, how many rules are shadowed,
  effective but redundant, or essential, and how many are ACCEPT or DROP rules (revised Section 9.7, which explains
  how the upper/lower approximations of the normal form produce the very large shadowed counts). The shadowed
  counts agree with `results/E7_realworld.csv` (the script asserts this); `--check` verifies the classification
  by deleting each effective rule and rebuilding the policy.
* `e5b_side_information.py` → `results/E5b_side_information.csv`: the single-box policy of E5 probed with a
  service-inventory prior and from one witness packet (revised Section 9.6).

Figure 7 (`fig_E8.png`): `make_figures.py` now places the legend above the bound line (axis head-room and
`loc="upper right"`); the data drawn are unchanged.

One correction: `e7_realworld.py` still wrote the pre-v1.2 Theorem 2b bound, (m−1)·32 + 3m − 1, into the
`tree_bound` column of `results/E7_realworld.csv`; it now writes (m−1)(32 + 5) + 2m. That column is an annotation
that the manuscript does not quote; all other columns of the file are byte-identical to v1.2.
The DOI line above now gives the concept DOI.

## Changes in v1.2
The upper bound of Theorem 2b was corrected from (m−1)⌈log W⌉ + 3m − 1 to (m−1)(⌈log W⌉ + d) + 2m: the
earlier proof counted the pair tests of `learn_tr_idq` once, whereas the algorithm re-tests each witness at
every level. No measurement changed. What changed: the bound formula in `run_experiments.py` (E2 `upper`
column), `e11_testbed.py` (E11 `bound` annotation) and `make_figures.py` (bound lines in Figures 1 and 3); the
`upper`/`bound` annotation columns in `results/E2_tree_idq.csv` and `results/E11_testbed.csv` were
recomputed with the corrected formula (the `queries`/`probes` measurements are byte-identical to v1.0; the
`.log` files are left as recorded).

## Licence
Code: MIT (see `LICENSE`).

**The embedded real-world rule sets are third-party data and are NOT covered by the MIT licence.**
The normal-form dumps come from https://github.com/diekmann/Iptables_Semantics (Cornelius Diekmann,
BSD 2-Clause — text in `THIRD_PARTY_LICENSE_Diekmann_BSD2.txt`); the raw dumps they derive from are published in
https://github.com/diekmann/net-network under CC BY-NC-SA 3.0/4.0. Per-file provenance and licences
are listed in `DATA_LICENSES.md`, which anyone reusing this repository must read first.
