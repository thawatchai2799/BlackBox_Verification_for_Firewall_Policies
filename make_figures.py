"""make_figures.py — regenerate paper figures from results/*.csv (run after run_experiments.py).
Figures are written to results/fig_E*.png. Uses only the CSV data, so figures always match the numbers.
"""
import os, csv, math, statistics as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(HERE, "results")
WIDTHS = [32, 32, 16, 16, 8]; SUMW = sum(WIDTHS); WMAX = 1 << 32
import sys
DPI = int(os.environ.get("FIG_DPI", "160"))
OUTDIR = os.environ.get("FIG_DIR", R)
os.makedirs(OUTDIR, exist_ok=True)
plt.rcParams.update({"font.size": 9, "figure.dpi": DPI})
def save(fig, name):
    fig.savefig(os.path.join(OUTDIR, name + ".png"), dpi=DPI)
    if os.environ.get("FIG_PDF"):
        fig.savefig(os.path.join(OUTDIR, name + ".pdf"))

def load(name):
    return list(csv.DictReader(open(os.path.join(R, name), encoding="utf-8")))

# ---------- Fig E2
E2 = load("E2_tree_idq.csv")
m = [int(r["m"]) for r in E2]; q = [int(r["queries"]) for r in E2]
xs = sorted(set(m))
fig, ax = plt.subplots(figsize=(5.2, 3.6))
ax.scatter(m, q, s=12, label="observed probes (100 trees)")
ax.plot(xs, [(x - 1) * (32 + 5) + 2 * x for x in xs], "r--", lw=1.2, label="upper bound (m−1)(log W + d) + 2m")
ax.plot(xs, [max(1, (x - 1) * math.log2(WMAX / x) / math.log2(x + 1)) for x in xs], "g:", lw=1.2, label="lower bound (m−1)·log(W/m)/log(m+1)")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("number of leaves m"); ax.set_ylabel("probes")
ax.set_title("Tree-Rule reconstruction, IDQ + witnesses (Thm 2b)"); ax.legend(fontsize=7); fig.tight_layout()
save(fig, "fig_E2"); plt.close(fig)

# ---------- Fig E1
E1 = load("E1_listed_vs_tree.csv")
n = [int(r["n"]) for r in E1]
fig, ax = plt.subplots(figsize=(5.2, 3.6))
ax.scatter(n, [int(r["q_listed"]) for r in E1], s=12, label="listed-rule (disjoint), IDQ")
ax.scatter(n, [int(r["q_tree"]) for r in E1], s=12, marker="^", label="Tree-Rule, same semantics, IDQ")
xs = sorted(set(n))
ax.plot(xs, [2 * x * SUMW + x for x in xs], "r--", lw=1.2, label="listed bound 2n·Σ log W_j + n = 209n")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("rules n = leaves m"); ax.set_ylabel("probes")
ax.set_title("Same policy, listed vs tree representation (Thm 2a/2b)"); ax.legend(fontsize=7); fig.tight_layout()
save(fig, "fig_E1"); plt.close(fig)

# ---------- Fig E6
E6 = load("E6_dimension.csv")
ds = sorted(set(int(r["d"]) for r in E6))
fig, ax = plt.subplots(figsize=(5.2, 3.6))
for d in ds:
    rs = [r for r in E6 if int(r["d"]) == d]
    ax.scatter([d] * len(rs), [int(r["q_listed"]) / int(r["n"]) for r in rs], c="C0", s=14)
    ax.scatter([d] * len(rs), [int(r["q_tree"]) / int(r["n"]) for r in rs], c="C1", marker="^", s=14)
ax.plot(ds, [16 * d + 1 for d in ds], "C0--", lw=1, label="listed bound per rule: 2d·8 + 1")
ax.plot(ds, [st.mean(((int(r["n"]) - 1) * (8 + d) + 2 * int(r["n"])) / int(r["n"]) for r in E6 if int(r["d"]) == d) for d in ds], "C1--", lw=1, label="tree bound per leaf: (m−1)(log W + d)/m + 2")
ax.scatter([], [], c="C0", label="listed: probes per rule"); ax.scatter([], [], c="C1", marker="^", label="tree: probes per leaf")
ax.set_xlabel("number of header fields d (8-bit fields, m ≈ 15–65)"); ax.set_ylabel("probes per rule / per leaf")
ax.set_title("Dimension dependence (Thm 2a vs 2b)"); ax.legend(fontsize=7); fig.tight_layout()
save(fig, "fig_E6"); plt.close(fig)
ratio_by_d = {d: st.mean(float(r["ratio"]) for r in E6 if int(r["d"]) == d) for d in ds}

# ---------- Fig E4
E4 = load("E4_certificate.csv")
mm = [int(r["m"]) for r in E4]
fig, ax = plt.subplots(figsize=(5.2, 3.6))
ax.plot(mm, [int(r["cert_size"]) for r in E4], "o-", label="certificate size |S|")
ax.plot(mm, [3 * x - 2 for x in mm], "r--", lw=1.2, label="upper bound 3m − 2")
ax.plot(mm, [int(r["lower_bound"]) for r in E4], "g:", lw=1.2, label="lower bound max(m, 2(m−1)/d)")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("number of leaves m"); ax.set_ylabel("packets")
ax.set_title("Audit certificate size (Thm 3)"); ax.legend(fontsize=7); fig.tight_layout()
save(fig, "fig_E4"); plt.close(fig)

# ---------- Fig E3
E3 = load("E3_mq_vs_idq.csv")
fig, ax = plt.subplots(figsize=(5.2, 3.6))
for i, d in enumerate(sorted(set(int(r["d"]) for r in E3))):
    rs = [r for r in E3 if int(r["d"]) == d]
    ax.scatter([int(r["m"]) for r in rs], [int(r["q_mq"]) for r in rs], s=14, c=f"C{i}", label=f"MQ-only, d = {d}")
ax.scatter([int(r["m"]) for r in E3], [int(r["q_idq"]) for r in E3], s=10, marker="x", c="k", label="IDQ (all d)")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("number of leaves m"); ax.set_ylabel("probes")
ax.set_title("Action-only observer vs identity oracle (Thm 4)"); ax.legend(fontsize=7); fig.tight_layout()
save(fig, "fig_E3"); plt.close(fig)


# ---------- Fig E7 (real rulesets)
E7 = load("E7_realworld.csv")
rs = [r for r in E7 if r["tree_probes"] not in ("", "None") and int(r["leaves"]) > 1]
fig, ax = plt.subplots(figsize=(5.2, 3.6))
ax.scatter([int(r["rules"]) for r in rs], [int(r["tree_probes"]) for r in rs], s=18, label="Tree-Rule reconstruction, IDQ + witnesses (measured)")
rc = [r for r in rs if r["certificate"] not in ("", "None")]
ax.scatter([int(r["rules"]) for r in rc], [int(r["certificate"]) for r in rc], s=18, marker="^", label="audit certificate size (Thm 3)")
xs = sorted(set(int(r["rules"]) for r in rs))
ax.plot(xs, [2 * x * SUMW + x for x in xs], "r--", lw=1, label="listed-rule bound 209 n (disjoint case)")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("rules n in the real ruleset"); ax.set_ylabel("packets")
ax.set_title("Real-world iptables rulesets (E7)"); ax.legend(fontsize=6.5); fig.tight_layout()
save(fig, "fig_E7"); plt.close(fig)


# ---------- Fig E8 (partial witnesses)
E8 = load("E8_partial.csv")
fig, ax = plt.subplots(figsize=(5.2, 3.6))
for mm in sorted(set(int(r["m"]) for r in E8)):
    rs = [r for r in E8 if int(r["m"]) == mm]
    ax.scatter([int(r["N"]) / mm for r in rs], [max(float(r["error"]), 1e-5) for r in rs], s=14, label=f"measured error, m = {mm}")
xs = [0.25, 0.5, 1, 2, 4, 16]
ax.plot(xs, [1 / (math.e * x) for x in xs], "r--", lw=1.2, label="bound m/(eN)")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("traffic sample size N / leaves m"); ax.set_ylabel("uniform-measure error of reconstruction")
ax.set_title("Partial witnesses from sampled traffic (Thm 6)"); ax.legend(fontsize=7); fig.tight_layout()
save(fig, "fig_E8"); plt.close(fig)

# ---------- summary printed for the paper
print("E2: N=%d, max m=%d, probes/m (m>=100): %.1f–%.1f, median %.1f" % (len(E2), max(m), min(q[i]/m[i] for i in range(len(m)) if m[i] >= 100), max(q[i]/m[i] for i in range(len(m)) if m[i] >= 100), st.median([q[i]/m[i] for i in range(len(m)) if m[i] >= 100])))
thr = 300 if any(int(r["n"]) >= 300 for r in E1) else 0          # --quick runs have no n >= 300
big = [float(r["ratio"]) for r in E1 if int(r["n"]) >= thr]
print("E1: N=%d, max n=%d, ratio n>=%d: %.1f–%.1f, listed probes/n: %.0f–%.0f" % (len(E1), max(n), thr, min(big), max(big), min(int(r["q_listed"])/int(r["n"]) for r in E1 if int(r["n"]) >= thr), max(int(r["q_listed"])/int(r["n"]) for r in E1 if int(r["n"]) >= thr)))
print("E6 ratio by d:", {d: round(v, 2) for d, v in ratio_by_d.items()})
print("E4: single %d/%d; combined %d/%d; |S|/m %.2f–%.2f; 70%%-subset miss %.1f%%–%.1f%%" % (sum(int(r["detected_single"]) for r in E4), sum(int(r["real_single"]) for r in E4), sum(int(r["detected_combined"]) for r in E4), sum(int(r["real_combined"]) for r in E4), min(int(r["cert_size"])/int(r["m"]) for r in E4), max(int(r["cert_size"])/int(r["m"]) for r in E4), min(100*int(r["missed_by_70pct_subset"])/int(r["real_single"]) for r in E4), max(100*int(r["missed_by_70pct_subset"])/int(r["real_single"]) for r in E4)))
for d in sorted(set(int(r["d"]) for r in E3)):
    rs = [(int(r["m"]), float(r["ratio"])) for r in E3 if int(r["d"]) == d]
    print("E3 d=%d: max ratio %.0f at m=%d (N=%d)" % (d, max(rs, key=lambda t: t[1])[1], max(rs, key=lambda t: t[1])[0], len(rs)))
