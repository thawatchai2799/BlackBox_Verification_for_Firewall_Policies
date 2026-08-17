"""e8_partial.py — Theorem 6: witnesses sampled from traffic (N packets) instead of one per leaf.
Measures the volume-weighted error of the reconstructed policy vs N and compares with the bound m/(eN).
Usage: python e8_partial.py   (≈ 1–2 min)"""
import os, sys, csv, math, random, time
try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
from a1sim import *
HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "results"); os.makedirs(OUT, exist_ok=True)
widths = DEFAULT_WIDTHS; W = [1 << w for w in widths]
rng = random.Random(88)

def log(m): print(time.strftime("[%H:%M:%S] ") + m, flush=True)

def volume_error(t, t2, samples=20000):
    """estimate uniform-measure disagreement between t and t2 (t2 has permuted? no: same field order)"""
    bad = 0
    for _ in range(samples):
        h = tuple(rng.randrange(Wj) for Wj in W)
        if t.action(h) != t2.action(h): bad += 1
    return bad / samples

rows = []
for m_target in [50, 200, 800]:
    for rep in range(3):
        t = TreeRule.random_with_leaves(widths, m_target, seed=1000 * m_target + rep)
        m = t.num_leaves()
        for N in [m // 4, m // 2, m, 2 * m, 4 * m, 16 * m]:
            # witnesses = N uniformly random packets (traffic sample under the uniform distribution)
            pk = [tuple(rng.randrange(Wj) for Wj in W) for _ in range(N)]
            covered = len(set(t.leaf_id(h) for h in pk))
            orc = Oracle(t)
            t2 = learn_tr_idq_partial(orc, pk, widths)
            err = volume_error(t, t2)
            discovered = t2.num_leaves()
            rows.append(dict(m=m, N=N, witnessed_leaves=covered, discovered_leaves=discovered, probes=orc.total, error=err, bound=m / (math.e * N)))
            log(f"m={m:4d} N={N:6d} witnessed={covered:4d} discovered={discovered:4d} probes={orc.total:7d} err={err:.4f} bound m/(eN)={m/(math.e*N):.4f}")
with open(os.path.join(OUT, "E8_partial.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
fig, ax = plt.subplots(figsize=(5.2, 3.6))
for m in sorted(set(r["m"] for r in rows)):
    rs = [r for r in rows if r["m"] == m]
    ax.scatter([r["N"] / r["m"] for r in rs], [max(r["error"], 1e-5) for r in rs], s=14, label=f"measured error, m = {m}")
xs = [0.25, 0.5, 1, 2, 4, 16]
ax.plot(xs, [1 / (math.e * x) for x in xs], "r--", lw=1.2, label="bound m/(eN)")
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("traffic sample size N / leaves m"); ax.set_ylabel("uniform-measure error of reconstruction")
ax.set_title("Partial witnesses from sampled traffic (Thm 6)"); ax.legend(fontsize=7); fig.tight_layout(); fig.savefig(os.path.join(OUT, "fig_E8.png"), dpi=160)
log("done")
