"""e10_overlap.py — Theorem 2a'': reconstruction of OVERLAPPING listed rules from IDQ + witnesses (CellSweep).
Random overlapping boxes, d = 2,3,4; every reconstruction checked for equivalence (exhaustively for d = 2).
Usage: python e10_overlap.py  (≈ 1 min)"""
import os, sys, csv, random, time
try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass
from a1sim import *
HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "results"); os.makedirs(OUT, exist_ok=True)
rng = random.Random(11)
def log(m): print(time.strftime("[%H:%M:%S] ") + m, flush=True)
rows = []
for widths in ([8, 8], [8, 8, 8], [6, 6, 6, 6]):
    d = len(widths)
    for n in [2, 3, 5, 8, 12]:
        for s in range(3):
            lr = ListedRule.random_boxes(widths, n, seed=s + 100 * n + 1000 * d, max_side_frac=0.6)
            wit = lr.witnesses(rng)
            o = Oracle(lr)
            lr2 = learn_lr_overlap_idq(o, wit, widths, n)
            if d == 2:
                W = [1 << w for w in widths]
                eq = all(lr.action((x, y)) == lr2.action((x, y)) for x in range(W[0]) for y in range(W[1]))
            else:
                eq = lr.equivalent(lr2, samples=6000, rng=rng)
            # overlap depth omega (max boxes containing a common packet, estimated on rule corners + samples)
            pts = [tuple(lo for lo, hi in b) for b, _ in lr.rules] + [tuple(hi for lo, hi in b) for b, _ in lr.rules]
            omega = max(sum(1 for b, _ in lr.rules if all(lo <= p[a] <= hi for a, (lo, hi) in enumerate(b))) for p in pts)
            rows.append(dict(d=d, n=n, n_eff=len(wit), omega=omega, queries=o.total, disjoint_bound=2 * n * sum(widths) + n, equiv=eq))
            log(f"d={d} n={n:2d} n_eff={len(wit):2d} omega={omega} queries={o.total:7d} disjoint-bound={2*n*sum(widths)+n:5d} equiv={eq}")
with open(os.path.join(OUT, "E10_overlap.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
assert all(r["equiv"] for r in rows)
log("done — all equivalent")
