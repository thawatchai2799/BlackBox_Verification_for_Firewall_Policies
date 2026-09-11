"""
run_experiments.py — Experiments E1–E6 (simulation) of the accompanying manuscript.
Usage:  python3 run_experiments.py [--quick]
Outputs: results/*.csv and results/*.png
Expected runtime: --quick ≈ 1 min ;  full ≈ 20–40 min on a laptop (well under the 24 h budget). Windows: run with  python run_experiments.py
"""
import sys, os, csv, math, random, time
try:
    sys.stdout.reconfigure(encoding="utf-8")   # Windows consoles: avoid UnicodeEncodeError on symbols
except Exception:
    pass
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from a1sim import *

QUICK = "--quick" in sys.argv
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(OUT, exist_ok=True)
widths = DEFAULT_WIDTHS
SUMW = sum(widths)                     # 104 bits
rng = random.Random(2026)


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


# ------------------------------------------------------------------ E2: Tree-Rule + IDQ (Theorem 2b)
def E2():
    log("E2: Tree-Rule + IDQ + witnesses (Theorem 2b)")
    ms = [5, 10, 20, 50, 100, 200, 500, 1000] + ([] if QUICK else [2000, 5000])
    reps = 3 if QUICK else 10
    rows = []
    for m in ms:
        for r in range(reps):
            t = TreeRule.random_with_leaves(widths, m, seed=1000 * m + r)
            wit = t.witnesses(rng)
            orc = Oracle(t)
            t2 = learn_tr_idq(orc, wit, widths)
            eq = t.equivalent(t2, samples=2000, rng=rng)
            mm, beta = t.num_leaves(), t.num_breakpoints()
            ub = (mm - 1) * (max(widths) + len(widths)) + 2 * mm   # Theorem 2b: (m-1)(log W + d) + 2m
            lb = (mm - 1) * math.log2(max(1, (1 << min(widths)) / mm)) / math.log2(mm + 1) if mm > 1 else 0
            rows.append(dict(m=mm, beta=beta, queries=orc.total, upper=ub, lower_info=lb, equiv=eq))
            log(f"   m={mm:5d} beta={beta:5d} q={orc.total:7d}  ub={ub:7d} equiv={eq}")
    with open(os.path.join(OUT, "E2_tree_idq.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    plt.figure(figsize=(6, 4))
    plt.scatter([r["m"] for r in rows], [r["queries"] for r in rows], s=12, label="observed queries")
    xs = sorted(set(r["m"] for r in rows))
    plt.plot(xs, [(x - 1) * (max(widths) + len(widths)) + 2 * x for x in xs], "r--", label="upper bound (m-1)(log W+d)+2m")
    plt.plot(xs, [max(0, (x - 1) * math.log2(max(1, (1 << min(widths)) / x)) / math.log2(x + 1)) for x in xs], "g:", label="info-theoretic lower bound")
    plt.xscale("log"); plt.yscale("log"); plt.xlabel("leaves m"); plt.ylabel("probes")
    plt.title("E2: Tree-Rule reconstruction with IDQ + witnesses"); plt.legend(fontsize=7); plt.tight_layout()
    plt.savefig(os.path.join(OUT, "E2_tree_idq.png"), dpi=160); plt.close()
    assert all(r["equiv"] for r in rows), "E2: some reconstruction was NOT equivalent!"


# ------------------------------------------------------------------ E1: disjoint Listed-Rule + IDQ (Theorem 2a) vs same-semantics Tree-Rule
def E1():
    log("E1: disjoint Listed-Rule + IDQ vs Tree-Rule (Theorems 2a/2b, dimension factor)")
    ms = [5, 10, 20, 50, 100, 200] + ([] if QUICK else [500, 1000])
    reps = 3 if QUICK else 5
    rows = []
    for m in ms:
        for r in range(reps):
            t = TreeRule.random_with_leaves(widths, m, seed=777 * m + r)
            lr = ListedRule.from_tree(t)
            n = len(lr.rules)
            wit = lr.witnesses(rng)
            orc = Oracle(lr)
            lr2 = learn_lr_disjoint_idq(orc, wit, widths, n)
            eq = lr.equivalent(lr2, samples=2000, rng=rng)
            q_lr = orc.total
            orc2 = Oracle(t)
            learn_tr_idq(orc2, t.witnesses(rng), widths)
            q_tr = orc2.total
            rows.append(dict(n=n, q_listed=q_lr, bound_listed=2 * n * SUMW + n, q_tree=q_tr, ratio=q_lr / max(1, q_tr), equiv=eq))
            log(f"   n={n:5d}  LR q={q_lr:8d} (bound {2*n*SUMW+n})   TR q={q_tr:7d}   ratio={q_lr/max(1,q_tr):.1f}  equiv={eq}")
    with open(os.path.join(OUT, "E1_listed_vs_tree.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    plt.figure(figsize=(6, 4))
    plt.scatter([r["n"] for r in rows], [r["q_listed"] for r in rows], s=12, label="Listed-Rule (disjoint) probes")
    plt.scatter([r["n"] for r in rows], [r["q_tree"] for r in rows], s=12, marker="^", label="Tree-Rule probes (same semantics)")
    xs = sorted(set(r["n"] for r in rows))
    plt.plot(xs, [2 * x * SUMW + x for x in xs], "r--", label="LR bound 2·n·Σ log W_j + n")
    plt.xscale("log"); plt.yscale("log"); plt.xlabel("rules n = leaves m"); plt.ylabel("probes")
    plt.title("E1: same policy, listed vs tree representation"); plt.legend(fontsize=7); plt.tight_layout()
    plt.savefig(os.path.join(OUT, "E1_listed_vs_tree.png"), dpi=160); plt.close()
    assert all(r["equiv"] for r in rows)


# ------------------------------------------------------------------ E4: audit certificate (Theorem 3), reduced spec, single and combined faults
def E4():
    log("E4: audit certificate size and detection power (Theorem 3)")
    rng4 = random.Random(4)
    ms = [10, 20, 50, 100, 200] + ([] if QUICK else [500, 1000])
    trials = 30 if QUICK else 200
    rows = []
    for m in ms:
        t = reduce_tree(TreeRule.random_with_leaves(widths, m, seed=4242 + m))
        S = audit_certificate(t)
        mm, beta = t.num_leaves(), t.num_breakpoints()
        real = 0; detected = 0; real_c = 0; detected_c = 0
        for k in range(trials):
            f = structural_deviation(t, rng4)                                    # single fault
            if not t.equivalent(f, samples=1500, rng=rng4):
                real += 1; detected += any(f.action(s) != t.action(s) for s in S)
            g = structural_deviation(structural_deviation(t, rng4, "move"), rng4, "flip")   # combined: move + flip
            if not t.equivalent(g, samples=1500, rng=rng4):
                real_c += 1; detected_c += any(g.action(s) != t.action(s) for s in S)
        miss_sub = 0
        for k in range(trials):
            f = structural_deviation(t, rng4)
            if t.equivalent(f, samples=800, rng=rng4):
                continue
            Ssub = rng4.sample(S, int(0.7 * len(S)))
            if not any(f.action(s) != t.action(s) for s in Ssub):
                miss_sub += 1
        rows.append(dict(m=mm, beta=beta, cert_size=len(S), bound_3m_minus_2=3 * mm - 2, lower_bound=max(mm, math.ceil(2 * beta / len(widths))),
                         real_single=real, detected_single=detected, real_combined=real_c, detected_combined=detected_c, missed_by_70pct_subset=miss_sub))
        log(f"   m={mm:5d} beta={beta:5d} |S|={len(S):5d} (3m-2={3*mm-2})  single {detected}/{real}  combined {detected_c}/{real_c}  70%-subset misses={miss_sub}")
    with open(os.path.join(OUT, "E4_certificate.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    plt.figure(figsize=(6, 4))
    plt.plot([r["m"] for r in rows], [r["cert_size"] for r in rows], "o-", label="certificate size |S|")
    plt.plot([r["m"] for r in rows], [r["bound_3m_minus_2"] for r in rows], "r--", label="upper 3m − 2")
    plt.plot([r["m"] for r in rows], [r["lower_bound"] for r in rows], "g:", label="lower max(m, 2(m−1)/d)")
    plt.xlabel("leaves m"); plt.ylabel("packets"); plt.title("E4: minimal audit certificate"); plt.legend(fontsize=7); plt.tight_layout()
    plt.savefig(os.path.join(OUT, "E4_certificate.png"), dpi=160); plt.close()


# ------------------------------------------------------------------ E5: needle in haystack (Theorem 1)
def E5():
    log("E5: needle-in-haystack — random probing against a single hidden box (Theorem 1)")
    import numpy as np
    budget = 10**6 if QUICK else 10**8
    block = 10**6
    trials = 5
    W = [1 << w for w in widths]
    npr = np.random.default_rng(2026)
    lines = []
    for k in range(trials):
        # a single allow-box of realistic size: /24 src, one dst host, any sport, one dport, TCP
        s0 = rng.randrange(0, W[0] - 256); dst = rng.randrange(W[1]); dport = rng.randrange(W[3])
        lo = np.array([s0, dst, 0, dport, 6], dtype=np.int64)
        hi = np.array([s0 + 255, dst, W[2] - 1, dport, 6], dtype=np.int64)
        vol_log2 = 8 + 0 + widths[2] + 0 + 0
        found = None; done = 0
        while done < budget:
            n = min(block, budget - done)
            cols = [npr.integers(0, W[j], size=n, dtype=np.int64) for j in range(len(W))]
            hit = np.ones(n, dtype=bool)
            for j in range(len(W)):
                hit &= (cols[j] >= lo[j]) & (cols[j] <= hi[j])
            idx = np.flatnonzero(hit)
            if idx.size:
                found = done + int(idx[0]); break
            done += n
        line = f"trial {k}: box volume 2^{vol_log2} of 2^{SUMW}; expected probes ≈ 2^{SUMW - vol_log2}; found after {found} (budget {budget})"
        log("   " + line); lines.append(line)
    with open(os.path.join(OUT, "E5_needle.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ------------------------------------------------------------------ E3: Tree-Rule with MQ only (Theorem 2c) — auditor vs attacker gap
def E3():
    log("E3: Tree-Rule + MQ-only + witnesses vs IDQ (Theorem 2c, auditor–attacker gap)")
    configs = [([8, 8], [4, 8, 16, 32, 64]), ([8, 8, 8], [4, 8, 16, 24, 32]), ([16, 16, 8], [4, 8, 16, 24])]
    if not QUICK:
        configs.append(([8, 8, 8, 8], [4, 8, 12, 16]))
    reps = 2 if QUICK else 5
    rows = []
    for widths_, ms in configs:
        d_ = len(widths_)
        for m in ms:
            for r in range(reps):
                t = TreeRule.random_with_leaves(widths_, m, seed=31 * m + r + 1000 * d_)
                wit = t.witnesses(rng)
                o1 = Oracle(t); learn_tr_idq(o1, wit, widths_)
                o2 = Oracle(t); t2 = learn_tr_mq(o2, wit, widths_)
                eq = t.equivalent(t2, samples=1500, rng=rng)
                rows.append(dict(d=d_, m=t.num_leaves(), q_idq=o1.total, q_mq=o2.total, ratio=o2.total / max(1, o1.total), equiv=eq))
                log(f"   d={d_} m={t.num_leaves():4d}  IDQ q={o1.total:6d}  MQ-only q={o2.total:8d}  ratio={o2.total/max(1,o1.total):7.1f} equiv={eq}")
    with open(os.path.join(OUT, "E3_mq_vs_idq.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    plt.figure(figsize=(6, 4))
    for d_ in sorted(set(r["d"] for r in rows)):
        rs = [r for r in rows if r["d"] == d_]
        plt.scatter([r["m"] for r in rs], [r["q_mq"] for r in rs], s=14, label=f"MQ-only, d={d_}")
    rs = rows
    plt.scatter([r["m"] for r in rs], [r["q_idq"] for r in rs], s=10, marker="x", c="k", label="IDQ (all d)")
    plt.xscale("log"); plt.yscale("log"); plt.xlabel("leaves m"); plt.ylabel("probes")
    plt.title("E3: action-only observer vs identity oracle"); plt.legend(fontsize=7); plt.tight_layout()
    plt.savefig(os.path.join(OUT, "E3_mq_vs_idq.png"), dpi=160); plt.close()
    assert all(r["equiv"] for r in rows)


# ------------------------------------------------------------------ E6: effect of dimension d (Theorems 2a vs 2b) with IDQ, same semantics
def E6():
    log("E6: number of header fields d — listed vs tree probes (IDQ + witnesses)")
    ds = [2, 3, 4, 5, 6, 8] + ([] if QUICK else [10, 12])
    reps = 3 if QUICK else 6
    m = 60
    rows = []
    for d_ in ds:
        widths_ = [8] * d_
        for r in range(reps):
            t = TreeRule.random_with_leaves(widths_, m, seed=91 * d_ + r)
            lr = ListedRule.from_tree(t)
            o1 = Oracle(lr); learn_lr_disjoint_idq(o1, lr.witnesses(rng), widths_, len(lr.rules))
            o2 = Oracle(t); learn_tr_idq(o2, t.witnesses(rng), widths_)
            rows.append(dict(d=d_, n=len(lr.rules), q_listed=o1.total, q_tree=o2.total, ratio=o1.total / max(1, o2.total)))
            log(f"   d={d_:2d} n=m={len(lr.rules):3d}  LR q={o1.total:7d}  TR q={o2.total:6d}  ratio={o1.total/max(1,o2.total):.1f}")
    with open(os.path.join(OUT, "E6_dimension.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    plt.figure(figsize=(6, 4))
    for d_ in ds:
        rs = [r for r in rows if r["d"] == d_]
        plt.scatter([d_] * len(rs), [r["q_listed"] / r["n"] for r in rs], c="C0", s=14)
        plt.scatter([d_] * len(rs), [r["q_tree"] / r["n"] for r in rs], c="C1", marker="^", s=14)
    plt.scatter([], [], c="C0", label="listed: probes per rule"); plt.scatter([], [], c="C1", marker="^", label="tree: probes per leaf")
    plt.xlabel("number of header fields d"); plt.ylabel("probes per rule/leaf"); plt.title("E6: dimension dependence (8-bit fields)")
    plt.legend(fontsize=7); plt.tight_layout(); plt.savefig(os.path.join(OUT, "E6_dimension.png"), dpi=160); plt.close()


if __name__ == "__main__":
    t0 = time.time()
    E2(); E1(); E4(); E5(); E3(); E6()
    log(f"done in {(time.time()-t0)/60:.1f} min. Results in {OUT}")


