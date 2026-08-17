"""e9_sensitivity.py — Sensitivity of the IDQ Tree-Rule learner (Thm 2b/6) to (a) wrong witnesses (packet labelled with a
leaf it does not belong to), (b) noisy identity feedback (a fraction of IDQ answers replaced by a random leaf id), and
(c) non-reduced vs reduced trees for the certificate of Thm 3 under combined faults.  Usage: python e9_sensitivity.py (≈1 min)"""
import os, sys, csv, math, random, time
try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass
from a1sim import *
HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "results"); os.makedirs(OUT, exist_ok=True)
widths = DEFAULT_WIDTHS; W = [1 << w for w in widths]
rng = random.Random(9)
def log(m): print(time.strftime("[%H:%M:%S] ") + m, flush=True)
def vol_err(t, t2, n=15000):
    bad = 0
    for _ in range(n):
        h = tuple(rng.randrange(Wj) for Wj in W)
        bad += t.action(h) != t2.action(h)
    return bad / n

rows = []
# ---------- (a) wrong witnesses: witness set is correct except that a fraction is replaced by random packets (they still
#            ARE packets of some leaf, so the learner treats them as witnesses of whatever leaf they fall in -> Thm 6 applies)
for m_t in [100, 400]:
    for rep in range(2):
        t = TreeRule.random_with_leaves(widths, m_t, seed=900 + m_t + rep); m = t.num_leaves()
        good = t.witnesses(rng)
        for frac in [0.0, 0.1, 0.3, 0.5]:
            wit = list(good)
            k = int(frac * m)
            for i in rng.sample(range(m), k):
                wit[i] = tuple(rng.randrange(Wj) for Wj in W)
            o = Oracle(t); t2 = learn_tr_idq_partial(o, wit, widths)
            err = vol_err(t, t2)
            rows.append(dict(exp="wrong_witness", m=m, param=frac, probes=o.total, error=err, note="fraction of witnesses replaced by random packets"))
            log(f"(a) m={m:4d} wrong-witness frac={frac:.1f} probes={o.total:6d} vol-error={err:.4f}")

# ---------- (b) noisy IDQ: each answer replaced with a uniformly random leaf id with prob p (learner unaware)
class NoisyOracle(Oracle):
    def __init__(self, p, prob, r): super().__init__(p); self.prob = prob; self.r = r
    def idq(self, h):
        v = super().idq(h)
        return self.r.randrange(self.p.num_leaves()) if self.r.random() < self.prob else v
for m_t in [100]:
    t = TreeRule.random_with_leaves(widths, m_t, seed=950); m = t.num_leaves(); wit = t.witnesses(rng)
    for prob in [0.0, 0.001, 0.01, 0.05]:
        errs = []; qs = []
        for rep in range(3):
            o = NoisyOracle(t, prob, random.Random(rep))
            try:
                t2 = learn_tr_idq(o, wit, widths); errs.append(vol_err(t, t2)); qs.append(o.total)
            except Exception as ex:
                errs.append(float("nan")); qs.append(o.total)
        rows.append(dict(exp="noisy_idq", m=m, param=prob, probes=sum(qs)/len(qs), error=sum(e for e in errs if e==e)/max(1,len([e for e in errs if e==e])), note="prob. each IDQ answer is a random id; error averaged over 3 runs"))
        log(f"(b) m={m:4d} noise p={prob:.3f} probes≈{sum(qs)/len(qs):.0f} vol-error≈{rows[-1]['error']:.4f} (runs with exception: {sum(1 for e in errs if e!=e)})")

# ---------- (c) certificate on non-reduced vs reduced trees under combined faults (move + flip)
for m_t in [50, 200]:
    for rep in range(2):
        t = TreeRule.random_with_leaves(widths, m_t, seed=990 + m_t + rep)
        for label, g in [("non-reduced", t), ("reduced", reduce_tree(t))]:
            S = audit_certificate(g); real = 0; det = 0
            for k in range(200):
                f = structural_deviation(structural_deviation(g, rng, "move"), rng, "flip")
                if not g.equivalent(f, samples=1200, rng=rng):
                    real += 1; det += any(f.action(s) != g.action(s) for s in S)
            rows.append(dict(exp="certificate_" + label, m=g.num_leaves(), param=len(S), probes=len(S), error=(real - det) / max(1, real), note="combined move+flip faults; error = missed fraction"))
            log(f"(c) {label:12s} m={g.num_leaves():4d} |S|={len(S):5d} combined faults detected {det}/{real}")

with open(os.path.join(OUT, "E9_sensitivity.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
log("done")
