"""
e5b_side_information.py — Supplement to E5 (Section 9.6): the same hidden single-box policy probed with
three amounts of side information.

The hidden policy allows one box of realistic size on a deny background — a /24 source, one destination
host, any source port, one destination port, TCP — i.e. 2^24 of the 2^104 headers, as in E5.
  (A) no side information          : uniformly random probes over the whole 5-tuple (this is E5 itself;
                                       expected 2^80 probes, so it is not re-run here);
  (B) a service-inventory prior      : destination host, destination port and protocol are known, so random
                                       probes range over source address x source port only (2^48 headers,
                                       expected 2^24 probes to the first hit);
  (C) one witness packet             : a packet known to lie in the box; the box is recovered exactly by the
                                       binary searches of Theorem 2a / Algorithm A.1 (two per field). With a
                                       single box on a deny background the action oracle MQ and the identity
                                       oracle IDQ give the same information, so MQ alone suffices.
Cases (B) and (C) chain: the first hit of (B) is a witness for (C).

Output: results/E5b_side_information.csv
Usage : python e5b_side_information.py           (≈ 1 s)
Deterministic: fixed seeds; independent of the random streams of run_experiments.py.
"""
import os, csv, random
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results")
WIDTHS = [32, 32, 16, 16, 8]          # src, dst, sport, dport, proto (as in run_experiments.py)
W = [1 << w for w in WIDTHS]
TRIALS, BUDGET, BLOCK = 5, 10**8, 10**6


def main():
    rnd = random.Random(5005)
    npr = np.random.default_rng(5005)
    rows = []
    for k in range(TRIALS):
        s0 = rnd.randrange(0, W[0] - 256) & ~0xFF            # a /24 source block
        dst = rnd.randrange(W[1]); dport = rnd.randrange(W[3])
        lo = [s0, dst, 0, dport, 6]
        hi = [s0 + 255, dst, W[2] - 1, dport, 6]
        member = lambda p: all(lo[j] <= p[j] <= hi[j] for j in range(5))

        # (B) random probes over src x sport, with dst, dport and proto fixed to the known service
        first = None; done = 0
        while done < BUDGET and first is None:
            n = min(BLOCK, BUDGET - done)
            src = npr.integers(0, W[0], size=n, dtype=np.int64)
            sport = npr.integers(0, W[2], size=n, dtype=np.int64)  # always inside [0, W-1]: the box spans all source ports
            idx = np.flatnonzero((src >= lo[0]) & (src <= hi[0]))
            if idx.size:
                i = int(idx[0]); first = done + i + 1
                witness = [int(src[i]), dst, int(sport[i]), dport, 6]
            done += n
        assert first is not None and member(witness)

        # (C) exact recovery from the witness by binary search on each field (Algorithm A.1), MQ only
        probes = 0; rec_lo, rec_hi = [], []
        for j in range(5):
            a, b = witness[j], W[j]                              # right end: member at a, virtual non-member at W_j
            while b - a > 1:
                mid = (a + b) // 2; q = list(witness); q[j] = mid; probes += 1
                if member(q): a = mid
                else: b = mid
            rec_hi.append(a)
            a, b = -1, witness[j]                                # left end: virtual non-member at -1
            while b - a > 1:
                mid = (a + b) // 2; q = list(witness); q[j] = mid; probes += 1
                if member(q): b = mid
                else: a = mid
            rec_lo.append(b)
        probes += 1                                              # the action of the box (one MQ)
        exact = rec_lo == lo and rec_hi == hi
        assert exact
        rows.append(dict(trial=k, box_log2_volume=24, header_log2=sum(WIDTHS),
                         A_no_side_info_expected_log2=sum(WIDTHS) - 24,
                         B_prior_space_log2=WIDTHS[0] + WIDTHS[2], B_expected_probes=2**24, B_probes_to_first_hit=first,
                         C_witness_probes=probes, C_bound_2sum_plus_1=2 * sum(WIDTHS) + 1, C_exact=exact))
        print(f"trial {k}: (B) first hit after {first:,} probes (expected 2^24 = {2**24:,}); "
              f"(C) exact box from one witness with {probes} probes (bound {2*sum(WIDTHS)+1})", flush=True)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "E5b_side_information.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print("wrote results/E5b_side_information.csv")


if __name__ == "__main__":
    main()
