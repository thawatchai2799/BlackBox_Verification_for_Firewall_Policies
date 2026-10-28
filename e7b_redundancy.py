"""
e7b_redundancy.py — Supplement to E7 (Section 9.7): shadowed, redundant and essential rules
in the 16 real iptables rule sets (Diekmann et al.; licences in DATA_LICENSES.md).

For every rule set in its simple-firewall normal form (first-match semantics, default deny,
exactly as in e7_realworld.py) each rule i is classified as
  * shadowed   : its effective region E_i is empty (it decides no packet);
  * redundant  : E_i is non-empty, but deleting rule i alone leaves the policy unchanged,
                 i.e. on every packet of E_i the next matching rule (or the default) has the same action;
  * essential  : E_i is non-empty and deleting rule i alone changes the policy.
The counts of ACCEPT and DROP rules are also reported, because they show the effect of the
upper/lower approximation used to produce the normal form (Section 9.7).

Method: the canonical first-match tree of e7_realworld.py is built with each leaf labelled by
(first matching rule, action of the second matching rule or the default). Every leaf is an
elementary box that each rule either contains or misses, so the labels are exact.
With --check, every effective rule of the chains with n <= 300 is additionally deleted and the
canonical tree rebuilt, and the result is compared with the classification (independent check).

Input : data/realworld/*.txt (extracted by e7_realworld.py on first run)
Output: results/E7b_redundancy.csv
Usage : python e7b_redundancy.py [--check]      (≈ 30 s; --check ≈ 2 min)
Deterministic: no randomness is used.
"""
import os, sys, csv
from functools import lru_cache

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.setrecursionlimit(100000)
import e7_realworld as e7

FIELDS = ["src", "dst", "proto", "sport", "dport"]
OUT = os.path.join(HERE, "results")


def field_order(name):
    """Use the best field order recorded by E7 (only for speed; the classification does not depend on it)."""
    path = os.path.join(OUT, "E7_realworld.csv")
    if os.path.exists(path):
        for r in csv.DictReader(open(path, encoding="utf-8")):
            if r["ruleset"] == name:
                return [FIELDS.index(f) for f in r["best_order"].split(",")]
    return [1, 4, 0, 3, 2]


def classify(rules, order):
    boxes = [r[0] for r in rules]; acts = [r[1] for r in rules]
    W, d = e7.W, len(order)

    @lru_cache(maxsize=None)
    def sub(level, idxs):
        if level == d:
            if not idxs:
                return ("L", -1, 0)
            nxt = acts[idxs[1]] if len(idxs) > 1 else 0          # default deny, as in e7_realworld.py
            return ("L", idxs[0], nxt)
        f = order[level]
        cuts = {0, W[f]}
        for i in idxs:
            lo, hi = boxes[i][f]; cuts.add(lo); cuts.add(hi + 1)
        cuts = sorted(cuts)
        kids = [sub(level + 1, tuple(i for i in idxs if boxes[i][f][0] <= a and b - 1 <= boxes[i][f][1]))
                for a, b in zip(cuts, cuts[1:])]
        merged = [kids[0]]
        for k in kids[1:]:
            if k != merged[-1]:
                merged.append(k)
        return ("N", tuple(merged))

    root = sub(0, tuple(range(len(rules))))
    nxt_actions, seen, stack = {}, set(), [root]
    while stack:
        nd = stack.pop()
        if id(nd) in seen:
            continue
        seen.add(id(nd))
        if nd[0] == "L":
            if nd[1] >= 0:
                nxt_actions.setdefault(nd[1], set()).add(nd[2])
        else:
            stack.extend(nd[1])
    redundant = {i for i, s in nxt_actions.items() if s == {acts[i]}}
    return set(nxt_actions), redundant


def semantic_key(rules, order):
    """canonical tree of the action function (identical keys <=> identical semantics)."""
    return e7.build_tree(rules, order)


def main():
    check = "--check" in sys.argv
    e7._ensure_data()
    files = sorted(f[:-4] for f in os.listdir(e7.DATA) if f.endswith(".txt") and not f.startswith("LICENSE"))
    e7_rows = {}
    p = os.path.join(OUT, "E7_realworld.csv")
    if os.path.exists(p):
        e7_rows = {r["ruleset"]: r for r in csv.DictReader(open(p, encoding="utf-8"))}
    rows = []
    print("ruleset                      n  accept   drop  shadowed  effective  redundant  essential  check")
    for name in files:
        rules = e7.parse_file(os.path.join(e7.DATA, name + ".txt"))
        n = len(rules); order = field_order(name)
        eff, red = classify(rules, order)
        acc = sum(1 for r in rules if r[1] == 1)
        if name in e7_rows:      # consistency with E7: shadowed = n - effective_rules
            assert n == int(e7_rows[name]["rules"]) and len(eff) == int(e7_rows[name]["effective_rules"]), name
        status = "-"
        if check and n <= 300:
            base = semantic_key(rules, order)
            brute = {i for i in eff if semantic_key(rules[:i] + rules[i + 1:], order) == base}
            assert brute == red, (name, sorted(brute ^ red))
            status = "ok"
        rows.append(dict(ruleset=name, rules=n, accept_rules=acc, drop_rules=n - acc, shadowed=n - len(eff),
                         effective=len(eff), effective_redundant=len(red), essential=len(eff) - len(red)))
        r = rows[-1]
        print(f"{name:26s} {n:5d} {acc:7d} {n-acc:6d} {r['shadowed']:9d} {r['effective']:10d} "
              f"{r['effective_redundant']:10d} {r['essential']:10d}  {status}", flush=True)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "E7b_redundancy.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print("wrote results/E7b_redundancy.csv")


if __name__ == "__main__":
    main()
