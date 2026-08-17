"""
a1sim.py — Simulation library for the query-complexity study of black-box firewall verification
(listed-rule and Tree-Rule policies)

Contents
  * Header space (IPv4 5-tuple by default: 32,32,16,16,8 bits)
  * Tree-Rule (TR) policies with fixed field order; Listed-Rule (LR) policies
  * Counting oracles: MQ (action), IDQ (rule / leaf id)
  * Learners:  learn_tr_idq  (Theorem 2b),  learn_lr_disjoint_idq (Theorem 2a, disjoint)
  * Audit certificate for structural deviations (Theorem 3)
Pure Python, no dependencies.
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict

DEFAULT_WIDTHS = [32, 32, 16, 16, 8]        # src IP, dst IP, src port, dst port, proto


# ----------------------------------------------------------------------------
# Tree-Rule policy
# ----------------------------------------------------------------------------
@dataclass
class TRNode:
    depth: int                                  # field index tested here (0..d-1); depth==d -> leaf
    breaks: List[int] = field(default_factory=list)   # sorted breakpoints b_1<...<b_{k-1}; child s covers [b_{s-1}, b_s)
    children: List["TRNode"] = field(default_factory=list)
    action: int = -1                            # for leaves
    leaf_id: int = -1

    def is_leaf(self) -> bool:
        return self.depth < 0 or self.action >= 0 and not self.children


class TreeRule:
    def __init__(self, widths=DEFAULT_WIDTHS):
        self.widths = widths
        self.d = len(widths)
        self.W = [1 << w for w in widths]
        self.root: Optional[TRNode] = None
        self.leaves: List[TRNode] = []

    # ---- random generation ----
    @staticmethod
    def random(widths=DEFAULT_WIDTHS, max_children=4, target_leaves=None, seed=None, p_split=0.7):
        rng = random.Random(seed)
        t = TreeRule(widths)
        d = t.d

        def build(depth, lo_hi):
            node = TRNode(depth=depth)
            if depth == d:
                node.action = rng.randint(0, 1)
                return node
            W = t.W[depth]
            k = 1
            if rng.random() < p_split:
                k = rng.randint(2, max_children)
            # choose k-1 distinct breakpoints in [1, W-1]
            if k > 1:
                bps = sorted(rng.sample(range(1, W), k - 1))
            else:
                bps = []
            node.breaks = bps
            node.children = [build(depth + 1, None) for _ in range(k)]
            return node

        # keep sampling until leaf count is in a reasonable range around target
        while True:
            t.root = build(0, None)
            t._index_leaves()
            if target_leaves is None or abs(len(t.leaves) - target_leaves) <= max(2, target_leaves // 4):
                break
        return t

    @staticmethod
    def random_with_leaves(widths, m, seed=None, max_children=6):
        """Grow a tree until it has ~m leaves by repeatedly splitting random leaves' ancestors.
        Simpler: build depth-first with fan-out chosen so product ~ m."""
        rng = random.Random(seed)
        t = TreeRule(widths)
        d = t.d
        # choose per-level fanout so that prod ~= m
        fan = [1] * d
        cur = 1
        i = 0
        while cur * 2 <= m:
            fan[i % d] += 1
            cur = 1
            for f in fan:
                cur *= f
            i += 1

        def build(depth):
            node = TRNode(depth=depth)
            if depth == d:
                node.action = rng.randint(0, 1)
                return node
            k = fan[depth]
            # jitter
            if k > 1 and rng.random() < 0.3:
                k = max(1, k + rng.choice([-1, 1]))
            W = t.W[depth]
            bps = sorted(rng.sample(range(1, W), k - 1)) if k > 1 else []
            node.breaks = bps
            node.children = [build(depth + 1) for _ in range(k)]
            return node

        t.root = build(0)
        t._index_leaves()
        return t

    def _index_leaves(self):
        self.leaves = []

        def rec(node):
            if node.depth == self.d:
                node.leaf_id = len(self.leaves)
                self.leaves.append(node)
            else:
                for c in node.children:
                    rec(c)
        rec(self.root)

    # ---- semantics ----
    def _descend(self, h):
        node = self.root
        while node.depth < self.d:
            v = h[node.depth]
            # find child index: number of breaks <= v
            s = 0
            for b in node.breaks:
                if v >= b:
                    s += 1
                else:
                    break
            node = node.children[s]
        return node

    def action(self, h) -> int:
        return self._descend(h).action

    def leaf_id(self, h) -> int:
        return self._descend(h).leaf_id

    def num_leaves(self):
        return len(self.leaves)

    def num_breakpoints(self):
        cnt = 0

        def rec(node):
            nonlocal cnt
            if node.depth < self.d:
                cnt += len(node.breaks)
                for c in node.children:
                    rec(c)
        rec(self.root)
        return cnt

    # ---- witnesses: one packet per leaf ----
    def leaf_regions(self) -> List[List[Tuple[int, int]]]:
        regs = []

        def rec(node, box):
            if node.depth == self.d:
                regs.append(list(box))
                return
            lo = 0
            bounds = node.breaks + [self.W[node.depth]]
            for s, c in enumerate(node.children):
                hi = bounds[s] - 1
                rec(c, box + [(lo, hi)])
                lo = bounds[s]
        rec(self.root, [])
        return regs

    def witnesses(self, rng: random.Random):
        return [tuple(rng.randint(lo, hi) for (lo, hi) in reg) for reg in self.leaf_regions()]

    def equivalent(self, other: "TreeRule", samples=20000, rng=None) -> bool:
        """Randomized equivalence check plus exhaustive check on all leaf-region corners."""
        rng = rng or random.Random(0)
        for reg in self.leaf_regions() + other.leaf_regions():
            # test corners & interior point
            pts = [tuple(lo for lo, hi in reg), tuple(hi for lo, hi in reg),
                   tuple((lo + hi) // 2 for lo, hi in reg)]
            for p in pts:
                if self.action(p) != other.action(p):
                    return False
        for _ in range(samples):
            h = tuple(rng.randrange(W) for W in self.W)
            if self.action(h) != other.action(h):
                return False
        return True


# ----------------------------------------------------------------------------
# Listed-Rule policy
# ----------------------------------------------------------------------------
class ListedRule:
    def __init__(self, widths, rules: List[Tuple[List[Tuple[int, int]], int]], default=0):
        self.widths = widths
        self.d = len(widths)
        self.W = [1 << w for w in widths]
        self.rules = rules          # list of (box, action), box = [(lo,hi)]*d inclusive
        self.default = default

    @staticmethod
    def from_tree(t: TreeRule):
        rules = [(reg, leaf.action) for reg, leaf in zip(t.leaf_regions(), t.leaves)]
        return ListedRule(t.widths, rules, default=0)

    @staticmethod
    def random_boxes(widths, n, seed=None, max_side_frac=0.3):
        rng = random.Random(seed)
        W = [1 << w for w in widths]
        rules = []
        for _ in range(n):
            box = []
            for Wj in W:
                side = rng.randint(1, max(1, int(Wj * max_side_frac)))
                lo = rng.randint(0, Wj - side)
                box.append((lo, lo + side - 1))
            rules.append((box, rng.randint(0, 1)))
        return ListedRule(widths, rules)

    def _in_box(self, h, box):
        return all(lo <= h[j] <= hi for j, (lo, hi) in enumerate(box))

    def match_index(self, h) -> int:
        for i, (box, a) in enumerate(self.rules):
            if self._in_box(h, box):
                return i
        return -1

    def action(self, h):
        i = self.match_index(h)
        return self.default if i < 0 else self.rules[i][1]

    def witnesses(self, rng, tries=2000):
        """One packet per non-shadowed rule (inside E_i). Returns dict i -> h."""
        wit = {}
        for i, (box, a) in enumerate(self.rules):
            for _ in range(tries):
                h = tuple(rng.randint(lo, hi) for lo, hi in box)
                if self.match_index(h) == i:
                    wit[i] = h
                    break
        return wit

    def equivalent(self, other, samples=20000, rng=None):
        rng = rng or random.Random(0)
        for box, _ in self.rules + other.rules:
            for p in (tuple(lo for lo, hi in box), tuple(hi for lo, hi in box)):
                if self.action(p) != other.action(p):
                    return False
        for _ in range(samples):
            h = tuple(rng.randrange(W) for W in self.W)
            if self.action(h) != other.action(h):
                return False
        return True


# ----------------------------------------------------------------------------
# Counting oracles
# ----------------------------------------------------------------------------
class Oracle:
    def __init__(self, policy):
        self.p = policy
        self.mq_count = 0
        self.idq_count = 0

    def mq(self, h) -> int:
        self.mq_count += 1
        return self.p.action(h)

    def idq(self, h) -> int:
        self.idq_count += 1
        if isinstance(self.p, TreeRule):
            return self.p.leaf_id(h)
        return self.p.match_index(h)

    @property
    def total(self):
        return self.mq_count + self.idq_count


# ----------------------------------------------------------------------------
# Learner for Theorem 2b:  Tree-Rule with IDQ + one witness per leaf
# ----------------------------------------------------------------------------
def learn_tr_idq(oracle: Oracle, witnesses: List[tuple], widths) -> TreeRule:
    d = len(widths)
    W = [1 << w for w in widths]
    ids = {h: oracle.idq(h) for h in witnesses}          # m queries: leaf id of every witness

    def bsearch_break(w, j, id_w, lo, hi):
        """largest t in [lo,hi] with idq(w[j<-t]) == id_w is t*; return t*+1 (the breakpoint).
        Precondition: predicate true at lo, false at hi."""
        while hi - lo > 1:
            mid = (lo + hi) // 2
            p = list(w); p[j] = mid
            if oracle.idq(tuple(p)) == id_w:
                lo = mid
            else:
                hi = mid
        return hi

    def build(j, wits):
        node = TRNode(depth=j)
        if j == d:
            # leaf; action from one MQ on the (single) witness
            node.action = oracle.mq(wits[0])
            return node
        wits = sorted(wits, key=lambda h: h[j])
        groups = [[wits[0]]]
        breaks = []
        for w_prev, w_next in zip(wits, wits[1:]):
            p = list(w_prev); p[j] = w_next[j]
            same = (oracle.idq(tuple(p)) == ids[w_prev])       # 1 query per adjacent pair
            if same:
                groups[-1].append(w_next)
            else:
                b = bsearch_break(w_prev, j, ids[w_prev], w_prev[j], w_next[j])
                breaks.append(b)
                groups.append([w_next])
        node.breaks = breaks
        node.children = [build(j + 1, g) for g in groups]
        return node

    t = TreeRule(widths)
    t.root = build(0, list(witnesses))
    t._index_leaves()
    return t


# ----------------------------------------------------------------------------
# Learner for Theorem 2a (disjoint boxes):  LR with IDQ + one witness per rule
# ----------------------------------------------------------------------------
def learn_lr_disjoint_idq(oracle: Oracle, witnesses: Dict[int, tuple], widths, n_rules) -> ListedRule:
    W = [1 << w for w in widths]
    d = len(widths)

    def extent(h, j, idx):
        # right end
        lo, hi = h[j], W[j]          # predicate true at lo; false at hi (virtual)
        while hi - lo > 1:
            mid = (lo + hi) // 2
            p = list(h); p[j] = mid
            if oracle.idq(tuple(p)) == idx:
                lo = mid
            else:
                hi = mid
        right = lo
        lo, hi = -1, h[j]            # false at -1 virtual, true at h[j]
        while hi - lo > 1:
            mid = (lo + hi) // 2
            p = list(h); p[j] = mid
            if oracle.idq(tuple(p)) == idx:
                hi = mid
            else:
                lo = mid
        left = hi
        return (left, right)

    rules = []
    default_pt = [None]
    _idq = oracle.idq
    def idq_rec(h):
        r = _idq(h)
        if r < 0 and default_pt[0] is None:
            default_pt[0] = h
        return r
    oracle.idq = idq_rec
    for i in range(n_rules):
        if i not in witnesses:
            rules.append(([(0, -1)] * d, 0))      # shadowed / empty rule: empty box
            continue
        h = witnesses[i]
        box = [extent(h, j, i) for j in range(d)]
        a = oracle.mq(h)
        rules.append((box, a))
    oracle.idq = _idq
    default = oracle.mq(default_pt[0]) if default_pt[0] is not None else 0     # one MQ if a default packet was seen
    return ListedRule(widths, rules, default=default)


# ----------------------------------------------------------------------------
# Theorem 3:  audit certificate for structural deviations of a Tree-Rule spec
# ----------------------------------------------------------------------------
def _subtree_regions(node, d, W, prefix_len):
    """regions (list of intervals over fields prefix_len..d-1) and actions of the leaves under node"""
    out = []

    def rec(nd, box):
        if nd.depth == d:
            out.append((list(box), nd.action))
            return
        lo = 0
        bounds = nd.breaks + [W[nd.depth]]
        for s, c in enumerate(nd.children):
            rec(c, box + [(lo, bounds[s] - 1)])
            lo = bounds[s]
    rec(node, [])
    return out


def _eval_subtree(node, d, y):
    """evaluate subtree rooted at node on suffix coordinates y (fields node.depth..d-1)"""
    nd = node
    k = 0
    while nd.depth < d:
        v = y[k]
        s = 0
        for b in nd.breaks:
            if v >= b:
                s += 1
            else:
                break
        nd = nd.children[s]
        k += 1
    return nd.action


def audit_certificate(t: TreeRule) -> List[tuple]:
    """Return a set S of packets: one per leaf + two straddling every breakpoint on a distinguishing slice."""
    d, W = t.d, t.W
    S = []
    # one packet per leaf
    for reg in t.leaf_regions():
        S.append(tuple((lo + hi) // 2 for lo, hi in reg))

    def rec(node, prefix):        # prefix: list of chosen coordinates for fields < node.depth
        if node.depth == d:
            return
        j = node.depth
        bounds = node.breaks + [W[j]]
        lo = 0
        for s in range(len(node.children) - 1):
            c, c2 = node.children[s], node.children[s + 1]
            b = bounds[s]                       # breakpoint: c covers [lo, b-1], c2 covers [b, ...]
            # find y (fields j+1..d-1) with c(y) != c2(y)
            y = None
            regs_c = _subtree_regions(c, d, W, j + 1)
            regs_c2 = _subtree_regions(c2, d, W, j + 1)
            for reg1, a1 in regs_c:
                for reg2, a2 in regs_c2:
                    if a1 == a2:
                        continue
                    inter = [(max(l1, l2), min(h1, h2)) for (l1, h1), (l2, h2) in zip(reg1, reg2)]
                    if all(l <= h for l, h in inter):
                        y = tuple((l + h) // 2 for l, h in inter)
                        break
                if y is not None:
                    break
            if y is not None:                   # (if None: siblings equivalent — spec not minimal; skip)
                S.append(tuple(prefix + [b - 1] + list(y)))
                S.append(tuple(prefix + [b] + list(y)))
            lo = b
        # recurse: choose a coordinate inside each child's interval
        lo = 0
        for s, c in enumerate(node.children):
            hi = bounds[s] - 1
            rec(c, prefix + [(lo + hi) // 2])
            lo = bounds[s]
    rec(t.root, [])
    # dedupe
    return list(dict.fromkeys(S))


def structural_deviation(t: TreeRule, rng: random.Random, kind=None) -> TreeRule:
    """Return a copy of t with either one leaf action flipped or one breakpoint moved (same shape)."""
    import copy
    t2 = copy.deepcopy(t)
    t2._index_leaves()
    kind = kind or rng.choice(["flip", "move"])
    if kind == "flip":
        leaf = rng.choice(t2.leaves)
        leaf.action ^= 1
        return t2
    # move: collect internal nodes with breaks
    internals = []

    def rec(nd):
        if nd.depth < t2.d:
            if nd.breaks:
                internals.append(nd)
            for c in nd.children:
                rec(c)
    rec(t2.root)
    if not internals:
        return structural_deviation(t, rng, "flip")
    nd = rng.choice(internals)
    i = rng.randrange(len(nd.breaks))
    lo = nd.breaks[i - 1] + 1 if i > 0 else 1
    hi = nd.breaks[i + 1] - 1 if i + 1 < len(nd.breaks) else t2.W[nd.depth] - 1
    delta = rng.choice([-1, 1]) * rng.randint(1, max(1, min(1000, (hi - lo) // 2 + 1)))
    newb = min(max(nd.breaks[i] + delta, lo), hi)
    if newb == nd.breaks[i]:
        newb = nd.breaks[i] + 1 if nd.breaks[i] + 1 <= hi else nd.breaks[i] - 1
    nd.breaks[i] = newb
    return t2


# ----------------------------------------------------------------------------
# Learner for Theorem 2c:  Tree-Rule with MQ only + one witness per leaf (slice recursion, O(m^d log W))
# ----------------------------------------------------------------------------
def learn_tr_mq(oracle: Oracle, witnesses: List[tuple], widths) -> TreeRule:
    d = len(widths)
    W = [1 << w for w in widths]

    def eval_tree(node, y):          # y = suffix coordinates for fields node.depth..d-1
        return _eval_subtree(node, d, y)

    def trees_equal(a, b, depth):
        """exact equality of two subtrees over fields depth..d-1 (structural compare after canonical merge)"""
        if depth == d:
            return a.action == b.action
        # compare via regions: build cell grid from both break sets
        cuts = sorted(set(a.breaks) | set(b.breaks))
        bounds = [0] + cuts + [W[depth]]
        for lo, hi in zip(bounds, bounds[1:]):
            if lo >= hi:
                continue
            ca = _child_at(a, lo); cb = _child_at(b, lo)
            if not trees_equal(ca, cb, depth + 1):
                return False
        return True

    def find_diff(a, b, depth):
        """return suffix y (fields depth..d-1) with a(y) != b(y), assuming they differ"""
        if depth == d:
            return ()
        cuts = sorted(set(a.breaks) | set(b.breaks))
        bounds = [0] + cuts + [W[depth]]
        for lo, hi in zip(bounds, bounds[1:]):
            if lo >= hi:
                continue
            ca = _child_at(a, lo); cb = _child_at(b, lo)
            if not trees_equal(ca, cb, depth + 1):
                return (lo,) + find_diff(ca, cb, depth + 1)
        raise RuntimeError("no difference found")

    def learn(prefix, j, wits):
        node = TRNode(depth=j)
        if j == d:
            node.action = oracle.mq(tuple(prefix))
            return node
        vals = sorted(set(w[j] for w in wits))
        subs = []
        for v in vals:
            proj = [tuple(list(prefix) + [v] + list(w[j + 1:])) for w in wits]
            subs.append((v, learn(list(prefix) + [v], j + 1, proj)))
        # merge equal adjacent slices, find breakpoints between different ones
        groups = [[subs[0]]]
        breaks = []
        for (v1, g1), (v2, g2) in zip(subs, subs[1:]):
            if trees_equal(g1, g2, j + 1):
                groups[-1].append((v2, g2))
            else:
                y = find_diff(g1, g2, j + 1)
                lo, hi = v1, v2          # true at lo (== g1 slice), false at hi
                gv = eval_tree(g1, y)
                while hi - lo > 1:
                    mid = (lo + hi) // 2
                    if oracle.mq(tuple(list(prefix) + [mid] + list(y))) == gv:
                        lo = mid
                    else:
                        hi = mid
                # note: equality at one point suffices because along this line f can only change at breakpoints of this node
                breaks.append(hi)
                groups.append([(v2, g2)])
        node.breaks = breaks
        node.children = [g[0][1] for g in groups]
        return node

    t = TreeRule(widths)
    t.root = learn([], 0, list(witnesses))
    t._index_leaves()
    return t


def _child_at(node, v):
    s = 0
    for b in node.breaks:
        if v >= b:
            s += 1
        else:
            break
    return node.children[s]


# ----------------------------------------------------------------------------
# Theorem 6: partial witnesses — IDQ learner that adopts newly discovered leaf identifiers as witnesses
# ----------------------------------------------------------------------------
def learn_tr_idq_partial(oracle: Oracle, witnesses: List[tuple], widths) -> TreeRule:
    """Same as learn_tr_idq but the witness set may miss leaves. Whenever a probe returns a leaf id not seen
    before, the probed packet is adopted as a witness for that leaf and the (sub)tree is re-learned locally.
    Guarantee (Thm 6): output agrees with the hidden policy on every leaf that contains a probed packet."""
    d = len(widths)
    ids: Dict[tuple, int] = {}
    known_ids = set()

    def q(h):
        r = oracle.idq(h)
        return r

    def build(j, wits):
        node = TRNode(depth=j)
        if j == d:
            node.action = oracle.mq(wits[0]); return node
        while True:
            wits = sorted(set(wits), key=lambda h: h[j])
            groups = [[wits[0]]]; breaks = []; restart = False
            for w_prev, w_next in zip(wits, wits[1:]):
                p = list(w_prev); p[j] = w_next[j]; p = tuple(p)
                r = q(p)
                if r not in known_ids:              # discovered a leaf without witness -> adopt and restart this node
                    known_ids.add(r); ids[p] = r; wits.append(p); restart = True; break
                if r == ids[w_prev]:
                    groups[-1].append(w_next)
                else:
                    lo, hi = w_prev[j], w_next[j]
                    while hi - lo > 1:
                        mid = (lo + hi) // 2
                        pm = list(w_prev); pm[j] = mid; pm = tuple(pm)
                        rm = q(pm)
                        if rm not in known_ids:
                            known_ids.add(rm); ids[pm] = rm; wits.append(pm); restart = True; break
                        if rm == ids[w_prev]:
                            lo = mid
                        else:
                            hi = mid
                    if restart:
                        break
                    breaks.append(hi); groups.append([w_next])
            if not restart:
                break
        node.breaks = breaks
        node.children = [build(j + 1, g) for g in groups]
        return node

    for h in witnesses:
        r = oracle.idq(h); ids[h] = r; known_ids.add(r)
    t = TreeRule(widths)
    t.root = build(0, list(dict.fromkeys(witnesses)))
    t._index_leaves()
    return t


# ----------------------------------------------------------------------------
# Reduction: merge adjacent semantically-equivalent siblings (needed by Theorem 3: the spec must be reduced)
# ----------------------------------------------------------------------------
def _subtree_key(node, d):
    """canonical hashable description of the subtree (semantics over remaining fields)"""
    if node.depth == d:
        return ("L", node.action)
    return ("N", tuple(node.breaks), tuple(_subtree_key(c, d) for c in node.children))


def reduce_tree(t: TreeRule) -> TreeRule:
    """Return a new TreeRule equivalent to t in which no two adjacent siblings are semantically equal."""
    import copy
    t2 = copy.deepcopy(t)
    d = t2.d

    def rec(node):
        if node.depth == d:
            return
        for c in node.children:
            rec(c)
        keys = [_subtree_key(c, d) for c in node.children]
        new_children = [node.children[0]]; new_breaks = []; last_key = keys[0]
        for b, c, k in zip(node.breaks, node.children[1:], keys[1:]):
            if k == last_key:
                continue                     # merge: drop the breakpoint, keep the earlier child
            new_children.append(c); new_breaks.append(b); last_key = k
        node.children = new_children; node.breaks = new_breaks
    rec(t2.root)
    t2._index_leaves()
    return t2


# ----------------------------------------------------------------------------
# Theorem 2a'' : overlapping listed rules with IDQ + one witness per non-shadowed rule (CellSweep)
# ----------------------------------------------------------------------------
def _intervals_on_line(boxes, x_other, j, W_j):
    """union of j-intervals of boxes that contain the other coordinates x_other (dict axis->coord); returns sorted merged list"""
    ivs = []
    for b in boxes:
        ok = all(b[a][0] <= x_other[a] <= b[a][1] for a in x_other)
        if ok:
            ivs.append(list(b[j]))
    ivs.sort()
    merged = []
    for lo, hi in ivs:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return merged


def _testable_intervals(covered, W_j):
    out = []; cur = 0
    for lo, hi in covered:
        if lo > cur:
            out.append((cur, lo - 1))
        cur = max(cur, hi + 1)
    if cur <= W_j - 1:
        out.append((cur, W_j - 1))
    return out


def learn_lr_overlap_idq(oracle: Oracle, witnesses: Dict[int, tuple], widths, n_rules) -> ListedRule:
    """Reconstruct an arbitrary (overlapping) first-match list from IDQ + witnesses. Output boxes B̂_i = hull(E_i),
    which satisfy B̂_i \\ U_{i-1} = E_i, hence f identical. Cost is polynomial for fixed d (see Theorem 2a'')."""
    import itertools
    d = len(widths); W = [1 << w for w in widths]
    learned = []      # boxes B̂_k in priority order (empty box for shadowed)
    default_pt = [None]
    _idq = oracle.idq
    def idq_rec(h):
        r = _idq(h)
        if r < 0 and default_pt[0] is None:
            default_pt[0] = h
        return r
    oracle.idq = idq_rec
    for i in range(n_rules):
        if i not in witnesses:
            learned.append([(0, -1)] * d); continue
        h = witnesses[i]
        H = [[h[a], h[a]] for a in range(d)]              # hull of known E_i points
        U = [b for b in learned if b[0][1] >= b[0][0]]
        # grid coordinates per axis from U boxes
        grid = []
        for a in range(d):
            cs = {0, W[a]}
            for b in U:
                cs.add(b[a][0]); cs.add(b[a][1] + 1)
            cs = sorted(cs)
            grid.append([(lo, hi - 1) for lo, hi in zip(cs, cs[1:])])
        # Phase 1 (cheap): witness-line search with jumps over U; if every side ends at a visible (non-U) exit,
        # all 2d endpoints of B_i are exact and the sweep is unnecessary (this recovers Theorem 2a's cost when unoccluded).
        exact_sides = 0
        for j in range(d):
            x = {a: h[a] for a in range(d) if a != j}
            covered = _intervals_on_line(U, x, j, W[j])
            tests = _testable_intervals(covered, W[j])
            # find the testable interval containing h[j]
            cur = [iv for iv in tests if iv[0] <= h[j] <= iv[1]][0]
            for direction in (+1, -1):
                pos = h[j]; iv = cur; exact = False
                while True:
                    lo, hi = (pos, iv[1] + 1) if direction > 0 else (iv[0] - 1, pos)
                    while hi - lo > 1:
                        mid = (lo + hi) // 2; qq = list(h); qq[j] = mid
                        if oracle.idq(tuple(qq)) == i:
                            if direction > 0: lo = mid
                            else: hi = mid
                        else:
                            if direction > 0: hi = mid
                            else: lo = mid
                    end = lo if direction > 0 else hi
                    H[j][1 if direction > 0 else 0] = max(H[j][1], end) if direction > 0 else min(H[j][0], end)
                    # did the search stop strictly inside the testable interval (visible exit) or at its border (occluded)?
                    if (direction > 0 and end < iv[1]) or (direction < 0 and end > iv[0]) or (direction > 0 and iv[1] == W[j] - 1) or (direction < 0 and iv[0] == 0):
                        exact = True; break
                    # occluded: jump to the next testable interval and test its nearest point
                    nxt = [t for t in tests if (t[0] > iv[1] if direction > 0 else t[1] < iv[0])]
                    if not nxt:
                        break                          # domain end reached inside U: extent beyond is unknown (not exact)
                    iv = nxt[0] if direction > 0 else nxt[-1]
                    pos = iv[0] if direction > 0 else iv[1]
                    qq = list(h); qq[j] = pos
                    if oracle.idq(tuple(qq)) != i:
                        break                          # B_i ends somewhere inside the occluding U-interval: not exact
                    H[j][1 if direction > 0 else 0] = max(H[j][1], pos) if direction > 0 else min(H[j][0], pos)
                if exact:
                    exact_sides += 1
        changed = exact_sides < 2 * d
        while changed:
            changed = False
            for j in range(d):
                others = [a for a in range(d) if a != j]
                for cell in itertools.product(*[grid[a] for a in others]):
                    x = {}
                    for a, (clo, chi) in zip(others, cell):
                        if chi < H[a][0]:
                            x[a] = chi
                        elif clo > H[a][1]:
                            x[a] = clo
                        else:
                            x[a] = max(clo, H[a][0])       # inside both
                    covered = _intervals_on_line(U, x, j, W[j])
                    for (ilo, ihi) in _testable_intervals(covered, W[j]):
                        # nearest point of I to H's j-range
                        if ihi < H[j][0]:
                            t = ihi
                        elif ilo > H[j][1]:
                            t = ilo
                        else:
                            t = max(ilo, H[j][0])
                        q = [0] * d
                        for a in others:
                            q[a] = x[a]
                        q[j] = t
                        # skip if already inside H (nothing new to learn from this line? still may extend along j) -> test anyway
                        if oracle.idq(tuple(q)) != i:
                            continue
                        # inside E_i: extend along j within I by binary search (predicate monotone inside I)
                        lo, hi = t, ihi + 1
                        while hi - lo > 1:
                            mid = (lo + hi) // 2; qq = list(q); qq[j] = mid
                            if oracle.idq(tuple(qq)) == i: lo = mid
                            else: hi = mid
                        right = lo
                        lo, hi = ilo - 1, t
                        while hi - lo > 1:
                            mid = (lo + hi) // 2; qq = list(q); qq[j] = mid
                            if oracle.idq(tuple(qq)) == i: hi = mid
                            else: lo = mid
                        left = hi
                        newH = [list(r) for r in H]
                        for a in others:
                            newH[a][0] = min(newH[a][0], x[a]); newH[a][1] = max(newH[a][1], x[a])
                        newH[j][0] = min(newH[j][0], left); newH[j][1] = max(newH[j][1], right)
                        if newH != H:
                            H = newH; changed = True
        learned.append([tuple(r) for r in H])
    oracle.idq = _idq
    rules = []
    for i in range(n_rules):
        b = learned[i]
        a = oracle.mq(witnesses[i]) if i in witnesses else 0
        rules.append((b, a))
    default = oracle.mq(default_pt[0]) if default_pt[0] is not None else 0
    return ListedRule(widths, rules, default=default)
