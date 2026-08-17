"""
e11_testbed.py — Real-firewall testbed (Theorems 2b, 3, 6 and Lemma 1 of the accompanying manuscript on a REAL iptables firewall).

Requires: Linux (WSL2 Ubuntu is fine), root (sudo), iproute2, iptables, python3 with scapy (pip install scapy).
Topology (three network namespaces created and destroyed by this script):
      client (cl) --veth-- firewall (fw, iptables FORWARD chain = the policy) --veth-- server (sv, sniffer)
  * MQ  : a probe is ACCEPTED iff the packet appears on the server side (real packet, real kernel decision)
  * IDQ : which rule matched = the FORWARD-chain rule whose packet counter incremented (real hit counters)
The policy is a real ruleset from Section IX-G loaded as the leaves of its canonical Tree-Rule (one leaf = one iptables
rule, expanded into CIDR blocks), so hit counters give leaf identities and Theorem 2b/3/6 can be exercised as stated.

Usage:  sudo python3 e11_testbed.py [--policy NAME ...] [--selftest] [--maxleaves N]
        (default policies: sargon_INP_lower synology_INP_lower home_user_FWD_upper docker_topos_FWD_upper)
Outputs: results/E11_testbed.csv and results/E11_testbed.log
"""
import os, sys, csv, time, random, subprocess, socket, struct, argparse, ctypes, math
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from a1sim import TreeRule, TRNode, Oracle, learn_tr_idq, learn_tr_idq_partial, audit_certificate, reduce_tree, structural_deviation
import e7_realworld as E7          # parser + canonical tree builder (embedded dataset)

OUT = os.path.join(HERE, "results"); os.makedirs(OUT, exist_ok=True)
LOG = open(os.path.join(OUT, "E11_testbed.log"), "a", encoding="utf-8")
def log(msg):
    line = time.strftime("[%H:%M:%S] ") + msg
    print(line, flush=True); LOG.write(line + "\n"); LOG.flush()

# ---------------------------------------------------------------- namespaces
CL, FW, SV = "a1cl", "a1fw", "a1sv"
CL_IP, FW_IP0, FW_IP1, SV_IP = "10.77.1.2", "10.77.1.1", "10.77.2.1", "10.77.2.2"

def sh(cmd, check=True, capture=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed: {cmd}\n{r.stderr}")
    return r.stdout if capture else r.returncode

def teardown():
    for ns in (CL, FW, SV):
        sh(f"ip netns del {ns} 2>/dev/null", check=False)

def setup():
    """Layer-2 testbed: the firewall namespace bridges cl0<->fw0 | br0 | fw1<->sv0 and iptables filters bridged IPv4
    frames (bridge-nf-call-iptables=1). No routing is involved, so EVERY IPv4 header (any src/dst, incl. reserved ranges,
    protocol 0, port 0) is forwarded or dropped purely by the FORWARD chain — the whole 2^104 header space is testable.
    Returns the MAC of the server interface (frames are addressed to it)."""
    teardown()
    for ns in (CL, FW, SV):
        sh(f"ip netns add {ns}")
    sh("ip link add cl0 type veth peer name fw0"); sh("ip link add fw1 type veth peer name sv0")
    sh(f"ip link set cl0 netns {CL}"); sh(f"ip link set fw0 netns {FW}"); sh(f"ip link set fw1 netns {FW}"); sh(f"ip link set sv0 netns {SV}")
    sh(f"ip -n {FW} link add br0 type bridge")
    sh(f"ip -n {FW} link set fw0 master br0"); sh(f"ip -n {FW} link set fw1 master br0")
    for ns, dev in ((CL, "cl0"), (FW, "fw0"), (FW, "fw1"), (FW, "br0"), (SV, "sv0")):
        sh(f"ip -n {ns} link set {dev} up"); sh(f"ip -n {ns} link set lo up")
    # bridged IPv4 must traverse iptables FORWARD
    r = sh(f"ip netns exec {FW} sysctl -q -w net.bridge.bridge-nf-call-iptables=1", check=False)
    if r != 0:
        raise RuntimeError("bridge-nf-call-iptables unavailable (br_netfilter). On WSL2 try: sudo modprobe br_netfilter, or use a distro kernel with CONFIG_BRIDGE_NETFILTER.")
    sh(f"ip netns exec {FW} sysctl -q -w net.bridge.bridge-nf-call-ip6tables=0", check=False)
    sh(f"ip netns exec {FW} sysctl -q -w net.bridge.bridge-nf-call-arptables=0", check=False)
    # disable IPv6 autoconf chatter and offloads that could confuse counters
    for ns in (CL, FW, SV):
        sh(f"ip netns exec {ns} sysctl -q -w net.ipv6.conf.all.disable_ipv6=1", check=False)
    svmac = sh(f"ip -n {SV} link show sv0", capture=True).split("link/ether")[1].split()[0]
    return svmac

# ---------------------------------------------------------------- policy -> iptables
def cidr_blocks(lo, hi):
    """split integer IPv4 range [lo,hi] into CIDR blocks"""
    out = []
    while lo <= hi:
        size = 1
        while lo % (size * 2) == 0 and lo + size * 2 - 1 <= hi:
            size *= 2
        out.append((lo, 32 - int(math.log2(size))))
        lo += size
    return out

def ip_str(x):
    return "%d.%d.%d.%d" % ((x >> 24) & 255, (x >> 16) & 255, (x >> 8) & 255, x & 255)

PORT_PROTOS = {6: "tcp", 17: "udp", 132: "sctp", 33: "dccp", 136: "udplite"}
USE_IPRANGE = True      # one iptables rule per leaf via xt_iprange; falls back to CIDR splitting if the module is missing

def detect_iprange():
    """probe whether xt_iprange and xt_u32 are usable in the firewall namespace"""
    global USE_IPRANGE
    r1 = sh(f"ip netns exec {FW} iptables -A FORWARD -m iprange --src-range 10.9.9.1-10.9.9.2 -j DROP", check=False)
    r2 = sh(f"ip netns exec {FW} iptables -A FORWARD -m u32 --u32 \"6&0xFF=0\" -j DROP", check=False)
    sh(f"ip netns exec {FW} iptables -F FORWARD", check=False)
    USE_IPRANGE = (r1 == 0)
    log(f"kernel modules: iprange={'yes' if r1 == 0 else 'NO (falling back to CIDR splitting)'} u32={'yes' if r2 == 0 else 'NO (protocol-0 packets will hit the default policy)'}")
    return r1 == 0, r2 == 0

def leaf_rules(reg, action):
    """iptables match strings for a leaf region (fields in ORDER = proto,src,dst,sport,dport). Returns list of strings."""
    (plo, phi), (slo, shi), (dlo, dhi), (splo, sphi), (dplo, dphi) = reg
    protos = ["all"] if (plo, phi) == (0, 255) else list(range(plo, phi + 1))
    out = []
    for pr in protos:
        # NOTE: iptables treats "-p 0" as "all"; protocol 0 (HOPOPT) is matched with the u32 module on the protocol byte
        pspec = "" if pr == "all" else (f"-p {pr}" if pr != 0 else '-m u32 --u32 "6&0xFF=0"')
        ports = ""
        if pr in PORT_PROTOS:
            if (splo, sphi) != (0, 65535):
                ports += f" --sport {splo}:{sphi}"
            if (dplo, dphi) != (0, 65535):
                ports += f" --dport {dplo}:{dphi}"
        elif (splo, sphi) != (0, 65535) or (dplo, dphi) != (0, 65535):
            raise ValueError("port constraint on a protocol without ports — canonical tree with proto-first order should not produce this")
        if USE_IPRANGE:
            src = "" if (slo, shi) == (0, 0xFFFFFFFF) else f" -m iprange --src-range {ip_str(slo)}-{ip_str(shi)}"
            dst = "" if (dlo, dhi) == (0, 0xFFFFFFFF) else (f" --dst-range {ip_str(dlo)}-{ip_str(dhi)}" if src else f" -m iprange --dst-range {ip_str(dlo)}-{ip_str(dhi)}")
            out.append(f"-A FORWARD {pspec}{src}{dst}{ports} -j {'ACCEPT' if action else 'DROP'}".replace("  ", " "))
        else:
            for sb, sp in cidr_blocks(slo, shi):
                for db, dp in cidr_blocks(dlo, dhi):
                    out.append(f"-A FORWARD {pspec} -s {ip_str(sb)}/{sp} -d {ip_str(db)}/{dp}{ports} -j {'ACCEPT' if action else 'DROP'}".replace("  ", " "))
    return out

def load_policy(name, maxleaves):
    path = os.path.join(E7.DATA, name + ".txt")
    E7._ensure_data()
    rules = E7.parse_file(path)
    order = [2, 0, 1, 3, 4]                     # proto, src, dst, sport, dport  (port cuts only under tcp/udp regions)
    root = E7.build_tree(rules, order)
    m = E7.count_leaves(root)
    if m > maxleaves:
        raise RuntimeError(f"{name}: {m} leaves > --maxleaves {maxleaves}")
    t = E7.to_treerule(root, order)               # TreeRule over permuted fields (widths 8,32,32,16,16)
    return t, rules, order

def install_tree(t):
    """write the leaves as FORWARD rules; return rule_index -> leaf_id list (in chain order)"""
    lines = ["*filter", ":INPUT ACCEPT", ":FORWARD DROP", ":OUTPUT ACCEPT"]
    idx2leaf = []
    for leaf_id, (reg, leaf) in enumerate(zip(t.leaf_regions(), t.leaves)):
        for r in leaf_rules(reg, leaf.action):
            lines.append(r); idx2leaf.append(leaf_id)
    lines.append("COMMIT")
    p = subprocess.run(f"ip netns exec {FW} iptables-restore", shell=True, input="\n".join(lines) + "\n", capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError("iptables-restore failed: " + p.stderr)
    return idx2leaf

def read_counters():
    """return (list of per-rule packet counts in chain order, policy packet count)"""
    out = sh(f"ip netns exec {FW} iptables -w -nvxL FORWARD", capture=True).splitlines()
    pol = int(out[0].split("policy")[1].split()[1])
    cnt = []
    for line in out[2:]:
        parts = line.split()
        if parts:
            cnt.append(int(parts[0]))
    return cnt, pol

# ---------------------------------------------------------------- raw sockets in namespaces
CLONE_NEWNET = 0x40000000
libc = ctypes.CDLL("libc.so.6", use_errno=True)

def enter_ns(name):
    fd = os.open(f"/var/run/netns/{name}", os.O_RDONLY)
    if libc.setns(fd, CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "setns failed")
    os.close(fd)

class RealFirewall:
    """MQ/IDQ oracle backed by the real firewall. Field order of packets: (proto, src, dst, sport, dport)."""
    def __init__(self, dstmac, idx2leaf):
        try:
            from scapy.all import Ether, IP, TCP, UDP, Raw
        except ImportError:
            raise SystemExit("scapy is not installed for root's python: run  sudo apt install -y python3-scapy   (or: sudo pip3 install scapy --break-system-packages)")
        self.Ether, self.IP, self.TCP, self.UDP, self.Raw = Ether, IP, TCP, UDP, Raw
        self.dstmac = dstmac; self.idx2leaf = idx2leaf
        home = os.open("/proc/self/ns/net", os.O_RDONLY)
        enter_ns(CL)
        self.tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); self.tx.bind(("cl0", 0))
        self.clmac = self.tx.getsockname()[4].hex(":") if hasattr(self.tx.getsockname()[4], "hex") else "02:00:00:00:00:02"
        libc.setns(home, CLONE_NEWNET)
        enter_ns(SV)
        self.rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)); self.rx.bind(("sv0", 0)); self.rx.setblocking(False)
        libc.setns(home, CLONE_NEWNET); os.close(home)
        self.mq_count = 0; self.idq_count = 0; self.probes = 0; self.seq = 1
        self.last_cnt, self.last_pol = read_counters()
        self.inconsistent = 0
        self.t_send = 0.0

    def _build(self, h):
        proto, src, dst, sport, dport = h
        ip = self.IP(src=ip_str(src), dst=ip_str(dst), proto=proto, id=self.seq, ttl=64)
        if proto == 6:
            l4 = self.TCP(sport=sport, dport=dport, flags="S")
        elif proto == 17:
            l4 = self.UDP(sport=sport, dport=dport)
        else:
            l4 = self.Raw(b"\x00" * 8)
        return bytes(self.Ether(dst=self.dstmac, src=self.clmac) / ip / l4)

    def _drain(self):
        seen = set()
        while True:
            try:
                pkt = self.rx.recv(65535)
            except BlockingIOError:
                return seen
            if len(pkt) >= 34 and pkt[12:14] == b"\x08\x00":
                seen.add(struct.unpack("!H", pkt[18:20])[0])     # IPv4 identification field

    def probe(self, h):
        """send one packet; return (accepted: bool, matched_leaf: int|-1). Both channels observed for every probe."""
        self._drain()
        myid = self.seq
        frame = self._build(h)                   # uses self.seq as the IP identification field
        self.seq = 1 + (self.seq % 65000)
        self.tx.send(frame); self.probes += 1
        t0 = time.time(); accepted = False
        while time.time() - t0 < 0.05:
            if myid in self._drain():
                accepted = True; break
            time.sleep(0.001)
        cnt, pol = read_counters()
        hit = [i for i, (a, b) in enumerate(zip(cnt, self.last_cnt)) if b > a]
        # counters can only grow; the rule(s) whose counter grew
        grown = [i for i, (a, b) in enumerate(zip(cnt, self.last_cnt)) if a > b]
        matched = self.idx2leaf[grown[0]] if grown else (-1 if pol > self.last_pol else None)
        if matched is None:                      # nothing counted yet: retry read once
            time.sleep(0.005); cnt, pol = read_counters()
            grown = [i for i, (a, b) in enumerate(zip(cnt, self.last_cnt)) if a > b]
            matched = self.idx2leaf[grown[0]] if grown else -1
        self.last_cnt, self.last_pol = cnt, pol
        return accepted, matched

    # oracle interface used by the learners
    def mq(self, h):
        self.mq_count += 1
        acc, _ = self.probe(h); return 1 if acc else 0
    def idq(self, h):
        self.idq_count += 1
        acc, leaf = self.probe(h)
        return leaf
    @property
    def total(self):
        return self.mq_count + self.idq_count

# ---------------------------------------------------------------- experiments
def run_policy(name, fwmac, maxleaves, rng, rows):
    t, rules, order = load_policy(name, maxleaves)
    tr = reduce_tree(t)                                   # reduced spec for Theorem 3 (same semantics)
    idx2leaf = install_tree(t)
    m = t.num_leaves()
    log(f"== {name}: {len(rules)} rules -> canonical tree {m} leaves (reduced {tr.num_leaves()}), {len(idx2leaf)} iptables rules")
    fw = RealFirewall(fwmac, idx2leaf)
    # ---- harness self-consistency: 200 random packets, MQ (server sniff) must equal action of matched leaf
    bad = 0
    for _ in range(200):
        h = tuple(rng.randrange(1 << w) for w in t.widths)
        acc, leaf = fw.probe(h)
        exp = t.leaves[leaf].action if leaf >= 0 else 0
        bad += (acc != bool(exp)) or (leaf != t.leaf_id(h))
    log(f"   consistency check: {200 - bad}/200 probes agree with the offline model (sniff == counter target, counter == leaf)")
    rows.append(dict(policy=name, experiment="consistency", value=200 - bad, probes=200, seconds=None, note="of 200 random probes"))
    # ---- (a) Theorem 2b: reconstruct from real hit counters + one witness per leaf
    wit = t.witnesses(rng)
    fw.mq_count = fw.idq_count = 0; t0 = time.time()
    t2 = learn_tr_idq(fw, wit, t.widths)
    secs = time.time() - t0
    eq = t.equivalent(t2, samples=20000, rng=rng)
    log(f"   (a) Thm 2b on real firewall: probes={fw.total} (bound {(m-1)*32+3*m-1}) time={secs:.1f}s equivalent={eq}")
    rows.append(dict(policy=name, experiment="thm2b_reconstruction", value=int(eq), probes=fw.total, seconds=round(secs, 1), note=f"m={m}, bound={(m-1)*32+3*m-1}"))
    # ---- (b) Theorem 3: certificate of the reduced spec against the real firewall; then inject faults
    S = audit_certificate(tr)
    fw.mq_count = fw.idq_count = 0; t0 = time.time()
    alarms = sum(1 for s in S if fw.mq(s) != tr.action(s))
    secs = time.time() - t0
    log(f"   (b) Thm 3 certificate |S|={len(S)} on unmodified firewall: {alarms} false alarms, {secs:.1f}s")
    rows.append(dict(policy=name, experiment="certificate_baseline", value=alarms, probes=len(S), seconds=round(secs, 1), note=f"|S|={len(S)}, expected 0 alarms"))
    detected = 0; injected = 0
    for k in range(6):
        # inject a structural fault into the REAL firewall: replace one leaf's rules by a modified leaf (moved boundary or flipped action)
        f = structural_deviation(tr, rng)
        if tr.equivalent(f, samples=3000, rng=rng):
            continue
        idx2leaf_f = install_tree(f); fw.idx2leaf = idx2leaf_f; fw.last_cnt, fw.last_pol = read_counters()
        injected += 1
        det = any(fw.mq(s) != tr.action(s) for s in S)
        detected += det
        log(f"      fault {k}: certificate {'DETECTED' if det else 'MISSED'}")
    install_tree(t); fw.idx2leaf = idx2leaf; fw.last_cnt, fw.last_pol = read_counters()
    rows.append(dict(policy=name, experiment="certificate_faults", value=detected, probes=injected * len(S), seconds=None, note=f"detected {detected}/{injected} injected structural faults"))
    log(f"   (b) faults detected {detected}/{injected}")
    # ---- (c) Lemma 1: insert a shadowed rule at the TOP that is covered by an existing higher-... use: append a rule that
    #          duplicates leaf 0 after itself (fully shadowed). Transcript of the certificate must be identical.
    reg0 = t.leaf_regions()[0]
    extra = leaf_rules(reg0, 1 - t.leaves[0].action)      # opposite action, but placed AFTER leaf 0's rules -> shadowed
    lines = ["*filter", ":INPUT ACCEPT", ":FORWARD DROP", ":OUTPUT ACCEPT"]
    idx = []
    for leaf_id, (reg, leaf) in enumerate(zip(t.leaf_regions(), t.leaves)):
        for r in leaf_rules(reg, leaf.action):
            lines.append(r); idx.append(leaf_id)
        if leaf_id == 0:
            for r in extra:
                lines.append(r); idx.append(-2)            # -2 marks the shadowed rule
    lines.append("COMMIT")
    subprocess.run(f"ip netns exec {FW} iptables-restore", shell=True, input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    fw.idx2leaf = idx; fw.last_cnt, fw.last_pol = read_counters()
    before = [(fw.probe(s)) for s in S[:60]]
    hits_on_shadow = sum(1 for _, leaf in before if leaf == -2)
    diffs = sum(1 for (acc, leaf), s in zip(before, S[:60]) if (acc != bool(tr.action(s))))
    log(f"   (c) Lemma 1: shadowed rule inserted; over 60 certificate probes it matched {hits_on_shadow} times, transcript differences {diffs}")
    rows.append(dict(policy=name, experiment="lemma1_shadowed_rule", value=hits_on_shadow, probes=60, seconds=None, note=f"transcript diffs {diffs} (expected 0)"))
    install_tree(t); fw.idx2leaf = idx2leaf; fw.last_cnt, fw.last_pol = read_counters()
    # ---- (d) Theorem 6: witnesses = N random packets, N = m
    pk = [tuple(rng.randrange(1 << w) for w in t.widths) for _ in range(m)]
    fw.mq_count = fw.idq_count = 0; t0 = time.time()
    t3 = learn_tr_idq_partial(fw, pk, t.widths)
    secs = time.time() - t0
    err = 0
    for _ in range(20000):
        h = tuple(rng.randrange(1 << w) for w in t.widths)
        err += t.action(h) != t3.action(h)
    log(f"   (d) Thm 6 with N=m={m} sampled packets: probes={fw.total} time={secs:.1f}s uniform error={err/20000:.4f} (bound m/(eN)={1/math.e:.3f})")
    rows.append(dict(policy=name, experiment="thm6_partial", value=round(err / 20000, 4), probes=fw.total, seconds=round(secs, 1), note=f"N=m={m}, bound {1/math.e:.3f}"))
    fw.tx.close(); fw.rx.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", nargs="*", default=["sargon_INP_lower", "synology_INP_lower", "home_user_FWD_upper", "docker_topos_FWD_upper"])
    ap.add_argument("--maxleaves", type=int, default=400)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("run as root: sudo python3 e11_testbed.py"); sys.exit(1)
    for tool in ("ip", "iptables", "iptables-restore"):
        if subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode != 0:
            print(f"missing '{tool}': run  sudo apt install -y iproute2 iptables"); sys.exit(1)
    subprocess.run("modprobe br_netfilter 2>/dev/null; modprobe xt_iprange 2>/dev/null; modprobe xt_u32 2>/dev/null", shell=True)
    rng = random.Random(1111)
    rows = []
    fwmac = setup()
    detect_iprange()
    try:
        if args.selftest:
            # tiny synthetic policy: 3 rules
            t = TreeRule([8, 32, 32, 16, 16])
            def chain(depth, action):            # pass-through nodes down to a leaf at depth 5
                if depth == 5:
                    n = TRNode(depth=5); n.action = action; return n
                n = TRNode(depth=depth); n.children = [chain(depth + 1, action)]; return n
            root = TRNode(depth=0); root.breaks = [6, 7]
            root.children = [chain(1, 0), chain(1, 1), chain(1, 0)]     # proto 6 (tcp) accepted, everything else dropped
            t.root = root; t._index_leaves()
            idx2leaf = install_tree(t); fw = RealFirewall(fwmac, idx2leaf)
            ok = 0
            for h in [(6, 0x0A010203, 0x0A020304, 3, 80), (17, 0x0A010203, 0x0A020304, 3, 53), (1, 0x0A010203, 0x0A020304, 0, 0), (0, 0x0A010203, 0x0A020304, 0, 0), (200, 0x01020304, 0xC0A80101, 0, 0)]:
                acc, leaf = fw.probe(h); ok += (acc == bool(t.action(h))) and (leaf == t.leaf_id(h))
                log(f"selftest probe {h}: accepted={acc} leaf={leaf} expected action={t.action(h)} leaf={t.leaf_id(h)}")
            log(f"selftest {'PASSED' if ok == 5 else 'FAILED'}")
            return
        for name in args.policy:
            try:
                run_policy(name, fwmac, args.maxleaves, rng, rows)
            except Exception as ex:
                log(f"!! {name}: {ex}")
        with open(os.path.join(OUT, "E11_testbed.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["policy", "experiment", "value", "probes", "seconds", "note"]); w.writeheader(); w.writerows(rows)
        log("done")
    finally:
        teardown()

if __name__ == "__main__":
    main()
