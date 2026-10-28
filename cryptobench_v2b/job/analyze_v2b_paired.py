#!/usr/bin/env python3
"""Within-pair name-visibility test for CryptoBench v2 + v2b.
For each of the 80 pairs, the original form comes from results_v2.jsonl (set v2) and the opposite
form from results_v2b.jsonl (set v2b). Same models, same 3 repeats, same prompt and decoding.
Usage: python3 analyze_v2b_paired.py results_v2.jsonl results_v2b.jsonl"""
import json, math, sys, collections
from math import comb
def load(p): return [json.loads(l) for l in open(p) if l.strip()]
v2 = [r for r in load(sys.argv[1]) if r["set"] == "v2" and r["verdict"] != "ERR"]
v2b = [r for r in load(sys.argv[2]) if r["verdict"] != "ERR"]
pairs = {r["pair"] for r in v2b}; models = sorted({r["model"] for r in v2b})
form = lambda r: "plain" if r["variant"] == "plain" else "obscured"   # alias_only counts as obscured
rows = [r for r in v2 if r["pair"] in pairs and r["model"] in models] + v2b
errs = collections.Counter(r["model"] for r in load(sys.argv[2]) if r["verdict"] == "ERR")
c = collections.defaultdict(lambda: [0, 0])
for r in rows: c[(r["model"], form(r), r["label"])][0] += r["detected"]; c[(r["model"], form(r), r["label"])][1] += 1
def w(k, n, z=1.96):
    p = k / n; d = 1 + z*z/n; m = (p + z*z/2/n) / d; h = z*math.sqrt(p*(1-p)/n + z*z/4/n/n) / d; return p, m-h, m+h
def f(k, n): p, lo, hi = w(k, n); return f"{100*p:5.1f}% [{100*lo:4.1f}-{100*hi:4.1f}] ({k}/{n})"
def sign(pos, neg):
    n = pos + neg; return min(1, 2*sum(comb(n, k) for k in range(max(pos, neg), n+1)) / 2**n) if n else 1
print(f"{len(pairs)} pairs, {len(models)} models, {len(rows)} scored rows, v2b errors {dict(errs) or 0}\n")
print("Per model, SAME pairs in both forms: TPR (vuln) / FPR (secure) / bAcc")
d_b = []; d_t = []; d_f = []
for m in models:
    s = {}
    for fm in ("plain", "obscured"):
        t, fp = c[(m, fm, "vuln")], c[(m, fm, "secure")]
        s[fm] = (t[0]/t[1], fp[0]/fp[1]); s[fm] += ((s[fm][0] + 1 - s[fm][1]) / 2,)
        print(f"  {m:22s} {fm:8s} TPR {f(*t)}  FPR {f(*fp)}  bAcc {s[fm][2]:.3f}")
    d_b.append(s["plain"][2] - s["obscured"][2]); d_t.append(s["plain"][0] - s["obscured"][0]); d_f.append(s["obscured"][1] - s["plain"][1])
print(f"\nbAcc plain > obscured in {sum(x>0 for x in d_b)}/{len(d_b)} models (sign p = {sign(sum(x>0 for x in d_b), sum(x<0 for x in d_b)):.4f}); mean diff {100*sum(d_b)/len(d_b):.1f} pts")
print(f"TPR drop when obscured: mean {100*sum(d_t)/len(d_t):.1f} pts (models with a drop: {sum(x>0 for x in d_t)})")
print(f"FPR rise when obscured: mean {100*sum(d_f)/len(d_f):.1f} pts (models with a rise: {sum(x>0 for x in d_f)})")
# pair-level: pooled over models, does each pair score better when plain?
pc = collections.defaultdict(lambda: [0, 0])
for r in rows:
    ok = r["detected"] if r["label"] == "vuln" else 1 - r["detected"]
    pc[(r["pair"], form(r))][0] += ok; pc[(r["pair"], form(r))][1] += 1
pd = [pc[(p, "plain")][0]/pc[(p, "plain")][1] - pc[(p, "obscured")][0]/pc[(p, "obscured")][1] for p in sorted(pairs)]
pos, neg = sum(x > 0 for x in pd), sum(x < 0 for x in pd)
print(f"\nPair level (accuracy pooled over models): plain better in {pos}, obscured better in {neg}, tied {len(pd)-pos-neg} of {len(pd)} pairs; sign p = {sign(pos, neg):.4g}")
print("\nPer class (pooled over models), bAcc plain / obscured:")
cc = collections.defaultdict(lambda: [0, 0])
for r in rows: cc[(r["category"], form(r), r["label"])][0] += r["detected"]; cc[(r["category"], form(r), r["label"])][1] += 1
for cat in sorted({k[0] for k in cc}):
    b = [(cc[(cat, fm, "vuln")][0]/cc[(cat, fm, "vuln")][1] + 1 - cc[(cat, fm, "secure")][0]/cc[(cat, fm, "secure")][1]) / 2 for fm in ("plain", "obscured")]
    print(f"  {cat:14s} {b[0]:.2f} / {b[1]:.2f}")
