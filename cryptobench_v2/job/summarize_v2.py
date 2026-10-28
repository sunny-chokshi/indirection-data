#!/usr/bin/env python3
"""Summarize CryptoBench v2 results (JSONL) with Wilson 95% intervals.

Per model: detection rate on vulnerable code (TPR), flag rate on secure twins
(FPR), balanced accuracy, error count, VERDICT-line compliance, and whether the
model discriminates (FPR at least 10 points below TPR). Then, pooled over
discriminating models: per class, split by variant (plain / obscured /
alias_only), so the name-visibility effect can be read directly.
"""
import json, math, sys
from collections import defaultdict

def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0, c - h), min(1, c + h)

def fmt(k, n):
    p, lo, hi = wilson(k, n)
    return f"{100*p:5.1f}% [{100*lo:4.1f}-{100*hi:4.1f}] ({k}/{n})" if n else "   n/a"

def main(path, sets=("v2",)):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    ok = [r for r in rows if r["verdict"] != "ERR" and r["set"] in sets]
    errs = defaultdict(int)
    for r in rows:
        if r["verdict"] == "ERR":
            errs[r["model"]] += 1
    by_model = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    compliance = defaultdict(lambda: [0, 0])
    for r in ok:
        m = by_model[r["model"]]
        m[r["label"]][0] += r["detected"]; m[r["label"]][1] += 1
        compliance[r["model"]][0] += int(r.get("verdict_line", False)); compliance[r["model"]][1] += 1
    print(f"Sets: {','.join(sets)}  |  rows {len(rows)}, scored {len(ok)}, errors {sum(errs.values())}\n")
    print("Per model (TPR on vulnerable, FPR on secure twins)")
    disc = []
    for model in sorted(by_model):
        v, s = by_model[model]["vuln"], by_model[model]["secure"]
        tpr = v[0] / v[1] if v[1] else 0
        fpr = s[0] / s[1] if s[1] else 0
        d = fpr <= tpr - 0.10
        if d:
            disc.append(model)
        c = compliance[model]
        print(f"  {model:28s} TPR {fmt(*v)}  FPR {fmt(*s)}  bAcc {(tpr + 1 - fpr) / 2:.3f}  "
              f"errors {errs[model]}  verdict-line {c[0]}/{c[1]}  {'' if d else '(non-discriminating)'}")
    print(f"\nDiscriminating models: {', '.join(disc) or 'none'}\n")
    cells = defaultdict(lambda: [0, 0])
    for r in ok:
        if r["model"] in disc:
            key = (r["category"], r["variant"], r["label"])
            cells[key][0] += r["detected"]; cells[key][1] += 1
    cats = sorted({k[0] for k in cells})
    variants = [v for v in ("plain", "obscured", "alias_only", "v1") if any(k[1] == v for k in cells)]
    print("Pooled over discriminating models: detection on vulnerable / flags on secure twins")
    for cat in cats:
        print(f"  {cat}")
        for var in variants:
            v, s = cells[(cat, var, "vuln")], cells[(cat, var, "secure")]
            if v[1] or s[1]:
                print(f"    {var:10s} vuln {fmt(*v)}   secure {fmt(*s)}")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "results_v2.jsonl"
    main(path, ("v2",))
    print("\n" + "=" * 80 + "\n")
    main(path, ("v1",))
