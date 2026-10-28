#!/usr/bin/env python3
"""v4 analysis for the BigData TAI short paper (Oct 8 2026). Usage: python3 analyze_v4.py <crypto_dir>
All intervals 4,000 pair-cluster draws. Token split = hand rule (exploratory, chosen after seeing data).
Token-present vs token-absent split, secure-twin audit, pair-cluster bootstrap (resampling pairs),
sign-flip permutation, leave-out checks, direction split. Bootstrap works on per-pair count tables."""
import json, sys, os, re, random, collections, importlib.util
from math import comb
CD = sys.argv[1]
def load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec)
    sys.path.insert(0, os.path.dirname(path)); spec.loader.exec_module(m); return m
s2 = load_mod("snippets_v2", f"{CD}/cryptobench_v2/job/snippets_v2.py")
s2b = load_mod("snippets_v2b", f"{CD}/cryptobench_v2b/job/snippets_v2b.py")
code = {s["id"]: s["code"] for s in s2.samples()}; code.update({s["id"]: s["code"] for s in s2b.samples()})
L = lambda p: [json.loads(l) for l in open(p) if l.strip()]
v2 = [r for r in L(f"{CD}/cryptobench_v2/results/extracted/results_v2.jsonl") if r["set"] == "v2"]
v2b = L(f"{CD}/cryptobench_v2b/results/extracted/results_v2b.jsonl")
STRONG = sorted({r["model"] for r in v2b}); P = sorted({r["pair"] for r in v2b})
F = lambda r: "plain" if r["variant"] == "plain" else "obscured"
D = [dict(r, form=F(r), src="v2") for r in v2 if r["pair"] in P and r["model"] in STRONG] + [dict(r, form=F(r), src="v2b") for r in v2b]
assert not any(r["verdict"] == "ERR" for r in D)
sid = {(r["pair"], r["form"], r["label"]): r["sample_id"] for r in D}
print("rows", len(D), "pairs", len(P), "models", STRONG); print("ids without code:", sum(v not in code for v in sid.values()))
cat = {r["pair"]: r["category"] for r in D}; orig = {r["pair"]: r["variant"] for r in v2 if r["pair"] in P}
print("original variants of the 80 pairs:", collections.Counter(orig.values()))
TOK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+"); toks = lambda s: {t.lower() for t in TOK.findall(s)}
group, diffs = {}, {}
for p in P:
    pv, ps, ov = (code[sid[(p, f, l)]] for f, l in (("plain", "vuln"), ("plain", "secure"), ("obscured", "vuln")))
    d = toks(pv) - toks(ps); diffs[p] = sorted(d)
    group[p] = "unclear" if not d else ("present" if d & toks(ov) else "absent")
print("misuse-token groups:", dict(collections.Counter(group.values())))
for c in sorted(set(cat.values())): print("  ", c, dict(collections.Counter(group[p] for p in P if cat[p] == c)))
ident = sorted(p for p in P if code[sid[(p, "plain", "secure")]].strip() == code[sid[(p, "obscured", "secure")]].strip())
print("byte-identical secure twins:", len(ident), ident)
QUEST = ["cv06", "cv09", "sk07", "ecb04", "ecb06", "ecb10"]
# count tables: cnt[(pair, model)][(form,label)] = [detected, n]
cnt = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
for r in D:
    c = cnt[(r["pair"], r["model"])][(r["form"], r["label"])]; c[0] += r["detected"]; c[1] += 1
def agg(pairs, models=STRONG):
    a = collections.defaultdict(lambda: [0, 0])
    for p in pairs:
        for m in models:
            for k, v in cnt[(p, m)].items(): a[k][0] += v[0]; a[k][1] += v[1]
    return a
def tpr(a, f): return a[(f, "vuln")][0] / a[(f, "vuln")][1]
def fpr(a, f): return a[(f, "secure")][0] / a[(f, "secure")][1]
def bacc(a, f): return (tpr(a, f) + 1 - fpr(a, f)) / 2
def drop(a): return bacc(a, "plain") - bacc(a, "obscured")
def boot(fn, pairs, models=STRONG, B=4000, seed=1):
    rnd = random.Random(seed); pre = {p: agg([p], models) for p in pairs}; vals = []
    for _ in range(B):
        a = collections.defaultdict(lambda: [0, 0])
        for p in (rnd.choice(pairs) for _ in pairs):
            for k, v in pre[p].items(): a[k][0] += v[0]; a[k][1] += v[1]
        try: vals.append(fn(a))
        except ZeroDivisionError: pass
    vals.sort(); return vals[int(.025 * len(vals))], vals[int(.975 * len(vals)) - 1]
pr = lambda x: f"{100*x:.1f}"
A = agg(P)
lo, hi = boot(drop, P)
print(f"\nOVERALL bAcc plain {bacc(A,'plain'):.3f} obscured {bacc(A,'obscured'):.3f} drop {pr(drop(A))} pts, pair-cluster 95% CI [{pr(lo)}, {pr(hi)}]")
for f in ("plain", "obscured"):
    a, b = boot(lambda x: tpr(x, f), P); c, d = boot(lambda x: fpr(x, f), P)
    print(f"  {f}: TPR {pr(tpr(A,f))} [{pr(a)},{pr(b)}]  FPR {pr(fpr(A,f))} [{pr(c)},{pr(d)}]")
dt = lambda x: tpr(x, "plain") - tpr(x, "obscured"); dfp = lambda x: fpr(x, "obscured") - fpr(x, "plain")
print(f"  TPR drop {pr(dt(A))}  FPR rise {pr(dfp(A))}  share of bAcc drop from FPR {100*(dfp(A)/2)/drop(A):.0f}%")
print("\nTOKEN SPLIT (vulnerable side)")
for g in ("present", "absent", "unclear"):
    ps = [p for p in P if group[p] == g]
    if not ps: continue
    a = agg(ps); l, h = boot(dt, ps)
    print(f"  {g:8s} pairs {len(ps):2d}: TPR plain {pr(tpr(a,'plain'))} obscured {pr(tpr(a,'obscured'))} drop {pr(dt(a))} [{pr(l)},{pr(h)}]  {dict(collections.Counter(cat[p] for p in ps))}")
print("\nSECURE SIDE (FPR plain -> obscured)")
for name, ex in (("all 80", []), ("minus identical", ident), ("minus identical+questionable", ident + QUEST)):
    ps = [p for p in P if p not in ex]; a = agg(ps); l, h = boot(dfp, ps)
    print(f"  {name:30s} n={len(ps)} FPR {pr(fpr(a,'plain'))} -> {pr(fpr(a,'obscured'))} rise {pr(dfp(a))} [{pr(l)},{pr(h)}]")
ps = [p for p in P if p not in ident + QUEST]; a = agg(ps); l, h = boot(drop, ps)
print(f"  bAcc drop on {len(ps)} pairs without identical/questionable twins: {pr(drop(a))} [{pr(l)},{pr(h)}]")
def pairdiffs(ps, models):
    out = []
    for p in ps:
        a = agg([p], models)
        acc = lambda f: (a[(f, "vuln")][0] + a[(f, "secure")][1] - a[(f, "secure")][0]) / (a[(f, "vuln")][1] + a[(f, "secure")][1])
        out.append(acc("plain") - acc("obscured"))
    return out
def signp(a, b):
    n = a + b; k = min(a, b); return min(1, 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n)
def perm(ds, B=20000, seed=2):
    rnd = random.Random(seed); obs = abs(sum(ds)); return sum(abs(sum(d if rnd.random() < .5 else -d for d in ds)) >= obs - 1e-12 for _ in range(B)) / B
print("\nROBUSTNESS")
noq = [m for m in STRONG if m != "qwen2.5-coder:32b"]; nosk = [p for p in P if cat[p] != "short_key"]
for name, ps, ms in (("all", P, STRONG), ("minus short_key", nosk, STRONG), ("minus qwen 32B", P, noq), ("minus both", nosk, noq)):
    ds = pairdiffs(ps, ms); a = sum(d > 0 for d in ds); b = sum(d < 0 for d in ds); l, h = boot(drop, ps, ms)
    print(f"  {name:16s} drop {pr(drop(agg(ps,ms)))} [{pr(l)},{pr(h)}] | pairs {a}/{b}/{len(ds)-a-b} sign p {signp(a,b):.4f} | perm p {perm(ds):.4f}")
print("\nDIRECTION SPLIT")
for o in ("plain", "other"):
    ps = [p for p in P if (orig[p] == "plain") == (o == "plain")]; a = agg(ps); l, h = boot(drop, ps)
    print(f"  originally {o:6s} pairs {len(ps)}: plain {bacc(a,'plain'):.3f} obscured {bacc(a,'obscured'):.3f} drop {pr(drop(a))} [{pr(l)},{pr(h)}]")
vb = collections.defaultdict(lambda: [0, 0])
for r in D:
    if r["src"] == "v2b": vb[(r["form"], r["label"])][0] += r["detected"]; vb[(r["form"], r["label"])][1] += 1
print(f"  v2b rows only: plain {bacc(vb,'plain'):.3f} obscured {bacc(vb,'obscured'):.3f}")
ii = [r for r in D if r["pair"] in ident and r["label"] == "secure"]
print("  identical secure twins, Oct 3 vs Oct 7 sessions: flags", sum(r["detected"] for r in ii if r["src"] == "v2"), "/", sum(1 for r in ii if r["src"] == "v2"), "vs", sum(r["detected"] for r in ii if r["src"] == "v2b"), "/", sum(1 for r in ii if r["src"] == "v2b"))
print("\nPER MODEL")
for m in STRONG:
    a = agg(P, [m]); l, h = boot(drop, P, [m], B=4000)
    print(f"  {m:20s} {bacc(a,'plain'):.3f} -> {bacc(a,'obscured'):.3f} drop {pr(drop(a))} [{pr(l)},{pr(h)}] TPR {pr(tpr(a,'plain'))}->{pr(tpr(a,'obscured'))} FPR {pr(fpr(a,'plain'))}->{pr(fpr(a,'obscured'))}")
l,h=boot(dt,P); l2,h2=boot(dfp,P); print(f"\nTPR drop {pr(dt(A))} [{pr(l)},{pr(h)}]  FPR rise {pr(dfp(A))} [{pr(l2)},{pr(h2)}]")
for v in ("plain","obscured","alias_only"):
    ps=[p for p in P if orig[p]==v]; aa=agg(ps); l,h=boot(drop,ps); print(f"  originally {v:10s} n={len(ps)} drop {pr(drop(aa))} [{pr(l)},{pr(h)}]")
print("\nPER CLASS (bAcc plain/obscured, TPR plain/obscured)")
for c in sorted(set(cat.values())):
    a = agg([p for p in P if cat[p] == c]); print(f"  {c:14s} {bacc(a,'plain'):.3f}/{bacc(a,'obscured'):.3f}  TPR {pr(tpr(a,'plain'))}/{pr(tpr(a,'obscured'))}  FPR {pr(fpr(a,'plain'))}/{pr(fpr(a,'obscured'))}")
print("\nQUESTIONABLE OBSCURED SECURE TWINS")
for q in QUEST: print(f"--- {q} ---\n{code[sid[(q,'obscured','secure')]].strip()}\n")
print("misuse tokens:", {p: diffs[p][:4] for p in P})

print("\nHAND TOKEN SPLIT (exploratory). Rule: token present if the class's familiar misuse name or value")
print("(False / CERT_NONE, ECB, MD5 / SHA1, DES / RC4 / ARC2, 1024 / 192, random module) still appears literally")
print("anywhere in the indirect vulnerable file, even inside a constant, dict or default argument.")
ABSENT = ["cv03","cv06","cv08","ecb04","ecb06","ecb10","sk01","sk04","sk05","sk08"]
TOKCLS = {"weak_hash","ecb_mode","broken_cipher","cert_verify","short_key","weak_prng"}
NONAME = {"bc05"}
hg = {p: ("none" if (cat[p] not in TOKCLS or p in NONAME) else ("absent" if p in ABSENT else "present")) for p in P}
print("  groups", dict(collections.Counter(hg.values())), "absent:", ABSENT)
for g in ("present","absent","none"):
    ps=[p for p in P if hg[p]==g]; a=agg(ps); l,h=boot(dt,ps); l2,h2=boot(dfp,ps)
    print(f"  {g:8s} n={len(ps)} TPR {pr(tpr(a,'plain'))}->{pr(tpr(a,'obscured'))} drop {pr(dt(a))} [{pr(l)},{pr(h)}] | FPR rise {pr(dfp(a))} [{pr(l2)},{pr(h2)}]")
pp=[p for p in P if hg[p]=="present"]; ap=[p for p in P if hg[p]=="absent"]
obs=dt(agg(ap))-dt(agg(pp)); rnd=random.Random(5); vals=[]
for _ in range(4000):
    vals.append(dt(agg([rnd.choice(ap) for _ in ap]))-dt(agg([rnd.choice(pp) for _ in pp])))
vals.sort(); print(f"  absent minus present TPR drop: {pr(obs)} [{pr(vals[100])},{pr(vals[3899])}]")
pool=pp+ap; rnd=random.Random(6); ge=0
for _ in range(20000):
    rnd.shuffle(pool); x=pool[:len(ap)]; y=pool[len(ap):]
    if dt(agg(x))-dt(agg(y))>=obs-1e-12: ge+=1
print(f"  label-permutation one-sided p {ge/20000:.4f}")
for p in ap:
    a=agg([p]); print(f"    {p:6s} {a[('plain','vuln')][0]}/{a[('plain','vuln')][1]} -> {a[('obscured','vuln')][0]}/{a[('obscured','vuln')][1]}")
r=[p for p in ap if p not in ("cv08","sk05")]; a=agg(r); l,h=boot(dt,r); print(f"  absent minus cv08,sk05 (n={len(r)}): drop {pr(dt(a))} [{pr(l)},{pr(h)}]")
print("\nCLASS LEVEL (bAcc drop per class; sign-flip over 9 classes)")
cd=[]
for c in sorted(set(cat.values())):
    a=agg([p for p in P if cat[p]==c]); cd.append(drop(a)); print(f"  {c:14s} {pr(drop(a))}")
print(f"  fell {sum(d>0 for d in cd)} of {len(cd)}; exact sign-flip two-sided p", end=" ")
import itertools
obs=abs(sum(cd)); n=sum(abs(sum(d*s for d,s in zip(cd,sg)))>=obs-1e-12 for sg in itertools.product((1,-1),repeat=len(cd))); print(f"{n/2**len(cd):.3f}")
print("\nSECURE TWIN EXAMPLES")
for q in ("cv03","ecb01"): print(f"--- {q} plain secure ---\n{code[sid[(q,'plain','secure')]].strip()}\n--- {q} obscured secure ---\n{code[sid[(q,'obscured','secure')]].strip()}")
