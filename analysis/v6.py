#!/usr/bin/env python3
"""v6 numbers (Oct 8 2026): 47 clean pairs (non-clean list = v5 independent review, 33 ids), per-model FPR change,
FPR contribution by class, fragility of TPR drop, shared secure twins, two-way bootstrap, Spearman size~bAcc (Study 1),
reply excerpts for cv01/cv04 plain secure, sk01/sk08/ecb04 indirect secure. Usage: python3 v6.py <crypto_dir>. 4,000 draws."""
import json,sys,os,random,collections,importlib.util,re
CD=sys.argv[1]
def lm(n,p):
    s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.path.insert(0,os.path.dirname(p));s.loader.exec_module(m);return m
code={}
for n,p in (("snippets_v2","cryptobench_v2/job/snippets_v2.py"),("snippets_v2b","cryptobench_v2b/job/snippets_v2b.py")):
    code.update({s["id"]:s["code"] for s in lm(n,f"{CD}/{p}").samples()})
L=lambda p:[json.loads(l) for l in open(p) if l.strip()]
v2all=[r for r in L(f"{CD}/cryptobench_v2/results/extracted/results_v2.jsonl") if r["set"]=="v2"]
v2b=L(f"{CD}/cryptobench_v2b/results/extracted/results_v2b.jsonl")
S=sorted({r["model"] for r in v2b});P=sorted({r["pair"] for r in v2b})
F=lambda r:"plain" if r["variant"]=="plain" else "obscured"
D=[dict(r,form=F(r)) for r in v2all if r["pair"] in P and r["model"] in S]+[dict(r,form=F(r)) for r in v2b]
sid={(r["pair"],r["form"],r["label"]):r["sample_id"] for r in D}; cat={r["pair"]:r["category"] for r in D}
cnt=collections.defaultdict(lambda:collections.defaultdict(lambda:[0,0]))
for r in D: x=cnt[(r["pair"],r["model"])][(r["form"],r["label"])]; x[0]+=r["detected"]; x[1]+=1
def agg(ps,ms=S):
    a=collections.defaultdict(lambda:[0,0])
    for p in ps:
        for m in ms:
            for k,v in cnt[(p,m)].items(): a[k][0]+=v[0]; a[k][1]+=v[1]
    return a
t=lambda a,f,l:a[(f,l)][0]/a[(f,l)][1]
bacc=lambda a,f:(t(a,f,"vuln")+1-t(a,f,"secure"))/2
dB=lambda a:bacc(a,"plain")-bacc(a,"obscured"); dT=lambda a:t(a,"plain","vuln")-t(a,"obscured","vuln"); dF=lambda a:t(a,"obscured","secure")-t(a,"plain","secure")
def boot(fn,ps,ms=S,B=4000,seed=21):
    r=random.Random(seed); v=sorted(fn(agg([r.choice(ps) for _ in ps],ms)) for _ in range(B)); return v[int(.025*B)],v[int(.975*B)-1]
pr=lambda x:f"{100*x:.1f}"; ci=lambda t2:f"[{pr(t2[0])}, {pr(t2[1])}]"
NC="cv01 cv02 cv04 cv05 cv08 sk05 bc03 bc10 pr05 wh04 ns01 wh10 ecb08 wh09 cv09 bc06 cv06 hk07 ecb10 ns09 hk04 hk10 hk08 ns10 sk07 wh07 hk05 pr10 iv03 ecb02 ecb05 pr03 hk01".split()
C=[p for p in P if p not in NC]
print("non-clean",len(NC),"clean",len(C))
for name,ps in (("all 80",P),("47 clean",C)):
    a=agg(ps); print(f"{name}: bAcc {bacc(a,'plain'):.3f}->{bacc(a,'obscured'):.3f} drop {pr(dB(a))} {ci(boot(dB,ps))} | TPR {pr(t(a,'plain','vuln'))}->{pr(t(a,'obscured','vuln'))} drop {pr(dT(a))} {ci(boot(dT,ps))} | FPR {pr(t(a,'plain','secure'))}->{pr(t(a,'obscured','secure'))} rise {pr(dF(a))} {ci(boot(dF,ps))}")
    w=l=0
    for p in ps:
        b=agg([p]); d=dB(b); w+=d>0; l+=d<0
    from math import comb
    k=min(w,l); n=w+l; print(f"   pairs plain better {w} indirect better {l} ties {len(ps)-w-l} sign p {min(1,2*sum(comb(n,i) for i in range(k+1))/2**n):.4f}")
print("TPR lower bound re-run with 3 seeds (all 80, indirect):",[pr(boot(lambda a:t(a,'obscured','vuln'),P,seed=s)[0]) for s in (31,32,33)])
six=["cv08","sk05","ns09","hk04","hk10","hk08"]; R=[p for p in P if p not in six]; print("TPR drop without six API-changing:",pr(dT(agg(R))),ci(boot(dT,R)))
four=["cv01","cv02","cv04","cv05"]; R4=[p for p in P if p not in four]
print("FPR rise without four cert:",pr(dF(agg(R4))),ci(boot(dF,R4)))
print("by twin plain-secure flags cv01/02/04/05:",[agg([p])[('plain','secure')][0] for p in four])
print("PER MODEL FPR rise (all 80 | without four | 47 clean) and bAcc drop clean")
for m in S:
    print(f"  {m:20s} {pr(dF(agg(P,[m]))):>6} | {pr(dF(agg(R4,[m]))):>6} | {pr(dF(agg(C,[m]))):>6} | bAcc {pr(dB(agg(C,[m])))}")
print("NET EXTRA SECURE FLAGS BY CLASS (indirect - plain), all 80:")
tot=0
for c in sorted(set(cat.values())):
    a=agg([p for p in P if cat[p]==c]); d=a[('obscured','secure')][0]-a[('plain','secure')][0]; tot+=d; print(f"  {c:14s} {d:+d}")
print("  total",tot)
print("SHARED SECURE TWINS ACROSS PAIRS (same form):")
for f in ("plain","obscured"):
    g=collections.defaultdict(list)
    for p in P: g[code[sid[(p,f,'secure')]].strip()].append(p)
    print(" ",f,[v for v in g.values() if len(v)>1])
g=collections.defaultdict(list)
for p in P: g[code[sid[(p,'plain','secure')]].strip()].append(p)
dup=set()
for v in g.values(): dup|=set(v[1:])
gv=collections.defaultdict(list)
for p in P: gv[code[sid[(p,'plain','vuln')]].strip()].append(p)
for v in gv.values(): dup|=set(v[1:])
R=[p for p in P if p not in dup]; print("drop one of every shared plain snippet",sorted(dup),"n",len(R),"bAcc drop",pr(dB(agg(R))),ci(boot(dB,R)))
rng=random.Random(41); o=[]
for _ in range(4000):
    ps=[rng.choice(P) for _ in P]; ms=[rng.choice(S) for _ in S]; o.append(dB(agg(ps,ms)))
o.sort(); print("two-way bootstrap bAcc drop CI",pr(o[100]),pr(o[3899]))
# Study 1 spearman
s1=collections.defaultdict(lambda:collections.defaultdict(lambda:[0,0]))
for r in v2all: x=s1[r["model"]][r["label"]]; x[0]+=r["detected"]; x[1]+=1
size=lambda m:float(re.search(r":(\d+(?:\.\d+)?)b",m).group(1))
ms=sorted(s1); ba=[(s1[m]["vuln"][0]/s1[m]["vuln"][1]+1-s1[m]["secure"][0]/s1[m]["secure"][1])/2 for m in ms]; sz=[size(m) for m in ms]
def rank(v):
    o=sorted(range(len(v)),key=lambda i:v[i]); r=[0]*len(v); i=0
    while i<len(o):
        j=i
        while j+1<len(o) and v[o[j+1]]==v[o[i]]: j+=1
        for k in range(i,j+1): r[o[k]]=(i+j)/2
        i=j+1
    return r
import statistics as st
print("Study 1 models",len(ms),"Spearman size~bAcc",round(st.correlation(rank(sz),rank(ba)),2))
print("\nREPLIES (repeat 0)")
def show(p,f,l):
    for r in D:
        if r["pair"]==p and r["form"]==f and r["label"]==l and r["repeat"]==0 and r["detected"]:
            print(f"  [{p} {f} {l}] {r['model']}: {r['content'].strip()[:230]!r}")
for p,f in (("cv01","plain"),("cv04","plain"),("sk01","obscured"),("sk08","obscured"),("ecb04","obscured")): show(p,f,"secure")
print("\nSECURE FLAGS plain vs indirect (7 models x 3)")
for p in ("sk01","sk04","sk08","ecb04","ecb06","ecb10"):
    a=agg([p]); print(f"  {p}: plain {a[('plain','secure')][0]}/21 indirect {a[('obscured','secure')][0]}/21 | plain secure: {code[sid[(p,'plain','secure')]].strip().splitlines()[-1][:80]!r}")
n=k=0
for r in D:
    if r["pair"]=="ecb04" and r["form"]=="obscured" and r["label"]=="secure" and r["detected"]:
        n+=1; k+=bool(re.search(r"not (a )?(valid|standard|recognized|specified)|invalid|undefined|incorrect|unknown",r["content"],re.I))
print(f"ecb04 indirect secure flags {n}, calling 11 invalid/non-standard/undefined (keyword): {k}")
n=k=0
for r in D:
    if r["pair"] in ("sk01","sk08") and r["form"]=="obscured" and r["label"]=="secure" and r["detected"]:
        n+=1; k+=bool(re.search(r"3072",r["content"]))
print(f"sk01+sk08 indirect secure flags {n}, mentioning 3072: {k}")
