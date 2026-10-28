#!/usr/bin/env python3
"""v7 numbers (numeric-pair split, gross flag changes). Base copied from v6 (Oct 8 2026): 47 clean pairs (non-clean list = v5 independent review, 33 ids), per-model FPR change,
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

NUM="ecb04 ecb06 ecb10 sk01 sk04 sk08 cv03 cv10 ns03 hk01 iv03".split()
R=[p for p in P if p not in NUM]; C=[p for p in P if p not in NC]; C2=[p for p in C if p not in NUM]
for name,ps in (("11 numeric",NUM),("other 69",R),("clean minus numeric",C2)):
    a=agg(ps); print(f"{name} n={len(ps)}: bAcc drop {pr(dB(a))} {ci(boot(dB,ps))} | FPR rise {pr(dF(a))} {ci(boot(dF,ps))} | TPR drop {pr(dT(a))} {ci(boot(dT,ps))}")
up=dn=0; net_num=0
for p in P:
    a=agg([p]); d=a[('obscured','secure')][0]-a[('plain','secure')][0]
    if d>0: up+=d
    else: dn+=-d
    if p in NUM: net_num+=d
print("gross secure-flag rise",up,"fall",dn,"net",up-dn,"net in numeric pairs",net_num)
print("numeric pairs in non-clean list:",[p for p in NUM if p in NC])
