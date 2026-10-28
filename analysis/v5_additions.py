#!/usr/bin/env python3
"""v5 additions (Oct 8 2026): F1 unmatched cert twins, F3 token contrast without cv08/sk05 and alternative readings,
importlib pairs, duplicate plain forms, repeat unanimity. Usage: python3 v5_additions.py <crypto_dir>. 4,000 pair draws."""
import json,sys,os,random,collections,importlib.util
CD=sys.argv[1]
def lm(n,p):
    s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.path.insert(0,os.path.dirname(p));s.loader.exec_module(m);return m
code={}
for n,p in (("snippets_v2","cryptobench_v2/job/snippets_v2.py"),("snippets_v2b","cryptobench_v2b/job/snippets_v2b.py")):
    code.update({s["id"]:s["code"] for s in lm(n,f"{CD}/{p}").samples()})
L=lambda p:[json.loads(l) for l in open(p) if l.strip()]
v2=[r for r in L(f"{CD}/cryptobench_v2/results/extracted/results_v2.jsonl") if r["set"]=="v2"]
v2b=L(f"{CD}/cryptobench_v2b/results/extracted/results_v2b.jsonl")
S=sorted({r["model"] for r in v2b});P=sorted({r["pair"] for r in v2b})
F=lambda r:"plain" if r["variant"]=="plain" else "obscured"
D=[dict(r,form=F(r)) for r in v2 if r["pair"] in P and r["model"] in S]+[dict(r,form=F(r)) for r in v2b]
sid={(r["pair"],r["form"],r["label"]):r["sample_id"] for r in D}; cat={r["pair"]:r["category"] for r in D}
cnt=collections.defaultdict(lambda:collections.defaultdict(lambda:[0,0]))
for r in D: x=cnt[r["pair"]][(r["form"],r["label"])]; x[0]+=r["detected"]; x[1]+=1
def agg(ps):
    a=collections.defaultdict(lambda:[0,0])
    for p in ps:
        for k,v in cnt[p].items(): a[k][0]+=v[0]; a[k][1]+=v[1]
    return a
t=lambda a,f,l: a[(f,l)][0]/a[(f,l)][1]
bacc=lambda a,f:(t(a,f,"vuln")+1-t(a,f,"secure"))/2
drop=lambda a:bacc(a,"plain")-bacc(a,"obscured"); dt=lambda a:t(a,"plain","vuln")-t(a,"obscured","vuln"); dfp=lambda a:t(a,"obscured","secure")-t(a,"plain","secure")
def boot(fn,ps,B=4000,seed=11):
    r=random.Random(seed); v=sorted(fn(agg([r.choice(ps) for _ in ps])) for _ in range(B)); return v[int(.025*B)],v[int(.975*B)-1]
def bdiff(A,Bp,B=4000,seed=12):
    r=random.Random(seed); v=sorted(dt(agg([r.choice(A) for _ in A]))-dt(agg([r.choice(Bp) for _ in Bp])) for _ in range(B)); return v[int(.025*B)],v[int(.975*B)-1]
def permp(A,Bp,B=20000,seed=13):
    obs=dt(agg(A))-dt(agg(Bp)); pool=A+Bp; r=random.Random(seed); g=0
    for _ in range(B):
        r.shuffle(pool); x=pool[:len(A)]; y=pool[len(A):]
        if abs(dt(agg(x))-dt(agg(y)))>=abs(obs)-1e-12: g+=1
    return g/B
pr=lambda x:f"{100*x:.1f}"
print("F1 UNMATCHED CERT SECURE TWINS (plain omits argument, indirect adds explicit safe value)")
U=["cv01","cv02","cv04","cv05"]
for p in U: print(f"--- {p} plain secure ---\n{code[sid[(p,'plain','secure')]].strip()}\n--- {p} indirect secure ---\n{code[sid[(p,'obscured','secure')]].strip()}")
a=agg(U); print(f"flags on these 4 secure twins: plain {a[('plain','secure')][0]}/{a[('plain','secure')][1]} -> indirect {a[('obscured','secure')][0]}/{a[('obscured','secure')][1]}")
R=[p for p in P if p not in U]; a=agg(R)
print(f"without them (n={len(R)}): FPR {pr(t(a,'plain','secure'))}->{pr(t(a,'obscured','secure'))} rise {pr(dfp(a))} {tuple(map(pr,boot(dfp,R)))} | bAcc drop {pr(drop(a))} {tuple(map(pr,boot(drop,R)))} | TPR drop {pr(dt(a))} {tuple(map(pr,boot(dt,R)))}")
a=agg(P); print(f"all 80: FPR rise {pr(dfp(a))} {tuple(map(pr,boot(dfp,P)))}")
c=[p for p in P if cat[p]=="cert_verify" and p not in U]; a=agg(c); print(f"cert_verify without the 4: bAcc {bacc(a,'plain'):.3f}->{bacc(a,'obscured'):.3f}")
print("\nF2/F3 TOKEN SPLIT ACCOUNTING")
TOK={"weak_hash","ecb_mode","broken_cipher","cert_verify","short_key","weak_prng"}
print("pairs in token classes:",sum(cat[p] in TOK for p in P),"no-token classes:",sum(cat[p] not in TOK for p in P))
ABS=["cv03","cv06","cv08","ecb04","ecb06","ecb10","sk01","sk04","sk05","sk08"]
def split(absent,none_extra=()):
    ap=list(absent); pp=[p for p in P if cat[p] in TOK and p not in ap and p not in none_extra]; return ap,pp
for name,ap_,ex in (("main (bc05 grouped with no-token)",ABS,("bc05",)),("bc05 as present",ABS,()),("bc05 as absent",ABS+["bc05"],()),("sk03 as absent",ABS+["sk03"],("bc05",))):
    ap,pp=split(ap_,ex); d=dt(agg(ap))-dt(agg(pp)); print(f"  {name:36s} absent {len(ap)} present {len(pp)} diff {pr(d)} {tuple(map(pr,bdiff(ap,pp)))} perm p(two-sided) {permp(ap,pp):.3f}")
ap,pp=split([p for p in ABS if p not in ("cv08","sk05")],("bc05","cv08","sk05")); d=dt(agg(ap))-dt(agg(pp))
print(f"  without cv08,sk05: absent drop {pr(dt(agg(ap)))} present drop {pr(dt(agg(pp)))} diff {pr(d)} {tuple(map(pr,bdiff(ap,pp)))} perm p {permp(ap,pp):.3f}")
for x in ("cv08","sk05"):
    ap,pp=split([p for p in ABS if p!=x],("bc05",x)); print(f"  without {x} only: diff {pr(dt(agg(ap))-dt(agg(pp)))}")
print("secure twins of absent pairs identical across forms:",[p for p in ABS if code[sid[(p,'plain','secure')]].strip()==code[sid[(p,'obscured','secure')]].strip()])
print("\nIMPORTLIB PAIRS")
IM=[p for p in P if "importlib" in code[sid[(p,"obscured","vuln")]] or "importlib" in code[sid[(p,"obscured","secure")]]]
a=agg(IM); print(IM, f"secure FPR {pr(t(a,'plain','secure'))}->{pr(t(a,'obscured','secure'))}  TPR {pr(t(a,'plain','vuln'))}->{pr(t(a,'obscured','vuln'))}")
print("\nDUPLICATE PLAIN FORMS ACROSS PAIRS")
seen=collections.defaultdict(list)
for p in P:
    seen[(code[sid[(p,"plain","vuln")]].strip(),code[sid[(p,"plain","secure")]].strip())].append(p)
dup=[v for v in seen.values() if len(v)>1]; print("identical plain vuln+secure:",dup)
sv=collections.defaultdict(list)
for p in P: sv[code[sid[(p,"plain","vuln")]].strip()].append(p)
print("identical plain vuln only:",[v for v in sv.values() if len(v)>1])
drop1=[v[1] for v in [v for v in sv.values() if len(v)>1]]; R=[p for p in P if p not in drop1]; a=agg(R)
print(f"dropping one of each ({drop1}): n={len(R)} drop {pr(drop(a))} {tuple(map(pr,boot(drop,R)))}")
print("\nREPEAT UNANIMITY (Study 2 cells: model x snippet)")
cell=collections.defaultdict(list)
for r in D: cell[(r["model"],r["sample_id"])].append(r["detected"])
u=sum(len(set(v))==1 for v in cell.values()); print(f"{u}/{len(cell)} = {100*u/len(cell):.1f}% unanimous")
