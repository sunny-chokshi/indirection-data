#!/usr/bin/env python3
"""v4 extras: length vs pair drop (Pearson r), exact codestral change, Study 2 output-cap hits. Usage: python3 extra_v4.py <crypto_dir>"""
import json,sys,os,importlib.util,collections,statistics as st
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
sid={(r["pair"],r["form"],r["label"]):r["sample_id"] for r in D}
c=collections.defaultdict(lambda:[0,0])
for r in D: x=c[(r["pair"],r["form"],r["label"])]; x[0]+=r["detected"]; x[1]+=1
def acc(p,f): return (c[(p,f,"vuln")][0]+c[(p,f,"secure")][1]-c[(p,f,"secure")][0])/(c[(p,f,"vuln")][1]+c[(p,f,"secure")][1])
dl=[];dd=[]
for p in P:
    lp=len(code[sid[(p,"plain","vuln")]])+len(code[sid[(p,"plain","secure")]]); lo=len(code[sid[(p,"obscured","vuln")]])+len(code[sid[(p,"obscured","secure")]])
    dl.append(lo-lp); dd.append(acc(p,"plain")-acc(p,"obscured"))
print("mean extra chars in indirect form (vuln+secure):",round(st.mean(dl),1)," Pearson r(length diff, pair drop):",round(st.correlation(dl,dd),3))
m="codestral:22b"; a=collections.defaultdict(lambda:[0,0])
for r in D:
    if r["model"]==m: x=a[(r["form"],r["label"])]; x[0]+=r["detected"]; x[1]+=1
b=lambda f:(a[(f,"vuln")][0]/a[(f,"vuln")][1]+1-a[(f,"secure")][0]/a[(f,"secure")][1])/2
print(f"codestral plain {b('plain'):.4f} indirect {b('obscured'):.4f} change {b('obscured')-b('plain'):+.4f}")
print("keys in rows:",sorted(D[0].keys()))
