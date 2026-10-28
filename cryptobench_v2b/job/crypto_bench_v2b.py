#!/usr/bin/env python3
"""CryptoBench v2b harness (within-pair counterparts; same prompt, parser, decoding as v2).

Runs the 54 v1 snippets plus the 180 v2 snippets (90 matched pairs, plain and
obscured) against local Ollama models. Changes from v1:
  - decoding is set explicitly: temperature 0, fixed seed, output cap
  - the full model reply is logged (JSONL), not a 120-character note
  - resume-safe: a (model, sample_id, repeat) already in the log is skipped
  - every error is logged with its message and counted, never scored

Usage
  python3 crypto_bench_v2.py --model qwen2.5-coder:7b --repeats 3 --out results_v2.jsonl
"""
import argparse, json, os, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import snippets_v2b
from crypto_bench import SAMPLES as V1_SAMPLES, SYS, parse_verdict  # same prompt and parser as v1

OLLAMA = os.environ.get("OLLAMA_ENDPOINT", "http://127.0.0.1:11434/api/chat")
SEED = 42

def all_samples():
    out = []
    for s in snippets_v2b.samples():
        d = dict(s); d["set"] = "v2b"; out.append(d)
    return out

def options_for(model):
    opts = {"temperature": 0, "seed": SEED, "num_ctx": 4096, "num_predict": 256}
    if model.startswith("gpt-oss"):
        opts["num_predict"] = 2048   # reasoning tokens count against the cap
    return opts

def ask(model, code):
    body = {"model": model, "stream": False, "options": options_for(model),
            "messages": [{"role": "system", "content": SYS},
                         {"role": "user", "content": "Review this code:\n\n" + code}]}
    if model.startswith("gpt-oss"):
        body["think"] = "low"
    req = urllib.request.Request(OLLAMA, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=600) as r:
        out = json.loads(r.read().decode())
    msg = out.get("message", {})
    return {"content": msg.get("content", ""), "thinking": msg.get("thinking", ""),
            "eval_count": out.get("eval_count"), "prompt_eval_count": out.get("prompt_eval_count"),
            "done_reason": out.get("done_reason"), "wall_s": round(time.time() - t0, 3)}

def done_keys(path):
    keys = set()
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("verdict") != "ERR":
                    keys.add((r["model"], r["sample_id"], r["repeat"]))
    return keys

def run_one(model, s, rep):
    rec = dict(ts=time.time(), model=model, sample_id=s["id"], pair=s["pair"], set=s["set"],
               cwe=s["cwe"], category=s["category"], variant=s["variant"], label=s["label"],
               repeat=rep, options=options_for(model))
    try:
        r = ask(model, s["code"])
        v = parse_verdict(r["content"])
        has_line = any(l.strip().upper().startswith("VERDICT:") for l in r["content"].splitlines())
        rec.update(r, verdict=v, verdict_line=has_line,
                   detected=1 if v == "VULNERABLE" else 0,
                   correct=int((v == "VULNERABLE") if s["label"] == "vuln" else (v == "SAFE")))
    except Exception as e:
        rec.update(verdict="ERR", error=str(e)[:500], detected=None, correct=None)
    return rec

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default="results_v2.jsonl")
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="first N samples only (smoke test)")
    a = ap.parse_args()
    samples = all_samples()
    if a.limit:
        samples = samples[:a.limit]
    done = done_keys(a.out)
    todo = [(s, r) for r in range(a.repeats) for s in samples if (a.model, s["id"], r) not in done]
    print(f"{a.model}: {len(samples)} samples x {a.repeats} repeats, {len(todo)} to run", flush=True)
    n = err = 0
    with open(a.out, "a") as f, ThreadPoolExecutor(a.parallel) as pool:
        for rec in pool.map(lambda t: run_one(a.model, *t), todo):
            f.write(json.dumps(rec) + "\n"); f.flush()
            n += 1; err += rec["verdict"] == "ERR"
            if n % 50 == 0:
                print(f"  {n}/{len(todo)} done, {err} errors", flush=True)
    print(f"{a.model}: finished {n}, errors {err}", flush=True)

if __name__ == "__main__":
    main()
