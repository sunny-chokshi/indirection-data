#!/usr/bin/env bash
# CryptoBench v2b on the RunPod pod. Same Ollama settings as the v2 run.
# bash run_v2b.sh smoke | full     (full resumes if restarted)
set -uo pipefail
cd "$(dirname "$0")"
MODE="${1:-full}"
export OLLAMA_MODELS=/workspace/ollama_models OLLAMA_NUM_PARALLEL=4 OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_KEEP_ALIVE=30m
mkdir -p "$OLLAMA_MODELS"
if ! curl -s http://127.0.0.1:11434/api/version >/dev/null; then
  nohup ollama serve > ollama_v2b.log 2>&1 &
  for i in $(seq 1 30); do curl -s http://127.0.0.1:11434/api/version >/dev/null && break; sleep 1; done
fi
echo "ollama $(curl -s http://127.0.0.1:11434/api/version)" | tee -a run_v2b.log
if [ "$MODE" = "smoke" ]; then
  ollama pull qwen2.5-coder:14b >> pull_v2b.log 2>&1
  python3 crypto_bench_v2b.py --model qwen2.5-coder:14b --repeats 1 --limit 4 --out smoke_v2b.jsonl
  python3 -c "import json;r=[json.loads(l) for l in open('smoke_v2b.jsonl')];print(len(r),'rows',sum(x['verdict']=='ERR' for x in r),'errors',[x['verdict'] for x in r])"
  exit 0
fi
MODELS=(qwen2.5-coder:14b qwen2.5-coder:32b qwen3-coder:30b codestral:22b gpt-oss:20b llama3.3:70b gpt-oss:120b)
for m in "${MODELS[@]}"; do
  echo "=== $m start $(date -u +%FT%TZ)" | tee -a run_v2b.log
  ollama pull "$m" >> pull_v2b.log 2>&1 || { echo "PULL FAILED $m" | tee -a run_v2b.log; continue; }
  python3 crypto_bench_v2b.py --model "$m" --repeats 3 --parallel 4 --out results_v2b.jsonl 2>&1 | tee -a run_v2b.log
  ollama rm "$m" >/dev/null 2>&1
  echo "=== $m end $(date -u +%FT%TZ)" | tee -a run_v2b.log
done
tar czf cryptobench_v2b_results.tgz results_v2b.jsonl run_v2b.log pull_v2b.log
echo "V2B DONE $(date -u +%FT%TZ)" | tee -a run_v2b.log
