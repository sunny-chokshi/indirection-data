#!/usr/bin/env bash
# CryptoBench v2 full run on a RunPod GPU pod (A100 80GB).
# Usage:  bash run_all.sh smoke   (2 min check, one small model, 5 samples)
#         bash run_all.sh full    (all models, resumes if restarted)
set -uo pipefail
cd "$(dirname "$0")"
MODE="${1:-full}"
export OLLAMA_MODELS=/workspace/ollama_models OLLAMA_NUM_PARALLEL=4 OLLAMA_MAX_LOADED_MODELS=1 OLLAMA_KEEP_ALIVE=30m
mkdir -p "$OLLAMA_MODELS"

if ! command -v ollama >/dev/null; then
  apt-get update -qq && apt-get install -y -qq zstd >/dev/null 2>&1 || true
  curl -fsSL https://ollama.com/install.sh | sh
fi
if ! curl -s http://127.0.0.1:11434/api/version >/dev/null; then
  nohup ollama serve > ollama.log 2>&1 &
  for i in $(seq 1 30); do curl -s http://127.0.0.1:11434/api/version >/dev/null && break; sleep 1; done
fi
echo "ollama $(curl -s http://127.0.0.1:11434/api/version)" | tee -a run.log
nvidia-smi --query-gpu=name,memory.total --format=csv | tee -a run.log

if [ "$MODE" = "smoke" ]; then
  ollama pull qwen2.5-coder:0.5b
  python3 crypto_bench_v2.py --model qwen2.5-coder:0.5b --repeats 1 --limit 5 --out smoke.jsonl
  python3 -c "import json;r=[json.loads(l) for l in open('smoke.jsonl')];print(len(r),'rows',sum(x['verdict']=='ERR' for x in r),'errors');print(r[0]['content'][:200])"
  exit 0
fi

MODELS=(
  # v1 models, rerun for direct comparison
  qwen2.5-coder:0.5b qwen2.5-coder:1.5b qwen2.5-coder:3b qwen2.5-coder:7b qwen2.5-coder:14b
  deepseek-coder:6.7b codellama:7b
  # new, larger
  deepseek-coder-v2:16b codestral:22b devstral:24b qwen3-coder:30b qwen2.5-coder:32b
  codellama:34b gpt-oss:20b llama3.3:70b gpt-oss:120b
)
for m in "${MODELS[@]}"; do
  echo "=== $m start $(date -u +%FT%TZ)" | tee -a run.log
  if ! ollama pull "$m" >> pull.log 2>&1; then echo "PULL FAILED $m" | tee -a run.log; continue; fi
  python3 crypto_bench_v2.py --model "$m" --repeats 3 --parallel 4 --out results_v2.jsonl 2>&1 | tee -a run.log
  ollama rm "$m" >/dev/null 2>&1
  echo "=== $m end $(date -u +%FT%TZ)" | tee -a run.log
done
python3 summarize_v2.py results_v2.jsonl > summary_v2.txt 2>&1
tar czf cryptobench_v2_results.tgz results_v2.jsonl summary_v2.txt run.log pull.log ollama.log
echo "ALL DONE $(date -u +%FT%TZ). Copy cryptobench_v2_results.tgz to the Mac, then TERMINATE the pod." | tee -a run.log
