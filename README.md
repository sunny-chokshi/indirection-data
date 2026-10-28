Archived release with a citable DOI: https://doi.org/10.5281/zenodo.23747614 (Zenodo). Preprint: https://doi.org/10.5281/zenodo.23351769. This repository mirrors the Zenodo v1.0.0 files.

# Does Indirection Hurt? Stimuli, per-call results and analysis scripts

Supplement to the preprint "Does Indirection Hurt? Paired Evidence on LLM Review of Indirectly Written Cryptographic API Misuse" (Zenodo, https://doi.org/10.5281/zenodo.23351769).

Author: Sunny Chokshi, University of the Cumberlands. ORCID 0009-0003-4738-7759.
Version 1.0.0, released 2026-10-28. Data and text CC BY 4.0, code MIT (see LICENSE).

## What is in here

| Folder | Contents |
|---|---|
| `cryptobench_v2/job/` | The 90 matched snippet pairs (`snippets_v2.py`), the harness that queried each model (`crypto_bench_v2.py`, `crypto_bench.py`), the run script and the summary script. |
| `cryptobench_v2/results/extracted/` | `results_v2.jsonl`: one line per model call, 11,232 calls. It holds the 2,592 Study 1 calls on the 54 CryptoBench v1 snippets and the 8,640 Study 2 calls on the 180 v2 snippets, across 16 open models with 3 repeats. `summary_v2.txt` is the run summary. |
| `cryptobench_v2b/job/` | The opposite-form counterparts for 80 of the 90 pairs (`cp_a.py`, `cp_b.py`, `cp_c.py`, `snippets_v2b.py`), the harness and the paired analysis script. |
| `cryptobench_v2b/results/extracted/` | `results_v2b.jsonl`: 3,360 calls (80 pairs, both snippets, 7 models, 3 repeats). |
| `audit/` | `audit_pairs.csv`: the post hoc stimulus audit. 33 of the 80 pairs are marked "not clean" with the reason. The other 47 are the clean set used for the audited results. `nonclean_pairs.txt` is the original note. |
| `analysis/` | The scripts that produce the paper's tables (`analyze_v4.py`, `extra_v4.py`, `v5_additions.py`, `v6.py`, `v7.py`) and their saved outputs (`out_*.txt`). |

## Try it in 2 minutes

You need Python 3 and nothing else. From this folder:

```
python3 analysis/v6.py .
```

This prints the headline numbers. Balanced accuracy of the seven strongest models falls 4.5 points when the misuse is written indirectly (95% CI 1.4 to 7.6 in this script), and 5.3 points (CI 2.1 to 8.5) on the 47 clean pairs. On the clean pairs the false positive rate rises 9.1 points (CI 4.2 to 14.6) and detection falls 1.5 points (CI -1.6 to 4.8). Over all 80 pairs detection falls 3.6 points (CI 1.0 to 6.5).

`analysis/analyze_v4.py .` takes a few minutes (it runs permutation tests) and prints the full all-pairs analysis, where the same overall drop has CI 1.3 to 7.6. The 1.3 versus 1.4 comes from a different random seed in the bootstrap. The paper reports 1.3 to 7.6.

Every script reproduces its saved `out_*.txt` byte for byte on the files in this record.

## Design in brief

Each of the 90 pairs has a vulnerable snippet and a secure twin. For 80 pairs, each snippet exists in a plain form (the familiar name at the call site) and an indirect form (an alias, constant, default or configuration value that reaches the same choice). Models run locally through Ollama at temperature 0 with seed 42 and a 256-token cap. The prompt and the verdict parser are in `crypto_bench.py`. Every reply is logged in full. Errors are logged and never scored.

## Things to know before you reuse this

- In the logs, the `variant` field says `obscured` where the paper says indirect.
- The audit file lists five pairs under "unmatched secure twin" (cv01, cv02, cv04, cv05 and ns01). The paper's "four unmatched certificate pairs" figure (false-alarm rise 8.0 points) leaves out only cv01, cv02, cv04 and cv05. The paper's audit paragraph also names only some of the reason categories. `audit/audit_pairs.csv` has the full list, and the count of 33 is the same.
- Models ran locally through Ollama. The Ollama version was not recorded, and the model tags are in the `model` field of each log line.

- The audit came after the runs. 33 of the 80 pairs differ in more than the route to the misuse (see `audit/audit_pairs.csv`). The paper reports results with and without them.
- Both exploratory splits in the paper were chosen after seeing the data.
- The seven models in Study 2 were chosen after Study 1. Confidence intervals treat them as fixed.
- Detection counts a vulnerable verdict given for any reason. I did not check whether each detection named the right misuse.
- The snippets and labels were written with AI assistance and checked by me. Labeling errors are possible.
- Ollama batches parallel requests, so reruns can differ by a few points even at temperature 0.

## One change from the logs as recorded

The static IV and nonce class was tagged CWE-329 at run time. CWE-329 is specific to CBC, and the class covers fixed or reused nonces in AEAD modes, so this record uses CWE-1204. I changed the `cwe` field for the `static_iv` class of the 90 v2 pairs in `results_v2.jsonl` (960 rows) and for all 252 `static_iv` rows in `results_v2b.jsonl`, and the two matching lines in `snippets_v2.py`. Nothing else in the logs was changed. The Study 1 rows from CryptoBench v1 keep CWE-329, as in the v1 release. md5 before the change: `results_v2.jsonl` a91cf27e6285bc20c296050b6430657c, `results_v2b.jsonl` 5cd390653d654e66c94309cdccb361df. md5 as released: `results_v2.jsonl` 23f7aa16804d428ca51a8de19e2e4e39, `results_v2b.jsonl` febce9ca42e2e0f7a920945682f83cc2. No analysis script uses the `cwe` field, and all outputs are identical before and after the change.

## Related records

- Preprint: https://doi.org/10.5281/zenodo.23351769
- CryptoBench v1: https://doi.org/10.5281/zenodo.23067052
- Known-Bad Names preprint: https://doi.org/10.5281/zenodo.23113861

## Cite as

Chokshi, S. (2026). Does Indirection Hurt? Stimuli, per-call results, audit list and analysis scripts (v1.0.0) [Data set]. Zenodo. Use the DOI shown on this record's Zenodo page.
