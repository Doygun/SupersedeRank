# SupersedeRank: Query-Time-Aware Reranking of Superseded CVSS Evidence

Code and derived data for the paper *SupersedeRank: Query-Time-Aware Reranking of Superseded CVSS Evidence in Retrieval-Augmented Generation*.

The repository contains the pipeline that builds the temporal CVSS assessment dataset from the NVD change history, the parameter-free reranking rule (called `ChronoRank-Rule-Target` in the code, `SupersedeRank-Rule-Target` in the paper) and its corpus-level scope variant, the comparison methods, the evaluation metrics, the CVE-level cluster bootstrap, and the scripts that produce the result tables.

## Layout

```
config/          YAML settings (timeline, split, queries, retrieval, reranking, statistics)
src/ingest       NVD download helpers
src/normalize    CVSS 2.0/3.x/4.0 vector parsing and score calculators
src/timeline     source-conditioned timeline replay and atomic replacement events
src/label        temporal split (future-entity protocol) and query-time labels
src/queries      source-conditioned query generation
src/evidence     evidence records and the full retrieval corpus
src/retrieval    BM25, dense and hybrid retrieval over the query-time-visible corpus
src/rerank       rule-based rerankers, recency and cross-encoder baselines, diagnostic policies
src/eval         ranking and stale-suppression metrics
src/analysis     bootstrap, paired comparisons, offset sensitivity, control audits
src/reports      LaTeX table generators
tools/           profiling, validation and figure scripts
tests/           unit tests (`pytest`) and full-data regression tests (`pytest -m full_data`)
results/         experiment reports (JSON) and generated paper tables
data/processed/  derived dataset (see below)
```

## Setup

```
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
pytest -q                       # unit tests
```

## Data

Raw NVD data are not included; `download_data.py` fetches the CVE and change-history records into `data/raw/`.

`data/processed/` holds the derived dataset used in the paper: the atomic replacement events, the source-conditioned timeline intervals, the temporal split (`splits/`), the source-conditioned queries with query-time labels (`queries/`), the main evidence set (`evidence/`), the negative controls, and the cross-event sensitivity records. Two large files are shipped compressed and must be unpacked before the retrieval scripts are run:

```
gunzip data/processed/cvss_evidence.jsonl.gz
gunzip data/processed/corpus/full_corpus.jsonl.gz
```

Retrieval caches (BM25 index, dense embeddings, cross-encoder scores) are not included; they are rebuilt by the retrieval scripts.

## Pipeline

Run the modules from the repository root in this order:

```
python download_data.py
python -m src.timeline.cvss_replacements
python -m src.timeline.replay
python -m src.label.splits
python -m src.queries.build_queries
python -m src.evidence.build_evidence
python -m src.evidence.build_corpus
python -m src.retrieval.bm25_full
python -m src.retrieval.dense_hybrid_run
python -m src.rerank.baselines_run
python -m src.rerank.rule_run
python -m src.rerank.rule_target_run
python -m src.analysis.cluster_bootstrap
python -m src.analysis.offset_sensitivity
python -m src.reports.results_tables
python -m src.reports.dataset_stats_table
```

Settings are read from `config/`. All randomness uses fixed seeds recorded in the configuration files, and every experiment writes a manifest next to its results.

## Results

`results/experiments/` contains the report and manifest files of every run reported in the paper (BM25, dense and hybrid retrieval, recency and cross-encoder baselines, the rule variants, the Direct-Link policy, the temporal-clean oracle, the pre-replacement controls, the offset sensitivity analysis and the statistical analysis). `results/paper_tables/` contains the LaTeX tables and the figure data generated from these files.
