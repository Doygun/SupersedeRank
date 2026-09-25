# Reranking Baseline'ları — Smoke-Test (300 sorgu) — 2026-09-15

## Sabit ayarlar (DECISION 011)
- Ortak aday havuzu: kabul edilmiş BM25 top-50 listeleri; reranker yalnız 50 adayın sırasını değiştirir; eşitlik zaman-kör SHA256.
- Recency-only (tanımlayıcı): observed_from'a göre yeniden eskiye. BM25 + Recency: `score = minmax_bm25(e, q) + lambda * exp(-observed_age_days / tau)` ile tau=30 gün, lambda=0.5 (3×3 grid, yalnız dev üzerinde, hedef dev NDCG@10; test seçimde yüklenmez). Yaş = observed_age_days (sol sansürde alt sınır).
- Cross-encoder `cross-encoder/ms-marco-MiniLM-L-6-v2`, girdi yalnız (query_text, evidence_text), ham logit, max_length 512, float32; skorlanan çift 0 (cache'ten 15000), truncation 0.0, 0.0 s, batch 64, OOM 0.
- Determinism (batch 16 vs 64, 20 sorgu / 1000 çift): max |skor farkı| 4.53e-06, top-50 küme aynı 20/20, top-10 sıra aynı 20/20.

## Ana sonuçlar (aynı BM25 top-50 havuzu)
| Metrik | BM25 | Recency-only (diag.) | BM25 + Recency | Cross-encoder |
|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7044 | 0.3966 | 0.9767 | 0.5848 |
| NDCG@10 (ikili) | 0.7818 | 0.4488 | 0.9828 | 0.6425 |
| NDCG@10 (dereceli) | 0.7799 | 0.4532 | 0.9577 | 0.5909 |
| StaleEvidenceRate@10 | 0.1023 | 0.045 | 0.1023 | 0.0627 |
| İlk sıra CURRENT | 0.41 | 0.3067 | 0.9533 | 0.46 |
| İlk sıra OUTDATED | 0.5867 | 0.0 | 0.0433 | 0.1167 |
| CURRENT ve OUTDATED birlikte top-10 | 1.0 | 0.44 | 1.0 | 0.5967 |
| OTHER_SOURCE_CURRENT top-10 | 0.48 | 0.2833 | 0.48 | 0.1667 |
| Retrieval failure | 0.0 | 0.0 | 0.0 | 0.0 |
| Ranking failure | 0.0 | 0.3833 | 0.0 | 0.1767 |

## Oracle üst sınırları (model sonucu değildir; aynı havuz)
| Metrik | Relevance-only current-first oracle | Temporal-clean oracle |
|---|---|---|
| Recall@10 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 |
| MRR@10 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 1.0 | 1.0 |
| StaleEvidenceRate@10 | 0.1023 | 0.0 |
| İlk sıra CURRENT | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.0 | 0.0 |
| CURRENT ve OUTDATED birlikte top-10 | 1.0 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.48 | 0.48 |
| Retrieval failure | 0.0 | 0.0 |
| Ranking failure | 0.0 | 0.0 |

**Split** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- dev: 0.72 / 0.7933 / 0.103 / 0.44 · 0.3373 / 0.3929 / 0.041 / 0.24 · 0.98 / 0.9852 / 0.103 / 0.96 · 0.5888 / 0.6526 / 0.065 / 0.43; n=100
- test: 0.74 / 0.8081 / 0.101 / 0.48 · 0.4191 / 0.4775 / 0.047 / 0.33 · 0.99 / 0.9926 / 0.101 / 0.98 · 0.5834 / 0.6415 / 0.062 / 0.49; n=100
- train: 0.6533 / 0.744 / 0.103 / 0.31 · 0.4332 / 0.4761 / 0.047 / 0.35 · 0.96 / 0.9705 / 0.103 / 0.92 · 0.5823 / 0.6333 / 0.061 / 0.46; n=100

**Sorgu şablonu** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- base_severity: 0.6929 / 0.7733 / 0.1029 / 0.3857 · 0.1631 / 0.2122 / 0.0243 / 0.0857 · 0.9929 / 0.9947 / 0.1029 / 0.9857 · 0.524 / 0.5848 / 0.0529 / 0.3714; n=70
- base_vector: 0.7063 / 0.7832 / 0.1 / 0.4125 · 0.476 / 0.5258 / 0.0475 / 0.4 · 0.9812 / 0.9862 / 0.1 / 0.9625 · 0.5888 / 0.6395 / 0.0638 / 0.4875; n=80
- combined: 0.6987 / 0.7776 / 0.1038 / 0.3974 · 0.7127 / 0.761 / 0.0744 / 0.6026 · 0.9487 / 0.9621 / 0.1038 / 0.8974 · 0.7663 / 0.8118 / 0.0808 / 0.641; n=78
- cvssb_score: 0.7199 / 0.7931 / 0.1028 / 0.4444 · 0.1928 / 0.2552 / 0.0306 / 0.0972 · 0.9861 / 0.9897 / 0.1028 / 0.9722 · 0.443 / 0.5183 / 0.0514 / 0.3194; n=72

**CVSS sürümü** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- 2.0: 0.5 / 0.6309 / 0.1 / 0.0 · 0.2854 / 0.3967 / 0.05 / 0.125 · 0.9375 / 0.9539 / 0.1 / 0.875 · 0.875 / 0.875 / 0.075 / 0.875; n=8
- 3.0: 0.6667 / 0.754 / 0.1 / 0.3333 · 0.1167 / 0.2399 / 0.0333 / 0.0 · 1.0 / 1.0 / 0.1 / 1.0 · 0.4226 / 0.5496 / 0.0333 / 0.3333; n=3
- 3.1: 0.706 / 0.783 / 0.1026 / 0.4133 · 0.4138 / 0.4609 / 0.0454 / 0.3321 · 0.976 / 0.9823 / 0.1026 / 0.952 · 0.572 / 0.6318 / 0.0627 / 0.4428; n=271
- 4.0: 0.7778 / 0.836 / 0.1 / 0.5556 · 0.2335 / 0.3248 / 0.0389 / 0.0556 · 1.0 / 1.0 / 0.1 / 1.0 · 0.6759 / 0.7156 / 0.0611 / 0.5556; n=18

**Kaynak grubu (tanımlayıcı)** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- 134c704f-9b21-4f2e-91b3-4a467353bcc0: 0.7472 / 0.8134 / 0.1011 / 0.4944 · 0.3122 / 0.3211 / 0.0348 / 0.2921 · 1.0 / 1.0 / 0.1011 / 1.0 · 0.4411 / 0.5004 / 0.0584 / 0.2921; n=89
- NVD: 0.6538 / 0.7445 / 0.1013 / 0.3077 · 0.5808 / 0.6137 / 0.0526 / 0.5256 · 0.9295 / 0.948 / 0.1013 / 0.859 · 0.7582 / 0.7871 / 0.0718 / 0.6667; n=78
- OTHER_SOURCE: 0.7162 / 0.7905 / 0.1041 / 0.4324 · 0.2968 / 0.4184 / 0.0527 / 0.0946 · 0.9932 / 0.995 / 0.1041 / 0.9865 · 0.5997 / 0.6895 / 0.0595 / 0.4324; n=74
- audit@patchstack.com: 0.5455 / 0.6645 / 0.1 / 0.0909 · 0.9545 / 0.9664 / 0.0636 / 0.9091 · 0.9545 / 0.9664 / 0.1 / 0.9091 · 0.9545 / 0.9664 / 0.0636 / 0.9091; n=11
- cna@vuldb.com: 0.5 / 0.6309 / 0.1 / 0.0 · 0.3389 / 0.4196 / 0.0667 / 0.1667 · 1.0 / 1.0 / 0.1 / 1.0 · 0.6905 / 0.7222 / 0.0833 / 0.6667; n=6
- disclosure@vulncheck.com: 0.7857 / 0.8418 / 0.1 / 0.5714 · 0.1871 / 0.2325 / 0.0179 / 0.1429 · 1.0 / 1.0 / 0.1 / 1.0 · 0.334 / 0.3878 / 0.05 / 0.2857; n=28
- secalert@redhat.com: 0.7024 / 0.7798 / 0.1143 / 0.4286 · 0.4393 / 0.5417 / 0.0571 / 0.2143 · 0.9643 / 0.9736 / 0.1143 / 0.9286 · 0.6197 / 0.7121 / 0.0714 / 0.4286; n=14

## Süre, bellek, bütünlük
- Yeniden sıralama süreleri (s): {'recency_only': 0.03, 'bm25_recency': 0.03, 'cross_encoder_rerank': 0.06}; peak GPU 0.271 GB, peak RSS 1.185 GB; liste dosyaları toplam 8.4 MB
- Aday sayısı 50 olmayan sorgu 0, aday kümesi değişen 0, Recall@50 BM25'ten farklı 0, NaN/inf 0, eksik sorgu 0

## Teknik kapılar
- all_queries_present: True
- fifty_candidates_each: True
- no_candidate_change: True
- recall50_equals_bm25: True
- no_nan_inf: True
- cross_encoder_top50_set_stable: True
- test_not_used_for_selection: True
- all_passed: True
