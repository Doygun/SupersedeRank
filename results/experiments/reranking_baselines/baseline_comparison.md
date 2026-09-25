# Reranking Baseline'ları — Tam Koşu (3.537 ana sorgu) — 2026-09-15

## Sabit ayarlar (DECISION 011)
- Ortak aday havuzu: kabul edilmiş BM25 top-50 listeleri; reranker yalnız 50 adayın sırasını değiştirir; eşitlik zaman-kör SHA256.
- Recency-only (tanımlayıcı): observed_from'a göre yeniden eskiye. BM25 + Recency: `score = minmax_bm25(e, q) + lambda * exp(-observed_age_days / tau)` ile tau=30 gün, lambda=0.5 (3×3 grid, yalnız dev üzerinde, hedef dev NDCG@10; test seçimde yüklenmez). Yaş = observed_age_days (sol sansürde alt sınır).
- Cross-encoder `cross-encoder/ms-marco-MiniLM-L-6-v2`, girdi yalnız (query_text, evidence_text), ham logit, max_length 512, float32; skorlanan çift 162800 (cache'ten 15000), truncation 0.0, 96.5 s, batch 64, OOM 0.
- Determinism (batch 16 vs 64, 20 sorgu / 1000 çift): max |skor farkı| 4.53e-06, top-50 küme aynı 20/20, top-10 sıra aynı 20/20.

## Ana sonuçlar (aynı BM25 top-50 havuzu)
| Metrik | BM25 | Recency-only (diag.) | BM25 + Recency | Cross-encoder |
|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7116 | 0.3815 | 0.98 | 0.5442 |
| NDCG@10 (ikili) | 0.787 | 0.4341 | 0.9852 | 0.6049 |
| NDCG@10 (dereceli) | 0.7852 | 0.4392 | 0.9572 | 0.5568 |
| StaleEvidenceRate@10 | 0.1047 | 0.0439 | 0.1047 | 0.0632 |
| İlk sıra CURRENT | 0.43 | 0.2997 | 0.9601 | 0.4173 |
| İlk sıra OUTDATED | 0.5655 | 0.0 | 0.0376 | 0.1233 |
| CURRENT ve OUTDATED birlikte top-10 | 0.9997 | 0.4207 | 0.9997 | 0.5864 |
| OTHER_SOURCE_CURRENT top-10 | 0.4984 | 0.2757 | 0.4936 | 0.1544 |
| Retrieval failure | 0.0 | 0.0 | 0.0 | 0.0 |
| Ranking failure | 0.0 | 0.3941 | 0.0 | 0.2041 |

## Oracle üst sınırları (model sonucu değildir; aynı havuz)
| Metrik | Relevance-only current-first oracle | Temporal-clean oracle |
|---|---|---|
| Recall@10 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 |
| MRR@10 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 1.0 | 1.0 |
| StaleEvidenceRate@10 | 0.1047 | 0.0 |
| İlk sıra CURRENT | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.0 | 0.0 |
| CURRENT ve OUTDATED birlikte top-10 | 0.9997 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.4993 | 0.4993 |
| Retrieval failure | 0.0 | 0.0 |
| Ranking failure | 0.0 | 0.0 |

**Split** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- dev: 0.7121 / 0.7873 / 0.1054 / 0.4295 · 0.3404 / 0.3937 / 0.0394 / 0.2564 · 0.9749 / 0.9814 / 0.1054 / 0.9519 · 0.5505 / 0.618 / 0.0631 / 0.4038; n=312
- test: 0.7212 / 0.7941 / 0.1048 / 0.4489 · 0.3957 / 0.4485 / 0.0463 / 0.3201 · 0.9877 / 0.9909 / 0.1048 / 0.9754 · 0.5053 / 0.5702 / 0.0631 / 0.3738; n=1506
- train: 0.7031 / 0.7807 / 0.1044 / 0.4136 · 0.3764 / 0.4289 / 0.0425 / 0.2897 · 0.9741 / 0.9809 / 0.1044 / 0.9482 · 0.5771 / 0.6329 / 0.0633 / 0.4578; n=1719

**Sorgu şablonu** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- base_severity: 0.7142 / 0.7889 / 0.1048 / 0.4344 · 0.2165 / 0.2702 / 0.0278 / 0.1368 · 0.9932 / 0.995 / 0.1048 / 0.9863 · 0.5049 / 0.5703 / 0.0587 / 0.3751; n=877
- base_vector: 0.7072 / 0.7837 / 0.1051 / 0.4228 · 0.4108 / 0.4708 / 0.047 / 0.318 · 0.981 / 0.986 / 0.1051 / 0.962 · 0.5418 / 0.5988 / 0.0616 / 0.4251; n=868
- combined: 0.7079 / 0.7842 / 0.105 / 0.4228 · 0.7449 / 0.7885 / 0.0794 / 0.6597 · 0.9479 / 0.9615 / 0.105 / 0.8966 · 0.7486 / 0.7973 / 0.0844 / 0.6132; n=861
- cvssb_score: 0.7168 / 0.7908 / 0.1039 / 0.4393 · 0.1733 / 0.2266 / 0.0231 / 0.1031 · 0.9962 / 0.9972 / 0.1039 / 0.9925 · 0.3944 / 0.4653 / 0.0492 / 0.2685; n=931

**CVSS sürümü** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- 2.0: 0.6152 / 0.7158 / 0.1015 / 0.2353 · 0.3198 / 0.4233 / 0.0441 / 0.1324 · 0.9265 / 0.9457 / 0.1015 / 0.8529 · 0.712 / 0.7465 / 0.0735 / 0.6324; n=68
- 3.0: 0.7059 / 0.7829 / 0.1059 / 0.4118 · 0.2035 / 0.3176 / 0.0471 / 0.0588 · 1.0 / 1.0 / 0.1059 / 1.0 · 0.5332 / 0.6266 / 0.0412 / 0.4118; n=17
- 3.1: 0.7136 / 0.7884 / 0.1045 / 0.433 · 0.3955 / 0.4419 / 0.0434 / 0.3238 · 0.9795 / 0.9848 / 0.1045 / 0.9592 · 0.5537 / 0.6124 / 0.0637 / 0.428; n=3159
- 4.0: 0.7133 / 0.788 / 0.1072 / 0.4437 · 0.2548 / 0.3594 / 0.0488 / 0.0922 · 0.9966 / 0.9975 / 0.1072 / 0.9932 · 0.4032 / 0.4897 / 0.057 / 0.2526; n=293

**Kaynak grubu (tanımlayıcı)** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Recency-only (diag.) · BM25 + Recency · Cross-encoder); n

- 134c704f-9b21-4f2e-91b3-4a467353bcc0: 0.7503 / 0.8156 / 0.1037 / 0.505 · 0.3109 / 0.3238 / 0.0367 / 0.2915 · 0.9977 / 0.9983 / 0.1037 / 0.9954 · 0.4632 / 0.521 / 0.0681 / 0.3254; n=1091
- NVD: 0.6806 / 0.7641 / 0.1024 / 0.3655 · 0.5879 / 0.6138 / 0.0529 / 0.5453 · 0.9405 / 0.9561 / 0.1024 / 0.882 · 0.756 / 0.7892 / 0.0751 / 0.6576; n=695
- OTHER_SOURCE: 0.7059 / 0.7827 / 0.1068 / 0.4195 · 0.3381 / 0.4468 / 0.048 / 0.1706 · 0.9857 / 0.9894 / 0.1068 / 0.9714 · 0.5311 / 0.6155 / 0.054 / 0.3761; n=944
- audit@patchstack.com: 0.6221 / 0.7211 / 0.1 / 0.2443 · 0.9924 / 0.9944 / 0.0611 / 0.9847 · 0.9389 / 0.9549 / 0.1 / 0.8779 · 0.9962 / 0.9972 / 0.0679 / 0.9924; n=131
- cna@vuldb.com: 0.6905 / 0.7711 / 0.1015 / 0.3985 · 0.2442 / 0.3341 / 0.0504 / 0.0902 · 0.9887 / 0.9917 / 0.1015 / 0.9774 · 0.4924 / 0.5634 / 0.0707 / 0.3609; n=133
- disclosure@vulncheck.com: 0.7169 / 0.7909 / 0.1053 / 0.4418 · 0.1647 / 0.2133 / 0.0243 / 0.1058 · 0.9987 / 0.999 / 0.1053 / 0.9974 · 0.2566 / 0.3214 / 0.0437 / 0.1587; n=378
- secalert@redhat.com: 0.6955 / 0.7747 / 0.1133 / 0.4121 · 0.3482 / 0.4756 / 0.0552 / 0.1273 · 0.9788 / 0.9843 / 0.1133 / 0.9576 · 0.6043 / 0.6943 / 0.0679 / 0.4303; n=165

## Future-event kohortu (tanımlayıcı; ana tabloyla birleştirilmez)
| Metrik | BM25 | Recency-only (diag.) | BM25 + Recency | Cross-encoder |
|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.6053 | 0.4962 | 1.0 | 0.6813 |
| NDCG@10 (ikili) | 0.7061 | 0.5529 | 1.0 | 0.7207 |
| NDCG@10 (dereceli) | 0.6988 | 0.5348 | 0.9574 | 0.6136 |
| StaleEvidenceRate@10 | 0.1842 | 0.0895 | 0.1842 | 0.1053 |
| İlk sıra CURRENT | 0.3158 | 0.4211 | 1.0 | 0.5789 |
| İlk sıra OUTDATED | 0.6842 | 0.0 | 0.0 | 0.1053 |
| CURRENT ve OUTDATED birlikte top-10 | 1.0 | 0.5789 | 1.0 | 0.6316 |
| OTHER_SOURCE_CURRENT top-10 | 0.5789 | 0.5263 | 0.5789 | 0.1579 |
| Retrieval failure | 0.0 | 0.0 | 0.0 | 0.0 |
| Ranking failure | 0.0 | 0.2632 | 0.0 | 0.1579 |
n=19 sorgu / 18 CVE.

## Süre, bellek, bütünlük
- Yeniden sıralama süreleri (s): {'recency_only': 0.41, 'bm25_recency': 0.46, 'cross_encoder_rerank': 0.74}; peak GPU 0.283 GB, peak RSS 1.301 GB; liste dosyaları toplam 99.3 MB
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
