# ChronoRank-Rule-Target — Tam Koşu (3.537 ana + 19 future-event) — 2026-09-16

## Yöntem
- ChronoRank-Rule-Target (RULE-INFERRED-TARGET-CHAIN-ONLY): parameter-free block ordering; the inferred-supersession signal is evaluated only for candidates in the query chain (cve_id, source_key, cvss_version); every other candidate keeps its BM25 position.
- Sinyal: newer visible same-chain witness with a different canonical Base vector; witness scope = main Base-query evidence minus cross-event ids (identical to Rule-Corpus).
- Corpus varyantı: ChronoRank-Rule-Corpus (RULE-INFERRED-CORPUS-WIDE) = src/rerank/rule_inferred.py, results/experiments/chronorank_rule (unchanged).
- İzinli alanlar: evidence_id, cve_id, source_key, cvss_version, observed_from, vector (Base part only), valid_from_censored; src.label içe aktarılmaz. Süre: toplam 8.4 s, yeniden sıralama 1.53 s.

## Ana karşılaştırma (aynı BM25 top-50 havuzu)
| Metrik | BM25 | BM25+Recency | Cross-encoder | ChronoRank-Rule-Corpus | **ChronoRank-Rule-Target** |
|---|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7116 | 0.98 | 0.5442 | 0.9986 | 0.9975 |
| NDCG@10 (ikili) | 0.787 | 0.9852 | 0.6049 | 0.999 | 0.9981 |
| NDCG@10 (dereceli) | 0.7852 | 0.9572 | 0.5568 | 0.999 | 0.994 |
| StaleEvidenceRate@10 | 0.1047 | 0.1047 | 0.0632 | 0.0082 | 0.0001 |
| İlk sıra CURRENT | 0.43 | 0.9601 | 0.4173 | 0.9972 | 0.9949 |
| İlk sıra OUTDATED | 0.5655 | 0.0376 | 0.1233 | 0.0003 | 0.0003 |
| OTHER_SOURCE_CURRENT top-10 | 0.4984 | 0.4936 | 0.1544 | 0.4987 | 0.4987 |
| Ranking failure | 0.0 | 0.0 | 0.2041 | 0.0 | 0.0 |
| OutdatedCount@10 | 1.0466 | 1.0466 | 0.6319 | 0.082 | 0.0006 |
| FirstOutdatedRank (ort.) | 1.4521 | 2.0102 | 13.0783 | 36.7789 | 49.9248 |
| FirstOutdatedRank (medyan) | 1.0 | 2.0 | 6.0 | 41.0 | 50.0 |
| OutdatedSuppression@10 | 0.0 | 0.0 | 0.3983 | 0.9191 | 0.9994 |
| CurrentPreservation@10 | 1.0 | 1.0 | 0.7959 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.0003 | 0.0003 | 0.0925 | 0.9166 | 0.9946 |

## Upper Bounds / Diagnostic Policies
| Metrik | Direct-Link Policy (UB) | Temporal-clean oracle (UB) |
|---|---|---|
| Recall@10 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 |
| MRR@10 | 0.9979 | 1.0 |
| NDCG@10 (ikili) | 0.9984 | 1.0 |
| NDCG@10 (dereceli) | 0.9985 | 1.0 |
| StaleEvidenceRate@10 | 0.0081 | 0.0 |
| İlk sıra CURRENT | 0.9958 | 1.0 |
| İlk sıra OUTDATED | 0.0 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.4987 | 0.4993 |
| Ranking failure | 0.0 | 0.0 |
| OutdatedCount@10 | 0.0811 | 0.0 |
| FirstOutdatedRank (ort.) | 36.8012 | 49.9534 |
| FirstOutdatedRank (medyan) | 41.0 | 50.0 |
| OutdatedSuppression@10 | 0.92 | 1.0 |
| CurrentPreservation@10 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.9157 | 1.0 |

## Split kırılımı (MRR@10 / dereceli NDCG@10 / Stale@10 / CurrentAt1AndNoStaleAt10; ana yorum test)
- BM25: train 0.7031 / 0.7777 / 0.1044 / 0.0006 (n=1719); dev 0.7121 / 0.7881 / 0.1054 / 0.0 (n=312); test 0.7212 / 0.7931 / 0.1048 / 0.0 (n=1506)
- BM25+Recency: train 0.9741 / 0.9545 / 0.1044 / 0.0006 (n=1719); dev 0.9749 / 0.9545 / 0.1054 / 0.0 (n=312); test 0.9877 / 0.9609 / 0.1048 / 0.0 (n=1506)
- Cross-encoder: train 0.5771 / 0.5867 / 0.0633 / 0.1006 (n=1719); dev 0.5505 / 0.5695 / 0.0631 / 0.1122 (n=312); test 0.5053 / 0.5201 / 0.0631 / 0.079 (n=1506)
- ChronoRank-Rule-Corpus: train 0.9985 / 0.999 / 0.0019 / 0.9791 (n=1719); dev 0.9952 / 0.9979 / 0.0019 / 0.9712 (n=312); test 0.9993 / 0.9993 / 0.0167 / 0.834 (n=1506)
- **ChronoRank-Rule-Target**: train 0.9971 / 0.993 / 0.0001 / 0.9936 (n=1719); dev 0.992 / 0.9914 / 0.0 / 0.984 (n=312); test 0.999 / 0.9957 / 0.0 / 0.998 (n=1506)
- Direct-Link Policy (UB): train 0.9983 / 0.9988 / 0.0017 / 0.9796 (n=1719); dev 0.9952 / 0.9979 / 0.0019 / 0.9712 (n=312); test 0.998 / 0.9984 / 0.0167 / 0.8313 (n=1506)
- Temporal-clean oracle (UB): train 1.0 / 1.0 / 0.0 / 1.0 (n=1719); dev 1.0 / 1.0 / 0.0 / 1.0 (n=312); test 1.0 / 1.0 / 0.0 / 1.0 (n=1506)

## Rule-Target kırılımları (CurrentAt1AndNoStaleAt10; n)
- Kaynak grubu: 134c704f-9b21-4f2e-91b3-4a467353bcc0 0.9963 (1091); NVD 0.9928 (695); OTHER_SOURCE 0.9989 (944); audit@patchstack.com 1.0 (131); cna@vuldb.com 0.9323 (133); disclosure@vulncheck.com 1.0 (378); secalert@redhat.com 1.0 (165)
- Kapasite (Rule-Target'a göre korunmuş aday): preserved_ge10 n=3537 Stale 0.0001 joint 0.9946; preserved_lt10 n=0 Stale None joint None

## Tanı (ana)
- Bastırılan aday 3709 (hedef zincir 3709, hedef dışı 0); sorgu başına 1.0486; CURRENT bastırılan 0; OTHER_SOURCE_CURRENT 0; diğer CVE 0; diğer sürüm 0; aynı-vektör witness 0; cross-event witness 0; gelecek witness 0; yeniden-ekleme kaydı 3 (daha sonraki farklı değer nedeniyle); 10'dan az korunmuş adaylı sorgu 0; zorunlu stale 0.

## Future-event (19; tanımlayıcı)
| Metrik | BM25 | BM25+Recency | Cross-encoder | ChronoRank-Rule-Corpus | **ChronoRank-Rule-Target** |
|---|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.6053 | 1.0 | 0.6813 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 0.7061 | 1.0 | 0.7207 | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 0.6988 | 0.9574 | 0.6136 | 1.0 | 0.9908 |
| StaleEvidenceRate@10 | 0.1842 | 0.1842 | 0.1053 | 0.0263 | 0.0 |
| İlk sıra CURRENT | 0.3158 | 1.0 | 0.5789 | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.6842 | 0.0 | 0.1053 | 0.0 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.5789 | 0.5789 | 0.1579 | 0.5789 | 0.5789 |
| Ranking failure | 0.0 | 0.0 | 0.1579 | 0.0 | 0.0 |
| OutdatedCount@10 | 1.8421 | 1.8421 | 1.0526 | 0.2632 | 0.0 |
| FirstOutdatedRank (ort.) | 1.3684 | 2.0 | 13.1579 | 29.7895 | 49.1579 |
| FirstOutdatedRank (medyan) | 1.0 | 2.0 | 4.0 | 28.0 | 49.0 |
| OutdatedSuppression@10 | 0.0 | 0.0 | 0.3947 | 0.8421 | 1.0 |
| CurrentPreservation@10 | 1.0 | 1.0 | 0.8421 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.0 | 0.0 | 0.1053 | 0.8421 | 1.0 |

## Güvenlik kapıları
- no_current_suppressed: True
- no_other_source_current_suppressed: True
- no_other_cve_suppressed: True
- no_other_version_suppressed: True
- no_non_target_suppressed: True
- no_same_vector_witness: True
- no_cross_event_witness: True
- no_future_witness: True
- no_gold_fields_used: True
- no_candidate_change: True
- fifty_candidates_each: True
- recall50_equals_bm25: True
- bm25_order_within_blocks: True
- reproducible: True
- all_queries_present: True
- all_passed: True

## Örnekler
- **target_suppression**: `{"query_id": "q_001279c0020278cb", "evidence_id": "CVE-2021-1675|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 50, "witness": "CVE-2021-1675|3.1|NVD|2"}`; `{"query_id": "q_001ec7d32e535ab4", "evidence_id": "CVE-2023-25911|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 50, "witness": "CVE-2023-25911|3.1|NVD|2"}`; `{"query_id": "q_007aaf9a80964011", "evidence_id": "CVE-2023-6004|3.1|secalert@redhat.com|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 50, "witness": "CVE-2023-6004|3.1|secalert@redhat.com|2"}`; `{"query_id": "q_009b5e016665b086", "evidence_id": "CVE-2024-34129|3.1|psirt@adobe.com|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 50, "witness": "CVE-2024-34129|3.1|psirt@adobe.com|2"}`; `{"query_id": "q_00b9be903f44539a", "evidence_id": "CVE-2024-41174|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 2, "new_rank": 50, "witness": "CVE-2024-41174|3.1|NVD|2"}`
- **non_target_kept**: `{"query_id": "q_001279c0020278cb", "evidence_id": "CVE-2024-3980|3.1|NVD|1", "rank": 2, "bm25_rank": 3}`; `{"query_id": "q_001ec7d32e535ab4", "evidence_id": "CVE-2021-3186|3.1|NVD|1", "rank": 2, "bm25_rank": 3}`; `{"query_id": "q_007aaf9a80964011", "evidence_id": "CVE-2023-6004|3.1|NVD|1", "rank": 3, "bm25_rank": 4}`
- **other_source_current_kept**: `{"query_id": "q_007aaf9a80964011", "evidence_id": "CVE-2023-6004|3.1|NVD|2", "rank": 2, "suppressed": false}`; `{"query_id": "q_009b5e016665b086", "evidence_id": "CVE-2024-34129|3.1|NVD|1", "rank": 2, "suppressed": false}`; `{"query_id": "q_00b9be903f44539a", "evidence_id": "CVE-2024-41174|3.1|info@cert.vde.com|1", "rank": 2, "suppressed": false}`
- **scope_differs**: `{"query_id": "q_001279c0020278cb", "split": "train", "n_preserved_target": 49, "n_preserved_corpus": 23, "joint_target_corpus": [true, true], "stale_target_corpus": [0.0, 0.0], "graded_ndcg_target_corpus": [1.0, 1.0]}`; `{"query_id": "q_001ec7d32e535ab4", "split": "train", "n_preserved_target": 49, "n_preserved_corpus": 15, "joint_target_corpus": [true, true], "stale_target_corpus": [0.0, 0.0], "graded_ndcg_target_corpus": [1.0, 1.0]}`; `{"query_id": "q_007aaf9a80964011", "split": "train", "n_preserved_target": 49, "n_preserved_corpus": 41, "joint_target_corpus": [true, true], "stale_target_corpus": [0.0, 0.0], "graded_ndcg_target_corpus": [1.0, 1.0]}`; `{"query_id": "q_009b5e016665b086", "split": "train", "n_preserved_target": 49, "n_preserved_corpus": 38, "joint_target_corpus": [true, true], "stale_target_corpus": [0.0, 0.0], "graded_ndcg_target_corpus": [1.0, 1.0]}`; `{"query_id": "q_00e0095e94101fe6", "split": "train", "n_preserved_target": 49, "n_preserved_corpus": 12, "joint_target_corpus": [true, true], "stale_target_corpus": [0.0, 0.0], "graded_ndcg_target_corpus": [1.0, 1.0]}`
