# ChronoRank-Learned — Smoke (300 sorgu) — 2026-09-16

## Kurulum
- Logistic Regression (L2, lbfgs, max_iter 1000, class_weight=None; sınıf oranı ~1,04). Eğitim yalnız train target-chain örnekleri (CURRENT pozitif, OUTDATED negatif); ön işleme yalnız train; C yalnız dev üzerinde; birleşim parametresiz blok (target-chain adaylardan p_current < 0,5 ikinci blok; target-chain dışı adaylar dokunulmaz); manifest kilitlendikten sonra 300 sorguluk smoke (100 test sorgusu ilk kez burada açıldı).
- learned_full: C=0.1, politika=block, alpha=None, blok politikası dev'de yetersiz mi: False; özellik sayısı 23
- learned_no_rule_signal: C=0.1, politika=block, alpha=None, blok politikası dev'de yetersiz mi: False; özellik sayısı 22

## Sınıflandırma (yardımcı tanı; ana sonuç yeniden sıralama metrikleridir)
- learned_full: train acc 1.0 / balanced 1.0 / P 1.0 / R 1.0 / F1 1.0 / AUC 1.0 CM [[1795, 0], [0, 1719]]; dev acc 1.0 / AUC 1.0 CM [[329, 0], [0, 312]]; yakınsamama uyarısı 0; dev olasılık histogramı {'0.0-0.1': 327, '0.1-0.2': 0, '0.2-0.3': 0, '0.3-0.4': 2, '0.4-0.5': 0, '0.5-0.6': 0, '0.6-0.7': 0, '0.7-0.8': 0, '0.8-0.9': 0, '0.9-1.0': 312}; NaN 0
- learned_no_rule_signal: train acc 1.0 / balanced 1.0 / P 1.0 / R 1.0 / F1 1.0 / AUC 1.0 CM [[1795, 0], [0, 1719]]; dev acc 1.0 / AUC 1.0 CM [[329, 0], [0, 312]]; yakınsamama uyarısı 0; dev olasılık histogramı {'0.0-0.1': 326, '0.1-0.2': 1, '0.2-0.3': 0, '0.3-0.4': 0, '0.4-0.5': 2, '0.5-0.6': 0, '0.6-0.7': 0, '0.7-0.8': 0, '0.8-0.9': 0, '0.9-1.0': 312}; NaN 0

## Katsayılar (standartlaştırılmış girdiler)
- learned_full (C=0.1, kesme 0.916463): OUTDATED yönünde [['newer_visible_same_chain_count', -2.538884], ['base_vector_differs_from_chain_newest', -1.392254], ['newer_different_base_vector_exists', -1.384946], ['days_to_newest_visible_same_chain', -0.319426], ['observed_age_days', -0.31304]]; CURRENT yönünde [['chain_position_observed', 1.247296], ['cross_encoder_score', 0.169736], ['template_base_severity', 0.082653], ['source_group_134c704f-9b21-4f2e-91b3-4a467353bcc0', 0.071475], ['source_group_NVD', 0.044145]]
- learned_no_rule_signal (C=0.1, kesme 0.116477): OUTDATED yönünde [['newer_visible_same_chain_count', -2.955546], ['base_vector_differs_from_chain_newest', -1.596118], ['days_to_newest_visible_same_chain', -0.362304], ['observed_age_days', -0.355442], ['bm25_rank', -0.154031]]; CURRENT yönünde [['chain_position_observed', 1.327431], ['cross_encoder_score', 0.181368], ['template_base_severity', 0.105815], ['source_group_134c704f-9b21-4f2e-91b3-4a467353bcc0', 0.095833], ['source_group_NVD', 0.068143]]

## Yeniden sıralama (aynı BM25 top-50 havuzu)
| Metrik | BM25 | BM25+Recency | Cross-encoder | Rule-Inferred | **Learned-Full** | Learned-NoRuleSignal |
|---|---|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7044 | 0.9767 | 0.5848 | 1.0 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 0.7818 | 0.9828 | 0.6425 | 1.0 | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 0.7799 | 0.9577 | 0.5909 | 0.9998 | 0.9974 | 0.9974 |
| StaleEvidenceRate@10 | 0.1023 | 0.1023 | 0.0627 | 0.0067 | 0.0 | 0.0 |
| İlk sıra CURRENT | 0.41 | 0.9533 | 0.46 | 1.0 | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.5867 | 0.0433 | 0.1167 | 0.0 | 0.0 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.48 | 0.48 | 0.1667 | 0.48 | 0.48 | 0.48 |
| Ranking failure | 0.0 | 0.0 | 0.1767 | 0.0 | 0.0 | 0.0 |
| OutdatedCount@10 | 1.0233 | 1.0233 | 0.6267 | 0.0667 | 0.0 | 0.0 |
| FirstOutdatedRank (ort.) | 1.4167 | 1.98 | 13.2533 | 36.1433 | 49.9767 | 49.9767 |
| OutdatedSuppression@10 | 0.0 | 0.0 | 0.3917 | 0.9333 | 1.0 | 1.0 |
| CurrentPreservation@10 | 1.0 | 1.0 | 0.8233 | 1.0 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.0 | 0.0 | 0.1067 | 0.9333 | 1.0 | 1.0 |

## Upper Bounds / Diagnostic Policies
| Metrik | Direct-Link Policy (UB) | Temporal-clean oracle (UB) |
|---|---|---|
| Recall@10 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 |
| MRR@10 | 0.9983 | 1.0 |
| NDCG@10 (ikili) | 0.9988 | 1.0 |
| NDCG@10 (dereceli) | 0.9987 | 1.0 |
| StaleEvidenceRate@10 | 0.0067 | 0.0 |
| İlk sıra CURRENT | 0.9967 | 1.0 |
| İlk sıra OUTDATED | 0.0 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.48 | 0.48 |
| Ranking failure | 0.0 | 0.0 |
| OutdatedCount@10 | 0.0667 | 0.0 |
| FirstOutdatedRank (ort.) | 36.1567 | 49.9767 |
| OutdatedSuppression@10 | 0.9333 | 1.0 |
| CurrentPreservation@10 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.93 | 1.0 |

## Kapasite grupları (Rule'a göre korunmuş aday ≥10 / <10; Stale@10, CurrentAt1AndNoStaleAt10, n)
- BM25: preserved_ge10 0.1025 / 0.0 (n=280); preserved_lt10 0.1 / 0.0 (n=20)
- BM25+Recency: preserved_ge10 0.1025 / 0.0 (n=280); preserved_lt10 0.1 / 0.0 (n=20)
- Cross-encoder: preserved_ge10 0.0614 / 0.1 (n=280); preserved_lt10 0.08 / 0.2 (n=20)
- Rule-Inferred: preserved_ge10 0.0 / 1.0 (n=280); preserved_lt10 0.1 / 0.0 (n=20)
- **Learned-Full**: preserved_ge10 0.0 / 1.0 (n=280); preserved_lt10 0.0 / 1.0 (n=20)
- Learned-NoRuleSignal: preserved_ge10 0.0 / 1.0 (n=280); preserved_lt10 0.0 / 1.0 (n=20)
- Direct-Link Policy (UB): preserved_ge10 0.0 / 0.9964 (n=280); preserved_lt10 0.1 / 0.0 (n=20)
- Temporal-clean oracle (UB): preserved_ge10 0.0 / 1.0 (n=280); preserved_lt10 0.0 / 1.0 (n=20)

## Split kırılımı (CurrentAt1AndNoStaleAt10 train / dev / test)
- BM25: 0.0 / 0.0 / 0.0
- BM25+Recency: 0.0 / 0.0 / 0.0
- Cross-encoder: 0.11 / 0.09 / 0.12
- Rule-Inferred: 1.0 / 1.0 / 0.8
- **Learned-Full**: 1.0 / 1.0 / 1.0
- Learned-NoRuleSignal: 1.0 / 1.0 / 1.0
- Direct-Link Policy (UB): 1.0 / 1.0 / 0.79
- Temporal-clean oracle (UB): 1.0 / 1.0 / 1.0

## Rule kopyası kontrolü
- Rule sinyali tek başına doğruluk: ""
- Learned-Full ile Rule-Inferred: aynı tam liste 44/300; target-chain kararları aynı 300/300; farklı listelerde Learned daha iyi 20, eşit 236, daha kötü 0.
- Learned-Full vs NoRuleSignal: {"mrr@10": [1.0, 1.0], "ndcg@10_graded": [0.9974, 0.9974], "stale@10": [0.0, 0.0], "outdated_suppression@10": [1.0, 1.0], "current_preservation@10": [1.0, 1.0], "current_at1_and_no_stale@10": [1.0, 1.0]}

## Negatif kontroller ve kapılar
- {"learned_full_nan_p": 0, "learned_no_rule_signal_nan_p": 0}
- no_candidate_change: True
- recall50_equals_bm25: True
- no_current_suppressed_full: True
- no_current_suppressed_no_rule: True
- no_other_source_current_suppressed: True
- no_non_target_suppressed: True
- no_nan: True
- test_not_used_for_selection: True
- train_only_preprocessing: True
- current_preservation_full_is_1: True
- stale_reduced_vs_bm25_full: True
- all_300_present: True
- all_passed: True

Süre: eğitim+seçim+kilit 7.1 s, toplam 8.4 s.
