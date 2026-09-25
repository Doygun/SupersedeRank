# RULE-INFERRED Bastırılan Aday Denetimi ve Test A/B Ayrıştırması — 2026-09-16

## 1. Bastırılan adaylar (50260 aday gösterimi, 3537 ana sorgu)
| Kategori | Gösterim | Pay | Benzersiz kanıt | Benzersiz CVE | BM25 top-10'dayken bastırılan | Aynı CVE payı | Farklı CVE payı | Sol sansürlü (pay) | Dereceli relevance kütlesi | Top-10'dan kaybedilen relevance |
|---|---|---|---|---|---|---|---|---|---|---|
| TARGET_CHAIN_OUTDATED | 3700 | 0.0736 | 3535 | 3160 | 3700 | 1.0 | 0.0 | 390 (0.1054) | 0 | 0 |
| OTHER_CVE_INFERRED_SUPERSEDED | 45998 | 0.9152 | 1188 | 1084 | 7404 | 0.0 | 1.0 | 42880 (0.9322) | 0 | 0 |
| SAME_CVE_OTHER_SOURCE_INFERRED_SUPERSEDED | 125 | 0.0025 | 115 | 59 | 125 | 1.0 | 0.0 | 25 (0.2) | 0 | 0 |
| SAME_CVE_OTHER_VERSION_INFERRED_SUPERSEDED | 428 | 0.0085 | 318 | 134 | 428 | 1.0 | 0.0 | 24 (0.0561) | 0 | 0 |
| UNLABELED_CHAIN_CONTEXT | 9 | 0.0002 | 9 | 9 | 9 | 1.0 | 0.0 | 0 (0.0) | 0 | 0 |
| OTHER | 0 | 0.0 | 0 | 0 | 0 | None | None | 0 (None) | 0 | 0 |

- Başka CVE'nin kendi zincirinde geçersiz kılınmış kanıtını bastıran sorgu sayısı: 2925 / 3537.
- Top-10'dan kaybedilen toplam dereceli relevance: 0 (CURRENT ve OTHER_SOURCE_CURRENT hiç bastırılmadığından 0 beklenir). Rule top-10'unda korunan relevance kütlesi: 9338.
- Cevap: RULE-INFERRED also moves other CVEs' own-chain superseded evidence (category OTHER_CVE_INFERRED_SUPERSEDED) to the second block; see the category shares. Target CURRENT and OTHER_SOURCE_CURRENT are never suppressed (gates).

## 2. Test kümesi: A (≥10 korunmuş aday) ve B (<10 korunmuş aday)
### A_preserved_ge10: n=1258, korunmuş aday 10–49; kaynaklar {'134c704f-9b21-4f2e-91b3-4a467353bcc0': 477, 'disclosure@vulncheck.com': 321, 'security@wordfence.com': 94, 'secalert@redhat.com': 62, 'NVD': 53, '0b0ca135-0b70-47e7-9f44-1890c2a1c46c': 27}
| Yöntem | Recall@50 | MRR@10 | NDCG@10 | NDCG@10 dereceli | Stale@10 | ilk sıra CURRENT | ilk sıra OUTDATED | OutdatedCount@10 | FirstOutdatedRank | OutdatedSuppression@10 | CurrentPreservation@10 | CurrentAt1AndNoStaleAt10 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| bm25 | 1.0 | 0.7324 | 0.8023 | 0.8015 | 0.1054 | 0.4722 | 0.5238 | 1.0541 | 1.4801 | 0.0 | 1.0 | 0.0 |
| recency_only | 1.0 | 0.2858 | 0.3468 | 0.351 | 0.0405 | 0.2003 | 0.0 | 0.4046 | 21.3839 | 0.6176 | 0.5477 | 0.0151 |
| bm25_recency | 1.0 | 0.9952 | 0.9965 | 0.9653 | 0.1054 | 0.9905 | 0.0079 | 1.0541 | 2.0326 | 0.0 | 1.0 | 0.0 |
| cross_encoder | 1.0 | 0.4231 | 0.4969 | 0.4503 | 0.0591 | 0.2798 | 0.1296 | 0.5906 | 13.7806 | 0.4426 | 0.7305 | 0.0588 |
| rule_inferred | 1.0 | 0.9992 | 0.9994 | 0.9991 | 0.0 | 0.9984 | 0.0 | 0.0 | 40.1669 | 1.0 | 1.0 | 0.9984 |
| rule_direct_upper_bound | 1.0 | 0.9976 | 0.9982 | 0.998 | 0.0 | 0.9952 | 0.0 | 0.0 | 40.1638 | 1.0 | 1.0 | 0.9952 |
| oracle_temporal | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 | 49.9459 | 1.0 | 1.0 | 1.0 |

### B_preserved_lt10: n=248, korunmuş aday 1–9; kaynaklar {'audit@patchstack.com': 126, 'NVD': 122}
| Yöntem | Recall@50 | MRR@10 | NDCG@10 | NDCG@10 dereceli | Stale@10 | ilk sıra CURRENT | ilk sıra OUTDATED | OutdatedCount@10 | FirstOutdatedRank | OutdatedSuppression@10 | CurrentPreservation@10 | CurrentAt1AndNoStaleAt10 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| bm25 | 1.0 | 0.6647 | 0.7524 | 0.7505 | 0.1016 | 0.3306 | 0.6694 | 1.0161 | 1.3306 | 0.0 | 1.0 | 0.0 |
| recency_only | 1.0 | 0.9528 | 0.9643 | 0.9549 | 0.0762 | 0.9274 | 0.0 | 0.7621 | 11.129 | 0.254 | 1.0 | 0.2298 |
| bm25_recency | 1.0 | 0.9496 | 0.9628 | 0.9385 | 0.1016 | 0.8992 | 0.0927 | 1.0161 | 1.9194 | 0.0 | 1.0 | 0.0 |
| cross_encoder | 1.0 | 0.922 | 0.9423 | 0.874 | 0.0835 | 0.8508 | 0.129 | 0.8347 | 6.5806 | 0.1815 | 1.0 | 0.1815 |
| rule_inferred | 1.0 | 1.0 | 1.0 | 1.0 | 0.1016 | 1.0 | 0.0 | 1.0161 | 6.0403 | 0.0 | 1.0 | 0.0 |
| rule_direct_upper_bound | 1.0 | 1.0 | 1.0 | 1.0 | 0.1016 | 1.0 | 0.0 | 1.0161 | 6.0403 | 0.0 | 1.0 | 0.0 |
| oracle_temporal | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 1.0 | 0.0 | 0.0 | 49.9839 | 1.0 | 1.0 | 1.0 |

- Test'te top-10'da kalan OUTDATED: A grubunda 0, B grubunda 252; test geneli CurrentAt1AndNoStaleAt10 0.834.
