# Construct-Validity Denetimi: Recency Avantajı, Offset Hassasiyeti, Pre-replacement Kontrol, Stale Bastırma — 2026-09-15

## 1. Recency avantajının yapısal nedeni (3.537 ana sorgu)
- Sorgu zamanı kuralı: `query_time = replacement_time + min(30 days, 0.5 * remaining CURRENT interval)  (config/queries.yaml)`. Olay → sorgu farkı (gün): min 0.0015, maks 30.0, ortalama 27.9834, medyan 30.0, p25 30.0, p75 30.0; tam 30 gün olanlar %90.0, 30 günden kısa %10.0.
- CURRENT − OUTDATED observed_from farkı (gün): medyan 12.8751, ortalama 104.902, p25 0.9583, p75 93.1251, maks 969.7068. CURRENT gözlenen yaşı medyan 30.0 gün; OUTDATED medyan 40.9998 gün; sol sansürlü OUTDATED 390.
- Hedef zincirde en yeni görünür kanıt CURRENT: %100.0 (istisna 0). CVE'nin bütün zincirleri düşünüldüğünde en yeni kanıt CURRENT: %85.7.
- Seçilen tau=30 ile recency özelliği: CURRENT ortalama 0.4062, OUTDATED 0.2216; CURRENT > OUTDATED oranı 1.0.
- tau=30, sorgu üretimindeki 30 günlük üst sınırla yapısal olarak örtüşür (structurally_aligned = True). the recency bonus is monotone in observed age for every tau, so within a same-chain BM25 tie the newer (CURRENT) evidence wins for any tau; tau only changes the bonus gap against other-CVE candidates and the newest-vs-older margin
- Ayrıştırma (BM25'te CURRENT–OUTDATED eşit skorlu sorgular = 'tied'):
  - tied 3088 sorgu: BM25 ilk sıra CURRENT 1467; BM25+Recency 3080; yalnız zincir-en-yeni eşitlik kırma 3076.
  - untied 449 sorgu: BM25 54; BM25+Recency 316; zincir-en-yeni eşitlik kırma 54.
  - BM25+Recency ile zincir-en-yeni kuralı aynı ilk sırayı verir: 3259 / 3537.
- İlk sıra CURRENT oranı: BM25 0.43, BM25+Recency 0.9601, BM25 + zincir-en-yeni eşitlik kırma 0.8849, Cross-encoder 0.4173, Relevance-only oracle 1.0, Temporal-clean oracle 1.0, Recency-only 0.2997

## 2. Query-time offset hassasiyeti (pool-sabit; bütün ana sorgular; tau=30, lambda=0,5 sabit)
| Offset | Uygun sorgu | Dışlanan | BM25 MRR / Stale / ilk sıra CURRENT | Recency-only MRR / Stale / ilk sıra CURRENT | BM25+Recency MRR / NDCG / Stale / ilk sıra CURRENT / ilk sıra OUTDATED | tau 180 ilk sıra CURRENT | tau 365 ilk sıra CURRENT | zincir en-yeni = CURRENT | OUTDATED−CURRENT yaş farkı (gün) |
|---|---|---|---|---|---|---|---|---|---|
| +1d | 3451 | {'CURRENT_INTERVAL_ENDS_BEFORE_OFFSET': 86} | 0.7088 / 0.1047 / 0.4245 | 0.9002 / 0.0833 / 0.8351 | 0.9943 / 0.9958 / 0.1047 / 0.9887 / 0.011 | 0.971 | 0.9618 | 1.0 | 105.7 |
| +30d | 3286 | {'CURRENT_INTERVAL_ENDS_BEFORE_OFFSET': 145, 'BEYOND_OBSERVATION_WINDOW': 106} | 0.7087 / 0.1044 / 0.4239 | 0.3704 / 0.0429 / 0.2928 | 0.9786 / 0.9842 / 0.1044 / 0.9574 / 0.0402 | 0.968 | 0.961 | 1.0 | 107.96 |
| +90d | 3042 | {'CURRENT_INTERVAL_ENDS_BEFORE_OFFSET': 177, 'BEYOND_OBSERVATION_WINDOW': 318} | 0.7055 / 0.1044 / 0.4175 | 0.3695 / 0.0425 / 0.2926 | 0.9419 / 0.9571 / 0.1044 / 0.8843 / 0.1121 | 0.9523 | 0.9497 | 1.0 | 110.17 |
| +180d | 2362 | {'CURRENT_INTERVAL_ENDS_BEFORE_OFFSET': 300, 'BEYOND_OBSERVATION_WINDOW': 875} | 0.7022 / 0.1048 / 0.4115 | 0.3492 / 0.0409 / 0.2697 | 0.9371 / 0.9535 / 0.1048 / 0.8747 / 0.1207 | 0.9263 | 0.9306 | 1.0 | 77.83 |
| +365d | 1402 | {'CURRENT_INTERVAL_ENDS_BEFORE_OFFSET': 402, 'BEYOND_OBSERVATION_WINDOW': 1733} | 0.6964 / 0.1049 / 0.4001 | 0.3737 / 0.0423 / 0.2782 | 0.9044 / 0.9294 / 0.1049 / 0.8096 / 0.1833 | 0.8409 | 0.8566 | 1.0 | 77.89 |

**Yeniden erişimli smoke (300 örneklem sorgusu, sorgu metni yeni tarihle yeniden üretildi, tam BM25 araması):**

| Offset | n | Orijinal top-50 ile örtüşme | BM25 R@50 / MRR / ilk sıra CURRENT | Recency-only MRR / ilk sıra CURRENT | BM25+Recency MRR / Stale / ilk sıra CURRENT | Pool-sabit BM25+Recency MRR (tüm ana) |
|---|---|---|---|---|---|---|
| +1d | 297 | 0.6481 | 1.0 / 0.6998 / 0.4007 | 0.4454 / 0.3838 | 0.9882 / 0.1024 / 0.9764 | 0.9943 |
| +30d | 288 | 0.9818 | 1.0 / 0.7008 / 0.4028 | 0.3835 / 0.2951 | 0.9757 / 0.1017 / 0.9514 | 0.9786 |
| +90d | 276 | 0.64 | 1.0 / 0.6969 / 0.3949 | 0.3599 / 0.308 | 0.9312 / 0.1018 / 0.8623 | 0.9419 |
| +180d | 228 | 0.5704 | 1.0 / 0.6944 / 0.3904 | 0.3303 / 0.2895 | 0.9232 / 0.1018 / 0.8465 | 0.9371 |
| +365d | 146 | 0.5863 | 1.0 / 0.6701 / 0.3425 | 0.3204 / 0.2877 | 0.8938 / 0.1027 / 0.7877 | 0.9044 |

## 3. PRE_REPLACEMENT_CONTROL denetimi (negatif kontrol; ana tabloya girmez)
- 3536 kontrol sorgusu; görünürlük ihlali 0; gelecekteki (replacing) kanıt havuzda 0; OUTDATED havuzda 154; CURRENT havuzda 3536; sol sansürlü hedef 372. Cross-encoder atlandı (cache yalnız ana çiftleri kapsar).
| Yöntem | Recall@50 | MRR@10 | NDCG@10 | Stale@10 | ilk sıra CURRENT | ranking failure | sansürsüz ilk sıra CURRENT (n) | sansürlü ilk sıra CURRENT (n) |
|---|---|---|---|---|---|---|---|---|
| BM25 | 1.0 | 0.9882 | 0.9912 | 0.0047 | 0.9771 | 0.0 | 0.9744 (3164) | 1.0 (372) |
| Recency-only | 1.0 | 0.3795 | 0.4305 | 0.0026 | 0.2899 | 0.405 | 0.3236 (3164) | 0.0027 (372) |
| BM25+Recency | 1.0 | 0.997 | 0.9978 | 0.0047 | 0.9941 | 0.0 | 0.9943 (3164) | 0.9919 (372) |

## 4. Stale bastırma metrikleri (BM25 top-50 havuzu sabit; docs/metrics_stale_suppression.md)
| Yöntem | OutdatedCount@10 | FirstOutdatedRank ort. / medyan | FirstOutdated > 10 | OutdatedSuppression@10 | CurrentPreservation@10 | CurrentAt1AndNoStaleAt10 |
|---|---|---|---|---|---|---|
| BM25 | 1.0466 | 1.4521 / 1.0 | 0.0003 | 0.0000 (n=3536) | 1.0000 | 0.0003 |
| Recency-only | 0.4385 | 21.0246 / 14.0 | 0.5793 | 0.5840 (n=3536) | 0.6059 | 0.0532 |
| BM25+Recency | 1.0466 | 2.0102 / 2.0 | 0.0003 | 0.0000 (n=3536) | 1.0000 | 0.0003 |
| Cross-encoder | 0.6319 | 13.0783 / 6.0 | 0.3933 | 0.3983 (n=3536) | 0.7959 | 0.0925 |
| Relevance-only oracle | 1.0466 | 2.6542 / 2.0 | 0.0003 | 0.0000 (n=3536) | 1.0000 | 0.0003 |
| Temporal-clean oracle | 0.0 | 49.9534 / 50.0 | 1.0 | 1.0000 (n=3536) | 1.0000 | 1.0 |
| BM25 + zincir-en-yeni eşitlik kırma | 1.0466 | 1.9067 / 2.0 | 0.0003 | 0.0000 (n=3536) | 1.0000 | 0.0003 |

Split kırılımı (CurrentAt1AndNoStaleAt10; train / dev / test): BM25 0.0006 / 0.0 / 0.0; Recency-only 0.0564 / 0.0481 / 0.0505; BM25+Recency 0.0006 / 0.0 / 0.0; Cross-encoder 0.1006 / 0.1122 / 0.079; Relevance-only oracle 0.0006 / 0.0 / 0.0; Temporal-clean oracle 1.0 / 1.0 / 1.0; BM25 + zincir-en-yeni eşitlik kırma 0.0006 / 0.0 / 0.0

