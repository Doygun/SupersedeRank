# Test Kümesi İstatistiksel Analizi — CVE-düzeyi cluster bootstrap (10000 tekrar, seed 20260924, percentile %95 GA) — 2026-09-16

Popülasyon: 1506 test sorgusu / 1356 CVE (eğitimde görülmemiş). Aynı CVE çekilişleri bütün yöntemler ve farklar için ortak. Tanımsız metrikler (outdated_suppression@10 / current_preservation@10 are undefined for queries whose BM25 top-10 has no OUTDATED / CURRENT; such queries are excluded from that metric's mean and from its paired difference).

## Yöntem başına %95 güven aralıkları (test)
| Yöntem | mrr@10 | ndcg@10 | ndcg@10_graded | stale@10 | outdated_suppression@10 | current_preservation@10 | current_at1_and_no_stale@10 |
|---|---|---|---|---|---|---|---|
| BM25 | 0.7212 [0.7087, 0.7341] | 0.7941 [0.7848, 0.8036] | 0.7931 [0.7851, 0.8013] | 0.1048 [0.1036, 0.106] | 0.0 [0.0, 0.0] | 1.0 [1.0, 1.0] | 0.0 [0.0, 0.0] |
| BM25+Recency | 0.9877 [0.9837, 0.9914] | 0.9909 [0.9879, 0.9937] | 0.9609 [0.9575, 0.964] | 0.1048 [0.1036, 0.106] | 0.0 [0.0, 0.0] | 1.0 [1.0, 1.0] | 0.0 [0.0, 0.0] |
| Cross-encoder | 0.5053 [0.4831, 0.5267] | 0.5702 [0.5494, 0.5904] | 0.5201 [0.5004, 0.5387] | 0.0631 [0.0602, 0.0659] | 0.3996 [0.3741, 0.4254] | 0.7749 [0.7528, 0.7962] | 0.079 [0.0652, 0.0929] |
| ChronoRank-Rule-Target | 0.999 [0.9977, 1.0] | 0.9993 [0.9983, 1.0] | 0.9957 [0.9945, 0.9968] | 0.0 [0.0, 0.0] | 1.0 [1.0, 1.0] | 1.0 [1.0, 1.0] | 0.998 [0.9954, 1.0] |
| ChronoRank-Rule-Corpus | 0.9993 [0.9983, 1.0] | 0.9995 [0.9988, 1.0] | 0.9993 [0.9986, 0.9998] | 0.0167 [0.0148, 0.0187] | 0.8353 [0.8163, 0.8544] | 1.0 [1.0, 1.0] | 0.834 [0.8147, 0.853] |
| Direct-Link Policy (upper bound) | 0.998 [0.9963, 0.9993] | 0.9985 [0.9973, 0.9995] | 0.9984 [0.9972, 0.9993] | 0.0167 [0.0148, 0.0187] | 0.8353 [0.8163, 0.8544] | 1.0 [1.0, 1.0] | 0.8313 [0.8122, 0.8506] |
| Temporal-clean oracle (upper bound) | 1.0 [1.0, 1.0] | 1.0 [1.0, 1.0] | 1.0 [1.0, 1.0] | 0.0 [0.0, 0.0] | 1.0 [1.0, 1.0] | 1.0 [1.0, 1.0] | 1.0 [1.0, 1.0] |

## Eşleştirilmiş farklar: ChronoRank-Rule-Target − diğer (test; birincil aile Holm ile düzeltildi: 4 comparisons x 3 primary metrics = 12 tests; Holm step-down at alpha 0.05 applied within this family)
| Karşılaştırma | Metrik | Aile | Fark | %95 GA | P(fark>0) | p (iki taraflı) | Holm p | Ret? | Kazanan / kaybeden / eşit |
|---|---|---|---|---|---|---|---|---|---|
| vs BM25 | mrr@10 | secondary | 0.2778 | [0.265, 0.2903] | 1.0 | <0.0001 | – | – | 829 / 0 / 677 |
| vs BM25 | ndcg@10 | secondary | 0.2052 | [0.1958, 0.2144] | 1.0 | <0.0001 | – | – | 829 / 0 / 677 |
| vs BM25 | ndcg@10_graded | primary | 0.2025 | [0.1943, 0.2105] | 1.0 | <0.0001 | 0.0012000000000000001 | True | 1181 / 0 / 325 |
| vs BM25 | stale@10 | primary | -0.1048 | [-0.106, -0.1036] | 0.0 | <0.0001 | 0.0012000000000000001 | True | 1506 / 0 / 0 |
| vs BM25 | outdated_suppression@10 | secondary | 1.0 | [1.0, 1.0] | 1.0 | <0.0001 | – | – | 1506 / 0 / 0 |
| vs BM25 | current_preservation@10 | secondary | 0.0 | [0.0, 0.0] | 0.0 | 1.0 | – | – | 0 / 0 / 1506 |
| vs BM25 | current_at1_and_no_stale@10 | primary | 0.998 | [0.9954, 1.0] | 1.0 | <0.0001 | 0.0012000000000000001 | True | 1503 / 0 / 3 |
| vs BM25+Recency | mrr@10 | secondary | 0.0113 | [0.0075, 0.0154] | 1.0 | <0.0001 | – | – | 36 / 2 / 1468 |
| vs BM25+Recency | ndcg@10 | secondary | 0.0083 | [0.0056, 0.0114] | 1.0 | <0.0001 | – | – | 36 / 2 / 1468 |
| vs BM25+Recency | ndcg@10_graded | primary | 0.0348 | [0.0317, 0.0381] | 1.0 | <0.0001 | 0.0012000000000000001 | True | 728 / 20 / 758 |
| vs BM25+Recency | stale@10 | primary | -0.1048 | [-0.106, -0.1036] | 0.0 | <0.0001 | 0.0012000000000000001 | True | 1506 / 0 / 0 |
| vs BM25+Recency | outdated_suppression@10 | secondary | 1.0 | [1.0, 1.0] | 1.0 | <0.0001 | – | – | 1506 / 0 / 0 |
| vs BM25+Recency | current_preservation@10 | secondary | 0.0 | [0.0, 0.0] | 0.0 | 1.0 | – | – | 0 / 0 / 1506 |
| vs BM25+Recency | current_at1_and_no_stale@10 | primary | 0.998 | [0.9954, 1.0] | 1.0 | <0.0001 | 0.0012000000000000001 | True | 1503 / 0 / 3 |
| vs Cross-encoder | mrr@10 | secondary | 0.4937 | [0.4724, 0.5159] | 1.0 | <0.0001 | – | – | 942 / 1 / 563 |
| vs Cross-encoder | ndcg@10 | secondary | 0.429 | [0.4089, 0.4498] | 1.0 | <0.0001 | – | – | 942 / 1 / 563 |
| vs Cross-encoder | ndcg@10_graded | primary | 0.4756 | [0.457, 0.495] | 1.0 | <0.0001 | 0.0012000000000000001 | True | 1200 / 3 / 303 |
| vs Cross-encoder | stale@10 | primary | -0.0631 | [-0.0659, -0.0602] | 0.0 | <0.0001 | 0.0012000000000000001 | True | 910 / 0 / 596 |
| vs Cross-encoder | outdated_suppression@10 | secondary | 0.6004 | [0.5746, 0.6259] | 1.0 | <0.0001 | – | – | 910 / 0 / 596 |
| vs Cross-encoder | current_preservation@10 | secondary | 0.2251 | [0.2038, 0.2472] | 1.0 | <0.0001 | – | – | 339 / 0 / 1167 |
| vs Cross-encoder | current_at1_and_no_stale@10 | primary | 0.919 | [0.9049, 0.9331] | 1.0 | <0.0001 | 0.0012000000000000001 | True | 1384 / 0 / 122 |
| vs ChronoRank-Rule-Corpus | mrr@10 | secondary | -0.0003 | [-0.001, 0.0] | 0.0 | 0.729 | – | – | 0 / 1 / 1505 |
| vs ChronoRank-Rule-Corpus | ndcg@10 | secondary | -0.0002 | [-0.0007, 0.0] | 0.0 | 0.729 | – | – | 0 / 1 / 1505 |
| vs ChronoRank-Rule-Corpus | ndcg@10_graded | primary | -0.0036 | [-0.0046, -0.0026] | 0.0 | <0.0001 | 0.0012000000000000001 | True | 0 / 106 / 1400 |
| vs ChronoRank-Rule-Corpus | stale@10 | primary | -0.0167 | [-0.0187, -0.0148] | 0.0 | <0.0001 | 0.0012000000000000001 | True | 248 / 0 / 1258 |
| vs ChronoRank-Rule-Corpus | outdated_suppression@10 | secondary | 0.1647 | [0.1456, 0.1837] | 1.0 | <0.0001 | – | – | 248 / 0 / 1258 |
| vs ChronoRank-Rule-Corpus | current_preservation@10 | secondary | 0.0 | [0.0, 0.0] | 0.0 | 1.0 | – | – | 0 / 0 / 1506 |
| vs ChronoRank-Rule-Corpus | current_at1_and_no_stale@10 | primary | 0.164 | [0.145, 0.1831] | 1.0 | <0.0001 | 0.0012000000000000001 | True | 248 / 1 / 1257 |

## Kapasite analizi (Rule-Corpus'a göre korunmuş aday ≥10 / <10)
- **test / preserved_ge10** (n=1258, CVE 1121): BM25 MRR 0.7324 Stale 0.1054 joint 0.0 Supp 0.0; BM25+Recency MRR 0.9952 Stale 0.1054 joint 0.0 Supp 0.0; Cross-encoder MRR 0.4231 Stale 0.0591 joint 0.0588 Supp 0.4426; ChronoRank-Rule-Target MRR 0.9988 Stale 0.0 joint 0.9976 Supp 1.0; ChronoRank-Rule-Corpus MRR 0.9992 Stale 0.0 joint 0.9984 Supp 1.0; Direct-Link Policy (upper bound) MRR 0.9976 Stale 0.0 joint 0.9952 Supp 1.0; Temporal-clean oracle (upper bound) MRR 1.0 Stale 0.0 joint 1.0 Supp 1.0
- **test / preserved_lt10** (n=248, CVE 245): BM25 MRR 0.6647 Stale 0.1016 joint 0.0 Supp 0.0; BM25+Recency MRR 0.9496 Stale 0.1016 joint 0.0 Supp 0.0; Cross-encoder MRR 0.922 Stale 0.0835 joint 0.1815 Supp 0.1815; ChronoRank-Rule-Target MRR 1.0 Stale 0.0 joint 1.0 Supp 1.0; ChronoRank-Rule-Corpus MRR 1.0 Stale 0.1016 joint 0.0 Supp 0.0; Direct-Link Policy (upper bound) MRR 1.0 Stale 0.1016 joint 0.0 Supp 0.0; Temporal-clean oracle (upper bound) MRR 1.0 Stale 0.0 joint 1.0 Supp 1.0
- **all_main / preserved_ge10** (n=3253, CVE 2899): BM25 MRR 0.7156 Stale 0.1049 joint 0.0003 Supp 0.0; BM25+Recency MRR 0.9831 Stale 0.1049 joint 0.0003 Supp 0.0; Cross-encoder MRR 0.5114 Stale 0.0613 joint 0.0861 Supp 0.4187; ChronoRank-Rule-Target MRR 0.9974 Stale 0.0001 joint 0.9945 Supp 0.9994; ChronoRank-Rule-Corpus MRR 0.9985 Stale 0.0001 joint 0.9966 Supp 0.9994; Direct-Link Policy (upper bound) MRR 0.9977 Stale 0.0 joint 0.9954 Supp 1.0; Temporal-clean oracle (upper bound) MRR 1.0 Stale 0.0 joint 1.0 Supp 1.0
- **all_main / preserved_lt10** (n=284, CVE 281): BM25 MRR 0.6661 Stale 0.1014 joint 0.0 Supp 0.0; BM25+Recency MRR 0.9437 Stale 0.1014 joint 0.0 Supp 0.0; Cross-encoder MRR 0.9196 Stale 0.0849 joint 0.1655 Supp 0.1655; ChronoRank-Rule-Target MRR 0.9982 Stale 0.0 joint 0.9965 Supp 1.0; ChronoRank-Rule-Corpus MRR 1.0 Stale 0.1014 joint 0.0 Supp 0.0; Direct-Link Policy (upper bound) MRR 1.0 Stale 0.1011 joint 0.0035 Supp 0.0035; Temporal-clean oracle (upper bound) MRR 1.0 Stale 0.0 joint 1.0 Supp 1.0
