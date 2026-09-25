# ChronoRank-Rule — Tam Koşu (3.537 ana sorgu + 19 future-event) — 2026-09-16

## Yöntem
- RULE-INFERRED (main) — parameter-free block ordering over the BM25 top-50 pool. Sinyal: same chain key (cve_id, source_key, cvss_version); witness visible at query_time; witness observed_from > candidate observed_from; canonical Base vectors differ.
- Witness kapsamı: data/processed/evidence/evidence.jsonl (main Base-query evidence scope membership only; roles/links unused); cross-event kimliği dışlanan 131; witness girişi 9005, zincir 5435.
- İzinli alanlar: evidence_id, cve_id, source_key, cvss_version, observed_from, vector (Base part only), valid_from_censored. Yasaklı alanlar: valid_until, superseded_by_evidence_id, replaced_by_evidence_id, replaces_evidence_id, replacement_type, replacement_event_id, timeline_status, termination_event_id, label, class, relation; src.label içe aktarılmaz.
- RULE-DIRECT = Direct-Link Policy (Upper Bound): replaced_by link visible at query_time; separate module src/rerank/rule_direct.py.
- Süre: zincir indeksi 4.1 s; 3.537 sorgu 2.03 s; future-event 0.01 s. Kural kodu smoke'tan beri değişmedi.

## Ana karşılaştırma (3.537 POST_REPLACEMENT_MAIN; aynı BM25 top-50 havuzu)
| Metrik | BM25 | Recency-only | BM25+Recency | Cross-encoder | **ChronoRank-Rule-Inferred** |
|---|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7116 | 0.3815 | 0.98 | 0.5442 | 0.9986 |
| NDCG@10 (ikili) | 0.787 | 0.4341 | 0.9852 | 0.6049 | 0.999 |
| NDCG@10 (dereceli) | 0.7852 | 0.4392 | 0.9572 | 0.5568 | 0.999 |
| StaleEvidenceRate@10 | 0.1047 | 0.0439 | 0.1047 | 0.0632 | 0.0082 |
| İlk sıra CURRENT | 0.43 | 0.2997 | 0.9601 | 0.4173 | 0.9972 |
| İlk sıra OUTDATED | 0.5655 | 0.0 | 0.0376 | 0.1233 | 0.0003 |
| OTHER_SOURCE_CURRENT top-10 | 0.4984 | 0.2757 | 0.4936 | 0.1544 | 0.4987 |
| Ranking failure | 0.0 | 0.3941 | 0.0 | 0.2041 | 0.0 |
| OutdatedCount@10 | 1.0466 | 0.4385 | 1.0466 | 0.6319 | 0.082 |
| FirstOutdatedRank (ort.) | 1.4521 | 21.0246 | 2.0102 | 13.0783 | 36.7789 |
| FirstOutdatedRank (medyan) | 1.0 | 14.0 | 2.0 | 6.0 | 41.0 |
| OutdatedSuppression@10 | 0.0 | 0.584 | 0.0 | 0.3983 | 0.9191 |
| CurrentPreservation@10 | 1.0 | 0.6059 | 1.0 | 0.7959 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.0003 | 0.0532 | 0.0003 | 0.0925 | 0.9166 |

## Upper Bounds / Diagnostic Policies (model sonucu değildir)
| Metrik | Direct-Link Policy (Upper Bound) | Temporal-clean oracle (Upper Bound) |
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

## Split kırılımı (MRR@10 / Stale@10 / CurrentAt1AndNoStaleAt10; ana bilimsel yorum test kümesine dayanır)
- BM25: train 0.7031 / 0.1044 / 0.0006 (n=1719); dev 0.7121 / 0.1054 / 0.0 (n=312); test 0.7212 / 0.1048 / 0.0 (n=1506)
- Recency-only: train 0.3764 / 0.0425 / 0.0564 (n=1719); dev 0.3404 / 0.0394 / 0.0481 (n=312); test 0.3957 / 0.0463 / 0.0505 (n=1506)
- BM25+Recency: train 0.9741 / 0.1044 / 0.0006 (n=1719); dev 0.9749 / 0.1054 / 0.0 (n=312); test 0.9877 / 0.1048 / 0.0 (n=1506)
- Cross-encoder: train 0.5771 / 0.0633 / 0.1006 (n=1719); dev 0.5505 / 0.0631 / 0.1122 (n=312); test 0.5053 / 0.0631 / 0.079 (n=1506)
- **ChronoRank-Rule-Inferred**: train 0.9985 / 0.0019 / 0.9791 (n=1719); dev 0.9952 / 0.0019 / 0.9712 (n=312); test 0.9993 / 0.0167 / 0.834 (n=1506)
- Direct-Link Policy (Upper Bound): train 0.9983 / 0.0017 / 0.9796 (n=1719); dev 0.9952 / 0.0019 / 0.9712 (n=312); test 0.998 / 0.0167 / 0.8313 (n=1506)
- Temporal-clean oracle (Upper Bound): train 1.0 / 0.0 / 1.0 (n=1719); dev 1.0 / 0.0 / 1.0 (n=312); test 1.0 / 0.0 / 1.0 (n=1506)

## ChronoRank-Rule-Inferred kırılımları
- **Sorgu şablonu** (**ChronoRank-Rule-Inferred** CurrentAt1AndNoStaleAt10; n): base_severity 0.935 (877); base_vector 0.8871 (868); combined 0.8931 (861); cvssb_score 0.9484 (931)
- **CVSS sürümü** (**ChronoRank-Rule-Inferred** CurrentAt1AndNoStaleAt10; n): 2.0 1.0 (68); 3.0 1.0 (17); 3.1 0.9088 (3159); 4.0 0.9761 (293)
- **Kaynak grubu (tanımlayıcı)** (**ChronoRank-Rule-Inferred** CurrentAt1AndNoStaleAt10; n): 134c704f-9b21-4f2e-91b3-4a467353bcc0 0.9973 (1091); NVD 0.7712 (695); OTHER_SOURCE 1.0 (944); audit@patchstack.com 0.0382 (131); cna@vuldb.com 0.9474 (133); disclosure@vulncheck.com 1.0 (378); secalert@redhat.com 1.0 (165)
- **Sol sansürlü hedef**: False n=3537 joint 0.9166; True n=0 joint None
- **≥10 korunmuş aday**: True: n=3253 MRR 0.9985 Stale 0.0001 joint 0.9966; False: n=284 MRR 1.0 Stale 0.1014 joint 0.0

## RULE-INFERRED tanı sayıları (ana)
- Sinyal alan aday 50260 / 176850; sinyal alan sorgu 3537 / 3537; sorgu başına ortalama bastırılan 14.2098.
- Bastırılan sınıflar: OTHER 46560, TARGET_OUTDATED 3700.
- CURRENT bastırılan 0; OTHER_SOURCE_CURRENT bastırılan 0 (aday 2266); aynı-vektörlü witness ile bastırılan 0; yeniden-ekleme kaydı adayı 214, bunlardan daha sonraki farklı değer nedeniyle bastırılan 3; cross-event witness 0; bastırılan cross-event kaydı 53; zincir uyuşmazlığı 0; gelecek witness 0.
- Sol sansürlü aday 80101, bastırılan 43319. RULE-INFERRED ile RULE-DIRECT aynı liste: 3454 / 3537.
- En az 10 korunmuş adayı olan sorgu 3253; 10'dan az olan 284. Top-10'daki toplam OUTDATED 290, bunların 288'i az-korunan-aday sorgularında zorunlu (284 sorgu); ≥10 korunmuş adaylı sorgularda Stale@10 0.0001. Kalan stale'in tamamı yapısal mı: False.

## Future-event kohortu (19 sorgu / 18 CVE; tanımlayıcı; ana tabloyla birleştirilmez)
| Metrik | BM25 | Recency-only | BM25+Recency | Cross-encoder | **ChronoRank-Rule-Inferred** |
|---|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.6053 | 0.4962 | 1.0 | 0.6813 | 1.0 |
| NDCG@10 (ikili) | 0.7061 | 0.5529 | 1.0 | 0.7207 | 1.0 |
| NDCG@10 (dereceli) | 0.6988 | 0.5348 | 0.9574 | 0.6136 | 1.0 |
| StaleEvidenceRate@10 | 0.1842 | 0.0895 | 0.1842 | 0.1053 | 0.0263 |
| İlk sıra CURRENT | 0.3158 | 0.4211 | 1.0 | 0.5789 | 1.0 |
| İlk sıra OUTDATED | 0.6842 | 0.0 | 0.0 | 0.1053 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.5789 | 0.5263 | 0.5789 | 0.1579 | 0.5789 |
| Ranking failure | 0.0 | 0.2632 | 0.0 | 0.1579 | 0.0 |
| OutdatedCount@10 | 1.8421 | 0.8947 | 1.8421 | 1.0526 | 0.2632 |
| FirstOutdatedRank (ort.) | 1.3684 | 14.9474 | 2.0 | 13.1579 | 29.7895 |
| FirstOutdatedRank (medyan) | 1.0 | 9.0 | 2.0 | 4.0 | 28.0 |
| OutdatedSuppression@10 | 0.0 | 0.5263 | 0.0 | 0.3947 | 0.8421 |
| CurrentPreservation@10 | 1.0 | 0.7368 | 1.0 | 0.8421 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.0 | 0.0526 | 0.0 | 0.1053 | 0.8421 |

| Metrik | Direct-Link Policy (Upper Bound) | Temporal-clean oracle (Upper Bound) |
|---|---|---|
| Recall@10 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 |
| MRR@10 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 0.9974 | 1.0 |
| StaleEvidenceRate@10 | 0.0263 | 0.0 |
| İlk sıra CURRENT | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.0 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.5789 | 0.5789 |
| Ranking failure | 0.0 | 0.0 |
| OutdatedCount@10 | 0.2632 | 0.0 |
| FirstOutdatedRank (ort.) | 29.8421 | 49.1579 |
| FirstOutdatedRank (medyan) | 29.0 | 49.0 |
| OutdatedSuppression@10 | 0.8421 | 1.0 |
| CurrentPreservation@10 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.8421 | 1.0 |

## Smoke ile tam koşu tutarlılığı
- `{"smoke_queries_found_in_full": 300, "rule_inferred_mrr_smoke_vs_full_subset": [1.0, 1.0], "rule_inferred_stale_smoke_vs_full_subset": [0.0067, 0.0067], "rule_inferred_joint_smoke_vs_full_subset": [0.9333, 0.9333]}`

## Dinamik denetimler
- forbidden_fields_perturbed_identical: True
- candidate_metadata_shuffled_identical: True
- future_witness_injected_identical: True
- repeat_identical: True

## Güvenlik kapıları
- no_candidate_change: True
- fifty_candidates_each: True
- recall50_equals_bm25: True
- current_preservation_is_1: True
- no_current_suppressed: True
- no_other_source_current_suppressed: True
- no_same_vector_witness: True
- no_cross_event_witness: True
- no_chain_mismatch: True
- no_future_witness: True
- forbidden_fields_and_labels_irrelevant: True
- reproducible: True
- all_queries_present_no_nan: True
- all_passed: True

## Deterministik karar örnekleri (ana)
**correct_suppression** (5):
- `{"query_id": "q_001279c0020278cb", "query_time": "2024-08-28T17:57:23.273000+00:00", "evidence_id": "CVE-2021-1675|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 24, "witness": "CVE-2021-1675|3.1|NVD|2", "vectors": ["AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"]}`
- `{"query_id": "q_001ec7d32e535ab4", "query_time": "2025-02-16T17:55:14.607000+00:00", "evidence_id": "CVE-2023-25911|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 16, "witness": "CVE-2023-25911|3.1|NVD|2", "vectors": ["AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"]}`
- `{"query_id": "q_007aaf9a80964011", "query_time": "2024-01-21T00:15:45.387000+00:00", "evidence_id": "CVE-2023-6004|3.1|secalert@redhat.com|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 42, "witness": "CVE-2023-6004|3.1|secalert@redhat.com|2", "vectors": ["AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", "AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H"]}`
- `{"query_id": "q_009b5e016665b086", "query_time": "2024-09-06T15:15:55.070000+00:00", "evidence_id": "CVE-2024-34129|3.1|psirt@adobe.com|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 39, "witness": "CVE-2024-34129|3.1|psirt@adobe.com|2", "vectors": ["AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N", "AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N"]}`
- `{"query_id": "q_00b9be903f44539a", "query_time": "2025-02-27T17:27:44.087000+00:00", "evidence_id": "CVE-2024-41174|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 2, "new_rank": 50, "witness": "CVE-2024-41174|3.1|NVD|2", "vectors": ["AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", "AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"]}`
**current_kept** (5):
- `{"query_id": "q_001279c0020278cb", "evidence_id": "CVE-2021-1675|3.1|NVD|2", "bm25_rank": 2, "new_rank": 1, "suppressed": false}`
- `{"query_id": "q_001ec7d32e535ab4", "evidence_id": "CVE-2023-25911|3.1|NVD|2", "bm25_rank": 2, "new_rank": 1, "suppressed": false}`
- `{"query_id": "q_007aaf9a80964011", "evidence_id": "CVE-2023-6004|3.1|secalert@redhat.com|2", "bm25_rank": 2, "new_rank": 1, "suppressed": false}`
- `{"query_id": "q_009b5e016665b086", "evidence_id": "CVE-2024-34129|3.1|psirt@adobe.com|2", "bm25_rank": 2, "new_rank": 1, "suppressed": false}`
- `{"query_id": "q_00b9be903f44539a", "evidence_id": "CVE-2024-41174|3.1|NVD|2", "bm25_rank": 1, "new_rank": 1, "suppressed": false}`
**other_source_current_kept** (5):
- `{"query_id": "q_007aaf9a80964011", "evidence_id": "CVE-2023-6004|3.1|NVD|2", "rank": 2, "target_source": "secalert@redhat.com"}`
- `{"query_id": "q_009b5e016665b086", "evidence_id": "CVE-2024-34129|3.1|NVD|1", "rank": 2, "target_source": "psirt@adobe.com"}`
- `{"query_id": "q_00b9be903f44539a", "evidence_id": "CVE-2024-41174|3.1|info@cert.vde.com|1", "rank": 2, "target_source": "NVD"}`
- `{"query_id": "q_00e0095e94101fe6", "evidence_id": "CVE-2024-28999|3.1|psirt@solarwinds.com|1", "rank": 2, "target_source": "NVD"}`
- `{"query_id": "q_00fed49149f27dbd", "evidence_id": "CVE-2023-52817|3.1|NVD|1", "rank": 2, "target_source": "134c704f-9b21-4f2e-91b3-4a467353bcc0"}`
**same_value_readd_kept** (5):
- `{"query_id": "q_03cabb7d564bdd17", "evidence_id": "CVE-2023-24935|3.1|secure@microsoft.com|2", "rank": 8, "class": "OTHER"}`
- `{"query_id": "q_055c62fef3eb184f", "evidence_id": "CVE-2025-0438|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 4, "class": "OTHER"}`
- `{"query_id": "q_055c62fef3eb184f", "evidence_id": "CVE-2024-37392|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 5, "class": "OTHER"}`
- `{"query_id": "q_055c62fef3eb184f", "evidence_id": "CVE-2025-23007|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 9, "class": "OTHER"}`
- `{"query_id": "q_055c62fef3eb184f", "evidence_id": "CVE-2024-42936|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 12, "class": "OTHER"}`
**left_censored** (5):
- `{"query_id": "q_001279c0020278cb", "evidence_id": "CVE-2021-1675|3.1|NVD|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 24}`
- `{"query_id": "q_001ec7d32e535ab4", "evidence_id": "CVE-2023-25911|3.1|NVD|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 16}`
- `{"query_id": "q_0268bb654524efd9", "evidence_id": "CVE-2023-48387|3.1|NVD|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 25}`
- `{"query_id": "q_02ea7c12cc592ef3", "evidence_id": "CVE-2023-49269|3.1|help@fluidattacks.com|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 38}`
- `{"query_id": "q_03f36b8e5e0c8d39", "evidence_id": "CVE-2023-41999|3.1|vulnreport@tenable.com|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 47}`
**inferred_vs_direct_differ** (5):
- `{"query_id": "q_0eb4e7b02018e1bf", "only_inferred": [], "only_direct": ["CVE-2024-9464|4.0|psirt@paloaltonetworks.com|1", "CVE-2024-9465|4.0|psirt@paloaltonetworks.com|1", "CVE-2024-9466|4.0|psirt@paloaltonetworks.com|1", "CVE-2024-9467|4.0|psirt@paloaltonetworks.com|1"]}`
- `{"query_id": "q_1fedfebaec8b84ad", "only_inferred": [], "only_direct": ["CVE-2025-2338|4.0|cna@vuldb.com|1"]}`
- `{"query_id": "q_212467f40bd25540", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
- `{"query_id": "q_256c38602e2e4641", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
- `{"query_id": "q_2cbab62ff059e758", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
**few_preserved_stale_forced** (5):
- `{"query_id": "q_075100cbff311444", "n_preserved": 5, "forced_outdated_ranks": [6], "source_key": "NVD"}`
- `{"query_id": "q_16791850a566c911", "n_preserved": 9, "forced_outdated_ranks": [10], "source_key": "NVD"}`
- `{"query_id": "q_1a422e506756860c", "n_preserved": 6, "forced_outdated_ranks": [7], "source_key": "NVD"}`
- `{"query_id": "q_3f60c05456a9599a", "n_preserved": 9, "forced_outdated_ranks": [10], "source_key": "NVD"}`
- `{"query_id": "q_4084bf783837b953", "n_preserved": 6, "forced_outdated_ranks": [7], "source_key": "NVD"}`
