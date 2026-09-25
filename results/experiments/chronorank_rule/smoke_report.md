# ChronoRank-Rule — Smoke-Test (300 sorgu) — 2026-09-16

## Yöntem
- RULE-INFERRED (main) — parameter-free block ordering over the BM25 top-50 pool. Sinyal: same chain key (cve_id, source_key, cvss_version); witness visible at query_time; witness observed_from > candidate observed_from; canonical Base vectors differ.
- Witness kapsamı: data/processed/evidence/evidence.jsonl (main Base-query evidence scope membership only; roles/links unused); cross-event kimliği dışlanan 131; witness girişi 9005, zincir 5435.
- İzinli alanlar: evidence_id, cve_id, source_key, cvss_version, observed_from, vector (Base part only), valid_from_censored. Yasaklı alanlar: valid_until, superseded_by_evidence_id, replaced_by_evidence_id, replaces_evidence_id, replacement_type, replacement_event_id, timeline_status, termination_event_id, label, class, relation; src.label içe aktarılmaz.
- Süre: zincir indeksi 4.2 s; 300 sorgu yeniden sıralama 0.14 s.

## Ana karşılaştırma (aynı BM25 top-50 havuzu)
| Metrik | BM25 | BM25+Recency | Cross-encoder | **RULE-INFERRED (ana)** |
|---|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7044 | 0.9767 | 0.5848 | 1.0 |
| NDCG@10 (ikili) | 0.7818 | 0.9828 | 0.6425 | 1.0 |
| NDCG@10 (dereceli) | 0.7799 | 0.9577 | 0.5909 | 0.9998 |
| StaleEvidenceRate@10 | 0.1023 | 0.1023 | 0.0627 | 0.0067 |
| İlk sıra CURRENT | 0.41 | 0.9533 | 0.46 | 1.0 |
| İlk sıra OUTDATED | 0.5867 | 0.0433 | 0.1167 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.48 | 0.48 | 0.1667 | 0.48 |
| OutdatedCount@10 | 1.0233 | 1.0233 | 0.6267 | 0.0667 |
| FirstOutdatedRank (ort.) | 1.4167 | 1.98 | 13.2533 | 36.1433 |
| FirstOutdatedRank (medyan) | 1.0 | 2.0 | 6.0 | 39.0 |
| OutdatedSuppression@10 | 0.0 | 0.0 | 0.3917 | 0.9333 |
| CurrentPreservation@10 | 1.0 | 1.0 | 0.8233 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.0 | 0.0 | 0.1067 | 0.9333 |

## Üst sınırlar (model sonucu değildir; ayrı statü)
| Metrik | RULE-DIRECT — Direct-Link Policy (Upper Bound) | Temporal-clean oracle (Upper Bound) |
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
| OutdatedCount@10 | 0.0667 | 0.0 |
| FirstOutdatedRank (ort.) | 36.1567 | 49.9767 |
| FirstOutdatedRank (medyan) | 39.0 | 50.0 |
| OutdatedSuppression@10 | 0.9333 | 1.0 |
| CurrentPreservation@10 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.93 | 1.0 |

## RULE-INFERRED tanı sayıları
- Sinyal alan aday 4458 / 15000; sinyal alan sorgu 300 / 300; sorgu başına ortalama bastırılan 14.86.
- Bastırılan sınıflar: OTHER 4151, TARGET_OUTDATED 307.
- CURRENT bastırılan 0; OTHER_SOURCE_CURRENT bastırılan 0 (aday 181); aynı-vektörlü witness ile bastırılan 0; yeniden-ekleme kaydı adayı 7, bunlardan daha sonraki farklı değer nedeniyle bastırılan 0; cross-event witness ile bastırılan 0; bastırılan cross-event kaydı 6; zincir uyuşmazlığıyla bastırılan 0; gelecekteki witness ile bastırılan 0.
- Sol sansürlü aday 7225, bunlardan bastırılan 3888. RULE-INFERRED ile RULE-DIRECT aynı listeyi verdi: 293 / 300.

## Split kırılımı (CurrentAt1AndNoStaleAt10 / Stale@10 / MRR@10)
- BM25: train 0.0 / 0.103 / 0.6533; dev 0.0 / 0.103 / 0.72; test 0.0 / 0.101 / 0.74
- BM25+Recency: train 0.0 / 0.103 / 0.96; dev 0.0 / 0.103 / 0.98; test 0.0 / 0.101 / 0.99
- Cross-encoder: train 0.11 / 0.061 / 0.5823; dev 0.09 / 0.065 / 0.5888; test 0.12 / 0.062 / 0.5834
- **RULE-INFERRED (ana)**: train 1.0 / 0.0 / 1.0; dev 1.0 / 0.0 / 1.0; test 0.8 / 0.02 / 1.0
- RULE-DIRECT — Direct-Link Policy (Upper Bound): train 1.0 / 0.0 / 1.0; dev 1.0 / 0.0 / 1.0; test 0.79 / 0.02 / 0.995
- Temporal-clean oracle (Upper Bound): train 1.0 / 0.0 / 1.0; dev 1.0 / 0.0 / 1.0; test 1.0 / 0.0 / 1.0

## Dinamik denetimler
- forbidden_fields_perturbed_identical: True
- candidate_metadata_shuffled_identical: True
- future_witness_injected_identical: True
- repeat_identical: True

## Başarı kapıları
- no_candidate_change: True
- fifty_candidates_each: True
- recall50_equals_bm25: True
- current_preservation_is_1: True
- no_current_suppressed: True
- no_other_source_current_suppressed: True
- no_same_vector_witness: True
- no_cross_event_witness: True
- no_future_witness: True
- forbidden_fields_and_labels_irrelevant: True
- reproducible: True
- all_queries_present_no_nan: True
- all_passed: True

## Deterministik karar örnekleri
**correct_suppression** (5):
- `{"query_id": "q_049541cc90acb72b", "query_time": "2024-06-15T16:15:11.130000+00:00", "evidence_id": "CVE-2024-4966|3.1|cna@vuldb.com|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 45, "witness": "CVE-2024-4966|3.1|cna@vuldb.com|2", "vectors": ["AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"]}`
- `{"query_id": "q_056d7de77d61343f", "query_time": "2024-09-25T14:35:04.427000+00:00", "evidence_id": "CVE-2024-29338|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|1", "class": "TARGET_OUTDATED", "bm25_rank": 2, "new_rank": 50, "witness": "CVE-2024-29338|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "vectors": ["AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N"]}`
- `{"query_id": "q_061f78c45f96ed10", "query_time": "2024-12-05T15:47:04.997000+00:00", "evidence_id": "CVE-2024-37847|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 23, "witness": "CVE-2024-37847|3.1|NVD|2", "vectors": ["AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"]}`
- `{"query_id": "q_06a4ed5abbd5a406", "query_time": "2025-06-18T19:15:46.530000+00:00", "evidence_id": "CVE-2023-5007|3.1|help@fluidattacks.com|1", "class": "TARGET_OUTDATED", "bm25_rank": 1, "new_rank": 37, "witness": "CVE-2023-5007|3.1|help@fluidattacks.com|2", "vectors": ["AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"]}`
- `{"query_id": "q_09fb009a0507a25d", "query_time": "2025-06-11T16:40:28.490000+00:00", "evidence_id": "CVE-2025-30290|3.1|NVD|1", "class": "TARGET_OUTDATED", "bm25_rank": 2, "new_rank": 11, "witness": "CVE-2025-30290|3.1|NVD|2", "vectors": ["AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H"]}`
**other_source_current_kept** (5):
- `{"query_id": "q_049541cc90acb72b", "evidence_id": "CVE-2024-4966|2.0|cna@vuldb.com|2", "rank": 2, "target_source": "cna@vuldb.com"}`
- `{"query_id": "q_061f78c45f96ed10", "evidence_id": "CVE-2024-37847|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|1", "rank": 2, "target_source": "NVD"}`
- `{"query_id": "q_09fb009a0507a25d", "evidence_id": "CVE-2025-30290|3.1|psirt@adobe.com|1", "rank": 2, "target_source": "NVD"}`
- `{"query_id": "q_0b735b304937b300", "evidence_id": "CVE-2025-24446|3.1|psirt@adobe.com|1", "rank": 2, "target_source": "NVD"}`
- `{"query_id": "q_0c96fcb5039ddd54", "evidence_id": "CVE-2025-2748|3.1|NVD|1", "rank": 2, "target_source": "disclosure@vulncheck.com"}`
**same_value_readd_kept** (5):
- `{"query_id": "q_24a142f42cd61522", "evidence_id": "CVE-2024-23920|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 4, "class": "OTHER"}`
- `{"query_id": "q_24a142f42cd61522", "evidence_id": "CVE-2024-54475|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 11, "class": "OTHER"}`
- `{"query_id": "q_24a142f42cd61522", "evidence_id": "CVE-2024-46972|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 24, "class": "OTHER"}`
- `{"query_id": "q_24a142f42cd61522", "evidence_id": "CVE-2024-49742|3.1|134c704f-9b21-4f2e-91b3-4a467353bcc0|2", "rank": 29, "class": "OTHER"}`
- `{"query_id": "q_01acde264d96b2cf", "evidence_id": "CVE-2024-35138|3.1|psirt@us.ibm.com|2", "rank": 23, "class": "OTHER"}`
**left_censored** (5):
- `{"query_id": "q_06a4ed5abbd5a406", "evidence_id": "CVE-2023-5007|3.1|help@fluidattacks.com|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 37}`
- `{"query_id": "q_0bc04a6ae8f3e7c2", "evidence_id": "CVE-2023-37307|3.1|NVD|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 35}`
- `{"query_id": "q_0e8659e768acfc5c", "evidence_id": "CVE-2023-6238|3.1|secalert@redhat.com|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 33}`
- `{"query_id": "q_36de39f8416459fa", "evidence_id": "CVE-2023-36390|3.1|NVD|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 13}`
- `{"query_id": "q_3ab3100bbf83554b", "evidence_id": "CVE-2021-41037|3.1|emo@eclipse.org|1", "class": "TARGET_OUTDATED", "suppressed": true, "rank": 41}`
**inferred_vs_direct_differ** (5):
- `{"query_id": "q_bde9639d37543e34", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
- `{"query_id": "q_bee6929b299ec397", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
- `{"query_id": "q_20ea93af7433cd81", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
- `{"query_id": "q_4a251ea50d9ba174", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
- `{"query_id": "q_6521cfac83799a43", "only_inferred": ["CVE-2023-22644|3.1|meissner@suse.de|1"], "only_direct": []}`
