# ChronoRank-Rule — Tam Koşu (3.537 ana sorgu + 19 future-event) — 2026-09-16

## Yöntem
- RULE-INFERRED (main) — parameter-free block ordering over the BM25 top-50 pool. Sinyal: same chain key (cve_id, source_key, cvss_version); witness visible at query_time; witness observed_from > candidate observed_from; canonical Base vectors differ.
- Witness kapsamı: data/processed/evidence/evidence.jsonl (main Base-query evidence scope membership only; roles/links unused); cross-event kimliği dışlanan 131; witness girişi 9005, zincir 5435.
- İzinli alanlar: evidence_id, cve_id, source_key, cvss_version, observed_from, vector (Base part only), valid_from_censored. Yasaklı alanlar: valid_until, superseded_by_evidence_id, replaced_by_evidence_id, replaces_evidence_id, replacement_type, replacement_event_id, timeline_status, termination_event_id, label, class, relation; src.label içe aktarılmaz.
- RULE-DIRECT = Direct-Link Policy (Upper Bound): replaced_by link visible at query_time; separate module src/rerank/rule_direct.py.

## Tam sonuç (ChronoRank-Rule-Inferred; BM25 referans; Direct-Link üst sınır)
| Metrik | BM25 | **ChronoRank-Rule-Inferred** | Direct-Link Policy (Upper Bound) |
|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7116 | 0.9986 | 0.9979 |
| NDCG@10 (ikili) | 0.787 | 0.999 | 0.9984 |
| NDCG@10 (dereceli) | 0.7852 | 0.999 | 0.9985 |
| StaleEvidenceRate@10 | 0.1047 | 0.0082 | 0.0081 |
| İlk sıra CURRENT | 0.43 | 0.9972 | 0.9958 |
| İlk sıra OUTDATED | 0.5655 | 0.0003 | 0.0 |
| OTHER_SOURCE_CURRENT top-10 | 0.4984 | 0.4987 | 0.4987 |
| Ranking failure | 0.0 | 0.0 | 0.0 |
| OutdatedCount@10 | 1.0466 | 0.082 | 0.0811 |
| FirstOutdatedRank (ort.) | 1.4521 | 36.7789 | 36.8012 |
| FirstOutdatedRank (medyan) | 1.0 | 41.0 | 41.0 |
| OutdatedSuppression@10 | 0.0 | 0.9191 | 0.92 |
| CurrentPreservation@10 | 1.0 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.0003 | 0.9166 | 0.9157 |

## Tanı
- Sinyal alan aday 50260 / 176850; sinyal alan sorgu 3537 / 3537; sorgu başına ortalama bastırılan 14.2098.
- Bastırılan sınıflar: OTHER 46560, TARGET_OUTDATED 3700.
- CURRENT bastırılan 0; OTHER_SOURCE_CURRENT bastırılan 0 (aday 2266); aynı-vektörlü witness ile bastırılan 0; yeniden-ekleme kaydı adayı 214, bunlardan daha sonraki farklı değer nedeniyle bastırılan 3; cross-event witness 0; bastırılan cross-event kaydı 53; zincir uyuşmazlığı 0; gelecek witness 0.
- Sol sansürlü aday 80101, bastırılan 43319. RULE-INFERRED ile RULE-DIRECT aynı liste: 3454 / 3537.
- En az 10 korunmuş adayı olan sorgu 3253; 10'dan az olan 284. Top-10'daki toplam OUTDATED 290, bunların 288'i az-korunan-aday sorgularında zorunlu (284 sorgu); ≥10 korunmuş adaylı sorgularda Stale@10 0.0001. Kalan stale'in tamamı yapısal mı: False.

## Kapılar
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
