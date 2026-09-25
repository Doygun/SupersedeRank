# BM25 Smoke-Test (FULL-CORPUS, 300 sorgu) — 2026-09-15

Config `config/retrieval.yaml`: BM25Okapi k1=1.5 b=0.75, alanlar identity+evidence_text, top-50, görünürlük `observed_from <= query_time`, eşit skor kırılımı `SHA256(seed | query_id | evidence_id), ascending` (seed 20260918).
İki oracle aynı top-50 adaylar üzerinde üst sınırdır, model sonucu değildir: **current-first (relevance) oracle** TARGET_CURRENT > OTHER_SOURCE_CURRENT > TARGET_OUTDATED > OTHER sırasıyla MRR/NDCG'yi en üste çıkarır ama OUTDATED kanıtı top-10 içinde tuttuğu için StaleEvidenceRate@10'u düşürmez; **temporal oracle** OUTDATED'ı bütün stale-olmayan adayların arkasına iterek verilen adaylarla ulaşılabilir en düşük StaleEvidenceRate@10'u verir.

Corpus belge sayısı 265.900; sorgu sayısı 300; achievable (CURRENT top-50'de) 1.0; sorgu zamanında ortalama görünür belge {'dev': 83604.9. 'test': 206765.9. 'train': 89119.1}.

## Ana sonuçlar
| Metrik | BM25 | Current-first oracle | Temporal oracle |
|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7044 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 0.7818 | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 0.7799 | 1.0 | 1.0 |
| StaleEvidenceRate@10 | 0.1023 | 0.1023 | 0.0 |
| Retrieval failure (CURRENT top-50'de yok) | 0.0 | 0.0 | 0.0 |
| Ranking failure (top-50'de var, top-10'da yok) | 0.0 | 0.0 | 0.0 |
| OUTDATED aynı-zincir top-50'de | 1.0 | 1.0 | 1.0 |
| OUTDATED aynı-zincir top-10'da | 1.0 | 1.0 | 0.0 |
| CURRENT ve OUTDATED birlikte top-50'de | 1.0 | 1.0 | 1.0 |
| OTHER_SOURCE_CURRENT top-50'de | 0.48 | 0.48 | 0.48 |
| İlk sıra CURRENT | 0.41 | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.5867 | 0.0 | 0.0 |
| CURRENT–OUTDATED skor eşitliği oranı | 0.8533 | 0.8533 | 0.8533 |

**Split** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- dev: 0.7933 / 0.72 / 0.103 / 0.44; n=100
- test: 0.8081 / 0.74 / 0.101 / 0.48; n=100
- train: 0.744 / 0.6533 / 0.103 / 0.31; n=100

**Şablon** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- base_severity: 0.7733 / 0.6929 / 0.1029 / 0.3857; n=70
- base_vector: 0.7832 / 0.7063 / 0.1 / 0.4125; n=80
- combined: 0.7776 / 0.6987 / 0.1038 / 0.3974; n=78
- cvssb_score: 0.7931 / 0.7199 / 0.1028 / 0.4444; n=72

**CVSS sürümü** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- 2.0: 0.6309 / 0.5 / 0.1 / 0.0; n=8
- 3.0: 0.754 / 0.6667 / 0.1 / 0.3333; n=3
- 3.1: 0.783 / 0.706 / 0.1026 / 0.4133; n=271
- 4.0: 0.836 / 0.7778 / 0.1 / 0.5556; n=18

**Sansürlü hedef (False/True)** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- False: 0.7818 / 0.7044 / 0.1023 / 0.41; n=300

## Süre
Corpus yükleme 1.7 s, indeks 4.9 s, arama+etiketleme 244.5 s.
