# Tam BM25 Koşusu (FULL-CORPUS, ana sorgular) — 2026-09-15

Config `config/retrieval.yaml`: BM25Okapi k1=1.5 b=0.75, alanlar identity+evidence_text, top-50, görünürlük `observed_from <= query_time`, eşit skor kırılımı `SHA256(seed | query_id | evidence_id), ascending` (seed 20260918).
İki oracle aynı top-50 adaylar üzerinde üst sınırdır, model sonucu değildir: **current-first (relevance) oracle** TARGET_CURRENT > OTHER_SOURCE_CURRENT > TARGET_OUTDATED > OTHER sırasıyla MRR/NDCG'yi en üste çıkarır ama OUTDATED kanıtı top-10 içinde tuttuğu için StaleEvidenceRate@10'u düşürmez; **temporal oracle** OUTDATED'ı bütün stale-olmayan adayların arkasına iterek verilen adaylarla ulaşılabilir en düşük StaleEvidenceRate@10'u verir.

Corpus belge sayısı 265.900; sorgu sayısı 3.537; achievable (CURRENT top-50'de) 1.0; sorgu zamanında ortalama görünür belge {'dev': 85586.1. 'test': 206253.8. 'train': 88821.3}.

## Ana sonuçlar
| Metrik | BM25 | Current-first oracle | Temporal oracle |
|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.7116 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 0.787 | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 0.7852 | 1.0 | 1.0 |
| StaleEvidenceRate@10 | 0.1047 | 0.1047 | 0.0 |
| Retrieval failure (CURRENT top-50'de yok) | 0.0 | 0.0 | 0.0 |
| Ranking failure (top-50'de var, top-10'da yok) | 0.0 | 0.0 | 0.0 |
| OUTDATED aynı-zincir top-50'de | 0.9997 | 0.9997 | 0.9997 |
| OUTDATED aynı-zincir top-10'da | 0.9997 | 0.9997 | 0.0 |
| CURRENT ve OUTDATED birlikte top-50'de | 0.9997 | 0.9997 | 0.9997 |
| OTHER_SOURCE_CURRENT top-50'de | 0.4993 | 0.4993 | 0.4993 |
| İlk sıra CURRENT | 0.43 | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.5655 | 0.0 | 0.0 |
| CURRENT–OUTDATED skor eşitliği oranı | 0.8733 | 0.8733 | 0.8733 |

**Split** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- dev: 0.7873 / 0.7121 / 0.1054 / 0.4295; n=312
- test: 0.7941 / 0.7212 / 0.1048 / 0.4489; n=1506
- train: 0.7807 / 0.7031 / 0.1044 / 0.4136; n=1719

**Şablon** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- base_severity: 0.7889 / 0.7142 / 0.1048 / 0.4344; n=877
- base_vector: 0.7837 / 0.7072 / 0.1051 / 0.4228; n=868
- combined: 0.7842 / 0.7079 / 0.105 / 0.4228; n=861
- cvssb_score: 0.7908 / 0.7168 / 0.1039 / 0.4393; n=931

**CVSS sürümü** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- 2.0: 0.7158 / 0.6152 / 0.1015 / 0.2353; n=68
- 3.0: 0.7829 / 0.7059 / 0.1059 / 0.4118; n=17
- 3.1: 0.7884 / 0.7136 / 0.1045 / 0.433; n=3159
- 4.0: 0.788 / 0.7133 / 0.1072 / 0.4437; n=293

**Sansürlü hedef (False/True)** (BM25 NDCG@10 / MRR@10 / Stale@10 / ilk sıra CURRENT; n):
- False: 0.787 / 0.7116 / 0.1047 / 0.43; n=3537

## Future-event kohortu (tanımlayıcı; ana tabloyla birleştirilmez)
| Metrik | BM25 | Current-first oracle | Temporal oracle |
|---|---|---|---|
| Recall@10 | 1.0 | 1.0 | 1.0 |
| Recall@50 | 1.0 | 1.0 | 1.0 |
| MRR@10 | 0.6053 | 1.0 | 1.0 |
| NDCG@10 (ikili) | 0.7061 | 1.0 | 1.0 |
| NDCG@10 (dereceli) | 0.6988 | 1.0 | 1.0 |
| StaleEvidenceRate@10 | 0.1842 | 0.1842 | 0.0 |
| Retrieval failure (CURRENT top-50'de yok) | 0.0 | 0.0 | 0.0 |
| Ranking failure (top-50'de var, top-10'da yok) | 0.0 | 0.0 | 0.0 |
| OUTDATED aynı-zincir top-50'de | 1.0 | 1.0 | 1.0 |
| OUTDATED aynı-zincir top-10'da | 1.0 | 1.0 | 0.0 |
| CURRENT ve OUTDATED birlikte top-50'de | 1.0 | 1.0 | 1.0 |
| OTHER_SOURCE_CURRENT top-50'de | 0.5789 | 0.5789 | 0.5789 |
| İlk sıra CURRENT | 0.3158 | 1.0 | 1.0 |
| İlk sıra OUTDATED | 0.6842 | 0.0 | 0.0 |
| CURRENT–OUTDATED skor eşitliği oranı | 1.0 | 1.0 | 1.0 |
n=19 sorgu / 18 CVE; güven aralıkları geniştir.

## Süre
Corpus yükleme 1.9 s, indeks 3.2 s, arama+etiketleme ana 2684.3 s, future-event 13.4 s.
