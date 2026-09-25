# Dense + Hybrid Smoke-Test (FULL-CORPUS, 300 sorgu) — 2026-09-15

## Sabit ayarlar (deney öncesi, `config/retrieval.yaml`)
- Model `BAAI/bge-base-en-v1.5`, revision `a5beb1e3e68b9ab74eb54cfd186867f64f240e1a`; `model.safetensors` sha256 `c7c1988aae201f80cf91a5dbbd5866409503b89dcaba877ca6dba7dd0a5167d7`
- Kütüphaneler: torch 2.14.0+cu126 (CUDA 12.6), transformers 5.17.0; cihaz cuda (NVIDIA GeForce RTX 3070 Ti, 8.0 GB)
- Sorgu öneki `Represent this sentence for searching relevant passages: `; belge öneki yok. Pooling mean (attention mask), l2 normalizasyon, benzerlik inner_product
- Embedding boyutu 768, max_length 512, dtype float32 (mixed precision yok); belge truncation oranı 0.0 (max 122 token, ortalama 89.7)
- Corpus embedding: 265900 belge, 473.1 s, dosya 779 MB, NaN/inf 0, batch 128, OOM olayı 0
- Hybrid: RRF, k=60; RRF(d) = 1/(60 + rank_BM25(d)) + 1/(60 + rank_Dense(d)); bir listede olmayan belge o listeden katkı almaz. Eşitlik BM25'teki zaman-kör SHA256 kuralıyla kırılır.

## Ana sonuçlar (top-50 üzerinden; BM25 satırları kabul edilmiş koşuyla birebir aynı)
| Metrik | BM25 | Dense | Hybrid (RRF) |
|---|---|---|---|
| Recall@10 | 1.0 | 0.65 | 0.9933 |
| Recall@50 | 1.0 | 0.65 | 0.9933 |
| MRR@10 | 0.7044 | 0.3129 | 0.6534 |
| NDCG@10 (ikili) | 0.7818 | 0.3578 | 0.7291 |
| NDCG@10 (dereceli) | 0.7799 | 0.3088 | 0.6824 |
| StaleEvidenceRate@10 | 0.1023 | 0.0453 | 0.0977 |
| Retrieval failure | 0.0 | 0.35 | 0.0067 |
| Ranking failure | 0.0 | 0.15 | 0.0333 |
| CURRENT ve OUTDATED birlikte top-50 | 1.0 | 0.5267 | 0.99 |
| OTHER_SOURCE_CURRENT top-50 | 0.48 | 0.0067 | 0.4367 |
| İlk sıra CURRENT | 0.41 | 0.2333 | 0.4667 |
| İlk sıra OUTDATED | 0.5867 | 0.1 | 0.3333 |
| CURRENT–OUTDATED skor eşitliği | 0.8533 | 0.0 | 0.0673 |
| Ortalama skor farkı (CURRENT − OUTDATED) | -0.5197 | 0.001 | 0.0011 |

## Oracle üst sınırları (model sonucu değildir)
Relevance-only current-first oracle CURRENT'ı ilk sıraya taşır ama OUTDATED'ı top-10 içinde tutabilir; StaleEvidenceRate'i düşürmek zorunda değildir. Temporal-clean oracle OUTDATED'ı top-10 dışına iter ve aday havuzunun zamansal temizleme üst sınırını gösterir.
| Metrik | Relevance-only current-first oracle (hybrid adayları) | Temporal-clean oracle (hybrid adayları) | Relevance-only current-first oracle (dense adayları) | Temporal-clean oracle (dense adayları) |
|---|---|---|---|---|
| Recall@10 | 0.9933 | 0.9933 | 0.65 | 0.65 |
| Recall@50 | 0.9933 | 0.9933 | 0.65 | 0.65 |
| MRR@10 | 0.9933 | 0.9933 | 0.65 | 0.65 |
| NDCG@10 (ikili) | 0.9933 | 0.9933 | 0.65 | 0.65 |
| NDCG@10 (dereceli) | 0.9825 | 0.9825 | 0.5522 | 0.5522 |
| StaleEvidenceRate@10 | 0.1017 | 0.0 | 0.0617 | 0.0 |
| Retrieval failure | 0.0067 | 0.0067 | 0.35 | 0.35 |
| Ranking failure | 0.0 | 0.0 | 0.0 | 0.0 |
| CURRENT ve OUTDATED birlikte top-50 | 0.99 | 0.99 | 0.5267 | 0.5267 |
| OTHER_SOURCE_CURRENT top-50 | 0.4367 | 0.4367 | 0.0067 | 0.0067 |
| İlk sıra CURRENT | 0.9933 | 0.9933 | 0.65 | 0.65 |
| İlk sıra OUTDATED | 0.0033 | 0.0 | 0.07 | 0.0 |
| CURRENT–OUTDATED skor eşitliği | 0.0673 | 0.0673 | 0.0 | 0.0 |
| Ortalama skor farkı (CURRENT − OUTDATED) | 0.0011 | 0.0011 | 0.001 | 0.001 |

**Split** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- dev: 0.72 / 0.7933 / 0.103 / 0.44 · 0.3454 / 0.3876 / 0.049 / 0.27 · 0.6629 / 0.7437 / 0.102 / 0.46; n=100
- test: 0.74 / 0.8081 / 0.101 / 0.48 · 0.2757 / 0.3219 / 0.04 / 0.2 · 0.6601 / 0.7287 / 0.093 / 0.5; n=100
- train: 0.6533 / 0.744 / 0.103 / 0.31 · 0.3174 / 0.3638 / 0.047 / 0.23 · 0.6372 / 0.7149 / 0.098 / 0.44; n=100

**Sorgu şablonu** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- base_severity: 0.6929 / 0.7733 / 0.1029 / 0.3857 · 0.3606 / 0.4055 / 0.0529 / 0.2571 · 0.6717 / 0.7528 / 0.1029 / 0.4714; n=70
- base_vector: 0.7063 / 0.7832 / 0.1 / 0.4125 · 0.293 / 0.3387 / 0.0375 / 0.225 · 0.6706 / 0.7486 / 0.0975 / 0.475; n=80
- combined: 0.6987 / 0.7776 / 0.1038 / 0.3974 · 0.2644 / 0.3052 / 0.0513 / 0.2051 · 0.5652 / 0.6507 / 0.0936 / 0.359; n=78
- cvssb_score: 0.7199 / 0.7931 / 0.1028 / 0.4444 · 0.341 / 0.3895 / 0.0403 / 0.25 · 0.712 / 0.7693 / 0.0972 / 0.5694; n=72

**CVSS sürümü** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- 2.0: 0.5 / 0.6309 / 0.1 / 0.0 · 0.75 / 0.75 / 0.0625 / 0.75 · 0.8125 / 0.8616 / 0.0875 / 0.625; n=8
- 3.0: 0.6667 / 0.754 / 0.1 / 0.3333 · 1.0 / 1.0 / 0.0667 / 1.0 · 1.0 / 1.0 / 0.1 / 1.0; n=3
- 3.1: 0.706 / 0.783 / 0.1026 / 0.4133 · 0.2644 / 0.3116 / 0.0421 / 0.1808 · 0.6298 / 0.7101 / 0.0978 / 0.4354; n=271
- 4.0: 0.7778 / 0.836 / 0.1 / 0.5556 · 0.7333 / 0.7708 / 0.0833 / 0.6667 · 0.8796 / 0.9107 / 0.1 / 0.7778; n=18

**Kaynak grubu (tanımlayıcı)** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- 134c704f-9b21-4f2e-91b3-4a467353bcc0: 0.7472 / 0.8134 / 0.1011 / 0.4944 · 0.0406 / 0.05 / 0.0146 / 0.0225 · 0.5239 / 0.6372 / 0.0978 / 0.2921; n=89
- NVD: 0.6538 / 0.7445 / 0.1013 / 0.3077 · 0.4313 / 0.4978 / 0.05 / 0.2949 · 0.7651 / 0.8182 / 0.0974 / 0.6026; n=78
- OTHER_SOURCE: 0.7162 / 0.7905 / 0.1041 / 0.4324 · 0.5615 / 0.6241 / 0.073 / 0.4595 · 0.7594 / 0.8097 / 0.1027 / 0.6081; n=74
- audit@patchstack.com: 0.5455 / 0.6645 / 0.1 / 0.0909 · 0.2828 / 0.3001 / 0.0364 / 0.2727 · 0.4409 / 0.5074 / 0.0818 / 0.3636; n=11
- cna@vuldb.com: 0.5 / 0.6309 / 0.1 / 0.0 · 0.2292 / 0.291 / 0.0667 / 0.1667 · 0.75 / 0.8155 / 0.1 / 0.5; n=6
- disclosure@vulncheck.com: 0.7857 / 0.8418 / 0.1 / 0.5714 · 0.1488 / 0.2162 / 0.05 / 0.0357 · 0.5923 / 0.6941 / 0.0964 / 0.3214; n=28
- secalert@redhat.com: 0.7024 / 0.7798 / 0.1143 / 0.4286 · 0.4566 / 0.4831 / 0.0571 / 0.4286 · 0.5412 / 0.5989 / 0.0857 / 0.4286; n=14

## Süre, bellek, bütünlük
- Sorgu kodlama 0.4 s, dense arama 2.2 s, RRF 0.1 s, BM25 liste yükleme 0.0 s
- Peak GPU bellek 1.708 GB, peak RSS 3.725 GB; dense indeks (embeddings.npy) 779 MB; liste dosyaları toplam 10.7 MB
- Görünürlük ihlali 0, duplicate sonuç 0, NaN/inf skor 0, eksik sorgu 0
- Tekrar üretilebilirlik: aynı seed ile dense listeler birebir aynı = True; 512 belge yeniden kodlandı, önbellekle max |fark| 1.04e-07; batch 128 vs 8 max |fark| 1.07e-07; id–satır eşlemesi = True

## Smoke kabul kapıları
- dense_recall@50_ok: True
- hybrid_recall@50_ok: True
- no_visibility_violation: True
- no_nan_inf: True
- ids_match_embedding_order: True
- reproducible_same_seed: True
- no_missing_queries: True
- no_duplicates: True
- test_not_used_for_selection: True
- all_passed: True
