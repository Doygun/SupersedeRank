# Tam Dense + Hybrid Koşusu (FULL-CORPUS, ana sorgular) — 2026-09-15

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
| Recall@10 | 1.0 | 0.6746 | 0.9949 |
| Recall@50 | 1.0 | 0.6746 | 0.9949 |
| MRR@10 | 0.7116 | 0.3037 | 0.6535 |
| NDCG@10 (ikili) | 0.787 | 0.3544 | 0.73 |
| NDCG@10 (dereceli) | 0.7852 | 0.2967 | 0.6731 |
| StaleEvidenceRate@10 | 0.1047 | 0.046 | 0.1004 |
| Retrieval failure | 0.0 | 0.3254 | 0.0051 |
| Ranking failure | 0.0 | 0.1597 | 0.0336 |
| CURRENT ve OUTDATED birlikte top-50 | 0.9997 | 0.5516 | 0.9932 |
| OTHER_SOURCE_CURRENT top-50 | 0.4993 | 0.0105 | 0.4563 |
| İlk sıra CURRENT | 0.43 | 0.2024 | 0.458 |
| İlk sıra OUTDATED | 0.5655 | 0.1349 | 0.3543 |
| CURRENT–OUTDATED skor eşitliği | 0.8733 | 0.0005 | 0.0749 |
| Ortalama skor farkı (CURRENT − OUTDATED) | -0.4553 | 0.0005 | 0.0011 |

## Oracle üst sınırları (model sonucu değildir)
Relevance-only current-first oracle CURRENT'ı ilk sıraya taşır ama OUTDATED'ı top-10 içinde tutabilir; StaleEvidenceRate'i düşürmek zorunda değildir. Temporal-clean oracle OUTDATED'ı top-10 dışına iter ve aday havuzunun zamansal temizleme üst sınırını gösterir.
| Metrik | Relevance-only current-first oracle (hybrid adayları) | Temporal-clean oracle (hybrid adayları) | Relevance-only current-first oracle (dense adayları) | Temporal-clean oracle (dense adayları) |
|---|---|---|---|---|
| Recall@10 | 0.9949 | 0.9949 | 0.6746 | 0.6746 |
| Recall@50 | 0.9949 | 0.9949 | 0.6746 | 0.6746 |
| MRR@10 | 0.9949 | 0.9949 | 0.6746 | 0.6746 |
| NDCG@10 (ikili) | 0.9949 | 0.9949 | 0.6746 | 0.6746 |
| NDCG@10 (dereceli) | 0.984 | 0.984 | 0.5646 | 0.5646 |
| StaleEvidenceRate@10 | 0.1042 | 0.0 | 0.0644 | 0.0 |
| Retrieval failure | 0.0051 | 0.0051 | 0.3254 | 0.3254 |
| Ranking failure | 0.0 | 0.0 | 0.0 | 0.0 |
| CURRENT ve OUTDATED birlikte top-50 | 0.9932 | 0.9932 | 0.5516 | 0.5516 |
| OTHER_SOURCE_CURRENT top-50 | 0.4563 | 0.4563 | 0.0105 | 0.0105 |
| İlk sıra CURRENT | 0.9949 | 0.9949 | 0.6746 | 0.6746 |
| İlk sıra OUTDATED | 0.0014 | 0.0 | 0.0597 | 0.0 |
| CURRENT–OUTDATED skor eşitliği | 0.0749 | 0.0749 | 0.0005 | 0.0005 |
| Ortalama skor farkı (CURRENT − OUTDATED) | 0.0011 | 0.0011 | 0.0005 | 0.0005 |

**Split** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- dev: 0.7121 / 0.7873 / 0.1054 / 0.4295 · 0.3524 / 0.4081 / 0.0529 / 0.2436 · 0.6884 / 0.763 / 0.1035 / 0.4872; n=312
- test: 0.7212 / 0.7941 / 0.1048 / 0.4489 · 0.2501 / 0.2996 / 0.0389 / 0.1574 · 0.6365 / 0.7135 / 0.0993 / 0.4475; n=1506
- train: 0.7031 / 0.7807 / 0.1044 / 0.4136 · 0.3417 / 0.3927 / 0.051 / 0.2344 · 0.6622 / 0.7384 / 0.1008 / 0.4619; n=1719

**Sorgu şablonu** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- base_severity: 0.7142 / 0.7889 / 0.1048 / 0.4344 · 0.3482 / 0.4015 / 0.0526 / 0.2338 · 0.678 / 0.7557 / 0.1027 / 0.4664; n=877
- base_vector: 0.7072 / 0.7837 / 0.1051 / 0.4228 · 0.2926 / 0.3419 / 0.0387 / 0.2016 · 0.6858 / 0.7566 / 0.1014 / 0.5046; n=868
- combined: 0.7079 / 0.7842 / 0.105 / 0.4228 · 0.239 / 0.2939 / 0.0503 / 0.1324 · 0.5709 / 0.6563 / 0.0977 / 0.3647; n=861
- cvssb_score: 0.7168 / 0.7908 / 0.1039 / 0.4393 · 0.3317 / 0.3777 / 0.0427 / 0.2385 · 0.6769 / 0.7491 / 0.0997 / 0.493; n=931

**CVSS sürümü** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- 2.0: 0.6152 / 0.7158 / 0.1015 / 0.2353 · 0.6135 / 0.658 / 0.0618 / 0.5147 · 0.7832 / 0.8382 / 0.0956 / 0.6029; n=68
- 3.0: 0.7059 / 0.7829 / 0.1059 / 0.4118 · 0.5316 / 0.6144 / 0.0647 / 0.4118 · 0.75 / 0.8145 / 0.1 / 0.5294; n=17
- 3.1: 0.7136 / 0.7884 / 0.1045 / 0.433 · 0.2774 / 0.3255 / 0.0418 / 0.1836 · 0.6425 / 0.7202 / 0.0999 / 0.4508; n=3159
- 4.0: 0.7133 / 0.788 / 0.1072 / 0.4437 · 0.502 / 0.5807 / 0.0874 / 0.3208 · 0.7371 / 0.8053 / 0.1068 / 0.4983; n=293

**Kaynak grubu (tanımlayıcı)** — MRR@10 / NDCG@10 / Stale@10 / ilk sıra CURRENT (BM25 · Dense · Hybrid); n

- 134c704f-9b21-4f2e-91b3-4a467353bcc0: 0.7503 / 0.8156 / 0.1037 / 0.505 · 0.0585 / 0.075 / 0.0124 / 0.0321 · 0.5418 / 0.6428 / 0.0982 / 0.3382; n=1091
- NVD: 0.6806 / 0.7641 / 0.1024 / 0.3655 · 0.4302 / 0.4923 / 0.0495 / 0.3007 · 0.7697 / 0.8264 / 0.1013 / 0.5942; n=695
- OTHER_SOURCE: 0.7059 / 0.7827 / 0.1068 / 0.4195 · 0.5184 / 0.5937 / 0.0748 / 0.3559 · 0.7425 / 0.803 / 0.1034 / 0.5551; n=944
- audit@patchstack.com: 0.6221 / 0.7211 / 0.1 / 0.2443 · 0.1784 / 0.2026 / 0.0229 / 0.145 · 0.5201 / 0.5724 / 0.0847 / 0.4122; n=131
- cna@vuldb.com: 0.6905 / 0.7711 / 0.1015 / 0.3985 · 0.42 / 0.4963 / 0.0707 / 0.2782 · 0.6964 / 0.7697 / 0.1008 / 0.4586; n=133
- disclosure@vulncheck.com: 0.7169 / 0.7909 / 0.1053 / 0.4418 · 0.2394 / 0.3051 / 0.0587 / 0.1217 · 0.6087 / 0.7028 / 0.1037 / 0.3598; n=378
- secalert@redhat.com: 0.6955 / 0.7747 / 0.1133 / 0.4121 · 0.3161 / 0.3713 / 0.0588 / 0.2061 · 0.5683 / 0.6376 / 0.0982 / 0.3818; n=165

## Future-event kohortu (tanımlayıcı; ana tabloyla birleştirilmez)
| Metrik | BM25 | Dense | Hybrid (RRF) |
|---|---|---|---|
| Recall@10 | 1.0 | 0.3158 | 1.0 |
| Recall@50 | 1.0 | 0.3158 | 1.0 |
| MRR@10 | 0.6053 | 0.1158 | 0.4642 |
| NDCG@10 (ikili) | 0.7061 | 0.1394 | 0.5538 |
| NDCG@10 (dereceli) | 0.6988 | 0.1035 | 0.4986 |
| StaleEvidenceRate@10 | 0.1842 | 0.0263 | 0.1526 |
| Retrieval failure | 0.0 | 0.6842 | 0.0 |
| Ranking failure | 0.0 | 0.1053 | 0.1579 |
| CURRENT ve OUTDATED birlikte top-50 | 1.0 | 0.2632 | 1.0 |
| OTHER_SOURCE_CURRENT top-50 | 0.5789 | 0.0 | 0.5789 |
| İlk sıra CURRENT | 0.3158 | 0.0526 | 0.3158 |
| İlk sıra OUTDATED | 0.6842 | 0.0 | 0.3684 |
| CURRENT–OUTDATED skor eşitliği | 1.0 | 0.0 | 0.0 |
| Ortalama skor farkı (CURRENT − OUTDATED) | 0.0 | -0.0004 | 0.0004 |
n=19 sorgu / 18 CVE.

## Süre, bellek, bütünlük
- Sorgu kodlama 5.1 s, dense arama 25.2 s, RRF 1.0 s, BM25 liste yükleme 0.4 s
- Peak GPU bellek 1.514 GB, peak RSS 3.418 GB; dense indeks (embeddings.npy) 779 MB; liste dosyaları toplam 127.5 MB
- Görünürlük ihlali 0, duplicate sonuç 0, NaN/inf skor 0, eksik sorgu 0
