# Rule Kapsam Karşılaştırması: ChronoRank-Rule-Corpus vs ChronoRank-Rule-Target — 2026-09-16

İki varyant aynı parametresiz kuralın bastırma kapsamını karşılaştırır; yeni model ailesi değildir. Corpus: 50 adayın tamamında kendi zincirinde eskimiş kayıtları bastırır. Target: yalnız sorgunun (CVE, kaynak, sürüm) zincirindeki eskimiş kayıtları bastırır.

| Ölçü | Rule-Corpus | Rule-Target |
|---|---|---|
| Toplam bastırılan aday | 50260 | 3709 |
| Hedef zincirden bastırılan | 3709 | 3709 |
| Hedef dışı bastırılan | 46551 | 0 |
| Sorgu başına ortalama bastırılan | 14.2098 | 1.0486 |
| 10'dan az korunmuş adaylı sorgu (capacity limitation) | 284 | 0 |
| CURRENT kaybı | 0 | 0 |
| OTHER_SOURCE_CURRENT kaybı | 0 | 0 |
| Top-10'dan kaybedilen dereceli relevance | 0 | 0 |
| MRR@10 | 0.9986 | 0.9975 |
| NDCG@10 | 0.999 | 0.9981 |
| NDCG@10 dereceli | 0.999 | 0.994 |
| Stale@10 | 0.0082 | 0.0001 |
| OutdatedSuppression@10 | 0.9191 | 0.9994 |
| CurrentPreservation@10 | 1.0 | 1.0 |
| CurrentAt1AndNoStaleAt10 | 0.9166 | 0.9946 |
| OTHER_SOURCE_CURRENT top-10 | 0.4987 | 0.4987 |

- Aynı liste 504 / 3537; farklı 3033. Farklı listelerde CurrentAt1AndNoStaleAt10/Stale açısından Target daha iyi 284, Corpus daha iyi 7, eşit 2742; dereceli NDCG açısından Target daha iyi 0, Corpus daha iyi 318, eşit 2715.
- Split (joint / Stale / dereceli NDCG): rule_corpus train 0.9791/0.0019/0.999, dev 0.9712/0.0019/0.9979, test 0.834/0.0167/0.9993; rule_target train 0.9936/0.0001/0.993, dev 0.984/0.0/0.9914, test 0.998/0.0/0.9957
- Future-event (joint / Stale / MRR): rule_corpus 0.8421/0.0263/1.0; rule_target 1.0/0.0/1.0

Ödünleşim: Corpus daha geniş zamansal temizlik (dereceli NDCG ve diğer-kaynak aktif kanıtın yükselmesi) sağlar ama 284 sorguda ilk blokta 10 aday kalmaz; Target top-10 kapasite sorununu tamamen kaldırır ve hedef zincir bastırmasını neredeyse eksiksiz yapar, buna karşılık hedef dışı eskimiş kayıtlar BM25 sırasında kalır (8 sorguda CURRENT 2. sırada kalır, dereceli NDCG 318 sorguda daha düşük).
