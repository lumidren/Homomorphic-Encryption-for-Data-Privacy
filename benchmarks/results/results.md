Measured on Intel64 Family 6 Model 154 Stepping 3, GenuineIntel (20 logical CPUs, 15.7 GB RAM), Windows 11, Python 3.12.16, TenSEAL 0.3.18; one process per parameter set, median of repeated runs.

| N | security | profile | depth | slots | keygen | public bundle | ciphertext | encrypt | decrypt | fresh precision (slot-wise / rotating) |
|---|---|---|---|---|---|---|---|---|---|---|
| 8192 | 128 | balanced | 2 | 4096 | 0.233 s | 35.3 MB | 331.7 KB | 3.24 ms | 0.94 ms | 22 / 14 bits |
| 8192 | 128 | deep | 4 | 4096 | 0.501 s | 65.3 MB | 405.9 KB | 4.43 ms | 1.47 ms | 12 / 4 bits |
| 8192 | 192 | balanced | 2 | 4096 | 0.233 s | 28.1 MB | 257.6 KB | 3.46 ms | 1.0 ms | 12 / 4 bits |
| 8192 | 192 | deep | 3 | 4096 | 0.356 s | 39.4 MB | 291.5 KB | 3.96 ms | 1.12 ms | 7 / 0 bits |
| 8192 | 256 | balanced | 2 | 4096 | 0.231 s | 22.8 MB | 211.1 KB | 3.25 ms | 0.85 ms | 5 / 0 bits |
| 16384 | 128 | balanced | 6 | 8192 | 1.915 s | 325.9 MB | 1449.9 KB | 11.54 ms | 5.08 ms | 21 / 12 bits |
| 16384 | 128 | deep | 11 | 8192 | 5.282 s | 682.4 MB | 1860.2 KB | 19.55 ms | 9.45 ms | 11 / 3 bits |
| 16384 | 192 | balanced | 5 | 8192 | 1.444 s | 222.5 MB | 1118.4 KB | 11.34 ms | 3.9 ms | 17 / 7 bits |
| 16384 | 192 | deep | 7 | 8192 | 2.427 s | 320.6 MB | 1253.2 KB | 13.55 ms | 6.65 ms | 11 / 4 bits |
| 16384 | 256 | balanced | 5 | 8192 | 1.444 s | 189.1 MB | 944.4 KB | 9.62 ms | 3.85 ms | 10 / 3 bits |
| 16384 | 256 | deep | 6 | 8192 | 1.926 s | 226.0 MB | 996.5 KB | 13.19 ms | 5.67 ms | 7 / 0 bits |

Operation latency (milliseconds; `—` = refused, not enough depth):

| N / security / profile | vector_add | scalar_multiply | elementwise_multiply | dot_product | sum | mean | variance | weighted_average | linear_regression | logistic_regression deg3 | logistic_regression deg5 | matvec_multiply (16x64) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 8192 / 128 / balanced | 0.1 | 0.5 | 2.2 | 13.3 | 17.9 | 18.3 | 33.6 | 12.7 | 2.1 | — | — | 67.0 |
| 8192 / 128 / deep | 0.2 | 0.9 | 4.9 | 32.8 | 40.9 | 42.3 | 78.1 | 31.1 | 4.1 | 15.4 | 20.5 | 156.5 |
| 8192 / 192 / balanced | 0.2 | 0.5 | 2.1 | 13.4 | 18.7 | 18.6 | 34.2 | 13.2 | 2.0 | — | — | 69.0 |
| 8192 / 192 / deep | 0.1 | 0.7 | 3.1 | 21.8 | 29.0 | 31.4 | 58.9 | 20.6 | 3.3 | 10.9 | — | 98.7 |
| 8192 / 256 / balanced | 0.1 | 0.6 | 2.1 | 13.7 | 18.2 | 18.6 | 34.1 | 13.0 | 2.1 | — | — | 65.9 |
| 16384 / 128 / balanced | 0.9 | 3.4 | 15.5 | 145.6 | 173.9 | 158.5 | 303.5 | 122.5 | 13.0 | 50.3 | 67.5 | 538.1 |
| 16384 / 128 / deep | 1.3 | 5.5 | 35.6 | 376.7 | 384.3 | 385.3 | 781.1 | 331.9 | 23.7 | 111.6 | 184.2 | 1216.3 |
| 16384 / 192 / balanced | 0.5 | 2.8 | 12.0 | 100.7 | 118.4 | 121.8 | 231.6 | 93.0 | 9.9 | 40.0 | 53.4 | 434.5 |
| 16384 / 192 / deep | 0.8 | 3.5 | 20.1 | 178.3 | 200.5 | 194.2 | 385.9 | 158.3 | 16.0 | 62.6 | 87.9 | 654.3 |
| 16384 / 256 / balanced | 0.5 | 2.4 | 11.8 | 99.8 | 128.9 | 117.5 | 237.2 | 96.3 | 10.6 | 41.0 | 55.6 | 440.2 |
| 16384 / 256 / deep | 1.1 | 3.5 | 16.3 | 146.0 | 156.8 | 154.1 | 303.8 | 123.8 | 12.8 | 53.0 | 70.7 | 534.7 |
