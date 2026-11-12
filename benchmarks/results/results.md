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

Operation latency at N = 8192 (milliseconds; `—` = refused, not enough depth):

| operation | 128-bit balanced | 128-bit deep | 192-bit balanced | 192-bit deep | 256-bit balanced |
|---|---|---|---|---|---|
| vector_add | 0.1 | 0.2 | 0.2 | 0.1 | 0.1 |
| scalar_multiply | 0.5 | 0.9 | 0.5 | 0.7 | 0.6 |
| elementwise_multiply | 2.2 | 4.9 | 2.1 | 3.1 | 2.1 |
| dot_product | 13.3 | 32.8 | 13.4 | 21.8 | 13.7 |
| sum | 17.9 | 40.9 | 18.7 | 29.0 | 18.2 |
| mean | 18.3 | 42.3 | 18.6 | 31.4 | 18.6 |
| variance | 33.6 | 78.1 | 34.2 | 58.9 | 34.1 |
| weighted_average | 12.7 | 31.1 | 13.2 | 20.6 | 13.0 |
| linear_regression | 2.1 | 4.1 | 2.0 | 3.3 | 2.1 |
| logistic_regression deg3 | — | 15.4 | — | 10.9 | — |
| logistic_regression deg5 | — | 20.5 | — | — | — |
| matvec_multiply (16x64) | 67.0 | 156.5 | 69.0 | 98.7 | 65.9 |

Operation latency at N = 16384 (milliseconds; `—` = refused, not enough depth):

| operation | 128-bit balanced | 128-bit deep | 192-bit balanced | 192-bit deep | 256-bit balanced | 256-bit deep |
|---|---|---|---|---|---|---|
| vector_add | 0.9 | 1.3 | 0.5 | 0.8 | 0.5 | 1.1 |
| scalar_multiply | 3.4 | 5.5 | 2.8 | 3.5 | 2.4 | 3.5 |
| elementwise_multiply | 15.5 | 35.6 | 12.0 | 20.1 | 11.8 | 16.3 |
| dot_product | 145.6 | 376.7 | 100.7 | 178.3 | 99.8 | 146.0 |
| sum | 173.9 | 384.3 | 118.4 | 200.5 | 128.9 | 156.8 |
| mean | 158.5 | 385.3 | 121.8 | 194.2 | 117.5 | 154.1 |
| variance | 303.5 | 781.1 | 231.6 | 385.9 | 237.2 | 303.8 |
| weighted_average | 122.5 | 331.9 | 93.0 | 158.3 | 96.3 | 123.8 |
| linear_regression | 13.0 | 23.7 | 9.9 | 16.0 | 10.6 | 12.8 |
| logistic_regression deg3 | 50.3 | 111.6 | 40.0 | 62.6 | 41.0 | 53.0 |
| logistic_regression deg5 | 67.5 | 184.2 | 53.4 | 87.9 | 55.6 | 70.7 |
| matvec_multiply (16x64) | 538.1 | 1216.3 | 434.5 | 654.3 | 440.2 | 534.7 |
