---
title: "CipherCompute: Statistics and Inference on Encrypted Data with CKKS"
author: "lumidren"
date: "November 2026"
---

# CipherCompute: Statistics and Inference on Encrypted Data with CKKS

*A technical whitepaper. It assumes linear algebra and modular arithmetic at the level of a strong
undergraduate, and no prior knowledge of homomorphic encryption. Every number in it was measured
on the system described; the scripts that produced them are in the repository.*

## 1. The problem

A hospital wants a statistic — a mean blood pressure, a risk score from a trained model — computed
by a service it does not fully trust. Encryption at rest and in transit does not help: to compute,
the service must decrypt, and at that moment the data is exposed to whoever controls the machine.

**Fully homomorphic encryption (FHE)** removes that moment. The service receives ciphertexts and
computes on them directly; the output is another ciphertext that only the data owner can decrypt.
CipherCompute packages one FHE scheme, CKKS, as a multi-tenant service: a client SDK that keeps
the secret key, an API and worker that only ever hold public keys, and the operational machinery
(depth budgeting, integrity checks, audit) that makes it usable.

## 2. From lattices to approximate arithmetic

### 2.1 Learning With Errors

Pick a secret vector **s**. Publish many pairs (**a**ᵢ, bᵢ = ⟨**a**ᵢ, **s**⟩ + eᵢ mod q) with random
**a**ᵢ and small random "errors" eᵢ. Without the errors, Gaussian elimination recovers **s**. With
them, recovering **s** — or even distinguishing the pairs from random — is believed hard, also for
quantum computers. This is the **Learning With Errors (LWE)** problem.

To hide a message m, add it to such a sample: c = (**a**, ⟨**a**, **s**⟩ + e + m). Whoever knows **s**
subtracts ⟨**a**, **s**⟩ and is left with m + e: the message, plus a little noise.

### 2.2 Rings make it efficient

LWE ciphertexts are large. **Ring-LWE** replaces vectors by polynomials in
R_q = ℤ_q[X]/(X^N + 1), with N a power of two. One ring element carries N coefficients, and
multiplication of polynomials (computed with the number-theoretic transform in O(N log N)) does
the work of an N×N matrix-vector product. CipherCompute uses N ∈ {8192, 16384, 32768}.

A ciphertext is a pair (c₀, c₁) ∈ R_q² with c₀ + c₁·s ≈ m.

### 2.3 Adding and multiplying ciphertexts

* **Addition** is component-wise: (c₀ + c₀′, c₁ + c₁′) decrypts to m + m′; the noises add.
* **Multiplication** of (c₀, c₁) by (c₀′, c₁′) gives three components (d₀, d₁, d₂) that decrypt
  with (1, s, s²) to m·m′. **Relinearisation** uses a public *relinearisation key* — an
  encryption of s² under s — to fold d₂ back into a normal two-component ciphertext.
* **Rotations** of the encoded vector (needed for sums and dot products) use public *Galois keys*.

None of these need the secret key. That is the whole point: the server holds public,
relinearisation and Galois keys, and computes.

### 2.4 CKKS: encoding real numbers

Integers mod q are a poor fit for statistics. **CKKS** (Cheon, Kim, Kim and Song, 2017) instead
treats the noise as part of the approximation error of fixed-point arithmetic:

1. **Slots.** A vector **z** of up to N/2 complex numbers is mapped by an inverse "canonical
   embedding" (essentially an inverse FFT) to a polynomial with real coefficients. Operations on
   polynomials then act *slot-wise* on **z** — one homomorphic multiplication multiplies thousands
   of numbers at once (SIMD).
2. **Scale.** The coefficients are multiplied by a large **scale** Δ (we use 2²⁵–2⁴⁰) and rounded to
   integers. Decryption divides by Δ again, so the rounding and the encryption noise become small
   errors in the low-order bits of the result.

### 2.5 Rescaling and the modulus chain

Multiplying two encodings multiplies their scales: Δ·Δ = Δ². Left alone, the scale explodes after a
few multiplications. CKKS **rescales**: it divides the ciphertext by (approximately) Δ, which also
divides the modulus q by one prime factor. So q is chosen as a product of primes
q = p₀·p₁·…·p_L — the **coefficient modulus chain** — and every multiplication consumes one prime.
When only p₀ remains, no further multiplication is possible.

The number of primes available for rescaling is the **multiplicative depth** of the parameter
set. This is CKKS's "noise budget": not a quantity of noise, but a count of levels. A degree-3
polynomial needs 2 levels; computing a logistic regression score needs 3.

### 2.6 Security: why the primes are bounded

Larger q leaves more room for depth but makes the lattice problem easier. The **Homomorphic
Encryption Security Standard** tabulates, for each N and target security, the maximum log₂ q:

| N | 128-bit | 192-bit | 256-bit |
|---|---|---|---|
| 8192 | 218 | 152 | 118 |
| 16384 | 438 | 305 | 237 |
| 32768 | 881 | 611 | 476 |

Every CipherCompute parameter set is checked against this table when it is constructed; an
insecure combination cannot be built, and the server re-checks every key bundle it receives.

## 3. System design

### 3.1 The key boundary

The SDK generates the key ring locally and stores the secret key encrypted (AES-256-GCM, key
derived with Argon2id). The only key object that is ever serialised for upload hard-codes
"no secret key", and the server's single entry point for key material, `PublicKeyBundle.load`,
rejects any context that can decrypt. A CI test scans the server source for any symbol that could
touch secret material. The guarantee is therefore structural, not procedural: there is no code
path by which the service could decrypt.

### 3.2 Depth planning before execution

Each operation declares its depth cost; the API sums the costs of a job, adds the levels its
inputs have already consumed, and refuses the job *before* queueing it if the chain is too short —
naming the smallest standard parameter set that would work. The declared costs are not trusted:
regression tests measure, for every operation and parameter set, the levels the result actually
consumed, two independent ways, and fail CI on any drift.

### 3.3 Integrity against a malicious server

FHE gives confidentiality, not correctness: a malicious server could return a well-formed wrong
ciphertext. CipherCompute narrows this: every upload's SHA-256 is recorded and re-checked by the
worker, every job carries a manifest hash committing to operation, arguments and inputs, and the
SDK can recompute a random sample of jobs in plaintext (`verify_sample`). This detects systematic
cheating probabilistically; it is not a proof of correct computation, and the threat model says so.

## 4. Precision: what "approximately equal" means

CKKS results are approximate, so "correct" needs a definition. For inputs **x**, plaintext
arguments **a** and exact result **y**, let M = max(1, |**x**|_∞, |**a**|_∞, |**y**|_∞). We call a
result correct when |result − **y**|_∞ ≤ M·2^(−b), where b is the **precision in bits** for the
parameter set at the depth the computation consumed.

Instead of quoting a theoretical bound, CipherCompute *measures* b: a calibration script runs every
operation on random, zero and constant inputs at several magnitudes and records the worst error per
level; a 16× safety margin (4 bits) is subtracted. Property-based tests (Hypothesis) then check
decrypt(op(enc(x))) against op(x) within exactly that tolerance, for every operation and parameter set.

**A finding worth knowing.** The first calibration used one key ring per parameter set. Hypothesis
immediately found inputs whose error was 13× larger than anything calibration had seen. Tracing it
showed the cause was not the inputs but the **key ring**: the noise floor of rotation-heavy
operations (sum, mean, dot product — 12 rotations each at N = 8192) varies by 14–26× between fresh
key rings with identical parameters, with outliers near 100×. A precision bound measured on one
key is not a bound. Calibration now samples 12 key rings per N = 8192 set and 4 per N = 16384 set.

The same data showed that one number per level is too coarse. Slot-wise operations (add, multiply,
element-wise products, regression on feature-major layouts) never key-switch, and their error is
set by the scale; rotating operations (sum, mean, dot product, variance, matrix-vector) pay the
key-switching noise floor at every level. Precision is therefore recorded per class, and every job
reports the class that applies to the operations it ran. Levels a class never reaches in the
calibration run are shown as n/a in the table rather than extrapolated.

The measured precision per level (bits, after the 4-bit margin; 0 = no usable precision) for each
standard set:

{{PRECISION_TABLE}}

Two consequences. First, sums and means have an *absolute* noise floor that does not shrink with
the data: at N = 8192 and 128-bit security it is about 2⁻¹⁴–2⁻¹⁸, ample for vital signs but not for
quantities that need six significant digits. Second, the 192- and 256-bit sets at N = 8192 retain
only a few bits after a sum — the security margin is paid for in precision. The parameter advisor
accepts a minimum precision and moves to N = 16384 when it is needed.

## 5. Performance

{{BENCHMARK_TABLE}}

Reading the table: costs grow roughly with N log N per polynomial operation and linearly with the
number of primes; rotations (sum, mean, dot product, variance) dominate the statistics. Public key
bundles are large because the Galois keys for all rotations are included — tens of megabytes at
N = 8192, hundreds at N = 16384 — which is why the worker caches them by fingerprint.

### 5.1 Throughput under load

{{LOADTEST_SUMMARY}}

## 6. Case study: encrypted cardiovascular risk

A hospital scores patients with a logistic regression model on a server it does not trust with
patient data (synthetic data only; `showcase/health-risk`). Seven standardised vital signs are
encrypted one *column* per ciphertext (up to 4,096 patients each); the server computes
w·x + b with seven plaintext-ciphertext products and applies a degree-3 polynomial approximation
of the sigmoid, fitted on [−8, 8]. The job uses 3 of the 4 levels of the N = 8192, 128-bit *deep*
parameter set.

| | value |
|---|---|
| max \|encrypted − plaintext polynomial model\| | 2.35 × 10⁻⁴ |
| max \|encrypted − exact sigmoid\| | 0.098 |
| AUC, encrypted scores | 0.861 |
| AUC, plaintext model | 0.861 |
| server compute time, 600 patients | 0.83 s |

The two error figures measure different things. CKKS noise moves each score by at most 2.4×10⁻⁴;
the homomorphic evaluation is faithful. The polynomial sigmoid differs from the true logistic
function by up to 0.098 — but it is monotonic over the model's logit range, so the ranking of
patients, and with it the AUC, is unchanged. Clinically, ranking and thresholding are what the
score is used for.

## 7. Limitations

* **No verifiable computation.** A malicious server can return wrong results; detection is
  probabilistic (§3.3).
* **Plaintext arguments are visible.** Model weights, scalars and matrices sent with a job are
  readable by the server; encrypting them costs one more level.
* **Metadata leaks.** Ciphertext sizes and vector lengths are observable (padding hides lengths).
* **Decryption oracles.** Returning decrypted CKKS outputs to an adversary who holds the
  ciphertexts can leak the secret key (Li and Micciancio, 2021). The SDK has no such path; client
  applications must not build one.
* **Approximation.** Results are approximate; §4 quantifies by how much, per parameter set.

## References

1. J. H. Cheon, A. Kim, M. Kim, Y. Song. *Homomorphic Encryption for Arithmetic of Approximate
   Numbers.* ASIACRYPT 2017.
2. O. Regev. *On Lattices, Learning with Errors, Random Linear Codes, and Cryptography.* STOC 2005.
3. V. Lyubashevsky, C. Peikert, O. Regev. *On Ideal Lattices and Learning with Errors over Rings.*
   EUROCRYPT 2010.
4. M. Albrecht et al. *Homomorphic Encryption Security Standard.* HomomorphicEncryption.org, 2018.
5. B. Li, D. Micciancio. *On the Security of Homomorphic Encryption on Approximate Numbers.*
   EUROCRYPT 2021.
6. M. Kim, Y. Song, S. Wang, Y. Xia, X. Jiang. *Secure Logistic Regression Based on Homomorphic
   Encryption.* JMIR Medical Informatics, 2018.
7. Microsoft SEAL (release 4.x); A. Benaissa et al., *TenSEAL: A Library for Encrypted Tensor
   Operations Using Homomorphic Encryption*, 2021.
