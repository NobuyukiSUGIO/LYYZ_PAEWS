# PAEWS_LYYZ

Implementation and experimental results for an analysis of the PAEWS scheme of

> F. Luo, X. Yan, H. Yang, and X. Zheng, "PAEWS: Public-key authenticated encryption with wildcard search over outsourced encrypted data," *IEEE Trans. Inf. Forensics Security*, vol. 20, pp. 2212–2223, 2025, doi: [10.1109/TIFS.2025.3540606](https://doi.org/10.1109/TIFS.2025.3540606).

The program implements the PAEWS construction of Section V of the paper (the "LYYZ scheme") with real pairing groups and checks that its claimed ciphertext indistinguishability (CI) and trapdoor indistinguishability (TI) do not hold within the original security games (Definitions 5 and 6). It also measures the cost of each operation.

This code is for research and reproducibility only. It is **not** production cryptography.

## Contents

| Path | Description |
|---|---|
| `paews_mcl_bench.cpp` | LYYZ scheme, validation of the CI/TI counterexamples, and timing benchmark |
| `Makefile` | Build (`make`), quick check (`make quick`), full run with the reported settings (`make bench`) |
| `run_benchmark.sh` | Records the environment, builds, and runs the full benchmark |
| `results/` | The reported run (CSV of timing statistics, console log, environment record) and the extended validation log |

## Requirements

- Linux with a C++17 compiler (tested with g++ 13.3.0 on Ubuntu 24.04)
- [herumi/mcl](https://github.com/herumi/mcl) built with BLS12-381 support (tested with revision `8f64cb614aac536c928a2cf269c1688b2633e51d`)
- GMP (`libgmp-dev`)

The Makefile expects mcl under `/usr/local` (`include/mcl` and `lib/libmcl.a`), which is where `sudo make install` in the mcl source tree puts it. Use `make MCL_DIR=/path/to/mcl` for another location.

## Build and run

```bash
make            # build paews_mcl_bench (mcl linked statically)
make quick      # sanity check: 100 timed samples, 10 validations
make bench      # full run with the settings of results/ (several minutes)
```

`make bench` runs

```bash
./paews_mcl_bench --n 8 --runs 10000 --validate 10000 --warmup 50 --pool 16 \
  --csv paews_bls12_381_validate10000.csv
```

Options:

- `--n`: keyword length (default 8, at least 2)
- `--runs`: timed samples per operation (default 10,000)
- `--validate`: independent validation trials (default 128; 10,000 in `results/`)
- `--warmup`: warm-up calls per operation (default 50)
- `--pool`: number of pre-generated inputs reused in the timing loop (default 16)
- `--csv`: output file for mean, median, 95th percentile, standard deviation, minimum, and maximum (µs)

Outputs are written to the repository root, so `results/` is never overwritten.

## What is checked

The validation stage runs independent trials. Each trial samples a fresh public parameter `t`, fresh sender and receiver keys, and fresh encryption and trapdoor randomness; only the hash-derived generators of G1 and G2 are fixed. Every trial checks:

1. Honest `Test` and a negative control
2. The CI counterexample, using one trapdoor query permitted by Definition 5
3. The TI counterexample, using one encryption query permitted by Definition 6
4. The TI counterexample that only compares two components of the challenge trapdoor (no query)
5. Acceptance of the all-identity token obtained with trapdoor randomness 0
6. Lemma 1 (shift identity) in general form: for a random number of specified positions ℓ ∈ [1, n], random characters, a random non-wrapping shift δ, and a random nonzero ρ, the shifted trapdoor equals the trapdoor of the shifted keyword with the same ρ component by component; as a negative control, it differs from the trapdoor of another keyword
7. PEWS (Section IV of the paper): honest `Test` and a negative control
8. The CI counterexample applied to PEWS

PEWS uses D_i = g1^{t^{x_i}} h_i^r and E_i = g2^{ρ t^{-y_i}} with the same T0, T1, T2, and `Test`, which are exactly the PAEWS algorithms with γ = 1; the program runs PEWS that way.

The program aborts if any check fails. `--runs 0` runs only the validation and skips the timing benchmark.

## Reported results

Environment: AMD Ryzen 7 5800X, Ubuntu 24.04 (Linux 6.8, native), g++ 13.3.0, `-O2 -DNDEBUG -std=c++17 -DMCL_FP_BIT=384 -DMCL_FR_BIT=256`, mcl `8f64cb61` (static), BLS12-381, n = 8.

Checks 1–5 and the timing statistics come from the run in `results/paews_run_validate10000.log`, made with the initial version of the program (commit `7649754`); later versions leave the timing code unchanged. All five checks succeeded in **10,000/10,000** independent trials.

Checks 1–8 were run again with the current version in `results/paews_validation_extended_10000.log` (`--runs 0 --validate 10000`, same machine).

Mean times over 10,000 timed samples (µs):

| Operation | Mean | Std. dev. |
|---|---:|---:|
| Enc (n = 8) | 930.261 | 6.971 |
| Trapdoor (ℓ = 1) | 432.265 | 7.536 |
| Test (ℓ = 1, three pairings) | 1427.541 | 6.597 |
| Shift (three G2 scalar multiplications) | 272.200 | 5.255 |
| CI: Shift+Test | 1694.653 | 6.013 |
| CI: oracle Trapdoor+Shift+Test | 2132.487 | 24.838 |
| TI: Shift+Test | 1738.643 | 66.138 |
| TI: oracle Enc+Shift+Test | 2706.002 | 30.461 |
| TI: direct E1 = E2 comparison | 0.446 | 0.005 |

The full statistics are in `results/paews_bls12_381_validate10000.csv`.

## Measurement notes

- Setup and the initial key generation are excluded from all timings. `Enc` and `Trapdoor` include random sampling.
- The timing loop reuses a pool of 16 valid inputs to isolate computation costs, so the 10,000 timed samples are **not** independent security experiments. The independent experiments are the validation trials.
- The direct E1 = E2 comparison is timed in batches of 256 comparisons and reported per comparison.
- The oracle-inclusive rows also include generating the permitted oracle answer; challenge generation and communication are excluded.
- Each operation is timed separately, so composite timings need not equal the sums of component timings.
- Setup resamples `t` if `t = 1`; trapdoor randomness 0 is not excluded, as in the original algorithm.
- Timings depend on the CPU, compiler, flags, mcl revision, and system load.

## License

MIT License. See [LICENSE](LICENSE). The mcl library is distributed separately under its own license.
