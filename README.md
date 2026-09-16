# Architectural Performance Evaluation of Post-Quantum and Classical Digital Signature Algorithms on x86 and ARM

Benchmark suite, raw data and analysis scripts for the paper *An Architectural Performance Evaluation of Post-Quantum and Classical Digital Signature Algorithms on x86 and ARM* (Victor H. Braz, Matheus A. Souza, PUC Minas). Under review at SSCAD 2026.

## Summary

An algorithm's ARM/x86 slowdown tracks whether liboqs ships a vectorized backend for
the target ISA, more than it tracks anything about the algorithm itself.

Clock speed accounts for none of the variance between algorithms. It is a uniform
2.7x divisor, so the 8x spread between the least- and most-affected operations is the
same before and after normalizing by it. SIMD width does no better: the two families
vectorized on both platforms differ by 2.8 to 2.9x among themselves once clock is
removed. Cryptographic ISA extensions predict less still. SLH-DSA-SHA2, whose
primitive is the one most directly accelerable on x86, has the smallest gap of any
family, because `slhdsa-c` bundles its own scalar SHA-256 and never reaches SHA-NI.

Building liboqs twice from one commit, with the AVX2 and NEON backends forced off and
then on, measures what vectorization is worth per family. Falcon signing gains 23 to
26x on x86 and 16 to 17x on ARM; ML-DSA gains 3.9 to 4.2x and 1.7 to 1.8x; SLH-DSA
gains nothing on either. For ML-DSA-65 the factors separate: a 28.2x raw ratio of
2.70x clock, 2.57x coverage and a 4.07x microarchitectural residual.

Also measured: parallel efficiency of 94 to 100% at four threads on ARM, resident
memory set by process baseline rather than by algorithm, stack depth varying 15x
across families, and no scheme short-circuiting on a corrupted signature.

## What is measured

**Post-quantum:** ML-DSA (FIPS 204), SLH-DSA (FIPS 205) in SHA2 and SHAKE instantiations with both `s` and `f` variants, and Falcon (FIPS 206 draft). 17 parameter sets in the extended round.

**Classical baselines:** RSA-3072 and ECDSA-P256 via OpenSSL's EVP API.

**Metrics:** keygen, sign and verify latency (mean, median, std, P95, P99); artifact sizes and signature-size distributions; verification under single-byte corruption; isolated peak RSS and stack high-water mark; multi-threaded throughput and parallel efficiency; message-size sensitivity from 64 B to 1 MB; and direct vectorization gain from paired builds.

## Environment

| | x86 platform | ARM platform |
|---|---|---|
| Processor | AMD Ryzen 5 7600 (Zen 4) | Raspberry Pi 4B (Cortex-A72) |
| ISA / cores | x86_64, 6 | AArch64, 4 |
| Base clock | 3.8 GHz | 1.8 GHz |
| SIMD | AVX-512, AVX2, AES-NI, SHA-NI | NEON (no crypto extensions) |
| RAM | 32 GB DDR5 | 8 GB LPDDR4 |
| OS | CachyOS (Linux 7.1.5) | Raspberry Pi OS 64-bit (Linux 6.12) |
| CPU governor | performance (pinned) | ondemand (default) |
| liboqs / OpenSSL | 0.16.0 / 3.6.3 | 0.16.0 / 3.5.5 |
| Compiler (harness) | GCC 16.1.1 (-O2) | GCC 14.2.0 (-O2) |

Both platforms run natively, without virtualization.

All runs use liboqs 0.16.0, commit `5a1a854`, identical on both machines, built with `-DOQS_DIST_BUILD=ON` to enable runtime CPU dispatch, and compiled at `-O3` independently of the harness's `-O2`. Version 0.16.0 removed the vendored PQClean SPHINCS+ code and takes SLH-DSA from `slhdsa-c`, which bundles its own scalar SHA-2 and Keccak rather than calling liboqs's hash layer. That property is what makes SLH-DSA usable as a negative control.

## Repository layout

### The two harnesses

This repository contains two benchmark harnesses, in sibling directories. They
share filenames (`Makefile`, `benchmark.h`, `bench_pqc.c`, `bench_classical.c`) but
not contents, and they produced different tables. Neither is a newer version of the
other in the sense of superseding it: the paper draws on both, so both are kept
intact and buildable, not merged.

| | `Benchmarking-Master/` | `Benchmarking-Extended/` |
|---|---|---|
| Paper's name for it | primary round | extended round (Section 4.3) |
| Warmup | fixed 20 iterations (`WARMUP_ITERS`) | fixed 300 ms (`WARMUP_MS_DURATION`) |
| Clocks | `CLOCK_MONOTONIC` | `CLOCK_MONOTONIC` + `CLOCK_PROCESS_CPUTIME_ID`, plus cycle counts |
| Pinning | none | `setarch -R` + `taskset -c 1` |
| PQC parameter sets | 10 | 17 |
| Operations | keygen, sign, verify | keygen, sign, verify, `verify_invalid` |
| `benchmark.h` | 7.8 KB | 34 KB |
| Feeds | Tables 2 and 4 | Tables 3, 5 and 6, and Sections 5.3–5.5 |

Build them separately, from inside their own directory. `cd Benchmarking-Extended &&
make` and `cd Benchmarking-Master && make` produce unrelated binaries from
same-named sources; running `make` from the wrong directory silently builds the other
round's harness.

```
README.md
LICENSE
CITATION.cff
Paper.pdf
Benchmarking-Master/
  Makefile                  build for both harnesses; PLATFORM tags the output filenames
  benchmark.h               shared timing, warmup and measurement helpers
  bench_pqc.c               liboqs harness: ML-DSA, SLH-DSA, Falcon
  bench_classical.c         OpenSSL EVP harness: RSA-3072, ECDSA-P256
  requirements.txt          pinned Python dependencies for the analysis scripts

  run_benchmark.sh          primary-round driver; records environment metadata,
                            optionally pins the governor, names output from `uname -m`
  run_arm_benchmark.sh      Pi variant: no governor pinning, logs SoC temperature
                            every 5 s alongside the run
  run_perf_matrix.sh        `perf stat` over every (algorithm, operation) pair,
                            using the _fast (N=100) binaries
  run_perf_matrix_016.sh    the same sweep, PQC only, against a separately built
                            liboqs 0.16.0 binary given as argument 2
  run_concurrency_scaling.sh  launches K concurrent copies of one (algorithm,
                            operation) and reports wall-clock aggregate throughput

  analyze.py                cross-platform latency tables, ARM/x86 slowdown ratios,
                            per-family bands, slowdown bar chart
  parse_perf_matrix.py      parses a directory of `perf stat` captures into one
                            perf_matrix CSV
  plot_tail_variance.py     boxplot of x86 sign-latency distributions, each
                            normalized by its own median

  fig9_slowdown_ratio.png   analyze.py's chart, committed under this name (see Figures)
  fig_tail_variance.png     plot_tail_variance.py's chart (copy of the one in the
                            x86 results directory)

  results_x86_20260803_145226/   primary round, x86
  results_arm_20260803_174513/   primary round, ARM
  perf_results/             derived measurement CSVs (see Data and outputs)
  perf_stat_raw/            raw `perf stat` captures, one text file per
                            (algorithm, operation)
    x86/ arm/               36 files each: 12 algorithms x 3 operations
    x86_016/ arm_016/       30 files each: the 10 PQC algorithms x 3 operations

Benchmarking-Extended/      the extended round (Section 4.3); see above
  Makefile                  targets: all, fast, threaded, mem_isolated
  benchmark.h               300 ms warmup, dual clocks, cycle counts, stack canary
  algo_table.h              the 17 PQC parameter sets, shared by the liboqs binaries
  algo_table_openssl.h      the OpenSSL-provider algorithm list
  bench_pqc.c               liboqs harness, 17 sets x 4 operations
  bench_classical.c         OpenSSL EVP harness, RSA-3072 and ECDSA-P256
  bench_pqc_threaded.c      T barrier-synchronised pthreads in one process  -> Table 6
  bench_classical_threaded.c  same, for the classical baselines             -> Table 6
  bench_mem_isolated.c      fresh fork/exec per (algorithm, op, library),
                            isolated peak RSS + stack high-water            -> Table 5
  bench_openssl_pqc.c       OpenSSL's own ML-DSA/SLH-DSA, for the library
                            comparison in Table 5

  build_liboqs_variant.sh   builds liboqs ref|optimized                     -> Table 3
  build_perf_events.sh      probes which perf events this host exposes
  capture_environment.sh    liboqs commit, library versions, microcode, governor
  monitor_system.sh         1 Hz frequency / temperature / throttle logger
  monitor_ina219.py         optional INA219 power sampling (sensor not attached
                            for the published runs; see the data dictionary)

  run_full_suite.sh         x86 entry point for the whole extended pass
  run_full_suite_arm.sh     ARM counterpart (thread list 1-4, vcgencmd logging)
  run_thread_scaling.sh     thread-level sweep                              -> Table 6
  run_message_size_sweep.sh 64 B / 1 KB / 64 KB / 1 MB sweep (Section 5.5)

  results/
    refopt_clean_x86/       ablation, 14 variants x {ref,opt}               -> Table 3
    refopt_clean_arm/       same on ARM                                     -> Table 3
    thread_scaling_x86.csv  48 rows: 8 jobs x 6 thread counts               -> Table 6
    thread_scaling_arm.csv  32 rows: 8 jobs x 4 thread counts               -> Table 6
```

Not staged here, and needed only to re-derive figures the tables already report: the
two full-suite output directories (~28 MB, mostly per-iteration raw CSVs, including
the 1 Hz `system_monitor.csv` behind Section 5.5's thermal claim and the message-size
sweep behind Section 5.5's growth factors) and the `refopt_matrix_*` perf captures.
Those are held outside the repository for now.

Each primary-round results directory holds the two aggregate CSVs
(`results_{pqc,classical}_<platform>.csv`), the two raw per-iteration CSVs
(`..._raw.csv`), the benchmarks' stdout (`pqc_log.txt`, `classical_log.txt`) and
`environment.txt`, which records CPU, governor, OS, compiler, OpenSSL and liboqs
version at run time. Both `pqc_log.txt` files print `liboqs version : 0.15.0` from
`OQS_VERSION_TEXT`, which is the direct evidence that these two directories predate
the 0.16.0 upgrade.

The ARM directory additionally holds `temp_log.txt`, 3,094 SoC temperature samples
at the 5 s interval `run_arm_benchmark.sh` uses, spanning 4.4 hours, which is this
run and not the 15.4-hour 1 Hz frequency log quoted in Section 5.5, and
`slowdown_ratios.csv`, which `analyze.py` writes into whichever ARM directory it is
given. The x86 directory additionally holds `fig_tail_variance.png`, which
`plot_tail_variance.py` writes into whichever x86 directory it is given.

`perf_results/` contains:

```
perf_results/
  perf_matrix_x86.csv       parsed perf counters, liboqs 0.15.0, 36 rows
  perf_matrix_arm.csv
  perf_matrix_x86_016.csv   parsed perf counters, liboqs 0.16.0, 30 rows (PQC only)
  perf_matrix_arm_016.csv
  concurrency_x86.csv       throughput sweep, K = 1,2,4,8
  concurrency_arm.csv       throughput sweep, K = 1,2,4
  concurrency_x86.log       progress log of the x86 sweep (no ARM counterpart committed)
  results_016/
    results_pqc_x86_016.csv   1,000-iteration PQC latency under liboqs 0.16.0
    results_pqc_arm_016.csv
```

The `_016` captures were taken with a liboqs 0.16.0 build kept outside this tree:
the `perf stat` headers in `perf_stat_raw/{x86,arm}_016/` record the binary as
`./liboqs016-bin/bench_pqc_fast`, which is `run_perf_matrix_016.sh`'s default
argument 2 and is not committed. The unsuffixed captures record `./bench_pqc_fast`,
built against the 0.15.0 install that `environment.txt` in both primary-round
directories reports.

## Building

Tested on Ubuntu 22.04 and equivalents. The same procedure is used on both platforms.

**System packages:**

```sh
sudo apt-get install -y build-essential cmake ninja-build libssl-dev pkg-config git
```

liboqs. The paper's numbers come from liboqs 0.16.0 at commit `5a1a854`, so clone
in full, not shallowly and check that commit out:

```sh
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && git checkout 5a1a854 && cd ..
cmake -S liboqs -B liboqs/build \
      -DCMAKE_INSTALL_PREFIX=$HOME/liboqs-install \
      -DOQS_DIST_BUILD=ON -GNinja
cmake --build liboqs/build --parallel
cmake --install liboqs/build
```

`-DOQS_DIST_BUILD=ON` enables runtime CPU dispatch to optimized code paths where they
exist. liboqs compiles itself at `-O3` independently of the harness's `-O2`.

The harnesses. The Makefile reads `OQS_PREFIX`, defaulting to
`$HOME/liboqs-install`. Override it if liboqs is installed elsewhere:

```sh
cd Benchmarking-Master
make                          # builds bench_pqc and bench_classical
make OQS_PREFIX=/usr/local    # if liboqs went to a system prefix
```

There is also a `fast` target building both binaries with `N_ITERATIONS=100` and
`WARMUP_ITERS=5`, used for the `perf stat` and concurrency sweeps:

```sh
make fast                     # bench_pqc_fast, bench_classical_fast
```

## Running

Primary round (1,000 iterations per operation):

```sh
make run                      # writes results_{pqc,classical}_x86.csv
make run PLATFORM=arm         # writes results_{pqc,classical}_arm.csv
```

`PLATFORM` defaults to `x86` and only tags the output filenames; it changes nothing
about the measurement. Use `PLATFORM=arm` on the ARM host, since `analyze.py` expects
the ARM directory to contain `results_pqc_arm.csv` and `results_classical_arm.csv`.
Each target also writes a per-iteration `..._raw.csv` beside the aggregate file.

Or run the binaries directly, naming both outputs yourself:

```sh
./bench_pqc        results_pqc_arm.csv        results_pqc_arm_raw.csv
./bench_classical  results_classical_arm.csv  results_classical_arm_raw.csv
```

Both binaries accept two further optional arguments, an algorithm name and one of
`keygen` / `sign` / `verify`, which restrict the run to a single timed block for
profiling. The algorithm name is the liboqs identifier (`ML-DSA-65`,
`SLH_DSA_PURE_SHA2_128S`, …) for `bench_pqc`, and `RSA-3072` or `ECDSA-P256` for
`bench_classical`.

For the full driver, environment capture, optional governor pinning, both
benchmarks and a merged CSV, use the shell runners instead:

```sh
sudo ./run_benchmark.sh       # x86; without sudo the governor is left alone
./run_arm_benchmark.sh <tag>  # Pi; no governor pinning, logs temperature at 5 s
```

Two things to know before using them. `run_arm_benchmark.sh` hardcodes the paths of
the Pi it was written for: it runs the binaries from `$HOME/Benchmarking`, expects
liboqs under `$HOME/liboqs-install`, writes to `$HOME/Benchmarking/results_<tag>/`,
and calls `vcgencmd`. And `run_benchmark.sh` labels its output from `uname -m`, so it
writes `results_pqc_x86_64.csv` / `results_pqc_aarch64.csv`, whereas `analyze.py`
loads `results_pqc_x86.csv` / `results_pqc_arm.csv`. The committed result directories
use the short names; rename the files, or use `make run PLATFORM=…` above, before
running the analysis.

Extended round (300 ms warmup, single-core pinning, ASLR disabled). This round
lives in `Benchmarking-Extended/`, which is a separate harness; see *The two
harnesses* above. One entry point runs the whole pass:

```sh
cd Benchmarking-Extended
./run_full_suite.sh     [oqs_prefix]              # x86,  defaults to $HOME/liboqs-install
./run_full_suite_arm.sh [oqs_prefix] [liboqs_src] # ARM,  defaults to $HOME/liboqs-016-opt-install
```

Both scripts pin every single-threaded stage identically:

```sh
RUN_PINNED="setarch $(uname -m) -R taskset -c 1"
```

`setarch -R` disables ASLR for the child, `taskset -c 1` confines it to one core. The
thread-scaling sweep of Section 5.4 is deliberately left unpinned so the scheduler can
place workers freely, which is why it is invoked without `$RUN_PINNED`.

Each suite runs, in order: `capture_environment.sh` (liboqs commit, library versions,
microcode revision, governor); `monitor_system.sh` in the background at 1 Hz for the
whole pass (frequency, temperature, `vcgencmd get_throttled` on the Pi); the three
canonical latency binaries under `$RUN_PINNED`; `bench_mem_isolated`; the thread
scaling sweep; and the message-size sweep. Stages log separately under the output
directory so a crash partway leaves everything collected up to that point on disk.

What the extended harness adds over the primary one: a 300 ms time-bounded warmup
(`WARMUP_MS_DURATION`) instead of a fixed 20 iterations; `CLOCK_PROCESS_CPUTIME_ID`
sampled alongside `CLOCK_MONOTONIC` every iteration; per-iteration cycle counts; a
measured timer-overhead figure printed per run (`log_timer_overhead()`); 17 PQC
parameter sets including the six `f` variants and SLH-DSA-SHAKE-192s; a fourth
operation, `verify_invalid`, timing verification of a single-byte-corrupted signature;
stack high-water measurement by canary; and isolated per-process peak RSS.

One wart, left as it ran, uncorrected: `run_full_suite.sh` line 38 hardcodes
`LIBOQS_SRC` to a scratch path that no longer exists. It is passed only to
`capture_environment.sh`, so it affects the recorded environment metadata, not any
measurement. Pass the right source path there, or ignore the resulting warning.

Multi-threaded scaling. Two different sweeps exist in this repository and they are
easy to confuse.

*Thread-level, and the source of Table 6.* `run_thread_scaling.sh` in
`Benchmarking-Extended/`, which drives `bench_pqc_threaded` / `bench_classical_threaded`:

```sh
cd Benchmarking-Extended
make threaded
./run_thread_scaling.sh results/thread_scaling_x86.csv 1,2,3,4,5,6 200   # x86: 6 physical cores
./run_thread_scaling.sh results/thread_scaling_arm.csv 1,2,3,4     200   # ARM: 4 physical cores
```

Arguments are the output CSV, the thread-count list, and iterations per thread. Each
binary spawns T pthreads inside one process, all blocking on a `pthread_barrier`
that main also joins, so staggered setup never enters the timed window. Eight
(algorithm, operation) jobs are fixed in the script's `JOBS` array: RSA-3072,
ML-DSA-65, Falcon-1024 and SLH-DSA-SHA2-128s, each swept for both `sign` and `verify`.
Parallel efficiency is not written by the script; compute it post hoc as
`throughput(T) / (T × throughput(1))` grouped by (algorithm, operation).

*Process-level, and NOT the source of Table 6.* The older
`run_concurrency_scaling.sh` in `Benchmarking-Master/`, which produced
`perf_results/concurrency_{arm,x86}.csv`:

```sh
make fast                                                       # bench_*_fast, N=100
./run_concurrency_scaling.sh perf_results/concurrency_x86.csv 1,2,4,8
./run_concurrency_scaling.sh perf_results/concurrency_arm.csv 1,2,4
```

The second argument is the comma-separated list of concurrency levels; it defaults to
`1,2,4,8`, which is what the committed x86 file covers, against `1,2,4` for ARM. For
each level the script launches K copies of the op-isolated `_fast` binary as
background processes, waits for all of them, and divides `K x 100` operations by the
elapsed wall time. The four algorithms swept are fixed in the script's `JOBS` array
(RSA-3072, ML-DSA-65, Falcon-1024 and SLH-DSA-SHA2-128s, signing only), and each copy
writes throwaway CSVs under `/tmp`.

These two sweeps measure different things and their numbers are not interchangeable.
The process-level one launches K separate OS processes and times them from the
outside, so process startup, warmup and teardown all fall inside the measured window;
at K=1 that overhead dominates, which is why its implied efficiencies exceed 100%
(191.9% for RSA-3072 at K=2). Its single-thread x86 RSA-3072 signing figure is
349.5 ops/s against Table 6's 1,932 ops/s, and it sweeps K=8 where Table 6 reports
T=6. It is retained as a valid process-level result and as the record of what was run
first; it is not the source of Table 6, and should not be quoted as one.

Analysis. With result CSVs present for both platforms:

```sh
python3 analyze.py <x86_results_dir> <arm_results_dir>
```

Given only the x86 directory it stops after printing the x86 table, which is useful
for validating a build before the second platform is measured. Requires `pandas`,
`matplotlib` and `numpy`.

## Reproducing the vectorization ablation

The same liboqs commit is built twice, differing only in whether vectorized backends are compiled in.

Both builds are performed by `Benchmarking-Extended/build_liboqs_variant.sh`, which is
the script that produced the published pair:

```sh
cd Benchmarking-Extended
./build_liboqs_variant.sh ref       ~/liboqs-016 ~/liboqs-016-ref-install
./build_liboqs_variant.sh optimized ~/liboqs-016 ~/liboqs-016-opt-install
```

Run it once per variant per platform. It does not cross-compile, so x86 and ARM
each need their own `ref` + `optimized` pair. It writes a `.liboqs_variant` marker
into each prefix recording which variant that prefix holds and when it was built.

Optimized build, as shipped. One flag:

```
-DOQS_DIST_BUILD=ON
```

This compiles in both the portable-C and the platform-optimized backends, with a
runtime `OQS_CPU_has_extension()` check inside each compiled function deciding which
executes. It is the same configuration used for every other result in this study.

Reference build, backends forced off. Twelve derived flags in addition to the one
that is supposed to gate them:

```
-DOQS_DIST_BUILD=OFF
-DOQS_DIST_X86_64_BUILD=OFF
-DOQS_DIST_ARM64_V8_BUILD=OFF
-DOQS_USE_AVX2_INSTRUCTIONS=OFF
-DOQS_USE_AVX512_INSTRUCTIONS=OFF
-DOQS_USE_BMI1_INSTRUCTIONS=OFF
-DOQS_USE_BMI2_INSTRUCTIONS=OFF
-DOQS_USE_POPCNT_INSTRUCTIONS=OFF
-DOQS_USE_AES_INSTRUCTIONS=OFF
-DOQS_USE_ARM_NEON_INSTRUCTIONS=OFF
-DOQS_USE_ARM_AES_INSTRUCTIONS=OFF
-DOQS_USE_ARM_SHA2_INSTRUCTIONS=OFF
-DOQS_USE_ARM_SHA3_INSTRUCTIONS=OFF
-DOQS_USE_SHA3_AVX512VL=OFF
```

`-DOQS_DIST_BUILD=OFF` on its own is not sufficient, which is the single most
important thing to know about reproducing this experiment. In this liboqs version the
per-architecture variables it is supposed to gate (`OQS_DIST_X86_64_BUILD` /
`OQS_DIST_ARM64_V8_BUILD`, which `.CMake/alg_support.cmake` consumes to decide whether
e.g. `OQS_ENABLE_SIG_ml_dsa_65_x86_64` is turned on) do not reliably end up `OFF` from
it alone: a first attempt built `ml_dsa_65` with its AVX2 backend compiled in despite
`OQS_DIST_BUILD=OFF`. Forcing every derived flag explicitly is what actually works.

`CMAKE_BUILD_TYPE` is deliberately left unset in both variants, matching every other
liboqs build in this study: with no override, liboqs's own top-level `CMakeLists.txt`
defaults it to `Release`, which is where the `-O3` documented in the Methodology comes
from. Only `OQS_DIST_BUILD` and its derived flags differ between the two.

Verifying the ablation took effect. Do not trust the flags alone, check the built
library for the backend symbols:

```sh
nm -g --defined-only <prefix>/lib/liboqs.a | grep -ciE 'aarch64|neon'   # ARM
nm -g --defined-only <prefix>/lib/liboqs.a | grep -ciE 'avx2|x86_64'    # x86
```

On the ARM pair this returns 0 for `ref` against 2,324 for `optimized`, with
the archive itself 15 MB against 19 MB. A `ref` build that still reports backend
symbols has hit the gating problem described above.

The harness side is `make fast` in `Benchmarking-Extended` built against each prefix
in turn, giving `bench_pqc_fast_ref` and `bench_pqc_fast_opt`; N = 100 iterations per
cell, as the paper states. Table 3 is then `ref ÷ opt` of the `mean_cycles` column,
per (algorithm, operation).

Note that the reference baseline is portable C which each platform's compiler still auto-vectorizes, and the two compilers differ, so cross-ISA comparison of these gains carries a compiler confound as well as an ISA one. SLH-DSA's residual movement across the two builds (1 to 2% on x86, up to 30% for SHAKE on ARM) bounds the experiment's own resolution, and is the yardstick for reading the lattice rows.

## Data files

Files in `perf_results/` are named `<measurement>_<platform>[_<liboqs version>].csv`.
The version suffix matters: files carrying `_016` are liboqs 0.16.0, and
those without it are 0.15.0. The difference between the two is what isolates the
coverage term in the ML-DSA-65 decomposition, since 0.16.0 replaced ML-DSA's backend
with `mldsa-native` while leaving every other family unchanged.

| Paper table | Produced by | Raw data |
|---|---|---|
| Table 2, cross-platform latency | `Benchmarking-Master/analyze.py` | PQC rows: `results_016/results_pqc_{x86,arm}_016.csv`; classical rows: `results_{x86,arm}_2026*/results_classical_{x86,arm}.csv` |
| Table 3, vectorization gain | `Benchmarking-Extended/build_liboqs_variant.sh` + `bench_pqc_fast` built against each prefix | `Benchmarking-Extended/results/refopt_clean_{x86,arm}/{ref,opt}_<algorithm>.csv`, `mean_cycles` column |
| Table 4, instruction counts and IPC | `Benchmarking-Master/parse_perf_matrix.py` | PQC rows: `perf_matrix_{arm,x86}_016.csv`; classical rows: `perf_matrix_{arm,x86}.csv` |
| Table 5, stack high-water | `Benchmarking-Extended/bench_mem_isolated` | `mem_isolated.csv` from each full-suite run (held outside the repository) |
| Table 6, parallel efficiency | `Benchmarking-Extended/run_thread_scaling.sh` driving `bench_{pqc,classical}_threaded` | `Benchmarking-Extended/results/thread_scaling_{x86,arm}.csv` |

Every cell of all five tables was recomputed from these files. All match the printed
values except one cell of Table 6, described below. Specifics worth recording:

- Table 2 verifies, but against a mix of two sources. Every classical cell matches
  the primary-round CSVs (RSA-3072 x86 keygen 110.476464 → 110.48, ARM sign 15.323470
  → 15.32). Every PQC cell matches the `_016` files, not the PQC CSVs in the
  primary-round directories: ARM ML-DSA-65 signing is 0.614867 in
  `results_pqc_arm_016.csv` against 1.522127 in `results_pqc_arm.csv`, and the table
  prints 0.615. That is the version split described above, the primary-round
  directories are liboqs 0.15.0, so reproducing Table 2 means loading the `_016`
  PQC files together with the 0.15.0 classical files. `analyze.py` cannot do that in
  one invocation: it looks for `results_pqc_<suffix>.csv` and
  `results_classical_<suffix>.csv` in the same directory, and `results_016/` holds no
  classical file. Pointed at the two primary-round directories it reproduces the
  0.15.0 comparison, which is what `slowdown_ratios.csv` and the committed chart show.
- Table 4 verifies, with the same split. RSA-3072 (instruction ratio 1.61, IPC
  2.95 / 0.91) and ECDSA-P256 (1.08, 2.47 / 1.01) match `perf_matrix_{arm,x86}.csv`;
  the PQC rows match `perf_matrix_{arm,x86}_016.csv` (ML-DSA 1.41–1.97 against
  5.53–6.40 in the unsuffixed files, SLH-DSA-SHAKE x86 IPC 5.29–5.31 against
  5.16–5.32). Both files are needed, since the `_016` sweep covers PQC only.
- Table 3 reproduces exactly, all 42 cells, as `ref ÷ opt` of `mean_cycles` per
  (algorithm, operation) across the 7 algorithms and 2 platforms, for example
  Falcon-512 x86 signing at 23.43x and SLH-DSA-SHAKE-128s ARM keygen at 0.77x.
- Table 5 reproduces exactly, all 12 ranges, as the min and max of
  `stack_hwm_bytes` grouped by (family, library, platform), including the 12-variant
  SLH-DSA groupings and the constant 6,280 B for OpenSSL's ML-DSA on x86.
- Table 6 reproduces in 55 of its 56 cells: all 40 efficiency cells and 15 of the
  16 single-thread throughputs. x86 RSA-3072 signing is 1932.042 ops/s → the printed
  1,932; ML-DSA-65 verification 54046.137 → 54,046. Section 5.4's ARM
  SLH-DSA-SHA2-128s series (0.855, 1.712, 2.567, 3.408 ops/s at T=1–4) is the
  `throughput_ops_per_sec` column verbatim. The exception is ARM ML-DSA-65 signing
  at T=1, printed as 1,784 where the data gives 1783.464, a last-digit
  discrepancy of 0.03%, recorded here for completeness. It is a
  transcription slip rather than a different derivation: rounding the
  `throughput_ops_per_sec` column reproduces the other 15 cells exactly, while the
  plausible alternative of `1000 / mean_latency_ms` disagrees with 10 of the 16.
  Nothing depends on it, that row's efficiency figures are ratios and come out at
  92% and 94% from either baseline.
- Table 6 is not the committed `concurrency_{arm,x86}.csv`, which is the earlier
  process-level sweep kept in `Benchmarking-Master/perf_results/`. That file's x86
  single-thread RSA-3072 signing is 349.5 ops/s against Table 6's 1,932; its implied
  efficiencies exceed 100% (191.9% for RSA-3072 at K=2, 176.7% for ML-DSA-65) because
  the K=1 baseline is dominated by process startup that amortizes at higher K; and it
  sweeps K=8 where Table 6 reports T=6. Only the SLH-DSA-SHA2-128s rows come close,
  startup being negligible against 33 s of signing per copy on x86 and 123 s on ARM
  (0.814/1.626/3.240 ops/s on ARM at K=1/2/4 against 0.855/1.712/3.408 at T=1/2/4),
  and even those differ by about 5%. The committed CSVs are a valid
  process-level throughput measurement; they are not the source of Table 6.

`analyze.py` also writes `slowdown_ratios.csv` into the ARM directory, and a
slowdown bar chart saved as `fig_slowdown_ratio.png`. It prints the per-family
ratio bands quoted in Section 5.1.

### Column reference

Aggregate latency CSVs, `results_{pqc,classical}_{x86,arm}.csv` and
`results_016/results_pqc_{x86,arm}_016.csv`. Written by `csv_write_row()` in
`benchmark.h`. One row is one (algorithm, operation) pair, summarizing
`N_ITERATIONS` timed samples (1,000 in these files).

| Column | Meaning | Units |
|---|---|---|
| `algorithm` | display name; PQC rows carry a parenthetical former name, e.g. `ML-DSA-65 (Dilithium3)`, which `analyze.py` strips |  |
| `security_level` | NIST level `1`/`2`/`3`/`5`, or `classical` for RSA and ECDSA |  |
| `operation` | `keygen`, `sign` or `verify` |  |
| `mean_ms` | arithmetic mean of the timed samples | ms |
| `median_ms` | median of the sorted samples | ms |
| `std_ms` | population standard deviation (divides by n, not n−1) | ms |
| `p95_ms`, `p99_ms` | nearest-rank percentiles: index `ceil(q·n)−1` of the sorted samples | ms |
| `peak_mem_delta_kb` | `ru_maxrss` after the timed block minus before it, via `getrusage(RUSAGE_SELF)`. A high-water mark, so `0` means the block never pushed the process above its prior peak, not that the block allocated nothing | kB |
| `pub_key_bytes`, `priv_key_bytes` | liboqs `length_public_key` / `length_secret_key`. For the classical rows these are constants declared in `bench_classical.c` (RSA 384 / 1679, P-256 65 / 121), not measured | bytes |
| `sig_bytes` | on `keygen` rows, the algorithm's declared maximum signature length; on `sign` and `verify` rows, the length actually produced. This is why the three rows of one variable-length algorithm disagree, Falcon-512 reads 752 / 653 / 651 | bytes |

Raw per-iteration CSVs, `..._raw.csv`, written by `write_raw_samples()`.
One row is one timed iteration.

| Column | Meaning | Units |
|---|---|---|
| `algorithm`, `operation` | as above |  |
| `iteration` | 0-based index within that operation's timed block, in execution order |  |
| `ms` | that single sample's elapsed time, `CLOCK_MONOTONIC` around the cryptographic call only | ms |

Hardware counter CSVs, `perf_matrix_{arm,x86}[_016].csv`, written by
`parse_perf_matrix.py` from the captures in `perf_stat_raw/`. One row is one
`perf stat` run of the `_fast` binary restricted to one (algorithm, operation).
Counts are whole-process, user-space totals (the captures record `:u` events), so
they include process startup, the 5 warmup iterations and the 100 timed ones, not a
per-iteration figure. The paper flags the one row where that matters, RSA-3072, whose
setup keygen is as expensive as the timed signing.

| Column | Meaning | Units |
|---|---|---|
| `algorithm` | liboqs identifier as passed to the binary, e.g. `SLH_DSA_PURE_SHA2_128S` (underscored, unlike the latency CSVs' display names) |  |
| `operation` | `keygen`, `sign` or `verify` |  |
| `instructions`, `cycles` | `instructions:u`, `cycles:u` | events |
| `ipc` | `instructions / cycles`, computed by the parser, 4 dp |  |
| `cache_references`, `cache_misses` | `cache-references:u`, `cache-misses:u` | events |
| `cache_miss_rate` | `cache_misses / cache_references`, computed by the parser, 6 dp | fraction |
| `branch_misses` | `branch-misses:u` | events |

Concurrency CSVs, `concurrency_{arm,x86}.csv`, written by
`run_concurrency_scaling.sh`. One row is one (algorithm, K) point.

| Column | Meaning | Units |
|---|---|---|
| `algorithm` | one of the four labels fixed in the script's `JOBS` array; signing only |  |
| `K` | number of concurrent *processes* launched |  |
| `wall_seconds` | elapsed time around the whole batch: from just before the first launch to after `wait` returns. Includes process spawn, warmup and teardown | s |
| `total_ops` | `K × 100`, the script's `N_PER_COPY` | operations |
| `throughput_ops_per_sec` | `total_ops / wall_seconds` | ops/s |

Slowdown ratios, `slowdown_ratios.csv`, written by `analyze.py` into the ARM
directory. One row is one (algorithm, operation) pair present on both platforms,
with `mean_ms_x86`, `mean_ms_arm` (ms) and `ratio` = `mean_ms_arm / mean_ms_x86`.

Thread-scaling CSVs, `Benchmarking-Extended/results/thread_scaling_{x86,arm}.csv`,
written by `bench_{pqc,classical}_threaded` (appending, one row per invocation).
One row is one (algorithm, operation, thread count) point. Note the column is
`workers`, not `threads`, and that these are threads in one process, unlike the
`K` of the process-level `concurrency_*.csv`, which counts separate processes.

| Column | Meaning | Units |
|---|---|---|
| `algorithm` | display name, carrying the parenthetical former name for PQC rows |  |
| `operation` | `sign` or `verify` (this sweep covers both, unlike the process-level one) |  |
| `workers` | T, the number of pthreads spawned in the single process |  |
| `iters_per_worker` | operations each thread performs after the barrier releases (200 in the committed files) |  |
| `wall_seconds` | elapsed time of the timed region only: from the barrier release to the last join. Thread creation and per-thread setup happen before the barrier and are excluded | s |
| `total_ops` | `workers × iters_per_worker` | operations |
| `throughput_ops_per_sec` | `total_ops / wall_seconds`, the Table 6 `T=1` column, and the basis of every efficiency figure | ops/s |
| `mean_latency_ms` | mean per-operation latency under contention at this thread count | ms |

Parallel efficiency is not a column; compute it as
`throughput(T) / (T × throughput(1))` within each (algorithm, operation) group.

Ablation CSVs, `Benchmarking-Extended/results/refopt_clean_{x86,arm}/`. Four
files per (variant, algorithm), where variant is `ref` or `opt`:

- `<variant>_<algorithm>.csv`, the aggregate, one row per operation. Carries the
  primary-round columns plus five cycle columns and an energy column. Table 3 is
  `ref ÷ opt` of `mean_cycles`.
- `<variant>_<algorithm>_raw.csv`, one row per iteration: `algorithm`,
  `operation`, `iteration` (0-based), `cycles`, `ms` (wall), `cpu_ms`
  (`CLOCK_PROCESS_CPUTIME_ID` for the same iteration, so wall−cpu isolates
  preemption), `sig_len` (bytes, `-1` where not applicable), `epoch_start`.
- `<variant>_<algorithm>.csv.stack_hwm_bytes`, a single integer, the stack
  high-water mark in bytes for that run.
- `<variant>_<algorithm>.log`, the binary's stdout, including the measured timer
  overhead for that run.

Two columns need care.

`mean_cycles` and its siblings are per-iteration counts read from the cycle
counter around the cryptographic call, unlike the whole-process totals in
`perf_matrix_*.csv`. Table 3 divides these.

`mean_energy_uj` is `-1.000` in every committed row on both platforms, and is not a
measurement. `-1` is the harness's uniform "counter unavailable" sentinel
(`read_energy_uj()` returns it whenever the counter could not be opened), and the
accompanying run logs print `energy=n/a` on every line. It reads `-1` for a different
reason on each platform: on x86 the source is the RAPL package counter at
`/sys/class/powercap/intel-rapl:0/energy_uj`, which exists on that host but is mode
`0400` root-only, and the harness ran unprivileged; on ARM the source is an INA219
shunt monitor, which was not attached. No energy figure appears anywhere in the
paper, energy-per-operation profiling is explicitly listed in Section 7 as future
work, scoped out, never measured. Anyone deriving energy numbers from this column
would be reading sentinels; don't.

Figures. The paper itself contains no figures: `Paper.pdf` embeds no images and
its text refers to no numbered figure, only to Tables 1–6. Both committed PNGs are
artifact outputs rather than paper exhibits, and nothing here regenerates them in
place:

- `fig_tail_variance.png` is written by `plot_tail_variance.py` into the x86 results
  directory it is given. The copy at the top of `Benchmarking-Master/` is byte-identical
  to the one in `results_x86_20260803_145226/`.
- `fig9_slowdown_ratio.png` is `analyze.py`'s chart under a different name, the script
  always saves to `<arm_dir>/fig_slowdown_ratio.png`, and no file by that name is
  committed. Title, axis label, per-operation colours, legend and bar ordering all
  match the script's output for the primary-round (0.15.0) CSVs, down to ML-DSA-65
  signing sitting second behind RSA-3072 signing, which is the 0.15.0 ordering and not
  the 0.16.0 one. The `fig9` prefix numbers it in some other document; there is no
  figure 9, or figure 1–8, in this paper.

Python dependencies. `pip install -r Benchmarking-Master/requirements.txt`
(`pandas`, `matplotlib`, `numpy`; `parse_perf_matrix.py` needs only the standard
library). The pins are a known-good set rather than a record of the versions used for
the published runs, which were not captured.

## What can be reproduced from this repository

Three different things get called "reproducible", so they are separated here.

Recomputable from committed data, no hardware needed. Every cell of Tables 2, 3,
4, 5 and 6 can be recalculated from files in this repository, except Table 5's, whose
source `mem_isolated.csv` is held outside it (the derivation is one `min`/`max` over
`stack_hwm_bytes` grouped by family, library and platform). All of these were checked
against the printed tables while this README was written. Every cell matches except
one in Table 6, documented under the table mapping above: a 0.03% last-digit
discrepancy in a single throughput figure, which changes nothing that depends on it.

Re-measurable on comparable hardware. The harnesses, drivers and both liboqs build
recipes are complete, so the experiments can be re-run end to end on any x86_64 and
AArch64 pair. Absolute latencies will differ with the hardware; the ratios the paper
argues from should not, and the ablation's `nm` check gives an independent way to
confirm a reference build really has its backends removed before trusting its numbers.

Not re-measurable in the recorded state. The ARM platform of Table 1 no longer
exists as described: that Raspberry Pi 4B now runs kernel 6.18.39, against the 6.12
recorded for the measurements, with the toolchain and OpenSSL moved accordingly. The
x86 host has likewise been updated since. A re-run today measures a different software
environment on the same silicon, which is adequate for the architectural ratios and
not adequate for reproducing a specific millisecond figure. The 15.4-hour ARM thermal
session of Section 5.5 in particular cannot be re-collected under the original kernel.

Two further gaps, stated so nobody looks for them: the liboqs source trees and build
directories used for the published builds were working copies on the two machines and
are not archived here, so `build_liboqs_variant.sh` must be pointed at a fresh clone
of `5a1a854`; and the full-suite output directories are excluded for bulk, so
Section 5.5's message-size and thermal series are quoted from the paper rather than
recomputable here.

## Limitations

As stated in the paper.

- Each number derives from a single run of 1,000 iterations rather than repeated independent runs. No confidence intervals are reported, and the vectorization ablation (N=100) carries no variance estimate. Small differences between adjacent cells should not be over-read.
- One hardware exemplar represents each architecture, with SMT enabled on x86 and the default `ondemand` governor on ARM.
- Clock normalization assumes clock-bound execution and overcorrects for any memory-bound component.
- The corruption test flips one byte at one position. That establishes no family short-circuits, but does not characterize structurally malformed input.
- The OpenSSL ML-DSA stack figure is constant across all operations and levels, consistent with heap allocation but possibly meaning the canary probe does not reach that library's frames. The liboqs-versus-OpenSSL stack contrast is therefore provisional.
- The x86 drop in parallel efficiency above four threads is reported as a limitation rather than corrected for. Confirming the SMT explanation requires re-measurement with SMT disabled.

## Citation

```bibtex
@inproceedings{braz2026architectural,
  author    = {Braz, Victor H. and Souza, Matheus A.},
  title     = {An Architectural Performance Evaluation of Post-Quantum and
               Classical Digital Signature Algorithms on x86 and ARM},
  booktitle = {Simp\'osio em Sistemas Computacionais de Alto Desempenho (SSCAD)},
  year      = {2026},
  note      = {Under review}
}
```

A machine-readable `CITATION.cff` matching this entry is in the repository root.

## License

MIT, see [LICENSE](LICENSE). The benchmark harnesses, drivers, analysis scripts and
measurement data in this repository are covered by it; liboqs and OpenSSL, which the
harnesses link against, carry their own licenses.
