/**
 * bench_pqc.c
 * Benchmarks CRYSTALS-Dilithium, FALCON, and SPHINCS+ using liboqs.
 *
 * Build:
 *   gcc -O2 -o bench_pqc bench_pqc.c -I/usr/local/include \
 *       -L/usr/local/lib -loqs -lm
 *
 * Usage:
 *   ./bench_pqc [output.csv]
 *   Default output file: results_pqc_x86.csv
 */

/* Must precede every system header in this translation unit: liboqs's own
 * headers (included below) pull in pthread.h before benchmark.h gets a
 * chance to, and glibc locks in feature-test-macro-gated declarations
 * (pthread_getattr_np, used by benchmark.h's stack-HWM helpers) at first
 * inclusion — defining it later would be too late. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>

#include "benchmark.h"
#include "algo_table.h"

/* ── Runtime backend-dispatch logging ────────────────────────────────────────
 * OQS_CPU_has_extension() is the exact same public API liboqs's own compiled
 * dispatch code calls internally (verified by reading sig_ml_dsa_65.c and
 * sig_falcon_512.c in liboqs 0.16.0 before writing this): each optimized
 * keypair/sign/verify function is wrapped in
 *   #if defined(OQS_DIST_BUILD)
 *     if (OQS_CPU_has_extension(...)) { <optimized path> } else { <ref path> }
 *   #endif
 * so calling it here from outside liboqs, at process start, reproduces
 * liboqs's own dispatch decision exactly — no source reading required to
 * know which backend a given run actually used; the log line below is
 * direct empirical evidence of it, not an inference from source or from
 * which liboqs release happened to be installed.
 *
 * Important subtlety, found by reading common.c (OQS_CPU_has_extension's
 * own implementation) rather than assumed: in a non-DIST build the function
 * is a stub that unconditionally returns 0 — it never runs the real cpuid /
 * getauxval detection (set_available_cpu_extensions()), because a non-DIST
 * build has no optimized path to branch to regardless of what it would
 * find. So "AVX2=0" from a ref build does NOT mean "this CPU lacks AVX2",
 * it means "detection is compiled out in this build". The installed
 * oqsconfig.h #defines OQS_DIST_BUILD only when linked against a DIST
 * build, which lets this function tell the two cases apart honestly
 * instead of printing a misleading "0" either way.
 *
 * ML-DSA and Falcon check different extension sets (confirmed from source):
 * ML-DSA requires AVX2+BMI2+POPCNT on x86, Falcon requires AVX2 alone. Both
 * require ARM_NEON on ARM. */
static void log_cpu_dispatch(void) {
#if !defined(OQS_DIST_BUILD)
    printf("  CPU dispatch   : reference-only build (OQS_DIST_BUILD off) —\n");
    printf("                   optimized backends are not compiled in; every\n");
    printf("                   call below is unconditionally the portable path.\n");
#elif defined(__x86_64__) || defined(__i386__)
    int avx2   = OQS_CPU_has_extension(OQS_CPU_EXT_AVX2);
    int bmi2   = OQS_CPU_has_extension(OQS_CPU_EXT_BMI2);
    int popcnt = OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT);
    printf("  CPU dispatch   : optimized build, real cpuid read: AVX2=%d BMI2=%d POPCNT=%d\n",
           avx2, bmi2, popcnt);
    printf("                   -> ML-DSA dispatches to: %s\n",
           (avx2 && bmi2 && popcnt) ? "x86_64-optimized (AVX2 asm)" : "portable reference (C)");
    printf("                   -> Falcon dispatches to: %s\n",
           avx2 ? "avx2-optimized" : "portable reference (clean)");
#elif defined(__aarch64__)
    int neon = OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON);
    printf("  CPU dispatch   : optimized build, real getauxval read: ARM_NEON=%d\n", neon);
    printf("                   -> ML-DSA dispatches to: %s\n",
           neon ? "aarch64-optimized (NEON asm)" : "portable reference (C)");
    printf("                   -> Falcon dispatches to: %s\n",
           neon ? "aarch64-optimized" : "portable reference (clean)");
#else
    printf("  CPU dispatch   : unknown architecture, cannot query extensions\n");
#endif
}

/* ── Benchmark one algorithm ─────────────────────────────────────────────── */

static void bench_algorithm(const AlgoEntry *entry, FILE *csv, FILE *raw_csv,
                             const char *only_op, int cycle_fd, FILE *energy_fp) {

    printf("\n[%s]  (NIST Level %s)\n",
           entry->display_name, entry->security_level);

    /* initialise the OQS signature object */
    OQS_SIG *sig = OQS_SIG_new(entry->oqs_name);
    if (!sig) {
        fprintf(stderr, "  WARNING: %s not available in this build — skipping.\n",
                entry->oqs_name);
        return;
    }

    /* allocate key and signature buffers */
    uint8_t *pub_key  = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *priv_key = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *signature= (uint8_t *)malloc(sig->length_signature);
    uint8_t  message[MESSAGE_LEN];
    size_t   sig_len = 0;

    if (!pub_key || !priv_key || !signature) {
        perror("malloc");
        OQS_SIG_free(sig);
        return;
    }

    /* fill message with deterministic dummy data */
    for (int i = 0; i < MESSAGE_LEN; i++) message[i] = (uint8_t)(i & 0xFF);

    uint64_t *samples         = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cycle_samples   = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cpu_samples     = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    int      *sig_len_samples = (int *)malloc(N_ITERATIONS * sizeof(int));
    if (!samples || !cycle_samples || !cpu_samples || !sig_len_samples) { perror("malloc"); exit(1); }

    OQS_STATUS rc;
    uint64_t t0, t1, c0, c1, cpu0, cpu1;
    long mem_before, mem_after;
    long long energy_before, energy_after;
    double mean_energy_uj, epoch_start;
    Stats st;
    CycleStats cst;

    /* only_op isolates one timed block for perf-stat profiling; the cheap
     * untimed setup calls each later block depends on still run so results
     * stay correct regardless of which block is skipped. */
    int do_keygen = !only_op || strcmp(only_op, "keygen") == 0;
    int do_sign   = !only_op || strcmp(only_op, "sign")   == 0;
    int do_verify = !only_op || strcmp(only_op, "verify") == 0;
    int do_verify_invalid = !only_op || strcmp(only_op, "verify_invalid") == 0;

    /* ── KeyGen ──────────────────────────────────────────────────────────── */

    if (do_keygen) {
        WARMUP_FOR(OQS_SIG_keypair(sig, pub_key, priv_key));

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            TIMED_ITERATION(rc = OQS_SIG_keypair(sig, pub_key, priv_key));
            if (rc != OQS_SUCCESS) {
                fprintf(stderr, "  KeyGen failed at iteration %d\n", i);
                break;
            }
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(entry->display_name, "keygen", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv,
            entry->display_name, entry->security_level, "keygen",
            cst, st, mem_after - mem_before, mean_energy_uj,
            (int)sig->length_public_key,
            (int)sig->length_secret_key,
            (int)sig->length_signature);
        write_raw_samples(raw_csv, entry->display_name, "keygen",
            cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    /* ── Sign ────────────────────────────────────────────────────────────── */

    if (do_sign || do_verify || do_verify_invalid) {
        /* generate one key pair to use for all sign iterations (and, if
         * verify is isolated on its own, to have a valid key to sign with) */
        OQS_SIG_keypair(sig, pub_key, priv_key);
    }

    if (do_sign) {
        WARMUP_FOR(OQS_SIG_sign(sig, signature, &sig_len, message, MESSAGE_LEN, priv_key));

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            TIMED_ITERATION(rc = OQS_SIG_sign(sig, signature, &sig_len,
                              message, MESSAGE_LEN, priv_key));
            if (rc != OQS_SUCCESS) {
                fprintf(stderr, "  Sign failed at iteration %d\n", i);
                break;
            }
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;
            sig_len_samples[i] = (int)sig_len; /* Falcon's length varies per
                                                   call — this is what makes
                                                   the size distribution, not
                                                   just a single mean/max */
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(entry->display_name, "sign", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv,
            entry->display_name, entry->security_level, "sign",
            cst, st, mem_after - mem_before, mean_energy_uj,
            (int)sig->length_public_key,
            (int)sig->length_secret_key,
            (int)sig_len);          /* actual signed length (FALCON is variable) */
        write_raw_samples(raw_csv, entry->display_name, "sign",
            cycle_samples, samples, cpu_samples, sig_len_samples, N_ITERATIONS, epoch_start);
    }

    /* ── Verify ──────────────────────────────────────────────────────────── */

    if (do_verify || do_verify_invalid) {
        /* produce one valid signature to verify repeatedly (and for
         * verify_invalid to corrupt a copy of) */
        OQS_SIG_sign(sig, signature, &sig_len, message, MESSAGE_LEN, priv_key);
    }

    if (do_verify) {
        WARMUP_FOR(OQS_SIG_verify(sig, message, MESSAGE_LEN, signature, sig_len, pub_key));

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            TIMED_ITERATION(rc = OQS_SIG_verify(sig, message, MESSAGE_LEN,
                                signature, sig_len, pub_key));
            if (rc != OQS_SUCCESS) {
                fprintf(stderr, "  Verify failed at iteration %d\n", i);
                break;
            }
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(entry->display_name, "verify", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv,
            entry->display_name, entry->security_level, "verify",
            cst, st, mem_after - mem_before, mean_energy_uj,
            (int)sig->length_public_key,
            (int)sig->length_secret_key,
            (int)sig_len);
        write_raw_samples(raw_csv, entry->display_name, "verify",
            cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    /* ── Verify (invalid signature) ──────────────────────────────────────────
     * No latency number for verifying a corrupted/adversarial signature has
     * been reported anywhere in this study so far, despite it being exactly
     * the input a service under hostile traffic actually sees. Flip one byte
     * in an otherwise-valid signature and time repeated verify calls against
     * it: a scheme that short-circuits on a cheap structural check before its
     * expensive core operation should show up here as faster than "verify"
     * above; a scheme that doesn't, won't. If any iteration reports success
     * despite the corruption, that's a correctness/security finding, not
     * noise — surfaced loudly rather than averaged away silently. */

    if (do_verify_invalid) {
        uint8_t *bad_sig = (uint8_t *)malloc(sig_len > 0 ? sig_len : 1);
        if (!bad_sig) {
            perror("malloc");
        } else {
            memcpy(bad_sig, signature, sig_len);
            bad_sig[sig_len / 2] ^= 0xFF; /* flip a byte in the middle */

            WARMUP_FOR(OQS_SIG_verify(sig, message, MESSAGE_LEN, bad_sig, sig_len, pub_key));

            int unexpected_accepts = 0;
            epoch_start = now_epoch();
            mem_before = read_peak_rss_kb();
            energy_before = read_energy_uj(energy_fp);
            for (int i = 0; i < N_ITERATIONS; i++) {
                TIMED_ITERATION(rc = OQS_SIG_verify(sig, message, MESSAGE_LEN,
                                    bad_sig, sig_len, pub_key));
                if (rc == OQS_SUCCESS) unexpected_accepts++;
                samples[i] = t1 - t0;
                cycle_samples[i] = c1 - c0;
                cpu_samples[i] = cpu1 - cpu0;
            }
            energy_after = read_energy_uj(energy_fp);
            mem_after = read_peak_rss_kb();
            mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
                ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

            if (unexpected_accepts > 0)
                fprintf(stderr,
                    "  *** SECURITY WARNING: %s accepted a corrupted signature "
                    "in %d/%d verify_invalid iterations ***\n",
                    entry->display_name, unexpected_accepts, N_ITERATIONS);

            st = compute_stats(samples, N_ITERATIONS);
            cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
            print_result(entry->display_name, "verify_invalid", cst, st, mem_after - mem_before, mean_energy_uj);
            csv_write_row(csv,
                entry->display_name, entry->security_level, "verify_invalid",
                cst, st, mem_after - mem_before, mean_energy_uj,
                (int)sig->length_public_key,
                (int)sig->length_secret_key,
                (int)sig_len);
            write_raw_samples(raw_csv, entry->display_name, "verify_invalid",
                cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);

            free(bad_sig);
        }
    }

    /* ── cleanup ──────────────────────────────────────────────────────────── */
    free(pub_key);
    free(priv_key);
    free(signature);
    free(samples);
    free(cycle_samples);
    free(cpu_samples);
    free(sig_len_samples);
    OQS_SIG_free(sig);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {

    const char *csv_path = (argc > 1) ? argv[1] : "results_pqc_x86.csv";
    const char *raw_csv_path = (argc > 2) ? argv[2] : "results_pqc_x86_raw.csv";
    const char *only_algo = (argc > 3) ? argv[3] : NULL; /* optional: isolate one
                                                             algorithm's oqs_name
                                                             for perf-stat profiling */
    const char *only_op   = (argc > 4) ? argv[4] : NULL; /* optional: "keygen",
                                                             "sign", or "verify",
                                                             for perf-stat profiling */

    FILE *csv = fopen(csv_path, "w");
    if (!csv) { perror("fopen"); return 1; }
    FILE *raw_csv = fopen(raw_csv_path, "w");
    if (!raw_csv) { perror("fopen"); return 1; }

    printf("=================================================================\n");
    printf("  PQC Benchmark — Dilithium / FALCON / SPHINCS+\n");
    printf("  liboqs version : %s\n", OQS_VERSION_TEXT);
    printf("  iterations     : %d  (+ %dms time-bounded warm-up)\n", N_ITERATIONS, WARMUP_MS_DURATION);
    printf("  message size   : %d bytes\n", MESSAGE_LEN);
    printf("  output CSV     : %s\n", csv_path);
    printf("  raw samples CSV: %s\n", raw_csv_path);
    if (only_algo) printf("  isolating algo : %s\n", only_algo);
    if (only_op)   printf("  isolating op   : %s\n", only_op);
    log_cpu_dispatch();
    log_timer_overhead();
    printf("=================================================================\n");

    int cycle_fd = open_cycle_counter();
    FILE *energy_fp = open_energy_counter();
#ifdef COLD_CACHE
    evict_cache_init();
    printf("  COLD_CACHE     : enabled — evicting cache before every timed call\n");
#endif

    csv_write_header(csv);
    raw_csv_write_header(raw_csv);

    stack_hwm_start();
    for (int i = 0; i < N_ALGORITHMS; i++) {
        if (only_algo && strcmp(ALGORITHMS[i].oqs_name, only_algo) != 0) continue;
        bench_algorithm(&ALGORITHMS[i], csv, raw_csv, only_op, cycle_fd, energy_fp);
    }
    stack_hwm_finish(csv_path);

    fclose(csv);
    fclose(raw_csv);
    if (energy_fp) fclose(energy_fp);

    printf("\n=================================================================\n");
    printf("  Done. Results written to: %s\n", csv_path);
    printf("=================================================================\n");

    return 0;
}
