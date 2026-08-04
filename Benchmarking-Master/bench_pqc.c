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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>

#include "benchmark.h"

/* ── Algorithm table ─────────────────────────────────────────────────────────
 * Each entry maps a liboqs algorithm name to a NIST security level string.
 * SPHINCS+ "s" variants = smaller signatures (slower).
 * SPHINCS+ "f" variants = faster (larger signatures).
 * We benchmark both SHA2 and SHAKE instantiations for completeness.
 * ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    const char *oqs_name;       /* exact name as used by OQS_SIG_new()     */
    const char *display_name;   /* friendly name for CSV / terminal output  */
    const char *security_level; /* NIST level: "1", "2", "3", "5"          */
} AlgoEntry;

static const AlgoEntry ALGORITHMS[] = {
    /* SLH-DSA (FIPS 205) — formerly SPHINCS+, run first so the slowest,
     * most cache/branch-heavy operations are not the ones absorbing any
     * residual process cold-start effect that per-operation warm-up misses.
     * "pure" variants = sign the message directly (equivalent to SPHINCS+ simple)
     * "s" = small signature, "f" = fast signing                                  */
    { "SLH_DSA_PURE_SHA2_128S",  "SLH-DSA-SHA2-128s (SPHINCS+)", "1" },
    { "SLH_DSA_PURE_SHA2_192S",  "SLH-DSA-SHA2-192s (SPHINCS+)", "3" },
    { "SLH_DSA_PURE_SHA2_256S",  "SLH-DSA-SHA2-256s (SPHINCS+)", "5" },
    { "SLH_DSA_PURE_SHAKE_128S", "SLH-DSA-SHAKE-128s (SPHINCS+)","1" },
    { "SLH_DSA_PURE_SHAKE_256S", "SLH-DSA-SHAKE-256s (SPHINCS+)","5" },

    /* FALCON */
    { "Falcon-512",             "Falcon-512",             "1" },
    { "Falcon-1024",            "Falcon-1024",            "5" },

    /* ML-DSA (FIPS 204) — formerly CRYSTALS-Dilithium
     * Level 2 = ML-DSA-44, Level 3 = ML-DSA-65, Level 5 = ML-DSA-87 */
    { "ML-DSA-44",              "ML-DSA-44 (Dilithium2)", "2" },
    { "ML-DSA-65",              "ML-DSA-65 (Dilithium3)", "3" },
    { "ML-DSA-87",              "ML-DSA-87 (Dilithium5)", "5" },
};

static const int N_ALGORITHMS = (int)(sizeof(ALGORITHMS) / sizeof(ALGORITHMS[0]));

/* ── Benchmark one algorithm ─────────────────────────────────────────────── */

static void bench_algorithm(const AlgoEntry *entry, FILE *csv, FILE *raw_csv) {

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

    uint64_t *samples = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    if (!samples) { perror("malloc"); exit(1); }

    OQS_STATUS rc;
    uint64_t t0, t1;
    long mem_before, mem_after;
    Stats st;

    /* ── KeyGen ──────────────────────────────────────────────────────────── */

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++)
        OQS_SIG_keypair(sig, pub_key, priv_key);

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        t0 = now_ns();
        rc = OQS_SIG_keypair(sig, pub_key, priv_key);
        t1 = now_ns();
        if (rc != OQS_SUCCESS) {
            fprintf(stderr, "  KeyGen failed at iteration %d\n", i);
            break;
        }
        samples[i] = t1 - t0;
    }
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);
    print_result(entry->display_name, "keygen", st, mem_after - mem_before);
    csv_write_row(csv,
        entry->display_name, entry->security_level, "keygen",
        st, mem_after - mem_before,
        (int)sig->length_public_key,
        (int)sig->length_secret_key,
        (int)sig->length_signature);
    write_raw_samples(raw_csv, entry->display_name, "keygen", samples, N_ITERATIONS);

    /* ── Sign ────────────────────────────────────────────────────────────── */

    /* generate one key pair to use for all sign iterations */
    OQS_SIG_keypair(sig, pub_key, priv_key);

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++)
        OQS_SIG_sign(sig, signature, &sig_len, message, MESSAGE_LEN, priv_key);

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        t0 = now_ns();
        rc = OQS_SIG_sign(sig, signature, &sig_len,
                          message, MESSAGE_LEN, priv_key);
        t1 = now_ns();
        if (rc != OQS_SUCCESS) {
            fprintf(stderr, "  Sign failed at iteration %d\n", i);
            break;
        }
        samples[i] = t1 - t0;
    }
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);
    print_result(entry->display_name, "sign", st, mem_after - mem_before);
    csv_write_row(csv,
        entry->display_name, entry->security_level, "sign",
        st, mem_after - mem_before,
        (int)sig->length_public_key,
        (int)sig->length_secret_key,
        (int)sig_len);          /* actual signed length (FALCON is variable) */
    write_raw_samples(raw_csv, entry->display_name, "sign", samples, N_ITERATIONS);

    /* ── Verify ──────────────────────────────────────────────────────────── */

    /* produce one valid signature to verify repeatedly */
    OQS_SIG_sign(sig, signature, &sig_len, message, MESSAGE_LEN, priv_key);

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++)
        OQS_SIG_verify(sig, message, MESSAGE_LEN, signature, sig_len, pub_key);

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        t0 = now_ns();
        rc = OQS_SIG_verify(sig, message, MESSAGE_LEN,
                            signature, sig_len, pub_key);
        t1 = now_ns();
        if (rc != OQS_SUCCESS) {
            fprintf(stderr, "  Verify failed at iteration %d\n", i);
            break;
        }
        samples[i] = t1 - t0;
    }
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);
    print_result(entry->display_name, "verify", st, mem_after - mem_before);
    csv_write_row(csv,
        entry->display_name, entry->security_level, "verify",
        st, mem_after - mem_before,
        (int)sig->length_public_key,
        (int)sig->length_secret_key,
        (int)sig_len);
    write_raw_samples(raw_csv, entry->display_name, "verify", samples, N_ITERATIONS);

    /* ── cleanup ──────────────────────────────────────────────────────────── */
    free(pub_key);
    free(priv_key);
    free(signature);
    free(samples);
    OQS_SIG_free(sig);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {

    const char *csv_path = (argc > 1) ? argv[1] : "results_pqc_x86.csv";
    const char *raw_csv_path = (argc > 2) ? argv[2] : "results_pqc_x86_raw.csv";

    FILE *csv = fopen(csv_path, "w");
    if (!csv) { perror("fopen"); return 1; }
    FILE *raw_csv = fopen(raw_csv_path, "w");
    if (!raw_csv) { perror("fopen"); return 1; }

    printf("=================================================================\n");
    printf("  PQC Benchmark — Dilithium / FALCON / SPHINCS+\n");
    printf("  liboqs version : %s\n", OQS_VERSION_TEXT);
    printf("  iterations     : %d  (+ %d warm-up)\n", N_ITERATIONS, WARMUP_ITERS);
    printf("  message size   : %d bytes\n", MESSAGE_LEN);
    printf("  output CSV     : %s\n", csv_path);
    printf("  raw samples CSV: %s\n", raw_csv_path);
    printf("=================================================================\n");

    csv_write_header(csv);
    raw_csv_write_header(raw_csv);

    for (int i = 0; i < N_ALGORITHMS; i++)
        bench_algorithm(&ALGORITHMS[i], csv, raw_csv);

    fclose(csv);
    fclose(raw_csv);

    printf("\n=================================================================\n");
    printf("  Done. Results written to: %s\n", csv_path);
    printf("=================================================================\n");

    return 0;
}
