/**
 * bench_classical.c
 * Benchmarks RSA-3072 and ECDSA P-256 using OpenSSL 3.x as classical baseline.
 *
 * Build:
 *   gcc -O2 -o bench_classical bench_classical.c \
 *       $(pkg-config --cflags --libs openssl) -lm
 *
 * Usage:
 *   ./bench_classical [output.csv]
 *   Default output file: results_classical_x86.csv
 *
 * Note: RSA key generation is intentionally benchmarked with a fixed public
 *       exponent of 65537 (F4), which is the universal standard.
 *       RSA-3072 provides ~128-bit classical security, equivalent to
 *       Dilithium2 / Falcon-512 at NIST Level 1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "benchmark.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void openssl_die(const char *msg) {
    fprintf(stderr, "OpenSSL error in %s:\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* ── RSA-3072 ─────────────────────────────────────────────────────────────── */

static void bench_rsa3072(FILE *csv, FILE *raw_csv) {

    const char *algo = "RSA-3072";
    const char *level = "classical";
    const int   bits  = 3072;
    printf("\n[%s]\n", algo);

    uint64_t *samples = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    if (!samples) { perror("malloc"); exit(1); }

    EVP_PKEY     *pkey     = NULL;
    EVP_PKEY_CTX *ctx      = NULL;
    EVP_MD_CTX   *md_ctx   = NULL;
    uint8_t       message[MESSAGE_LEN];
    uint8_t      *sig      = NULL;
    size_t        sig_len  = 0;

    for (int i = 0; i < MESSAGE_LEN; i++) message[i] = (uint8_t)(i & 0xFF);

    uint64_t t0, t1;
    long mem_before, mem_after;
    Stats st;
    int rc;

    /* ── KeyGen ──────────────────────────────────────────────────────────── */

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
        EVP_PKEY *tmp = NULL;
        EVP_PKEY_keygen(ctx, &tmp);
        EVP_PKEY_free(tmp);
        EVP_PKEY_CTX_free(ctx);
    }

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) openssl_die("EVP_PKEY_CTX_new_id");
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);

        t0 = now_ns();
        rc = EVP_PKEY_keygen(ctx, &pkey);
        t1 = now_ns();

        if (rc <= 0) openssl_die("EVP_PKEY_keygen RSA");
        samples[i] = t1 - t0;

        /* keep last key for sign/verify; free intermediates */
        if (i < N_ITERATIONS - 1) EVP_PKEY_free(pkey);
        pkey = (i == N_ITERATIONS - 1) ? pkey : NULL;
        EVP_PKEY_CTX_free(ctx);
    }
    /* regenerate a clean key for sign/verify steps */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);

    /* RSA-3072: pub ~384 B, priv ~1679 B (DER), sig = 384 B */
    int pub_bytes = 384, priv_bytes = 1679, sig_bytes_rsa = 384;
    print_result(algo, "keygen", st, mem_after - mem_before);
    csv_write_row(csv, algo, level, "keygen",
        st, mem_after - mem_before,
        pub_bytes, priv_bytes, sig_bytes_rsa);
    write_raw_samples(raw_csv, algo, "keygen", samples, N_ITERATIONS);

    /* ── Sign ────────────────────────────────────────────────────────────── */

    /* determine max signature size */
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
    EVP_DigestSignFinal(md_ctx, NULL, &sig_len);
    sig = (uint8_t *)malloc(sig_len);
    EVP_MD_CTX_free(md_ctx);

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        size_t tmp_len = sig_len;
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
        EVP_DigestSignFinal(md_ctx, sig, &tmp_len);
        EVP_MD_CTX_free(md_ctx);
    }

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        size_t tmp_len = sig_len;
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);

        t0 = now_ns();
        rc = EVP_DigestSignFinal(md_ctx, sig, &tmp_len);
        t1 = now_ns();

        EVP_MD_CTX_free(md_ctx);
        if (rc <= 0) openssl_die("EVP_DigestSignFinal RSA");
        samples[i] = t1 - t0;
    }
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);
    print_result(algo, "sign", st, mem_after - mem_before);
    csv_write_row(csv, algo, level, "sign",
        st, mem_after - mem_before,
        pub_bytes, priv_bytes, (int)sig_len);
    write_raw_samples(raw_csv, algo, "sign", samples, N_ITERATIONS);

    /* ── Verify ──────────────────────────────────────────────────────────── */

    /* produce one valid signature */
    {
        size_t tmp_len = sig_len;
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
        EVP_DigestSignFinal(md_ctx, sig, &tmp_len);
        sig_len = tmp_len;
        EVP_MD_CTX_free(md_ctx);
    }

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);
        EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
        EVP_MD_CTX_free(md_ctx);
    }

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);

        t0 = now_ns();
        rc = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
        t1 = now_ns();

        EVP_MD_CTX_free(md_ctx);
        if (rc <= 0) openssl_die("EVP_DigestVerifyFinal RSA");
        samples[i] = t1 - t0;
    }
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);
    print_result(algo, "verify", st, mem_after - mem_before);
    csv_write_row(csv, algo, level, "verify",
        st, mem_after - mem_before,
        pub_bytes, priv_bytes, (int)sig_len);
    write_raw_samples(raw_csv, algo, "verify", samples, N_ITERATIONS);

    free(sig);
    free(samples);
    EVP_PKEY_free(pkey);
}

/* ── ECDSA P-256 ─────────────────────────────────────────────────────────── */

static void bench_ecdsa_p256(FILE *csv, FILE *raw_csv) {

    const char *algo  = "ECDSA-P256";
    const char *level = "classical";
    printf("\n[%s]\n", algo);

    uint64_t *samples = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    if (!samples) { perror("malloc"); exit(1); }

    EVP_PKEY     *pkey    = NULL;
    EVP_PKEY_CTX *ctx     = NULL;
    EVP_MD_CTX   *md_ctx  = NULL;
    uint8_t       message[MESSAGE_LEN];
    uint8_t      *sig     = NULL;
    size_t        sig_len = 0;

    for (int i = 0; i < MESSAGE_LEN; i++) message[i] = (uint8_t)(i & 0xFF);

    uint64_t t0, t1;
    long mem_before, mem_after;
    Stats st;
    int rc;

    /* ── KeyGen ──────────────────────────────────────────────────────────── */

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        EVP_PKEY_keygen_init(ctx);
        OSSL_PARAM params[2] = {
            OSSL_PARAM_utf8_string("group", "P-256", 0),
            OSSL_PARAM_END
        };
        EVP_PKEY_CTX_set_params(ctx, params);
        EVP_PKEY *tmp = NULL;
        EVP_PKEY_keygen(ctx, &tmp);
        EVP_PKEY_free(tmp);
        EVP_PKEY_CTX_free(ctx);
    }

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!ctx) openssl_die("EVP_PKEY_CTX_new_from_name EC");
        EVP_PKEY_keygen_init(ctx);
        OSSL_PARAM params[2] = {
            OSSL_PARAM_utf8_string("group", "P-256", 0),
            OSSL_PARAM_END
        };
        EVP_PKEY_CTX_set_params(ctx, params);

        t0 = now_ns();
        rc = EVP_PKEY_keygen(ctx, &pkey);
        t1 = now_ns();

        if (rc <= 0) openssl_die("EVP_PKEY_keygen EC");
        samples[i] = t1 - t0;

        if (i < N_ITERATIONS - 1) { EVP_PKEY_free(pkey); pkey = NULL; }
        EVP_PKEY_CTX_free(ctx);
    }
    /* regenerate clean key */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_keygen_init(ctx);
    OSSL_PARAM params2[2] = {
        OSSL_PARAM_utf8_string("group", "P-256", 0),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX_set_params(ctx, params2);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);

    /* P-256: pub 65 B (uncompressed), priv ~121 B (DER), sig ~72 B (DER max) */
    int pub_bytes = 65, priv_bytes = 121, sig_bytes_ec = 72;
    print_result(algo, "keygen", st, mem_after - mem_before);
    csv_write_row(csv, algo, level, "keygen",
        st, mem_after - mem_before,
        pub_bytes, priv_bytes, sig_bytes_ec);
    write_raw_samples(raw_csv, algo, "keygen", samples, N_ITERATIONS);

    /* ── Sign ────────────────────────────────────────────────────────────── */

    /* get max sig length safely via EVP_PKEY_size — no context needed */
    size_t sig_max = (size_t)EVP_PKEY_size(pkey);
    sig_len = sig_max;
    sig = (uint8_t *)malloc(sig_max);
    if (!sig) { perror("malloc"); exit(1); }

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        size_t tmp = sig_max;           /* always reset to max */
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
        EVP_DigestSignFinal(md_ctx, sig, &tmp);
        EVP_MD_CTX_free(md_ctx);
        sig_len = tmp;                  /* record last actual length for verify */
    }

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        size_t tmp = sig_max;           /* always reset to max before each call */
        md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) openssl_die("EVP_MD_CTX_new ECDSA sign");
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);

        t0 = now_ns();
        rc = EVP_DigestSignFinal(md_ctx, sig, &tmp);
        t1 = now_ns();

        EVP_MD_CTX_free(md_ctx);
        if (rc <= 0) {
            fprintf(stderr, "  failed at iteration %d\n", i);
            openssl_die("EVP_DigestSignFinal ECDSA");
        }
        samples[i] = t1 - t0;
        sig_len = tmp;                  /* track last actual sig length */
    }
    mem_after = read_peak_rss_kb();

    /* produce a final valid signature for verify step */
    {
        size_t tmp = sig_max;
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
        rc = EVP_DigestSignFinal(md_ctx, sig, &tmp);
        EVP_MD_CTX_free(md_ctx);
        if (rc <= 0) openssl_die("EVP_DigestSignFinal ECDSA (verify setup)");
        sig_len = tmp;
    }

    st = compute_stats(samples, N_ITERATIONS);
    print_result(algo, "sign", st, mem_after - mem_before);
    csv_write_row(csv, algo, level, "sign",
        st, mem_after - mem_before,
        pub_bytes, priv_bytes, (int)sig_len);
    write_raw_samples(raw_csv, algo, "sign", samples, N_ITERATIONS);

    /* ── Verify ──────────────────────────────────────────────────────────── */

    /* warm-up */
    for (int i = 0; i < WARMUP_ITERS; i++) {
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);
        EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
        EVP_MD_CTX_free(md_ctx);
    }

    mem_before = read_peak_rss_kb();
    for (int i = 0; i < N_ITERATIONS; i++) {
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);

        t0 = now_ns();
        rc = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
        t1 = now_ns();

        EVP_MD_CTX_free(md_ctx);
        if (rc <= 0) openssl_die("EVP_DigestVerifyFinal ECDSA");
        samples[i] = t1 - t0;
    }
    mem_after = read_peak_rss_kb();

    st = compute_stats(samples, N_ITERATIONS);
    print_result(algo, "verify", st, mem_after - mem_before);
    csv_write_row(csv, algo, level, "verify",
        st, mem_after - mem_before,
        pub_bytes, priv_bytes, (int)sig_len);
    write_raw_samples(raw_csv, algo, "verify", samples, N_ITERATIONS);

    free(sig);
    free(samples);
    EVP_PKEY_free(pkey);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {

    const char *csv_path = (argc > 1) ? argv[1] : "results_classical_x86.csv";
    const char *raw_csv_path = (argc > 2) ? argv[2] : "results_classical_x86_raw.csv";

    FILE *csv = fopen(csv_path, "w");
    if (!csv) { perror("fopen"); return 1; }
    FILE *raw_csv = fopen(raw_csv_path, "w");
    if (!raw_csv) { perror("fopen"); return 1; }

    printf("=================================================================\n");
    printf("  Classical Baseline Benchmark — RSA-3072 / ECDSA P-256\n");
    printf("  OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("  iterations     : %d  (+ %d warm-up)\n", N_ITERATIONS, WARMUP_ITERS);
    printf("  message size   : %d bytes\n", MESSAGE_LEN);
    printf("  output CSV     : %s\n", csv_path);
    printf("  raw samples CSV: %s\n", raw_csv_path);
    printf("=================================================================\n");

    csv_write_header(csv);
    raw_csv_write_header(raw_csv);

    bench_rsa3072(csv, raw_csv);
    bench_ecdsa_p256(csv, raw_csv);

    fclose(csv);
    fclose(raw_csv);

    printf("\n=================================================================\n");
    printf("  Done. Results written to: %s\n", csv_path);
    printf("=================================================================\n");

    return 0;
}
