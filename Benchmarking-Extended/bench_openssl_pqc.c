/**
 * bench_openssl_pqc.c
 * Secondary, controlled comparison: RSA-3072, ECDSA-P256, ML-DSA, and
 * SLH-DSA all benchmarked through the SAME library (OpenSSL's own EVP
 * API), instead of classical-via-OpenSSL vs. PQC-via-liboqs.
 *
 * Why this exists: the main study's classical baselines go through
 * OpenSSL while its PQC algorithms go through liboqs — a different
 * codebase, built with liboqs's own -O3 (independent of the harness's
 * -O2), and (on top of that) the two platforms already run different
 * OpenSSL versions (3.6.3 on x86, 3.5.5 on ARM, per Table~tab:hardware).
 * That conflates the algorithm-vs-algorithm comparison with a
 * library-implementation-quality confound. OpenSSL 3.5+ ships ML-DSA and
 * SLH-DSA natively (verified against the locally installed 3.6.3: exact
 * key/signature sizes match the liboqs-derived Table~tab:artifact-sizes
 * byte-for-byte), so running everything through one library removes that
 * confound for those two families. Falcon has no OpenSSL implementation
 * (FIPS 206 is still a draft) and is therefore absent here — a real gap,
 * not an oversight, and should be stated as such wherever this data is
 * used.
 *
 * Timing convention matches bench_classical.c exactly: context setup
 * (EVP_PKEY_CTX_new_from_name / EVP_*Init) happens before t0 and is
 * excluded; only the core cryptographic call is timed. ML-DSA/SLH-DSA
 * are "pure" signature schemes (no caller-supplied pre-hash), so signing
 * uses the one-shot EVP_DigestSign/EVP_DigestVerify with a NULL digest
 * (verified against real OpenSSL 3.6.3: this is the correct API for pure
 * schemes, distinct from RSA/ECDSA's EVP_DigestSignUpdate+Final
 * streaming pattern used elsewhere in this suite) rather than an
 * Update+Final split, since there is nothing to stream.
 *
 * Build:
 *   gcc -O2 -o bench_openssl_pqc bench_openssl_pqc.c \
 *       $(pkg-config --cflags --libs openssl) -lm
 *
 * Usage:
 *   ./bench_openssl_pqc [output.csv] [raw.csv] [only_algo] [only_op]
 */

/* Must precede every system header in this translation unit — see the
 * identical note in bench_pqc.c / bench_classical.c: OpenSSL's headers
 * pull in pthread.h before benchmark.h gets a chance to define this, and
 * glibc locks in feature-test-macro-gated declarations
 * (pthread_getattr_np) at first inclusion. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "benchmark.h"
#include "algo_table_openssl.h"

static void openssl_die(const char *msg) {
    fprintf(stderr, "OpenSSL error in %s:\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* ── shared PQC (ML-DSA / SLH-DSA) benchmark ─────────────────────────── */

static void bench_pqc_algorithm(const OsslAlgoEntry *entry, FILE *csv, FILE *raw_csv,
                                 const char *only_op, int cycle_fd, FILE *energy_fp) {
    printf("\n[%s]  (NIST Level %s)\n", entry->display_name, entry->security_level);

    int do_keygen = !only_op || strcmp(only_op, "keygen") == 0;
    int do_sign   = !only_op || strcmp(only_op, "sign")   == 0;
    int do_verify = !only_op || strcmp(only_op, "verify") == 0;
    int do_verify_invalid = !only_op || strcmp(only_op, "verify_invalid") == 0;

    uint64_t *samples         = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cycle_samples   = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cpu_samples     = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    int      *sig_len_samples = (int *)malloc(N_ITERATIONS * sizeof(int));
    if (!samples || !cycle_samples || !cpu_samples || !sig_len_samples) { perror("malloc"); exit(1); }

    EVP_PKEY *pkey = NULL;
    uint8_t   message[MESSAGE_LEN];
    uint8_t  *sig = NULL;
    size_t    sig_max = 0, sig_len = 0;
    int       pub_bytes = -1, priv_bytes = -1;

    for (int i = 0; i < MESSAGE_LEN; i++) message[i] = (uint8_t)(i & 0xFF);

    uint64_t t0, t1, c0, c1, cpu0, cpu1;
    long mem_before, mem_after;
    long long energy_before, energy_after;
    double mean_energy_uj, epoch_start;
    Stats st;
    CycleStats cst;
    int rc;

    /* ── KeyGen ──────────────────────────────────────────────────────── */

    if (do_keygen) {
        WARMUP_FOR({
            EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, entry->openssl_name, NULL);
            EVP_PKEY_keygen_init(kctx);
            EVP_PKEY *tmp = NULL;
            EVP_PKEY_keygen(kctx, &tmp);
            EVP_PKEY_free(tmp);
            EVP_PKEY_CTX_free(kctx);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, entry->openssl_name, NULL);
            if (!kctx) openssl_die("EVP_PKEY_CTX_new_from_name");
            EVP_PKEY_keygen_init(kctx);

            TIMED_ITERATION(rc = EVP_PKEY_keygen(kctx, &pkey));

            if (rc <= 0) openssl_die("EVP_PKEY_keygen");
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;

            if (i < N_ITERATIONS - 1) { EVP_PKEY_free(pkey); pkey = NULL; }
            EVP_PKEY_CTX_free(kctx);
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        size_t pl = 0, sl = 0;
        EVP_PKEY_get_raw_public_key(pkey, NULL, &pl);
        EVP_PKEY_get_raw_private_key(pkey, NULL, &sl);
        pub_bytes = (int)pl;
        priv_bytes = (int)sl;
        sig_max = (size_t)EVP_PKEY_size(pkey);

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(entry->display_name, "keygen", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, entry->display_name, entry->security_level, "keygen",
            cst, st, mem_after - mem_before, mean_energy_uj, pub_bytes, priv_bytes, (int)sig_max);
        write_raw_samples(raw_csv, entry->display_name, "keygen",
            cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    if (do_sign || do_verify || do_verify_invalid) {
        /* regenerate a clean key for sign/verify steps */
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, entry->openssl_name, NULL);
        EVP_PKEY_keygen_init(kctx);
        EVP_PKEY_keygen(kctx, &pkey);
        EVP_PKEY_CTX_free(kctx);

        sig_max = (size_t)EVP_PKEY_size(pkey);
        sig = (uint8_t *)malloc(sig_max);
        if (!sig) { perror("malloc"); exit(1); }
    }

    /* ── Sign ────────────────────────────────────────────────────────── */
    /* "Pure" scheme: no pre-hash, so EVP_DigestSignInit takes a NULL
     * digest and signing is the single one-shot EVP_DigestSign call —
     * verified against real OpenSSL 3.6.3 before writing this file. */

    if (do_sign) {
        WARMUP_FOR({
            size_t tmp = sig_max;
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestSignInit(md, NULL, NULL, NULL, pkey);
            EVP_DigestSign(md, sig, &tmp, message, MESSAGE_LEN);
            EVP_MD_CTX_free(md);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            size_t tmp = sig_max;
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestSignInit(md, NULL, NULL, NULL, pkey);

            TIMED_ITERATION(rc = EVP_DigestSign(md, sig, &tmp, message, MESSAGE_LEN));

            EVP_MD_CTX_free(md);
            if (rc <= 0) openssl_die("EVP_DigestSign");
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;
            sig_len = tmp;
            sig_len_samples[i] = (int)tmp;
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(entry->display_name, "sign", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, entry->display_name, entry->security_level, "sign",
            cst, st, mem_after - mem_before, mean_energy_uj, pub_bytes, priv_bytes, (int)sig_len);
        write_raw_samples(raw_csv, entry->display_name, "sign",
            cycle_samples, samples, cpu_samples, sig_len_samples, N_ITERATIONS, epoch_start);
    }

    /* ── Verify ──────────────────────────────────────────────────────── */

    if (do_verify || do_verify_invalid) {
        /* produce one valid signature to verify repeatedly (and for
         * verify_invalid to corrupt a copy of) */
        size_t tmp = sig_max;
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestSignInit(md, NULL, NULL, NULL, pkey);
        rc = EVP_DigestSign(md, sig, &tmp, message, MESSAGE_LEN);
        EVP_MD_CTX_free(md);
        if (rc <= 0) openssl_die("EVP_DigestSign (verify setup)");
        sig_len = tmp;
    }

    if (do_verify) {
        WARMUP_FOR({
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md, NULL, NULL, NULL, pkey);
            EVP_DigestVerify(md, sig, sig_len, message, MESSAGE_LEN);
            EVP_MD_CTX_free(md);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md, NULL, NULL, NULL, pkey);

            TIMED_ITERATION(rc = EVP_DigestVerify(md, sig, sig_len, message, MESSAGE_LEN));

            EVP_MD_CTX_free(md);
            if (rc != 1) openssl_die("EVP_DigestVerify");
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
        csv_write_row(csv, entry->display_name, entry->security_level, "verify",
            cst, st, mem_after - mem_before, mean_energy_uj, pub_bytes, priv_bytes, (int)sig_len);
        write_raw_samples(raw_csv, entry->display_name, "verify",
            cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    /* ── Verify (invalid signature) — see bench_pqc.c for rationale ────────── */

    if (do_verify_invalid) {
        uint8_t *bad_sig = (uint8_t *)malloc(sig_len > 0 ? sig_len : 1);
        if (!bad_sig) {
            perror("malloc");
        } else {
            memcpy(bad_sig, sig, sig_len);
            bad_sig[sig_len / 2] ^= 0xFF;

            WARMUP_FOR({
                EVP_MD_CTX *md = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(md, NULL, NULL, NULL, pkey);
                EVP_DigestVerify(md, bad_sig, sig_len, message, MESSAGE_LEN);
                EVP_MD_CTX_free(md);
            });

            int unexpected_accepts = 0;
            epoch_start = now_epoch();
            mem_before = read_peak_rss_kb();
            energy_before = read_energy_uj(energy_fp);
            for (int i = 0; i < N_ITERATIONS; i++) {
                EVP_MD_CTX *md = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(md, NULL, NULL, NULL, pkey);

                TIMED_ITERATION(rc = EVP_DigestVerify(md, bad_sig, sig_len, message, MESSAGE_LEN));

                EVP_MD_CTX_free(md);
                if (rc == 1) unexpected_accepts++;
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
            csv_write_row(csv, entry->display_name, entry->security_level, "verify_invalid",
                cst, st, mem_after - mem_before, mean_energy_uj, pub_bytes, priv_bytes, (int)sig_len);
            write_raw_samples(raw_csv, entry->display_name, "verify_invalid",
                cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);

            free(bad_sig);
        }
    }

    free(sig);
    free(samples);
    free(cycle_samples);
    free(cpu_samples);
    free(sig_len_samples);
    EVP_PKEY_free(pkey);
}

/* ── RSA-3072 / ECDSA-P256 ────────────────────────────────────────────
 * Identical in substance to bench_classical.c's own implementation —
 * duplicated rather than shared because bench_classical.c's versions are
 * static functions in a different translation unit, and this file needs
 * to run RSA/ECDSA back-to-back with ML-DSA/SLH-DSA in the SAME process
 * to make the "one library, one process, one binary" comparison direct.
 * ─────────────────────────────────────────────────────────────────────── */

static void bench_rsa3072(FILE *csv, FILE *raw_csv, const char *only_op, int cycle_fd, FILE *energy_fp) {
    int do_keygen = !only_op || strcmp(only_op, "keygen") == 0;
    int do_sign   = !only_op || strcmp(only_op, "sign")   == 0;
    int do_verify = !only_op || strcmp(only_op, "verify") == 0;
    int do_verify_invalid = !only_op || strcmp(only_op, "verify_invalid") == 0;

    const char *algo = "RSA-3072";
    const char *level = "classical";
    const int   bits  = 3072;
    printf("\n[%s]\n", algo);

    uint64_t *samples         = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cycle_samples   = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cpu_samples     = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    int      *sig_len_samples = (int *)malloc(N_ITERATIONS * sizeof(int));
    if (!samples || !cycle_samples || !cpu_samples || !sig_len_samples) { perror("malloc"); exit(1); }

    EVP_PKEY     *pkey    = NULL;
    EVP_PKEY_CTX *ctx     = NULL;
    EVP_MD_CTX   *md_ctx  = NULL;
    uint8_t       message[MESSAGE_LEN];
    uint8_t      *sig     = NULL;
    size_t        sig_len = 0;

    for (int i = 0; i < MESSAGE_LEN; i++) message[i] = (uint8_t)(i & 0xFF);

    uint64_t t0, t1, c0, c1, cpu0, cpu1;
    long mem_before, mem_after;
    long long energy_before, energy_after;
    double mean_energy_uj, epoch_start;
    Stats st;
    CycleStats cst;
    int rc;

    int pub_bytes = 384, priv_bytes = 1679, sig_bytes_rsa = 384;

    if (do_keygen) {
        WARMUP_FOR({
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
            EVP_PKEY *tmp = NULL;
            EVP_PKEY_keygen(ctx, &tmp);
            EVP_PKEY_free(tmp);
            EVP_PKEY_CTX_free(ctx);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (!ctx) openssl_die("EVP_PKEY_CTX_new_id");
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);

            TIMED_ITERATION(rc = EVP_PKEY_keygen(ctx, &pkey));

            if (rc <= 0) openssl_die("EVP_PKEY_keygen RSA");
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;

            if (i < N_ITERATIONS - 1) EVP_PKEY_free(pkey);
            pkey = (i == N_ITERATIONS - 1) ? pkey : NULL;
            EVP_PKEY_CTX_free(ctx);
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(algo, "keygen", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, algo, level, "keygen", cst, st, mem_after - mem_before, mean_energy_uj,
            pub_bytes, priv_bytes, sig_bytes_rsa);
        write_raw_samples(raw_csv, algo, "keygen", cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    if (do_sign || do_verify || do_verify_invalid) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);

        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
        EVP_DigestSignFinal(md_ctx, NULL, &sig_len);
        sig = (uint8_t *)malloc(sig_len);
        EVP_MD_CTX_free(md_ctx);
    }

    if (do_sign) {
        WARMUP_FOR({
            size_t tmp_len = sig_len;
            md_ctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
            EVP_DigestSignFinal(md_ctx, sig, &tmp_len);
            EVP_MD_CTX_free(md_ctx);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            size_t tmp_len = sig_len;
            md_ctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);

            TIMED_ITERATION(rc = EVP_DigestSignFinal(md_ctx, sig, &tmp_len));

            EVP_MD_CTX_free(md_ctx);
            if (rc <= 0) openssl_die("EVP_DigestSignFinal RSA");
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;
            sig_len_samples[i] = (int)tmp_len;
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(algo, "sign", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, algo, level, "sign", cst, st, mem_after - mem_before, mean_energy_uj,
            pub_bytes, priv_bytes, (int)sig_len);
        write_raw_samples(raw_csv, algo, "sign", cycle_samples, samples, cpu_samples, sig_len_samples, N_ITERATIONS, epoch_start);
    }

    if (do_verify || do_verify_invalid) {
        size_t tmp_len = sig_len;
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
        EVP_DigestSignFinal(md_ctx, sig, &tmp_len);
        sig_len = tmp_len;
        EVP_MD_CTX_free(md_ctx);
    }

    if (do_verify) {
        WARMUP_FOR({
            md_ctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);
            EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
            EVP_MD_CTX_free(md_ctx);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            md_ctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);

            TIMED_ITERATION(rc = EVP_DigestVerifyFinal(md_ctx, sig, sig_len));

            EVP_MD_CTX_free(md_ctx);
            if (rc <= 0) openssl_die("EVP_DigestVerifyFinal RSA");
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
        print_result(algo, "verify", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, algo, level, "verify", cst, st, mem_after - mem_before, mean_energy_uj,
            pub_bytes, priv_bytes, (int)sig_len);
        write_raw_samples(raw_csv, algo, "verify", cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    if (do_verify_invalid) {
        uint8_t *bad_sig = (uint8_t *)malloc(sig_len > 0 ? sig_len : 1);
        if (!bad_sig) {
            perror("malloc");
        } else {
            memcpy(bad_sig, sig, sig_len);
            bad_sig[sig_len / 2] ^= 0xFF;

            WARMUP_FOR({
                md_ctx = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
                EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);
                EVP_DigestVerifyFinal(md_ctx, bad_sig, sig_len);
                EVP_MD_CTX_free(md_ctx);
            });

            int unexpected_accepts = 0;
            epoch_start = now_epoch();
            mem_before = read_peak_rss_kb();
            energy_before = read_energy_uj(energy_fp);
            for (int i = 0; i < N_ITERATIONS; i++) {
                md_ctx = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
                EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);

                TIMED_ITERATION(rc = EVP_DigestVerifyFinal(md_ctx, bad_sig, sig_len));

                EVP_MD_CTX_free(md_ctx);
                if (rc == 1) unexpected_accepts++;
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
                    algo, unexpected_accepts, N_ITERATIONS);

            st = compute_stats(samples, N_ITERATIONS);
            cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
            print_result(algo, "verify_invalid", cst, st, mem_after - mem_before, mean_energy_uj);
            csv_write_row(csv, algo, level, "verify_invalid", cst, st, mem_after - mem_before, mean_energy_uj,
                pub_bytes, priv_bytes, (int)sig_len);
            write_raw_samples(raw_csv, algo, "verify_invalid", cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);

            free(bad_sig);
        }
    }

    free(sig);
    free(samples);
    free(cycle_samples);
    free(cpu_samples);
    free(sig_len_samples);
    EVP_PKEY_free(pkey);
}

static void bench_ecdsa_p256(FILE *csv, FILE *raw_csv, const char *only_op, int cycle_fd, FILE *energy_fp) {
    const char *algo  = "ECDSA-P256";
    const char *level = "classical";
    printf("\n[%s]\n", algo);

    int do_keygen = !only_op || strcmp(only_op, "keygen") == 0;
    int do_sign   = !only_op || strcmp(only_op, "sign")   == 0;
    int do_verify = !only_op || strcmp(only_op, "verify") == 0;
    int do_verify_invalid = !only_op || strcmp(only_op, "verify_invalid") == 0;

    uint64_t *samples         = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cycle_samples   = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    uint64_t *cpu_samples     = (uint64_t *)malloc(N_ITERATIONS * sizeof(uint64_t));
    int      *sig_len_samples = (int *)malloc(N_ITERATIONS * sizeof(int));
    if (!samples || !cycle_samples || !cpu_samples || !sig_len_samples) { perror("malloc"); exit(1); }

    EVP_PKEY     *pkey    = NULL;
    EVP_PKEY_CTX *ctx     = NULL;
    EVP_MD_CTX   *md_ctx  = NULL;
    uint8_t       message[MESSAGE_LEN];
    uint8_t      *sig     = NULL;
    size_t        sig_len = 0;

    for (int i = 0; i < MESSAGE_LEN; i++) message[i] = (uint8_t)(i & 0xFF);

    uint64_t t0, t1, c0, c1, cpu0, cpu1;
    long mem_before, mem_after;
    long long energy_before, energy_after;
    double mean_energy_uj, epoch_start;
    Stats st;
    CycleStats cst;
    int rc;

    int pub_bytes = 65, priv_bytes = 121, sig_bytes_ec = 72;

    OSSL_PARAM params[2] = {
        OSSL_PARAM_utf8_string("group", "P-256", 0),
        OSSL_PARAM_END
    };

    if (do_keygen) {
        WARMUP_FOR({
            ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_CTX_set_params(ctx, params);
            EVP_PKEY *tmp = NULL;
            EVP_PKEY_keygen(ctx, &tmp);
            EVP_PKEY_free(tmp);
            EVP_PKEY_CTX_free(ctx);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
            if (!ctx) openssl_die("EVP_PKEY_CTX_new_from_name EC");
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_CTX_set_params(ctx, params);

            TIMED_ITERATION(rc = EVP_PKEY_keygen(ctx, &pkey));

            if (rc <= 0) openssl_die("EVP_PKEY_keygen EC");
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;

            if (i < N_ITERATIONS - 1) { EVP_PKEY_free(pkey); pkey = NULL; }
            EVP_PKEY_CTX_free(ctx);
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(algo, "keygen", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, algo, level, "keygen", cst, st, mem_after - mem_before, mean_energy_uj,
            pub_bytes, priv_bytes, sig_bytes_ec);
        write_raw_samples(raw_csv, algo, "keygen", cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    if (do_sign || do_verify || do_verify_invalid) {
        ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_params(ctx, params);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
    }

    size_t sig_max = 0;
    if (do_sign || do_verify || do_verify_invalid) {
        sig_max = (size_t)EVP_PKEY_size(pkey);
        sig_len = sig_max;
        sig = (uint8_t *)malloc(sig_max);
        if (!sig) { perror("malloc"); exit(1); }
    }

    if (do_sign) {
        WARMUP_FOR({
            size_t tmp = sig_max;
            md_ctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
            EVP_DigestSignFinal(md_ctx, sig, &tmp);
            EVP_MD_CTX_free(md_ctx);
            sig_len = tmp;
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            size_t tmp = sig_max;
            md_ctx = EVP_MD_CTX_new();
            if (!md_ctx) openssl_die("EVP_MD_CTX_new ECDSA sign");
            EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);

            TIMED_ITERATION(rc = EVP_DigestSignFinal(md_ctx, sig, &tmp));

            EVP_MD_CTX_free(md_ctx);
            if (rc <= 0) openssl_die("EVP_DigestSignFinal ECDSA");
            samples[i] = t1 - t0;
            cycle_samples[i] = c1 - c0;
            cpu_samples[i] = cpu1 - cpu0;
            sig_len = tmp;
            sig_len_samples[i] = (int)tmp;
        }
        energy_after = read_energy_uj(energy_fp);
        mem_after = read_peak_rss_kb();
        mean_energy_uj = (energy_before >= 0 && energy_after >= 0)
            ? (double)(energy_after - energy_before) / N_ITERATIONS : -1.0;

        st = compute_stats(samples, N_ITERATIONS);
        cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
        print_result(algo, "sign", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, algo, level, "sign", cst, st, mem_after - mem_before, mean_energy_uj,
            pub_bytes, priv_bytes, (int)sig_len);
        write_raw_samples(raw_csv, algo, "sign", cycle_samples, samples, cpu_samples, sig_len_samples, N_ITERATIONS, epoch_start);
    }

    if (do_verify || do_verify_invalid) {
        size_t tmp = sig_max;
        md_ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
        EVP_DigestSignUpdate(md_ctx, message, MESSAGE_LEN);
        rc = EVP_DigestSignFinal(md_ctx, sig, &tmp);
        EVP_MD_CTX_free(md_ctx);
        if (rc <= 0) openssl_die("EVP_DigestSignFinal ECDSA (verify setup)");
        sig_len = tmp;
    }

    if (do_verify) {
        WARMUP_FOR({
            md_ctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);
            EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
            EVP_MD_CTX_free(md_ctx);
        });

        epoch_start = now_epoch();
        mem_before = read_peak_rss_kb();
        energy_before = read_energy_uj(energy_fp);
        for (int i = 0; i < N_ITERATIONS; i++) {
            md_ctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
            EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);

            TIMED_ITERATION(rc = EVP_DigestVerifyFinal(md_ctx, sig, sig_len));

            EVP_MD_CTX_free(md_ctx);
            if (rc <= 0) openssl_die("EVP_DigestVerifyFinal ECDSA");
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
        print_result(algo, "verify", cst, st, mem_after - mem_before, mean_energy_uj);
        csv_write_row(csv, algo, level, "verify", cst, st, mem_after - mem_before, mean_energy_uj,
            pub_bytes, priv_bytes, (int)sig_len);
        write_raw_samples(raw_csv, algo, "verify", cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);
    }

    if (do_verify_invalid) {
        uint8_t *bad_sig = (uint8_t *)malloc(sig_len > 0 ? sig_len : 1);
        if (!bad_sig) {
            perror("malloc");
        } else {
            memcpy(bad_sig, sig, sig_len);
            bad_sig[sig_len / 2] ^= 0xFF;

            WARMUP_FOR({
                md_ctx = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
                EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);
                EVP_DigestVerifyFinal(md_ctx, bad_sig, sig_len);
                EVP_MD_CTX_free(md_ctx);
            });

            int unexpected_accepts = 0;
            epoch_start = now_epoch();
            mem_before = read_peak_rss_kb();
            energy_before = read_energy_uj(energy_fp);
            for (int i = 0; i < N_ITERATIONS; i++) {
                md_ctx = EVP_MD_CTX_new();
                EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
                EVP_DigestVerifyUpdate(md_ctx, message, MESSAGE_LEN);

                TIMED_ITERATION(rc = EVP_DigestVerifyFinal(md_ctx, bad_sig, sig_len));

                EVP_MD_CTX_free(md_ctx);
                if (rc == 1) unexpected_accepts++;
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
                    algo, unexpected_accepts, N_ITERATIONS);

            st = compute_stats(samples, N_ITERATIONS);
            cst = compute_cycle_stats(cycle_samples, N_ITERATIONS);
            print_result(algo, "verify_invalid", cst, st, mem_after - mem_before, mean_energy_uj);
            csv_write_row(csv, algo, level, "verify_invalid", cst, st, mem_after - mem_before, mean_energy_uj,
                pub_bytes, priv_bytes, (int)sig_len);
            write_raw_samples(raw_csv, algo, "verify_invalid", cycle_samples, samples, cpu_samples, NULL, N_ITERATIONS, epoch_start);

            free(bad_sig);
        }
    }

    free(sig);
    free(samples);
    free(cycle_samples);
    free(cpu_samples);
    free(sig_len_samples);
    EVP_PKEY_free(pkey);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *csv_path     = (argc > 1) ? argv[1] : "results_openssl_pqc.csv";
    const char *raw_csv_path = (argc > 2) ? argv[2] : "results_openssl_pqc_raw.csv";
    const char *only_algo    = (argc > 3) ? argv[3] : NULL;
    const char *only_op      = (argc > 4) ? argv[4] : NULL;

    FILE *csv = fopen(csv_path, "w");
    if (!csv) { perror("fopen"); return 1; }
    FILE *raw_csv = fopen(raw_csv_path, "w");
    if (!raw_csv) { perror("fopen"); return 1; }

    printf("=================================================================\n");
    printf("  OpenSSL-only secondary comparison: RSA / ECDSA / ML-DSA / SLH-DSA\n");
    printf("  OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("  iterations     : %d  (+ %dms time-bounded warm-up)\n", N_ITERATIONS, WARMUP_MS_DURATION);
    printf("  message size   : %d bytes\n", MESSAGE_LEN);
    printf("  output CSV     : %s\n", csv_path);
    printf("  NOTE: Falcon has no OpenSSL implementation and is absent here.\n");
    if (only_algo) printf("  isolating algo : %s\n", only_algo);
    if (only_op)   printf("  isolating op   : %s\n", only_op);
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
    if (!only_algo || strcmp(only_algo, "RSA-3072") == 0)
        bench_rsa3072(csv, raw_csv, only_op, cycle_fd, energy_fp);
    if (!only_algo || strcmp(only_algo, "ECDSA-P256") == 0)
        bench_ecdsa_p256(csv, raw_csv, only_op, cycle_fd, energy_fp);

    for (int i = 0; i < N_ALGORITHMS_OPENSSL; i++) {
        if (only_algo && strcmp(ALGORITHMS_OPENSSL[i].openssl_name, only_algo) != 0) continue;
        bench_pqc_algorithm(&ALGORITHMS_OPENSSL[i], csv, raw_csv, only_op, cycle_fd, energy_fp);
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
