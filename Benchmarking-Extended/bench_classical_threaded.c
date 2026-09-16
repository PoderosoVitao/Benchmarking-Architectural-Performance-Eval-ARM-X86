/**
 * bench_classical_threaded.c
 * Thread-level scalability benchmark for RSA-3072 / ECDSA-P256.
 *
 * Mirrors bench_pqc_threaded.c's synchronization design: every worker
 * thread generates its own independent EVP_PKEY (its own keygen) and
 * allocates a fresh EVP_MD_CTX per call, exactly as the single-threaded
 * harness (bench_classical.c) already does — so no mutable state is ever
 * shared across threads, and all T threads clear a pthread_barrier before
 * the timed region starts, keeping staggered per-thread setup out of the
 * wall-clock measurement.
 *
 * Build:
 *   gcc -O2 -pthread -o bench_classical_threaded bench_classical_threaded.c \
 *       $(pkg-config --cflags --libs openssl) -lm
 *
 * Usage:
 *   ./bench_classical_threaded <RSA-3072|ECDSA-P256> <keygen|sign|verify> \
 *       <threads> <iters_per_thread> [out.csv]
 */

/* Must precede every system header in this translation unit — see the
 * identical note in bench_pqc.c. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#include "benchmark.h"

typedef struct {
    const char *algo;   /* "RSA-3072" or "ECDSA-P256" */
    const char *op;
    int         iterations;
    pthread_barrier_t *barrier;

    /* per-thread independent state — no sharing across threads */
    EVP_PKEY *pkey;
    uint8_t   message[MESSAGE_LEN];
    uint8_t  *sig;
    size_t    sig_max, sig_len;

    uint64_t total_ns;
    long     ops_done;
    long     failed;
} ThreadCtx;

static EVP_PKEY *keygen_rsa3072(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *keygen_ecdsa_p256(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) return NULL;
    EVP_PKEY_keygen_init(ctx);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_utf8_string("group", "P-256", 0),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX_set_params(ctx, params);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *keygen_for(const char *algo) {
    return (strcmp(algo, "RSA-3072") == 0) ? keygen_rsa3072() : keygen_ecdsa_p256();
}

static void *worker(void *arg) {
    ThreadCtx *ctx = (ThreadCtx *)arg;
    for (int i = 0; i < MESSAGE_LEN; i++) ctx->message[i] = (uint8_t)(i & 0xFF);

    ctx->pkey = keygen_for(ctx->algo);
    if (!ctx->pkey) {
        ctx->failed = ctx->iterations;
        pthread_barrier_wait(ctx->barrier);
        return NULL;
    }

    ctx->sig_max = (size_t)EVP_PKEY_size(ctx->pkey);
    ctx->sig     = (uint8_t *)malloc(ctx->sig_max);

    /* one valid signature up front, needed by verify (and harmless for
     * sign/keygen) */
    {
        size_t tmp = ctx->sig_max;
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, ctx->pkey);
        EVP_DigestSignUpdate(md, ctx->message, MESSAGE_LEN);
        EVP_DigestSignFinal(md, ctx->sig, &tmp);
        EVP_MD_CTX_free(md);
        ctx->sig_len = tmp;
    }

    /* warm-up, uncounted — time-bounded (WARMUP_MS_DURATION), not a fixed
     * iteration count: see benchmark.h's WARMUP_FOR for why a fixed count
     * under-warms fast operations. */
    WARMUP_FOR({
        if (strcmp(ctx->op, "sign") == 0) {
            size_t tmp = ctx->sig_max;
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, ctx->pkey);
            EVP_DigestSignUpdate(md, ctx->message, MESSAGE_LEN);
            EVP_DigestSignFinal(md, ctx->sig, &tmp);
            EVP_MD_CTX_free(md);
        } else if (strcmp(ctx->op, "verify") == 0) {
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, ctx->pkey);
            EVP_DigestVerifyUpdate(md, ctx->message, MESSAGE_LEN);
            EVP_DigestVerifyFinal(md, ctx->sig, ctx->sig_len);
            EVP_MD_CTX_free(md);
        } else {
            EVP_PKEY *tmp = keygen_for(ctx->algo);
            EVP_PKEY_free(tmp);
        }
    });

    /* every worker (plus main) waits here before the timed region starts */
    pthread_barrier_wait(ctx->barrier);

    for (int i = 0; i < ctx->iterations; i++) {
        int rc = 0;
        uint64_t t0 = now_ns();

        if (strcmp(ctx->op, "sign") == 0) {
            size_t tmp = ctx->sig_max;
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, ctx->pkey);
            EVP_DigestSignUpdate(md, ctx->message, MESSAGE_LEN);
            rc = EVP_DigestSignFinal(md, ctx->sig, &tmp);
            EVP_MD_CTX_free(md);
        } else if (strcmp(ctx->op, "verify") == 0) {
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, ctx->pkey);
            EVP_DigestVerifyUpdate(md, ctx->message, MESSAGE_LEN);
            rc = EVP_DigestVerifyFinal(md, ctx->sig, ctx->sig_len);
            EVP_MD_CTX_free(md);
        } else { /* keygen */
            EVP_PKEY *tmp = keygen_for(ctx->algo);
            rc = tmp ? 1 : 0;
            EVP_PKEY_free(tmp);
        }

        uint64_t t1 = now_ns();
        if (rc > 0) { ctx->total_ns += (t1 - t0); ctx->ops_done++; }
        else ctx->failed++;
    }

    free(ctx->sig);
    EVP_PKEY_free(ctx->pkey);
    return NULL;
}

static int file_is_empty(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 1;
    return st.st_size == 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr,
            "Usage: %s <RSA-3072|ECDSA-P256> <keygen|sign|verify> "
            "<threads> <iters_per_thread> [out.csv]\n", argv[0]);
        return 1;
    }

    const char *algo     = argv[1];
    const char *op       = argv[2];
    int threads          = atoi(argv[3]);
    int iters            = atoi(argv[4]);
    const char *csv_path = (argc > 5) ? argv[5] : "thread_scaling_classical.csv";

    if (strcmp(algo, "RSA-3072") != 0 && strcmp(algo, "ECDSA-P256") != 0) {
        fprintf(stderr, "algo must be RSA-3072 or ECDSA-P256\n");
        return 1;
    }
    if (strcmp(op, "keygen") != 0 && strcmp(op, "sign") != 0 && strcmp(op, "verify") != 0) {
        fprintf(stderr, "op must be keygen, sign, or verify\n");
        return 1;
    }
    if (threads < 1 || iters < 1) {
        fprintf(stderr, "threads and iters_per_thread must both be >= 1\n");
        return 1;
    }

    int need_header = file_is_empty(csv_path);
    FILE *csv = fopen(csv_path, "a");
    if (!csv) { perror("fopen"); return 1; }
    if (need_header) csv_write_scaling_header(csv);

    printf("[%s] op=%s threads=%d iters/thread=%d\n", algo, op, threads, iters);

    pthread_t *tids = (pthread_t *)malloc((size_t)threads * sizeof(pthread_t));
    ThreadCtx *ctxs = (ThreadCtx *)calloc((size_t)threads, sizeof(ThreadCtx));
    if (!tids || !ctxs) { perror("malloc"); return 1; }

    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, (unsigned)threads + 1);

    for (int i = 0; i < threads; i++) {
        ctxs[i].algo       = algo;
        ctxs[i].op         = op;
        ctxs[i].iterations = iters;
        ctxs[i].barrier    = &barrier;
        if (pthread_create(&tids[i], NULL, worker, &ctxs[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    pthread_barrier_wait(&barrier);
    uint64_t wall_t0 = now_ns();
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    uint64_t wall_t1 = now_ns();

    long total_ops = 0, total_failed = 0;
    uint64_t total_ns = 0;
    for (int i = 0; i < threads; i++) {
        total_ops    += ctxs[i].ops_done;
        total_failed += ctxs[i].failed;
        total_ns     += ctxs[i].total_ns;
    }

    double wall_seconds = ns_to_ms(wall_t1 - wall_t0) / 1000.0;
    double mean_latency = (total_ops > 0) ? ns_to_ms(total_ns) / (double)total_ops : 0.0;

    if (total_failed > 0)
        fprintf(stderr, "  WARNING: %ld operations failed\n", total_failed);

    printf("  wall=%.4fs  total_ops=%ld  throughput=%.1f ops/s  mean_latency=%.4fms\n",
        wall_seconds, total_ops,
        (wall_seconds > 0.0) ? (double)total_ops / wall_seconds : 0.0, mean_latency);

    csv_write_scaling_row(csv, algo, op, threads, iters,
                           wall_seconds, total_ops, mean_latency);

    fclose(csv);
    pthread_barrier_destroy(&barrier);
    free(tids);
    free(ctxs);
    return 0;
}
