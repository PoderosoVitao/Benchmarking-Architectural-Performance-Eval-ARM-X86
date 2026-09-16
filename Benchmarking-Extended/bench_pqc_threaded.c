/**
 * bench_pqc_threaded.c
 * Thread-level scalability benchmark for PQC signature algorithms.
 *
 * Unlike run_concurrency_scaling.sh (which launches K independent OS
 * processes, each single-threaded, each with its own address space),
 * this spawns T pthreads inside ONE process. Every thread holds its own
 * OQS_SIG object and its own key pair — nothing is shared between threads
 * except read-only library state — so the aggregate throughput and mean
 * per-op latency measured here reflect real intra-process contention
 * (shared L2/L3 cache, shared memory bandwidth, one scheduler) rather
 * than the OS-level process isolation the K-process experiment captures.
 * The two are complementary, not redundant.
 *
 * All T worker threads finish their own setup (keygen + warm-up) and then
 * block on a pthread_barrier before the timed region starts, so staggered
 * per-thread setup time never leaks into the wall-clock measurement.
 *
 * Build:
 *   gcc -O2 -pthread -o bench_pqc_threaded bench_pqc_threaded.c \
 *       -I$OQS_PREFIX/include -L$OQS_PREFIX/lib -l:liboqs.a -lm
 *
 * Usage:
 *   ./bench_pqc_threaded <oqs_name> <op> <threads> <iters_per_thread> [out.csv]
 *     oqs_name          exact liboqs algorithm name (see algo_table.h)
 *     op                "keygen" | "sign" | "verify"
 *     threads           number of worker threads (e.g. 1, 2, 4, 8)
 *     iters_per_thread  timed iterations run by EACH thread
 *     out.csv           appended to; header written only if the file is new
 *                        (default: thread_scaling.csv)
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
#include <oqs/oqs.h>

#include "benchmark.h"
#include "algo_table.h"

typedef struct {
    const AlgoEntry *entry;
    const char      *op;
    int              iterations;
    pthread_barrier_t *barrier;

    /* per-thread independent state — nothing here is shared with any
     * other thread, deliberately, so there is no ambiguity about liboqs
     * thread-safety: each thread behaves like its own isolated caller. */
    OQS_SIG *sig;
    uint8_t *pub_key, *priv_key, *signature;
    size_t   sig_len;
    uint8_t  message[MESSAGE_LEN];

    /* results, filled in by the thread itself */
    uint64_t total_ns;
    long     ops_done;
    long     failed;
} ThreadCtx;

static void *worker(void *arg) {
    ThreadCtx *ctx = (ThreadCtx *)arg;

    ctx->sig = OQS_SIG_new(ctx->entry->oqs_name);
    if (!ctx->sig) {
        ctx->failed = ctx->iterations;
        pthread_barrier_wait(ctx->barrier); /* still release the barrier */
        return NULL;
    }

    ctx->pub_key   = (uint8_t *)malloc(ctx->sig->length_public_key);
    ctx->priv_key  = (uint8_t *)malloc(ctx->sig->length_secret_key);
    ctx->signature = (uint8_t *)malloc(ctx->sig->length_signature);
    for (int i = 0; i < MESSAGE_LEN; i++) ctx->message[i] = (uint8_t)(i & 0xFF);

    OQS_SIG_keypair(ctx->sig, ctx->pub_key, ctx->priv_key);
    /* sign (and verify) need one valid signature to work with up front */
    OQS_SIG_sign(ctx->sig, ctx->signature, &ctx->sig_len,
                 ctx->message, MESSAGE_LEN, ctx->priv_key);

    /* warm-up, uncounted — time-bounded (WARMUP_MS_DURATION), not a fixed
     * iteration count: see benchmark.h's WARMUP_FOR for why a fixed count
     * under-warms fast operations. */
    WARMUP_FOR({
        if (strcmp(ctx->op, "sign") == 0)
            OQS_SIG_sign(ctx->sig, ctx->signature, &ctx->sig_len,
                         ctx->message, MESSAGE_LEN, ctx->priv_key);
        else if (strcmp(ctx->op, "verify") == 0)
            OQS_SIG_verify(ctx->sig, ctx->message, MESSAGE_LEN,
                            ctx->signature, ctx->sig_len, ctx->pub_key);
        else
            OQS_SIG_keypair(ctx->sig, ctx->pub_key, ctx->priv_key);
    });

    /* Every worker (plus main) waits here. The timed region below only
     * starts once every thread has cleared setup+warm-up, so the wall
     * clock captures a genuinely concurrent execution window. */
    pthread_barrier_wait(ctx->barrier);

    for (int i = 0; i < ctx->iterations; i++) {
        OQS_STATUS rc;
        uint64_t t0 = now_ns();
        if (strcmp(ctx->op, "sign") == 0)
            rc = OQS_SIG_sign(ctx->sig, ctx->signature, &ctx->sig_len,
                               ctx->message, MESSAGE_LEN, ctx->priv_key);
        else if (strcmp(ctx->op, "verify") == 0)
            rc = OQS_SIG_verify(ctx->sig, ctx->message, MESSAGE_LEN,
                                 ctx->signature, ctx->sig_len, ctx->pub_key);
        else
            rc = OQS_SIG_keypair(ctx->sig, ctx->pub_key, ctx->priv_key);
        uint64_t t1 = now_ns();

        if (rc == OQS_SUCCESS) { ctx->total_ns += (t1 - t0); ctx->ops_done++; }
        else ctx->failed++;
    }

    free(ctx->pub_key);
    free(ctx->priv_key);
    free(ctx->signature);
    OQS_SIG_free(ctx->sig);
    return NULL;
}

static int file_is_empty(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 1; /* doesn't exist yet */
    return st.st_size == 0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr,
            "Usage: %s <oqs_name> <keygen|sign|verify> <threads> "
            "<iters_per_thread> [out.csv]\n", argv[0]);
        return 1;
    }

    const char *oqs_name = argv[1];
    const char *op       = argv[2];
    int threads          = atoi(argv[3]);
    int iters            = atoi(argv[4]);
    const char *csv_path = (argc > 5) ? argv[5] : "thread_scaling.csv";

    if (strcmp(op, "keygen") != 0 && strcmp(op, "sign") != 0 && strcmp(op, "verify") != 0) {
        fprintf(stderr, "op must be keygen, sign, or verify\n");
        return 1;
    }
    if (threads < 1 || iters < 1) {
        fprintf(stderr, "threads and iters_per_thread must both be >= 1\n");
        return 1;
    }

    const AlgoEntry *entry = NULL;
    for (int i = 0; i < N_ALGORITHMS; i++)
        if (strcmp(ALGORITHMS[i].oqs_name, oqs_name) == 0) entry = &ALGORITHMS[i];
    if (!entry) {
        fprintf(stderr, "Unknown oqs_name: %s (see algo_table.h)\n", oqs_name);
        return 1;
    }

    int need_header = file_is_empty(csv_path);
    FILE *csv = fopen(csv_path, "a");
    if (!csv) { perror("fopen"); return 1; }
    if (need_header) csv_write_scaling_header(csv);

    printf("[%s] op=%s threads=%d iters/thread=%d\n",
           entry->display_name, op, threads, iters);

    pthread_t *tids = (pthread_t *)malloc((size_t)threads * sizeof(pthread_t));
    ThreadCtx *ctxs = (ThreadCtx *)calloc((size_t)threads, sizeof(ThreadCtx));
    if (!tids || !ctxs) { perror("malloc"); return 1; }

    pthread_barrier_t barrier;
    /* threads + 1: every worker plus main itself must reach the barrier
     * before main starts the wall-clock timer (see below). */
    pthread_barrier_init(&barrier, NULL, (unsigned)threads + 1);

    for (int i = 0; i < threads; i++) {
        ctxs[i].entry      = entry;
        ctxs[i].op         = op;
        ctxs[i].iterations = iters;
        ctxs[i].barrier    = &barrier;
        if (pthread_create(&tids[i], NULL, worker, &ctxs[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    /* main joins the same barrier; when this returns, every worker has
     * just cleared setup and is about to enter its timed loop. */
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

    csv_write_scaling_row(csv, entry->display_name, op, threads, iters,
                           wall_seconds, total_ops, mean_latency);

    fclose(csv);
    pthread_barrier_destroy(&barrier);
    free(tids);
    free(ctxs);
    return 0;
}
