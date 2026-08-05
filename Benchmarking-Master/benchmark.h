/**
 * benchmark.h
 * Shared utilities for the PQC benchmark suite.
 *
 * Provides:
 *   - High-resolution timing via clock_gettime(CLOCK_MONOTONIC)
 *   - Statistical functions: mean, median, std, P95, P99
 *   - Peak resident memory measurement via getrusage(RUSAGE_SELF)
 *   - CSV output helpers
 *
 * Compile with: -lm
 */

#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <sys/resource.h>

/* ── Configuration ─────────────────────────────────────────────────────────── */

#ifndef N_ITERATIONS
#define N_ITERATIONS   1000     /* number of timed iterations per operation   */
#endif
#ifndef WARMUP_ITERS
#define WARMUP_ITERS     20     /* untimed warm-up iterations before benchmark */
#endif
#define MESSAGE_LEN      64     /* bytes of dummy message to sign              */

/* ── Timing ─────────────────────────────────────────────────────────────────── */

/** Returns current time in nanoseconds (monotonic clock). */
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/** Converts nanoseconds to milliseconds. */
static inline double ns_to_ms(uint64_t ns) {
    return (double)ns / 1.0e6;
}

/* ── Statistics ──────────────────────────────────────────────────────────────── */

typedef struct {
    double mean_ms;
    double median_ms;
    double std_ms;
    double p95_ms;
    double p99_ms;
} Stats;

/** Comparison function for qsort (ascending doubles). */
static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

/**
 * Computes mean, median, std, P95 and P99 from an array of timing samples
 * (in nanoseconds). Sorts a copy internally — original array is unchanged.
 */
static Stats compute_stats(const uint64_t *samples, int n) {
    Stats s = {0};

    /* copy and convert to ms for computation */
    double *ms = (double *)malloc(n * sizeof(double));
    if (!ms) { perror("malloc"); exit(1); }

    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        ms[i] = ns_to_ms(samples[i]);
        sum += ms[i];
    }

    s.mean_ms = sum / n;

    /* standard deviation */
    double variance = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = ms[i] - s.mean_ms;
        variance += diff * diff;
    }
    s.std_ms = sqrt(variance / n);

    /* sort for median and percentiles */
    qsort(ms, n, sizeof(double), cmp_double);

    /* median */
    if (n % 2 == 0)
        s.median_ms = (ms[n / 2 - 1] + ms[n / 2]) / 2.0;
    else
        s.median_ms = ms[n / 2];

    /* percentiles — nearest-rank method */
    int idx_p95 = (int)ceil(0.95 * n) - 1;
    int idx_p99 = (int)ceil(0.99 * n) - 1;
    if (idx_p95 < 0) idx_p95 = 0;
    if (idx_p99 < 0) idx_p99 = 0;
    if (idx_p95 >= n) idx_p95 = n - 1;
    if (idx_p99 >= n) idx_p99 = n - 1;

    s.p95_ms = ms[idx_p95];
    s.p99_ms = ms[idx_p99];

    free(ms);
    return s;
}

/* ── Memory measurement ──────────────────────────────────────────────────────── */

/**
 * Reads ru_maxrss (peak resident set size, kB on Linux) via getrusage().
 * Unlike a plain VmRSS snapshot, this is a kernel-tracked high-water mark:
 * it only ever increases, and it updates whenever the process's RSS exceeds
 * its prior historical peak, not just at the two moments this function is
 * called. Reading it once before and once after an iteration block and
 * subtracting therefore captures any transient peak that occurred *inside*
 * the block, even if memory was freed again before the block ended, without
 * adding any per-iteration sampling overhead to the timed loop itself.
 */
static long read_peak_rss_kb(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return 0L;
    return ru.ru_maxrss; /* kB on Linux */
}

/* ── CSV output ──────────────────────────────────────────────────────────────── */

/**
 * Writes the CSV header row. Call once at the start of the output file.
 */
static void csv_write_header(FILE *fp) {
    fprintf(fp,
        "algorithm,"
        "security_level,"
        "operation,"
        "mean_ms,"
        "median_ms,"
        "std_ms,"
        "p95_ms,"
        "p99_ms,"
        "peak_mem_delta_kb,"
        "pub_key_bytes,"
        "priv_key_bytes,"
        "sig_bytes\n"
    );
}

/**
 * Writes one result row to the CSV file.
 *
 * @param fp             output file pointer
 * @param algorithm      algorithm name string (e.g. "Dilithium2")
 * @param security_level NIST security level string (e.g. "1", "3", "5", "classical")
 * @param operation      "keygen", "sign", or "verify"
 * @param st             computed statistics
 * @param mem_delta_kb   peak RSS delta in kB during this operation
 * @param pub_key_bytes  public key size in bytes  (-1 if not applicable)
 * @param priv_key_bytes private key size in bytes (-1 if not applicable)
 * @param sig_bytes      signature size in bytes   (-1 if not applicable)
 */
static void csv_write_row(
    FILE       *fp,
    const char *algorithm,
    const char *security_level,
    const char *operation,
    Stats       st,
    long        mem_delta_kb,
    int         pub_key_bytes,
    int         priv_key_bytes,
    int         sig_bytes
) {
    fprintf(fp,
        "%s,%s,%s,%.6f,%.6f,%.6f,%.6f,%.6f,%ld,%d,%d,%d\n",
        algorithm,
        security_level,
        operation,
        st.mean_ms,
        st.median_ms,
        st.std_ms,
        st.p95_ms,
        st.p99_ms,
        mem_delta_kb,
        pub_key_bytes,
        priv_key_bytes,
        sig_bytes
    );
    fflush(fp);
}

/* ── Raw sample persistence (for boxplots / CDFs) ───────────────────────────── */

/**
 * Writes the raw per-iteration CSV header row. Call once at the start of
 * the raw output file.
 */
static void raw_csv_write_header(FILE *fp) {
    fprintf(fp, "algorithm,operation,iteration,ms\n");
}

/**
 * Appends one row per sample in the array (in nanoseconds, converted to ms).
 * Called once per operation block, right after compute_stats() on the same
 * samples array, before it is overwritten by the next operation.
 */
static void write_raw_samples(
    FILE       *fp,
    const char *algorithm,
    const char *operation,
    const uint64_t *samples_ns,
    int n
) {
    for (int i = 0; i < n; i++) {
        fprintf(fp, "%s,%s,%d,%.6f\n",
            algorithm, operation, i, ns_to_ms(samples_ns[i]));
    }
    fflush(fp);
}

/**
 * Pretty-prints a result row to stdout for live feedback during the run.
 */
static void print_result(
    const char *algorithm,
    const char *operation,
    Stats       st,
    long        mem_delta_kb
) {
    printf("  %-28s %-8s  mean=%8.4f ms  median=%8.4f ms  "
           "std=%7.4f ms  P95=%8.4f ms  P99=%8.4f ms  "
           "mem_delta=%5ld kB\n",
        algorithm, operation,
        st.mean_ms, st.median_ms, st.std_ms,
        st.p95_ms,  st.p99_ms,
        mem_delta_kb
    );
}

#endif /* BENCHMARK_H */
