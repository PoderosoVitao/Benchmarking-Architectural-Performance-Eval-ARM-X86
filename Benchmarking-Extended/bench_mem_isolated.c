/**
 * bench_mem_isolated.c
 * Per-algorithm, per-operation peak resident memory, measured in a FRESH
 * process for every single (algorithm, operation, library) combination.
 *
 * Why this exists (isolation): bench_pqc.c / bench_classical.c /
 * bench_openssl_pqc.c each benchmark every one of their algorithms
 * sequentially inside ONE process, and measure memory via ru_maxrss
 * (getrusage's peak-RSS high-water mark). That mark is monotonic for the
 * *whole process lifetime*, not per-operation — so once an early,
 * memory-hungry algorithm (SLH-DSA runs first in bench_pqc.c, by design,
 * to keep warm-up-sensitive fast algorithms last — see algo_table.h)
 * pushes the mark up, every algorithm measured afterward in that same
 * process can show a misleadingly small (often 0 kB) delta regardless of
 * its own real memory footprint, simply because the process-wide peak
 * never has a reason to fall back down. That is almost certainly why the
 * original results showed ~0 kB for nearly every algorithm/operation.
 *
 * This tool sidesteps that entirely: for each (algorithm, operation,
 * library) triple it forks a child that execve()s a FRESH instance of
 * the relevant _fast binary with the already-supported only_algo/only_op
 * filters, and reads that child's OWN ru_maxrss via wait4() the instant
 * it exits — a clean process start every time (execve() replaces the
 * address space outright, so there is no copy-on-write carryover from
 * the parent either), with no cross-algorithm contamination possible.
 *
 * Why this exists (library column): ML-DSA and SLH-DSA are measured
 * twice — once via liboqs (bench_pqc_fast) and once via OpenSSL's own
 * native implementation (bench_openssl_pqc_fast, added specifically to
 * remove the liboqs-vs-OpenSSL library-implementation confound from the
 * classical-vs-PQC comparison; see bench_openssl_pqc.c). Both isolated
 * peak-RSS numbers are reported side by side, tagged by library, rather
 * than picking one — the two numbers are themselves a data point about
 * how much of any memory-footprint difference is algorithm vs. library.
 * RSA-3072/ECDSA-P256 have only one implementation in this suite
 * (OpenSSL) and Falcon has only one (liboqs), so those appear once each.
 *
 * Deliberately uses the _fast (N_ITERATIONS=100) binaries, not the
 * canonical 1000-iteration ones: peak memory stabilizes within the first
 * few calls (buffers are allocated once, outside the timed loop; only
 * genuine library-internal transient allocations could move the peak,
 * and those show up on call one), so 100 iterations costs far less wall
 * time than 1000 while capturing the same peak.
 *
 * Build:
 *   gcc -O2 -o bench_mem_isolated bench_mem_isolated.c
 *   (no liboqs/OpenSSL linkage needed — this only forks/execs the
 *    already-built _fast binaries)
 *
 * Usage:
 *   ./bench_mem_isolated [out.csv]
 *   Requires bench_pqc_fast, bench_classical_fast, and
 *   bench_openssl_pqc_fast to already be built (`make fast &&
 *   make bench_openssl_pqc_fast`).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include "algo_table.h"
#include "algo_table_openssl.h"

#define TMP_CSV     "/tmp/bench_mem_isolated_tmp.csv"
#define TMP_RAW_CSV "/tmp/bench_mem_isolated_tmp_raw.csv"

static const char *OPS[] = { "keygen", "sign", "verify" };

/**
 * Runs one algorithm/operation combination in a fresh child process.
 * Writes that child's own peak RSS in kB (0 on failure) to *rss_out, and
 * its stack high-water mark in bytes (0 if unavailable) to *stack_hwm_out.
 * Isolation is what makes both numbers trustworthy: see this file's
 * header comment for RSS, and benchmark.h's stack_hwm_start/finish for
 * why the same fork+exec-per-combo isolation gives a genuinely per-
 * operation stack depth too, not a whole-run maximum.
 */
static void run_isolated(const char *binary, const char *algo_name, const char *op,
                          long *rss_out, size_t *stack_hwm_out) {
    *rss_out = 0;
    *stack_hwm_out = 0;

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }

    if (pid == 0) {
        /* child: execve() replaces this process image entirely — a
         * genuinely fresh address space, nothing inherited from the
         * parent's own memory footprint */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
        execl(binary, binary, TMP_CSV, TMP_RAW_CSV, algo_name, op, (char *)NULL);
        perror("execl");
        _exit(127);
    }

    int status;
    struct rusage usage;
    if (wait4(pid, &status, 0, &usage) < 0) { perror("wait4"); return; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "  WARNING: %s %s %s exited abnormally (status %d)\n",
                binary, algo_name, op, status);
    }
    *rss_out = usage.ru_maxrss; /* kB on Linux — this child's own isolated peak RSS */

    /* stack_hwm_finish() in the child wrote "<TMP_CSV>.stack_hwm_bytes" —
     * read it back and remove it so a failed/skipped next run can't read
     * a stale value left over from this one. */
    char path[512];
    snprintf(path, sizeof(path), "%s.stack_hwm_bytes", TMP_CSV);
    FILE *fp = fopen(path, "r");
    if (fp) {
        unsigned long long v = 0;
        if (fscanf(fp, "%llu", &v) == 1) *stack_hwm_out = (size_t)v;
        fclose(fp);
        remove(path);
    }
}

static void report(FILE *csv, const char *display_name, const char *op,
                    const char *library, long rss, size_t stack_hwm) {
    printf("  %-30s %-8s %-8s  isolated peak RSS = %6ld kB  stack HWM = %8zu B\n",
           display_name, op, library, rss, stack_hwm);
    fprintf(csv, "%s,%s,%s,%ld,%zu\n", display_name, op, library, rss, stack_hwm);
    fflush(csv);
}

int main(int argc, char *argv[]) {
    const char *csv_path = (argc > 1) ? argv[1] : "mem_isolated.csv";
    FILE *csv = fopen(csv_path, "w");
    if (!csv) { perror("fopen"); return 1; }
    fprintf(csv, "algorithm,operation,library,isolated_peak_rss_kb,stack_hwm_bytes\n");

    printf("=================================================================\n");
    printf("  Isolated peak-RSS + stack HWM: one fresh process per (algorithm, operation, library)\n");
    printf("  output CSV: %s\n", csv_path);
    printf("=================================================================\n");

    long rss;
    size_t stack_hwm;

    /* PQC via liboqs — every algorithm this suite covers, including
     * Falcon, which has no OpenSSL counterpart */
    for (int i = 0; i < N_ALGORITHMS; i++)
        for (int j = 0; j < 3; j++) {
            run_isolated("./bench_pqc_fast", ALGORITHMS[i].oqs_name, OPS[j], &rss, &stack_hwm);
            report(csv, ALGORITHMS[i].display_name, OPS[j], "liboqs", rss, stack_hwm);
        }

    /* ML-DSA / SLH-DSA again, this time via OpenSSL's native
     * implementation — the library-controlled comparison */
    for (int i = 0; i < N_ALGORITHMS_OPENSSL; i++)
        for (int j = 0; j < 3; j++) {
            run_isolated("./bench_openssl_pqc_fast",
                          ALGORITHMS_OPENSSL[i].openssl_name, OPS[j], &rss, &stack_hwm);
            report(csv, ALGORITHMS_OPENSSL[i].display_name, OPS[j], "openssl", rss, stack_hwm);
        }

    /* RSA-3072 / ECDSA-P256 — OpenSSL only, one implementation in this suite */
    static const char *CLASSICAL[] = { "RSA-3072", "ECDSA-P256" };
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 3; j++) {
            run_isolated("./bench_classical_fast", CLASSICAL[i], OPS[j], &rss, &stack_hwm);
            report(csv, CLASSICAL[i], OPS[j], "openssl", rss, stack_hwm);
        }

    fclose(csv);
    printf("\nDone. Results written to: %s\n", csv_path);
    return 0;
}
