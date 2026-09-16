/**
 * benchmark.h
 * Shared utilities for the PQC benchmark suite.
 *
 * Provides:
 *   - CPU-cycle counting via perf_event_open (PRIMARY latency metric)
 *   - High-resolution wall-clock timing via clock_gettime(CLOCK_MONOTONIC)
 *     (secondary metric, kept for the deployment/ms-latency argument)
 *   - Statistical functions: mean, median, std, P95, P99 (both metrics)
 *   - Peak resident memory measurement via getrusage(RUSAGE_SELF)
 *   - CSV output helpers
 *
 * Compile with: -lm
 */

#ifndef BENCHMARK_H
#define BENCHMARK_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <pthread.h>

/* ── Configuration ─────────────────────────────────────────────────────────── */

#ifndef N_ITERATIONS
#define N_ITERATIONS   1000     /* number of timed iterations per operation   */
#endif
#ifndef WARMUP_MS_DURATION
#define WARMUP_MS_DURATION 300  /* untimed warm-up duration, milliseconds     */
#endif
#ifndef MESSAGE_LEN
#define MESSAGE_LEN      64     /* bytes of dummy message to sign              */
#endif

/* ── CPU cycles (primary latency metric) ───────────────────────────────────────
 * Deliberately NOT rdtsc (x86) or cntvct_el0 (ARM): the x86 invariant TSC
 * runs at a fixed reference frequency, not the core's actual clock, and the
 * Raspberry Pi's cntvct_el0 runs off a ~54 MHz generic timer — both measure
 * elapsed time, not retired cycles, which is exactly the confound clock-
 * speed normalization has to correct for after the fact. PMCCNTR_EL0 (the
 * ARM core cycle counter) is not readable from userspace by default either,
 * so there is no assembly shortcut there.
 *
 * perf_event_open with PERF_COUNT_HW_CPU_CYCLES, opened once per process in
 * per-thread mode (pid=0, cpu=-1) and left running, gives a real hardware
 * cycle count directly comparable across platforms with no clock-speed
 * correction needed. Userspace-only (exclude_kernel=1, exclude_hv=1)
 * deliberately: perf_event_paranoid defaults to 2 on both this x86 machine
 * and stock Raspberry Pi OS, which blocks unprivileged kernel-cycle
 * counting outright — requiring root here would make the harness fragile
 * for no benefit, since the crypto calls being measured are pure userspace
 * computation anyway. ─────────────────────────────────────────────────────── */

static long perf_event_open_syscall(struct perf_event_attr *hw_event, pid_t pid,
                                     int cpu, int group_fd, unsigned long flags) {
    return syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/**
 * Opens and enables a per-thread PERF_COUNT_HW_CPU_CYCLES counter for the
 * calling thread. Call once at process start and keep the fd open for the
 * whole run; read_cycles() just samples the running total, the same way
 * now_ns() samples CLOCK_MONOTONIC. Returns -1 on failure (e.g. no PMU
 * access), in which case read_cycles() safely returns 0 and every cycle
 * column downstream reads 0 rather than crashing — ms latency still works.
 */
static int open_cycle_counter(void) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int fd = (int)perf_event_open_syscall(&pe, 0 /* self thread */, -1 /* any cpu */, -1, 0);
    if (fd == -1) {
        fprintf(stderr,
            "WARNING: perf_event_open failed (%s) — cycle counts will read as 0.\n"
            "  Check /proc/sys/kernel/perf_event_paranoid; userspace-only hardware\n"
            "  counters should not need root, but some kernels restrict them further.\n",
            strerror(errno));
        return -1;
    }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    return fd;
}

/** Samples the running cycle count. Safe to call with fd == -1 (returns 0). */
static inline uint64_t read_cycles(int fd) {
    uint64_t count = 0;
    if (fd < 0) return 0;
    if (read(fd, &count, sizeof(count)) != (ssize_t)sizeof(count)) return 0;
    return count;
}

/* ── Timing (secondary metric) ─────────────────────────────────────────────── */

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

/** Returns current per-thread CPU time in nanoseconds (excludes time spent
 * preempted off-CPU). Paired with now_ns() (wall clock) at every timed
 * call: the gap between the two deltas for a given iteration is time the
 * thread was runnable-but-not-running — scheduler preemption, not the
 * crypto call itself. This is what turns "the P99 tail is probably
 * scheduling jitter" from a guess into something with a per-iteration
 * number behind it. */
static inline uint64_t now_cpu_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Measures clock_gettime's own call overhead for a given clockid, by
 * calling it back-to-back N times with no work in between and averaging
 * the deltas. A vDSO-resolved clock (no kernel entry) typically lands in
 * the tens of ns; a real syscall typically lands in the hundreds to low
 * thousands of ns. This does not (and cannot, portably) introspect
 * whether the vDSO path was taken — it measures the thing that actually
 * matters, which is how much the timer itself perturbs a measurement, and
 * reports that number rather than assuming it from the platform.
 */
static double measure_clock_overhead_ns(clockid_t clk) {
    enum { WARM = 1000, N = 100000 };
    struct timespec ts;
    for (int i = 0; i < WARM; i++) clock_gettime(clk, &ts);

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    for (int i = 0; i < N; i++) clock_gettime(clk, &ts);
    clock_gettime(CLOCK_MONOTONIC, &t_end);

    uint64_t elapsed_ns = (uint64_t)(t_end.tv_sec - t_start.tv_sec) * 1000000000ULL
                        + (uint64_t)(t_end.tv_nsec - t_start.tv_nsec);
    return (double)elapsed_ns / (double)N;
}

/** Prints the measured overhead of every clock this harness uses, so the
 * number ships with every run instead of being asserted once in the
 * paper. Called once at startup, before any timed loop. */
static void log_timer_overhead(void) {
    double mono_ns = measure_clock_overhead_ns(CLOCK_MONOTONIC);
    double cpu_ns   = measure_clock_overhead_ns(CLOCK_PROCESS_CPUTIME_ID);
    printf("  Timer overhead : CLOCK_MONOTONIC=%.1f ns/call (%s)\n",
           mono_ns, mono_ns < 100.0 ? "consistent with vDSO" : "consistent with syscall path — check vdso mapping");
    printf("                   CLOCK_PROCESS_CPUTIME_ID=%.1f ns/call (%s)\n",
           cpu_ns, cpu_ns < 100.0 ? "consistent with vDSO" : "consistent with syscall path");
    printf("                   (measured here, not assumed — see log_timer_overhead())\n");
}

/* ── Time-bounded warm-up ───────────────────────────────────────────────────
 * A fixed iteration COUNT warm-up is wrong when iterations are cheap: e.g.
 * 20 iterations of ML-DSA-44 keygen is on the order of ~0.2ms total — far
 * shorter than the Zen 4 boost-clock ramp or the Pi's ondemand governor's
 * sampling window need to reach steady state. Warming up for a fixed
 * DURATION instead (WARMUP_MS_DURATION, default 300ms) guarantees the same
 * physical warm-up time regardless of how fast or slow the operation being
 * warmed is. do/while so at least one call always happens even if a single
 * iteration already exceeds the duration. ─────────────────────────────── */
/* Variadic (not a single `stmt` parameter): a warm-up block containing an
 * array initializer like `OSSL_PARAM params[2] = {a, b};` has a top-level
 * comma outside any parentheses, which the preprocessor treats as a macro
 * argument separator, not punctuation — a plain single-parameter macro
 * would reject that call with "passed 2 arguments, but takes just 1".
 * __VA_ARGS__ reassembles everything between the outer parens verbatim,
 * commas included, so multi-statement/multi-declaration blocks work the
 * same as a single call. */
#define WARMUP_FOR(...) do { \
    uint64_t _warm_deadline = now_ns() + (uint64_t)WARMUP_MS_DURATION * 1000000ULL; \
    do { __VA_ARGS__; } while (now_ns() < _warm_deadline); \
} while (0)

/* ── Cache-cold variant hook ─────────────────────────────────────────────
 * Every measurement in this suite reuses the same key/signature buffers
 * across N_ITERATIONS calls — cache-warm by construction, which
 * overstates performance relative to a real TLS handshake or one-off
 * verification that arrives cache-cold. Compiling with -DCOLD_CACHE=1
 * makes TIMED_ITERATION() evict the working set (by streaming through a
 * buffer larger than the last-level cache, forcing prior contents out via
 * normal replacement — there is no portable userspace cache-flush
 * instruction on ARM the way clflush exists on x86, so eviction-by-
 * replacement is the one technique that works identically on both
 * platforms) immediately before each timed call, and — critically —
 * BEFORE t0/c0/cpu0 are sampled, so the eviction's own cost is never
 * counted as part of the operation's latency; only its cache-cold *effect*
 * on the subsequent call is measured. ───────────────────────────────────── */
#ifndef COLD_CACHE_BUFFER_BYTES
#define COLD_CACHE_BUFFER_BYTES (32 * 1024 * 1024)  /* 32MB: larger than any
                                                        LLC on either study
                                                        platform */
#endif

#ifdef COLD_CACHE
static volatile uint8_t *g_evict_buf = NULL;
static volatile uint64_t g_evict_sink = 0; /* prevents the read loop from
                                               being optimized away */

static void evict_cache_init(void) {
    g_evict_buf = (volatile uint8_t *)malloc(COLD_CACHE_BUFFER_BYTES);
    if (!g_evict_buf) { perror("malloc (cold-cache buffer)"); exit(1); }
    for (size_t i = 0; i < COLD_CACHE_BUFFER_BYTES; i += 4096)
        g_evict_buf[i] = (uint8_t)i;
}

static inline void evict_cache(void) {
    uint64_t sink = 0;
    /* stride by cache-line size (64B, true on both Zen4 and Cortex-A72);
     * touching every line, not every byte, is enough to force replacement
     * without wasting time re-reading bytes already in the same line */
    for (size_t i = 0; i < COLD_CACHE_BUFFER_BYTES; i += 64)
        sink += g_evict_buf[i];
    g_evict_sink = sink;
}
#define COLD_CACHE_EVICT() evict_cache()
#else
#define COLD_CACHE_EVICT() ((void)0)
#endif

/* ── Timed-call macro ───────────────────────────────────────────────────
 * Wraps a single call statement with wall-clock (t0/t1), hardware-cycle
 * (c0/c1), and per-thread-CPU-time (cpu0/cpu1) brackets, in that fixed
 * order, identically at every call site in the suite. Centralizing this
 * (instead of hand-duplicating 5-7 lines at each of the ~20 timed blocks
 * across bench_pqc.c/bench_classical.c/bench_openssl_pqc.c) is what makes
 * it possible to add a new bracket (CLOCK_PROCESS_CPUTIME_ID, added this
 * round) in one place instead of two dozen. Callers must have
 * t0,t1,c0,c1,cpu0,cpu1 (all uint64_t) and cycle_fd in scope. */
#define TIMED_ITERATION(...) do { \
    COLD_CACHE_EVICT(); \
    t0 = now_ns(); \
    c0 = read_cycles(cycle_fd); \
    cpu0 = now_cpu_ns(); \
    __VA_ARGS__; \
    cpu1 = now_cpu_ns(); \
    c1 = read_cycles(cycle_fd); \
    t1 = now_ns(); \
} while (0)

/* ── Statistics ──────────────────────────────────────────────────────────────── */

typedef struct {
    double mean_ms;
    double median_ms;
    double std_ms;
    double p95_ms;
    double p99_ms;
} Stats;

/** Same five statistics, over raw cycle counts instead of milliseconds. */
typedef struct {
    double mean_cycles;
    double median_cycles;
    double std_cycles;
    double p95_cycles;
    double p99_cycles;
} CycleStats;

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

/**
 * Same computation as compute_stats(), directly on raw cycle counts — no
 * unit conversion, since a cycle count needs none.
 */
static CycleStats compute_cycle_stats(const uint64_t *samples, int n) {
    CycleStats s = {0};

    double *cy = (double *)malloc(n * sizeof(double));
    if (!cy) { perror("malloc"); exit(1); }

    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        cy[i] = (double)samples[i];
        sum += cy[i];
    }

    s.mean_cycles = sum / n;

    double variance = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = cy[i] - s.mean_cycles;
        variance += diff * diff;
    }
    s.std_cycles = sqrt(variance / n);

    qsort(cy, n, sizeof(double), cmp_double);

    if (n % 2 == 0)
        s.median_cycles = (cy[n / 2 - 1] + cy[n / 2]) / 2.0;
    else
        s.median_cycles = cy[n / 2];

    int idx_p95 = (int)ceil(0.95 * n) - 1;
    int idx_p99 = (int)ceil(0.99 * n) - 1;
    if (idx_p95 < 0) idx_p95 = 0;
    if (idx_p99 < 0) idx_p99 = 0;
    if (idx_p95 >= n) idx_p95 = n - 1;
    if (idx_p99 >= n) idx_p99 = n - 1;

    s.p95_cycles = cy[idx_p95];
    s.p99_cycles = cy[idx_p99];

    free(cy);
    return s;
}

/* ── Energy (x86 RAPL) ──────────────────────────────────────────────────────────
 * /sys/class/powercap/intel-rapl:0/energy_uj is the package-domain RAPL
 * energy counter (microjoules, monotonically increasing, wraps at
 * max_energy_range_uj — ~65.5 kJ on this machine, i.e. many minutes at any
 * realistic draw, so wrap-around inside one N-iteration block is not a
 * practical concern here). Despite the "intel-rapl" driver name this is
 * present and populated on AMD Zen too (confirmed: package-0 exists on
 * this Ryzen 5 7600) — the kernel's generic RAPL-MSR driver claims it on
 * both vendors' RAPL-compatible parts.
 *
 * Bracketed around the WHOLE N_ITERATIONS loop, not per-iteration like
 * cycles/time: RAPL's own update granularity is far coarser than a single
 * ~10-100us crypto call (typically ~1ms), so per-iteration reads would
 * mostly re-read the same accumulator value and add pure per-call file-I/O
 * overhead for no additional information. Mean energy per operation is
 * therefore (energy_after - energy_before) / N over the full block.
 *
 * This is package-wide energy, not per-process — it includes whatever else
 * was running on the machine during the block. Standard practice for this
 * kind of measurement is a quiet foreground-only run; it is not perfectly
 * attributable to the benchmark alone, and that should be stated wherever
 * this number is used, not papered over.
 *
 * On ARM there is no RAPL equivalent (the Raspberry Pi's SoC exposes no
 * on-chip energy accumulator to the OS) — open_energy_counter() simply
 * returns -1 there, exactly like a permission failure on x86, and callers
 * already treat -1 as "unavailable" uniformly. Per-operation ARM energy
 * needs an external sensor (INA219 or similar) instead — see
 * read_ina219_energy_uj.c.
 * ─────────────────────────────────────────────────────────────────────────── */

#define RAPL_ENERGY_PATH "/sys/class/powercap/intel-rapl:0/energy_uj"

/**
 * Opens the RAPL package-energy sysfs file for repeated reads. Returns
 * NULL if unavailable (wrong architecture, no RAPL, or — as confirmed on
 * this machine — permission denied; the file is mode 0400 root-only by
 * default). Callers must treat a NULL handle as "energy unavailable" and
 * skip energy columns rather than fail the whole run.
 */
static FILE *open_energy_counter(void) {
    FILE *fp = fopen(RAPL_ENERGY_PATH, "r");
    if (!fp) {
        fprintf(stderr,
            "NOTE: RAPL energy counter unavailable (%s: %s) — energy "
            "columns will read as -1.\n"
            "  On x86 this is almost always a permission issue: "
            "%s is root-only by default.\n"
            "  Options: run via sudo, `sudo setcap cap_dac_read_search=ep "
            "<binary>`, or a udev rule granting read access.\n",
            RAPL_ENERGY_PATH, strerror(errno), RAPL_ENERGY_PATH);
        return NULL;
    }
    return fp;
}

/** Re-reads the current cumulative package energy in microjoules. Returns
 * -1 on failure or if fp is NULL (energy unavailable). */
static long long read_energy_uj(FILE *fp) {
    if (!fp) return -1;
    long long uj = -1;
    rewind(fp);
    if (fscanf(fp, "%lld", &uj) != 1) return -1;
    return uj;
}

/* ── Wall-clock epoch markers (for correlating iterations against the
 * external 1Hz frequency/thermal/throttle monitor — see monitor_system.sh)
 * ─────────────────────────────────────────────────────────────────────── */

/** Current wall-clock time, seconds since epoch, sub-second precision.
 * Deliberately CLOCK_REALTIME (not MONOTONIC): this needs to line up with
 * monitor_system.sh's `date +%s.%N` timestamps in post-hoc analysis, which
 * only wall-clock time can do. */
static inline double now_epoch(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1.0e9;
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

/* ── Stack high-water-mark measurement ───────────────────────────────────
 * Peak RSS (above) captures heap + mapped pages, not stack depth
 * specifically — for an embedded target, stack depth is usually the
 * number that decides whether a call fits, and this suite had no measure
 * of it at all before this. Classic canary technique (the same one
 * FreeRTOS's uxTaskGetStackHighWaterMark uses): paint the unused portion
 * of the stack with a known byte pattern before running, then scan from
 * the bottom of the stack region upward for the first byte that's no
 * longer the pattern — that boundary is the deepest point the stack
 * pointer reached. This measures cumulative usage from process/thread
 * start through paint_stack()'s caller down through the workload, not an
 * isolated delta — which is the number that actually matters for "does
 * the whole call path fit," not just the workload's own marginal cost.
 * Known limitation: a false-negative is possible if stale stack content
 * below the true high-water mark happens to already equal the canary
 * byte; accepted here as the standard tradeoff of this technique rather
 * than solved with a random per-run pattern, for reproducibility. ────────── */

#define STACK_CANARY_BYTE   0xAAu
#define STACK_PAINT_MARGIN  4096  /* bytes below the current SP left
                                      unpainted, so painting can never
                                      clobber a frame still in use */

typedef struct {
    uint8_t *stack_low;   /* lowest address of the stack region */
    size_t   stack_size;
} StackRegion;

/** Finds the calling thread's stack bounds. Returns 0 on failure (fields
 * left zeroed; callers must skip stack-HWM reporting rather than treat a
 * zeroed region as real). */
static int get_stack_region(StackRegion *out) {
    memset(out, 0, sizeof(*out));
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return 0;
    void *stackaddr = NULL;
    size_t stacksize = 0;
    int rc = pthread_attr_getstack(&attr, &stackaddr, &stacksize);
    pthread_attr_destroy(&attr);
    if (rc != 0 || !stackaddr || stacksize == 0) return 0;
    out->stack_low = (uint8_t *)stackaddr;
    out->stack_size = stacksize;
    return 1;
}

/** Paints the stack region from its low address up to
 * (current_sp - STACK_PAINT_MARGIN) with STACK_CANARY_BYTE. Call once,
 * immediately before the workload whose stack depth is being measured. */
static void paint_stack(const StackRegion *region) {
    if (!region->stack_low) return;
    volatile uint8_t sp_marker;
    uintptr_t current_sp = (uintptr_t)&sp_marker;
    uintptr_t paint_top = current_sp - STACK_PAINT_MARGIN;
    uintptr_t paint_bottom = (uintptr_t)region->stack_low;
    if (paint_top <= paint_bottom) return; /* margin doesn't fit — skip
                                               rather than risk painting
                                               over a live frame */
    memset(region->stack_low, STACK_CANARY_BYTE, paint_top - paint_bottom);
}

/** Returns the stack high-water mark in bytes: the distance from the
 * deepest disturbed byte (scanning up from the region's low address) to
 * the top of the stack region. 0 if the region is unavailable. */
static size_t measure_stack_hwm(const StackRegion *region) {
    if (!region->stack_low) return 0;
    uint8_t *p = region->stack_low;
    uint8_t *end = region->stack_low + region->stack_size;
    while (p < end && *p == STACK_CANARY_BYTE) p++;
    return (size_t)(end - p);
}

/* ── Stack HWM: whole-process convenience wrapper ────────────────────────
 * The per-primitive get_stack_region/paint_stack/measure_stack_hwm above
 * are generic; this pair is what each binary's main() actually calls —
 * paint once near the top (before the algorithm loop), measure once at
 * the end, write the result to a sidecar file next to the CSV output so
 * bench_mem_isolated.c's fork+exec-per-(algorithm,operation) isolation
 * (see that file for why isolation matters — the same reasoning applies
 * to stack depth as to RSS) gives a genuinely per-operation number, not a
 * whole-run maximum, whenever the caller also passes only_algo+only_op. */
static StackRegion g_stack_region;
static int g_have_stack_region = 0;

static void stack_hwm_start(void) {
    g_have_stack_region = get_stack_region(&g_stack_region);
    if (g_have_stack_region) paint_stack(&g_stack_region);
}

static void stack_hwm_finish(const char *csv_path) {
    if (!g_have_stack_region) return;
    size_t hwm = measure_stack_hwm(&g_stack_region);
    char path[512];
    snprintf(path, sizeof(path), "%s.stack_hwm_bytes", csv_path);
    FILE *fp = fopen(path, "w");
    if (fp) { fprintf(fp, "%zu\n", hwm); fclose(fp); }
    printf("  Stack high-water mark : %zu bytes (see %s)\n", hwm, path);
}

/* ── CSV output ──────────────────────────────────────────────────────────────── */

/**
 * Writes the CSV header row. Call once at the start of the output file.
 * Cycle columns come first (primary metric); ms columns follow (secondary,
 * for the deployment-latency argument).
 */
static void csv_write_header(FILE *fp) {
    fprintf(fp,
        "algorithm,"
        "security_level,"
        "operation,"
        "mean_cycles,"
        "median_cycles,"
        "std_cycles,"
        "p95_cycles,"
        "p99_cycles,"
        "mean_ms,"
        "median_ms,"
        "std_ms,"
        "p95_ms,"
        "p99_ms,"
        "peak_mem_delta_kb,"
        "mean_energy_uj,"
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
 * @param cst            computed cycle statistics (primary metric)
 * @param st             computed ms statistics (secondary metric)
 * @param mem_delta_kb   peak RSS delta in kB during this operation
 * @param mean_energy_uj mean RAPL package energy per operation, microjoules
 *                       (-1 if RAPL unavailable — see open_energy_counter)
 * @param pub_key_bytes  public key size in bytes  (-1 if not applicable)
 * @param priv_key_bytes private key size in bytes (-1 if not applicable)
 * @param sig_bytes      signature size in bytes   (-1 if not applicable)
 */
static void csv_write_row(
    FILE       *fp,
    const char *algorithm,
    const char *security_level,
    const char *operation,
    CycleStats  cst,
    Stats       st,
    long        mem_delta_kb,
    double      mean_energy_uj,
    int         pub_key_bytes,
    int         priv_key_bytes,
    int         sig_bytes
) {
    fprintf(fp,
        "%s,%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.6f,%.6f,%.6f,%.6f,%.6f,%ld,%.3f,%d,%d,%d\n",
        algorithm,
        security_level,
        operation,
        cst.mean_cycles,
        cst.median_cycles,
        cst.std_cycles,
        cst.p95_cycles,
        cst.p99_cycles,
        st.mean_ms,
        st.median_ms,
        st.std_ms,
        st.p95_ms,
        st.p99_ms,
        mem_delta_kb,
        mean_energy_uj,
        pub_key_bytes,
        priv_key_bytes,
        sig_bytes
    );
    fflush(fp);
}

/* ── Raw sample persistence (for boxplots / CDFs) ───────────────────────────── */

/**
 * Writes the raw per-iteration CSV header row. Call once at the start of
 * the raw output file. Cycles first (primary), ms second (secondary).
 * epoch_start is the wall-clock time (seconds since epoch) the block this
 * iteration belongs to began — constant across every row in one block, not
 * a per-iteration timestamp — added so iteration i's approximate wall-clock
 * time can be reconstructed post-hoc as epoch_start + cumsum(ms[0..i]) and
 * cross-referenced against monitor_system.sh's independent 1Hz log, rather
 * than adding a clock_gettime(CLOCK_REALTIME) call inside the timed loop
 * itself (which cycles/ms already bracket as tightly as possible).
 */
static void raw_csv_write_header(FILE *fp) {
    fprintf(fp, "algorithm,operation,iteration,cycles,ms,cpu_ms,sig_len,epoch_start\n");
}

/**
 * Appends one row per sample. Called once per operation block, right after
 * compute_stats()/compute_cycle_stats() on the same arrays, before they are
 * overwritten by the next operation.
 *
 * @param samples_cpu_ns per-iteration CLOCK_PROCESS_CPUTIME_ID deltas
 *                        (parallel to samples_ns/wall-clock) — the gap
 *                        between wall time and CPU time on a given row is
 *                        that iteration's scheduling/preemption jitter.
 * @param sig_len_samples per-iteration signature length in bytes, or NULL
 *                        for op blocks that don't produce one (keygen).
 *                        Passing NULL writes -1 for every row rather than
 *                        requiring every call site to allocate a constant
 *                        array just to satisfy the signature.
 */
static void write_raw_samples(
    FILE       *fp,
    const char *algorithm,
    const char *operation,
    const uint64_t *samples_cycles,
    const uint64_t *samples_ns,
    const uint64_t *samples_cpu_ns,
    const int  *sig_len_samples,
    int n,
    double      epoch_start
) {
    for (int i = 0; i < n; i++) {
        fprintf(fp, "%s,%s,%d,%llu,%.6f,%.6f,%d,%.3f\n",
            algorithm, operation, i,
            (unsigned long long)samples_cycles[i],
            ns_to_ms(samples_ns[i]),
            ns_to_ms(samples_cpu_ns[i]),
            sig_len_samples ? sig_len_samples[i] : -1,
            epoch_start);
    }
    fflush(fp);
}

/**
 * Pretty-prints a result row to stdout for live feedback during the run.
 * Cycles shown first (primary), ms second (secondary).
 */
static void print_result(
    const char *algorithm,
    const char *operation,
    CycleStats  cst,
    Stats       st,
    long        mem_delta_kb,
    double      mean_energy_uj
) {
    char energy_str[32];
    if (mean_energy_uj >= 0)
        snprintf(energy_str, sizeof(energy_str), "%.1f uJ", mean_energy_uj);
    else
        snprintf(energy_str, sizeof(energy_str), "n/a");

    printf("  %-28s %-8s  mean=%10.0f cyc  median=%10.0f cyc  "
           "std=%9.0f cyc  P99=%10.0f cyc  |  mean=%8.4f ms  "
           "mem_delta=%5ld kB  energy=%s\n",
        algorithm, operation,
        cst.mean_cycles, cst.median_cycles, cst.std_cycles, cst.p99_cycles,
        st.mean_ms,
        mem_delta_kb,
        energy_str
    );
}

/* ── Scalability sweep output (thread- or process-level concurrency) ────────
 * Shared schema so thread-level (bench_*_threaded) and process-level
 * (run_concurrency_scaling.sh) sweeps produce directly comparable CSVs.
 * ─────────────────────────────────────────────────────────────────────────── */

/** Writes the header row for a concurrency/scalability sweep CSV. */
static void csv_write_scaling_header(FILE *fp) {
    fprintf(fp,
        "algorithm,operation,workers,iters_per_worker,"
        "wall_seconds,total_ops,throughput_ops_per_sec,mean_latency_ms\n"
    );
}

/**
 * Appends one row of aggregate throughput/latency for a given worker count.
 * "workers" is threads for the thread-level harness, or K processes for the
 * process-level sweep script. throughput is derived here so callers never
 * duplicate the division (and its divide-by-zero guard).
 */
static void csv_write_scaling_row(
    FILE       *fp,
    const char *algorithm,
    const char *operation,
    int         workers,
    int         iters_per_worker,
    double      wall_seconds,
    long        total_ops,
    double      mean_latency_ms
) {
    double throughput = (wall_seconds > 0.0) ? (double)total_ops / wall_seconds : 0.0;
    fprintf(fp, "%s,%s,%d,%d,%.6f,%ld,%.6f,%.6f\n",
        algorithm, operation, workers, iters_per_worker,
        wall_seconds, total_ops, throughput, mean_latency_ms);
    fflush(fp);
}

#endif /* BENCHMARK_H */
