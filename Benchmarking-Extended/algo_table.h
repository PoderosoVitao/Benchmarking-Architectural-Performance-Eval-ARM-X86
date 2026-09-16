/**
 * algo_table.h
 * Shared PQC algorithm table used by bench_pqc.c and bench_pqc_threaded.c.
 * Kept in one place so the two binaries can't drift apart as algorithms
 * are added, renamed, or dropped.
 */

#ifndef ALGO_TABLE_H
#define ALGO_TABLE_H

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
     * "s" = small signature, "f" = fast signing. Both are standardized,
     * real deployment choices — "f" trades a larger signature for ~40-60x
     * faster signing, and is the parameter set an interactive-latency
     * deployment would actually pick, so both must be measured before
     * drawing any "rules out interactive use"-style conclusion.
     * Full 3-level (128/192/256) x 2-hash (SHA2/SHAKE) x 2-speed (s/f)
     * matrix — SHAKE-192 used to be missing here, which meant the
     * "192 is slower than 256" non-monotonicity noted in the paper's
     * results could only be checked against SHA2's own numbers, with no
     * way to tell whether it's a general property of the standardized
     * hypertree layer/height split or a SHA2-specific artifact. */
    { "SLH_DSA_PURE_SHA2_128S",  "SLH-DSA-SHA2-128s (SPHINCS+)", "1" },
    { "SLH_DSA_PURE_SHA2_192S",  "SLH-DSA-SHA2-192s (SPHINCS+)", "3" },
    { "SLH_DSA_PURE_SHA2_256S",  "SLH-DSA-SHA2-256s (SPHINCS+)", "5" },
    { "SLH_DSA_PURE_SHAKE_128S", "SLH-DSA-SHAKE-128s (SPHINCS+)","1" },
    { "SLH_DSA_PURE_SHAKE_192S", "SLH-DSA-SHAKE-192s (SPHINCS+)","3" },
    { "SLH_DSA_PURE_SHAKE_256S", "SLH-DSA-SHAKE-256s (SPHINCS+)","5" },
    { "SLH_DSA_PURE_SHA2_128F",  "SLH-DSA-SHA2-128f (SPHINCS+)", "1" },
    { "SLH_DSA_PURE_SHA2_192F",  "SLH-DSA-SHA2-192f (SPHINCS+)", "3" },
    { "SLH_DSA_PURE_SHA2_256F",  "SLH-DSA-SHA2-256f (SPHINCS+)", "5" },
    { "SLH_DSA_PURE_SHAKE_128F", "SLH-DSA-SHAKE-128f (SPHINCS+)","1" },
    { "SLH_DSA_PURE_SHAKE_192F", "SLH-DSA-SHAKE-192f (SPHINCS+)","3" },
    { "SLH_DSA_PURE_SHAKE_256F", "SLH-DSA-SHAKE-256f (SPHINCS+)","5" },

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

#endif /* ALGO_TABLE_H */
