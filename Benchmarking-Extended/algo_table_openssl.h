/**
 * algo_table_openssl.h
 * Shared PQC algorithm table for bench_openssl_pqc.c and
 * bench_mem_isolated.c. Kept separate from algo_table.h (liboqs's own
 * naming) because OpenSSL uses different name strings and, as of this
 * writing, does not implement Falcon at all — mirroring that table
 * one-to-one here would misrepresent OpenSSL's actual coverage.
 */

#ifndef ALGO_TABLE_OPENSSL_H
#define ALGO_TABLE_OPENSSL_H

typedef struct {
    const char *openssl_name;   /* exact string for EVP_PKEY_CTX_new_from_name */
    const char *display_name;   /* matches algo_table.h's display names so the
                                    liboqs-path and OpenSSL-path results for
                                    the same algorithm join cleanly */
    const char *security_level;
} OsslAlgoEntry;

static const OsslAlgoEntry ALGORITHMS_OPENSSL[] = {
    { "ML-DSA-44",          "ML-DSA-44 (Dilithium2)",       "2" },
    { "ML-DSA-65",          "ML-DSA-65 (Dilithium3)",       "3" },
    { "ML-DSA-87",          "ML-DSA-87 (Dilithium5)",       "5" },
    { "SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128s (SPHINCS+)", "1" },
    { "SLH-DSA-SHA2-192s",  "SLH-DSA-SHA2-192s (SPHINCS+)", "3" },
    { "SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256s (SPHINCS+)", "5" },
    { "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s (SPHINCS+)","1" },
    { "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s (SPHINCS+)","3" },
    { "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s (SPHINCS+)","5" },
    /* "f" = fast signing, ~40-60x faster than "s" at the cost of a larger
     * signature — see algo_table.h for why these matter. Confirmed present
     * via `openssl list -signature-algorithms` on the installed 3.6.3. */
    { "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-128f (SPHINCS+)", "1" },
    { "SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-192f (SPHINCS+)", "3" },
    { "SLH-DSA-SHA2-256f",  "SLH-DSA-SHA2-256f (SPHINCS+)", "5" },
    { "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f (SPHINCS+)","1" },
    { "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f (SPHINCS+)","3" },
    { "SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f (SPHINCS+)","5" },
};
static const int N_ALGORITHMS_OPENSSL =
    (int)(sizeof(ALGORITHMS_OPENSSL) / sizeof(ALGORITHMS_OPENSSL[0]));

#endif /* ALGO_TABLE_OPENSSL_H */
