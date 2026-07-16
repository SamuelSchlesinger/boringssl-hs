#ifndef BSSL_HS_SECURE_ALLOC_H
#define BSSL_HS_SECURE_ALLOC_H

#include <stddef.h>

/* Allocate |len| bytes of zero-initialized, page-aligned memory outside the
 * GC heap, locked into RAM on a best-effort basis (mlock / VirtualLock) and
 * excluded from core dumps where the platform supports it (MADV_DONTDUMP).
 * Lock failures are soft: the allocation still succeeds, unlocked, matching
 * libsodium's and OpenSSL's behaviour when RLIMIT_MEMLOCK is exhausted.
 * Returns NULL only if the underlying mapping fails. */
void *bssl_hs_secure_alloc(size_t len);

/* Cleanse (OPENSSL_cleanse) the entire mapped region backing |ptr|, unlock
 * it, and release it. |len| must be the value passed to
 * bssl_hs_secure_alloc. NULL is ignored. */
void bssl_hs_secure_free(void *ptr, size_t len);

#endif
