#ifndef BSSL_CONSTANTS_H
#define BSSL_CONSTANTS_H

#include <openssl/nid.h>
#include <openssl/ec.h>
#include <openssl/digest.h>
#include <openssl/mlkem.h>
#include <openssl/mldsa.h>
#include <openssl/xwing.h>
#include <stddef.h>

/* NID constants for EC curves */
int bssl_NID_X9_62_prime256v1(void);
int bssl_NID_secp384r1(void);
int bssl_NID_secp521r1(void);

/* NID constants for digest algorithms */
int bssl_NID_sha1(void);
int bssl_NID_sha224(void);
int bssl_NID_sha256(void);
int bssl_NID_sha384(void);
int bssl_NID_sha512(void);
int bssl_NID_sha512_256(void);
int bssl_NID_md5(void);

/* Struct sizes for ML-KEM */
size_t bssl_sizeof_MLKEM768_private_key(void);
size_t bssl_sizeof_MLKEM768_public_key(void);
size_t bssl_sizeof_MLKEM1024_private_key(void);
size_t bssl_sizeof_MLKEM1024_public_key(void);

/* Struct sizes for ML-DSA */
size_t bssl_sizeof_MLDSA44_private_key(void);
size_t bssl_sizeof_MLDSA44_public_key(void);
size_t bssl_sizeof_MLDSA65_private_key(void);
size_t bssl_sizeof_MLDSA65_public_key(void);
size_t bssl_sizeof_MLDSA87_private_key(void);
size_t bssl_sizeof_MLDSA87_public_key(void);

/* Struct size for X-Wing */
size_t bssl_sizeof_XWING_private_key(void);

#endif /* BSSL_CONSTANTS_H */
