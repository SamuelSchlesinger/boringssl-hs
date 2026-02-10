#include "constants.h"

/* NID constants for EC curves */
int bssl_NID_X9_62_prime256v1(void) { return NID_X9_62_prime256v1; }
int bssl_NID_secp384r1(void) { return NID_secp384r1; }
int bssl_NID_secp521r1(void) { return NID_secp521r1; }

/* NID constants for digest algorithms */
int bssl_NID_sha1(void) { return NID_sha1; }
int bssl_NID_sha224(void) { return NID_sha224; }
int bssl_NID_sha256(void) { return NID_sha256; }
int bssl_NID_sha384(void) { return NID_sha384; }
int bssl_NID_sha512(void) { return NID_sha512; }
int bssl_NID_sha512_256(void) { return NID_sha512_256; }
int bssl_NID_md5(void) { return NID_md5; }

/* Struct sizes for ML-KEM */
size_t bssl_sizeof_MLKEM768_private_key(void) { return sizeof(struct MLKEM768_private_key); }
size_t bssl_sizeof_MLKEM768_public_key(void) { return sizeof(struct MLKEM768_public_key); }
size_t bssl_sizeof_MLKEM1024_private_key(void) { return sizeof(struct MLKEM1024_private_key); }
size_t bssl_sizeof_MLKEM1024_public_key(void) { return sizeof(struct MLKEM1024_public_key); }

/* Struct sizes for ML-DSA */
size_t bssl_sizeof_MLDSA44_private_key(void) { return sizeof(struct MLDSA44_private_key); }
size_t bssl_sizeof_MLDSA44_public_key(void) { return sizeof(struct MLDSA44_public_key); }
size_t bssl_sizeof_MLDSA65_private_key(void) { return sizeof(struct MLDSA65_private_key); }
size_t bssl_sizeof_MLDSA65_public_key(void) { return sizeof(struct MLDSA65_public_key); }
size_t bssl_sizeof_MLDSA87_private_key(void) { return sizeof(struct MLDSA87_private_key); }
size_t bssl_sizeof_MLDSA87_public_key(void) { return sizeof(struct MLDSA87_public_key); }

/* Struct size for X-Wing */
size_t bssl_sizeof_XWING_private_key(void) { return sizeof(struct XWING_private_key); }
