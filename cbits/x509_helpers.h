#ifndef BSSL_X509_HELPERS_H
#define BSSL_X509_HELPERS_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* BASIC_CONSTRAINTS field accessors */
int bssl_basic_constraints_ca(const BASIC_CONSTRAINTS *bc);
ASN1_INTEGER *bssl_basic_constraints_pathlen(const BASIC_CONSTRAINTS *bc);

/* GENERAL_NAME field accessors */
int bssl_general_name_type(const GENERAL_NAME *gen);
void *bssl_general_name_data(const GENERAL_NAME *gen);

/* STACK_OF(GENERAL_NAME) accessors */
int bssl_sk_GENERAL_NAME_num(const GENERAL_NAMES *sk);
GENERAL_NAME *bssl_sk_GENERAL_NAME_value(const GENERAL_NAMES *sk, int i);

/* ASN1_STRING accessors */
const unsigned char *bssl_ASN1_STRING_get0_data(const ASN1_STRING *str);
int bssl_ASN1_STRING_length(const ASN1_STRING *str);

/* STACK_OF(X509) helpers for chain verification */
STACK_OF(X509) *bssl_sk_X509_new_null(void);
int bssl_sk_X509_push(STACK_OF(X509) *sk, X509 *cert);
void bssl_sk_X509_free(STACK_OF(X509) *sk);

#endif /* BSSL_X509_HELPERS_H */
