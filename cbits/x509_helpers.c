#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stddef.h>

/* BASIC_CONSTRAINTS field accessors */
int bssl_basic_constraints_ca(const BASIC_CONSTRAINTS *bc) {
    return bc->ca;
}

ASN1_INTEGER *bssl_basic_constraints_pathlen(const BASIC_CONSTRAINTS *bc) {
    return bc->pathlen;
}

/* GENERAL_NAME field accessors */
int bssl_general_name_type(const GENERAL_NAME *gen) {
    return gen->type;
}

void *bssl_general_name_data(const GENERAL_NAME *gen) {
    return gen->d.ptr;
}

/* STACK_OF(GENERAL_NAME) accessors */
int bssl_sk_GENERAL_NAME_num(const GENERAL_NAMES *sk) {
    return (int)sk_GENERAL_NAME_num(sk);
}

GENERAL_NAME *bssl_sk_GENERAL_NAME_value(const GENERAL_NAMES *sk, int i) {
    return sk_GENERAL_NAME_value(sk, (size_t)i);
}

/* ASN1_STRING accessors */
const unsigned char *bssl_ASN1_STRING_get0_data(const ASN1_STRING *str) {
    return ASN1_STRING_get0_data(str);
}

int bssl_ASN1_STRING_length(const ASN1_STRING *str) {
    return ASN1_STRING_length(str);
}

/* STACK_OF(X509) helpers for chain verification */
STACK_OF(X509) *bssl_sk_X509_new_null(void) {
    return sk_X509_new_null();
}

int bssl_sk_X509_push(STACK_OF(X509) *sk, X509 *cert) {
    return (int)sk_X509_push(sk, cert);
}

void bssl_sk_X509_free(STACK_OF(X509) *sk) {
    sk_X509_free(sk);
}
