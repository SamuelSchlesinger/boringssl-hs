#include "trust_token_helpers.h"

size_t boringssl_sk_TRUST_TOKEN_num(const STACK_OF(TRUST_TOKEN) *sk) {
    if (!sk) return 0;
    return sk_TRUST_TOKEN_num(sk);
}

TRUST_TOKEN *boringssl_sk_TRUST_TOKEN_value(const STACK_OF(TRUST_TOKEN) *sk, size_t i) {
    if (!sk) return NULL;
    return sk_TRUST_TOKEN_value(sk, i);
}

void boringssl_sk_TRUST_TOKEN_pop_free(STACK_OF(TRUST_TOKEN) *sk) {
    if (!sk) return;
    sk_TRUST_TOKEN_pop_free(sk, TRUST_TOKEN_free);
}

const uint8_t *boringssl_TRUST_TOKEN_data(const TRUST_TOKEN *token) {
    if (!token) return NULL;
    return token->data;
}

size_t boringssl_TRUST_TOKEN_len(const TRUST_TOKEN *token) {
    if (!token) return 0;
    return token->len;
}
