#ifndef BSSL_TRUST_TOKEN_HELPERS_H
#define BSSL_TRUST_TOKEN_HELPERS_H

#include <openssl/trust_token.h>
#include <openssl/stack.h>
#include <stddef.h>
#include <stdint.h>

size_t boringssl_sk_TRUST_TOKEN_num(const STACK_OF(TRUST_TOKEN) *sk);
TRUST_TOKEN *boringssl_sk_TRUST_TOKEN_value(const STACK_OF(TRUST_TOKEN) *sk, size_t i);
void boringssl_sk_TRUST_TOKEN_pop_free(STACK_OF(TRUST_TOKEN) *sk);
const uint8_t *boringssl_TRUST_TOKEN_data(const TRUST_TOKEN *token);
size_t boringssl_TRUST_TOKEN_len(const TRUST_TOKEN *token);

#endif /* BSSL_TRUST_TOKEN_HELPERS_H */
