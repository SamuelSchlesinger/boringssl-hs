#ifndef CBS_HELPERS_H
#define CBS_HELPERS_H

#include <openssl/bytestring.h>
#include <stddef.h>

/* Initialize a CBS from a pointer and length, avoiding manual struct layout in Haskell. */
void bssl_CBS_init(CBS *cbs, const uint8_t *data, size_t len);

/* Return sizeof(CBS) so Haskell can allocate the right amount of stack space. */
size_t bssl_CBS_size(void);

#endif
