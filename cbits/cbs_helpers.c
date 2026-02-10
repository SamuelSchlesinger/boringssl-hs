#include "cbs_helpers.h"

void bssl_CBS_init(CBS *cbs, const uint8_t *data, size_t len) {
    CBS_init(cbs, data, len);
}

size_t bssl_CBS_size(void) {
    return sizeof(CBS);
}
