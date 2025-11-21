#include "utils/s2n_log.h"

static s2n_log_fn s2n_global_log;

void s2n_set_global_log(s2n_log_fn cb) {
    s2n_global_log = cb;
}
