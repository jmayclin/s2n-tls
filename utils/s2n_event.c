#include <string.h>

#include "utils/s2n_event.h"


s2n_event_log_fn s2n_event_log_cb;

int s2n_default_event_log_cb(const char *level, const char *description) {
    /* define on their own lines to make toggling visibility easy */
    if (memcmp(level, "DEBUG", sizeof "DEBUG") == 0) {
        return 0;
    }
    if ((memcmp(level, "TRACE", sizeof "TRACE") == 0)) {
        return 0;
    }
    printf("[%s]: %s\n", level, description);
    return 0;
}


S2N_API extern int s2n_global_set_event_log_cb(s2n_event_log_fn callback) {
    s2n_event_log_cb = callback;
    return 0;
}
