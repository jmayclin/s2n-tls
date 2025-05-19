#include "api/s2n.h"

/* global event logging callback */
extern s2n_event_log_fn s2n_event_log_cb;

int s2n_default_event_log_cb(const char *level, const char *description);

S2N_API extern int s2n_global_set_event_log_cb(s2n_event_log_fn callback);
