/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <string.h>

#include "utils/s2n_event.h"

s2n_event_log_fn s2n_event_log_cb;

int s2n_default_event_log_cb(const char *level, const char *file, int line,
        const char *function, const char *description)
{
    if (memcmp(level, "TRACE", sizeof("TRACE")) == 0) {
        return 0;
    }
#ifndef S2N_EVENT_LOG_DEBUG
    if (memcmp(level, "DEBUG", sizeof("DEBUG")) == 0) {
        return 0;
    }
#endif
    printf("[%s][%s:%d %s] %s\n", level, file, line, function, description);
    return 0;
}

int s2n_global_set_event_log_cb(s2n_event_log_fn callback)
{
    s2n_event_log_cb = callback;
    return 0;
}
