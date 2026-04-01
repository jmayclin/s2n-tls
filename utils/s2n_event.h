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

#pragma once

#include <stdio.h>

#include "api/s2n.h"

/* Global event logging callback */
extern s2n_event_log_fn s2n_event_log_cb;

int s2n_default_event_log_cb(const char *level, const char *file, int line,
        const char *function, const char *description);

#define S2N_LOG(level, ...)                                              \
    do {                                                                 \
        if (s2n_event_log_cb) {                                          \
            char _s2n_log_buf[256];                                      \
            snprintf(_s2n_log_buf, sizeof(_s2n_log_buf), __VA_ARGS__);   \
            s2n_event_log_cb(level, __FILE__, __LINE__, __func__,        \
                    _s2n_log_buf);                                        \
        }                                                                \
    } while (0)

#define S2N_LOG_TRACE(...) S2N_LOG("TRACE", __VA_ARGS__)
#define S2N_LOG_DEBUG(...) S2N_LOG("DEBUG", __VA_ARGS__)
#define S2N_LOG_INFO(...)  S2N_LOG("INFO", __VA_ARGS__)
#define S2N_LOG_WARN(...)  S2N_LOG("WARN", __VA_ARGS__)
#define S2N_LOG_ERROR(...) S2N_LOG("ERROR", __VA_ARGS__)
