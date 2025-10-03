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

#include <s2n.h>

typedef enum {
    S2N_RESUMPTION_NONE = 0,
    S2N_RESUMPTION_SUCCESS,
    S2N_RESUMPTION_TICKET_EXPIRED,
    S2N_RESUMPTION_FORMAT_UNKNOWN,
    S2N_RESUMPTION_STEK_UNKNOWN,
    S2N_RESUMPTION_OTHER_ERROR,
} s2n_resumption_outcome;

struct s2n_event_resumption {
    bool supports_resumption;
    bool attempted_resumption;
    s2n_resumption_outcome outcome;
    uint64_t ticket_age_ms;
    uint64_t material_age_ms;
};

struct s2n_event_handshake {
    int protocol_version;
    /* static memory */
    const char * cipher;
    /* static memory */
    const char * group;
    /* static memory */
    const char * signature;
    /* true if the connection was resumed */
    bool resumed;
    /* true if the connection performed a hello retry */
    bool hello_retry;

    /* the amount of time between when the s2n_negotiate was started and when it
     * finished, including network round trips */
    uint64_t handshake_duration_ns;
    /* the amount of time inside the synchronus s2n_negotiate method */
    uint64_t handshake_negotiate_duration_ns;

    struct s2n_event_resumption resumption_event;
};

typedef void (*s2n_event_on_handshake_cb)(void *subscriber, struct s2n_event_handshake *event);

S2N_API extern int s2n_config_set_subscriber(struct s2n_config *config, void *subscriber);
S2N_API extern int s2n_config_set_handshake_event(struct s2n_config *config, s2n_event_on_handshake_cb callback);
