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

struct s2n_event_handshake {
    uint8_t protocol_version;
    /* static memory */
    char * cipher;
    /* static memory */
    char * group;
    /* static memory */
    char * signature;
    /* true if the connection was resumed */
    bool resumed;
    bool supports_resumption;
    bool attempted_resumption;
};

typedef void (*s2n_on_handshake_complete)(void *subscriber, struct s2n_event_handshake *event);

S2N_API extern int s2n_config_set_subscriber(struct s2n_config *config, void *subscriber);
S2N_API extern int s2n_config_set_handshake_event(struct s2n_config *config, s2n_on_handshake_complete callback);

void s2n_event_on_handshake_finished(void * subscriber, struct s2n_event_handshake *event);
