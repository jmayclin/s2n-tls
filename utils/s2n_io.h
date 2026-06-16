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

#include "utils/s2n_result.h"
#include "stuffer/s2n_stuffer.h"

// I think that these is also likely a need for a higher level IO construct. This
// would track read/write closed status, and also abstract away the recv buffering
// etc


/**
 * This struct is a thin handle to the outside world. 
 * 
 * All reading or writing of bytes must go through this IO provider
 */
struct s2n_io_provider {
    /**
     * a "true" value indicates s2n managed socket-based IO
     * 
     * In this scenario, it means that s2n-tls has allocated state for the socket
     * based IO and it must be freed when the io provider is cleaned up
     */
    bool managed_send;
    bool managed_recv;

    /* set to `true` when a send call returns EPIPE */
    bool transport_send_closed;
    /* set to `true` when a read call returns 0 */
    bool transport_recv_closed;

    /* book keeping */
    size_t wire_bytes_in;
    size_t wire_bytes_out;

    s2n_send_fn *send;
    void* send_ctx;

    s2n_recv_fn *recv;
    void* recv_ctx;
};

int s2n_io_provider_read_bytes(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
);

int s2n_io_provider_write(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
);

/* While we shouldn't need to reset errno before executing `action`,
 * we do so just in case action doesn't set errno properly on failure.
 */
#define S2N_IO_RETRY_EINTR(result, action) \
    do {                                   \
        errno = 0;                         \
        result = action;                   \
    } while (result < 0 && errno == EINTR)

S2N_RESULT s2n_io_check_write_result(ssize_t result);
S2N_RESULT s2n_io_check_read_result(ssize_t result);
