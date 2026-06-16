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

#include "utils/s2n_io.h"

#include <errno.h>

#include "utils/s2n_safety.h"

S2N_RESULT s2n_io_check_write_result(ssize_t result)
{
    if (result < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        }
        RESULT_BAIL(S2N_ERR_IO);
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_io_check_read_result(ssize_t result)
{
    RESULT_GUARD(s2n_io_check_write_result(result));
    if (result == 0) {
        RESULT_BAIL(S2N_ERR_CLOSED);
    }
    return S2N_RESULT_OK;
}

/**
 * Read bytes from the network (`io`) into `buffer`
 * 
 * This will advance the write_cursor of `buffer`.
 * 
 * Will return OK only `read_size` was successfully read.
 */
S2N_RESULT s2n_io_provider_read_bytes(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    size_t read_size
);

/**
 * Write bytes from `buffer` into the network `io`
 * 
 * This will advance the read_cursor of `buffer`.
 * 
 * Will return OK only if `write_size` was successfully written.
 */
S2N_RESULT s2n_io_provider_write_bytes(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    size_t write_size
);


// int s2n_connection_set_write_fd(struct s2n_connection *conn, int wfd)
// {
//     struct s2n_blob ctx_mem = { 0 };
//     struct s2n_socket_write_io_context *peer_socket_ctx = NULL;

//     POSIX_ENSURE_REF(conn);
//     POSIX_GUARD(s2n_alloc(&ctx_mem, sizeof(struct s2n_socket_write_io_context)));

//     peer_socket_ctx = (struct s2n_socket_write_io_context *) (void *) ctx_mem.data;
//     peer_socket_ctx->fd = wfd;

//     POSIX_GUARD(s2n_connection_set_send_cb(conn, s2n_socket_write));
//     POSIX_GUARD(s2n_connection_set_send_ctx(conn, peer_socket_ctx));
//     conn->managed_send_io = true;

//     /* This is only needed if the user is using corked io.
//      * Take the snapshot in case optimized io is enabled after setting the fd.
//      */
//     POSIX_GUARD(s2n_socket_write_snapshot(conn));

//     uint8_t ipv6 = 0;
//     if (0 == s2n_socket_is_ipv6(wfd, &ipv6)) {
//         conn->ipv6 = (ipv6 ? 1 : 0);
//     }

//     conn->write_fd_broken = 0;

//     return 0;
// }
