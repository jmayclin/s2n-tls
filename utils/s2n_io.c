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

/* return S2N_ERR_IO_BLOCKED if the underlying errno is blocked. For any other
 * errors return S2N_ERR_IO.
*/
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

/* return S2N_ERR_IO_BLOCKED if the underlying errno is blocked/
 * return S2N_ERR_CLOSED if the read was 0.
 * All other errors return S2N_ERR_IO.*/
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
 * It will attempt to read `length` bytes, but a smaller number may be returned.
 * If an exact number of bytes needs to be read, use `s2n_io_provider_read_exact`.
 * 
 * This will advance the write_cursor of `buffer`.
 * 
 * Returns:
 * - success: the number of bytes read
 * - failure: -1. Callers should then check the errno set by the underlying IO call
 *      -> `S2N_ERR_CLOSED` is returned if the transport layer is closed
 *      -> `S2N_ERR_BLOCKED` if the transport layer is blocked
 *      -> others
 */
int s2n_io_provider_read(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
) {
    POSIX_ENSURE_REF(io);
    POSIX_ENSURE_REF(io->recv);
    POSIX_ENSURE(!io->transport_recv_closed, S2N_ERR_CLOSED);
    POSIX_ENSURE_REF(buffer);

    /* Make sure we have enough space to write */
    POSIX_GUARD(s2n_stuffer_reserve_space(buffer, length));

    /* we defensively reset the ERRNO, although it shouldn't be necessary */
    errno = 0;
    int result = io->recv(io->recv_ctx, buffer->blob.data + buffer->write_cursor, length);
    POSIX_ENSURE(result >= 0, S2N_ERR_RECV_STUFFER_FROM_CONN);
    
    /* a read result of "0" indicates that the transport layer (e.g. TCP stream) 
     * is closed */
    if (result == 0) {
        io->transport_recv_closed = true;
    }

    /* bubble up S2N_ERR_CLOSED or S2N_ERR_BLOCKED as appropriate */
    POSIX_GUARD_RESULT(s2n_io_check_read_result(result));

    /* If we got this far, it means we read a non-zero number of bytes. Record that */
    POSIX_GUARD(s2n_stuffer_skip_write(buffer, result));
    io->wire_bytes_in += result;

    return result;
}

/**
 * Read exactly `length` bytes into buffer.
 * 
 * This function will never return `S2N_ERR_BLOCKED`, and will repeatedly call
 * `s2n_io_provider_read` until `length` bytes have been read.
 * 
 * Advances the `write_cursor` of `buffer`.
 * 
 * Returns:
 * - `S2N_RESULT_OK`: when at least `length` bytes were read
 * - `S2N_RESULT_ERR`: Callers should then check the errno set by the underlying IO call
 *     -> `S2N_ERR_CLOSED` is returned if the transport layer is closed
 */
S2N_RESULT s2n_io_provider_read_exact(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
) {
    while (s2n_stuffer_data_available(buffer) < length) {
        uint32_t remaining = length - s2n_stuffer_data_available(buffer);
        RESULT_GUARD_POSIX(s2n_io_provider_read(io, buffer, remaining));
    }

    return S2N_RESULT_OK;
}

/**
 * Write bytes from `buffer` into the network `io`
 * 
 * This will advance the read_cursor of `buffer`.
 * 
 * Will return OK only if `write_size` was successfully written.
 */
int s2n_io_provider_write(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
) {
    POSIX_ENSURE_REF(io);
    POSIX_ENSURE_REF(io->send);
    POSIX_ENSURE(!io->transport_recv_closed, S2N_ERR_IO);
    POSIX_ENSURE_REF(buffer);

    /* Make sure we even have the data */
    POSIX_ENSURE(s2n_stuffer_data_available(buffer) >= length, S2N_ERR_STUFFER_OUT_OF_DATA);

    /* we defensively reset the ERRNO, although it shouldn't be necessary */
    errno = 0;
    int result = io->send(io->send_ctx, buffer->blob.data + buffer->read_cursor, length);
    if (result < 0 && errno == EPIPE) {
        io->transport_send_closed = true;
    }
    
    /* bubble up S2N_ERR_BLOCKED/S2N_ERR_CLOSED as appropriate */
    POSIX_GUARD_RESULT(s2n_io_check_write_result(result));

    POSIX_GUARD(s2n_stuffer_skip_read(buffer, result));
    io->wire_bytes_out += result;

    return result;
}

S2N_RESULT s2n_io_provider_write_exact(
    struct s2n_io_provider *io,
    struct s2n_stuffer *buffer,
    uint32_t length
) {
    RESULT_ENSURE(s2n_stuffer_data_available(buffer) >= length, S2N_ERR_STUFFER_OUT_OF_DATA);
    /* the amount of data that should be left in the stuffer */
    uint32_t leftover = s2n_stuffer_data_available(buffer) - length;
    while (s2n_stuffer_data_available(buffer) > leftover) {
        uint32_t to_send = s2n_stuffer_data_available(buffer) - leftover;
        RESULT_GUARD_POSIX(s2n_io_provider_write(io, buffer, to_send));
    }
    return S2N_RESULT_OK;
}


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


// /* Retrieve bytes from the network */
// S2N_RESULT s2n_read_in_bytes(struct s2n_connection *conn, struct s2n_stuffer *output, uint32_t length)
// {
//     while (s2n_stuffer_data_available(output) < length) {
//         uint32_t remaining = length - s2n_stuffer_data_available(output);
//         if (conn->recv_buffering) {
//             remaining = S2N_MAX(remaining, s2n_stuffer_space_remaining(output));
//         }
//         errno = 0;
//         int r = s2n_connection_recv_stuffer(output, conn, remaining);
//         if (r == 0) {
//             s2n_atomic_flag_set(&conn->read_closed);
//         }
//         RESULT_GUARD(s2n_io_check_read_result(r));
//         conn->wire_bytes_in += r;
//     }

//     return S2N_RESULT_OK;
// }


// int s2n_connection_recv_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len)
// {
//     POSIX_ENSURE_REF(conn->recv);
//     /* Make sure we have enough space to write */
//     POSIX_GUARD(s2n_stuffer_reserve_space(stuffer, len));

//     int r = 0;
//     S2N_IO_RETRY_EINTR(r,
//             conn->recv(conn->recv_io_context, stuffer->blob.data + stuffer->write_cursor, len));
//     POSIX_ENSURE(r >= 0, S2N_ERR_RECV_STUFFER_FROM_CONN);

//     /* Record just how many bytes we have written */
//     POSIX_GUARD(s2n_stuffer_skip_write(stuffer, r));
//     return r;
// }


// int s2n_flush(struct s2n_connection *conn, s2n_blocked_status *blocked)
// {
//     POSIX_ENSURE_REF(conn);
//     POSIX_ENSURE_REF(blocked);
//     *blocked = S2N_BLOCKED_ON_WRITE;

//     /* Write any data that's already pending */
//     while (s2n_stuffer_data_available(&conn->out)) {
//         errno = 0;
//         int w = s2n_connection_send_stuffer(&conn->out, conn, s2n_stuffer_data_available(&conn->out));
//         POSIX_GUARD_RESULT(s2n_io_check_write_result(w));
//         conn->wire_bytes_out += w;
//     }
//     POSIX_GUARD(s2n_stuffer_rewrite(&conn->out));

//     if (conn->reader_warning_out) {
//         POSIX_GUARD_RESULT(s2n_alerts_write_warning(conn));
//         conn->reader_warning_out = 0;
//         POSIX_GUARD(s2n_flush(conn, blocked));
//     }

//     *blocked = S2N_NOT_BLOCKED;
//     return 0;
// }


// int s2n_connection_send_stuffer(struct s2n_stuffer *stuffer, struct s2n_connection *conn, uint32_t len)
// {
//     POSIX_ENSURE_REF(conn);
//     POSIX_ENSURE_REF(conn->send);
//     if (conn->write_fd_broken) {
//         POSIX_BAIL(S2N_ERR_SEND_STUFFER_TO_CONN);
//     }
//     /* Make sure we even have the data */
//     S2N_ERROR_IF(s2n_stuffer_data_available(stuffer) < len, S2N_ERR_STUFFER_OUT_OF_DATA);

//     int w = 0;
//     S2N_IO_RETRY_EINTR(w,
//             conn->send(conn->send_io_context, stuffer->blob.data + stuffer->read_cursor, len));
//     if (w < 0 && errno == EPIPE) {
//         conn->write_fd_broken = 1;
//     }
//     POSIX_ENSURE(w >= 0, S2N_ERR_SEND_STUFFER_TO_CONN);

//     POSIX_GUARD(s2n_stuffer_skip_read(stuffer, w));
//     return w;
// }
