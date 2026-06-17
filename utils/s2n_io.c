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
 * Attempt to read `length` bytes from the network (`io`) into `buffer`
 * 
 * This will call the underlying recv function a single time. Generally this should
 * be called in a loop, until it blocks or the desired number of bytes are returned.
 * This functionality is provided in s2n_io_provider_read.
 * 
 * This may allocate additional data for `buffer` if it is not large enough.
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
int s2n_io_provider_read_impl(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
) {
    POSIX_ENSURE_REF(io);
    POSIX_ENSURE(io->recv != NULL, S2N_ERR_IO);
    POSIX_ENSURE(!io->transport_recv_closed, S2N_ERR_CLOSED);
    POSIX_ENSURE_REF(buffer);

    /* allocate more space if needed */
    POSIX_GUARD(s2n_stuffer_reserve_space(buffer, length));

    /* we defensively reset the ERRNO, although it shouldn't be necessary */
    errno = 0;
    int result = io->recv(io->recv_ctx, buffer->blob.data + buffer->write_cursor, length);

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
 * Read bytes from the network into `buffer` until there are `length` bytes available.
 * 
 * Advances the `write_cursor` of `buffer`.
 * 
 * Returns:
 * - `S2N_RESULT_OK`: when at least `length` bytes were read
 * - `S2N_RESULT_ERR`: Callers should then check the errno set by the underlying IO call
 *     -> `S2N_ERR_CLOSED` is returned if the transport layer is closed
 *     -> `S2N_ERR_BLOCKED` is returned if the transport layer is blocked
 */
S2N_RESULT s2n_io_provider_read(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
) {
    while (s2n_stuffer_data_available(buffer) < length) {
        uint32_t remaining = length - s2n_stuffer_data_available(buffer);
        RESULT_GUARD_POSIX(s2n_io_provider_read_impl(io, buffer, remaining));
    }

    return S2N_RESULT_OK;
}

/**
 * Read bytes from the network into `buffer` until there are _at least_ `min_length`
 * bytes available.
 * 
 * Advances the `write_cursor` of `buffer`.
 * 
 * Returns:
 * - `S2N_RESULT_OK`: when at least `length` bytes were read
 * - `S2N_RESULT_ERR`: Callers should then check the errno set by the underlying IO call
 *     -> `S2N_ERR_CLOSED` is returned if the transport layer is closed
 *     -> `S2N_ERR_BLOCKED` is returned if the transport layer is blocked
 */
S2N_RESULT s2n_io_provider_greedy_read(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t min_length
) {
    while (s2n_stuffer_data_available(buffer) < min_length) {
        uint32_t remaining = min_length - s2n_stuffer_data_available(buffer);
        uint32_t to_read = S2N_MAX(remaining, s2n_stuffer_space_remaining(buffer));
        RESULT_GUARD_POSIX(s2n_io_provider_read_impl(io, buffer, to_read));
    }

    return S2N_RESULT_OK;
}


int s2n_io_provider_write_impl(
    struct s2n_io_provider* io,
    struct s2n_stuffer* buffer,
    uint32_t length
) {
    /* we defensively reset the ERRNO, although it shouldn't be necessary. Additionally,
     * it's necessary to clear it before we do any of the ENSURE checks */
    errno = 0;

    POSIX_ENSURE_REF(io);
    POSIX_ENSURE(io->send != NULL, S2N_ERR_IO);
    POSIX_ENSURE(!io->transport_send_closed, S2N_ERR_IO);
    POSIX_ENSURE_REF(buffer);

    /* Make sure we even have the data */
    POSIX_ENSURE(s2n_stuffer_data_available(buffer) >= length, S2N_ERR_STUFFER_OUT_OF_DATA);

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

/**
 * Write `length` bytes from `buffer` into the network `io`
 * 
 * This will advance the read_cursor of `buffer`.
 * 
 * Will return OK only if `length` bytes were successfully written.
 */
S2N_RESULT s2n_io_provider_write(
    struct s2n_io_provider *io,
    struct s2n_stuffer *buffer,
    uint32_t length
) {
    RESULT_ENSURE(s2n_stuffer_data_available(buffer) >= length, S2N_ERR_STUFFER_OUT_OF_DATA);
    /* the amount of data that should be left in the stuffer */
    uint32_t left_over = s2n_stuffer_data_available(buffer) - length;
    while (s2n_stuffer_data_available(buffer) > left_over) {
        uint32_t to_send = s2n_stuffer_data_available(buffer) - left_over;
        RESULT_GUARD_POSIX(s2n_io_provider_write_impl(io, buffer, to_send));
    }
    return S2N_RESULT_OK;
}
