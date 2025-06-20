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

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_event.h"
#include "utils/s2n_safety.h"

int s2n_server_cert_recv(struct s2n_connection *conn)
{
    /* s2n_server_cert_recv() may be re-entered due to handling an async callback.
     * We operate on a copy of `handshake.io` to ensure the stuffer is initilized properly on the re-entry case.
     */
    struct s2n_stuffer in = conn->handshake.io;

    if (conn->actual_protocol_version == S2N_TLS13) {
        uint8_t certificate_request_context_len = 0;
        POSIX_GUARD(s2n_stuffer_read_uint8(&in, &certificate_request_context_len));
        S2N_ERROR_IF(certificate_request_context_len != 0, S2N_ERR_BAD_MESSAGE);
    }

    uint32_t size_of_all_certificates = 0;
    POSIX_GUARD(s2n_stuffer_read_uint24(&in, &size_of_all_certificates));

    S2N_ERROR_IF(size_of_all_certificates > s2n_stuffer_data_available(&in) || size_of_all_certificates < 3,
            S2N_ERR_BAD_MESSAGE);

    s2n_cert_public_key public_key;
    POSIX_GUARD(s2n_pkey_zero_init(&public_key));

    s2n_pkey_type actual_cert_pkey_type;
    struct s2n_blob cert_chain = { 0 };
    cert_chain.size = size_of_all_certificates;
    cert_chain.data = s2n_stuffer_raw_read(&in, size_of_all_certificates);
    POSIX_ENSURE_REF(cert_chain.data);

    POSIX_GUARD_RESULT(s2n_x509_validator_validate_cert_chain(&conn->x509_validator, conn, cert_chain.data,
            cert_chain.size, &actual_cert_pkey_type, &public_key));

    POSIX_GUARD(s2n_is_cert_type_valid_for_auth(conn, actual_cert_pkey_type));
    POSIX_GUARD_RESULT(s2n_pkey_setup_for_type(&public_key, actual_cert_pkey_type));
    conn->handshake_params.server_public_key = public_key;

    /* Update handshake.io to reflect the true stuffer state after all async callbacks are handled. */
    conn->handshake.io = in;

    /* Log server certificate received event */
    {
        char event_log_buffer[256];
        
        /* Get certificate fingerprint if available */
        struct s2n_cert_chain_and_key peer_chain_and_key = { 0 };
        
        if (s2n_connection_get_peer_cert_chain(conn, &peer_chain_and_key) == S2N_SUCCESS) {
            sprintf(event_log_buffer, "Received server certificate chain: [SHA256: <hash available via s2n_connection_get_peer_cert_chain>]");
        } else {
            sprintf(event_log_buffer, "Received server certificate chain");
        }
        
        s2n_event_log_cb("INFO", event_log_buffer);
    }

    return 0;
}

int s2n_server_cert_send(struct s2n_connection *conn)
{
    S2N_ERROR_IF(conn->handshake_params.our_chain_and_key == NULL, S2N_ERR_CERT_TYPE_UNSUPPORTED);
    if (conn->actual_protocol_version == S2N_TLS13) {
        /* server's certificate request context should always be of zero length */
        /* https://tools.ietf.org/html/rfc8446#section-4.4.2 */
        uint8_t certificate_request_context_len = 0;
        POSIX_GUARD(s2n_stuffer_write_uint8(&conn->handshake.io, certificate_request_context_len));
    }

    POSIX_GUARD(s2n_send_cert_chain(conn, &conn->handshake.io, conn->handshake_params.our_chain_and_key));

    /* Log server certificate sent event */
    {
        char event_log_buffer[256];
        
        /* Get certificate fingerprint if available */
        if (conn->handshake_params.our_chain_and_key && conn->handshake_params.our_chain_and_key->cert_chain) {
            sprintf(event_log_buffer, "Sent server certificate chain: [SHA256: <hash available via certificate chain>]");
        } else {
            sprintf(event_log_buffer, "Sent server certificate chain");
        }
        
        s2n_event_log_cb("INFO", event_log_buffer);
    }

    return 0;
}
