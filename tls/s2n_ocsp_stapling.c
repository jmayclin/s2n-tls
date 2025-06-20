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

#include <strings.h>

#include "error/s2n_errno.h"
#include "tls/extensions/s2n_cert_status.h"
#include "utils/s2n_event.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_x509_validator.h"
#include "utils/s2n_safety.h"

int s2n_server_status_send(struct s2n_connection *conn)
{
    if (s2n_server_can_send_ocsp(conn)) {
        /* Log OCSP stapling status event */
        {
            char event_log_buffer[256];
            uint32_t ocsp_size = 0;
            if (conn->handshake_params.our_chain_and_key && conn->handshake_params.our_chain_and_key->ocsp_status.size > 0) {
                ocsp_size = conn->handshake_params.our_chain_and_key->ocsp_status.size;
            }
            sprintf(event_log_buffer, "OCSP stapling status: sending OCSP response (length=%u bytes)", ocsp_size);
            s2n_event_log_cb("INFO", event_log_buffer);
        }
        
        POSIX_GUARD(s2n_cert_status_send(conn, &conn->handshake.io));
    }

    return 0;
}

int s2n_server_status_recv(struct s2n_connection *conn)
{
    int result = s2n_cert_status_recv(conn, &conn->handshake.io);
    
    /* Log OCSP response reception event if successful */
    if (result == 0 && conn->status_response.size > 0) {
        char event_log_buffer[256];
        sprintf(event_log_buffer, "Received OCSP response: length=%u bytes", (uint32_t)conn->status_response.size);
        s2n_event_log_cb("INFO", event_log_buffer);
    }
    
    return result;
}
