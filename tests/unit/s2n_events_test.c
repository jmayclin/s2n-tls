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

#include <math.h>
#include <stdlib.h>

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

struct subscriber {
    uint64_t invoked;
};

void subscriber_on_handshake_complete(void* subscriber, struct s2n_event_handshake *event) {
    struct subscriber* sub = (struct subscriber*) subscriber;
    sub->invoked++;
}

// typedef void (*s2n_event_on_handshake_cb)(void *subscriber, struct s2n_event_handshake *event);

// S2N_API extern int s2n_config_set_subscriber(struct s2n_config *config, void *subscriber);
// S2N_API extern int s2n_config_set_handshake_event(struct s2n_config *config, s2n_event_on_handshake_cb callback);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    {
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20240503"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20240503"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        /* setup subscriber */
        struct subscriber sub = {0};
        s2n_config_set_subscriber(server_config, (void *)&sub);
        s2n_config_set_handshake_event(server_config, subscriber_on_handshake_complete);

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *cert_chain = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&cert_chain, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, cert_chain));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_EQUAL(sub.invoked, 1);
    };

    END_TEST();
}
