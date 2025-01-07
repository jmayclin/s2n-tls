#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#include "testlib/s2n_testlib.h"
#include "tests/s2n_test.h"
#include "utils/s2n_safety.h"

// # define MY_CTX_CLEAR_OPTIONS(ctx,op) \
//         SSL_CTX_ctrl((ctx),77,(op),NULL)

// struct IoRing {
//     uint8_t[1024] buffer,
//     size_t read,
//     size_t write,
// };

#define SERVER_CHAIN "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem"
#define SERVER_KEY "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-key.pem"

struct s2n_client_hello_version_detector {
    int invoked;
};

int client_hello_send_alerts(struct s2n_connection *conn, void *ctx)
{
    struct s2n_client_hello_version_detector *detector = ctx;
    detector->invoked += 1;
    struct s2n_client_hello* ch = s2n_connection_get_client_hello(conn);
    //s2n_client_hello_get_raw_message_length
    int version = s2n_connection_get_client_hello_version(conn);
    int sslv3 = S2N_SSLv3;
    int sslv2 = S2N_SSLv2;
    int tls10 = S2N_TLS12;
    printf("client hello version was %d\n", version);
    
    return 0;
}

void handle_openssl_error()
{
    printf("handling the error\n");
    ERR_print_errors_fp(stderr);
}

static S2N_RESULT s2n_validate_negotiate_result(bool success, bool peer_is_done, bool *is_done)
{
    /* If we succeeded, we're done. */
    if (success) {
        *is_done = true;
        return S2N_RESULT_OK;
    }

    /* If we failed for any error other than 'blocked', propagate the error. */
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        return S2N_RESULT_ERROR;
    }

    if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
        return S2N_RESULT_ERROR;
    }

    /* If we're blocked but our peer is done writing, propagate the error. */
    if (peer_is_done) {
        return S2N_RESULT_ERROR;
    }

    *is_done = false;
    return S2N_RESULT_OK;
}

/**
 * Function pointer for a user provided send callback.
 */
//typedef int s2n_recv_fn(void *io_context, uint8_t *buf, uint32_t len);
int s2n_bio_read(void *io_context, uint8_t *buf, uint32_t len) {
    int bytes_read = BIO_read(io_context, buf, len);
    printf("s2n bio read: %d\n", bytes_read);
    if (bytes_read == -1) {
        errno = EWOULDBLOCK;
    }
    return bytes_read;
}

/**
 * Function pointer for a user provided send callback.
 */
//typedef int s2n_send_fn(void *io_context, const uint8_t *buf, uint32_t len);
int s2n_bio_write(void *io_context, const uint8_t *buf, uint32_t len) {
    printf("s2n bio write: %d\n", len);
    return BIO_write(io_context, buf, len);
}

//     POSIX_GUARD(s2n_connection_set_recv_cb(conn, &buffer_read));
//     POSIX_GUARD(s2n_connection_set_recv_ctx(conn, input));
//     POSIX_GUARD(s2n_connection_set_send_cb(conn, &buffer_write));
//     POSIX_GUARD(s2n_connection_set_send_ctx(conn, output));

int main()
{
    // Initialize OpenSSL
    {
        SSL_library_init();
        // is the interning script maybe clobbering this?
        //OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        printf("trying to run the openssl test\n");

        // Create SSL contexts for client and server
        SSL_CTX *server_ctx = SSL_CTX_new(SSLv23_server_method());
        SSL_CTX *client_ctx = SSL_CTX_new(SSLv23_client_method());
        if (!server_ctx || !client_ctx) {
            handle_openssl_error();
            return 1;
        }

        // Generate self-signed certificates and keys for the server
        if (SSL_CTX_use_certificate_file(server_ctx, SERVER_CHAIN, SSL_FILETYPE_PEM) <= 0 
            || SSL_CTX_use_PrivateKey_file(server_ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
            handle_openssl_error();
            return 1;
        }

        // Create SSL objects
        SSL *server_ssl = SSL_new(server_ctx);
        SSL *client_ssl = SSL_new(client_ctx);

        if (!server_ssl || !client_ssl) {
            handle_openssl_error();
            return 1;
        }

        // Create memory BIOs for in-memory communication
        BIO *server_to_client = BIO_new(BIO_s_mem());
        //BIO_up_ref(server_to_client);
        BIO *client_to_server = BIO_new(BIO_s_mem());
        //BIO_up_ref(client_to_server);
        if (!server_to_client || !client_to_server) {
            handle_openssl_error();
            return 1;
        }

        // Set up SSL to use the BIOs
        SSL_set_bio(server_ssl, client_to_server, server_to_client);
        SSL_set_bio(client_ssl, server_to_client, client_to_server);

        // Server waits for a handshake
        SSL_set_accept_state(server_ssl);

        // Client initiates a handshake
        SSL_set_connect_state(client_ssl);

        // Perform handshake loop
        int server_handshake_done = 0, client_handshake_done = 0;
        while (!server_handshake_done || !client_handshake_done) {
            if (!server_handshake_done) {
                int ret = SSL_do_handshake(server_ssl);
                if (ret == 1) {
                    server_handshake_done = 1;
                    printf("Server: Handshake complete.\n");
                } else {
                    int err = SSL_get_error(server_ssl, ret);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                        handle_openssl_error();
                        return 1;
                    }
                }
            }

            if (!client_handshake_done) {
                int ret = SSL_do_handshake(client_ssl);
                if (ret == 1) {
                    client_handshake_done = 1;
                    printf("Client: Handshake complete.\n");
                } else {
                    int err = SSL_get_error(client_ssl, ret);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                        handle_openssl_error();
                        return 1;
                    }
                }
            }
        }

        printf("SSL/TLS handshake succeeded!\n");

        // Cleanup
        // SSL_free(server_ssl);
        // SSL_free(client_ssl);
        SSL_CTX_free(server_ctx);
        SSL_CTX_free(client_ctx);

        // BIOs are now owned by the SSL object and should not be freed?
        // BIO_free(server_to_client);
        // BIO_free(client_to_server);
    }

    {
        EXPECT_SUCCESS(s2n_init());

        char non_root_cert_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem(SERVER_CHAIN, non_root_cert_pem, S2N_MAX_TEST_PEM_SIZE));

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                SERVER_CHAIN, SERVER_KEY));

        // DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL,
        //         s2n_cert_chain_and_key_ptr_free);
        // EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
        //         S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        //EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_wipe_trust_store(config));
        EXPECT_SUCCESS(s2n_config_add_pem_to_trust_store(config, non_root_cert_pem));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_set_server_name(client, "localhost"));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        //if (type == S2N_TEST_DURING_HANDSHAKE) {
        //    /* Partially perform handshake */
        //    EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_CERT));
        //} else {
        /* Complete handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        //}
        EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);

        struct s2n_connection *receiver = server;
    }

    /* s2n-tls client w/ openssl server */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                SERVER_CHAIN, SERVER_KEY));

        struct s2n_client_hello_version_detector d = { 0 };

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        //EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "AWS-CRT-SDK-SSLv3.0-2023"));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_wipe_trust_store(config));

        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_send_alerts, &d));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        // DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        // EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        // EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        //EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));


        // Create SSL contexts for client and server
        SSL_CTX *client_ctx = SSL_CTX_new(SSLv23_client_method());
        if (!client_ctx) {
            handle_openssl_error();
            return 1;
        }
        SSL_CTX_clear_options(client_ctx, SSL_OP_NO_SSLv2);
        //SSL_CTX_set_min_proto_version(client_ctx, )

        // Create SSL objects
        SSL *client_ssl = SSL_new(client_ctx);

        if (!client_ssl) {
            handle_openssl_error();
            return 1;
        }
        SSL_clear_options(client_ssl, SSL_OP_NO_SSLv2);

        // Create memory BIOs for in-memory communication
        BIO *server_to_client = BIO_new(BIO_s_mem());
        //BIO_up_ref(server_to_client);
        BIO *client_to_server = BIO_new(BIO_s_mem());
        //BIO_up_ref(client_to_server);
        if (!server_to_client || !client_to_server) {
            handle_openssl_error();
            return 1;
        }

        s2n_connection_set_recv_cb(server, s2n_bio_read);
        s2n_connection_set_recv_ctx(server, client_to_server);

        s2n_connection_set_send_cb(server, s2n_bio_write);
        s2n_connection_set_send_ctx(server, server_to_client);

        // Set up SSL to use the BIOs
        //SSL_set_bio(server_ssl, client_to_server, server_to_client);
        SSL_set_bio(client_ssl, server_to_client, client_to_server);

        // Client initiates a handshake
        SSL_set_connect_state(client_ssl);

        bool server_done = false, client_done = false;
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        do {
            int ret = SSL_do_handshake(client_ssl);
                if (ret == 1) {
                    client_done = true;
                    printf("Client: Handshake complete.\n");
                } else {
                    int err = SSL_get_error(client_ssl, ret);
                    printf("error from ossl client was %d\n", err);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                        printf("we done have a problem (ossl)\n");
                        handle_openssl_error();
                        return 1;
                    }
                }
            server_done = (s2n_negotiate(server, &blocked) >= S2N_SUCCESS);
            /* If we failed for any error other than 'blocked', propagate the error. */
            if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
                printf("server done: %d, client done: %d\n", server_done, client_done);
                printf("Error issue: '%s'\n", s2n_strerror(s2n_errno, "EN"));
                printf("Error location: '%s'\n", s2n_strerror_debug(s2n_errno, "EN"));
                printf("s2n server encountered error :(\n");
                return 1;
            }
        } while (!client_done || !server_done);


        // // Perform handshake loop
        // int server_handshake_done = 0, client_handshake_done = 0;
        // while (!server_handshake_done || !client_handshake_done) {
        //     if (!server_handshake_done) {
        //         int ret = SSL_do_handshake(server_ssl);
        //         if (ret == 1) {
        //             server_handshake_done = 1;
        //             printf("Server: Handshake complete.\n");
        //         } else {
        //             int err = SSL_get_error(server_ssl, ret);
        //             if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        //                 handle_openssl_error();
        //                 return 1;
        //             }
        //         }
        //     }

        //     if (!client_handshake_done) {
        //         int ret = SSL_do_handshake(client_ssl);
        //         if (ret == 1) {
        //             client_handshake_done = 1;
        //             printf("Client: Handshake complete.\n");
        //         } else {
        //             int err = SSL_get_error(client_ssl, ret);
        //             if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        //                 handle_openssl_error();
        //                 return 1;
        //             }
        //         }
        //     }
        // }

        printf("interop SSL/TLS handshake succeeded!\n");

        // Cleanup
        // SSL_free(server_ssl);
        // SSL_free(client_ssl);
        //SSL_CTX_free(server_ctx);
        SSL_CTX_free(client_ctx);
    }

    return 0;
}
