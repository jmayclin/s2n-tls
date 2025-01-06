#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

#include "testlib/s2n_testlib.h"
#include "tests/s2n_test.h"
#include "utils/s2n_safety.h"

// struct IoRing {
//     uint8_t[1024] buffer,
//     size_t read,
//     size_t write,
// };

#define SERVER_CHAIN "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem"
#define SERVER_KEY "/home/ubuntu/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/server-key.pem"

void handle_openssl_error()
{
    printf("handling the error\n");
    ERR_print_errors_fp(stderr);
}

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

    return 0;
}
