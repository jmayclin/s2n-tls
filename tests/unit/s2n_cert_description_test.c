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

#include <errno.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "api/s2n.h"
#include "crypto/s2n_openssl_x509.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* s2n_cert_chain_and_key_load */
    {
        /* when loading a cert, all certs have a description associated with them and root is self-signed */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *cert_chain = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&cert_chain, "ec", "ecdsa",
                    "p384", "sha256"));
            struct s2n_cert *leaf = cert_chain->cert_chain->head;
            EXPECT_EQUAL(leaf->description.self_signed, false);
            EXPECT_EQUAL(leaf->description.signature_nid, NID_ecdsa_with_SHA256);
            EXPECT_EQUAL(leaf->description.signature_digest_nid, NID_sha256);

            struct s2n_cert *intermediate = leaf->next;
            EXPECT_EQUAL(intermediate->description.self_signed, false);
            EXPECT_EQUAL(intermediate->description.signature_nid, NID_ecdsa_with_SHA256);
            EXPECT_EQUAL(intermediate->description.signature_digest_nid, NID_sha256);

            struct s2n_cert *root = intermediate->next;
            EXPECT_NULL(root->next);
            EXPECT_EQUAL(root->description.self_signed, true);
            EXPECT_EQUAL(root->description.signature_nid, NID_ecdsa_with_SHA256);
            EXPECT_EQUAL(root->description.signature_digest_nid, NID_sha256);
        };
    };

    /* s2n_cert_get_cert_description */
    struct {
        const char *key_type;
        const char *signature;
        const char *key_size;
        const char *digest;
        int expected_signature_nid;
        int expected_digest_nid;
    } test_cases[] = {
        { .key_type = "ec",
                .signature = "ecdsa",
                .key_size = "p384",
                .digest = "sha256",
                .expected_signature_nid = NID_ecdsa_with_SHA256,
                .expected_digest_nid = NID_sha256 },
        { .key_type = "ec",
                .signature = "ecdsa",
                .key_size = "p256",
                .digest = "sha384",
                .expected_signature_nid = NID_ecdsa_with_SHA384,
                .expected_digest_nid = NID_sha384 },
        { .key_type = "ec",
                .signature = "ecdsa",
                .key_size = "p521",
                .digest = "sha512",
                .expected_signature_nid = NID_ecdsa_with_SHA512,
                .expected_digest_nid = NID_sha512 },
        { .key_type = "rsae",
                .signature = "pkcs",
                .key_size = "2048",
                .digest = "sha1",
                .expected_signature_nid = NID_sha1WithRSAEncryption,
                .expected_digest_nid = NID_sha1 },
        { .key_type = "rsae",
                .signature = "pkcs",
                .key_size = "2048",
                .digest = "sha224",
                .expected_signature_nid = NID_sha224WithRSAEncryption,
                .expected_digest_nid = NID_sha224 },
        { .key_type = "rsae",
                .signature = "pkcs",
                .key_size = "3072",
                .digest = "sha384",
                .expected_signature_nid = NID_sha384WithRSAEncryption,
                .expected_digest_nid = NID_sha384 },
        { .key_type = "rsae",
                .signature = "pss",
                .key_size = "4096",
                .digest = "sha384",
                .expected_signature_nid = NID_rsassaPss,
                .expected_digest_nid = NID_undef },
        { .key_type = "rsapss",
                .signature = "pss",
                .key_size = "2048",
                .digest = "sha256",
                .expected_signature_nid = NID_rsassaPss,
                .expected_digest_nid = NID_undef },
    };
    for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
        /* print statement to help debugging in CI */
        printf("get_cert_description test case %zu\n", i);
        char pathbuffer[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        uint8_t cert_file[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_SUCCESS(
                s2n_test_cert_permutation_get_server_chain_path(&pathbuffer[0], test_cases[i].key_type,
                        test_cases[i].signature, test_cases[i].key_size, test_cases[i].digest));
        EXPECT_SUCCESS(s2n_read_test_pem(pathbuffer, (char *) cert_file, S2N_MAX_TEST_PEM_SIZE));

        DEFER_CLEANUP(X509 *leaf = NULL, X509_free_pointer);
        DEFER_CLEANUP(X509 *intermediate = NULL, X509_free_pointer);
        DEFER_CLEANUP(X509 *root = NULL, X509_free_pointer);
        {
            /* read in cert chain */
            size_t chain_len = strlen((const char *) cert_file);
            BIO *cert_bio = NULL;
            EXPECT_NOT_NULL(cert_bio = BIO_new(BIO_s_mem()));
            EXPECT_TRUE(BIO_write(cert_bio, cert_file, chain_len) > 0);
            EXPECT_NOT_NULL(leaf = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL));
            EXPECT_NOT_NULL(intermediate = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL));
            EXPECT_NOT_NULL(root = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL));
            EXPECT_SUCCESS(BIO_free(cert_bio));
        };

        struct s2n_cert_description leaf_description = { 0 };
        struct s2n_cert_description intermediate_description = { 0 };
        struct s2n_cert_description root_description = { 0 };

        EXPECT_OK(s2n_cert_get_cert_description(leaf, &leaf_description));
        EXPECT_OK(s2n_cert_get_cert_description(intermediate, &intermediate_description));
        EXPECT_OK(s2n_cert_get_cert_description(root, &root_description));

        EXPECT_EQUAL(leaf_description.signature_nid, test_cases[i].expected_signature_nid);
        EXPECT_EQUAL(leaf_description.signature_digest_nid, test_cases[i].expected_digest_nid);
        EXPECT_EQUAL(leaf_description.self_signed, false);

        /* leaf and intermediate should have the same descriptions */
        EXPECT_EQUAL(memcmp(&leaf_description, &intermediate_description,
                             sizeof(struct s2n_cert_description)),
                0);

        /* root should be self-signed */
        EXPECT_EQUAL(root_description.signature_nid, test_cases[i].expected_signature_nid);
        EXPECT_EQUAL(root_description.signature_digest_nid, test_cases[i].expected_digest_nid);
        EXPECT_EQUAL(root_description.self_signed, true);
    }

    END_TEST();
    return 0;
}
