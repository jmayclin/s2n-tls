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
        /* when loading a cert, all certs have a info associated with them and root is self-signed */
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *cert_chain = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&cert_chain, "ec", "ecdsa",
                    "p384", "sha256"));
            struct s2n_cert *leaf = cert_chain->cert_chain->head;
            EXPECT_EQUAL(leaf->info.self_signed, false);
            EXPECT_EQUAL(leaf->info.signature_nid, NID_ecdsa_with_SHA256);
            EXPECT_EQUAL(leaf->info.signature_digest_nid, NID_sha256);

            struct s2n_cert *intermediate = leaf->next;
            EXPECT_EQUAL(intermediate->info.self_signed, false);
            EXPECT_EQUAL(intermediate->info.signature_nid, NID_ecdsa_with_SHA256);
            EXPECT_EQUAL(intermediate->info.signature_digest_nid, NID_sha256);

            struct s2n_cert *root = intermediate->next;
            EXPECT_NULL(root->next);
            EXPECT_EQUAL(root->info.self_signed, true);
            EXPECT_EQUAL(root->info.signature_nid, NID_ecdsa_with_SHA256);
            EXPECT_EQUAL(root->info.signature_digest_nid, NID_sha256);
        };
    };

    END_TEST();
    return 0;
}
