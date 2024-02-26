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

#pragma once

#include <stdint.h>

struct s2n_certificate_signature {
    uint16_t signature_libcrypto_nid;
};

struct s2n_certificate_signature_preferences {
    uint8_t count;
    const struct s2n_certificate_signature *const *certificate_keys;
};

/* RSA PKCS1 */
extern const struct s2n_certificate_signature s2n_rsa_pkcs1_md5_sha1;
extern const struct s2n_certificate_signature s2n_rsa_pkcs1_sha1;
extern const struct s2n_certificate_signature s2n_rsa_pkcs1_sha224;
extern const struct s2n_certificate_signature s2n_rsa_pkcs1_sha256;
extern const struct s2n_certificate_signature s2n_rsa_pkcs1_sha384;
extern const struct s2n_certificate_signature s2n_rsa_pkcs1_sha512;

extern const struct s2n_certificate_signature s2n_ecdsa_sha1;
extern const struct s2n_certificate_signature s2n_ecdsa_sha224;
extern const struct s2n_certificate_signature s2n_ecdsa_sha256;
extern const struct s2n_certificate_signature s2n_ecdsa_sha384;
extern const struct s2n_certificate_signature s2n_ecdsa_sha512;

/* RSA PSS */
extern const struct s2n_certificate_signature s2n_rsa_pss_pss_sha256;
extern const struct s2n_certificate_signature s2n_rsa_pss_pss_sha384;
extern const struct s2n_certificate_signature s2n_rsa_pss_pss_sha512;
