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

#include "crypto/s2n_rfc_9151_rules.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_result.h"

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf */
const uint8_t rfc_9151_cipher_suite_ianas[][2] = {
    /* What section? */
    /* TLS 1.3 */
    { TLS_AES_256_GCM_SHA384 },

    /* TLS 1.2 */
    { TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 },
    { TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
    { TLS_RSA_WITH_AES_256_GCM_SHA384 },
    /* s2n-tls does not provide mechanisms for restricting the FFDHE group size,
     * so it is not included here.
     */
    /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */ 
};

S2N_RESULT s2n_rfc_9151_validate_cipher_suite(const struct s2n_cipher_suite *cipher_suite, bool *valid)
{
    RESULT_ENSURE_REF(cipher_suite);
    RESULT_ENSURE_REF(valid);

    *valid = false;
    for (size_t i = 0; i < s2n_array_len(rfc_9151_cipher_suite_ianas); i++) {
        if (rfc_9151_cipher_suite_ianas[i][0] != cipher_suite->iana_value[0]) {
            continue;
        }
        if (rfc_9151_cipher_suite_ianas[i][1] != cipher_suite->iana_value[1]) {
            continue;
        }
        *valid = true;
        return S2N_RESULT_OK;
    }
    return S2N_RESULT_OK;
}

const struct s2n_signature_scheme *rfc_9151_certificate_signature_schemes[] = {
    &s2n_ecdsa_secp384r1_sha384,
    &s2n_ecdsa_sha384,
    &s2n_rsa_pkcs1_sha384,
    /* While rsa_pss signatures are allowed by rfc9151, s2n-tls does not currently
     * support digest validation for pss signatures in certificates, so they aren't
     * allowed here.
     */
    /* s2n_rsa_pss_pss_sha384, */
    /* s2n_rsa_pss_rsae_sha384, */
};
S2N_RESULT s2n_rfc_9151_validate_certificate_signature_scheme(const struct s2n_signature_scheme *sig_alg, bool *valid)
{
    RESULT_ENSURE_REF(sig_alg);
    *valid = false;
    for (size_t i = 0; i < s2n_array_len(rfc_9151_certificate_signature_schemes); i++) {
        if (rfc_9151_certificate_signature_schemes[i] == sig_alg) {
            *valid = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

const struct s2n_signature_scheme *rfc_9151_transcript_signature_schemes[] = {
    &s2n_ecdsa_secp384r1_sha384,
    &s2n_ecdsa_sha384,
    &s2n_rsa_pkcs1_sha384,
    &s2n_rsa_pss_pss_sha384,
    &s2n_rsa_pss_rsae_sha384,
};
S2N_RESULT s2n_rfc_9151_validate_transcript_signature_scheme(const struct s2n_signature_scheme *sig_alg, bool *valid)
{
    RESULT_ENSURE_REF(sig_alg);
    *valid = false;
    for (size_t i = 0; i < s2n_array_len(rfc_9151_transcript_signature_schemes); i++) {
        if (rfc_9151_transcript_signature_schemes[i] == sig_alg) {
            *valid = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf */
const struct s2n_ecc_named_curve *rfc_9151_curves[] = {
    &s2n_ecc_curve_secp384r1,
};
S2N_RESULT s2n_rfc_9151_validate_curve(const struct s2n_ecc_named_curve *curve, bool *valid)
{
    RESULT_ENSURE_REF(curve);
    RESULT_ENSURE_REF(valid);
    *valid = false;
    for (size_t i = 0; i < s2n_array_len(rfc_9151_curves); i++) {
        if (rfc_9151_curves[i] == curve) {
            *valid = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_rfc_9151_validate_version(uint8_t version, bool *valid)
{
    RESULT_ENSURE_REF(valid);
    *valid = (version >= S2N_TLS12);
    return S2N_RESULT_OK;
}
