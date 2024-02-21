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

#include <stdbool.h>

#include "api/s2n.h"
#include "utils/s2n_result.h"

#pragma once

struct s2n_cipher_suite;
S2N_RESULT s2n_rfc_9151_validate_cipher_suite(const struct s2n_cipher_suite *cipher_suite, bool *valid);
struct s2n_signature_scheme;
S2N_RESULT s2n_rfc_9151_validate_certificate_signature_scheme(const struct s2n_signature_scheme *sig_alg, bool *valid);
S2N_RESULT s2n_rfc_9151_validate_transcript_signature_scheme(const struct s2n_signature_scheme *sig_alg, bool *valid);
struct s2n_ecc_named_curve;
S2N_RESULT s2n_rfc_9151_validate_curve(const struct s2n_ecc_named_curve *curve, bool *valid);
S2N_RESULT s2n_rfc_9151_validate_version(uint8_t version, bool *valid);
