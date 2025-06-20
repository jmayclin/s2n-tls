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

#include <arpa/inet.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <sys/socket.h>

#include "crypto/s2n_libcrypto.h"
#include "crypto/s2n_openssl_x509.h"
#include "crypto/s2n_pkey.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crl.h"
#include "tls/s2n_security_policies.h"
#include "utils/s2n_event.h"
#include "utils/s2n_result.h"
#include "utils/s2n_rfc5952.h"
#include "utils/s2n_safety.h"

#if S2N_OCSP_STAPLING_SUPPORTED
    #include <openssl/ocsp.h>
DEFINE_POINTER_CLEANUP_FUNC(OCSP_RESPONSE *, OCSP_RESPONSE_free);
DEFINE_POINTER_CLEANUP_FUNC(OCSP_BASICRESP *, OCSP_BASICRESP_free);

#endif

#ifndef X509_V_FLAG_PARTIAL_CHAIN
    #define X509_V_FLAG_PARTIAL_CHAIN 0x80000
#endif

#define DEFAULT_MAX_CHAIN_DEPTH 7
/* Time used by default for nextUpdate if none provided in OCSP: 1 hour since thisUpdate. */
#define DEFAULT_OCSP_NEXT_UPDATE_PERIOD 3600

/* s2n's internal clock measures epoch-nanoseconds stored with a uint64_t. The
 * maximum representable timestamp is Sunday, July 21, 2554. time_t measures
 * epoch-seconds in a int64_t or int32_t (platform dependent). If time_t is an
 * int32_t, the maximum representable timestamp is January 19, 2038.
 *
 * This means that converting from the internal clock to a time_t is not safe,
 * because the internal clock might hold a value that is too large to represent
 * in a time_t. This constant represents the largest internal clock value that
 * can be safely represented as a time_t.
 */
#define MAX_32_TIMESTAMP_NANOS 2147483647 * ONE_SEC_IN_NANOS

#define OSSL_VERIFY_CALLBACK_IGNORE_ERROR 1

DEFINE_POINTER_CLEANUP_FUNC(STACK_OF(X509_CRL) *, sk_X509_CRL_free);
DEFINE_POINTER_CLEANUP_FUNC(STACK_OF(GENERAL_NAME) *, GENERAL_NAMES_free);

uint8_t s2n_x509_ocsp_stapling_supported(void)
{
    return S2N_OCSP_STAPLING_SUPPORTED;
}

void s2n_x509_trust_store_init_empty(struct s2n_x509_trust_store *store)
{
    store->trust_store = NULL;
}

uint8_t s2n_x509_trust_store_has_certs(struct s2n_x509_trust_store *store)
{
    return store->trust_store ? (uint8_t) 1 : (uint8_t) 0;
}

int s2n_x509_trust_store_add_pem(struct s2n_x509_trust_store *store, const char *pem)
{
    POSIX_ENSURE_REF(store);
    POSIX_ENSURE_REF(pem);

    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
    }

    DEFER_CLEANUP(struct s2n_stuffer pem_in_stuffer = { 0 }, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer der_out_stuffer = { 0 }, s2n_stuffer_free);

    POSIX_GUARD(s2n_stuffer_alloc_ro_from_string(&pem_in_stuffer, pem));
    POSIX_GUARD(s2n_stuffer_growable_alloc(&der_out_stuffer, 2048));

    do {
        DEFER_CLEANUP(struct s2n_blob next_cert = { 0 }, s2n_free);

        POSIX_GUARD(s2n_stuffer_certificate_from_pem(&pem_in_stuffer, &der_out_stuffer));
        POSIX_GUARD(s2n_alloc(&next_cert, s2n_stuffer_data_available(&der_out_stuffer)));
        POSIX_GUARD(s2n_stuffer_read(&der_out_stuffer, &next_cert));

        const uint8_t *data = next_cert.data;
        DEFER_CLEANUP(X509 *ca_cert = d2i_X509(NULL, &data, next_cert.size), X509_free_pointer);
        S2N_ERROR_IF(ca_cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

        if (!X509_STORE_add_cert(store->trust_store, ca_cert)) {
            unsigned long error = ERR_get_error();
            POSIX_ENSURE(ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE, S2N_ERR_DECODE_CERTIFICATE);
        }
    } while (s2n_stuffer_data_available(&pem_in_stuffer));

    return 0;
}

int s2n_x509_trust_store_from_ca_file(struct s2n_x509_trust_store *store, const char *ca_pem_filename, const char *ca_dir)
{
    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
        POSIX_ENSURE_REF(store->trust_store);
    }

    int err_code = X509_STORE_load_locations(store->trust_store, ca_pem_filename, ca_dir);
    if (!err_code) {
        s2n_x509_trust_store_wipe(store);
        POSIX_BAIL(S2N_ERR_X509_TRUST_STORE);
    }

    return 0;
}

void s2n_x509_trust_store_wipe(struct s2n_x509_trust_store *store)
{
    if (store->trust_store) {
        X509_STORE_free(store->trust_store);
        store->trust_store = NULL;
        store->loaded_system_certs = false;
    }
}

int s2n_x509_validator_init_no_x509_validation(struct s2n_x509_validator *validator)
{
    POSIX_ENSURE_REF(validator);
    validator->trust_store = NULL;
    validator->store_ctx = NULL;
    validator->skip_cert_validation = 1;
    validator->check_stapled_ocsp = 0;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;
    validator->state = INIT;
    validator->cert_chain_from_wire = sk_X509_new_null();
    validator->crl_lookup_list = NULL;
    validator->cert_validation_info = (struct s2n_cert_validation_info){ 0 };
    validator->cert_validation_cb_invoked = false;

    return 0;
}

int s2n_x509_validator_init(struct s2n_x509_validator *validator, struct s2n_x509_trust_store *trust_store, uint8_t check_ocsp)
{
    POSIX_ENSURE_REF(trust_store);
    validator->trust_store = trust_store;
    validator->skip_cert_validation = 0;
    validator->check_stapled_ocsp = check_ocsp;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;
    validator->store_ctx = NULL;
    if (validator->trust_store->trust_store) {
        validator->store_ctx = X509_STORE_CTX_new();
        POSIX_ENSURE_REF(validator->store_ctx);
    }
    validator->cert_chain_from_wire = sk_X509_new_null();
    validator->state = INIT;
    validator->crl_lookup_list = NULL;
    validator->cert_validation_info = (struct s2n_cert_validation_info){ 0 };
    validator->cert_validation_cb_invoked = false;

    return 0;
}

static inline void wipe_cert_chain(STACK_OF(X509) *cert_chain)
{
    if (cert_chain) {
        sk_X509_pop_free(cert_chain, X509_free);
    }
}

int s2n_x509_validator_wipe(struct s2n_x509_validator *validator)
{
    if (validator->store_ctx) {
        X509_STORE_CTX_free(validator->store_ctx);
        validator->store_ctx = NULL;
    }
    wipe_cert_chain(validator->cert_chain_from_wire);
    validator->cert_chain_from_wire = NULL;
    validator->trust_store = NULL;
    validator->skip_cert_validation = 0;
    validator->state = UNINIT;
    validator->max_chain_depth = 0;
    if (validator->crl_lookup_list) {
        POSIX_GUARD_RESULT(s2n_array_free(validator->crl_lookup_list));
        validator->crl_lookup_list = NULL;
    }

    return S2N_SUCCESS;
}

int s2n_x509_validator_set_max_chain_depth(struct s2n_x509_validator *validator, uint16_t max_depth)
{
    POSIX_ENSURE_REF(validator);
    S2N_ERROR_IF(max_depth == 0, S2N_ERR_INVALID_ARGUMENT);

    validator->max_chain_depth = max_depth;
    return 0;
}

static S2N_RESULT s2n_verify_host_information_san_entry(struct s2n_connection *conn, GENERAL_NAME *current_name, bool *san_found)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(current_name);
    RESULT_ENSURE_REF(san_found);

    if (current_name->type == GEN_DNS || current_name->type == GEN_URI) {
        *san_found = true;

        const char *name = (const char *) ASN1_STRING_data(current_name->d.ia5);
        RESULT_ENSURE_REF(name);
        int name_len = ASN1_STRING_length(current_name->d.ia5);
        RESULT_ENSURE_GT(name_len, 0);

        RESULT_ENSURE(conn->verify_host_fn(name, name_len, conn->data_for_verify_host), S2N_ERR_CERT_UNTRUSTED);

        return S2N_RESULT_OK;
    }

    if (current_name->type == GEN_IPADD) {
        *san_found = true;

        /* try to validate an IP address if it's in the subject alt name. */
        const unsigned char *ip_addr = current_name->d.iPAddress->data;
        RESULT_ENSURE_REF(ip_addr);
        int ip_addr_len = current_name->d.iPAddress->length;
        RESULT_ENSURE_GT(ip_addr_len, 0);

        RESULT_STACK_BLOB(address, INET6_ADDRSTRLEN + 1, INET6_ADDRSTRLEN + 1);

        if (ip_addr_len == 4) {
            RESULT_GUARD(s2n_inet_ntop(AF_INET, ip_addr, &address));
        } else if (ip_addr_len == 16) {
            RESULT_GUARD(s2n_inet_ntop(AF_INET6, ip_addr, &address));
        } else {
            /* we aren't able to parse this value so skip it */
            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }

        /* strlen should be safe here since we made sure we were null terminated AND that inet_ntop succeeded */
        const char *name = (const char *) address.data;
        size_t name_len = strlen(name);

        RESULT_ENSURE(conn->verify_host_fn(name, name_len, conn->data_for_verify_host), S2N_ERR_CERT_UNTRUSTED);

        return S2N_RESULT_OK;
    }

    /* we don't understand this entry type so skip it */
    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

static S2N_RESULT s2n_verify_host_information_san(struct s2n_connection *conn, X509 *public_cert, bool *san_found)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(public_cert);
    RESULT_ENSURE_REF(san_found);

    *san_found = false;

    DEFER_CLEANUP(STACK_OF(GENERAL_NAME) *names_list = NULL, GENERAL_NAMES_free_pointer);
    names_list = X509_get_ext_d2i(public_cert, NID_subject_alt_name, NULL, NULL);
    RESULT_ENSURE(names_list, S2N_ERR_CERT_UNTRUSTED);

    int n = sk_GENERAL_NAME_num(names_list);
    RESULT_ENSURE(n > 0, S2N_ERR_CERT_UNTRUSTED);

    s2n_result result = S2N_RESULT_OK;
    for (int i = 0; i < n; i++) {
        GENERAL_NAME *current_name = sk_GENERAL_NAME_value(names_list, i);

        /* return success on the first entry that passes verification */
        result = s2n_verify_host_information_san_entry(conn, current_name, san_found);
        if (s2n_result_is_ok(result)) {
            return S2N_RESULT_OK;
        }
    }

    /* if an error was set by one of the entries, then just propagate the error from the last SAN entry call */
    RESULT_GUARD(result);

    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

static S2N_RESULT s2n_verify_host_information_common_name(struct s2n_connection *conn, X509 *public_cert, bool *cn_found)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(public_cert);
    RESULT_ENSURE_REF(cn_found);

    X509_NAME *subject_name = X509_get_subject_name(public_cert);
    RESULT_ENSURE(subject_name, S2N_ERR_CERT_UNTRUSTED);

    int curr_idx = -1;
    while (true) {
        int next_idx = X509_NAME_get_index_by_NID(subject_name, NID_commonName, curr_idx);
        if (next_idx >= 0) {
            curr_idx = next_idx;
        } else {
            break;
        }
    }

    RESULT_ENSURE(curr_idx >= 0, S2N_ERR_CERT_UNTRUSTED);

    ASN1_STRING *common_name = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject_name, curr_idx));
    RESULT_ENSURE(common_name, S2N_ERR_CERT_UNTRUSTED);

    /* X520CommonName allows the following ANSI string types per RFC 5280 Appendix A.1 */
    RESULT_ENSURE(ASN1_STRING_type(common_name) == V_ASN1_TELETEXSTRING
                    || ASN1_STRING_type(common_name) == V_ASN1_PRINTABLESTRING
                    || ASN1_STRING_type(common_name) == V_ASN1_UNIVERSALSTRING
                    || ASN1_STRING_type(common_name) == V_ASN1_UTF8STRING
                    || ASN1_STRING_type(common_name) == V_ASN1_BMPSTRING,
            S2N_ERR_CERT_UNTRUSTED);

    /* at this point we have a valid CN value */
    *cn_found = true;

    char peer_cn[255] = { 0 };
    int cn_len = ASN1_STRING_length(common_name);
    RESULT_ENSURE_GT(cn_len, 0);
    uint32_t len = (uint32_t) cn_len;
    RESULT_ENSURE_LTE(len, s2n_array_len(peer_cn) - 1);
    RESULT_CHECKED_MEMCPY(peer_cn, ASN1_STRING_data(common_name), len);
    RESULT_ENSURE(conn->verify_host_fn(peer_cn, len, conn->data_for_verify_host), S2N_ERR_CERT_UNTRUSTED);

    return S2N_RESULT_OK;
}

/*
 * For each name in the cert. Iterate them. Call the callback. If one returns true, then consider it validated,
 * if none of them return true, the cert is considered invalid.
 */
static S2N_RESULT s2n_verify_host_information(struct s2n_connection *conn, X509 *public_cert)
{
    bool entry_found = false;

    /* Check SubjectAltNames before CommonName as per RFC 6125 6.4.4 */
    s2n_result result = s2n_verify_host_information_san(conn, public_cert, &entry_found);

    /*
     *= https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4
     *# As noted, a client MUST NOT seek a match for a reference identifier
     *# of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
     *# URI-ID, or any application-specific identifier types supported by the
     *# client.
     */
    if (entry_found) {
        return result;
    }

    /*
     *= https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4
     *# Therefore, if and only if the presented identifiers do not include a
     *# DNS-ID, SRV-ID, URI-ID, or any application-specific identifier types
     *# supported by the client, then the client MAY as a last resort check
     *# for a string whose form matches that of a fully qualified DNS domain
     *# name in a Common Name field of the subject field (i.e., a CN-ID).
     */
    result = s2n_verify_host_information_common_name(conn, public_cert, &entry_found);
    if (entry_found) {
        return result;
    }

    /* make a null-terminated string in case the callback tries to use strlen */
    const char *name = "";
    size_t name_len = 0;

    /* at this point, we don't have anything to identify the certificate with so pass an empty string to the callback */
    RESULT_ENSURE(conn->verify_host_fn(name, name_len, conn->data_for_verify_host), S2N_ERR_CERT_UNTRUSTED);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_validator_read_asn1_cert(struct s2n_stuffer *cert_chain_in_stuffer,
        struct s2n_blob *asn1_cert)
{
    uint32_t certificate_size = 0;

    RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(cert_chain_in_stuffer, &certificate_size));
    RESULT_ENSURE(certificate_size > 0, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(certificate_size <= s2n_stuffer_data_available(cert_chain_in_stuffer), S2N_ERR_CERT_INVALID);

    asn1_cert->size = certificate_size;
    asn1_cert->data = s2n_stuffer_raw_read(cert_chain_in_stuffer, certificate_size);
    RESULT_ENSURE_REF(asn1_cert->data);

    return S2N_RESULT_OK;
}

/**
* Validates that each certificate in a peer's cert chain contains only signature algorithms in a security policy's
* certificate_signatures_preference list.
*/
S2N_RESULT s2n_x509_validator_check_cert_preferences(struct s2n_connection *conn, X509 *cert)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(cert);

    const struct s2n_security_policy *security_policy = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &security_policy));

    /**
     * We only restrict the signature algorithm on the certificates in the
     * peer's certificate chain if the certificate_signature_preferences field
     * is set in the security policy. This is contrary to the RFC, which
     * specifies that the signatures in the "signature_algorithms" extension
     * apply to signatures in the certificate chain in certain scenarios, so RFC
     * compliance would imply validating that the certificate chain signature
     * algorithm matches one of the algorithms specified in the
     * "signature_algorithms" extension.
     *
     *= https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
     *= type=exception
     *= reason=not implemented due to lack of utility
     *# If the client provided a "signature_algorithms" extension, then all
     *# certificates provided by the server MUST be signed by a
     *# hash/signature algorithm pair that appears in that extension.
     *
     *= https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
     *= type=exception
     *= reason=not implemented due to lack of utility
     *# If no "signature_algorithms_cert" extension is present, then the
     *# "signature_algorithms" extension also applies to signatures appearing in
     *# certificates.
     */
    struct s2n_cert_info info = { 0 };
    RESULT_GUARD(s2n_openssl_x509_get_cert_info(cert, &info));

    bool certificate_preferences_defined = security_policy->certificate_signature_preferences != NULL
            || security_policy->certificate_key_preferences != NULL;
    if (certificate_preferences_defined && !info.self_signed && conn->actual_protocol_version == S2N_TLS13) {
        /* Ensure that the certificate signature does not use SHA-1. While this check
         * would ideally apply to all connections, we only enforce it when certificate
         * preferences exist to stay backwards compatible.
         */
        RESULT_ENSURE(info.signature_digest_nid != NID_sha1, S2N_ERR_CERT_UNTRUSTED);
    }

    if (!info.self_signed) {
        RESULT_GUARD(s2n_security_policy_validate_cert_signature(security_policy, &info, S2N_ERR_CERT_UNTRUSTED));
    }
    RESULT_GUARD(s2n_security_policy_validate_cert_key(security_policy, &info, S2N_ERR_CERT_UNTRUSTED));

    return S2N_RESULT_OK;
}

/* Validates that the root certificate uses a key allowed by the security policy
 * certificate preferences.
 */
static S2N_RESULT s2n_x509_validator_check_root_cert(struct s2n_x509_validator *validator, struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(conn);

    const struct s2n_security_policy *security_policy = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &security_policy));
    RESULT_ENSURE_REF(security_policy);

    RESULT_ENSURE_REF(validator->store_ctx);
    DEFER_CLEANUP(STACK_OF(X509) *cert_chain = X509_STORE_CTX_get1_chain(validator->store_ctx),
            s2n_openssl_x509_stack_pop_free);
    RESULT_ENSURE_REF(cert_chain);

    const int certs_in_chain = sk_X509_num(cert_chain);
    RESULT_ENSURE(certs_in_chain > 0, S2N_ERR_CERT_UNTRUSTED);
    X509 *root = sk_X509_value(cert_chain, certs_in_chain - 1);
    RESULT_ENSURE_REF(root);

    struct s2n_cert_info info = { 0 };
    RESULT_GUARD(s2n_openssl_x509_get_cert_info(root, &info));

    RESULT_GUARD(s2n_security_policy_validate_cert_key(security_policy, &info,
            S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_read_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len)
{
    RESULT_ENSURE(validator->skip_cert_validation || s2n_x509_trust_store_has_certs(validator->trust_store), S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    struct s2n_blob cert_chain_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&cert_chain_blob, cert_chain_in, cert_chain_len));
    DEFER_CLEANUP(struct s2n_stuffer cert_chain_in_stuffer = { 0 }, s2n_stuffer_free);

    RESULT_GUARD_POSIX(s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob));

    while (s2n_stuffer_data_available(&cert_chain_in_stuffer)
            && sk_X509_num(validator->cert_chain_from_wire) < validator->max_chain_depth) {
        struct s2n_blob asn1_cert = { 0 };
        RESULT_GUARD(s2n_x509_validator_read_asn1_cert(&cert_chain_in_stuffer, &asn1_cert));

        /* We only do the trailing byte validation when parsing the leaf cert to
         * match historical s2n-tls behavior.
         */
        DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);
        if (sk_X509_num(validator->cert_chain_from_wire) == 0) {
            RESULT_GUARD(s2n_openssl_x509_parse(&asn1_cert, &cert));
        } else {
            RESULT_GUARD(s2n_openssl_x509_parse_without_length_validation(&asn1_cert, &cert));
        }

        if (!validator->skip_cert_validation) {
            RESULT_GUARD(s2n_x509_validator_check_cert_preferences(conn, cert));
        }

        /* add the cert to the chain */
        RESULT_ENSURE(sk_X509_push(validator->cert_chain_from_wire, cert) > 0,
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

        /* After the cert is added to cert_chain_from_wire, it will be freed
         * with the call to s2n_x509_validator_wipe. We disable the cleanup
         * function since cleanup is no longer "owned" by cert.
         */
        ZERO_TO_DISABLE_DEFER_CLEANUP(cert);

        /* certificate extensions is a field in TLS 1.3 - https://tools.ietf.org/html/rfc8446#section-4.4.2 */
        if (conn->actual_protocol_version >= S2N_TLS13) {
            s2n_parsed_extensions_list parsed_extensions_list = { 0 };
            RESULT_GUARD_POSIX(s2n_extension_list_parse(&cert_chain_in_stuffer, &parsed_extensions_list));
        }
    }

    /* if this occurred we exceeded validator->max_chain_depth */
    RESULT_ENSURE(validator->skip_cert_validation || s2n_stuffer_data_available(&cert_chain_in_stuffer) == 0,
            S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
    RESULT_ENSURE(sk_X509_num(validator->cert_chain_from_wire) > 0, S2N_ERR_NO_CERT_FOUND);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_process_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len)
{
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    RESULT_GUARD(s2n_x509_validator_read_cert_chain(validator, conn, cert_chain_in, cert_chain_len));

    if (validator->skip_cert_validation) {
        return S2N_RESULT_OK;
    }

    X509 *leaf = sk_X509_value(validator->cert_chain_from_wire, 0);
    RESULT_ENSURE_REF(leaf);

    if (conn->verify_host_fn) {
        RESULT_GUARD(s2n_verify_host_information(conn, leaf));
    }

    RESULT_GUARD_OSSL(X509_STORE_CTX_init(validator->store_ctx, validator->trust_store->trust_store, leaf,
                              validator->cert_chain_from_wire),
            S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

    if (conn->config->crl_lookup_cb) {
        RESULT_GUARD(s2n_crl_invoke_lookup_callbacks(conn, validator));
        RESULT_GUARD(s2n_crl_handle_lookup_callback_result(validator));
    }

    validator->state = READY_TO_VERIFY;

    return S2N_RESULT_OK;
}
