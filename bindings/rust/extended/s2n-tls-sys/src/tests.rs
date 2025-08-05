
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[test]
fn s2n_async_pkey_op_apply () {
    let ptr = crate::s2n_async_pkey_op_apply as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_async_pkey_op_free () {
    let ptr = crate::s2n_async_pkey_op_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_async_pkey_op_get_input () {
    let ptr = crate::s2n_async_pkey_op_get_input as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_async_pkey_op_get_input_size () {
    let ptr = crate::s2n_async_pkey_op_get_input_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_async_pkey_op_get_op_type () {
    let ptr = crate::s2n_async_pkey_op_get_op_type as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_async_pkey_op_perform () {
    let ptr = crate::s2n_async_pkey_op_perform as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_async_pkey_op_set_output () {
    let ptr = crate::s2n_async_pkey_op_set_output as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_calculate_stacktrace () {
    let ptr = crate::s2n_calculate_stacktrace as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_free () {
    let ptr = crate::s2n_cert_chain_and_key_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_get_ctx () {
    let ptr = crate::s2n_cert_chain_and_key_get_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_get_private_key () {
    let ptr = crate::s2n_cert_chain_and_key_get_private_key as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_load_pem () {
    let ptr = crate::s2n_cert_chain_and_key_load_pem as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_load_pem_bytes () {
    let ptr = crate::s2n_cert_chain_and_key_load_pem_bytes as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_load_public_pem_bytes () {
    let ptr = crate::s2n_cert_chain_and_key_load_public_pem_bytes as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_new () {
    let ptr = crate::s2n_cert_chain_and_key_new as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_set_ctx () {
    let ptr = crate::s2n_cert_chain_and_key_set_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_set_ocsp_data () {
    let ptr = crate::s2n_cert_chain_and_key_set_ocsp_data as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_and_key_set_sct_list () {
    let ptr = crate::s2n_cert_chain_and_key_set_sct_list as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_get_cert () {
    let ptr = crate::s2n_cert_chain_get_cert as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_chain_get_length () {
    let ptr = crate::s2n_cert_chain_get_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_get_der () {
    let ptr = crate::s2n_cert_get_der as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_get_utf8_string_from_extension_data () {
    let ptr = crate::s2n_cert_get_utf8_string_from_extension_data as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_get_utf8_string_from_extension_data_length () {
    let ptr = crate::s2n_cert_get_utf8_string_from_extension_data_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_get_x509_extension_value () {
    let ptr = crate::s2n_cert_get_x509_extension_value as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cert_get_x509_extension_value_length () {
    let ptr = crate::s2n_cert_get_x509_extension_value_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cleanup () {
    let ptr = crate::s2n_cleanup as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_cleanup_final () {
    let ptr = crate::s2n_cleanup_final as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_cb_done () {
    let ptr = crate::s2n_client_hello_cb_done as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_free () {
    let ptr = crate::s2n_client_hello_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_cipher_suites () {
    let ptr = crate::s2n_client_hello_get_cipher_suites as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_cipher_suites_length () {
    let ptr = crate::s2n_client_hello_get_cipher_suites_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_compression_methods () {
    let ptr = crate::s2n_client_hello_get_compression_methods as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_compression_methods_length () {
    let ptr = crate::s2n_client_hello_get_compression_methods_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_extension_by_id () {
    let ptr = crate::s2n_client_hello_get_extension_by_id as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_extension_length () {
    let ptr = crate::s2n_client_hello_get_extension_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_extensions () {
    let ptr = crate::s2n_client_hello_get_extensions as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_extensions_length () {
    let ptr = crate::s2n_client_hello_get_extensions_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_legacy_protocol_version () {
    let ptr = crate::s2n_client_hello_get_legacy_protocol_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_legacy_record_version () {
    let ptr = crate::s2n_client_hello_get_legacy_record_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_raw_message () {
    let ptr = crate::s2n_client_hello_get_raw_message as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_raw_message_length () {
    let ptr = crate::s2n_client_hello_get_raw_message_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_server_name () {
    let ptr = crate::s2n_client_hello_get_server_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_server_name_length () {
    let ptr = crate::s2n_client_hello_get_server_name_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_session_id () {
    let ptr = crate::s2n_client_hello_get_session_id as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_session_id_length () {
    let ptr = crate::s2n_client_hello_get_session_id_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_get_supported_groups () {
    let ptr = crate::s2n_client_hello_get_supported_groups as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_has_extension () {
    let ptr = crate::s2n_client_hello_has_extension as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_client_hello_parse_message () {
    let ptr = crate::s2n_client_hello_parse_message as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_accept_max_fragment_length () {
    let ptr = crate::s2n_config_accept_max_fragment_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_add_cert_chain_and_key () {
    let ptr = crate::s2n_config_add_cert_chain_and_key as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_add_cert_chain_and_key_to_store () {
    let ptr = crate::s2n_config_add_cert_chain_and_key_to_store as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_add_dhparams () {
    let ptr = crate::s2n_config_add_dhparams as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_add_pem_to_trust_store () {
    let ptr = crate::s2n_config_add_pem_to_trust_store as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_add_ticket_crypto_key () {
    let ptr = crate::s2n_config_add_ticket_crypto_key as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_append_protocol_preference () {
    let ptr = crate::s2n_config_append_protocol_preference as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_disable_x509_time_verification () {
    let ptr = crate::s2n_config_disable_x509_time_verification as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_disable_x509_verification () {
    let ptr = crate::s2n_config_disable_x509_verification as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_enable_cert_req_dss_legacy_compat () {
    let ptr = crate::s2n_config_enable_cert_req_dss_legacy_compat as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_free () {
    let ptr = crate::s2n_config_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_free_cert_chain_and_key () {
    let ptr = crate::s2n_config_free_cert_chain_and_key as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_free_dhparams () {
    let ptr = crate::s2n_config_free_dhparams as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_get_client_auth_type () {
    let ptr = crate::s2n_config_get_client_auth_type as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_get_ctx () {
    let ptr = crate::s2n_config_get_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_get_supported_groups () {
    let ptr = crate::s2n_config_get_supported_groups as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_load_system_certs () {
    let ptr = crate::s2n_config_load_system_certs as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_new () {
    let ptr = crate::s2n_config_new as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_new_minimal () {
    let ptr = crate::s2n_config_new_minimal as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_require_ticket_forward_secrecy () {
    let ptr = crate::s2n_config_require_ticket_forward_secrecy as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_send_max_fragment_length () {
    let ptr = crate::s2n_config_send_max_fragment_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_alert_behavior () {
    let ptr = crate::s2n_config_set_alert_behavior as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_async_pkey_callback () {
    let ptr = crate::s2n_config_set_async_pkey_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_async_pkey_validation_mode () {
    let ptr = crate::s2n_config_set_async_pkey_validation_mode as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_cache_delete_callback () {
    let ptr = crate::s2n_config_set_cache_delete_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_cache_retrieve_callback () {
    let ptr = crate::s2n_config_set_cache_retrieve_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_cache_store_callback () {
    let ptr = crate::s2n_config_set_cache_store_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_cert_authorities_from_trust_store () {
    let ptr = crate::s2n_config_set_cert_authorities_from_trust_store as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_cert_chain_and_key_defaults () {
    let ptr = crate::s2n_config_set_cert_chain_and_key_defaults as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_cert_tiebreak_callback () {
    let ptr = crate::s2n_config_set_cert_tiebreak_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_check_stapled_ocsp_response () {
    let ptr = crate::s2n_config_set_check_stapled_ocsp_response as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_cipher_preferences () {
    let ptr = crate::s2n_config_set_cipher_preferences as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_client_auth_type () {
    let ptr = crate::s2n_config_set_client_auth_type as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_client_hello_cb () {
    let ptr = crate::s2n_config_set_client_hello_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_client_hello_cb_mode () {
    let ptr = crate::s2n_config_set_client_hello_cb_mode as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_ct_support_level () {
    let ptr = crate::s2n_config_set_ct_support_level as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_ctx () {
    let ptr = crate::s2n_config_set_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_early_data_cb () {
    let ptr = crate::s2n_config_set_early_data_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_extension_data () {
    let ptr = crate::s2n_config_set_extension_data as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_initial_ticket_count () {
    let ptr = crate::s2n_config_set_initial_ticket_count as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_key_log_cb () {
    let ptr = crate::s2n_config_set_key_log_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_max_blinding_delay () {
    let ptr = crate::s2n_config_set_max_blinding_delay as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_max_cert_chain_depth () {
    let ptr = crate::s2n_config_set_max_cert_chain_depth as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_monotonic_clock () {
    let ptr = crate::s2n_config_set_monotonic_clock as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_protocol_preferences () {
    let ptr = crate::s2n_config_set_protocol_preferences as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_psk_mode () {
    let ptr = crate::s2n_config_set_psk_mode as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_psk_selection_callback () {
    let ptr = crate::s2n_config_set_psk_selection_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_recv_multi_record () {
    let ptr = crate::s2n_config_set_recv_multi_record as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_send_buffer_size () {
    let ptr = crate::s2n_config_set_send_buffer_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_serialization_version () {
    let ptr = crate::s2n_config_set_serialization_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_server_max_early_data_size () {
    let ptr = crate::s2n_config_set_server_max_early_data_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_session_cache_onoff () {
    let ptr = crate::s2n_config_set_session_cache_onoff as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_session_state_lifetime () {
    let ptr = crate::s2n_config_set_session_state_lifetime as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_session_ticket_cb () {
    let ptr = crate::s2n_config_set_session_ticket_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_session_tickets_onoff () {
    let ptr = crate::s2n_config_set_session_tickets_onoff as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_status_request_type () {
    let ptr = crate::s2n_config_set_status_request_type as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_ticket_decrypt_key_lifetime () {
    let ptr = crate::s2n_config_set_ticket_decrypt_key_lifetime as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_ticket_encrypt_decrypt_key_lifetime () {
    let ptr = crate::s2n_config_set_ticket_encrypt_decrypt_key_lifetime as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_verification_ca_location () {
    let ptr = crate::s2n_config_set_verification_ca_location as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_verify_after_sign () {
    let ptr = crate::s2n_config_set_verify_after_sign as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_verify_host_callback () {
    let ptr = crate::s2n_config_set_verify_host_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_set_wall_clock () {
    let ptr = crate::s2n_config_set_wall_clock as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_config_wipe_trust_store () {
    let ptr = crate::s2n_config_wipe_trust_store as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_add_new_tickets_to_send () {
    let ptr = crate::s2n_connection_add_new_tickets_to_send as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_append_protocol_preference () {
    let ptr = crate::s2n_connection_append_protocol_preference as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_append_psk () {
    let ptr = crate::s2n_connection_append_psk as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_client_cert_used () {
    let ptr = crate::s2n_connection_client_cert_used as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_deserialize () {
    let ptr = crate::s2n_connection_deserialize as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_free () {
    let ptr = crate::s2n_connection_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_free_handshake () {
    let ptr = crate::s2n_connection_free_handshake as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_actual_protocol_version () {
    let ptr = crate::s2n_connection_get_actual_protocol_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_alert () {
    let ptr = crate::s2n_connection_get_alert as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_certificate_match () {
    let ptr = crate::s2n_connection_get_certificate_match as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_cipher () {
    let ptr = crate::s2n_connection_get_cipher as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_cipher_iana_value () {
    let ptr = crate::s2n_connection_get_cipher_iana_value as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_client_auth_type () {
    let ptr = crate::s2n_connection_get_client_auth_type as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_client_cert_chain () {
    let ptr = crate::s2n_connection_get_client_cert_chain as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_client_hello () {
    let ptr = crate::s2n_connection_get_client_hello as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_client_hello_version () {
    let ptr = crate::s2n_connection_get_client_hello_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_client_protocol_version () {
    let ptr = crate::s2n_connection_get_client_protocol_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_ctx () {
    let ptr = crate::s2n_connection_get_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_curve () {
    let ptr = crate::s2n_connection_get_curve as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_delay () {
    let ptr = crate::s2n_connection_get_delay as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_early_data_status () {
    let ptr = crate::s2n_connection_get_early_data_status as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_handshake_type_name () {
    let ptr = crate::s2n_connection_get_handshake_type_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_kem_group_name () {
    let ptr = crate::s2n_connection_get_kem_group_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_kem_name () {
    let ptr = crate::s2n_connection_get_kem_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_key_exchange_group () {
    let ptr = crate::s2n_connection_get_key_exchange_group as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_last_message_name () {
    let ptr = crate::s2n_connection_get_last_message_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_master_secret () {
    let ptr = crate::s2n_connection_get_master_secret as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_max_early_data_size () {
    let ptr = crate::s2n_connection_get_max_early_data_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_negotiated_psk_identity () {
    let ptr = crate::s2n_connection_get_negotiated_psk_identity as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_negotiated_psk_identity_length () {
    let ptr = crate::s2n_connection_get_negotiated_psk_identity_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_ocsp_response () {
    let ptr = crate::s2n_connection_get_ocsp_response as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_peer_cert_chain () {
    let ptr = crate::s2n_connection_get_peer_cert_chain as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_read_fd () {
    let ptr = crate::s2n_connection_get_read_fd as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_remaining_early_data_size () {
    let ptr = crate::s2n_connection_get_remaining_early_data_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_sct_list () {
    let ptr = crate::s2n_connection_get_sct_list as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_selected_cert () {
    let ptr = crate::s2n_connection_get_selected_cert as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_selected_client_cert_digest_algorithm () {
    let ptr = crate::s2n_connection_get_selected_client_cert_digest_algorithm as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_selected_client_cert_signature_algorithm () {
    let ptr = crate::s2n_connection_get_selected_client_cert_signature_algorithm as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_selected_digest_algorithm () {
    let ptr = crate::s2n_connection_get_selected_digest_algorithm as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_selected_signature_algorithm () {
    let ptr = crate::s2n_connection_get_selected_signature_algorithm as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_server_protocol_version () {
    let ptr = crate::s2n_connection_get_server_protocol_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_session () {
    let ptr = crate::s2n_connection_get_session as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_session_id () {
    let ptr = crate::s2n_connection_get_session_id as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_session_id_length () {
    let ptr = crate::s2n_connection_get_session_id_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_session_length () {
    let ptr = crate::s2n_connection_get_session_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_session_ticket_lifetime_hint () {
    let ptr = crate::s2n_connection_get_session_ticket_lifetime_hint as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_tickets_sent () {
    let ptr = crate::s2n_connection_get_tickets_sent as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_wire_bytes_in () {
    let ptr = crate::s2n_connection_get_wire_bytes_in as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_wire_bytes_out () {
    let ptr = crate::s2n_connection_get_wire_bytes_out as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_get_write_fd () {
    let ptr = crate::s2n_connection_get_write_fd as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_is_ocsp_stapled () {
    let ptr = crate::s2n_connection_is_ocsp_stapled as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_is_session_resumed () {
    let ptr = crate::s2n_connection_is_session_resumed as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_is_valid_for_cipher_preferences () {
    let ptr = crate::s2n_connection_is_valid_for_cipher_preferences as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_new () {
    let ptr = crate::s2n_connection_new as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_prefer_low_latency () {
    let ptr = crate::s2n_connection_prefer_low_latency as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_prefer_throughput () {
    let ptr = crate::s2n_connection_prefer_throughput as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_release_buffers () {
    let ptr = crate::s2n_connection_release_buffers as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_request_key_update () {
    let ptr = crate::s2n_connection_request_key_update as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_serialization_length () {
    let ptr = crate::s2n_connection_serialization_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_serialize () {
    let ptr = crate::s2n_connection_serialize as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_server_name_extension_used () {
    let ptr = crate::s2n_connection_server_name_extension_used as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_blinding () {
    let ptr = crate::s2n_connection_set_blinding as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_cipher_preferences () {
    let ptr = crate::s2n_connection_set_cipher_preferences as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_client_auth_type () {
    let ptr = crate::s2n_connection_set_client_auth_type as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_config () {
    let ptr = crate::s2n_connection_set_config as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_ctx () {
    let ptr = crate::s2n_connection_set_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_dynamic_buffers () {
    let ptr = crate::s2n_connection_set_dynamic_buffers as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_dynamic_record_threshold () {
    let ptr = crate::s2n_connection_set_dynamic_record_threshold as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_fd () {
    let ptr = crate::s2n_connection_set_fd as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_protocol_preferences () {
    let ptr = crate::s2n_connection_set_protocol_preferences as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_psk_mode () {
    let ptr = crate::s2n_connection_set_psk_mode as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_read_fd () {
    let ptr = crate::s2n_connection_set_read_fd as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_recv_buffering () {
    let ptr = crate::s2n_connection_set_recv_buffering as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_recv_cb () {
    let ptr = crate::s2n_connection_set_recv_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_recv_ctx () {
    let ptr = crate::s2n_connection_set_recv_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_send_cb () {
    let ptr = crate::s2n_connection_set_send_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_send_ctx () {
    let ptr = crate::s2n_connection_set_send_ctx as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_server_early_data_context () {
    let ptr = crate::s2n_connection_set_server_early_data_context as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_server_keying_material_lifetime () {
    let ptr = crate::s2n_connection_set_server_keying_material_lifetime as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_server_max_early_data_size () {
    let ptr = crate::s2n_connection_set_server_max_early_data_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_session () {
    let ptr = crate::s2n_connection_set_session as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_verify_host_callback () {
    let ptr = crate::s2n_connection_set_verify_host_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_set_write_fd () {
    let ptr = crate::s2n_connection_set_write_fd as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_tls_exporter () {
    let ptr = crate::s2n_connection_tls_exporter as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_use_corked_io () {
    let ptr = crate::s2n_connection_use_corked_io as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_connection_wipe () {
    let ptr = crate::s2n_connection_wipe as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_crypto_disable_init () {
    let ptr = crate::s2n_crypto_disable_init as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_disable_atexit () {
    let ptr = crate::s2n_disable_atexit as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_errno_location () {
    let ptr = crate::s2n_errno_location as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_error_get_type () {
    let ptr = crate::s2n_error_get_type as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_external_psk_new () {
    let ptr = crate::s2n_external_psk_new as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_free_stacktrace () {
    let ptr = crate::s2n_free_stacktrace as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_get_application_protocol () {
    let ptr = crate::s2n_get_application_protocol as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_get_fips_mode () {
    let ptr = crate::s2n_get_fips_mode as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_get_openssl_version () {
    let ptr = crate::s2n_get_openssl_version as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_get_server_name () {
    let ptr = crate::s2n_get_server_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_get_stacktrace () {
    let ptr = crate::s2n_get_stacktrace as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_init () {
    let ptr = crate::s2n_init as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_mem_set_callbacks () {
    let ptr = crate::s2n_mem_set_callbacks as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_negotiate () {
    let ptr = crate::s2n_negotiate as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_early_data_accept () {
    let ptr = crate::s2n_offered_early_data_accept as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_early_data_get_context () {
    let ptr = crate::s2n_offered_early_data_get_context as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_early_data_get_context_length () {
    let ptr = crate::s2n_offered_early_data_get_context_length as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_early_data_reject () {
    let ptr = crate::s2n_offered_early_data_reject as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_psk_free () {
    let ptr = crate::s2n_offered_psk_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_psk_get_identity () {
    let ptr = crate::s2n_offered_psk_get_identity as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_psk_list_choose_psk () {
    let ptr = crate::s2n_offered_psk_list_choose_psk as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_psk_list_has_next () {
    let ptr = crate::s2n_offered_psk_list_has_next as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_psk_list_next () {
    let ptr = crate::s2n_offered_psk_list_next as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_psk_list_reread () {
    let ptr = crate::s2n_offered_psk_list_reread as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_offered_psk_new () {
    let ptr = crate::s2n_offered_psk_new as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_peek () {
    let ptr = crate::s2n_peek as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_peek_buffered () {
    let ptr = crate::s2n_peek_buffered as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_print_stacktrace () {
    let ptr = crate::s2n_print_stacktrace as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_psk_configure_early_data () {
    let ptr = crate::s2n_psk_configure_early_data as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_psk_free () {
    let ptr = crate::s2n_psk_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_psk_set_application_protocol () {
    let ptr = crate::s2n_psk_set_application_protocol as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_psk_set_early_data_context () {
    let ptr = crate::s2n_psk_set_early_data_context as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_psk_set_hmac () {
    let ptr = crate::s2n_psk_set_hmac as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_psk_set_identity () {
    let ptr = crate::s2n_psk_set_identity as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_psk_set_secret () {
    let ptr = crate::s2n_psk_set_secret as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_rand_set_callbacks () {
    let ptr = crate::s2n_rand_set_callbacks as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_recv () {
    let ptr = crate::s2n_recv as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_recv_early_data () {
    let ptr = crate::s2n_recv_early_data as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_send () {
    let ptr = crate::s2n_send as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_send_early_data () {
    let ptr = crate::s2n_send_early_data as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_sendv () {
    let ptr = crate::s2n_sendv as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_sendv_with_offset () {
    let ptr = crate::s2n_sendv_with_offset as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_session_ticket_get_data () {
    let ptr = crate::s2n_session_ticket_get_data as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_session_ticket_get_data_len () {
    let ptr = crate::s2n_session_ticket_get_data_len as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_session_ticket_get_lifetime () {
    let ptr = crate::s2n_session_ticket_get_lifetime as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_set_server_name () {
    let ptr = crate::s2n_set_server_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_shutdown () {
    let ptr = crate::s2n_shutdown as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_shutdown_send () {
    let ptr = crate::s2n_shutdown_send as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_stack_traces_enabled () {
    let ptr = crate::s2n_stack_traces_enabled as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_stack_traces_enabled_set () {
    let ptr = crate::s2n_stack_traces_enabled_set as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_strerror () {
    let ptr = crate::s2n_strerror as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_strerror_debug () {
    let ptr = crate::s2n_strerror_debug as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_strerror_name () {
    let ptr = crate::s2n_strerror_name as *const ();
    assert!(!ptr.is_null());
}

#[test]
fn s2n_strerror_source () {
    let ptr = crate::s2n_strerror_source as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "internal")]
fn s2n_config_add_cert_chain () {
    let ptr = crate::s2n_config_add_cert_chain as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "internal")]
fn s2n_connection_get_config () {
    let ptr = crate::s2n_connection_get_config as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "internal")]
fn s2n_flush () {
    let ptr = crate::s2n_flush as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_config_enable_quic () {
    let ptr = crate::s2n_config_enable_quic as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_connection_are_session_tickets_enabled () {
    let ptr = crate::s2n_connection_are_session_tickets_enabled as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_connection_enable_quic () {
    let ptr = crate::s2n_connection_enable_quic as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_connection_get_quic_transport_parameters () {
    let ptr = crate::s2n_connection_get_quic_transport_parameters as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_connection_is_quic_enabled () {
    let ptr = crate::s2n_connection_is_quic_enabled as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_connection_set_quic_transport_parameters () {
    let ptr = crate::s2n_connection_set_quic_transport_parameters as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_connection_set_secret_callback () {
    let ptr = crate::s2n_connection_set_secret_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_error_get_alert () {
    let ptr = crate::s2n_error_get_alert as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "quic")]
fn s2n_recv_quic_post_handshake_message () {
    let ptr = crate::s2n_recv_quic_post_handshake_message as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-cert_authorities")]
fn s2n_certificate_authority_list_has_next () {
    let ptr = crate::s2n_certificate_authority_list_has_next as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-cert_authorities")]
fn s2n_certificate_authority_list_next () {
    let ptr = crate::s2n_certificate_authority_list_next as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-cert_authorities")]
fn s2n_certificate_authority_list_reread () {
    let ptr = crate::s2n_certificate_authority_list_reread as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-cert_authorities")]
fn s2n_certificate_request_get_ca_list () {
    let ptr = crate::s2n_certificate_request_get_ca_list as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-cert_authorities")]
fn s2n_certificate_request_set_certificate () {
    let ptr = crate::s2n_certificate_request_set_certificate as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-cert_authorities")]
fn s2n_config_set_cert_request_callback () {
    let ptr = crate::s2n_config_set_cert_request_callback as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-cleanup")]
fn s2n_cleanup_thread () {
    let ptr = crate::s2n_cleanup_thread as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_cert_validation_accept () {
    let ptr = crate::s2n_cert_validation_accept as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_cert_validation_reject () {
    let ptr = crate::s2n_cert_validation_reject as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_config_set_cert_validation_cb () {
    let ptr = crate::s2n_config_set_cert_validation_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_config_set_crl_lookup_cb () {
    let ptr = crate::s2n_config_set_crl_lookup_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_free () {
    let ptr = crate::s2n_crl_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_get_issuer_hash () {
    let ptr = crate::s2n_crl_get_issuer_hash as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_load_pem () {
    let ptr = crate::s2n_crl_load_pem as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_lookup_get_cert_issuer_hash () {
    let ptr = crate::s2n_crl_lookup_get_cert_issuer_hash as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_lookup_ignore () {
    let ptr = crate::s2n_crl_lookup_ignore as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_lookup_set () {
    let ptr = crate::s2n_crl_lookup_set as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_new () {
    let ptr = crate::s2n_crl_new as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_validate_active () {
    let ptr = crate::s2n_crl_validate_active as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-crl")]
fn s2n_crl_validate_not_expired () {
    let ptr = crate::s2n_crl_validate_not_expired as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-custom_x509_extensions")]
fn s2n_config_add_custom_x509_extension () {
    let ptr = crate::s2n_config_add_custom_x509_extension as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_client_hello_get_fingerprint_hash () {
    let ptr = crate::s2n_client_hello_get_fingerprint_hash as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_client_hello_get_fingerprint_string () {
    let ptr = crate::s2n_client_hello_get_fingerprint_string as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_free () {
    let ptr = crate::s2n_fingerprint_free as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_get_hash () {
    let ptr = crate::s2n_fingerprint_get_hash as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_get_hash_size () {
    let ptr = crate::s2n_fingerprint_get_hash_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_get_raw () {
    let ptr = crate::s2n_fingerprint_get_raw as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_get_raw_size () {
    let ptr = crate::s2n_fingerprint_get_raw_size as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_new () {
    let ptr = crate::s2n_fingerprint_new as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_set_client_hello () {
    let ptr = crate::s2n_fingerprint_set_client_hello as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-fingerprint")]
fn s2n_fingerprint_wipe () {
    let ptr = crate::s2n_fingerprint_wipe as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-ktls")]
fn s2n_config_ktls_enable_unsafe_tls13 () {
    let ptr = crate::s2n_config_ktls_enable_unsafe_tls13 as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-ktls")]
fn s2n_connection_get_key_update_counts () {
    let ptr = crate::s2n_connection_get_key_update_counts as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-ktls")]
fn s2n_connection_ktls_enable_recv () {
    let ptr = crate::s2n_connection_ktls_enable_recv as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-ktls")]
fn s2n_connection_ktls_enable_send () {
    let ptr = crate::s2n_connection_ktls_enable_send as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-ktls")]
fn s2n_sendfile () {
    let ptr = crate::s2n_sendfile as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-npn")]
fn s2n_config_set_npn () {
    let ptr = crate::s2n_config_set_npn as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-renegotiate")]
fn s2n_config_set_renegotiate_request_cb () {
    let ptr = crate::s2n_config_set_renegotiate_request_cb as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-renegotiate")]
fn s2n_renegotiate () {
    let ptr = crate::s2n_renegotiate as *const ();
    assert!(!ptr.is_null());
}

#[test]
#[cfg(feature = "unstable-renegotiate")]
fn s2n_renegotiate_wipe () {
    let ptr = crate::s2n_renegotiate_wipe as *const ();
    assert!(!ptr.is_null());
}

