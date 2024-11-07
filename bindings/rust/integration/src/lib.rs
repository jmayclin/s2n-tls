use s2n_tls::enums::{HashAlgorithm, SignatureAlgorithm, Version};

struct TlsMetrics {
    protocol: Version,
    cipher: String,
    kem_name: Option<String>,
    kem_group: Option<String>,
    selected_signature: SignatureAlgorithm,
    selected_hash: HashAlgorithm,
    selected_curve: String,
    handshake_type: String,

    /// true if the connection was resumed using session tickets or session id
    is_resumed: bool,
}

fn owned_str_option(maybe: Option<&str>) -> Option<String> {

    match maybe {
        Some(s) => Some(s.to_owned()),
        _ => None,
    }
}

impl TlsMetrics {
    fn from_connection(
        conn: &s2n_tls::connection::Connection,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let protocol = conn.actual_protocol_version()?;
        let cipher = conn.cipher_suite()?;
        let kem_name = conn.kem_name()?;
        let kem_group = conn.kem_group_name()?;
        let selected_signature = conn.selected_signature_algorithm()?;
        let selected_hash = conn.selected_hash_algorithm()?;
        let selected_curve = conn.selected_curve()?;
        let something = conn.handshake_type()?;

        let is_resumed = conn.resumed();

        Ok(TlsMetrics {
            protocol,
            cipher: cipher.into(),
            kem_name: owned_str_option(kem_name),
            kem_group: owned_str_option(kem_group),
            selected_signature,
            selected_hash,
            selected_curve: selected_curve.into(),
            handshake_type: something.into(),
            is_resumed,
        })
    }
}
