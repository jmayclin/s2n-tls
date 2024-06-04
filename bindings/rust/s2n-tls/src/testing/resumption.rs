// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::{
        callbacks::{SessionTicket, SessionTicketCallback},
        config::ConnectionInitializer,
        connection::{self, Connection},
        testing::{s2n_tls::*, *},
    };
    use futures_test::task::noop_waker;
    use std::{error::Error, sync::Mutex, time::{Duration, SystemTime}};


    #[derive(Default, Clone)]
    pub struct SessionTicketHandler {
        expected_lifetime_seconds: u32,
        stored_ticket: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl SessionTicketHandler {
        /// the session ticket handler will assert that received session tickets have
        /// the correct lifetime
        fn new(expected_lifetime_seconds: u32) -> Self {
            SessionTicketHandler {
                expected_lifetime_seconds,
                stored_ticket: Default::default(),
            }
        }
    }

    // Implement the session ticket callback that stores the SessionTicket type
    impl SessionTicketCallback for SessionTicketHandler {
        fn on_session_ticket(
            &self,
            _connection: &mut connection::Connection,
            session_ticket: &SessionTicket,
        ) { 
            let size = session_ticket.len().unwrap();
            let mut data = vec![0; size];
            let lifetime = session_ticket.lifetime().unwrap();
            println!("session ticket lifetime is {:?}", lifetime);
            assert_eq!(lifetime.as_secs(), self.expected_lifetime_seconds as u64);
            session_ticket.data(&mut data).unwrap();
            let mut ptr = (*self.stored_ticket).lock().unwrap();
            if ptr.is_none() {
                *ptr = Some(data);
            }
        }
    }

    // Create test ticket key
    const KEY: [u8; 16] = [0; 16];
    const KEYNAME: [u8; 3] = [1, 3, 4];

    fn validate_session_ticket(conn: &Connection) -> Result<(), Box<dyn Error>> {
        assert!(conn.session_ticket_length()? > 0);
        let mut session = vec![0; conn.session_ticket_length()?];
        //load the ticket and make sure session is no longer empty
        assert_eq!(
            conn.session_ticket(&mut session)?,
            conn.session_ticket_length()?
        );
        assert_ne!(session, vec![0; conn.session_ticket_length()?]);
        Ok(())
    }

    // correct, yay!
    #[test]
    fn short_lifetime() -> Result<(), Box<dyn Error>> {
        let keypair = CertKeyPair::default();

        const ENCRYPT_LIFETIME: Duration = Duration::from_secs(3_600);
        const DECRYPT_LIFETIME: Duration = Duration::from_secs(3_600);

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
            .set_ticket_key_encrypt_decrypt_lifetime(ENCRYPT_LIFETIME)?
            .set_ticket_key_decrypt_lifetime(DECRYPT_LIFETIME)?
            .load_pem(keypair.cert(), keypair.key())?;
        let server_config = server_config_builder.build()?;

        // create config for client
        let mut client_config_builder = Builder::new();

        let session_ticket_handler = SessionTicketHandler::new(3_600 * 2);
        client_config_builder
            .enable_session_tickets(true)?
            .set_session_ticket_callback(session_ticket_handler)?
            .trust_pem(keypair.cert())?
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        let client_config = client_config_builder.build()?;

        // create and configure a server connection
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config.clone())?;

        // create a client connection
        let mut client = connection::Connection::new_client();
        client.set_config(client_config)?;

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check connection was full handshake and a session ticket was included
        assert!(!client.resumed());
        assert!(client.session_ticket_length()? > 0);

        Ok(())
    }

    #[test]
    fn long_lifetime() -> Result<(), Box<dyn Error>> {
        let keypair = CertKeyPair::default();

        const ENCRYPT_LIFETIME: Duration = Duration::from_secs(3_600 * 24);
        const DECRYPT_LIFETIME: Duration = Duration::from_secs(3_600 * 24);

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
            .set_ticket_key_encrypt_decrypt_lifetime(ENCRYPT_LIFETIME)?
            .set_ticket_key_decrypt_lifetime(DECRYPT_LIFETIME)?
            .load_pem(keypair.cert(), keypair.key())?;
        let server_config = server_config_builder.build()?;

        // create config for client
        let mut client_config_builder = Builder::new();

        let session_ticket_handler = SessionTicketHandler::new(3_600 * 48);
        client_config_builder
            .enable_session_tickets(true)?
            .set_session_ticket_callback(session_ticket_handler)?
            .trust_pem(keypair.cert())?
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        let client_config = client_config_builder.build()?;

        // create and configure a server connection
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config.clone())?;

        // create a client connection
        let mut client = connection::Connection::new_client();
        client.set_config(client_config)?;

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check connection was full handshake and a session ticket was included
        assert!(!client.resumed());
        assert!(client.session_ticket_length()? > 0);

        Ok(())
    }

    // #[test]
    // fn resume_tls13_session() -> Result<(), Box<dyn Error>> {
    //     let keypair = CertKeyPair::default();

    //     // Initialize config for server with a ticket key
    //     let mut server_config_builder = Builder::new();
    //     server_config_builder
    //         .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
    //         .load_pem(keypair.cert(), keypair.key())?
    //         .set_security_policy(&security::DEFAULT_TLS13)?;
    //     let server_config = server_config_builder.build()?;

    //     let handler = SessionTicketHandler::default();

    //     // create config for client
    //     let mut client_config_builder = Builder::new();
    //     client_config_builder
    //         .enable_session_tickets(true)?
    //         .set_session_ticket_callback(handler.clone())?
    //         .set_connection_initializer(handler)?
    //         .trust_pem(keypair.cert())?
    //         .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
    //         .set_security_policy(&security::DEFAULT_TLS13)?;
    //     let client_config = client_config_builder.build()?;

    //     // create and configure a server connection
    //     let mut server = connection::Connection::new_server();
    //     server
    //         .set_config(server_config.clone())
    //         .expect("Failed to bind config to server connection");

    //     // create a client connection
    //     let mut client = connection::Connection::new_client();
    //     client
    //         .set_waker(Some(&noop_waker()))?
    //         .set_config(client_config.clone())
    //         .expect("Unable to set client config");

    //     let server = Harness::new(server);
    //     let client = Harness::new(client);
    //     let pair = Pair::new(server, client);
    //     let mut pair = poll_tls_pair(pair);

    //     // Do a recv call on the client side to read a session ticket. Poll function
    //     // returns pending since no application data was read, however it is enough
    //     // to collect the session ticket.
    //     assert!(pair.poll_recv(Mode::Client, &mut [0]).is_pending());

    //     let client = pair.client.0.connection();
    //     // Check connection was full handshake
    //     assert!(!client.resumed());
    //     // validate that a ticket is available
    //     validate_session_ticket(client)?;

    //     // create and configure a client/server connection again
    //     let mut server = connection::Connection::new_server();
    //     server
    //         .set_config(server_config)
    //         .expect("Failed to bind config to server connection");

    //     // create a client connection with a resumption ticket
    //     let mut client = connection::Connection::new_client();
    //     client
    //         .set_waker(Some(&noop_waker()))?
    //         .set_config(client_config)
    //         .expect("Unable to set client config");

    //     let server = Harness::new(server);
    //     let client = Harness::new(client);
    //     let pair = Pair::new(server, client);
    //     let mut pair = poll_tls_pair(pair);

    //     // Do a recv call on the client side to read a session ticket. Poll function
    //     // returns pending since no application data was read, however it is enough
    //     // to collect the session ticket.
    //     assert!(pair.poll_recv(Mode::Client, &mut [0]).is_pending());

    //     let client = pair.client.0.connection();
    //     // Check new connection was resumed
    //     assert!(client.resumed());
    //     // validate that a ticket is available
    //     validate_session_ticket(client)?;
    //     Ok(())
    // }
}
