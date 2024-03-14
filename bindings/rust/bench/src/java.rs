use std::io::{Read, Write};

use duchess::{java, Global, Jvm};

use crate::{
    get_cert_path,
    harness::TlsBenchConfig,
    java::javax::net::ssl::{KeyManager, SSLContext, TrustManagerFactory},
    CipherSuite, ConnectedBuffer, Mode, SigType, TlsConnection,
};

use self::javax::net::ssl::{SSLEngine, SSLEngineResult, SSLParameters};

use duchess::{
    java::{
        io::FileInputStream,
        nio::ByteBuffer,
        security::{cert::CertificateFactory, KeyStore, SecureRandom},
    },
    JvmOp, Local, NullJRef, ToJava,
};

duchess::java_package! {
    package javax.net.ssl;

    class SSLParameters {
        public javax.net.ssl.SSLParameters();
        // public javax.net.ssl.SSLParameters(java.lang.String[]);
        // public javax.net.ssl.SSLParameters(java.lang.String[], java.lang.String[]);
        // public java.lang.String[] getCipherSuites();
        public void setCipherSuites(java.lang.String[]);
        // public java.lang.String[] getProtocols();
        // public void setProtocols(java.lang.String[]);
        // public boolean getWantClientAuth();
        // public void setWantClientAuth(boolean);
        // public boolean getNeedClientAuth();
        // public void setNeedClientAuth(boolean);
        // public java.security.AlgorithmConstraints getAlgorithmConstraints();
        // public void setAlgorithmConstraints(java.security.AlgorithmConstraints);
        // public java.lang.String getEndpointIdentificationAlgorithm();
        // public void setEndpointIdentificationAlgorithm(java.lang.String);
        // public final void setServerNames(java.util.List<javax.net.ssl.SNIServerName>);
        // public final java.util.List<javax.net.ssl.SNIServerName> getServerNames();
        // public final void setSNIMatchers(java.util.Collection<javax.net.ssl.SNIMatcher>);
        // public final java.util.Collection<javax.net.ssl.SNIMatcher> getSNIMatchers();
        // public final void setUseCipherSuitesOrder(boolean);
        // public final boolean getUseCipherSuitesOrder();
        // public void setEnableRetransmissions(boolean);
        // public boolean getEnableRetransmissions();
        // public void setMaximumPacketSize(int);
        // public int getMaximumPacketSize();
        // public java.lang.String[] getApplicationProtocols();
        // public void setApplicationProtocols(java.lang.String[]);
        // public java.lang.String[] getSignatureSchemes();
        public void setSignatureSchemes(java.lang.String[]);
        // public java.lang.String[] getNamedGroups();
        public void setNamedGroups(java.lang.String[]);
    }

    class SSLEngineResult {
        public java.lang.String toString();
    }

    class SSLEngine {
        // protected javax.net.ssl.SSLEngine();
        // protected javax.net.ssl.SSLEngine(java.lang.String, int);
        // public java.lang.String getPeerHost();
        // public int getPeerPort();
        public javax.net.ssl.SSLEngineResult wrap(java.nio.ByteBuffer, java.nio.ByteBuffer) throws javax.net.ssl.SSLException;
        // public javax.net.ssl.SSLEngineResult wrap(java.nio.ByteBuffer[], java.nio.ByteBuffer) throws javax.net.ssl.SSLException;
        // public abstract javax.net.ssl.SSLEngineResult wrap(java.nio.ByteBuffer[], int, int, java.nio.ByteBuffer) throws javax.net.ssl.SSLException;
        public javax.net.ssl.SSLEngineResult unwrap(java.nio.ByteBuffer, java.nio.ByteBuffer) throws javax.net.ssl.SSLException;
        // public javax.net.ssl.SSLEngineResult unwrap(java.nio.ByteBuffer, java.nio.ByteBuffer[]) throws javax.net.ssl.SSLException;
        // public abstract javax.net.ssl.SSLEngineResult unwrap(java.nio.ByteBuffer, java.nio.ByteBuffer[], int, int) throws javax.net.ssl.SSLException;
        public abstract java.lang.Runnable getDelegatedTask();
        // public abstract void closeInbound() throws javax.net.ssl.SSLException;
        // public abstract boolean isInboundDone();
        // public abstract void closeOutbound();
        // public abstract boolean isOutboundDone();
        // public abstract java.lang.String[] getSupportedCipherSuites();
        public abstract java.lang.String[] getEnabledCipherSuites();
        // public abstract void setEnabledCipherSuites(java.lang.String[]);
        // public abstract java.lang.String[] getSupportedProtocols();
        public abstract java.lang.String[] getEnabledProtocols();
        // public abstract void setEnabledProtocols(java.lang.String[]);
        // public abstract javax.net.ssl.SSLSession getSession();
        // public javax.net.ssl.SSLSession getHandshakeSession();
        // public abstract void beginHandshake() throws javax.net.ssl.SSLException;
        // public abstract javax.net.ssl.SSLEngineResult$HandshakeStatus getHandshakeStatus();
        public abstract void setUseClientMode(boolean);
        // public abstract boolean getUseClientMode();
        // public abstract void setNeedClientAuth(boolean);
        // public abstract boolean getNeedClientAuth();
        // public abstract void setWantClientAuth(boolean);
        // public abstract boolean getWantClientAuth();
        // public abstract void setEnableSessionCreation(boolean);
        // public abstract boolean getEnableSessionCreation();
        public javax.net.ssl.SSLParameters getSSLParameters();
        public void setSSLParameters(javax.net.ssl.SSLParameters);
        // public java.lang.String getApplicationProtocol();
        // public java.lang.String getHandshakeApplicationProtocol();
        // public void setHandshakeApplicationProtocolSelector(java.util.function.BiFunction<javax.net.ssl.SSLEngine, java.util.List<java.lang.String>, java.lang.String>);
        // public java.util.function.BiFunction<javax.net.ssl.SSLEngine, java.util.List<java.lang.String>, java.lang.String> getHandshakeApplicationProtocolSelector();
    }

    class javax.net.ssl.SSLContext {
        //protected javax.net.ssl.SSLContext(javax.net.ssl.SSLContextSpi, java.security.Provider, java.lang.String);
        //public static javax.net.ssl.SSLContext getDefault() throws java.security.NoSuchAlgorithmException;
        //public static void setDefault(javax.net.ssl.SSLContext);
        public static javax.net.ssl.SSLContext getInstance(java.lang.String) throws java.security.NoSuchAlgorithmException;
        //public static javax.net.ssl.SSLContext getInstance(java.lang.String, java.lang.String) throws java.security.NoSuchAlgorithmException, java.security.NoSuchProviderException;
        //public static javax.net.ssl.SSLContext getInstance(java.lang.String, java.security.Provider) throws java.security.NoSuchAlgorithmException;
        //public final java.lang.String getProtocol();
        //public final java.security.Provider getProvider();
        public final void init(javax.net.ssl.KeyManager[], javax.net.ssl.TrustManager[], java.security.SecureRandom) throws java.security.KeyManagementException;
        //public final javax.net.ssl.SSLSocketFactory getSocketFactory();
        //public final javax.net.ssl.SSLServerSocketFactory getServerSocketFactory();
        public final javax.net.ssl.SSLEngine createSSLEngine();
        //public final javax.net.ssl.SSLEngine createSSLEngine(java.lang.String, int);
        //public final javax.net.ssl.SSLSessionContext getServerSessionContext();
        //public final javax.net.ssl.SSLSessionContext getClientSessionContext();
        //public final javax.net.ssl.SSLParameters getDefaultSSLParameters();
        //public final javax.net.ssl.SSLParameters getSupportedSSLParameters();
        //static {};
    }

    class TrustManagerFactory {
        public static final java.lang.String getDefaultAlgorithm();
        // protected javax.net.ssl.TrustManagerFactory(javax.net.ssl.TrustManagerFactorySpi, java.security.Provider, java.lang.String);
        // public final java.lang.String getAlgorithm();
        public static final javax.net.ssl.TrustManagerFactory getInstance(java.lang.String) throws java.security.NoSuchAlgorithmException;
        // public static final javax.net.ssl.TrustManagerFactory getInstance(java.lang.String, java.lang.String) throws java.security.NoSuchAlgorithmException, java.security.NoSuchProviderException;
        // public static final javax.net.ssl.TrustManagerFactory getInstance(java.lang.String, java.security.Provider) throws java.security.NoSuchAlgorithmException;
        // public final java.security.Provider getProvider();
        public final void init(java.security.KeyStore) throws java.security.KeyStoreException;
        // public final void init(javax.net.ssl.ManagerFactoryParameters) throws java.security.InvalidAlgorithmParameterException;
        public final javax.net.ssl.TrustManager[] getTrustManagers();
    }

    class TrustManager { }

    class KeyManager { }


}

pub struct JavaConfig {
    context: Global<SSLContext>,
    ssl_params: Global<SSLParameters>,
    mode: crate::Mode,
}

impl JavaConfig {
    /// given the path to a CA cert, return a trust manager with that CA-cert added
    /// to the trust store. We return a `Global` rather than a `Local<'_, >` because
    /// otherwise the compiler complains about two mutable borrows of the Jvm.
    fn trust_manager_factory<'jvm>(
        filepath: &str,
        jvm: &'jvm mut Jvm,
    ) -> Global<TrustManagerFactory> {
        // load the
        let filestream = FileInputStream::new(filepath);
        let factory = CertificateFactory::get_instance("X.509");
        let certificate = factory.generate_certificate(filestream);

        let keystore = KeyStore::get_instance(KeyStore::get_default_type())
            .execute_with(jvm)
            .unwrap()
            .unwrap();

        let null_input_stream: Option<Local<FileInputStream>> = None;
        let null_char_array: Option<Local<java::Array<u16>>> = None;

        // we pass in null parameters since we don't want to load any of the
        // system certs
        keystore
            .load(&null_input_stream, &null_char_array)
            .execute_with(jvm)
            .unwrap();
        keystore
            .set_certificate_entry("ca-certificate", certificate)
            .execute_with(jvm)
            .unwrap();
        let factory =
            TrustManagerFactory::get_instance(TrustManagerFactory::get_default_algorithm())
                .global()
                .execute_with(jvm)
                .unwrap()
                .unwrap();
        factory.init(&keystore).execute_with(jvm).unwrap();
        factory
    }

    fn ssl_parameters(config: crate::CryptoConfig, jvm: &mut Jvm) -> Global<SSLParameters> {
        let ssl_parameters = SSLParameters::new().global().execute_with(jvm).unwrap();
        // set ciphers
        // https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#jsse-cipher-suite-names
        let java_cipher = match config.cipher_suite {
            CipherSuite::AES_128_GCM_SHA256 => vec!["TLS_AES_128_GCM_SHA256".to_owned()],
            CipherSuite::AES_256_GCM_SHA384 => vec!["TLS_AES_256_GCM_SHA384".to_owned()],
        }
        .to_owned();

        ssl_parameters
            .set_cipher_suites(java_cipher.to_java::<java::Array<java::lang::String>>())
            .execute_with(jvm)
            .unwrap();

        // set signatures
        // https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#signature-schemes
        let java_sig = match config.sig_type {
            SigType::Ecdsa256 => vec!["ecdsa_secp256r1_sha256".to_owned()],
            SigType::Ecdsa384 => vec!["ecdsa_secp384r1_sha384".to_owned()],
            _ => vec![
                "rsa_pkcs1_sha256".to_owned(),
                "rsa_pkcs1_sha384".to_owned(),
                "rsa_pss_rsae_sha256".to_owned(),
                "rsa_pss_rsae_sha384".to_owned(),
            ],
        };
        ssl_parameters
            .set_signature_schemes(java_sig.to_java::<java::Array<java::lang::String>>())
            .execute_with(jvm)
            .unwrap();

        // set groups
        // https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#named-groups
        let groups = match config.kx_group {
            crate::KXGroup::Secp256R1 => vec!["secp256r1".to_owned()],
            crate::KXGroup::X25519 => vec!["x25519".to_owned()],
        };
        ssl_parameters
            .set_named_groups(groups.to_java::<java::Array<java::lang::String>>())
            .execute_with(jvm)
            .unwrap();

        ssl_parameters
    }
}

impl TlsBenchConfig for JavaConfig {
    fn make_config(
        mode: crate::Mode,
        crypto_config: crate::CryptoConfig,
        handshake_type: crate::HandshakeType,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if handshake_type != crate::HandshakeType::ServerAuth {
            panic!("why did you do that");
        }
        let path = get_cert_path(crate::PemType::CACert, crypto_config.sig_type);
        let (context, ssl_params) = Jvm::with(|jvm| {
            let trust_manager_factory = Self::trust_manager_factory(&path, jvm);
            let context = SSLContext::get_instance("TLSv1.3")
                .global()
                .execute_with(jvm)
                .unwrap()
                .unwrap();

            let null_key_manager: Option<Local<java::Array<KeyManager>>> = None;
            let null_secure_random: Option<Local<java::security::SecureRandom>> = None;
            context
                .init(
                    &null_key_manager,
                    trust_manager_factory.get_trust_managers(),
                    &null_secure_random,
                )
                .execute_with(jvm)
                .unwrap();

            let ssl_params = JavaConfig::ssl_parameters(crypto_config, jvm);

            Ok((context, ssl_params))
        })
        .unwrap();

        Ok(JavaConfig {
            context,
            ssl_params,
            mode,
        })
    }
}

// For any operation which may potentially block, the SSLEngine will create a
// Runnable delegated task. When SSLEngineResult indicates that a delegated task
// result is needed, the application must call getDelegatedTask() to obtain an
// outstanding delegated task and call its run() method (possibly using a different
// thread depending on the compute strategy). The application should continue
// obtaining delegated tasks until no more exist, and try the original operation
// again.

pub struct JavaConnection {
    conn: Global<SSLEngine>,
    // this is a handle to the native buffers that the peer also has access to
    conected_buffer: ConnectedBuffer,
    // this is used to make reading in data more convenient due to the necessity
    // of the bytes buffers
    // I don't think I need the chunked buffer
    recv_buffer: ChunkedByteBuffer,
    send_buffer: Global<ByteBuffer>,
    //
    dummy_buffer: Global<ByteBuffer>,
    handshake_done: bool,
}

impl JavaConnection {
    fn poll_runnables(
        &mut self,
        result: &str,
        jvm: &mut Jvm,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if SSLEngineResult::status(&result) != HandshakeStatus::NeedTask {
            return Ok(());
        }
        loop {
            // use unwrap here because the exception has the JVM lifetime which
            // makes things complicated to manage
            let task = self.conn.get_delegated_task().execute_with(jvm).unwrap();
            match task {
                Some(t) => t.run().execute_with(jvm).unwrap(),
                None => return Ok(()),
            };
        }
    }
}

impl TlsConnection for JavaConnection {
    type Config = JavaConfig;

    fn name() -> String {
        todo!()
    }

    fn new_from_config(
        config: &Self::Config,
        connected_buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let Self::Config {
            context,
            ssl_params,
            mode,
        } = config;
        let engine = Jvm::with(|jvm| {
            let engine = context
                .create_ssl_engine()
                .global()
                .execute_with(jvm)?
                .unwrap();

            if mode == &Mode::Client {
                engine.set_use_client_mode(true).execute_with(jvm)?;
            }

            engine.set_ssl_parameters(ssl_params).execute_with(jvm)?;

            Ok(engine)
        })
        .unwrap();

        let (recv_buffer, send_buffer, dummy_buffer) = Jvm::with(|jvm| {
            let recv = ByteBuffer::allocate(0).global().execute_with(jvm)?.unwrap();
            let send = ByteBuffer::allocate(100_000)
                .global()
                .execute_with(jvm)?
                .unwrap();
            let dummy = ByteBuffer::allocate(100_000)
                .global()
                .execute_with(jvm)?
                .unwrap();
            Ok((recv, send, dummy))
        })
        .unwrap();

        let recv_buffer = ChunkedByteBuffer::new(recv_buffer);

        Ok(JavaConnection {
            conn: engine,
            conected_buffer: connected_buffer,
            recv_buffer,
            send_buffer,
            dummy_buffer,
            handshake_done: false,
        })
    }

    // think of this more like s2n_connection_negotiate, but with more method calls
    fn handshake(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // take all of the data that the endpoint has sent and add it to the recv_buffer
        let mut buffer = vec![0; 10_000];
        if let Ok(length) = self.conected_buffer.read(&mut buffer) {
            self.recv_buffer.add_chunk(buffer[0..length].to_owned());
            // write the server stuff into the stream
            println!("length of server hello: {}", length);
        }

        let mut previous_status = HandshakeStatus::NeedUnwrap;
        let mut current_status = HandshakeStatus::NeedUnwrap;
        let mut result = "".to_owned();
        // try and make progress over the records
        Jvm::with(|jvm| {
            loop {
                match current_status {
                    HandshakeStatus::NeedTask => {
                        println!("trying to drive");
                        loop {
                            // use unwrap here because the exception has the JVM lifetime which
                            // makes things complicated to manage
                            let task = self.conn.get_delegated_task().execute_with(jvm).unwrap();
                            match task {
                                Some(t) => t.run().execute_with(jvm).unwrap(),
                                None => break,
                            };
                        }
                        // retry the previous action
                        current_status = previous_status;
                    }
                    HandshakeStatus::NeedUnwrap => {
                        previous_status = HandshakeStatus::NeedUnwrap;

                        if self.recv_buffer.current_buffer_empty(jvm) {
                            println!("advancing chunk");
                            self.recv_buffer.advance_chunk(jvm);
                        }

                        result = self
                            .conn
                            .unwrap(self.recv_buffer.current_buffer(), &self.dummy_buffer)
                            .to_string()
                            .to_rust()
                            .execute_with(jvm)?
                            .unwrap();
                        println!("unwrap result: {}", result);
                        current_status = SSLEngineResult::status(&result);
                        if current_status == HandshakeStatus::NeedUnwrap && self.recv_buffer.exhausted(jvm) {
                            return Ok(());
                        }
                    }
                    HandshakeStatus::NeedWrap => {
                        previous_status = HandshakeStatus::NeedWrap;
                        result = self
                            .conn
                            .wrap(&self.dummy_buffer, &self.send_buffer)
                            .to_string()
                            .to_rust()
                            .execute_with(jvm)?
                            .unwrap();
                        println!("wrap result: {}", result);

                        current_status = SSLEngineResult::status(&result);
                        let send_payload = java_2_rust_jvm(&self.send_buffer, jvm);
                        self.conected_buffer.write_all(&send_payload).unwrap();
                        self.send_buffer.clear().execute_with(jvm).unwrap();
                    }
                    HandshakeStatus::Finished => {
                        self.handshake_done = true;
                        return Ok(());
                    }
                }
            }
            Ok(())
        })?;

        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        self.handshake_done
    }

    fn get_negotiated_cipher_suite(&self) -> crate::CipherSuite {
        todo!()
    }

    fn negotiated_tls13(&self) -> bool {
        todo!()
    }

    fn resumed_connection(&self) -> bool {
        todo!()
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        Jvm::with(|jvm| {
            let plaintext_to_send = rust_2_java(data, jvm);  
        })
        Ok(())
    }

    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }

    fn shrink_connection_buffers(&mut self) {
        todo!()
    }

    fn shrink_connected_buffer(&mut self) {
        todo!()
    }

    fn connected_buffer(&self) -> &ConnectedBuffer {
        todo!()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum HandshakeStatus {
    NeedTask,
    NeedUnwrap,
    NeedWrap,
    Finished,
}

impl SSLEngineResult {
    fn status(status: &str) -> HandshakeStatus {
        if status.contains("NEED_TASK") {
            HandshakeStatus::NeedTask
        } else if status.contains("NEED_UNWRAP") {
            HandshakeStatus::NeedUnwrap
        } else if status.contains("NEED_WRAP") {
            HandshakeStatus::NeedWrap
        } else if status.contains("FINISHED") {
            HandshakeStatus::Finished
        } else {
            panic!(
                "status: {} did not contains a recognized handshake status",
                status
            );
        }
    }
}

// pub trait IntoJava<T: JavaObject>: Copy {
//     type Output<'jvm>: AsJRef<T>;

//     fn into_java<'jvm>(self, jvm: &mut Jvm<'jvm>) -> crate::Result<'jvm, Self::Output<'jvm>>;
// }

// /// Possibly null reference to a Java object.
// pub trait AsJRef<U>: TryJDeref {
//     fn as_jref(&self) -> Nullable<&U>;
// }

// /// Marker type used to indicate an attempt to dereference a null java reference.
// /// See [`TryJDeref`][] trait.
// pub struct NullJRef;

// pub type Nullable<T> = Result<T, NullJRef>;

// impl<'jvm, T, U> AsJRef<U> for T
// where
//     T: TryJDeref,
//     T::Java: Upcast<U>,
//     U: JavaObject,
// {
//     fn as_jref(&self) -> Nullable<&U> {
//         let this = self.try_jderef()?;
//         Ok(unsafe { std::mem::transmute(this) })
//     }
// }

struct ChunkedByteBuffer {
    buffer: Global<ByteBuffer>,
    next_chunks: Vec<Vec<u8>>,
}

// we can't set the position of a ByteBuffer because of method override things :(
// so we can't really "put" things onto a byte buffer. Instead we store the chunks
impl ChunkedByteBuffer {
    fn new(buffer: Global<ByteBuffer>) -> Self {
        ChunkedByteBuffer {
            buffer,
            next_chunks: Vec::new(),
        }
    }

    fn exhausted(&self, jvm: &mut Jvm) -> bool {
        let result = self.next_chunks.is_empty() && !self.buffer.has_remaining().execute_with(jvm).unwrap();
        println!("buffer exhausted? :{:?}", result);
        result
    }

    fn current_buffer(&self) -> &Global<ByteBuffer> {
        &self.buffer
    }

    fn current_buffer_empty(&self, jvm: &mut Jvm) -> bool {
        println!(
            "remaining in byte buffer: {}",
            self.buffer.remaining().to_rust().execute_with(jvm).unwrap()
        );
        !self.buffer.has_remaining().execute_with(jvm).unwrap() && !self.next_chunks.is_empty()
    }

    fn advance_chunk(&mut self, jvm: &mut Jvm) {
        // if buffer is
        self.buffer = rust_2_java(&self.next_chunks.remove(0), jvm);
    }

    fn add_chunk(&mut self, chunk: Vec<u8>) {
        println!("added chunk of length {}", chunk.len());
        self.next_chunks.push(chunk);
    }
}

// eventually don't totally nuke the things.
fn java_2_rust_jvm(src: &Global<ByteBuffer>, jvm: &mut Jvm) -> Vec<u8> {
    // slice should cause this to be right sized
    let mut i8 = src.array().to_rust().execute_with(jvm).unwrap().unwrap();
    let position = src.position().execute_with(jvm).unwrap();
    i8.resize(position as usize, 0);
    // yes, this should be a slice
    let mut v = std::mem::ManuallyDrop::new(i8);
    let ptr = v.as_mut_ptr();
    let length = v.len();
    let capacity = v.capacity();
    unsafe { Vec::from_raw_parts(ptr as *mut u8, length, capacity) }
}

// eventually don't totally nuke the things.
fn java_2_rust(src: &Global<ByteBuffer>) -> Vec<u8> {
    // slice should cause this to be right sized
    let mut i8 = src.array().to_rust().execute().unwrap().unwrap();
    let position = src.position().execute().unwrap();
    i8.resize(position as usize, 0);
    // yes, this should be a slice
    let mut v = std::mem::ManuallyDrop::new(i8);
    let ptr = v.as_mut_ptr();
    let length = v.len();
    let capacity = v.capacity();
    unsafe { Vec::from_raw_parts(ptr as *mut u8, length, capacity) }
}

//       v position        v position
// [xxxxx1111111] -> [xxxxx11111111111111111111]
// keeps position the same, but adds to back of buffer
fn rust_2_java(src: &[u8], jvm: &mut Jvm) -> Global<ByteBuffer> {
    // this is the current position of the buffer, we need to reset here
    let src = src.to_owned();
    let byte_array = src.to_java();
    let byte_buffer = ByteBuffer::wrap(byte_array)
        .global()
        .execute_with(jvm)
        .unwrap()
        .unwrap();
    byte_buffer
}

fn create_ssl_engine() -> Global<SSLEngine> {
    Jvm::with(|jvm| {
        let path = get_cert_path(crate::PemType::CACert, crate::SigType::Rsa2048);
        let filestream = FileInputStream::new(&path);
        let factory = CertificateFactory::get_instance("X.509");

        let certificate = factory.generate_certificate(filestream);
        println!(
            "keystore default type: {:?}",
            KeyStore::get_default_type().to_rust().execute_with(jvm)
        );
        let keystore = KeyStore::get_instance(KeyStore::get_default_type())
            .execute_with(jvm)
            .unwrap()
            .unwrap();
        //println!("debug keystore: {:?}", keystore.as_ref().err());
        let null_input_stream: Option<Local<FileInputStream>> = None;
        let null_char_array: Option<Local<java::Array<u16>>> = None;
        // can't use default execute otherwise it will nest things
        keystore
            .load(&null_input_stream, &null_char_array)
            .execute_with(jvm)
            .unwrap();
        keystore
            .set_certificate_entry("ca-certificate", certificate)
            .execute_with(jvm)
            .unwrap();
        let factory =
            TrustManagerFactory::get_instance(TrustManagerFactory::get_default_algorithm())
                .execute_with(jvm)
                .unwrap()
                .unwrap();
        factory.init(&keystore).execute_with(jvm).unwrap();

        let null_key_manager: Option<Local<java::Array<KeyManager>>> = None;
        let null_secure_random: Option<Local<java::security::SecureRandom>> = None;
        // I'm assuming that the impl doesn't cache the value that it yields, and I need to directly instantiate it
        // here?
        let context = SSLContext::get_instance("TLSv1.3")
            .execute_with(jvm)
            .unwrap()
            .unwrap();
        context
            .init(
                &null_key_manager,
                factory.get_trust_managers(),
                &null_secure_random,
            )
            .execute_with(jvm)
            .unwrap();

        let engine = context
            .create_ssl_engine()
            .global()
            .execute_with(jvm)?
            .unwrap();
        engine.set_use_client_mode(true).execute_with(jvm)?;
        Ok(engine)
    })
    .unwrap()
}
#[cfg(test)]
mod test {
    use std::io::{Read, Write};

    use duchess::IntoRust;

    use crate::harness::TlsBenchConfig;
    use crate::s2n_tls::S2NConfig;
    use crate::{
        CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup, Mode, S2NConnection,
        SigType, TlsConnection,
    };

    use super::*;

    // this feels forbidden
    use super::javax::net::ssl::{KeyManager, SSLContext, TrustManager, TrustManagerFactory};

    #[test]
    fn create_ssl_context() {
        let tls_string = "TLSv1.3".to_owned();
        let ssl_context = SSLContext::get_instance(tls_string.to_java::<java::lang::String>())
            .global()
            .execute()
            // what are the possible errors here? Presumable the exceptions?
            .unwrap()
            // why is this an option? That doesn't make sense to me. If it's
            // successful then should this always be populated?
            .unwrap();
    }

    #[test]
    fn create_secure_random() {
        const TEST_ARRAY_LENGTH: usize = 256;
        //let secure_random = SecureRandom::new().global().execute().unwrap();
        let initial_array: Vec<i8> = vec![0; TEST_ARRAY_LENGTH];
        let random_array = Jvm::with(|jvm| {
            // create the java SecureRandom instance
            let secure_random = SecureRandom::new().execute_with(jvm).unwrap();
            // java copy of the initial_array
            let java_array = initial_array.to_java().execute_with(jvm)?.unwrap();
            secure_random
                .next_bytes(&java_array)
                .execute_with(jvm)
                .unwrap();
            java_array.into_rust(jvm)
        })
        .unwrap();
        // the initial array did not have it's memory modified
        assert_eq!(initial_array, vec![0; TEST_ARRAY_LENGTH]);
        // we have a copy of the random java array
        assert_ne!(random_array, vec![0; TEST_ARRAY_LENGTH]);
    }

    #[test]
    fn null_initialized_context() {
        let null_key_managers: Option<Global<java::Array<KeyManager>>> = None;
        let null_trust_managers: Option<Global<java::Array<TrustManager>>> = None;
        let null_secure_random: Option<Global<java::security::SecureRandom>> = None;
        let context = SSLContext::get_instance("TLSv1.3")
            .global()
            .execute()
            .unwrap()
            .unwrap();
        context
            .init(
                &null_key_managers,
                &null_trust_managers,
                &null_secure_random,
            )
            .execute()
            .unwrap();
    }

    #[test]
    fn create_ssl_engine_test() {
        let engine = super::create_ssl_engine();
    }

    #[test]
    fn ssl_params_test() {
        let crypto_config = CryptoConfig::default();
        Jvm::with(|jvm| {
            JavaConfig::ssl_parameters(crypto_config, jvm);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn ssl_engine_handshake() {
        Jvm::builder()
            .custom("-Djavax.net.debug=ssl")
            .try_launch()
            .unwrap();
        let engine = super::create_ssl_engine();
        let (recv, send) = Jvm::with(|jvm| {
            let recv = ByteBuffer::allocate(0).global().execute_with(jvm)?.unwrap();
            recv.flip().execute_with(jvm).unwrap();
            // wrap dst (ciphertext sent to serer)
            let send = ByteBuffer::allocate(1024 * 100)
                .global()
                .execute_with(jvm)?
                .unwrap();
            Ok((recv, send))
        })
        .unwrap();

        let mut recv = ChunkedByteBuffer::new(recv);

        // the java client is set up to use the
        let crypto_config =
            CryptoConfig::new(CipherSuite::default(), KXGroup::default(), SigType::Rsa2048);

        let server_config =
            S2NConfig::make_config(Mode::Server, crypto_config, HandshakeType::ServerAuth).unwrap();

        let server_buffer = ConnectedBuffer::default();
        let mut client_buffer = server_buffer.clone_inverse();

        let mut server = S2NConnection::new_from_config(&server_config, server_buffer).unwrap();

        // handshake
        {
            // used to ferry information between the TCP stream and the connected buffer
            // we can't directly read to the copied buffer because it's a vecdequeue
            // (or maybe we can, but for now this is easiest)
            let mut buffer = vec![0; 1_000_000];
            let mut count = 40;
            while count > 0 {
                count -= 1;
                // if there is something to write to the client, write it to the byte buffer
                if let Ok(length) = client_buffer.read(&mut buffer) {
                    recv.add_chunk(buffer[0..length].to_owned());
                    // write the server stuff into the stream
                    println!("length of server hello: {}", length);
                }

                // try and make progress over the records
                Jvm::with(|jvm| {
                    loop {
                        // if there is no data availabile in the receive buffer,
                        // then no more progress can be made.
                        if recv.exhausted(jvm) {
                            break;
                        }

                        // we might have finished reading the current chunk, in
                        // which case we should pull in the next chunk
                        if recv.current_buffer_empty(jvm) {
                            println!("advancing chunk");
                            recv.advance_chunk(jvm);
                        }

                        let result = engine
                            .unwrap(recv.current_buffer(), &send)
                            .execute_with(jvm)?
                            .unwrap();

                        println!(
                            "handshake result after unwrap: {:?}",
                            &result.to_string().to_rust().execute_with(jvm)
                        );

                        let task = engine.get_delegated_task().execute_with(jvm).unwrap();
                        match task {
                            Some(r) => r.run().execute_with(jvm).unwrap(),
                            None => break,
                        };
                        //if let Some(r) = task {
                        //    r.run().execute_with(jvm)?;
                        //}
                    }

                    Ok(())
                })
                .unwrap();

                // maybe read in data, and drive client forward
                Jvm::with(|jvm| {
                    let task = engine.get_delegated_task().execute_with(jvm)?;
                    if let Some(r) = task {
                        r.run().execute_with(jvm)?;
                    }
                    send.clear().execute_with(jvm)?;
                    // plaintext is empty, ciphertext is empty
                    let result = engine
                        // nothing should be written
                        .wrap(recv.current_buffer(), &send)
                        .execute_with(jvm)?
                        .unwrap();
                    // plaintext is empty, ciphertext has data
                    println!(
                        "handshake result after wrap: {:?}",
                        &result.to_string().to_rust().execute_with(jvm)
                    );

                    Ok(())
                })
                .unwrap();

                println!("gonna read from stream");
                // if the client wrote something, give it to the server
                let client_ciphertext = java_2_rust(&send);
                println!("client ciphertext was {} bytes", client_ciphertext.len());
                if !client_ciphertext.is_empty() {
                    client_buffer.write_all(&client_ciphertext).unwrap();
                }

                server.handshake().unwrap();
            }
        }
        assert!(server.handshake_completed());
        assert!(false);
    }

    #[test]
    fn string_array_rt() {
        let strings = vec!["a".to_owned(), "".to_owned(), "hello".to_owned()];
        let java: Vec<String> = strings
            .to_java::<java::Array<java::lang::String>>()
            .to_rust()
            .execute()
            .unwrap()
            .unwrap();
        assert_eq!(strings, java);
    }
}

// CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

// FileInputStream is = new FileInputStream(certificatePath);

// X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
// is.close();

// KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
// caKeyStore.load(null, null);
// caKeyStore.setCertificateEntry("ca-certificate", cert);

// TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
//         TrustManagerFactory.getDefaultAlgorithm());
// trustManagerFactory.init(caKeyStore);

// SSLContext context = SSLContext.getInstance(protocol);
// context.init(null, trustManagerFactory.getTrustManagers(), null);
