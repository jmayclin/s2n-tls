use duchess::java;

duchess::java_package! {
    package javax.net.ssl;

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
        // public abstract java.lang.Runnable getDelegatedTask();
        // public abstract void closeInbound() throws javax.net.ssl.SSLException;
        // public abstract boolean isInboundDone();
        // public abstract void closeOutbound();
        // public abstract boolean isOutboundDone();
        // public abstract java.lang.String[] getSupportedCipherSuites();
        public abstract java.lang.String[] getEnabledCipherSuites();
        // public abstract void setEnabledCipherSuites(java.lang.String[]);
        // public abstract java.lang.String[] getSupportedProtocols();
        // public abstract java.lang.String[] getEnabledProtocols();
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
        // public javax.net.ssl.SSLParameters getSSLParameters();
        // public void setSSLParameters(javax.net.ssl.SSLParameters);
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


#[cfg(test)]
mod test {
    use crate::get_cert_path;
    use duchess::{
        java::{
            self, io::FileInputStream, nio::ByteBuffer, security::{cert::CertificateFactory, KeyStore, SecureRandom}
        },
        Global, IntoRust, Jvm, JvmOp, Local, NullJRef, ToJava,
    };

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
    fn create_cert_factory() {
        let certificate = Jvm::with(|jvm| {
            let path = get_cert_path(crate::PemType::CACert, crate::SigType::Rsa2048);
            let filestream = FileInputStream::new(&path);
            let factory = CertificateFactory::get_instance("X.509");
            let certificate = factory.generate_certificate(filestream);
            certificate.global().execute_with(jvm)
        })
        .unwrap()
        .unwrap();
    }

    #[test]
    fn get_keystore_instance() {
        let key_store = Jvm::with(|jvm| {
            KeyStore::get_instance(KeyStore::get_default_type())
                .global()
                .execute_with(jvm)
        })
        .unwrap();
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
    fn create_tmf() {
        let ssl_config = Jvm::with(|jvm| {
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
            //keystore.set_certificate("ca-certificate", certificate);
            let factory =
                TrustManagerFactory::get_instance(TrustManagerFactory::get_default_algorithm())
                    .execute_with(jvm)
                    .unwrap()
                    .unwrap();
            factory.init(&keystore).execute_with(jvm).unwrap();

            let null_key_manager: Option<Local<java::Array<KeyManager>>> = None;
            let null_secure_random: Option<Local<java::security::SecureRandom>> = None;
            let context = SSLContext::get_instance("TLSv1.3")
                .global()
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
            Ok(context)
        })
        .unwrap();
    }

    fn java_2_rust(src: Global<ByteBuffer>) -> Vec<u8> {
        // slice should cause this to be right sized
        let mut i8 = src.array().to_rust().execute().unwrap().unwrap();
        let position = src.position().execute().unwrap();
        i8.resize(position as usize, 0);
        // yes, this should be a slice
        let mut v = std::mem::ManuallyDrop::new(i8);
        let ptr = v.as_mut_ptr();
        let length = v.len();
        let capacity = v.capacity();
        unsafe { Vec::from_raw_parts(ptr as *mut u8, length, capacity)}
    }

    fn rust_2_java(src: Vec<u8>) -> Global<ByteBuffer> {
        Jvm::with(|jvm| {
            let byte_array = src.to_java().execute_with(jvm).unwrap().unwrap();
            ByteBuffer::wrap(&byte_array).global().execute_with(jvm)
        }).unwrap().unwrap()
    }

    #[test]
    fn ssl_engine() {
        let (engine, plaintext, ciphertext) = Jvm::with(|jvm| {
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
            //keystore.set_certificate("ca-certificate", certificate);
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
            
            let engine = context.create_ssl_engine().global().execute_with(jvm)?.unwrap();
            engine.set_use_client_mode(true).execute_with(jvm)?;
            //let supported = engine.get_enabled_cipher_suites().execute_with(jvm)?.unwrap();
            //let supported = &supported.to_rust();
            //println!("engine ciphers: {:?}", );
            // data the the engine will read in goes here
            let plaintext = ByteBuffer::allocate(1024 * 100).global().execute_with(jvm)?.unwrap();
            let ciphertext = ByteBuffer::allocate(1024 * 100).global().execute_with(jvm)?.unwrap();
            let result = engine.wrap(&plaintext, &ciphertext).execute_with(jvm)?.unwrap();
            println!("handshake result: {:?}", &result.to_string().to_rust().execute_with(jvm));
            Ok((engine, plaintext, ciphertext))
        }).unwrap();

        let bytes = java_2_rust(ciphertext);
        assert_eq!(bytes.len(), 0);


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
