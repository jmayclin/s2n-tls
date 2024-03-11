

duchess::java_package! {
    package javax.net.ssl;

    class SSLContext {
        public static javax.net.ssl.SSLContext getInstance(java.lang.String);
        public final void init(javax.net.ssl.KeyManager[], javax.net.ssl.TrustManager[], java.security.SecureRandom);
    }

    class TrustManagerFactory {
        public static final java.lang.String getDefaultAlgorithm();
        public static final javax.net.ssl.TrustManagerFactory getInstance(java.lang.String);
        public final javax.net.ssl.TrustManager[] getTrustManagers();
    }

    class TrustManager { }

    class KeyManager { }

    package javax.security.cert;

    class X509Certificate { }
}

#[cfg(test)]
mod test {
    use duchess::{
        java::{self, io::FileInputStream, security::{cert::CertificateFactory, KeyStore, SecureRandom}}, IntoRust, Jvm, JvmOp, Local, NullJRef, ToJava
    };
    use crate::get_cert_path;

    // this feels forbidden
    use super::javax::net::ssl::SSLContext;

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
            secure_random.next_bytes(&java_array).execute_with(jvm).unwrap();
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
            KeyStore::get_instance("X.509").global().execute_with(jvm)
        })
        .unwrap();
    }

    #[test]
    fn create_key_store() {
        let key_store = Jvm::with(|jvm| {
            let path = get_cert_path(crate::PemType::CACert, crate::SigType::Rsa2048);
            let filestream = FileInputStream::new(&path);
            let factory = CertificateFactory::get_instance("X.509");

            let certificate = factory.generate_certificate(filestream).execute_with(jvm).unwrap().unwrap();
            let keystore = KeyStore::get_instance("X.509").global().execute_with(jvm);
            println!("debug keystore: {:?}", keystore.as_ref().err());
            let null_input_stream: Option<Local<FileInputStream>> = None;
            let null_char_array: Option<Local<java::Array<u16>>> = None;
            //keystore.load(&null_input_stream, &null_char_array);
            //keystore.set_certificate_entry("ca-certificate", certificate);
            //keystore.set_certificate("ca-certificate", certificate);
            Ok(keystore.unwrap())
        })
        .unwrap();
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
