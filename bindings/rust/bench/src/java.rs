
mod utility_jni {
    duchess::java_package! {
        package java.security;
    
        class SecureRandom {
            public java.security.SecureRandom();
        }
    }
}

mod ssl_jni {
    use super::utility_jni::java::security;

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
    }
}


#[cfg(test)]
mod test {
    use duchess::{java, JvmOp, ToJava};
    // this feels forbidden
    use super::{ssl_jni::javax::net::ssl::SSLContext, utility_jni::java::security::SecureRandom};

    #[test]
    fn create_ssl_context() {
        let tls_string = "TLSv1.3".to_owned();
        let ssl_context = SSLContext::get_instance(tls_string.to_java::<java::lang::String>()).global().execute().unwrap().unwrap();
    }

    #[test]
    fn create_secure_random() {
        let secure_random = SecureRandom::new().global().execute().unwrap();
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
