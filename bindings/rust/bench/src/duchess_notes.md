https://duchess-rs.github.io/duchess/call_java_from_rust.html#using-a-package-from-rust

This section mentioned "see below" but below there isn't anything to see :(

They mention that the class signatures are just essentially from the javap tool

```
[ec2-user@ip-172-31-6-209 bench]$ javap -public javax.net.ssl.SSLContext
public class javax.net.ssl.SSLContext {
  public static javax.net.ssl.SSLContext getDefault() throws java.security.NoSuchAlgorithmException;
  public static void setDefault(javax.net.ssl.SSLContext);
  public static javax.net.ssl.SSLContext getInstance(java.lang.String) throws java.security.NoSuchAlgorithmException;
  public static javax.net.ssl.SSLContext getInstance(java.lang.String, java.lang.String) throws java.security.NoSuchAlgorithmException, java.security.NoSuchProviderException;
  public static javax.net.ssl.SSLContext getInstance(java.lang.String, java.security.Provider) throws java.security.NoSuchAlgorithmException;
  public final java.lang.String getProtocol();
  public final java.security.Provider getProvider();
  public final void init(javax.net.ssl.KeyManager[], javax.net.ssl.TrustManager[], java.security.SecureRandom) throws java.security.KeyManagementException;
  public final javax.net.ssl.SSLSocketFactory getSocketFactory();
  public final javax.net.ssl.SSLServerSocketFactory getServerSocketFactory();
  public final javax.net.ssl.SSLEngine createSSLEngine();
  public final javax.net.ssl.SSLEngine createSSLEngine(java.lang.String, int);
  public final javax.net.ssl.SSLSessionContext getServerSessionContext();
  public final javax.net.ssl.SSLSessionContext getClientSessionContext();
  public final javax.net.ssl.SSLParameters getDefaultSSLParameters();
  public final javax.net.ssl.SSLParameters getSupportedSSLParameters();
}
```
