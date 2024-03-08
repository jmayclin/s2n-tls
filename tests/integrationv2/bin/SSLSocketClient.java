import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.security.KeyStore;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;

/*
 * Simple JDK SSL client for integration testing purposes
 */

public class SSLSocketClient {
    static final String TLS_13 = "TLSv1.3";
    static final String APP_REQUEST = "gimme data";
    static final String SERVER_FINAL = "thats all for now folks";
    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "ssl");

        int port = 9004;
        String certificatePath = "/home/ec2-user/workspace/s2n-tls/tests/pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem";
        String[] protocolList = new String[] {TLS_13};
        String[] cipherList = new String[] {"TLS_AES_128_GCM_SHA256"};

        String host = "localhost";
        //byte[] buffer = new byte[1_000_000];

        SSLSocketFactory socketFactory = createSocketFactory(certificatePath, TLS_13);

        try (
            SSLSocket socket = (SSLSocket)socketFactory.createSocket(host, port);
        ) {
            // their naming confuses me
            // the input stream is for reading bytes from the socket
            InputStream in = new BufferedInputStream(socket.getInputStream());
            // the out stream is for writing bytes to the socket
            OutputStream out = new BufferedOutputStream(socket.getOutputStream());

            socket.setEnabledProtocols(protocolList);
            socket.setEnabledCipherSuites(cipherList);
            socket.startHandshake();
            // this helps prevent the mixing of handshake and application data
            // this should be handled properly but that is not my current goal
            Thread.sleep(1_000);
            System.out.println("Starting handshake");
            
            // "request" the data from the peer
            out.write(APP_REQUEST.getBytes());
            System.out.println("Wrote the app request");
            out.flush();

            // read in 200 GB from the server
            for (int i = 0; i < 200 * 1000; i++) {
                byte[] buffer = in.readNBytes(1_000_000);
                if (i % 1_000 == 0) {
                    System.out.println("Read in " + i / 1_000 + "Gb, and the first byte was " + buffer[0]);
                }
            }

            // read in the server message
            byte[] final_buffer = out.readNBytes(SERVER_FINAL.length());
            String str = new String(final_buffer, StandardCharsets.UTF_8);
            System.out.println("the final message was " + str);

            // closed the things
            in.close();
            out.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SSLSocketFactory createSocketFactory(String certificatePath, String protocol) {

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            FileInputStream is = new FileInputStream(certificatePath);

            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
            is.close();

            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(null, null);
            caKeyStore.setCertificateEntry("ca-certificate", cert);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(caKeyStore);

            SSLContext context = SSLContext.getInstance(protocol);
            context.init(null, trustManagerFactory.getTrustManagers(), null);

            return context.getSocketFactory();

        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String sslProtocols(String s2nProtocol) {
        switch (s2nProtocol) {
            case "TLS1.3":
                return "TLSv1.3";
            case "TLS1.2":
                return "TLSv1.2";
            case "TLS1.1":
                return "TLSv1.1";
            case "TLS1.0":
                return "TLSv1.0";
        }

        return null;
    }
}
