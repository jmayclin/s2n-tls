import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
    static final int LARGE_DATA_DOWNLOAD_GB = 256;
    static final String TLS_13 = "TLSv1.3";
    static final String CLIENT_GREETING = "i am the client. nice to meet you server.";
    static final String SERVER_GREETING = "i am the server. a pleasure to make your acquaintance.";

    public static void main(String[] args) throws Exception {
        // enable debug logging for all of the ssl related things

        System.setProperty("javax.net.debug", "ssl");

        // parse the test arguments
        String testCase = args[0];
        int port = Integer.parseInt(args[1]);

        String host = "localhost";
        // byte[] buffer = new byte[100];

        String certificatePath = "../certificates/ca-cert.pem";
        SSLSocketFactory socketFactory = createSocketFactory(certificatePath, TLS_13);
        System.out.println("opening the socket");
        try (
            SSLSocket socket = (SSLSocket)socketFactory.createSocket(host, port);
        ) {
            InputStream in = new BufferedInputStream(socket.getInputStream());
            OutputStream out = new BufferedOutputStream(socket.getOutputStream());
            //socket.setEnabledProtocols(protocolList);
            //socket.setEnabledCipherSuites(cipher);
            socket.startHandshake();
            System.out.println("FINISHED THE HANDSHAKE");
            System.out.println(testCase);
            if (testCase == "handshake") {
                // no action required for handshake case
            }
            if (testCase.equals("greeting")) {
                System.out.println("doing the greeting");
                out.write(CLIENT_GREETING.getBytes());
                out.flush();
                System.out.println("wrote the client greeting");

                byte[] buffer = in.readNBytes(SERVER_GREETING.getBytes().length);
                System.out.println("read the server greeting");
                
                String s = new String(buffer);
                if (!s.equals(SERVER_GREETING)) {
                    throw new Exception("Unexpected server greeting");
                }
            } else if (testCase == "large_data_download" || testCase == "large_data_download_with_frequent_key_updates") {
                out.write(CLIENT_GREETING.getBytes());

                // read in 200 GB from the server
                for (int i = 0; i < LARGE_DATA_DOWNLOAD_GB; i++) {
                    for (int j = 0; j < 1_000; j++) {
                        byte[] buffer = in.readNBytes(1_000_000);
                        // java bytes are signed, so we have to upcast to an int to 
                        // read the tag value
                        int tag = buffer[0] & 0xFF;
                        if (tag != i) {
                            throw new Exception("Unexpected tag value");
                        }
                    }
                }
            } else {
                // unsupported test case
                System.exit(127);
            }




            socket.close();
        }
    }

    private void large_data_download() {
        
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

}
