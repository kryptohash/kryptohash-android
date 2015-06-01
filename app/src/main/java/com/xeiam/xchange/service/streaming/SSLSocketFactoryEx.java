// Based on the SSLSocketFactoryEx() by jww. 
//   See http://stackoverflow.com/questions/1037590/which-cipher-suites-to-enable-for-ssl-socket/23365536#23365536

package com.xeiam.xchange.service.streaming;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SSLSocketFactoryEx extends SSLSocketFactory {

    private static final String PREFERRED_PROTOCOL = "TLSv1.2";
    private static final String PREFERRED_CIPHER_SUITE = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

    private final SSLSocketFactory delegate;

    public SSLSocketFactoryEx(SSLSocketFactory delegate) {
        this.delegate = delegate;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return setupPreferredDefaultCipherSuites(this.delegate);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return setupPreferredSupportedCipherSuites(this.delegate);
    }

    @Override
    public Socket createSocket(String arg0, int arg1) throws IOException, UnknownHostException {
        Socket socket = this.delegate.createSocket(arg0, arg1);
        String[] protocols = GetProtocolList(delegate);
        ((SSLSocket)socket).setEnabledProtocols(protocols);
        String[] cipherSuites = GetCipherList(delegate);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

        return socket;
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1) throws IOException {
        Socket socket = this.delegate.createSocket(arg0, arg1);
        String[] protocols = GetProtocolList(delegate);
        ((SSLSocket)socket).setEnabledProtocols(protocols);
        String[] cipherSuites = GetCipherList(delegate);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

        return socket;
    }

    @Override
    public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException {
        Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
        String[] protocols = GetProtocolList(delegate);
        ((SSLSocket)socket).setEnabledProtocols(protocols);
        String[] cipherSuites = GetCipherList(delegate);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

        return socket;
    }

    @Override
    public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3) throws IOException, UnknownHostException {
        Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
        String[] protocols = GetProtocolList(delegate);
        ((SSLSocket)socket).setEnabledProtocols(protocols);
        String[] cipherSuites = GetCipherList(delegate);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

        return socket;
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException {
        Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
        String[] protocols = GetProtocolList(delegate);
        ((SSLSocket)socket).setEnabledProtocols(protocols);
        String[] cipherSuites = GetCipherList(delegate);
        ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);

        return socket;
    }

    protected String[] GetProtocolList(SSLSocketFactory sslSocketFactory)
    {
        String[] preferredProtocols = { PREFERRED_PROTOCOL };
        String[] availableProtocols = null;

        SSLSocket socket = null;

        try
        {
            socket = (SSLSocket)sslSocketFactory.createSocket();
            availableProtocols = socket.getSupportedProtocols();
            Arrays.sort(availableProtocols);
        }
        catch(Exception e)
        {
            return new String[]{ "TLSv1" };
        }
        finally
        {
            if(socket != null) {
                try {
                    socket.close();
                } catch (final Exception e) {
					// swallow
                }
            }
        }

        List<String> aa = new ArrayList<String>();
        for(int i = 0; i < preferredProtocols.length; i++)
        {
            int idx = Arrays.binarySearch(availableProtocols, preferredProtocols[i]);
            if(idx >= 0)
                aa.add(preferredProtocols[i]);
        }

        return aa.toArray(new String[0]);
    }

    protected String[] GetCipherList(SSLSocketFactory sslSocketFactory)
    {
        String[] preferredCiphers = {

            // *_CHACHA20_POLY1305 are 3x to 4x faster than existing cipher suites.
            //   http://googleonlinesecurity.blogspot.com/2014/04/speeding-up-and-strengthening-https.html
            // Use them if available. Normative names can be found at (TLS spec depends on IPSec spec):
            //   http://tools.ietf.org/html/draft-nir-ipsecme-chacha20-poly1305-01
            //   http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-02
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_SHA",
            "TLS_ECDHE_RSA_WITH_CHACHA20_SHA",

            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305",
            "TLS_RSA_WITH_CHACHA20_POLY1305",
            "TLS_DHE_RSA_WITH_CHACHA20_SHA",
            "TLS_RSA_WITH_CHACHA20_SHA",

            // Done with bleeding edge, back to TLS v1.2 and below
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",

            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",

            // TLS v1.0 (with some SSLv3 interop)
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",

            "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA",
            "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA",

            // RSA key transport sucks, but they are needed as a fallback.
            // For example, microsoft.com fails under all versions of TLS
            // if they are not included. If only TLS 1.0 is available at
            // the client, then google.com will fail too. TLS v1.3 is
            // trying to deprecate them, so it will be interesting to see
            // what happens.
            "TLS_RSA_WITH_AES_256_CBC_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA"
        };

        String[] availableCiphers = null;

        try
        {
            availableCiphers = sslSocketFactory.getSupportedCipherSuites();
            Arrays.sort(availableCiphers);
        }
        catch(Exception e)
        {
            return new String[] {
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
            };
        }

        List<String> aa = new ArrayList<String>();
        for(int i = 0; i < preferredCiphers.length; i++)
        {
            int idx = Arrays.binarySearch(availableCiphers, preferredCiphers[i]);
            if(idx >= 0)
                aa.add(preferredCiphers[i]);
        }

        aa.add("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");

        return aa.toArray(new String[0]);
    }

    private static String[] setupPreferredDefaultCipherSuites(SSLSocketFactory sslSocketFactory) {
        String[] defaultCipherSuites = sslSocketFactory.getDefaultCipherSuites();

        ArrayList<String> suitesList = new ArrayList<String>(Arrays.asList(defaultCipherSuites));
        suitesList.remove(PREFERRED_CIPHER_SUITE);
        suitesList.add(0, PREFERRED_CIPHER_SUITE);

        return suitesList.toArray(new String[suitesList.size()]);
    }

    private static String[] setupPreferredSupportedCipherSuites(SSLSocketFactory sslSocketFactory) {
        String[] supportedCipherSuites = sslSocketFactory.getSupportedCipherSuites();

        ArrayList<String> suitesList = new ArrayList<String>(Arrays.asList(supportedCipherSuites));
        suitesList.remove(PREFERRED_CIPHER_SUITE);
        suitesList.add(0, PREFERRED_CIPHER_SUITE);

        return suitesList.toArray(new String[suitesList.size()]);
    }
}
