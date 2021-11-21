package gtrboy.learning.IKEv2;

import java.io.*;
import java.net.InetAddress;
import java.util.Properties;

public class IKEv2Config {

    private Properties props;
    private InetAddress peerAddress;  // ip address of the ikev2 server
    private InetAddress localAddress;   // local address of the client
    private int port = 500;  // ikev2 server port, UDP
    private int timeout = 5;  //timeout

    public IKEv2Config() throws IOException {
        props = new Properties();
        //String configFile = System.getProperty("user.dir") + "/conf/config.properties";
        //InputStream in = new BufferedInputStream(new FileInputStream(configFile));
        InputStream in = this.getClass().getResourceAsStream("ikev2_config.properties");
        props.load(in);

        peerAddress = InetAddress.getByName(props.getProperty("peer_address"));
        localAddress = InetAddress.getByName(props.getProperty("local_address"));
        port = Integer.parseInt(props.getProperty("port"));
        timeout = Integer.parseInt(props.getProperty("timeout"));

    }

    public InetAddress getPeerAddress() {
        return peerAddress;
    }

    public InetAddress getLocalAddress() {
        return localAddress;
    }

    public int getPort() {
        return port;
    }

    public int getTimeout() {
        return timeout;
    }
}
