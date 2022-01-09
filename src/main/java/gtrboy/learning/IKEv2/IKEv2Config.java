package gtrboy.learning.IKEv2;

import java.io.*;
import java.util.Properties;

public class IKEv2Config {

    private final String peerAddress;  // ip address of the ikev2 server
    private final String localAddress;   // local address of the client
    private final int port;  // ikev2 server port, UDP
    private final float timeout;  //timeout

    private final String hmacFunc;   // integrity function
    private final String encFunc;    // encryption function
    private final String psk;
    private final int dhGroup;
    private final int nonceLen;

    private final int retry_num;
    private final String telnet_username;
    private final String telnet_password;
    private final String sul;


    public IKEv2Config(String fileName) throws IOException {
        Properties props = new Properties();
        //"ikev2_config.properties"
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(fileName);
        props.load(in);

        peerAddress = props.getProperty("peer_address");
        localAddress = props.getProperty("local_address");
        port = Integer.parseInt(props.getProperty("port"));
        timeout = Float.parseFloat(props.getProperty("timeout"));

        hmacFunc = props.getProperty("hmac_algo");
        encFunc = props.getProperty("enc_algo");
        psk = props.getProperty("psk");
        dhGroup = Integer.parseInt(props.getProperty("dh_group"));
        nonceLen = Integer.parseInt(props.getProperty("nonce_len"));

        telnet_username = props.getProperty("tel_user");
        telnet_password = props.getProperty("tel_pass");
        retry_num = Integer.parseInt(props.getProperty("retry"));
        sul = props.getProperty("sul");
    }


    public String getTelUser(){
        return telnet_username;
    }

    public String getTelPass(){
        return telnet_password;
    }

    public String getPeerAddress() {
        return peerAddress;
    }

    public String getLocalAddress() {
        return localAddress;
    }

    public int getPort() {
        return port;
    }

    public float getTimeout() {
        return timeout;
    }

    public int getDhGroup(){
        return dhGroup;
    }

    public String getHmacFunc(){
        return hmacFunc;
    }

    public int getNonceLen(){
        return nonceLen;
    }


    public String getPsk(){
        return psk;
    }

    public String getEncFunc(){
        return encFunc;
    }

    public int getRetryNum(){
        return retry_num;
    }

    public String getSul(){
        return sul;
    }

}
