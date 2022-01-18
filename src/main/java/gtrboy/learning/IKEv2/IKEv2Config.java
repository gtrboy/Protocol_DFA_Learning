package gtrboy.learning.IKEv2;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.Properties;

public class IKEv2Config {

    private final String peerAddress;  // ip address of the ikev2 server
    private final String localAddress;   // local address of the client
    private final int port;  // ikev2 server port, UDP
    private final float timeout;  //timeout

    private final String hmacFunc;   // integrity function
    private final String encFunc;    // encryption function
    private final int dhGroup;
    private final int nonceLen;

    private final int retry_num;
    private final String telnet_username;
    private final String telnet_password;
    private final String sul;

    private final String auth_type;
    private String rsa_sign_algo = null;
    private String private_key = null;
    private String psk = null;

    private static final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);


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
        dhGroup = Integer.parseInt(props.getProperty("dh_group"));
        nonceLen = Integer.parseInt(props.getProperty("nonce_len"));

        auth_type = props.getProperty("auth_type");
        switch (auth_type){
            case "psk":
                psk = props.getProperty("psk");
                break;
            case "cert_http":
                rsa_sign_algo = props.getProperty("rsa_sign_algo");
                private_key = props.getProperty("private_key");
                break;
            default:
                LOGGER.error("Invalid Authentication Type! ");
                System.exit(-1);
        }

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

    public String getRsaSignAlgo(){
        return rsa_sign_algo;
    }

    public String getPrivateKey(){
        return private_key;
    }

    public String getAuthType(){
        return auth_type;
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
