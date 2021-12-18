package gtrboy.learning.IKEv2;

import java.io.*;
import java.net.InetAddress;
import java.util.Properties;

public class IKEv2Config {

    private Properties props;
    private String peerAddress;  // ip address of the ikev2 server
    private String localAddress;   // local address of the client
    private int port = 500;  // ikev2 server port, UDP
    private int timeout = 5;  //timeout
    private int dhGroup = 14;
    private String prfFunc = null;
    private String intgFunc = null;
    private String psk = null;
    private int integ_key_len;
    private int enc_key_len;
    private int prf_key_len;
    private int aes_block_size;
    private int debug;
    private int retry_num;
    private String telnet_password = null;


    public IKEv2Config(String fileName) throws IOException {
        props = new Properties();
        //"ikev2_config.properties"
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(fileName);
        props.load(in);

        peerAddress = props.getProperty("peer_address");
        localAddress = props.getProperty("local_address");
        port = Integer.parseInt(props.getProperty("port"));
        timeout = Integer.parseInt(props.getProperty("timeout"));

        dhGroup = Integer.parseInt(props.getProperty("DH_group"));
        prfFunc = props.getProperty("prf");
        intgFunc = props.getProperty("integrity");
        integ_key_len = Integer.parseInt(props.getProperty("integ_key_len"));
        enc_key_len = Integer.parseInt(props.getProperty("enc_key_len"));
        aes_block_size = Integer.parseInt(props.getProperty("aes_block_size"));
        prf_key_len = Integer.parseInt(props.getProperty("prf_key_len"));
        psk = props.getProperty("psk");
        telnet_password = props.getProperty("tel_pass");
        debug = Integer.parseInt(props.getProperty("debug"));
        retry_num = Integer.parseInt(props.getProperty("retry"));
    }

    public int getDebug(){
        return debug;
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

    public int getTimeout() {
        return timeout;
    }

    public int getDhGroup(){ return dhGroup; }

    public String getPrfFunc(){
        return prfFunc;
    }

    public String getIntgFunc() {
        return intgFunc;
    }

    public String getPsk(){
        return psk;
    }

    public int getIntegKeyLen(){
        return integ_key_len;
    }

    public int getEncKeyLen(){
        return enc_key_len;
    }

    public int getPrfKeyLen(){
        return prf_key_len;
    }

    public int getAESBlockSize(){
        return aes_block_size;
    }

    public int getRetryNum(){
        return retry_num;
    }

}
