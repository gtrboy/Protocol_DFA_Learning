package gtrboy.learning.IKEv2;

import gtrboy.learning.IKEv2.messages.*;
import gtrboy.learning.IKEv2.parsers.*;
import gtrboy.learning.utils.DataUtils;
//import gtrboy.learning.utils.LogUtils;

import java.io.IOException;
import java.net.*;

import gtrboy.learning.utils.SshMain;
import gtrboy.learning.utils.TelnetMain;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;




public class IKEv2Client extends IKEv2{

    //private final IKEv2Config clientConf;
    private final int g_RetryNum;
    //private byte[] lastPkt;
    private final String g_sulName;
    private final String g_peerAddr;
    private final String g_localAddr;
    private final int g_port;
    private final float g_Timeout;
    private final int g_dhGrp;
    private final String g_encAlg;
    private final String g_hmacAlg;
    private String g_psk = null;
    private String g_rsaSignAlgo = null;
    private String g_privateKey = null;
    private final int nonce_len;



    private byte[] g_iSpi = null;
    private byte[] g_rSpi = null;
    private byte[] g_iOldSpi = null;
    private byte[] g_rOldSpi = null;
    private byte[] g_iKe = null;
    private byte[] g_iNnonce = null;
    private byte[] g_rKe = null;
    private byte[] g_rNonce = null;
    private byte[] old_i_nonce = null;
    private byte[] old_r_nonce = null;
    private byte[] g_iInitSaPkt;
    private byte[] g_iChildSpi;
    private byte[] g_rChildSpi;
    private byte[] g_iOldChildSpi;
    private byte[] g_rOldChildSpi;
    private int g_curMsgId = 0;
    private int g_oldMsgId = 0;

    //private DatagramSocket _sock_;
    private IKEv2KeysGener g_curKeyGen;
    private IKEv2KeysGener g_oldKeyGen;
    private TelnetMain g_telnetClient = null;
    private SshMain g_sshClient = null;

    private static final String TIMEOUT = "TIMEOUT";
    private static final String ERROR = "ERROR";
    private static final int IPSEC_SPI_LEN = 4;
    private static final int IKE_SPI_LEN = 8;


    public IKEv2Client(IKEv2Config config) {
        String telnetUserName;
        String telnetPassword;

        LOGGER.debug("CREATE IKEv2 CLIENT! ");
        //clientConf = config;
        g_peerAddr = config.getPeerAddress();
        g_localAddr = config.getLocalAddress();
        g_port = config.getPort();
        g_Timeout = config.getTimeout();
        g_RetryNum = config.getRetryNum();
        g_sulName = config.getSul();
        g_dhGrp = config.getDhGroup();
        g_encAlg = config.getEncFunc();
        g_hmacAlg = config.getHmacFunc();
        nonce_len = config.getNonceLen();

        telnetUserName = config.getTelUser();
        telnetPassword = config.getTelPass();
        if (g_sulName.equals("sonicwall")){
            g_sshClient = new SshMain(g_peerAddr, telnetUserName, telnetPassword, g_sulName);
            g_sshClient.openSession();
        }else{
            g_telnetClient = new TelnetMain(g_peerAddr, telnetUserName, telnetPassword, g_sulName);
            g_telnetClient.connect();
        }


        String authType = config.getAuthType();
        switch (authType){
            case "psk":
                g_psk = config.getPsk();
                break;
            case "cert_http":
                g_rsaSignAlgo = config.getRsaSignAlgo();
                g_privateKey = config.getPrivateKey();
                break;
            default:
                LOGGER.error("Invalid Authentication Type! ");
                System.exit(-1);
        }

    }

    private void addMsgId(boolean isCurrent){
        if(isCurrent){
            g_curMsgId += 1;
        }else{
            g_oldMsgId += 1;
        }
    }
    private void resetMsgId(int id, boolean isCurrent) {
        if(isCurrent){
            g_curMsgId = id;
        }else{
            g_oldMsgId = id;
        }
    }

//    private void send(byte[] data) throws IOException {
//        try {
//            InetSocketAddress peerSocketAddr = new InetSocketAddress(g_peerAddr, g_port);
//            DatagramPacket packet = new DatagramPacket(data, data.length, peerSocketAddr);
//            // DatagramSocket udpSock = new DatagramSocket();
//            _sock_.send(packet);
//            // udpSock.close();
//        } catch (Exception e) {
//            LOGGER.error("UDP socket send Error! ");
//            e.printStackTrace();
//        }
//    }
//
//
//
//    private DatagramPacket receive() throws IOException {
//        byte[] buffer = new byte[1024];
//        int msgId;
//        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
//        while(true) {
//            _sock_.receive(packet);
//            if(validatePkt(packet)){
//                break;
//            }
//        }
//        return packet;
//    }

    public void prepare() {
        InitSocket();
        saInitWithAcceptedSa();
        //InitSPI();
    }

    public void reset() throws IOException {
        //this.connect(internetAddress, port);
        g_iSpi = null;
        g_rSpi = null;
        g_iOldSpi = null;
        g_rOldSpi = null;
        g_iChildSpi = null;
        g_rChildSpi = null;
        g_iOldChildSpi = null;
        g_rOldChildSpi = null;
        g_curMsgId = 0;
        g_oldMsgId = 0;
        g_wantedMsgId = 0;
        g_curKeyGen = null;
        g_oldKeyGen = null;
        g_iKe = null;
        g_rKe = null;
        g_iNnonce = null;
        g_rNonce = null;

        // 通过telnet清除目标设备的ike sa
        switch (g_sulName){
            case "cisco7200":
                g_telnetClient.resetCisco();
                break;
            case "fortigate":
                g_telnetClient.resetFG();
                break;
            case "hillstone":
                g_telnetClient.resetHS();
                break;
            case "sonicwall":
                g_sshClient.resetSW();
                break;
            default:
                LOGGER.error("Invalid SUL Name! ");
                System.exit(-1);
        }

        // Close the socket.
        close();
    }

    public void InitSocket() {
        try{
            // Open the socket.
            open(g_port);
            int timeout = (int) (g_Timeout * 1000);
            setSoTimeout(timeout);
        } catch (SocketException e){
            LOGGER.error("UDP socket init error! ");
            e.printStackTrace();
        }
    }

    private IKEv2KeysGener prepareKeyGen(){
        return new IKEv2KeysGener(g_dhGrp, g_encAlg, g_hmacAlg, g_psk);
    }

    private void prepareInitSa(){
        InitSPI();
        g_curKeyGen = prepareKeyGen();
        g_iKe = g_curKeyGen.getPubKey();
        g_iNnonce = DataUtils.genRandomBytes(nonce_len);
        resetMsgId(0, true);
    }

    private void InitSPI() {
        g_iSpi = DataUtils.genRandomBytes(IKE_SPI_LEN);
        g_rSpi = DataUtils.genEmptyBytes(IKE_SPI_LEN);
    }


    /*************  Packets  **************/

    public String saInitWithAcceptedSa(){
        String retStr = null;
        prepareInitSa();
        PktIKEInitSA pkt = new PktIKEInitSA(g_sulName + "/ike_init_sa_acc_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_iKe, g_iNnonce);
        byte[] pktBytes = pkt.getPacketBytes();

        beginBufferedOps();
        int round = g_RetryNum;
        while(round>=0){
            try{
                //send(pktBytes);
                bufferedSend(pktBytes, g_peerAddr, g_port);
                g_wantedMsgId = g_curMsgId;
            } catch (IOException e) {
                LOGGER.error("Send UDP packet Error!");
                e.printStackTrace();
            }
            try {
                IKEv2Parser parser= bufferedReceive(null);
                switch (parser.getType()){
                    case IKEv2Parser.INIT:
                        IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                        retStr = initParser.parsePacket();
                        if("OK".equals(retStr)){
                            // For Authentication, store the INIT_SA packet first.
                            g_iInitSaPkt = pktBytes;
                            g_rSpi = initParser.getRespSPI();
                            g_rKe = initParser.getPubKey();
                            g_rNonce = initParser.getNonce();
                            g_curKeyGen.genKeys(g_iSpi, g_rSpi, g_iNnonce, g_rNonce, g_rKe);
                            LOGGER.debug("ispi: " + DataUtils.bytesToHexStr(g_iSpi));
                            LOGGER.debug("rspi: " + DataUtils.bytesToHexStr(g_rSpi));
                            LOGGER.debug("r_ke: " + DataUtils.bytesToHexStr(g_rKe));
                            LOGGER.debug("r_nonce: " + DataUtils.bytesToHexStr(g_rNonce));
                        }
                        break;
                    case IKEv2Parser.INFO:
                        IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                        retStr = infoParser.parsePacket();
                        break;
                    default:
                        LOGGER.error("Receive invalid exchange type: " + parser.getType());
                        System.exit(-1);
                }
                addMsgId(true);
                break;
            } catch (SocketTimeoutException e){
                retStr = TIMEOUT;
                round--;
                //LOGGER.debug("Timeout in IKE_INIT_SA!");
            } catch (IOException e){
                LOGGER.error("UDP receive packet error! ");
                e.printStackTrace();
            }
        }
        endBufferedOps();

        LOGGER.info("saInitWithAcceptedSA, RET: " + retStr);
        return retStr;
    }

    public String authWithPsk(){
        String retStr = authExchange(IKEv2AuthType.PSK, "ike_auth_psk.xml");
        LOGGER.info("authWithPsk, RET: " + retStr);
        return retStr;
    }

    public String authWithCert(){
        String retStr = authExchange(IKEv2AuthType.CERT, "ike_auth_cert.xml");
        LOGGER.info("authWithCert, RET: " + retStr);
        return retStr;
    }

    public String authWithCertHttp(){
        String retStr = authExchange(IKEv2AuthType.CERT, "ike_auth_cert_http.xml");
        LOGGER.info("authWithCertHttp, RET: " + retStr);
        return retStr;
    }

    private String authExchange(IKEv2AuthType type, String xmlFile){
        String retStr = null;
        if(g_iSpi ==null || g_rSpi ==null ){
            retStr = ERROR;
        }else {
            byte[] i_child_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
            byte[] pktBytes = null;
            switch (type){
                case PSK:
                    PktIKEAuthPSK pktPsk = new PktIKEAuthPSK(g_sulName + "/" + xmlFile, g_iSpi, g_rSpi, g_curMsgId,
                            g_curKeyGen, g_rNonce, g_iInitSaPkt, g_localAddr, i_child_spi);
                    pktBytes = pktPsk.getPacketBytes();
                    break;
                case CERT:
                    PktIKEAuthCert pktCert = new PktIKEAuthCert(g_sulName + "/" + xmlFile, g_iSpi, g_rSpi, g_curMsgId,
                            g_curKeyGen, g_rNonce, g_iInitSaPkt, g_localAddr, i_child_spi, g_rsaSignAlgo, g_privateKey);
                    pktBytes = pktCert.getPacketBytes();
                    break;
                default:
                    LOGGER.error("Invalid Authentication Type!");
                    System.exit(-1);
            }


            beginBufferedOps();
            int round = g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    switch (parser.getType()){
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            if ("OK".equals(retStr)) {
                                g_iChildSpi = i_child_spi;
                                g_rChildSpi = authParser.getRChildSpi();
                            }/* else {
                                g_iChildSpi = null;
                            }*/
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        return retStr;
    }


    /* IKE SA Operations */
    public String rekeyIkeSa(){
        String retStr = null;
        if(g_iSpi ==null || g_rSpi ==null ){
            retStr = ERROR;
        }else {
            IKEv2KeysGener tmpKeyG = prepareKeyGen();
            //byte[] new_spi = DataUtils.genRandomBytes(IKE_SPI_LEN);
            byte[] new_spi = DataUtils.genNewSpiForHs(g_iSpi);
            byte[] new_nc = DataUtils.genRandomBytes(nonce_len);
            byte[] new_ke = tmpKeyG.getPubKey();
            PktRekeyIkeSa pkt = new PktRekeyIkeSa(g_sulName + "/cre_cld_sa_rekey_ike_sa.xml", g_iSpi, g_rSpi, g_curMsgId,
                    g_curKeyGen, new_spi, new_nc, new_ke);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    switch (parser.getType()){
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            if (retStr.equals("OK_IKE")) {
                                g_iOldSpi = g_iSpi;
                                g_iSpi = new_spi;
                                g_rOldSpi = g_rSpi;
                                g_rSpi = ccsaParser.getRSpi();
                                old_i_nonce = g_iNnonce;
                                g_iNnonce = new_nc;
                                old_r_nonce = g_rNonce;
                                g_rNonce = ccsaParser.getRNonce();
                                //oldKeyGen = curKeyGen;
                                tmpKeyG.reGenKeys(g_curKeyGen.getSkD(), new_spi, ccsaParser.getRSpi(), new_nc, ccsaParser.getRNonce(), ccsaParser.getKe());
                                //tmpNewKeyGen = tmpKeyG;
                                g_oldKeyGen = g_curKeyGen;
                                g_curKeyGen = tmpKeyG;
                                g_oldMsgId = g_curMsgId + 1;
                                resetMsgId(0, true);
                                retStr = "OK";
                                LOGGER.debug("new iSPI: " + DataUtils.bytesToHexStr(g_iSpi));
                                LOGGER.debug("new rSPI: " + DataUtils.bytesToHexStr(g_rSpi));
                            } else {
                                addMsgId(true);
                            }
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            addMsgId(true);
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        LOGGER.info("rekeyIKESA, RET: " + retStr);
        return retStr;
    }

    public String delCurIkeSa(){
        String retStr = null;
        if(g_iSpi ==null || g_rSpi ==null ){
            retStr = ERROR;
        }else {
            PktDelIKESa pkt = new PktDelIKESa(g_sulName + "/info_del_ike_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_curKeyGen);

            beginBufferedOps();
            int round= g_RetryNum;
            while (round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    if (parser.getType() == IKEv2Parser.INFO) {
                        IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                        retStr = infoParser.parsePacket();
                        if ("OK_DEL".equals(retStr) || "EmptyInfo".equals(retStr)) {
                            resetMsgId(0, true);
                            g_iSpi = null;
                            g_rSpi = null;
                            g_curKeyGen = null;
                            //retStr = "OK";
                            if ("OK_DEL".equals(retStr)){
                                retStr = "OK";
                            }
                        } else {
                            addMsgId(true);
                        }
                    } else {
                        LOGGER.error("Receive invalid exchange type: " + parser.getType());
                        System.exit(-1);
                    }
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("delCurIKESA, RET: " + retStr);
        return retStr;
    }

    public String delOldIkeSa(){
        String retStr = null;
        if(g_iOldSpi ==null || g_rOldSpi ==null ){
            retStr = ERROR;
        }else {
            PktDelIKESa pkt = new PktDelIKESa(g_sulName + "/info_del_ike_sa.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId, g_oldKeyGen);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_oldKeyGen);
                    if (parser.getType() == IKEv2Parser.INFO) {
                        IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                        retStr = infoParser.parsePacket();
                        if ("OK_DEL".equals(retStr) || "EmptyInfo".equals(retStr)) {
                            resetMsgId(0, false);
                            g_iOldSpi = null;
                            g_rOldSpi = null;
                            g_oldKeyGen = null;
                            if ("OK_DEL".equals(retStr)){
                                retStr = "OK";
                            }
                        } else {
                            addMsgId(false);
                        }
                    } else {
                        LOGGER.error("Receive invalid exchange type: " + parser.getType());
                        System.exit(-1);
                    }
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        LOGGER.info("delOldIKESA, RET: " + retStr);
        return retStr;
    }


    /* Child SA Operations */

    private String newChildSaWithCurIkeSa(String patternFile){
        String retStr = null;
        if(g_iSpi ==null || g_rSpi ==null || g_iChildSpi ==null){
            retStr = ERROR;
        }else {
            byte[] old_c_spi;
            byte[] new_c_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
            byte[] new_nc = DataUtils.genRandomBytes(nonce_len);
            if (g_iChildSpi != null) {
                old_c_spi = g_iChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }
            PktRekeyChildSa pkt = new PktRekeyChildSa(g_sulName + patternFile, g_iSpi, g_rSpi, g_curMsgId,
                    g_curKeyGen, old_c_spi, new_c_spi, new_nc);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    switch (parser.getType()){
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            if (retStr.equals("OK_ESP")) {
                                g_iOldChildSpi = g_iChildSpi;
                                g_iChildSpi = new_c_spi;
                                g_rOldChildSpi = g_rChildSpi;
                                g_rChildSpi = ccsaParser.getRChildSpi();
                                retStr = "OK";
                            }
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            addMsgId(true);
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        return retStr;
    }

    private String newChildSaWithOldIkeSa(String patternFile){
        String retStr = null;
        if(g_iOldSpi ==null || g_rOldSpi ==null || g_iChildSpi ==null){
            retStr = ERROR;
        }else {
            byte[] old_c_spi;
            byte[] new_c_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
            byte[] new_nc = DataUtils.genRandomBytes(nonce_len);
            if (g_iChildSpi != null) {
                old_c_spi = g_iChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }
            PktRekeyChildSa pkt = new PktRekeyChildSa(g_sulName + patternFile, g_iOldSpi, g_rOldSpi, g_oldMsgId,
                    g_oldKeyGen, old_c_spi, new_c_spi, new_nc);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_oldKeyGen);
                    switch (parser.getType()){
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            if (retStr.equals("OK_ESP")) {
                                g_iOldChildSpi = g_iChildSpi;
                                g_iChildSpi = new_c_spi;
                                g_rOldChildSpi = g_rChildSpi;
                                g_rChildSpi = ccsaParser.getRChildSpi();
                                retStr = "OK";
                            }
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            addMsgId(false);
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(false);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        //LOGGER.info("rekeyChildSaWithOldIkeSa, RET: " + retStr);
        return retStr;
    }

    public String creChildSaWithCurIkeSa(){
        String retStr = newChildSaWithCurIkeSa("/cre_cld_sa_cre_cld_sa.xml");
        LOGGER.info("creChildSaWithCurIkeSa, RET: " + retStr);
        return retStr;
    }

    public String creChildSaWithOldIkeSa(){
        String retStr = newChildSaWithOldIkeSa("/cre_cld_sa_cre_cld_sa.xml");
        LOGGER.info("creChildSaWithOldIkeSa, RET: " + retStr);
        return retStr;
    }

    public String rekeyChildSaWithCurIkeSa(){
        String retStr = newChildSaWithCurIkeSa("/cre_cld_sa_rekey_cld_sa.xml");
        LOGGER.info("rekeyChildSaWithCurIkeSa, RET: " + retStr);
        return retStr;
    }

    public String rekeyChildSaWithOldIkeSa(){
        String retStr = newChildSaWithOldIkeSa("/cre_cld_sa_rekey_cld_sa.xml");
        LOGGER.info("rekeyChildSaWithOldIkeSa, RET: " + retStr);
        return retStr;
    }

    public String delCurChildSaWithCurIkeSa(){
        String retStr = null;
        if(g_iSpi ==null || g_rSpi ==null || g_iChildSpi ==null){
            retStr = ERROR;
        }else {
            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_curKeyGen, g_iChildSpi);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    if(parser.getType() == IKEv2Parser.INFO) {
                        IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                        retStr = infoParser.parsePacket();
                        if ("OK_DEL".equals(retStr)) {
                            g_iChildSpi = null;
                            g_rChildSpi = null;
                            retStr = "OK";
                        }
                    }else{
                        LOGGER.error("Receive invalid exchange type: " + parser.getType());
                        System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        LOGGER.info("delCurChildSaWithCurIkeSa, RET: " + retStr);
        return retStr;
    }

    public String delCurChildSaWithOldIkeSa(){
        String retStr = null;
        if(g_iOldSpi ==null|| g_rOldSpi ==null || g_iChildSpi ==null){
            retStr = ERROR;
        }else {

            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId, g_oldKeyGen, g_iChildSpi);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_oldKeyGen);
                    if(parser.getType()==IKEv2Parser.INFO) {
                        IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                        retStr = infoParser.parsePacket();
                        if ("OK_DEL".equals(retStr)) {
                            g_iChildSpi = null;
                            g_rChildSpi = null;
                            retStr = "OK";
                        }
                    }else{
                        LOGGER.error("Receive invalid exchange type: " + parser.getType());
                        System.exit(-1);
                    }
                    addMsgId(false);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        LOGGER.info("delCurChildSaWithOldIkeSa, RET: " + retStr);
        return retStr;
    }

    public String delOldChildSaWithCurIkeSa(){
        String retStr = null;
        if(g_iSpi ==null || g_rSpi ==null || g_iOldChildSpi ==null){
            retStr = ERROR;
        }else {

            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_curKeyGen, g_iOldChildSpi);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    if(parser.getType()==IKEv2Parser.INFO) {
                        IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                        retStr = infoParser.parsePacket();
                        if ("OK_DEL".equals(retStr)) {
                            g_iOldChildSpi = null;
                            g_rOldChildSpi = null;
                            retStr = "OK";
                        }
                    }else{
                        LOGGER.error("Receive invalid exchange type: " + parser.getType());
                        System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        LOGGER.info("delOldChildSaWithCurIkeSa, RET: " + retStr);
        return retStr;
    }

    public String delOldChildSaWithOldIkeSa(){
        String retStr = null;
        if(g_iOldSpi ==null|| g_rOldSpi ==null || g_iOldChildSpi ==null){
            retStr = ERROR;
        }else {
            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId, g_oldKeyGen, g_iOldChildSpi);

            beginBufferedOps();
            int round= g_RetryNum;
            while(round>=0) {
                try {
                    bufferedSend(pkt.getPacketBytes(), g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error! ");
                    e.printStackTrace();
                }

                try {
                    IKEv2Parser parser = bufferedReceive(g_oldKeyGen);
                    if(parser.getType()==IKEv2Parser.INFO) {
                        IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                        retStr = infoParser.parsePacket();
                        if ("OK_DEL".equals(retStr)) {
                            g_iOldChildSpi = null;
                            g_rOldChildSpi = null;
                            retStr = "OK";
                        }
                    }else{
                        LOGGER.error("Receive invalid exchange type: " + parser.getType());
                        System.exit(-1);
                    }
                    addMsgId(false);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }
        LOGGER.info("delOldChildSaWithOldIkeSa, RET: " + retStr);
        return retStr;

    }

    /* Others */

    public String emptyEncInfoCur(){
        String retStr = null;
        if(g_iSpi == null || g_rSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEncEmpty pkt = new PktInfoEncEmpty(g_sulName + "/info_enc_empty.xml", g_iSpi, g_rSpi, g_curMsgId, g_curKeyGen);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyEncInfoCur, RET: " + retStr);
        return retStr;
    }

    public String emptyInfoCur(){
        String retStr = null;
        if(g_iSpi == null || g_rSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEmpty pkt = new PktInfoEmpty(g_sulName + "/info_empty.xml", g_iSpi, g_rSpi, g_curMsgId);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(null);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyInfoCur, RET: " + retStr);
        return retStr;
    }

    public String emptyEncInfoOld(){
        String retStr = null;
        if(g_iOldSpi == null || g_rOldSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEncEmpty pkt = new PktInfoEncEmpty(g_sulName + "/info_enc_empty.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId, g_oldKeyGen);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(g_oldKeyGen);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyEncInfoOld, RET: " + retStr);
        return retStr;
    }

    public String emptyInfoOld(){
        String retStr = null;
        if(g_iOldSpi == null || g_rOldSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEmpty pkt = new PktInfoEmpty(g_sulName + "/info_empty.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(null);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyInfoOld, RET: " + retStr);
        return retStr;
    }

    /* Response */
    public String emptyEncInfoCurResp(){
        String retStr = null;
        if(g_iSpi == null || g_rSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEncEmpty pkt = new PktInfoEncEmpty(g_sulName + "/info_enc_empty_resp.xml", g_rSpi, g_iSpi, g_curMsgId, g_curKeyGen);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(g_curKeyGen);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyEncInfoCurResp RET: " + retStr);
        return retStr;
    }

    public String emptyInfoCurResp(){
        String retStr = null;
        if(g_iSpi == null || g_rSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEmpty pkt = new PktInfoEmpty(g_sulName + "/info_empty_resp.xml", g_rSpi, g_iSpi, g_curMsgId);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_curMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(null);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyInfoCurResp, RET: " + retStr);
        return retStr;
    }

    public String emptyEncInfoOldResp(){
        String retStr = null;
        if(g_iOldSpi == null || g_rOldSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEncEmpty pkt = new PktInfoEncEmpty(g_sulName + "/info_enc_empty_resp.xml", g_rOldSpi, g_iOldSpi, g_oldMsgId, g_oldKeyGen);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(g_oldKeyGen);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyEncInfoOldResp, RET: " + retStr);
        return retStr;
    }

    public String emptyInfoOldResp(){
        String retStr = null;
        if(g_iOldSpi == null || g_rOldSpi == null){
            retStr = ERROR;
        }else {
            PktInfoEmpty pkt = new PktInfoEmpty(g_sulName + "/info_empty_resp.xml", g_rOldSpi, g_iOldSpi, g_oldMsgId);
            byte[] pktBytes = pkt.getPacketBytes();

            beginBufferedOps();
            int round = g_RetryNum;
            while (round >= 0) {
                try {
                    //send(pktBytes);
                    bufferedSend(pktBytes, g_peerAddr, g_port);
                    g_wantedMsgId = g_oldMsgId;
                } catch (IOException e) {
                    LOGGER.error("Send UDP packet Error!");
                    e.printStackTrace();
                }
                try {
                    IKEv2Parser parser = bufferedReceive(null);
                    switch (parser.getType()) {
                        case IKEv2Parser.INIT:
                            IKEv2SaInitParser initParser = (IKEv2SaInitParser) parser;
                            retStr = initParser.parsePacket();
                            break;
                        case IKEv2Parser.AUTH:
                            IKEv2AuthParser authParser = (IKEv2AuthParser) parser;
                            retStr = authParser.parsePacket();
                            break;
                        case IKEv2Parser.CCSA:
                            IKEv2CreChSaParser ccsaParser = (IKEv2CreChSaParser) parser;
                            retStr = ccsaParser.parsePacket();
                            break;
                        case IKEv2Parser.INFO:
                            IKEv2InfoParser infoParser = (IKEv2InfoParser) parser;
                            retStr = infoParser.parsePacket();
                            break;
                        default:
                            LOGGER.error("Receive invalid exchange type: " + parser.getType());
                            System.exit(-1);
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                    //LOGGER.debug("Timeout in IKE_INIT_SA!");
                } catch (IOException e) {
                    LOGGER.error("UDP receive packet error! ");
                    e.printStackTrace();
                }
            }
            endBufferedOps();
        }

        LOGGER.info("emptyInfoOldResp, RET: " + retStr);
        return retStr;
    }

}
