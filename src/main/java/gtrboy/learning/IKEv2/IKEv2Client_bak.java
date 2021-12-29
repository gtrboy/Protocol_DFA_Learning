//package gtrboy.learning.IKEv2;
//
//import gtrboy.learning.IKEv2.messages.*;
//import gtrboy.learning.IKEv2.parsers.*;
//import gtrboy.learning.utils.DataUtils;
//import gtrboy.learning.utils.TelnetMain;
//import org.apache.logging.log4j.LogManager;
//import org.apache.logging.log4j.Logger;
//
//import java.io.IOException;
//import java.net.*;
//
//
//public class IKEv2Client_bak {
//
//    //private final IKEv2Config clientConf;
//    private final int g_RetryNum;
//    //private byte[] lastPkt;
//    private final String g_sulName;
//    private final String g_peerAddr;
//    private final String g_localAddr;
//    private final int g_port;
//    private final float g_Timeout;
//    private final int g_dhGrp;
//    private final String g_encAlg;
//    private final String g_hmacAlg;
//    private final String g_psk;
//
//
//
//    private byte[] g_iSpi = null;
//    private byte[] g_rSpi = null;
//    private byte[] g_iOldSpi = null;
//    private byte[] g_rOldSpi = null;
//    private byte[] g_iKe = null;
//    private byte[] g_iNnonce = null;
//    private byte[] g_rKe = null;
//    private byte[] g_rNonce = null;
//    private byte[] old_i_nonce = null;
//    private byte[] old_r_nonce = null;
//    private byte[] g_iInitSaPkt;
//    private byte[] g_iChildSpi;
//    private byte[] g_rChildSpi;
//    private byte[] g_iOldChildSpi;
//    private byte[] g_rOldChildSpi;
//    private int g_curMsgId = 0;
//    private int g_oldMsgId = 0;
//    private int g_wantedMsgId = 0;
//    private DatagramSocket _sock_;
//    private IKEv2KeysGener g_curKeyGen;
//    private IKEv2KeysGener g_oldKeyGen;
//    private final TelnetMain g_telnetClient;
//
//    private static final String TIMEOUT = "TIMEOUT";
//    private static final String ERROR = "ERROR";
//    private static final int NONCE_LEN = 20;
//    private static final int IPSEC_SPI_LEN = 4;
//    private static final int IKE_SPI_LEN = 8;
//
//    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);
//
//    public IKEv2Client_bak(IKEv2Config config) {
//        String telnetUserName;
//        String telnetPassword;
//
//        LOGGER.debug("CREATE IKEv2 CLIENT! ");
//        //clientConf = config;
//        g_peerAddr = config.getPeerAddress();
//        g_localAddr = config.getLocalAddress();
//        g_port = config.getPort();
//        g_Timeout = config.getTimeout();
//        g_RetryNum = config.getRetryNum();
//        g_sulName = config.getSul();
//        g_dhGrp = config.getDhGroup();
//        g_encAlg = config.getEncFunc();
//        g_hmacAlg = config.getHmacFunc();
//        g_psk = config.getPsk();
//
//        telnetUserName = config.getTelUser();
//        telnetPassword = config.getTelPass();
//        g_telnetClient = new TelnetMain(g_peerAddr, telnetUserName, telnetPassword, g_sulName);
//        g_telnetClient.connect();
//
//    }
//
//    private void addMsgId(boolean isCurrent){
//        if(isCurrent){
//            g_curMsgId += 1;
//        }else{
//            g_oldMsgId += 1;
//        }
//    }
//    private void resetMsgId(int id, boolean isCurrent) {
//        if(isCurrent){
//            g_curMsgId = id;
//        }else{
//            g_oldMsgId = id;
//        }
//    }
//
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
//    private boolean validatePkt(DatagramPacket packet){
//        boolean ret;
//        byte[] bPkt = packet.getData();
//        byte exchType = bPkt[18];
//        byte flags = bPkt[19];
//        int msgId = DataUtils.bytesToIntB(bPkt, 20);
//        LOGGER.debug("Msg Id: " + msgId);
//        // discard cmd del information packet or init request packet
//        if((exchType==0x25 && flags==0x00) || flags==0x08){
//            ret = false;
//        }else if(msgId!= g_wantedMsgId) {
//            ret = false;
//        }else {
//            ret = true;
//        }
//        return ret;
//    }
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
//
//    public void prepare() {
//        InitSocket();
//        saInitWithAcceptedSa();
//        //InitSPI();
//    }
//
//    public void reset() throws IOException {
//        //this.connect(internetAddress, port);
//        g_iSpi = null;
//        g_rSpi = null;
//        g_iOldSpi = null;
//        g_rOldSpi = null;
//        g_iChildSpi = null;
//        g_rChildSpi = null;
//        g_iOldChildSpi = null;
//        g_rOldChildSpi = null;
//        g_curMsgId = 0;
//        g_oldMsgId = 0;
//        g_wantedMsgId = 0;
//        g_curKeyGen = null;
//        g_oldKeyGen = null;
//        g_iKe = null;
//        g_rKe = null;
//        g_iNnonce = null;
//        g_rNonce = null;
//
//        // 通过telnet清除目标设备的ike sa
//        switch (g_sulName){
//            case "cisco7200":
//                g_telnetClient.resetCisco();
//                break;
//            case "fortigate":
//                g_telnetClient.resetFG();
//                break;
//            default:
//                LOGGER.error("Invalid SUL Name! ");
//                System.exit(-1);
//        }
//
//        _sock_.disconnect();
//        _sock_.close();
//        _sock_ = null;
//    }
//
//    public void InitSocket() {
//        try{
//            _sock_ = new DatagramSocket(500);
//            _sock_.setSoTimeout((int) (g_Timeout *1000));
//        } catch (SocketException e){
//            LOGGER.error("UDP socket init error! ");
//            e.printStackTrace();
//        }
//    }
//
//    private IKEv2KeysGener prepareKeyGen(){
//        return new IKEv2KeysGener(g_dhGrp, g_encAlg, g_hmacAlg, g_psk);
//    }
//
//    private void prepareInitSa(){
//        InitSPI();
//        g_curKeyGen = prepareKeyGen();
//        g_iKe = g_curKeyGen.getPubKey();
//        g_iNnonce = DataUtils.genRandomBytes(NONCE_LEN);
//        resetMsgId(0, true);
//    }
//
//    private void InitSPI() {
//        g_iSpi = DataUtils.genRandomBytes(IKE_SPI_LEN);
//        g_rSpi = DataUtils.genEmptyBytes(IKE_SPI_LEN);
//    }
//
//
//    /*************  Packets  **************/
//    public String saInitWithAcceptedSa(){
//        String retStr = null;
//        prepareInitSa();
//        PktIKEInitSA pkt = new PktIKEInitSA(g_sulName + "/ike_init_sa_acc_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_iKe, g_iNnonce);
//        byte[] pktBytes = pkt.getPacketBytes();
//
//        int round = g_RetryNum;
//        while(round>=0){
//            try{
//                send(pktBytes);
//                g_wantedMsgId = g_curMsgId;
//            } catch (IOException e){
//                LOGGER.error("Send UDP packet Error!");
//                e.printStackTrace();
//            }
//
//            try {
//                DatagramPacket rPkt =  receive();
//                IKEv2SaInitParser parser = new IKEv2SaInitParser(rPkt);
//                retStr = parser.parsePacket();
//
//                //if("RESP_IKE_INIT_SA".equals(retstr)){
//                if("OK".equals(retStr)){
//                    // For Authentication, store the INIT_SA packet first.
//                    g_iInitSaPkt = pktBytes;
//                    g_rSpi = parser.getRespSPI();
//                    g_rKe = parser.getPubKey();
//                    g_rNonce = parser.getNonce();
//                    g_curKeyGen.genKeys(g_iSpi, g_rSpi, g_iNnonce, g_rNonce, g_rKe);
//                    LOGGER.debug("ispi: " + DataUtils.bytesToHexStr(g_iSpi));
//                    LOGGER.debug("rspi: " + DataUtils.bytesToHexStr(g_rSpi));
//                    LOGGER.debug("r_ke: " + DataUtils.bytesToHexStr(g_rKe));
//                    LOGGER.debug("r_nonce: " + DataUtils.bytesToHexStr(g_rNonce));
//                }
//                addMsgId(true);
//                break;
//            } catch (SocketTimeoutException e){
//                retStr = TIMEOUT;
//                round--;
//                //LOGGER.debug("Timeout in IKE_INIT_SA!");
//            } catch (IOException e){
//                LOGGER.error("UDP receive packet error! ");
//                e.printStackTrace();
//            }
//        }
//
//        LOGGER.info("saInitWithAcceptedSA, RET: " + retStr);
//        return retStr;
//    }
//
//    public String authWithPsk(){
//        String retStr = null;
//        if(g_iSpi ==null || g_rSpi ==null ){
//            retStr = ERROR;
//        }else {
//            byte[] i_child_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
//            PktIKEAuthPSK pkt = new PktIKEAuthPSK(g_sulName + "/ike_auth_psk.xml", g_iSpi, g_rSpi, g_curMsgId,
//                    g_curKeyGen, g_rNonce, g_iInitSaPkt, g_localAddr, i_child_spi);
//            byte[] pktBytes = pkt.getPacketBytes();
//            int round = g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pktBytes);
//                    g_wantedMsgId = g_curMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error!");
//                    e.printStackTrace();
//                }
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2AuthParser parser = new IKEv2AuthParser(rPkt, g_curKeyGen);
//                    retStr = parser.parsePacket();
//                    //if("RESP_IKE_AUTH".equals(retStr)) {
//                    if ("OK".equals(retStr)) {
//                        g_iChildSpi = i_child_spi;
//                        g_rChildSpi = parser.getRChildSpi();
//                        //LOGGER.debug("Response child SPI: " + DataUtils.bytesToHexStr(rChildSpi));
//                    } else {
//                        g_iChildSpi = null;
//                    }
//                    addMsgId(true);
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//
//        }
//        LOGGER.info("authWithPsk, RET: " + retStr);
//        return retStr;
//    }
//
//
//    /* IKE SA Operations */
//    public String rekeyIkeSa(){
//        String retStr = null;
//        if(g_iSpi ==null || g_rSpi ==null ){
//            retStr = ERROR;
//        }else {
//            IKEv2KeysGener tmpKeyG = prepareKeyGen();
//            byte[] new_spi = DataUtils.genRandomBytes(IKE_SPI_LEN);
//            byte[] new_nc = DataUtils.genRandomBytes(NONCE_LEN);
//            byte[] new_ke = tmpKeyG.getPubKey();
//            PktRekeyIkeSa pkt = new PktRekeyIkeSa(g_sulName + "/cre_cld_sa_rekey_ike_sa.xml", g_iSpi, g_rSpi, g_curMsgId,
//                    g_curKeyGen, new_spi, new_nc, new_ke);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_curMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2RekeyIkeSaParser parser = new IKEv2RekeyIkeSaParser(rPkt, g_curKeyGen);
//                    retStr = parser.parsePacket();
//                    //if(retStr.equals("RESP_REKEY_IKE_SA")){
//                    if (retStr.equals("OK")) {
//                        g_iOldSpi = g_iSpi;
//                        g_iSpi = new_spi;
//                        g_rOldSpi = g_rSpi;
//                        g_rSpi = parser.getRSpi();
//                        old_i_nonce = g_iNnonce;
//                        g_iNnonce = new_nc;
//                        old_r_nonce = g_rNonce;
//                        g_rNonce = parser.getNonce();
//                        //oldKeyGen = curKeyGen;
//                        tmpKeyG.reGenKeys(g_curKeyGen.getSkD(), new_spi, parser.getRSpi(), new_nc, parser.getNonce(), parser.getKe());
//                        //tmpNewKeyGen = tmpKeyG;
//                        g_oldKeyGen = g_curKeyGen;
//                        g_curKeyGen = tmpKeyG;
//                        g_oldMsgId = g_curMsgId + 1;
//                        resetMsgId(0, true);
//                        //resetMsgId(0);
//                        LOGGER.debug("new iSPI: " + DataUtils.bytesToHexStr(g_iSpi));
//                        LOGGER.debug("new rSPI: " + DataUtils.bytesToHexStr(g_rSpi));
//                    } else {
//                        addMsgId(true);
//                    }
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//        }
//        LOGGER.info("rekeyIKESA, RET: " + retStr);
//        return retStr;
//    }
//
//    public String delCurIkeSa(){
//        String retStr = null;
//        if(g_iSpi ==null || g_rSpi ==null ){
//            retStr = ERROR;
//        }else {
//            PktDelIKESa pkt = new PktDelIKESa(g_sulName + "/info_del_ike_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_curKeyGen);
//            int round= g_RetryNum;
//            while (round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_curMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2InfoParser parser = new IKEv2InfoParser(rPkt, g_curKeyGen);
//                    retStr = parser.parsePacket();
//                    if ("OK".equals(retStr)) {
//                        resetMsgId(0, true);
//                        g_iSpi = null;
//                        g_rSpi = null;
//                        g_curKeyGen = null;
//                    } else {
//                        addMsgId(true);
//                    }
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//            //addMsgId();
//            //resetMsgId(0);
//        }
//        LOGGER.info("delCurIKESA, RET: " + retStr);
//        return retStr;
//    }
//
//    public String delOldIkeSa(){
//        String retStr = null;
//        if(g_iOldSpi ==null || g_rOldSpi ==null ){
//            retStr = ERROR;
//        }else {
//            PktDelIKESa pkt = new PktDelIKESa(g_sulName + "/info_del_ike_sa.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId, g_oldKeyGen);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_oldMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2InfoParser parser = new IKEv2InfoParser(rPkt, g_oldKeyGen);
//                    retStr = parser.parsePacket();
//                    //if("RESP_INFO_DEL_IKE_SA".equals(retStr)){
//                    if ("OK".equals(retStr)) {
//                        resetMsgId(0, false);
//                        g_iOldSpi = null;
//                        g_rOldSpi = null;
//                        g_oldKeyGen = null;
//                    } else {
//                        addMsgId(false);
//                    }
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//            //addMsgId();
//            //resetMsgId(0);
//        }
//        LOGGER.info("delOldIKESA, RET: " + retStr);
//        return retStr;
//    }
//
//
//    /* Child SA Operations */
//    public String rekeyChildSaWithCurIkeSa(){
//        String retStr = null;
//        if(g_iSpi ==null || g_rSpi ==null || g_iChildSpi ==null){
//            retStr = ERROR;
//        }else {
//            byte[] old_c_spi = null;
//            byte[] new_c_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
//            byte[] new_nc = DataUtils.genRandomBytes(NONCE_LEN);
//            if (g_iChildSpi != null) {
//                old_c_spi = g_iChildSpi;
//            } else {
//                old_c_spi = DataUtils.genRandomBytes(4);
//            }
//            PktRekeyChildSa pkt = new PktRekeyChildSa(g_sulName + "/cre_cld_sa_rekey_cld_sa.xml", g_iSpi, g_rSpi, g_curMsgId,
//                    g_curKeyGen, old_c_spi, new_c_spi, new_nc);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_curMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2RekeyChildSaParser parser = new IKEv2RekeyChildSaParser(rPkt, g_curKeyGen);
//                    retStr = parser.parsePacket();
//                    //if(retStr.equals("RESP_REKEY_Child_SA")){
//                    if (retStr.equals("OK")) {
//                        g_iOldChildSpi = g_iChildSpi;
//                        g_iChildSpi = new_c_spi;
//                        g_rOldChildSpi = g_rChildSpi;
//                        g_rChildSpi = parser.getRChildSpi();
//                        //old_i_nonce = i_nonce;
//                        //i_nonce = new_nc;
//                        //old_r_nonce = r_nonce;
//                        //r_nonce = parser.getRNonce();
//                    }
//                    addMsgId(true);
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//
//        }
//        LOGGER.info("rekeyChildSaWithCurIkeSa, RET: " + retStr);
//        return retStr;
//    }
//
//    public String rekeyChildSaWithOldIkeSa(){
//        String retStr = null;
//        if(g_iOldSpi ==null || g_rOldSpi ==null || g_iChildSpi ==null){
//            retStr = ERROR;
//        }else {
//            byte[] old_c_spi = null;
//            byte[] new_c_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
//            byte[] new_nc = DataUtils.genRandomBytes(NONCE_LEN);
//            if (g_iChildSpi != null) {
//                old_c_spi = g_iChildSpi;
//            } else {
//                old_c_spi = DataUtils.genRandomBytes(4);
//            }
//            PktRekeyChildSa pkt = new PktRekeyChildSa(g_sulName + "/cre_cld_sa_rekey_cld_sa.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId,
//                    g_oldKeyGen, old_c_spi, new_c_spi, new_nc);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_oldMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2RekeyChildSaParser parser = new IKEv2RekeyChildSaParser(rPkt, g_oldKeyGen);
//                    retStr = parser.parsePacket();
//                    //if(retStr.equals("RESP_REKEY_Child_SA")){
//                    if (retStr.equals("OK")) {
//                        g_iOldChildSpi = g_iChildSpi;
//                        g_iChildSpi = new_c_spi;
//                        g_rOldChildSpi = g_rChildSpi;
//                        g_rChildSpi = parser.getRChildSpi();
//                        //old_i_nonce = i_nonce;
//                        //i_nonce = new_nc;
//                        //old_r_nonce = r_nonce;
//                        //r_nonce = parser.getRNonce();
//                    }
//                    addMsgId(false);
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//
//        }
//        LOGGER.info("rekeyChildSaWithOldIkeSa, RET: " + retStr);
//        return retStr;
//    }
//
//    public String delCurChildSaWithCurIkeSa(){
//        String retStr = null;
//        if(g_iSpi ==null || g_rSpi ==null || g_iChildSpi ==null){
//            retStr = ERROR;
//        }else {
//
//            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_curKeyGen, g_iChildSpi);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_curMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2InfoParser parser = new IKEv2InfoParser(rPkt, g_curKeyGen);
//                    retStr = parser.parsePacket();
//                    if ("OK".equals(retStr)) {
//                        g_iChildSpi = null;
//                        g_rChildSpi = null;
//                    }
//                    addMsgId(true);
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//        }
//        LOGGER.info("delCurChildSaWithCurIkeSa, RET: " + retStr);
//        return retStr;
//    }
//
//    public String delCurChildSaWithOldIkeSa(){
//        String retStr = null;
//        if(g_iOldSpi ==null|| g_rOldSpi ==null || g_iChildSpi ==null){
//            retStr = ERROR;
//        }else {
//
//            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId, g_oldKeyGen, g_iChildSpi);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_oldMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2InfoParser parser = new IKEv2InfoParser(rPkt, g_oldKeyGen);
//                    retStr = parser.parsePacket();
//                    if ("OK".equals(retStr)) {
//                        g_iChildSpi = null;
//                        g_rChildSpi = null;
//                    }
//                    addMsgId(false);
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//        }
//        LOGGER.info("delCurChildSaWithOldIkeSa, RET: " + retStr);
//        return retStr;
//    }
//
//    public String delOldChildSaWithCurIkeSa(){
//        String retStr = null;
//        if(g_iSpi ==null || g_rSpi ==null || g_iOldChildSpi ==null){
//            retStr = ERROR;
//        }else {
//
//            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iSpi, g_rSpi, g_curMsgId, g_curKeyGen, g_iOldChildSpi);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_curMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2InfoParser parser = new IKEv2InfoParser(rPkt, g_curKeyGen);
//                    retStr = parser.parsePacket();
//                    if ("OK".equals(retStr)) {
//                        g_iOldChildSpi = null;
//                        g_rOldChildSpi = null;
//                    }
//                    addMsgId(true);
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//        }
//        LOGGER.info("delOldChildSaWithCurIkeSa, RET: " + retStr);
//        return retStr;
//    }
//
//    public String delOldChildSaWithOldIkeSa(){
//        String retStr = null;
//        if(g_iOldSpi ==null|| g_rOldSpi ==null || g_iOldChildSpi ==null){
//            retStr = ERROR;
//        }else {
//            PktDelChildSa pkt = new PktDelChildSa(g_sulName + "/info_del_cld_sa.xml", g_iOldSpi, g_rOldSpi, g_oldMsgId, g_oldKeyGen, g_iOldChildSpi);
//            int round= g_RetryNum;
//            while(round>=0) {
//                try {
//                    send(pkt.getPacketBytes());
//                    g_wantedMsgId = g_oldMsgId;
//                } catch (IOException e) {
//                    LOGGER.error("Send UDP packet Error! ");
//                    e.printStackTrace();
//                }
//
//                try {
//                    DatagramPacket rPkt = receive();
//                    IKEv2InfoParser parser = new IKEv2InfoParser(rPkt, g_oldKeyGen);
//                    retStr = parser.parsePacket();
//                    if ("OK".equals(retStr)) {
//                        g_iOldChildSpi = null;
//                        g_rOldChildSpi = null;
//                    }
//                    addMsgId(false);
//                    break;
//                } catch (SocketTimeoutException e) {
//                    retStr = TIMEOUT;
//                    round--;
//                } catch (IOException e) {
//                    LOGGER.error("UDP receive packet error! ");
//                    e.printStackTrace();
//                }
//            }
//        }
//        LOGGER.info("delOldChildSaWithOldIkeSa, RET: " + retStr);
//        return retStr;
//
//    }
//
//
//
//
//
//
//
//
//    public String malformedIKEAuth(){
//        String retstr = null;
//        PktMalformed pkt = new PktMalformed("malformed_ike_auth.xml", g_iSpi, g_rSpi, g_curMsgId);
//        byte[] pktBytes = pkt.getPacketBytes();
//        // For Authentication, store the INIT_SA packet first.
//        //iInitSaPkt = pktBytes;
//
//        try{
//            send(pktBytes);
//        } catch (IOException e){
//            LOGGER.error("Send UDP packet Error!");
//            e.printStackTrace();
//        }
//
//        try {
//            DatagramPacket rPkt =  receive();
//
//
//        } catch (SocketTimeoutException e){
//            retstr = TIMEOUT;
//        } catch (IOException e){
//            LOGGER.error("UDP receive packet error! ");
//            e.printStackTrace();
//        }
//
//        addMsgId(true);
//        return retstr;
//    }
//
//    public String malformedRekeyIKE(){
//        String retstr = null;
//        PktMalformed pkt = new PktMalformed("malformed_cre_cld_sa_rekey_ike.xml", g_iSpi, g_rSpi, g_curMsgId);
//        byte[] pktBytes = pkt.getPacketBytes();
//        // For Authentication, store the INIT_SA packet first.
//        //iInitSaPkt = pktBytes;
//
//        try{
//            send(pktBytes);
//        } catch (IOException e){
//            LOGGER.error("Send UDP packet Error!");
//            e.printStackTrace();
//        }
//
//        try {
//            DatagramPacket rPkt =  receive();
//
//
//        } catch (SocketTimeoutException e){
//            retstr = TIMEOUT;
//        } catch (IOException e){
//            LOGGER.error("UDP receive packet error! ");
//            e.printStackTrace();
//        }
//
//        addMsgId(true);
//        return retstr;
//    }
//
//
//
//
//    public String infoCPReqAppverwithOldSA(){
//        return null;
//    }
//
//    public String infoCPReqAppverwithNewSA(){
//        return null;
//    }
//}
