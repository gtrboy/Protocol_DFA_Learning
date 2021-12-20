package gtrboy.learning.IKEv2;

import gtrboy.learning.IKEv2.messages.*;
import gtrboy.learning.IKEv2.parsers.*;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;

import java.io.IOException;
import java.net.*;

import gtrboy.learning.utils.TelnetMain;


public class IKEv2Client {

    private IKEv2Config clientConf;
    private byte[] ispi = null;
    private byte[] rspi = null;
    private byte[] iOldSpi = null;
    private byte[] rOldSpi = null;
    private byte[] i_ke = null;
    private byte[] i_nonce = null;
    private byte[] r_ke = null;
    private byte[] r_nonce = null;
    private byte[] old_i_nonce = null;
    private byte[] old_r_nonce = null;
    private int curMsgId = 0;
    private int oldMsgId = 0;
    private int wantedMsgId = 0;
    private String peeraddr;
    private String localaddr;
    private int port;
    private float timeout;
    private DatagramSocket ds;
    //IKEv2Parser parser;
    private IKEv2KeysGener curKeyGen;
    private IKEv2KeysGener oldKeyGen;
    private byte[] iInitSaPkt;
    private byte[] iChildSpi;
    private byte[] rChildSpi;
    private byte[] iOldChildSpi;
    private byte[] rOldChildSpi;
    private String telnetPassword;
    private TelnetMain ciscoTel;
    private int gRetryNum=0;
    //private byte[] lastPkt;


    private static final String TIMEOUT = "TIMEOUT";
    private static final String ERROR = "ERROR";
    private static final String CISCO_RESET_CMD = "clear crypto ikev2 sa fast";
    private static final int NONCE_LEN = 20;
    private static final int IPSEC_SPI_LEN = 4;
    private static final int IKE_SPI_LEN = 8;
    // private static final int RETRY_NUM = 3;
    private static final boolean OLD_SA = false;
    private static final boolean CUR_SA = true;


    public IKEv2Client(IKEv2Config config) {
        LogUtils.logDebug(this.getClass().getName(), "CREATE IKEv2 CLIENT! ");
        clientConf = config;
        curMsgId = 0;
        peeraddr = config.getPeerAddress();
        localaddr = config.getLocalAddress();
        port = config.getPort();
        timeout = config.getTimeout();
        telnetPassword = config.getTelPass();
        gRetryNum = config.getRetryNum();
        ciscoTel = new TelnetMain(peeraddr, telnetPassword);
        ciscoTel.connect();

        //curKeyGen = prepareKeyGen(config);

        //prepare();
    }

    private IKEv2KeysGener prepareKeyGen(IKEv2Config config){

        int dhGroup = config.getDhGroup();
        String prfAlg = config.getPrfFunc();
        String intgAlg = config.getIntgFunc();
        String psk = config.getPsk();
        int integ_key_len = config.getIntegKeyLen();
        int enc_key_len = config.getEncKeyLen();
        int prf_key_len = config.getPrfKeyLen();
        int aes_block_size = config.getAESBlockSize();

        // Initialize key generator
        IKEv2KeysGener keyGen = new IKEv2KeysGener(dhGroup, prfAlg, intgAlg, psk, integ_key_len, enc_key_len, prf_key_len, aes_block_size);
        return keyGen;
    }

    private void addMsgId(boolean isCurrent){
        if(isCurrent){
            curMsgId += 1;
        }else{
            oldMsgId += 1;
        }
    }
    private void resetMsgId(int id, boolean isCurrent) {
        if(isCurrent){
            curMsgId = id;
        }else{
            oldMsgId = id;
        }
    }

    private void send(byte[] data) throws IOException {
        try {
            InetSocketAddress peerSocketAddr = new InetSocketAddress(peeraddr, port);
            DatagramPacket packet = new DatagramPacket(data, data.length, peerSocketAddr);
            // DatagramSocket udpSock = new DatagramSocket();
            ds.send(packet);
            // udpSock.close();
        } catch (Exception e) {
            LogUtils.logException(e, this.getClass().getName(), "UDP socket send Error! ");
        }
    }

    private DatagramPacket receive() throws IOException {
        byte[] buffer = new byte[1024];
        int msgId = 0;
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        while(true) {
            ds.receive(packet);
            byte[] bPkt = packet.getData();
            msgId = DataUtils.bytesToIntB(bPkt, 20);
            LogUtils.logDebug(this.getClass().getName(), "Msg Id: " + msgId);
            // discard cmd del information packet
            if(bPkt[18]==0x25 && bPkt[19]==0x00){

            }else if(msgId!=wantedMsgId) {

            }else {
                break;
            }
        }
        return packet;
    }

    /*
    private String receive() throws IOException {
        byte[] buffer = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        ds.receive(packet);

        byte

        //return packet;
    }

     */


    public void prepare() {
        InitSocket();
        saInitWithAcceptedSa();
        //InitSPI();
    }

    public void reset() throws IOException {
        //this.connect(internetAddress, port);
        ispi = null;
        rspi = null;
        iOldSpi = null;
        rOldSpi = null;
        iChildSpi = null;
        rChildSpi = null;
        iOldChildSpi = null;
        rOldChildSpi = null;
        curMsgId = 0;
        oldMsgId = 0;
        wantedMsgId = 0;
        curKeyGen = null;
        oldKeyGen = null;
        i_ke = null;
        r_ke = null;
        i_nonce = null;
        r_nonce = null;

        // 通过telnet清除目标设备的ike sa
        //ciscoTelRemoveSa();
        ciscoTel.sendCommand(CISCO_RESET_CMD);
        ds.disconnect();
        ds.close();
        ds = null;
    }

    private void resetSocketBuffer(){
        ds.disconnect();
    }

    private void InitSocket() {
        try{
            ds = new DatagramSocket(500);
            ds.setSoTimeout((int) (timeout*1000));
        } catch (SocketException e){
            LogUtils.logException(e, this.getClass().getName(), "UDP socket init error! ");
        }

    }

    private void prepareInitSa(){
        InitSPI();
        curKeyGen = prepareKeyGen(clientConf);
        i_ke = curKeyGen.getPubKey();
        i_nonce = DataUtils.genRandomBytes(NONCE_LEN);
        resetMsgId(0, true);
    }

    private void InitSPI() {
        ispi = DataUtils.genRandomBytes(IKE_SPI_LEN);
        rspi = DataUtils.genEmptyBytes(IKE_SPI_LEN);
    }

    /*
    public void ciscoTelRemoveSa(){
        TelnetMain tel = new TelnetMain(peeraddr, telnetPassword);
        tel.connect();
        tel.sendCommand(CISCO_RESET_CMD);
        tel.disconnect();
    }

     */



    /*************  Packets  **************/

    public String saInitWithAcceptedSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "saInitWithAcceptedSA Start.");
        String retStr = null;
        prepareInitSa();
        byte[] respSPI = DataUtils.hexStrToBytes("0000000000000000");
        PktIKEInitSA pkt = new PktIKEInitSA("ike_init_sa_acc_sa.xml", ispi, respSPI, curMsgId, i_ke, i_nonce);
        byte[] pktBytes = pkt.getPacketBytes();

        int round = gRetryNum;
        while(round>=0){
            try{
                send(pktBytes);
                wantedMsgId = curMsgId;
            } catch (IOException e){
                LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error!");
            }

            try {
                DatagramPacket rPkt =  receive();
                IKEv2SaInitParser parser = new IKEv2SaInitParser(rPkt);
                retStr = parser.parsePacket();

                //if("RESP_IKE_INIT_SA".equals(retstr)){
                if("OK".equals(retStr)){
                    // For Authentication, store the INIT_SA packet first.
                    iInitSaPkt = pktBytes;
                    rspi = parser.getRespSPI();
                    r_ke = parser.getPubKey();
                    r_nonce = parser.getNonce();
                    curKeyGen.genKeys(ispi, rspi, i_nonce, r_nonce, r_ke);
                    LogUtils.logDebug(this.getClass().getName(), "ispi: " + DataUtils.bytesToHexStr(ispi));
                    LogUtils.logDebug(this.getClass().getName(), "rspi: " + DataUtils.bytesToHexStr(rspi));
                    LogUtils.logDebug(this.getClass().getName(), "r_ke: " + DataUtils.bytesToHexStr(r_ke));
                    LogUtils.logDebug(this.getClass().getName(), "r_nonce: " + DataUtils.bytesToHexStr(r_nonce));
                }
                addMsgId(true);
                break;
            } catch (SocketTimeoutException e){
                retStr = TIMEOUT;
                round--;
                //LogUtils.logDebug(this.getClass().getName(), "Timeout in IKE_INIT_SA!");
            } catch (IOException e){
                LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
            }
        }

        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "saInitWithAcceptedSA End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String authWithPsk(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "authWithPsk Start.");

        String retStr = null;
        if(ispi==null || rspi==null ){
            retStr = ERROR;
        }else {
            byte[] i_child_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
            PktIKEAuthPSK pkt = new PktIKEAuthPSK("ike_auth_psk.xml", ispi, rspi, curMsgId,
                    curKeyGen, r_nonce, iInitSaPkt, localaddr, i_child_spi);
            byte[] pktBytes = pkt.getPacketBytes();
            int round = gRetryNum;
            while(round>=0) {
                try {
                    send(pktBytes);
                    wantedMsgId = curMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error!");
                }
                try {
                    DatagramPacket rPkt = receive();
                    IKEv2AuthParser parser = new IKEv2AuthParser(rPkt, curKeyGen);
                    retStr = parser.parsePacket();
                    //if("RESP_IKE_AUTH".equals(retStr)) {
                    if ("OK".equals(retStr)) {
                        iChildSpi = i_child_spi;
                        rChildSpi = parser.getRChildSpi();
                        //LogUtils.logDebug(this.getClass().getName(), "Response child SPI: " + DataUtils.bytesToHexStr(rChildSpi));
                    } else {
                        iChildSpi = null;
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }

        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "authWithPsk End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }


    /* IKE SA Operations */
    public String rekeyIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "rekeyIKESA Start.");
        String retStr = null;
        if(ispi==null || rspi==null ){
            retStr = ERROR;
        }else {
            IKEv2KeysGener tmpKeyG = prepareKeyGen(clientConf);
            byte[] new_spi = DataUtils.genRandomBytes(IKE_SPI_LEN);
            byte[] new_nc = DataUtils.genRandomBytes(NONCE_LEN);
            byte[] new_ke = tmpKeyG.getPubKey();
            PktRekeyIkeSa pkt = new PktRekeyIkeSa("cre_cld_sa_rekey_ike_sa.xml", ispi, rspi, curMsgId,
                    curKeyGen, new_spi, new_nc, new_ke);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = curMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2RekeyIkeSaParser parser = new IKEv2RekeyIkeSaParser(rPkt, curKeyGen);
                    retStr = parser.parsePacket();
                    //if(retStr.equals("RESP_REKEY_IKE_SA")){
                    if (retStr.equals("OK")) {
                        iOldSpi = ispi;
                        ispi = new_spi;
                        rOldSpi = rspi;
                        rspi = parser.getRSpi();
                        old_i_nonce = i_nonce;
                        i_nonce = new_nc;
                        old_r_nonce = r_nonce;
                        r_nonce = parser.getNonce();
                        //oldKeyGen = curKeyGen;
                        tmpKeyG.reGenKeys(curKeyGen.getSkD(), new_spi, parser.getRSpi(), new_nc, parser.getNonce(), parser.getKe());
                        //tmpNewKeyGen = tmpKeyG;
                        oldKeyGen = curKeyGen;
                        curKeyGen = tmpKeyG;
                        oldMsgId = curMsgId + 1;
                        resetMsgId(0, true);
                        //resetMsgId(0);
                        LogUtils.logInfo(this.getClass().getName(), "new iSPI: " + DataUtils.bytesToHexStr(ispi));
                        LogUtils.logInfo(this.getClass().getName(), "new rSPI: " + DataUtils.bytesToHexStr(rspi));
                    } else {
                        addMsgId(true);
                    }
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }
        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "rekeyIKESA End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String delCurIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "delCurIKESA Start.");
        String retStr = null;
        if(ispi==null || rspi==null ){
            retStr = ERROR;
        }else {
            PktDelIKESa pkt = new PktDelIKESa("info_del_ike_sa.xml", ispi, rspi, curMsgId, curKeyGen);
            int round=gRetryNum;
            while (round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = curMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2DelParser parser = new IKEv2DelParser(rPkt, curKeyGen);
                    retStr = parser.parsePacket();
                    if ("OK".equals(retStr)) {
                        resetMsgId(0, true);
                        ispi = null;
                        rspi = null;
                        curKeyGen = null;
                    } else {
                        addMsgId(true);
                    }
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }
            //addMsgId();
            //resetMsgId(0);
        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "delCurIKESA End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String delOldIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "delOldIKESA Start.");
        String retStr = null;
        if(iOldSpi==null || rOldSpi==null ){
            retStr = ERROR;
        }else {
            PktDelIKESa pkt = new PktDelIKESa("info_del_ike_sa.xml", iOldSpi, rOldSpi, oldMsgId, oldKeyGen);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = oldMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2DelParser parser = new IKEv2DelParser(rPkt, oldKeyGen);
                    retStr = parser.parsePacket();
                    //if("RESP_INFO_DEL_IKE_SA".equals(retStr)){
                    if ("OK".equals(retStr)) {
                        resetMsgId(0, false);
                        iOldSpi = null;
                        rOldSpi = null;
                        oldKeyGen = null;
                    } else {
                        addMsgId(false);
                    }
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }
            //addMsgId();
            //resetMsgId(0);
        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "delOldIKESA End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }


    /* Child SA Operations */
    public String rekeyChildSaWithCurIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "rekeyChildSaWithCurIkeSa Start.");
        String retStr = null;
        if(ispi==null || rspi==null ){
            retStr = ERROR;
        }else {
            byte[] old_c_spi = null;
            byte[] new_c_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
            byte[] new_nc = DataUtils.genRandomBytes(NONCE_LEN);
            if (iChildSpi != null) {
                old_c_spi = iChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }
            PktRekeyChildSa pkt = new PktRekeyChildSa("cre_cld_sa_rekey_cld_sa.xml", ispi, rspi, curMsgId,
                    curKeyGen, old_c_spi, new_c_spi, new_nc);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = curMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2RekeyChildSaParser parser = new IKEv2RekeyChildSaParser(rPkt, curKeyGen);
                    retStr = parser.parsePacket();
                    //if(retStr.equals("RESP_REKEY_Child_SA")){
                    if (retStr.equals("OK")) {
                        iOldChildSpi = iChildSpi;
                        iChildSpi = new_c_spi;
                        rOldChildSpi = rChildSpi;
                        rChildSpi = parser.getRChildSpi();
                        //old_i_nonce = i_nonce;
                        //i_nonce = new_nc;
                        //old_r_nonce = r_nonce;
                        //r_nonce = parser.getRNonce();
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }

        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "rekeyChildSaWithCurIkeSa End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String rekeyChildSaWithOldIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "rekeyChildSaWithOldIkeSa Start.");
        String retStr = null;
        if(iOldSpi==null || rOldSpi==null ){
            retStr = ERROR;
        }else {
            byte[] old_c_spi = null;
            byte[] new_c_spi = DataUtils.genRandomBytes(IPSEC_SPI_LEN);
            byte[] new_nc = DataUtils.genRandomBytes(NONCE_LEN);
            if (iChildSpi != null) {
                old_c_spi = iChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }
            PktRekeyChildSa pkt = new PktRekeyChildSa("cre_cld_sa_rekey_cld_sa.xml", iOldSpi, rOldSpi, oldMsgId,
                    oldKeyGen, old_c_spi, new_c_spi, new_nc);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = oldMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2RekeyChildSaParser parser = new IKEv2RekeyChildSaParser(rPkt, oldKeyGen);
                    retStr = parser.parsePacket();
                    //if(retStr.equals("RESP_REKEY_Child_SA")){
                    if (retStr.equals("OK")) {
                        iOldChildSpi = iChildSpi;
                        iChildSpi = new_c_spi;
                        rOldChildSpi = rChildSpi;
                        rChildSpi = parser.getRChildSpi();
                        //old_i_nonce = i_nonce;
                        //i_nonce = new_nc;
                        //old_r_nonce = r_nonce;
                        //r_nonce = parser.getRNonce();
                    }
                    addMsgId(false);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }

        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "rekeyChildSaWithOldIkeSa End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String delCurChildSaWithCurIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "delCurChildSaWithCurIkeSa Start.");
        String retStr = null;
        if(ispi==null || rspi==null){
            retStr = ERROR;
        }else {
            byte[] old_c_spi;
            if (iChildSpi != null) {
                old_c_spi = iChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }

            PktDelChildSa pkt = new PktDelChildSa("info_del_cld_sa.xml", ispi, rspi, curMsgId, curKeyGen, old_c_spi);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = curMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2DelParser parser = new IKEv2DelParser(rPkt, curKeyGen);
                    retStr = parser.parsePacket();
                    if ("OK".equals(retStr)) {
                        iChildSpi = null;
                        rChildSpi = null;
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }
        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "delCurChildSaWithCurIkeSa End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String delCurChildSaWithOldIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "delCurChildSaWithOldIkeSa Start.");
        String retStr = null;
        if(iOldSpi==null||rOldSpi==null){
            retStr = ERROR;
        }else {
            byte[] old_c_spi;

            if (iChildSpi != null) {
                old_c_spi = iChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }

            PktDelChildSa pkt = new PktDelChildSa("info_del_cld_sa.xml", iOldSpi, rOldSpi, oldMsgId, oldKeyGen, old_c_spi);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = oldMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2DelParser parser = new IKEv2DelParser(rPkt, oldKeyGen);
                    retStr = parser.parsePacket();
                    if ("OK".equals(retStr)) {
                        iChildSpi = null;
                        rChildSpi = null;
                    }
                    addMsgId(false);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }
        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "delCurChildSaWithOldIkeSa End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String delOldChildSaWithCurIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "delOldChildSaWithCurIkeSa Start.");
        String retStr = null;
        if(ispi==null || rspi==null ){
            retStr = ERROR;
        }else {
            byte[] old_c_spi;
            if (iOldChildSpi != null) {
                old_c_spi = iOldChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }

            PktDelChildSa pkt = new PktDelChildSa("info_del_cld_sa.xml", ispi, rspi, curMsgId, curKeyGen, old_c_spi);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = curMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2DelParser parser = new IKEv2DelParser(rPkt, curKeyGen);
                    retStr = parser.parsePacket();
                    if ("OK".equals(retStr)) {
                        iOldChildSpi = null;
                        rOldChildSpi = null;
                    }
                    addMsgId(true);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }
        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "delOldChildSaWithCurIkeSa End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;
    }

    public String delOldChildSaWithOldIkeSa(){
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        LogUtils.logInfo(this.getClass().getName(), "delOldChildSaWithOldIkeSa Start.");
        String retStr = null;
        if(iOldSpi==null||rOldSpi==null){
            retStr = ERROR;
        }else {
            byte[] old_c_spi;
            if (iOldChildSpi != null) {
                old_c_spi = iOldChildSpi;
            } else {
                old_c_spi = DataUtils.genRandomBytes(4);
            }

            PktDelChildSa pkt = new PktDelChildSa("info_del_cld_sa.xml", iOldSpi, rOldSpi, oldMsgId, oldKeyGen, old_c_spi);
            int round=gRetryNum;
            while(round>=0) {
                try {
                    send(pkt.getPacketBytes());
                    wantedMsgId = oldMsgId;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error! ");
                }

                try {
                    DatagramPacket rPkt = receive();
                    IKEv2DelParser parser = new IKEv2DelParser(rPkt, oldKeyGen);
                    retStr = parser.parsePacket();
                    if ("OK".equals(retStr)) {
                        iOldChildSpi = null;
                        rOldChildSpi = null;
                    }
                    addMsgId(false);
                    break;
                } catch (SocketTimeoutException e) {
                    retStr = TIMEOUT;
                    round--;
                } catch (IOException e) {
                    LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
                }
            }
        }
        LogUtils.logInfo(this.getClass().getName(), "Return Value: " + retStr);
        LogUtils.logInfo(this.getClass().getName(), "delOldChildSaWithOldIkeSa End.");
        LogUtils.logInfo(this.getClass().getName(), "***********************************");
        return retStr;

    }








    public String malformedIKEAuth(){
        String retstr = null;
        PktMalformed pkt = new PktMalformed("malformed_ike_auth.xml", ispi, rspi, curMsgId);
        byte[] pktBytes = pkt.getPacketBytes();
        // For Authentication, store the INIT_SA packet first.
        //iInitSaPkt = pktBytes;

        try{
            send(pktBytes);
        } catch (IOException e){
            LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error!");
        }

        try {
            DatagramPacket rPkt =  receive();


        } catch (SocketTimeoutException e){
            retstr = TIMEOUT;
        } catch (IOException e){
            LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
        }

        addMsgId(true);
        return retstr;
    }

    public String malformedRekeyIKE(){
        String retstr = null;
        PktMalformed pkt = new PktMalformed("malformed_cre_cld_sa_rekey_ike.xml", ispi, rspi, curMsgId);
        byte[] pktBytes = pkt.getPacketBytes();
        // For Authentication, store the INIT_SA packet first.
        //iInitSaPkt = pktBytes;

        try{
            send(pktBytes);
        } catch (IOException e){
            LogUtils.logException(e, this.getClass().getName(), "Send UDP packet Error!");
        }

        try {
            DatagramPacket rPkt =  receive();


        } catch (SocketTimeoutException e){
            retstr = TIMEOUT;
        } catch (IOException e){
            LogUtils.logException(e, this.getClass().getName(), "UDP receive packet error! ");
        }

        addMsgId(true);
        return retstr;
    }




    public String infoCPReqAppverwithOldSA(){
        return null;
    }

    public String infoCPReqAppverwithNewSA(){
        return null;
    }
}
