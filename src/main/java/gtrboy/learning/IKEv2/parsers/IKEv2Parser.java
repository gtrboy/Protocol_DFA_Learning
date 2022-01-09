package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2Exception;
import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.IKEv2.messages.PktIKEInitSA;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.commons.net.tftp.TFTPPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.*;
import java.util.HashMap;


public abstract class IKEv2Parser {
    public byte eType;
    protected byte[] pb;
    //protected int pLen;
    protected byte nPld;
    protected int offset = 0;

    private final byte[] initSPI;
    private final byte[] respSPI;
    private final byte[] finalPacketBytes;

    private int g_type;

    protected short notifyType = 0;
    protected byte[] notifyData = null;

    protected IKEv2KeysGener keyG;

    protected static final int NOTIFY_ERROR_MAX = 16383;
    private static final int MIN_PACKET_SIZE = 28;

    public static final int INIT = 1;
    public static final int AUTH = 2;
    public static final int CCSA = 3;
    public static final int INFO = 4;

    protected static final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);


    public static final HashMap<Integer, String> NOTIFY_TYPES = new HashMap<Integer, String>(){{
        put(1, "UNSUPPORTED_CRITICAL_PAYLOAD");
        put(4, "INVALID_IKE_SPI");
        put(5, "INVALID_MAJOR_VERSION");
        put(7, "INVALID_SYNTAX");
        put(9, "INVALID_MESSAGE_ID");
        put(11, "INVALID_SPI");
        put(14, "NO_PROPOSAL_CHOSEN");
        put(17, "INVALID_KE_PAYLOAD");
        put(24, "AUTHENTICATION_FAILED");
        put(34, "SINGLE_PAIR_REQUIRED");
        put(35, "NO_ADDITIONAL_SAS");
        put(36, "INTERNAL_ADDRESS_FAILURE");
        put(37, "FAILED_CP_REQUIRED");
        put(38, "TS_UNACCEPTABLE");
        put(39, "INVALID_SELECTORS");
        put(40, "UNACCEPTABLE_ADDRESSES");
        put(41, "UNEXPECTED_NAT_DETECTED");
        put(42, "USE_ASSIGNED_HoA");
        put(43, "TEMPORARY_FAILURE");
        put(44, "CHILD_SA_NOT_FOUND");
        put(45, "INVALID_GROUP_ID");
        put(46, "AUTHORIZATION_FAILED");
        put(16388, "NAT_DETECTION_SOURCE_IP");
        put(16389, "NAT_DETECTION_DESTINATION_IP");
        put(16393, "REKEY_SA");
    }};


    public IKEv2Parser(final int type, DatagramPacket pkt, IKEv2KeysGener keysGener){
        g_type = type;
        initSPI = new byte[8];
        respSPI = new byte[8];
        keyG = keysGener;
        pb = pkt.getData();
        finalPacketBytes = pb;
        //pLen = pkt.getLength();
        parseIKEv2Hdr();
    }

    public static IKEv2Parser newIKEv2Parser(DatagramPacket datagram, IKEv2KeysGener keysGener) {
        byte[] data;
        IKEv2Parser packet = null;

        if(datagram.getLength() < MIN_PACKET_SIZE){
            LOGGER.error("Bad packet. Datagram data length is too short.");
            System.exit(-1);
        }

        data = datagram.getData();
        byte excgType = data[18];

        switch (excgType){
            case 0x22:
                packet =  new IKEv2SaInitParser(datagram);
                break;
            case 0x23:
                packet = new IKEv2AuthParser(datagram, keysGener);
                break;
            case 0x24:
                packet = new IKEv2CreChSaParser(datagram, keysGener);
                break;
            case 0x25:
                packet  = new IKEv2InfoParser(datagram, keysGener);
                break;
            default:
                LOGGER.error("Invalid exchange type!");
                System.exit(-1);
        }
        return packet;
    }


    public abstract String parsePacket();


    protected void parseIKEv2Hdr(){
        System.arraycopy(pb, 0, initSPI, 0, 8);
        System.arraycopy(pb, 8, respSPI, 0, 8);
        nPld = pb[16];
        eType = pb[18];
        //totalLen = DataUtils.bytesToIntB(pb, 24);
        offset = 28;
    }

    public byte[] getRespSPI(){
        if (respSPI != null){
            return respSPI;
        }
        else{
            LOGGER.error("Response SPI is null! ");
            System.exit(-1);
        }
        return null;
    }

    protected void parseDefault(){
        int pLen = parsePayloadHdr();
        AO(pLen - 4);
    }

    protected void parseNotifyPayload(){
        int pLen = parsePayloadHdr();
        AO(1);
        int spiSize = (int) pb[AO(1)];
        notifyType = DataUtils.bytesToShortB(pb, AO(2));
        int notDataLen = pLen - 8;
        if(notDataLen > 0) {
            notifyData = new byte[notDataLen];
            System.arraycopy(pb, AO(notDataLen), notifyData, 0, notDataLen);
        }

    }

    protected int parsePayloadHdr(){
        //byte[] pHdr = new byte[4];
        short pLen;
        nPld = pb[AO(1)];
        AO(1);
        pLen = DataUtils.bytesToShortB(pb, AO(2));
        return pLen;
    }

    protected final int AO(int v){
        int oldOffset = offset;
        offset += v;
        return oldOffset;
    }

    protected void parseEncPayload() throws Exception {
        byte[] decData;
        int payLen = parsePayloadHdr();
        //LOGGER.debug("Enc Payload Length: " + payLen);
        // Initialization Vector
        byte[] peerIV = parseIV();
        //LOGGER.debug("IV: " + DataUtils.bytesToHexStr(peerIV));
        int ivLen = peerIV.length;
        int checksumLen = keyG.getChecksumLen();
        int encDataLen = payLen - ivLen - checksumLen - 4;
        //LOGGER.debug("encDataLen: " + encDataLen);

        decData = parseDecData(encDataLen, peerIV);
        LOGGER.debug("Dec Data: " + DataUtils.bytesToHexStr(decData));
        //LOGGER.debug("DECDATA: "+DataUtils.bytesToHexStr(decData));
        pb = decData;
        offset = 0;
    }

    private byte[] parseIV(){
        int ivLen = keyG.getIVLen();
        byte[] iv = new byte[ivLen];
        System.arraycopy(pb, AO(ivLen), iv, 0, ivLen);
        return iv;
    }

    private byte[] parseDecData(int dataLen, byte[] iv) throws Exception {
        byte[] encData = new byte[dataLen];
        System.arraycopy(pb, AO(dataLen), encData, 0, dataLen);
        return keyG.decrypt(encData, keyG.getSkEr(), iv);
    }

    public int getType(){
        return g_type;
    }

    public byte[] getPktBytes(){
        return finalPacketBytes;
    }
}
