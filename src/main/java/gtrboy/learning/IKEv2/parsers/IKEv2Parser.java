package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.messages.PktIKEInitSA;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;

import java.net.*;
import java.util.HashMap;


public class IKEv2Parser {
    public byte eType;
    protected byte[] pb;
    //protected int pLen;
    protected byte nPld;
    protected int offset = 0;

    private byte[] initSPI;
    private byte[] respSPI;

    private int totalLen = 0;
    // private int remainedLen = 0;

    protected short notifyType = 0;
    protected byte[] notifyData = null;

    protected static final int NOTIFY_ERROR_MAX = 16383;

    /*
    public @interface NotifyType {}
    public static final int UNSUPPORTED_CRITICAL_PAYLOAD = 1;
    public static final int INVALID_IKE_SPI = 4;
    public static final int INVALID_MAJOR_VERSION = 5;
    public static final int INVALID_SYNTAX = 7;
    public static final int INVALID_MESSAGE_ID = 9;
    public static final int INVALID_SPI = 11;
    public static final int NO_PROPOSAL_CHOSEN = 14;
    public static final int INVALID_KE_PAYLOAD = 17;
    public static final int AUTHENTICATION_FAILED = 24;
    public static final int SINGLE_PAIR_REQUIRED = 34;
    public static final int NO_ADDITIONAL_SAS = 35;
    public static final int INTERNAL_ADDRESS_FAILURE = 36;
    public static final int FAILED_CP_REQUIRED = 37;
    public static final int TS_UNACCEPTABLE = 38;
    public static final int INVALID_SELECTORS = 39;
    public static final int TEMPORARY_FAILURE = 43;
    public static final int CHILD_SA_NOT_FOUND = 44;
    public static final int NAT_DETECTION_SOURCE_IP = 16388;
    public static final int NAT_DETECTION_DESTINATION_IP = 16389;
    public static final int REKEY_SA = 16393;
     */

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
        put(43, "TEMPORARY_FAILURE");
        put(44, "CHILD_SA_NOT_FOUND");
        put(16388, "NAT_DETECTION_SOURCE_IP");
        put(16389, "NAT_DETECTION_DESTINATION_IP");
        put(16393, "REKEY_SA");
    }};


    public IKEv2Parser(DatagramPacket pkt){
        initSPI = new byte[8];
        respSPI = new byte[8];
        pb = pkt.getData();
        //pLen = pkt.getLength();
        parseIKEv2Hdr();
    }

    public String parsePacket() {
        return null;
    }


    protected void parseIKEv2Hdr(){
        System.arraycopy(pb, 0, initSPI, 0, 8);
        System.arraycopy(pb, 8, respSPI, 0, 8);
        nPld = pb[16];
        eType = pb[18];
        totalLen = DataUtils.bytesToIntB(pb, 24);
        offset = 28;
    }

    public byte[] getRespSPI(){
        if (respSPI != null){
            return respSPI;
        }
        else{
            LogUtils.logErrExit(this.getClass().getName(), "Response SPI is null! ");
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
}
