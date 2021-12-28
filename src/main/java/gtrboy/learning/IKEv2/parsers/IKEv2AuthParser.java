package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.DatagramPacket;

public class IKEv2AuthParser extends IKEv2Parser {
    IKEv2KeysGener keyG = null;
    byte[] rChildSpi = null;
    //byte[] peerIV = null;

    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);


    public IKEv2AuthParser(DatagramPacket pkt, IKEv2KeysGener keysGener){
        super(pkt, keysGener);
        keyG = keysGener;
    }

    @Override
    public String parsePacket() {
        String retStr = null;
        boolean isSA = false;
        boolean isAuth = false;
        boolean isIDr = false;
        boolean isTSi = false;
        boolean isTSr = false;
        while(nPld != 0) {
            switch (nPld) {
                case 0x2e:    // Encrypted and Authenticated
                    try {
                        parseEncPayload();
                    } catch (Exception e){
                        LOGGER.error("Failed to decrypt the enc data! ");
                        e.printStackTrace();
                    }
                    break;
                case 0x29:    // Notify
                    parseNotifyPayload();
                    break;
                case 0x21:
                    parseSaPayload();
                    isSA = true;
                    break;
                case 0x27:
                    parseDefault();
                    isAuth = true;
                    break;
                case 0x24:
                    parseIDrPayload();
                    isIDr = true;
                    break;
                case 0x2c:
                    parseTsiPayload();
                    isTSi = true;
                    break;
                case 0x2d:
                    parseTsrPayload();
                    isTSr = true;
                    break;
                default:
                    parseDefault();
            }
        }

        boolean isNormal = isSA && isAuth && isIDr && isTSi && isTSr;
        if(notifyType <= NOTIFY_ERROR_MAX && notifyType != 0){  // Error Notify
            retStr = NOTIFY_TYPES.get(Integer.valueOf((int)notifyType));
            //LogUtils.logDebug(this.getClass().getName(), "Notify Type: " + notifyType);
            if(retStr == null){
                LOGGER.error("Unknown Notify Type! ");
                System.exit(-1);
            }
        } else if (isNormal){   // Normal
            //retStr = "RESP_IKE_AUTH";
            retStr = "OK";
        }else {
            LOGGER.error("Receive wrong IKE_AUTH! ");
            System.exit(-1);
        }
        return retStr;
    }



    private void parseSaPayload(){
        int pLen = parsePayloadHdr();
        parseProposal(pLen - 4);
    }

    private void parseProposal(int propLen){
        rChildSpi = new byte[4];
        AO(8);
        System.arraycopy(pb, AO(4), rChildSpi, 0, 4);
        int remainedLen = propLen - 12;
        AO(remainedLen);
    }

    // Do not handle anything now
    private void parseIDrPayload(){
        int pLen = parsePayloadHdr();
        AO(pLen - 4);
    }

    // Do not handle anything now
    private void parseTsiPayload(){
        int pLen = parsePayloadHdr();
        AO(pLen - 4);
    }

    // Do not handle anything now
    private void parseTsrPayload(){
        int pLen = parsePayloadHdr();
        AO(pLen - 4);
    }

    public byte[] getRChildSpi(){
        return rChildSpi;
    }
}
