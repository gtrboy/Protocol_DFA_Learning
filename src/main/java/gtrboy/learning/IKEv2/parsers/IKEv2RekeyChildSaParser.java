package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
//import gtrboy.learning.utils.DataUtils;
//import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.DatagramPacket;

public class IKEv2RekeyChildSaParser extends IKEv2EncParser{

    byte[] r_nonce = null;
    byte[] r_child_spi = null;
    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public IKEv2RekeyChildSaParser(DatagramPacket pkt, IKEv2KeysGener keysGener){
        super(pkt, keysGener);
    }

    @Override
    public String parsePacket() {
        String retStr = null;
        boolean isSa = false;
        boolean isNc = false;
        boolean isTsi = false;
        boolean isTsr = false;

        while (nPld != 0){
            switch (nPld) {
                case 0x2e:
                    try{
                        parseEncPayload();
                    } catch (Exception e){
                        LOGGER.error("Failed to decrypt the enc data!");
                        e.printStackTrace();
                    }
                    break;
                case 0x29:
                    parseNotifyPayload();
                    break;
                case 0x21:
                    parseSaPayload();
                    //LOGGER.debug("Meet SA");
                    isSa = true;
                    break;
                case 0x28:
                    parseNoncePayload();
                    //LOGGER.debug("Meet Nonce");
                    isNc = true;
                    break;
                case 0x2c:
                    parseDefault();
                    //LOGGER.debug("Meet Tsi");
                    isTsi = true;
                    break;
                case 0x2d:
                    parseDefault();
                    //LOGGER.debug("Meet Tsr");
                    isTsr = true;
                    break;
                default:
                    //LOGGER.debug("nPLD: "+nPld);
                    parseDefault();
            }
        }

        boolean isNormal = isSa && isNc && isTsi && isTsr;
        if(notifyType <= NOTIFY_ERROR_MAX && notifyType != 0){
            retStr = NOTIFY_TYPES.get(Integer.valueOf(notifyType));
            //LOGGER.debug("Notify Type: " + notifyType);
            if(retStr == null){
                LOGGER.error("Unknown Notify Type! ");
                System.exit(-1);
            }
        } else if(isNormal){
            //retStr = "RESP_REKEY_CHILD_SA";
            retStr = "OK";
        }else{
            LOGGER.error("Receive wrong REKEY_CHILD_SA! ");
            System.exit(-1);
        }
        return retStr;
    }

    private void parseSaPayload(){
        int pLen = parsePayloadHdr();
        //LOGGER.debug("SA nPLD: "+nPld);
        r_child_spi = new byte[4];
        AO(8);
        System.arraycopy(pb, AO(4), r_child_spi, 0, 4);
        //LOGGER.debug("r_child_spi: " + DataUtils.bytesToHexStr(r_child_spi));
        AO(pLen - 16);
    }

    private void parseNoncePayload(){
        int nonceLen = parsePayloadHdr() - 4;
        //LOGGER.debug("Nonce Len: " + nonceLen);
        r_nonce = new byte[nonceLen];
        System.arraycopy(pb, AO(nonceLen), r_nonce, 0, nonceLen);
    }

    public byte[] getRNonce(){
        return r_nonce;
    }

    public byte[] getRChildSpi(){
        return r_child_spi;
    }
}
