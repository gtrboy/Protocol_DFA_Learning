package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2Exception;
import gtrboy.learning.IKEv2.IKEv2KeysGener;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.DatagramPacket;


public class IKEv2CreChSaParser extends IKEv2Parser {

    //IKEv2KeysGener curKeyG;
    private byte[] r_nonce = null;
    private byte[] r_ke = null;
    private byte[] r_spi = null;
    private byte[] r_child_spi = null;

    private boolean isIke = false;
    private boolean isEsp = false;

    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public IKEv2CreChSaParser(DatagramPacket pkt, IKEv2KeysGener curKG){
        super(IKEv2Parser.CCSA, pkt, curKG);
        LOGGER.debug("See CRE_CHILD_SA.");
    }

    @Override
    public String parsePacket() {
        String retStr = null;

        while(nPld != 0){
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
                case 0x21:   // SA
                    parseSaPayload();
                    break;
                case 0x28:
                    parseNoncePayload();
                    break;
                case 0x22:
                    parseKePayload();
                    break;
                case 0x2c:
                    parseDefault();
                    //LOGGER.debug("Meet Tsi");
                    break;
                case 0x2d:
                    parseDefault();
                    //LOGGER.debug("Meet Tsr");
                    break;
                default:
                    parseDefault();

            }
        }

        //boolean isIke = isSa && isNc && isKe;
        //boolean isEsp = isSa && isNc && isTsi && isTsr;
        if(notifyType <= NOTIFY_ERROR_MAX && notifyType != 0){  // Normal
            retStr = NOTIFY_TYPES.get((int) notifyType);
            LOGGER.debug("Notify Type: " + retStr);
            if(retStr == null){
                LOGGER.error("Unknown Notify Type! ");
                System.exit(-1);
            }
        } else if (isIke){      // Error Notify
            //retStr = "RESP_REKEY_IKE_SA";
            retStr = "OK_IKE";
        } else if (isEsp){
            retStr = "OK_ESP";
        }else {
            LOGGER.error("Receive wrong REKEY_IKE_SA! ");
            System.exit(-1);
        }
        return retStr;
    }

    private void parseNoncePayload(){
        int nonceLen = parsePayloadHdr() - 4;
        r_nonce = new byte[nonceLen];
        LOGGER.debug("Nonce Length: " + nonceLen);
        LOGGER.debug("Offset: " + offset);
        System.arraycopy(pb, AO(nonceLen), r_nonce, 0, nonceLen);
    }

    private void parseKePayload(){
        int keyLen = parsePayloadHdr() - 8;
        AO(4);
        r_ke = new byte[keyLen];
        System.arraycopy(pb, AO(keyLen), r_ke, 0, keyLen);
    }

    private void parseSaPayload(){
        int pLen = parsePayloadHdr();
        AO(5);
        byte protoId = pb[AO(1)];
        AO(2);
        if (protoId == 0x01){
            isIke = true;
            r_spi = new byte[8];
            System.arraycopy(pb, AO(8), r_spi, 0, 8);
            AO(pLen - 20);
        } else if (protoId == 0x03){
            isEsp = true;
            r_child_spi = new byte[4];
            System.arraycopy(pb, AO(4), r_child_spi, 0, 4);
            AO(pLen - 16);
        }else{
            LOGGER.error("Invalid protocol ID!");
            System.exit(-1);
        }
    }

    public byte[] getRNonce(){
        return r_nonce;
    }

    public byte[] getKe(){
        return r_ke;
    }

    public byte[] getRSpi(){
        return r_spi;
    }

    public byte[] getRChildSpi(){
        return r_child_spi;
    }
}
