package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;

import java.net.DatagramPacket;

public class IKEv2RekeyChildSaParser extends IKEv2EncParser{

    byte[] r_nonce = null;
    byte[] r_child_spi = null;

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
                        LogUtils.logException(e, this.getClass().getName(), "Failed to decrypt the enc data!");
                    }
                    break;
                case 0x29:
                    parseNotifyPayload();
                    break;
                case 0x21:
                    parseSaPayload();
                    //LogUtils.logDebug(this.getClass().getName(), "Meet SA");
                    isSa = true;
                    break;
                case 0x28:
                    parseNoncePayload();
                    //LogUtils.logDebug(this.getClass().getName(), "Meet Nonce");
                    isNc = true;
                    break;
                case 0x2c:
                    parseDefault();
                    //LogUtils.logDebug(this.getClass().getName(), "Meet Tsi");
                    isTsi = true;
                    break;
                case 0x2d:
                    parseDefault();
                    //LogUtils.logDebug(this.getClass().getName(), "Meet Tsr");
                    isTsr = true;
                    break;
                default:
                    //LogUtils.logDebug(this.getClass().getName(), "nPLD: "+nPld);
                    parseDefault();
            }
        }

        boolean isNormal = isSa && isNc && isTsi && isTsr;
        if(notifyType <= NOTIFY_ERROR_MAX && notifyType != 0){
            retStr = NOTIFY_TYPES.get(Integer.valueOf(notifyType));
            //LogUtils.logDebug(this.getClass().getName(), "Notify Type: " + notifyType);
            if(retStr == null){
                LogUtils.logErrExit(this.getClass().getName(), "Unknown Notify Type! ");
            }
        } else if(isNormal){
            //retStr = "RESP_REKEY_CHILD_SA";
            retStr = "OK";
        }else{
            LogUtils.logErrExit(this.getClass().getName(), "Receive wrong REKEY_CHILD_SA! ");
        }
        return retStr;
    }

    private void parseSaPayload(){
        int pLen = parsePayloadHdr();
        //LogUtils.logDebug(this.getClass().getName(), "SA nPLD: "+nPld);
        r_child_spi = new byte[4];
        AO(8);
        System.arraycopy(pb, AO(4), r_child_spi, 0, 4);
        //LogUtils.logDebug(this.getClass().getName(), "r_child_spi: " + DataUtils.bytesToHexStr(r_child_spi));
        AO(pLen - 16);
    }

    private void parseNoncePayload(){
        int nonceLen = parsePayloadHdr() - 4;
        //LogUtils.logDebug(this.getClass().getName(), "Nonce Len: " + nonceLen);
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
