package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.DatagramPacket;

public class IKEv2InfoParser extends IKEv2Parser{

    //boolean isCurrent;

    public IKEv2InfoParser(DatagramPacket pkt, IKEv2KeysGener keysGener){
        super(IKEv2Parser.INFO, pkt, keysGener);
        //isCurrent = old_or_cur;
    }

    @Override
    public String parsePacket(){
        String retStr = null;
        boolean isDel = false;
        boolean isEmpty = false;
        boolean isNotify = false;

        while(nPld!=0){
            switch (nPld){
                case 0x2e:
                    try{
                        parseEncPayload();
                        if(nPld==0){
                            isEmpty = true;
                        }
                    }catch (Exception e){
                        LOGGER.error("Failed to decrypt the enc data! ");
                    }
                    break;
                case 0x2a:   //Delete Payload
                    //delNum = parseDelPayload();
                    parseDefault();
                    isDel = true;
                    break;
                case 0x29:
                    parseNotifyPayload();
                    isNotify = true;
                    break;
                default:
                    parseDefault();
            }
        }

        if(notifyType <= NOTIFY_ERROR_MAX && notifyType != 0){
            retStr = NOTIFY_TYPES.get((int) notifyType);
            LOGGER.debug("Notify Type: " + retStr);
            if(retStr==null){
                LOGGER.error("Unknown Notify Type! ");
                System.exit(-1);
            }
        }else if (isNotify){
            retStr = "NOTIFY_" + String.valueOf(notifyType);
        } else if(isDel){
            retStr = "OK_DEL";
        }else if(isEmpty){
            retStr = "EmptyInfo";
        }else{
            LOGGER.error("Receive wrong INFORMATION packet! ");
            System.exit(-1);
        }
        return retStr;
    }

}
