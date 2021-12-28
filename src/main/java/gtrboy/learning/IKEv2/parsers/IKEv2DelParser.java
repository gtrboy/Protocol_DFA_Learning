package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.DatagramPacket;

public class IKEv2DelParser extends IKEv2Parser{

    //boolean isCurrent;
    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public IKEv2DelParser(DatagramPacket pkt, IKEv2KeysGener keysGener){
        super(pkt, keysGener);
        //isCurrent = old_or_cur;
    }

    @Override
    public String parsePacket(){
        String retStr = null;
        boolean isDel = false;
        boolean isEmpty = false;

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
                    break;
                default:
                    parseDefault();
            }
        }

        if(notifyType <= NOTIFY_ERROR_MAX && notifyType != 0){
            retStr = NOTIFY_TYPES.get(Integer.valueOf(notifyType));
            //LogUtils.logDebug(this.getClass().getName(), "Notify Type: " + notifyType);
            if(retStr==null){
                LOGGER.error("Unknown Notify Type! ");
                System.exit(-1);
            }
        } else if(isDel){
            retStr = "OK";
        }else if(isEmpty){
            retStr = "EmptyInfo";
        }else{
            LOGGER.error("Receive wrong Del packet! ");
            System.exit(-1);
        }
        return retStr;
    }

}
