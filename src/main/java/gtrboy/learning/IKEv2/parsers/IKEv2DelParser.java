package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.LogUtils;

import java.net.DatagramPacket;

public class IKEv2DelParser extends IKEv2EncParser{

    //boolean isCurrent;

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
                        LogUtils.logException(e, this.getClass().getName(), "Failed to decrypt the enc data! ");
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
                LogUtils.logErrExit(this.getClass().getName(), "Unknown Notify Type! ");
            }
        } else if(isDel){
            retStr = "OK";
        }else if(isEmpty){
            retStr = "EmptyInfo";
        }else{
            LogUtils.logErrExit(this.getClass().getName(), "Receive wrong Del packet! ");
        }
        return retStr;
    }

}
