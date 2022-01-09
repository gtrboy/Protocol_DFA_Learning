package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dom4j.Element;

import java.io.ByteArrayOutputStream;
import java.util.Iterator;

public class PktRekeyChildSa extends PktIKEEnc{

    private byte[] oldCldSpi = null;
    private byte[] newCldSpi = null;
    private byte[] newNc = null;


    public PktRekeyChildSa(String patternFile, byte[] initspi, byte[] respspi, int msgid,
                           IKEv2KeysGener keysGener, byte[] old_c_spi, byte[] new_c_spi, byte[] new_nonce){
        super(initspi, respspi, msgid, keysGener);
        if(old_c_spi!=null) {
            oldCldSpi = old_c_spi;
        }else{
            oldCldSpi = new byte[4];
        }
        newCldSpi = new_c_spi;
        newNc = new_nonce;

        doConstruct(patternFile);
    }

    @Override
    protected byte[] getPlaintext(Element plainRoot, int dataLen) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element eleNo = plainRoot.element("payload_notify");
        Element eleSa = plainRoot.element("payload_sa");
        Element eleNc = plainRoot.element("payload_nc");
        Element eleTsi = plainRoot.element("payload_tsi");
        Element eleTsr = plainRoot.element("payload_tsr");

        if(eleNo!=null) {
            bAos.writeBytes(ParseNotifyPayload(eleNo));
        }
        if(eleSa!=null) {
            bAos.writeBytes(ParseSaPayload(eleSa));
        }
        if(eleNc!=null) {
            bAos.writeBytes(ParseNcPayload(eleNc));
        }
        if(eleTsi!=null) {
            bAos.writeBytes(ParseTsPayload(eleTsi));
        }
        if(eleTsr!=null) {
            bAos.writeBytes(ParseTsPayload(eleTsr));
        }

        return bAos.toByteArray();
    }

    private byte[] ParseTsPayload(Element tsRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = tsRoot.element("p_header");
        Element pData = tsRoot.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));

        Element tsNum = pData.element("ts_num");
        Element reserved = pData.element("reserved");
        Element ts = pData.element("ts");
        bAos.writeBytes(DataUtils.hexStrToBytes(tsNum.getText()));
        bAos.writeBytes(DataUtils.hexStrToBytes(reserved.getText()));
        bAos.writeBytes(ParseFinalField(ts));

        return bAos.toByteArray();
    }


    private byte[] ParseNcPayload(Element root){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = root.element("p_header");
        Element pData = root.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));
        bAos.writeBytes(newNc);
        return bAos.toByteArray();
    }

    private byte[] ParseSaPayload(Element saRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = saRoot.element("p_header");
        Element pData = saRoot.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));
        bAos.writeBytes(ParseSaData(pData));
        return bAos.toByteArray();
    }

    private byte[] ParseSaData(Element dataRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator it = dataRoot.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            bAos.writeBytes(ParseProposal(element));
        }
        return bAos.toByteArray();
    }

    private byte[] ParseProposal(Element propRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        short propLen = (short) getTreeLen(propRoot, 0);
        for(Iterator it = propRoot.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String nodeName = element.getName();
            if("prop_header".equals(nodeName)){
                // Proposal Header
                bAos.writeBytes(ParsePropHdr(element, DataUtils.shortToBytesB(propLen)));
            }else{
                //Transform
                bAos.writeBytes(ParseTransform(element));
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParsePropHdr(Element element, byte[] bPropLen){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator itt = element.elementIterator(); itt.hasNext();){
            Element element1 = (Element) itt.next();
            switch (element1.getName()){
                case "paylen":
                    bAos.writeBytes(bPropLen);
                    break;
                case "spi":
                    bAos.writeBytes(newCldSpi);
                    break;
                default:
                    String text = element1.getText();
                    bAos.writeBytes(DataUtils.hexStrToBytes(text));
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParseTransform(Element element) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator it = element.elementIterator();it.hasNext();){
            Element curele = (Element) it.next();
            String nodeName = curele.getName();
            if ("transattr".equals(nodeName)){
                bAos.writeBytes(ParseFinalField(curele));
            }else{
                try {
                    bAos.writeBytes(DataUtils.hexStrToBytes(curele.getText()));
                } catch (NumberFormatException e){
                    LOGGER.error("Convert Hex Error! ");
                    e.printStackTrace();
                }
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParseNotifyPayload(Element notifyRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = notifyRoot.element("p_header");
        Element pData = notifyRoot.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));
        bAos.writeBytes(ParseNotifyData(pData));
        return bAos.toByteArray();
    }

    private byte[] ParseNotifyData(Element dataRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator it = dataRoot.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String text = element.getText();
            String name = element.getName();
            if("spi".equals(name)){
                bAos.writeBytes(oldCldSpi);
            }else {
                bAos.writeBytes(DataUtils.hexStrToBytes(text));
            }
        }
        return bAos.toByteArray();
    }
}
