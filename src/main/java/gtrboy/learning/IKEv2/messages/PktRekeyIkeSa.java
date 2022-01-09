package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dom4j.Element;

import java.io.ByteArrayOutputStream;
import java.util.Iterator;

public class PktRekeyIkeSa extends PktIKEEnc{

    private byte[] newIkeSpi = null;
    private byte[] newNc = null;
    private byte[] newKe = null;


    public PktRekeyIkeSa(String patternFile, byte[] initspi, byte[] respspi, int msgid,
                         IKEv2KeysGener keysGener, byte[] new_spi, byte[] new_nc, byte[] new_ke){
        super(initspi, respspi, msgid, keysGener);
        newIkeSpi = new_spi;
        newNc = new_nc;
        newKe = new_ke;

        doConstruct(patternFile);
    }

    @Override
    protected byte[] getPlaintext(Element plainRoot, int dataLen) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element eleSa = plainRoot.element("payload_sa");
        Element eleNc = plainRoot.element("payload_nc");
        Element eleKe = plainRoot.element("payload_ke");

        if(eleSa!=null) {
            bAos.writeBytes(ParseSaPayload(eleSa));
        }
        if(eleNc!=null) {
            bAos.writeBytes(ParseNcPayload(eleNc));
        }
        if(eleKe!=null) {
            bAos.writeBytes(ParseKePayload(eleKe));
        }

        return bAos.toByteArray();
    }

    private byte[] ParseSaPayload(Element saRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = saRoot.element("p_header");
        Element pData = saRoot.element("data");
        byte[] hdr = ParsePayloadHdr(pHdr, pData);
        bAos.writeBytes(hdr);

        if(hdr.length != 4){
            LOGGER.error("Invalid payload header length: " + hdr.length);
            System.exit(-1);
        }

        /*
        byte[] bPropLen = new byte[2];
        bPropLen[0] = (byte) 0x00;
        bPropLen[1] = (byte) (hdr[3] - 4);

         */

        Element proposal = pData.element("proposal");
        byte[] propBytes = ParseProposal(proposal);
        bAos.writeBytes(propBytes);

        return bAos.toByteArray();
    }

    private byte[] ParseProposal(Element root){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        short propLen = (short) getTreeLen(root, 0);
        for(Iterator it = root.elementIterator(); it.hasNext();)
        {
            Element element = (Element) it.next();
            String nodeName = element.getName();
            if("prop_header".equals(nodeName)){
                bAos.writeBytes(ParsePropHdr(element, propLen));
            }else{
                //Transform
                bAos.writeBytes(ParseTransform(element));
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParsePropHdr(Element hdrRoot, short propLen){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator it = hdrRoot.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String nodeName = element.getName();
            if("paylen".equals(nodeName)){
                bAos.writeBytes(DataUtils.shortToBytesB(propLen));
            }else if ("spi".equals(nodeName)){
                bAos.writeBytes(newIkeSpi);
            }else{
                String text = element.getText();
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

    private byte[] ParseNcPayload(Element root){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = root.element("p_header");
        Element pData = root.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));
        bAos.writeBytes(newNc);
        return bAos.toByteArray();
    }

    private byte[] ParseKePayload(Element root){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = root.element("p_header");
        Element pData = root.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));
        for(Iterator it = pData.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String elename = element.getName();
            if(elename.equals("ke_data")){
                bAos.writeBytes(newKe);
            }else{
                try {
                    bAos.writeBytes(DataUtils.hexStrToBytes(element.getText()));
                } catch (NumberFormatException e){
                    LOGGER.error("Convert Hex Error! ");
                }
            }
        }
        return bAos.toByteArray();
    }


}
