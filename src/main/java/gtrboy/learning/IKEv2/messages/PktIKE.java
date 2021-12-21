package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dom4j.*;
import java.io.*;
import java.util.Iterator;
import java.util.List;

abstract class PktIKE {
    protected ByteArrayOutputStream bout;
    protected byte[] packetBytes;
    protected int totallen = 0;
    protected byte[] initspi;
    protected byte[] respspi;
    protected byte[] msgid;

    protected static final int IKE_HDR_LEN = 28;
    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);
    //Document document;

    //public byte[] packetbytes;

    public PktIKE(byte[] initspi, byte[] respspi, int msgid){
        this.initspi = initspi;
        this.respspi = respspi;
        this.msgid = DataUtils.intToBytesB(msgid);
        this.bout = new ByteArrayOutputStream();
    }

    abstract protected Element getXMLRoot(InputStream xmlStream) throws DocumentException;

    abstract protected byte[] fromXMLToBytes(Element root);

    public byte[] getPacketBytes(){
        return packetBytes;
    }

    protected void doConstruct(String patternFile){
        InputStream xmlStream = this.getClass().getClassLoader().getResourceAsStream("IKEv2/IKEv2Messages/" + patternFile);
        try{
            Element root = getXMLRoot(xmlStream);
            packetBytes = fromXMLToBytes(root);
        } catch (DocumentException e){
            LOGGER.error("Document Error!");
            //e.printStackTrace();
        }
    }

    protected int getTreeLen(Element root, int t_len){
        int cur_len = t_len;
        if(root.attributeCount()!=0) {
            Attribute attr = root.attribute("size");
            int nodeLen = Integer.parseInt(attr.getText());
            return nodeLen + cur_len;
        }
        List<Element> listElement = root.elements();
        for(Element e:listElement){
            cur_len = this.getTreeLen(e, cur_len);
        }
        return cur_len;
    }


    protected void initTotalLen(Element root, int preLen){
        totallen = getTreeLen(root, preLen);
    }

    protected byte[] ParseFinalField(Element ele){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator it = ele.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String text = element.getText();
            bAos.writeBytes(DataUtils.hexStrToBytes(text));
        }
        return bAos.toByteArray();
    }

    protected byte[] ParseIKEHeader(Element ih_root) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        try {
            for (Iterator it = ih_root.elementIterator(); it.hasNext(); ) {
                Element element = (Element) it.next();
                String ele_name = element.getName();
                switch (ele_name) {
                    case "initspi":
                        if (initspi.length == 8) {
                            bAos.writeBytes(initspi);
                        } else {
                            LOGGER.error("Init SPI length error! ");
                            System.exit(-1);
                        }
                        break;
                    case "msgid":
                        if (msgid.length == 4) {
                            bAos.writeBytes(msgid);
                        } else {
                            LOGGER.error("Message ID length error! ");
                            System.exit(-1);
                        }
                        break;
                    case "length":
                        if (totallen != 0) {
                            bAos.writeBytes(DataUtils.intToBytesB(totallen));
                        } else {
                            LOGGER.error("total len is zero! ");
                            System.exit(-1);
                        }
                        break;
                    case "respspi":
                        if (respspi.length == 8) {
                            bAos.writeBytes(respspi);
                        } else {
                            LOGGER.error("Resp SPI length error! ");
                            System.exit(-1);
                        }
                        break;
                    default:
                        bAos.writeBytes(DataUtils.hexStrToBytes(element.getText()));
                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        return bAos.toByteArray();
    }



    protected byte[] ParsePayloadHdr(Element pHdr, Element pData){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        short pLen = (short) getTreeLen(pData,4);
        for(Iterator it = pHdr.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String text = element.getText();
            String name = element.getName();
            if("payld_len".equals(name)){
                bAos.writeBytes(DataUtils.shortToBytesB(pLen));
            }else {
                bAos.writeBytes(DataUtils.hexStrToBytes(text));
            }
        }
        return bAos.toByteArray();
    }


}
