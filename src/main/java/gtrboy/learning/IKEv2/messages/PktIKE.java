package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.dom4j.*;
import org.dom4j.io.SAXReader;
import java.io.*;
import java.util.Iterator;
import java.util.List;

public class PktIKE {
    public ByteArrayOutputStream bout;
    private int totallen = 0;
    private byte[] initspi;
    private byte[] respspi;
    private byte[] msgid;
    private byte nextpld;
    private byte exchtype;
    Document document;

    //public byte[] packetbytes;

    public PktIKE(byte[] initspi, byte[] respspi, int msgid, byte nextpld, byte exchtype){
        this.initspi = initspi;
        this.respspi = respspi;
        this.msgid = DataUtils.intToBytes(msgid);
        this.nextpld = nextpld;
        this.exchtype = exchtype;
        this.bout = new ByteArrayOutputStream();



    }

    public void getTotalLen(Element node){
        if(node.attributeCount()!=0) {
            Attribute attr = node.attribute("size");
            int nodelen = Integer.parseInt(attr.getText());
            totallen = totallen + nodelen;
        }
        List<Element> listElement = node.elements();
        for(Element e:listElement){
            this.getTotalLen(e);
        }
    }

    public Document getXMLDocument(String xmlpath) throws DocumentException {
        File xmlfile = new File(xmlpath);
        SAXReader saxReader = new SAXReader();
        Document doc = saxReader.read(xmlfile);
        return doc;
    }

    public void ParseFinalField(Element ele){
        for(Iterator it = ele.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String text = element.getText();
            bout.writeBytes(DataUtils.hexStrToBytes(text));
        }
    }

    public void ParseIKEHeader(Element ih_root) {
        for(Iterator it = ih_root.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String ele_name = element.getName();
            switch (ele_name){
                case "initspi":
                    if (initspi.length==8){
                        bout.writeBytes(initspi);
                    }else{
                        LogUtils.logErrExit(this.getClass().getName(), "Init SPI length error! ");
                    }
                    break;
                case "msgid":
                    if(msgid.length==4){
                        bout.writeBytes(msgid);
                    }else{
                        LogUtils.logErrExit(this.getClass().getName(), "Message ID length error! ");
                    }
                    break;
                case "length":
                    if(totallen!=0){
                        bout.writeBytes(DataUtils.intToBytes(totallen));
                    }
                    else{
                        LogUtils.logErrExit(this.getClass().getName(), "total len is zero! ");
                    }
                    break;
                case "respspi":
                    if (respspi.length==8){
                        bout.writeBytes(respspi);
                    }else{
                        LogUtils.logErrExit(this.getClass().getName(), "Resp SPI length error! ");
                    }
                    break;
                case "nextpld":
                    bout.write(nextpld);
                    break;
                case "exch_type":
                    bout.write(exchtype);
                    break;

                default:
                    bout.writeBytes(DataUtils.hexStrToBytes(element.getText()));
            }
        }
    }

    public void ParsePayloadHdr(Element ele_phdr){
        ParseFinalField(ele_phdr);
    }

}
