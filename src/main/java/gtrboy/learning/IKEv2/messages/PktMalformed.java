package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class PktMalformed extends PktIKE{

    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public PktMalformed(String patternFile, byte[] initspi, byte[] respspi, int msgid){
        super(initspi, respspi, msgid);
        doConstruct(patternFile);
    }

    @Override
    public byte[] fromXMLToBytes(Element root) {
        Element ele_ih = root.element("ike_header");
        Element ele_malformed = root.element("data");


        if (ele_ih!=null) {
            bout.writeBytes(ParseIKEHeader(ele_ih));
        }
        if(ele_malformed!=null){
            bout.writeBytes(DataUtils.hexStrToBytes(ele_malformed.getText()));
        }
        try {
            bout.flush();
        } catch (IOException e){
            LOGGER.error("Byte stream flush error! ");
            e.printStackTrace();
        }
        return bout.toByteArray();
    }

    protected byte[] ParseIKEHeader(Element ih_root) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator it = ih_root.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String ele_name = element.getName();
            switch (ele_name){
                case "initspi":
                    if (initspi.length==8){
                        bAos.writeBytes(initspi);
                    }else{
                        LOGGER.error("Init SPI length error! ");
                        System.exit(-1);
                    }
                    break;
                case "msgid":
                    if(msgid.length==4){
                        bAos.writeBytes(msgid);
                    }else{
                        LOGGER.error("Message ID length error! ");
                        System.exit(-1);
                    }
                    break;
                case "respspi":
                    if (respspi.length==8){
                        bAos.writeBytes(respspi);
                    }else{
                        LOGGER.error("Resp SPI length error! ");
                        System.exit(-1);
                    }
                    break;
                default:
                    bAos.writeBytes(DataUtils.hexStrToBytes(element.getText()));
            }
        }
        return bAos.toByteArray();
    }


    @Override
    public Element getXMLRoot(InputStream xmlStream) throws DocumentException {
        //File xmlfile = new File(xmlpath);
        SAXReader saxReader = new SAXReader();
        Document doc = saxReader.read(xmlStream);
        Element root = doc.getRootElement();
        initTotalLen(root, 0);
        return root;
    }
}
