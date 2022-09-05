package gtrboy.learning.IKEv2.messages;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;

import java.io.IOException;
import java.io.InputStream;

public class PktInfoEmpty extends PktIKE{


    public PktInfoEmpty(String patternFile, byte[] initspi, byte[] respspi, int msgid){
        super(initspi, respspi, msgid);
        doConstruct(patternFile);
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

    @Override
    public byte[] fromXMLToBytes(Element root) {
        Element ele_ih = root.element("ike_header");

        if (ele_ih!=null) {
            bout.writeBytes(ParseIKEHeader(ele_ih));
        }
        try {
            bout.flush();
        } catch (IOException e){
            LOGGER.error("Byte stream flush error! ");
            e.printStackTrace();
        }
        return bout.toByteArray();
    }
}
