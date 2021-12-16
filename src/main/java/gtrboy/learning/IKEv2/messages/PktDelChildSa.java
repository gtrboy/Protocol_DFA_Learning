package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import org.dom4j.Element;

import javax.xml.crypto.Data;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;

public class PktDelChildSa extends PktIKEEnc{

    private byte[] delSpi = null;

    public PktDelChildSa(String patternFile, byte[] initspi, byte[] respspi, int msgid,
                         IKEv2KeysGener keysGener, byte[] del_spi){
        super(initspi, respspi, msgid, keysGener);
        if(del_spi!=null){
            delSpi = del_spi;
        }else{
            delSpi = new byte[4];
        }

        doConstruct(patternFile);
    }

    @Override
    protected byte[] getPlaintext(Element plainRoot, int dataLen){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element eleDel = plainRoot.element("payload_del");
        if(eleDel!=null){
            bAos.writeBytes(ParseDelPayload(eleDel));
        }
        return bAos.toByteArray();
    }

    private byte[] ParseDelPayload(Element delRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = delRoot.element("p_header");
        Element pData = delRoot.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));

        for(Iterator it = pData.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String name = element.getName();
            if("spi".equals(name)){
                bAos.writeBytes(delSpi);
            }else{
                String text = element.getText();
                bAos.writeBytes(DataUtils.hexStrToBytes(text));
            }
        }
        return bAos.toByteArray();
    }
}
