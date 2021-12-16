package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.dom4j.Element;

import javax.xml.crypto.Data;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;

public class PktDelIKESa extends PktIKEEnc{

    private byte[] delSpi = null;

    public PktDelIKESa(String patternFile, byte[] initspi, byte[] respspi, int msgid,
                         IKEv2KeysGener keysGener){
        super(initspi, respspi, msgid, keysGener);

        //LogUtils.logDebug(this.getClass().getName(), "Start construct DEL_IKE_SA!");
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
        bAos.writeBytes(ParseFinalField(pData));
        return bAos.toByteArray();
    }
}
