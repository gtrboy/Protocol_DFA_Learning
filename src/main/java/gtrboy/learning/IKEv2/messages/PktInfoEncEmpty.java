package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dom4j.Element;


public class PktInfoEncEmpty extends PktIKEEnc{


    public PktInfoEncEmpty(String patternFile, byte[] initspi, byte[] respspi, int msgid,
                           IKEv2KeysGener keysGener){
        super(initspi, respspi, msgid, keysGener);
        doConstruct(patternFile);
    }

    @Override
    protected byte[] getPlaintext(Element plainRoot, int dataLen){
        String text = plainRoot.getText();
        return DataUtils.hexStrToBytes(text);
    }

}
