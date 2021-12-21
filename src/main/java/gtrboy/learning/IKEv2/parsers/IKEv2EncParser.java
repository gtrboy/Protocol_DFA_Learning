package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.DatagramPacket;

public class IKEv2EncParser extends IKEv2Parser{
    protected IKEv2KeysGener keyG;
    //private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public IKEv2EncParser(DatagramPacket pkt, IKEv2KeysGener keysGener){
        super(pkt);
        keyG = keysGener;
    }

    protected void parseEncPayload() throws Exception {
        byte[] decData;
        int payLen = parsePayloadHdr();
        //LOGGER.debug("Enc Payload Length: " + payLen);
        // Initialization Vector
        byte[] peerIV = parseIV();
        //LOGGER.debug("IV: " + DataUtils.bytesToHexStr(peerIV));
        int ivLen = peerIV.length;
        int checksumLen = keyG.getChecksumLen();
        int encDataLen = payLen - ivLen - checksumLen - 4;
        //LOGGER.debug("encDataLen: " + encDataLen);

        decData = parseDecData(encDataLen, peerIV);
        //LOGGER.debug("DECDATA: "+DataUtils.bytesToHexStr(decData));
        pb = decData;
        offset = 0;
    }

    private byte[] parseIV(){
        int ivLen = keyG.getIVLen();
        byte[] iv = new byte[ivLen];
        System.arraycopy(pb, AO(ivLen), iv, 0, ivLen);
        return iv;
    }

    private byte[] parseDecData(int dataLen, byte[] iv) throws Exception {
        byte[] encData = new byte[dataLen];;
        System.arraycopy(pb, AO(dataLen), encData, 0, dataLen);
        byte[] decData = keyG.decrypt(encData, keyG.getSkEr(), iv);
        return decData;
    }
}
