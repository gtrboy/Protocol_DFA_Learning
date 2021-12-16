package gtrboy.learning.IKEv2.parsers;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;

import java.net.DatagramPacket;

public class IKEv2EncParser extends IKEv2Parser{
    protected IKEv2KeysGener keyG;

    public IKEv2EncParser(DatagramPacket pkt, IKEv2KeysGener keysGener){
        super(pkt);
        keyG = keysGener;
    }

    protected void parseEncPayload() throws Exception {
        byte[] decData;
        int payLen = parsePayloadHdr();
        //LogUtils.logDebug(this.getClass().getName(), "Enc Payload Length: " + payLen);
        // Initialization Vector
        byte[] peerIV = parseIV();
        //LogUtils.logDebug(this.getClass().getName(), "IV: " + DataUtils.bytesToHexStr(peerIV));
        int ivLen = peerIV.length;
        int checksumLen = keyG.getChecksumLen();
        int encDataLen = payLen - ivLen - checksumLen - 4;
        //LogUtils.logDebug(this.getClass().getName(), "encDataLen: " + encDataLen);

        decData = parseDecData(encDataLen, peerIV);
        //LogUtils.logDebug(this.getClass().getName(), "DECDATA: "+DataUtils.bytesToHexStr(decData));
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
