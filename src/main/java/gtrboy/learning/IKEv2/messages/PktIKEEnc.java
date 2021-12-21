package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.IKEv2.IKEv2KeysGener;
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
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;

abstract class PktIKEEnc extends PktIKE{
    public IKEv2KeysGener keysGenerator;
    public boolean isEnc = false;
    public int padLen = 0;
    public int encDataLen = 0;

    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public PktIKEEnc(byte[] initspi, byte[] respspi, int msgid, IKEv2KeysGener Gener){
        super(initspi, respspi, msgid);
        keysGenerator = Gener;
        if(keysGenerator!=null) {
            isEnc = keysGenerator.isKeysPrepared();
        }else {
            isEnc = false;
        }
    }

    protected abstract byte[] getPlaintext(Element plainRoot, int DataLen);

    protected byte[] ParseIKEHeader(Element ih_root, byte[] nextPld) {
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
                    case "nextpld":
                        bAos.writeBytes(nextPld);
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


    @Override
    protected byte[] fromXMLToBytes(Element root) {
        Element eleIKEHdr = root.element("ike_header");
        Element eleEnc = root.element("payload_enc");

        byte[] ikeHdr = null;
        if(isEnc){
            if(eleIKEHdr!=null) {
                ikeHdr = ParseIKEHeader(eleIKEHdr);
                bout.writeBytes(ikeHdr);
            }
        }else{
            byte[] nextPld = null;
            if(eleEnc!=null) {
                // Make the next_payload to Identification, not ENC
                nextPld = DataUtils.hexStrToBytes(eleEnc.element("p_header").element("n_payld").getText());
            }
            if(eleIKEHdr!=null && nextPld!=null) {
                // LogUtils.logDebug(this.getClass().getName(), "next payload: " + DataUtils.bytesToHexStr(nextPld));
                ikeHdr = ParseIKEHeader(eleIKEHdr, nextPld);
                bout.writeBytes(ikeHdr);
            }
        }
        if(eleEnc!=null) {
            bout.writeBytes(ParseEncPayload(eleEnc, ikeHdr));
        }

        try{
            bout.flush();
        }catch (IOException e){
            LOGGER.error("Byte stream flush error! ");
            e.printStackTrace();
        }
        return bout.toByteArray();
    }

    @Override
    protected Element getXMLRoot(InputStream xmlStream) throws DocumentException {
        //File xmlfile = new File(xmlpath);
        SAXReader saxReader = new SAXReader();
        Document doc = saxReader.read(xmlStream);
        Element root = doc.getRootElement();
        padLen = getPaddingLen(root.element("payload_enc").element("data").element("enc_data"));
        if(isEnc) {
            initTotalLen(root, padLen);
        }else {
            totallen = encDataLen + IKE_HDR_LEN;
        }
        return root;
    }


    private byte[] ParseEncHdr(Element pHdr, Element pData, int encDataLen){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        int ivLen = Integer.parseInt(pData.element("inivec").attribute("size").getText());
        int checkLen = Integer.parseInt(pData.element("checksum").attribute("size").getText());
        int totalLen = encDataLen + ivLen + checkLen + 4;

        for(Iterator it = pHdr.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String text = element.getText();
            String name = element.getName();
            if("payld_len".equals(name)){
                bAos.writeBytes(DataUtils.shortToBytesB(totalLen));
            }else {
                bAos.writeBytes(DataUtils.hexStrToBytes(text));
            }
        }
        return bAos.toByteArray();
    }

    private byte[] getPadding(int encDataLen) {
        padLen = 16 - (encDataLen % 16);
        int prePadLen = padLen - 1;
        byte[] padding = new byte[padLen];
        byte[] prePad = new byte[prePadLen];
        Arrays.fill(prePad, (byte)0x00);
        System.arraycopy(prePad, 0, padding, 0, prePadLen);
        padding[prePadLen] = (byte) prePadLen;
        return padding;
    }

    private int getPaddingLen(Element clearData){
        encDataLen = getTreeLen(clearData, 0);
        int padLen = 16 - (encDataLen % 16);
        return padLen;
    }

    private byte[] calChecksum(byte[] content){
        byte[] skAi = keysGenerator.getSkAi();
        byte[] checksum = null;
        if(isEnc) {
            try {
                byte[] hash = IKEv2KeysGener.getMacDigest(skAi, content, keysGenerator.intgAlg);
                int checksumLen = hash.length / 2;
                checksum = new byte[checksumLen];
                System.arraycopy(hash, 0, checksum, 0, checksumLen);
            }catch (NoSuchAlgorithmException e){
                e.printStackTrace();
            }catch (InvalidKeyException e){
                e.printStackTrace();
            }
        }else{
            LOGGER.error("Keys are not prepared! ");
        }
        return checksum;
    }

    private byte[] ParseEncPayload(Element encRoot, byte[] ikeHdr){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = encRoot.element("p_header");
        Element pData = encRoot.element("data");
        Element initVec = pData.element("inivec");
        Element clearDataRoot = pData.element("enc_data");
        byte[] plaintext = getPlaintext(clearDataRoot, encDataLen);

        // 密钥已生成，需要加密；密钥尚未生成（IKE_SA_INIT还没交互），不加密，没有iv和checksum字段；
        if(isEnc){
            // ENC Header
            byte[] padding = getPadding(encDataLen);
            int totalLen = encDataLen + padding.length;
            bAos.writeBytes(ParseEncHdr(pHdr, pData, totalLen));

            // IV
            byte[] ivBytes = DataUtils.hexStrToBytes(initVec.getText());
            bAos.writeBytes(ivBytes);

            // ENC data
            ByteBuffer clearBuf = ByteBuffer.allocate(totalLen);
            byte[] clearBytes = clearBuf.put(plaintext).put(padding).array();
            byte[] skEi = keysGenerator.getSkEi();
            LOGGER.debug("skEi: " + DataUtils.bytesToHexStr(skEi));
            try {
                // Encrypt
                byte[] encBytes = keysGenerator.encrypt(clearBytes, skEi);
                bAos.writeBytes(encBytes);
            }catch (Exception e){
                LOGGER.error("Encrypt Failed! ");
                e.printStackTrace();
            }

            // Calculate the integrity checksum
            ByteBuffer buffer = ByteBuffer.allocate(ikeHdr.length + bAos.size());
            buffer.put(ikeHdr).put(bAos.toByteArray());
            byte[] checksum = calChecksum(buffer.array());
            bAos.writeBytes(checksum);
        }
        else{
            bAos.writeBytes(plaintext);
        }

        return bAos.toByteArray();
    }





}
