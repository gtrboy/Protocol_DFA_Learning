package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.IKEv2.IKEv2AuthType;
import gtrboy.learning.IKEv2.IKEv2KeysGener;
import gtrboy.learning.utils.DataUtils;
import org.dom4j.Element;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Iterator;

public class PktIKEAuthPSK extends PktIKEEnc{

    //private byte[] packetBytes;
    private byte[] rNonce;
    private byte[] iInitSaPkt;
    private byte[] localAddr;

    private byte[] initIDPayload = null;
    private byte[] ipsecSPI = null;


    public PktIKEAuthPSK(String patternFile, byte[] initspi, byte[] respspi, int msgid, IKEv2KeysGener keysGen,
                         byte[] r_nonce, byte[] i_initsa_pkt, String local_address, byte[] ipsec_spi) {
        super(initspi, respspi, msgid, keysGen);
        rNonce = r_nonce;
        if(i_initsa_pkt!=null) {
            iInitSaPkt = i_initsa_pkt;
        }else {
            iInitSaPkt = new byte[100];
        }
        //keysGenerator = keysGen;
        localAddr = DataUtils.ipToBytes(local_address);
        ipsecSPI = ipsec_spi;

        doConstruct(patternFile);
    }

    @Override
    public byte[] getPlaintext(Element plainRoot, int dataLen) {
        ByteBuffer bb = ByteBuffer.allocate(dataLen);
        Element eleId = plainRoot.element("payload_id");
        Element eleAuth = plainRoot.element("payload_auth");
        Element eleSa = plainRoot.element("payload_sa");
        Element eleTsi = plainRoot.element("payload_tsi");
        Element eleTsr = plainRoot.element("payload_tsr");
        Element eleNot = plainRoot.element("payload_notify");

        bb.put(ParseIdPayload(eleId));
        bb.put(ParseAuthPayload(eleAuth));
        bb.put(ParseSaPayload(eleSa));
        bb.put(ParseTsPayload(eleTsi));
        bb.put(ParseTsPayload(eleTsr));
        bb.put(ParseNotifyPayload(eleNot));

        return bb.array();
    }

    private byte[] ParseIdPayload(Element idRoot) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        ByteArrayOutputStream bInitIDPld = new ByteArrayOutputStream();
        Element pHdr = idRoot.element("p_header");
        Element pData = idRoot.element("data");
        byte[] hdr = ParsePayloadHdr(pHdr, pData);
        bAos.writeBytes(hdr);

        for(Iterator it = pData.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String eleName = element.getName();
            if(eleName.equals("id_data")){
                bAos.writeBytes(localAddr);
                bInitIDPld.writeBytes(localAddr);
            }else{
                try {
                    byte[] tmp = DataUtils.hexStrToBytes(element.getText());
                    bAos.writeBytes(tmp);
                    bInitIDPld.writeBytes(tmp);
                } catch (NumberFormatException e){
                    LOGGER.error("Convert Hex Error! ");
                    e.printStackTrace();
                }
            }
        }

        initIDPayload = bInitIDPld.toByteArray();
        return bAos.toByteArray();
    }

    private byte[] ParseAuthPayload(Element authRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = authRoot.element("p_header");
        Element pData = authRoot.element("data");
        byte[] hdr = ParsePayloadHdr(pHdr, pData);
        bAos.writeBytes(hdr);

        for(Iterator it = pData.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String eleName = element.getName();
            if(eleName.equals("auth_data")){
                int authLen = Integer.parseInt(element.attribute("size").getText());
                if(isEnc){
                    bAos.writeBytes(keysGenerator.calcAuthPsk(iInitSaPkt, rNonce, initIDPayload));
                }else{
                    bAos.writeBytes(DataUtils.genRandomBytes(authLen));
                }
            }else{
                try {
                    bAos.writeBytes(DataUtils.hexStrToBytes(element.getText()));
                } catch (NumberFormatException e){
                    LOGGER.error("Convert Hex Error! ");
                    e.printStackTrace();
                }
            }
        }
        return bAos.toByteArray();
    }

    protected byte[] ParseSaPayload(Element saRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = saRoot.element("p_header");
        Element pData = saRoot.element("data");
        byte[] hdr = ParsePayloadHdr(pHdr, pData);
        bAos.writeBytes(hdr);

        if(hdr.length != 4){
            LOGGER.error("Invalid payload header length: " + hdr.length);
            System.exit(-1);
        }

        /*
        byte[] bPropLen = new byte[2];
        bPropLen[0] = (byte) 0x00;
        bPropLen[1] = (byte) (hdr[3] - 4);

         */

        Element proposal = pData.element("proposal");
        byte[] propBytes = ParseProposal(proposal);
        bAos.writeBytes(propBytes);

        return bAos.toByteArray();
    }

    private byte[] ParseProposal(Element propRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        short propLen = (short) getTreeLen(propRoot, 0);
        for(Iterator it = propRoot.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String nodeName = element.getName();
            if("prop_header".equals(nodeName)){
                // Proposal Header
                bAos.writeBytes(ParsePropHdr(element, DataUtils.shortToBytesB(propLen)));
            }else{
                //Transform
                bAos.writeBytes(ParseTransform(element));
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParsePropHdr(Element element, byte[] bPropLen){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator itt = element.elementIterator(); itt.hasNext();){
            Element element1 = (Element) itt.next();
            switch (element1.getName()){
                case "proplen":
                    bAos.writeBytes(bPropLen);
                    break;
                case "spi":
                    bAos.writeBytes(ipsecSPI);
                    break;
                default:
                    String text = element1.getText();
                    bAos.writeBytes(DataUtils.hexStrToBytes(text));
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParseTransform(Element element) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator it = element.elementIterator();it.hasNext();){
            Element curele = (Element) it.next();
            String nodeName = curele.getName();
            if ("transattr".equals(nodeName)){
                bAos.writeBytes(ParseFinalField(curele));
            }else{
                try {
                    bAos.writeBytes(DataUtils.hexStrToBytes(curele.getText()));
                } catch (NumberFormatException e){
                    LOGGER.error("Convert Hex Error! ");
                    e.printStackTrace();
                }
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParseNotifyPayload(Element notifyRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = notifyRoot.element("p_header");
        Element pData = notifyRoot.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));
        bAos.writeBytes(ParseFinalField(pData));
        return bAos.toByteArray();
    }



    private byte[] ParseTsPayload(Element tsRoot){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element pHdr = tsRoot.element("p_header");
        Element pData = tsRoot.element("data");
        bAos.writeBytes(ParsePayloadHdr(pHdr, pData));

        Element tsNum = pData.element("ts_num");
        Element reserved = pData.element("reserved");
        Element ts = pData.element("ts");
        bAos.writeBytes(DataUtils.hexStrToBytes(tsNum.getText()));
        bAos.writeBytes(DataUtils.hexStrToBytes(reserved.getText()));
        bAos.writeBytes(ParseFinalField(ts));

        return bAos.toByteArray();
    }




}
