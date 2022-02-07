package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.utils.DataUtils;
// import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.dom4j.*;
import org.dom4j.io.SAXReader;
import java.io.*;
import java.util.Iterator;
import java.util.List;


public class PktIKEInitSA extends PktIKE {

    private byte[] ke;
    private byte[] nc;


    public PktIKEInitSA(String patternFile, byte[] initspi, byte[] respspi, int msgid, byte[] key_exchg, byte[] nonce)  {
        super(initspi, respspi, msgid);
        ke = key_exchg;
        nc = nonce;

        doConstruct(patternFile);
    }

    @Override
    public byte[] fromXMLToBytes(Element root) {
        Element ele_ih = root.element("ike_header");
        Element ele_sa = root.element("payload_sa");
        Element ele_ke = root.element("payload_ke");
        Element ele_nc = root.element("payload_nc");

        if (ele_ih!=null) {
            bout.writeBytes(ParseIKEHeader(ele_ih));
        }
        if(ele_sa!=null) {
            bout.writeBytes(ParseSAPayload(ele_sa));
        }
        if(ele_ke!=null) {
            bout.writeBytes(ParseKEPayload(ele_ke));
        }
        if(ele_nc!=null) {
            bout.writeBytes(ParseNCPayload(ele_nc));
        }
        try {
            bout.flush();
        } catch (IOException e){
            LOGGER.error("Byte stream flush error! ");
            e.printStackTrace();
        }
        return bout.toByteArray();
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


    private byte[] ParseNCPayload(Element nc_root) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element p_hdr = nc_root.element("p_header");
        Element p_data = nc_root.element("data");
        //ParseFinalField(p_hdr);
        bAos.writeBytes(ParsePayloadHdr(p_hdr, p_data));
        bAos.writeBytes(nc);
        return bAos.toByteArray();
    }

    private byte[] ParseKEPayload(Element ke_root) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element p_hdr = ke_root.element("p_header");
        Element p_data = ke_root.element("data");
        //ParseFinalField(p_hdr);
        bAos.writeBytes(ParsePayloadHdr(p_hdr, p_data));
        for(Iterator it = p_data.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String elename = element.getName();
            if(elename.equals("ke_data")){
                bAos.writeBytes(ke);
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

    private byte[] ParseSAPayload(Element sa_root) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        Element p_hdr = sa_root.element("p_header");
        Element p_data = sa_root.element("data");
        bAos.writeBytes(ParsePayloadHdr(p_hdr, p_data));
        bAos.writeBytes(ParseSAData(p_data));
        return bAos.toByteArray();
    }

    private byte[] ParseSAData(Element p_data) {
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        // For each Proposal
        for(Iterator it = p_data.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            bAos.writeBytes(ParseProposal(element));
        }
        return bAos.toByteArray();
    }

    private byte[] ParseProposal(Element proposal){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        short propLen = (short) getTreeLen(proposal, 0);
        for(Iterator it=proposal.elementIterator(); it.hasNext();) {
            Element element = (Element) it.next();
            String nodeName = element.getName();
            if("prop_header".equals(nodeName)){
                bAos.writeBytes(ParsePropHdr(element, DataUtils.shortToBytesB(propLen)));
            }else if("transform".equals(nodeName)){
                bAos.writeBytes(ParseTransform(element));
            }
        }
        return bAos.toByteArray();
    }

    private byte[] ParsePropHdr(Element element, byte[] bPropLen){
        ByteArrayOutputStream bAos = new ByteArrayOutputStream();
        for(Iterator itt = element.elementIterator(); itt.hasNext();){
            Element element1 = (Element) itt.next();
            if(element1.getName().equals("proplen")){
                bAos.writeBytes(bPropLen);
            }else{
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


}
