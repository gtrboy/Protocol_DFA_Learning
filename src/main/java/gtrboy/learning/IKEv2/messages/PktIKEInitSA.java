package gtrboy.learning.IKEv2.messages;

import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.dom4j.*;
import org.dom4j.io.SAXReader;
import java.io.*;
import java.util.Iterator;
import java.util.List;


public class PktIKEInitSA extends PktIKE {


    private byte[] packetbytes;
    private byte[] ke;
    private byte[] nc;

    public PktIKEInitSA(byte[] initspi, byte[] respspi, int msgid, byte nextpld, byte exchtype, byte[] key_exchg, byte[] nonce) throws Exception {
        super(initspi, respspi, msgid, nextpld, exchtype);
        ke = key_exchg;
        nc = nonce;
        String xmlpath = this.getClass().getResource("/IKEv2Messages/ike_init_sa_acc_sa.xml").getPath();
        Document document = getXMLDocument(xmlpath);
        packetbytes = fromXMLToBytes(document);
    }

    public byte[] getPacketBytes(){
        return packetbytes;
    }

    private byte[] fromXMLToBytes(Document doc) throws IOException {
        Element root = doc.getRootElement();
        getTotalLen(root);

        Element ele_ih = root.element("ike_header");
        Element ele_sa = root.element("payload_sa");
        Element ele_ke = root.element("payload_ke");
        Element ele_nc = root.element("payload_nc");

        ParseIKEHeader(ele_ih);
        ParseSAPayload(ele_sa);
        ParseKEPayload(ele_ke);
        ParseNCPayload(ele_nc);

        bout.flush();
        return bout.toByteArray();
    }


    private void ParseNCPayload(Element nc_root) {
        Element p_hdr = nc_root.element("p_header");
        Element p_data = nc_root.element("data");
        ParseFinalField(p_hdr);
        bout.writeBytes(nc);
    }

    private void ParseKEPayload(Element ke_root) {
        Element p_hdr = ke_root.element("p_header");
        Element p_data = ke_root.element("data");
        ParseFinalField(p_hdr);
        for(Iterator it = p_data.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String elename = element.getName();
            if(elename.equals("ke_data")){
                bout.writeBytes(ke);
            }else{
                bout.writeBytes(DataUtils.hexStrToBytes(element.getText()));
            }
        }
    }

    private void ParseSAPayload(Element sa_root) {

        Element p_hdr = sa_root.element("p_header");
        Element p_data = sa_root.element("data");
        ParsePayloadHdr(p_hdr);
        ParseSAData(p_data);
    }

    private void ParseSAData(Element p_data) {
        Element proposal = p_data.element("proposal");
        for(Iterator it = proposal.elementIterator(); it.hasNext();){
            Element element = (Element) it.next();
            String nodeName = element.getName();
            if("prop_header".equals(nodeName)){
                ParseFinalField(element);
            }else{
                ParseTransform(element);
            }
        }
    }

    private void ParseTransform(Element element) {
        for(Iterator it = element.elementIterator();it.hasNext();){
            Element curele = (Element) it.next();
            String nodeName = curele.getName();
            if ("transattr".equals(nodeName)){
                ParseFinalField(curele);
            }else{
                bout.writeBytes(DataUtils.hexStrToBytes(curele.getText()));
            }
        }

    }


}
