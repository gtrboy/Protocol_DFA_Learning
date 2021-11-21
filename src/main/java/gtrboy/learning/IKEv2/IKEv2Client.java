package gtrboy.learning.IKEv2;

import java.io.IOException;

public class IKEv2Client {

    private int msgid;

    public IKEv2Client(IKEv2Config config){
        msgid = 0;
    }

    private void addMsgId(){
        msgid = msgid + 1;
    }

    public void buildConnection() throws IOException {

    }

    public void reset() throws IOException {
        //this.connect(internetAddress, port);
    }


    public String saInitWithAcceptedSA(){

        addMsgId();
        return;
    }

    public String saInitWithUnacceptedSA(){

    }

    public String authWithPSK(){

    }

    public String authWithCert(){

    }

    public String authWithCertAndPSK(){

    }

    public String createChildSARekeyIKESA(){

    }

    public String createChildSARekeyChildSA(){

    }

    public String createChildSACreateChildSA(){

    }

    public String infoDelIKESA(){

    }

    public String infoDelChildSA(){

    }

    public String infoCPReqAppverwithOldSA(){

    }

    public String infoCPReqAppverwithNewSA(){

    }
}
