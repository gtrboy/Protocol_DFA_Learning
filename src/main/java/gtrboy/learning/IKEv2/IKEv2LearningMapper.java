package gtrboy.learning.IKEv2;

import de.learnlib.drivers.reflect.ConcreteMethodInput;
import de.learnlib.drivers.reflect.MethodInput;
import de.learnlib.drivers.reflect.ReturnValue;
import de.learnlib.mapper.api.SULMapper;
import gtrboy.learning.FTP.FTPClient;
import gtrboy.learning.FTP.FTPServerAdapterConfig;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;


public class IKEv2LearningMapper implements SULMapper<String, String, ConcreteMethodInput, Object> {
    IKEv2Client client;
    private Method m_SA_INIT_ACC;
    private Method m_SA_INIT_UNACC;
    private Method m_AUTH_PSK;
    private Method m_AUTH_CERT;
    private Method m_AUTH_CERT_PSK;
    private Method m_CRE_CH_SA_REK_IKE_SA;
    private Method m_CRE_CH_SA_REK_CLD_SA;
    private Method m_CRE_CH_SA_CRE_CLD_SA;
    private Method m_INFO_DEL_IKE_SA;
    private Method m_INFO_DEL_CLD_SA;
    private Method m_INFO_CP_APPV_OLD_SA;
    private Method m_INFO_CP_APPV_NEW_SA;

    public IKEv2LearningMapper(IKEv2Config config) throws UnknownHostException, NoSuchMethodException {
        this.client = new IKEv2Client(config);
        getMethods();
    }

    private void getMethods() throws NoSuchMethodException {
        m_SA_INIT_ACC = IKEv2Client.class.getMethod("saInitWithAcceptedSA");
        m_SA_INIT_UNACC = IKEv2Client.class.getMethod("saInitWithUnacceptedSA");
        m_AUTH_PSK = IKEv2Client.class.getMethod("authWithPSK");
        m_AUTH_CERT = IKEv2Client.class.getMethod("authWithCert");
        m_AUTH_CERT_PSK = IKEv2Client.class.getMethod("authWithCertAndPSK");
        m_CRE_CH_SA_REK_IKE_SA = IKEv2Client.class.getMethod("createChildSARekeyIKESA");
        m_CRE_CH_SA_REK_CLD_SA = IKEv2Client.class.getMethod("createChildSARekeyChildSA");
        m_CRE_CH_SA_CRE_CLD_SA = IKEv2Client.class.getMethod("createChildSACreateChildSA");
        m_INFO_DEL_IKE_SA = IKEv2Client.class.getMethod("infoDelIKESA");
        m_INFO_DEL_CLD_SA = IKEv2Client.class.getMethod("infoDelChildSA");
        m_INFO_CP_APPV_OLD_SA = IKEv2Client.class.getMethod("infoCPReqAppverwithOldSA");
        m_INFO_CP_APPV_NEW_SA = IKEv2Client.class.getMethod("infoCPReqAppverwithNewSA");
        // random = new Random();
    }

    private ConcreteMethodInput getConcreteMethod(String name, Method method, List<String> params){
        MethodInput mi = new MethodInput(name, method, new HashMap<>(), params.toArray());
        return new ConcreteMethodInput(mi, new HashMap<>(), client);
    }

    // 一个Word中的每个letter的映射
    @Override
    public ConcreteMethodInput mapInput(String abstractInput) {
        switch (abstractInput){
            case "SA_INIT_ACC":
                return getConcreteMethod("saInitWithAcceptedSA", m_SA_INIT_ACC, Collections.emptyList());
            case "SA_INIT_UNACC":
                return getConcreteMethod("saInitWithUnacceptedSA", m_SA_INIT_UNACC, Collections.emptyList());
            case "AUTH_PSK":
                return getConcreteMethod("authWithPSK", m_AUTH_PSK, Collections.emptyList());
            case "AUTH_CERT":
                return getConcreteMethod("authWithCert", m_AUTH_CERT, Collections.emptyList());
            case "AUTH_CERT_PSK":
                return getConcreteMethod("authWithCertAndPSK", m_AUTH_CERT_PSK, Collections.emptyList());
            case "CRE_CH_SA_REK_IKE_SA":
                return getConcreteMethod("createChildSARekeyIKESA", m_CRE_CH_SA_REK_IKE_SA, Collections.emptyList());
            case "CRE_CH_SA_REK_CLD_SA":
                return getConcreteMethod("createChildSARekeyChildSA", m_CRE_CH_SA_REK_CLD_SA, Collections.emptyList());
            case "CRE_CH_SA_CRE_CLD_SA":
                return getConcreteMethod("createChildSACreateChildSA", m_CRE_CH_SA_CRE_CLD_SA, Collections.emptyList());
            case "INFO_DEL_IKE_SA":
                return getConcreteMethod("infoDelIKESA", m_INFO_DEL_IKE_SA, Collections.emptyList());
            case "INFO_DEL_CLD_SA":
                return getConcreteMethod("infoDelChildSA", m_INFO_DEL_CLD_SA, Collections.emptyList());
            case "INFO_CP_APPV_OLD_SA":
                return getConcreteMethod("infoCPReqAppverwithOldSA", m_INFO_CP_APPV_OLD_SA, Collections.emptyList());
            case "INFO_CP_APPV_NEW_SA":
                return getConcreteMethod("infoCPReqAppverwithNewSA", m_INFO_CP_APPV_NEW_SA, Collections.emptyList());
            default:
                throw new IllegalStateException("Unexpected value: " + abstractInput);
        }
    }

    @Override
    public String mapOutput(Object concreteOutput) {
        return new ReturnValue(concreteOutput).toString();
    }

    // 在每次一个word（输入序列）执行之前被调用
    @Override
    public void pre() {
        SULMapper.super.pre();
        try {
            client.buildConnection();
            // client.arrangeServerDir();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 在每次一个word（输入序列）执行之后被调用
    @Override
    public void post() {
        SULMapper.super.post();
        try {
            client.reset();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
