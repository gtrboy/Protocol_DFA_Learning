package gtrboy.learning.IKEv2;

import de.learnlib.drivers.reflect.ConcreteMethodInput;
import de.learnlib.drivers.reflect.MethodInput;
import de.learnlib.drivers.reflect.ReturnValue;
import de.learnlib.mapper.api.SULMapper;
import gtrboy.learning.FTP.FTPClient;
import gtrboy.learning.FTP.FTPServerAdapterConfig;
import gtrboy.learning.utils.LogUtils;

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
    private Method m_REKEY_IKE_SA;
    private Method m_DEL_CUR_IKE_SA;
    private Method m_DEL_OLD_IKE_SA;
    private Method m_REKEY_CHILD_SA_CUR_IKE;
    private Method m_REKEY_CHILD_SA_OLD_IKE;
    private Method m_DEL_CUR_CHILD_SA_CUR_IKE;
    private Method m_DEL_CUR_CHILD_SA_OLD_IKE;
    private Method m_DEL_OLD_CHILD_SA_CUR_IKE;
    private Method m_DEL_OLD_CHILD_SA_OLD_IKE;


    public IKEv2LearningMapper(IKEv2Config config) {
        try {
            this.client = new IKEv2Client(config);
            getMethods();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private void getMethods() throws NoSuchMethodException {
        //m_SA_INIT_ACC = IKEv2Client.class.getMethod("saInitWithAcceptedSa");
        //m_SA_INIT_UNACC = IKEv2Client.class.getMethod("saInitWithUnacceptedSA");
        m_AUTH_PSK = IKEv2Client.class.getMethod("authWithPsk");
        //m_AUTH_CERT = IKEv2Client.class.getMethod("authWithCert");
        //m_AUTH_CERT_PSK = IKEv2Client.class.getMethod("authWithCertAndPSK");
        m_REKEY_IKE_SA = IKEv2Client.class.getMethod("rekeyIkeSa");
        m_DEL_CUR_IKE_SA = IKEv2Client.class.getMethod("delCurIkeSa");
        m_DEL_OLD_IKE_SA = IKEv2Client.class.getMethod("delOldIkeSa");
        m_REKEY_CHILD_SA_CUR_IKE = IKEv2Client.class.getMethod("rekeyChildSaWithCurIkeSa");
        m_REKEY_CHILD_SA_OLD_IKE = IKEv2Client.class.getMethod("rekeyChildSaWithOldIkeSa");
        m_DEL_CUR_CHILD_SA_CUR_IKE = IKEv2Client.class.getMethod("delCurChildSaWithCurIkeSa");
        m_DEL_CUR_CHILD_SA_OLD_IKE = IKEv2Client.class.getMethod("delCurChildSaWithOldIkeSa");
        m_DEL_OLD_CHILD_SA_CUR_IKE = IKEv2Client.class.getMethod("delOldChildSaWithCurIkeSa");
        m_DEL_OLD_CHILD_SA_OLD_IKE = IKEv2Client.class.getMethod("delOldChildSaWithOldIkeSa");
        //m_INFO_CP_APPV_NEW_SA = IKEv2Client.class.getMethod("infoCPReqAppverwithNewSA");
        // random = new Random();
    }

    private ConcreteMethodInput getConcreteMethod(String name, Method method, List<String> params){
        MethodInput mi = new MethodInput(name, method, new HashMap<>(), params.toArray());
        return new ConcreteMethodInput(mi, new HashMap<>(), client);
    }

    // 一个Word中的每个letter的映射
    /*
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
     */
    @Override
    public ConcreteMethodInput mapInput(String abstractInput) {
        switch (abstractInput){
            //case "SA_INIT_ACC":
            //    return getConcreteMethod("saInitWithAcceptedSa", m_SA_INIT_ACC, Collections.emptyList());
            case "AUTH_PSK":
                return getConcreteMethod("authWithPsk", m_AUTH_PSK, Collections.emptyList());
            case "REKEY_IKE_SA":
                return getConcreteMethod("rekeyIkeSa", m_REKEY_IKE_SA, Collections.emptyList());
            case "DEL_CUR_IKE_SA":
                return getConcreteMethod("delCurIkeSa", m_DEL_CUR_IKE_SA, Collections.emptyList());
            case "DEL_OLD_IKE_SA":
                return getConcreteMethod("delOldIkeSa", m_DEL_OLD_IKE_SA, Collections.emptyList());
            case "REKEY_CHILD_SA_CUR_IKE":
                return getConcreteMethod("rekeyChildSaWithCurIkeSa", m_REKEY_CHILD_SA_CUR_IKE, Collections.emptyList());
            case "REKEY_CHILD_SA_OLD_IKE":
                return getConcreteMethod("rekeyChildSaWithOldIkeSa", m_REKEY_CHILD_SA_OLD_IKE, Collections.emptyList());
            case "DEL_CUR_CHILD_SA_CUR_IKE":
                return getConcreteMethod("delCurChildSaWithCurIkeSa", m_DEL_CUR_CHILD_SA_CUR_IKE, Collections.emptyList());
            case "DEL_CUR_CHILD_SA_OLD_IKE":
                return getConcreteMethod("delCurChildSaWithOldIkeSa", m_DEL_CUR_CHILD_SA_OLD_IKE, Collections.emptyList());
            case "DEL_OLD_CHILD_SA_CUR_IKE":
                return getConcreteMethod("delOldChildSaWithCurIkeSa", m_DEL_OLD_CHILD_SA_CUR_IKE, Collections.emptyList());
            case "DEL_OLD_CHILD_SA_OLD_IKE":
                return getConcreteMethod("delOldChildSaWithOldIkeSa", m_DEL_OLD_CHILD_SA_OLD_IKE, Collections.emptyList());
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
        LogUtils.logInfo(this.getClass().getName(), "-----------------------------------------");
        SULMapper.super.pre();
        try {
            client.prepare();
            // client.arrangeServerDir();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 在每次一个word（输入序列）执行之后被调用
    @Override
    public void post() {
        SULMapper.super.post();
        try {
            client.reset();
            //Thread.sleep(200);
        } catch (IOException  e) {
            e.printStackTrace();
        }
        LogUtils.logInfo(this.getClass().getName(), "-----------------------------------------\n\n");
    }
}
