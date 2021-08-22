package gtrboy.learning.FTP;

import de.learnlib.drivers.reflect.ConcreteMethodInput;
import de.learnlib.drivers.reflect.MethodInput;
import de.learnlib.drivers.reflect.ReturnValue;
import de.learnlib.mapper.api.SULMapper;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class FTPLearningMapper implements SULMapper<String, String, ConcreteMethodInput, Object> {
    FTPClient client;
    private Method mUSER;
    private Method mPASS;
    private Method mPWD;
    private Method mPORT;
    private Method mSTOR;
    private Method mRETR;
    private Method mLIST;
    private Method mCWD;
    private Method mDELE;
    private Method mQUIT;

    public FTPLearningMapper(FTPServerAdapterConfig config) throws UnknownHostException, NoSuchMethodException {
        this.client = new FTPClient(config);
        getMethods();
    }

    private void getMethods() throws NoSuchMethodException {
        mUSER = FTPClient.class.getMethod("ftp_user");
        mPASS = FTPClient.class.getMethod("ftp_pass");
        mPWD = FTPClient.class.getMethod("ftp_pwd");
        mPORT = FTPClient.class.getMethod("ftp_port");
        //mSTOR = FTPClient.class.getMethod("ftp_stor", String.class);
        mRETR = FTPClient.class.getMethod("ftp_retr");
        mLIST = FTPClient.class.getMethod("ftp_list");
        mCWD = FTPClient.class.getMethod("ftp_cwd");
        mDELE = FTPClient.class.getMethod("ftp_dele");
        mQUIT = FTPClient.class.getMethod("ftp_quit");
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
            case "USER":
                return getConcreteMethod("ftp_user", mUSER, Collections.emptyList());
            case "PASS":
                return getConcreteMethod("ftp_pass", mPASS, Collections.emptyList());
            case "PWD":
                return getConcreteMethod("ftp_pwd", mPWD, Collections.emptyList());
            case "PORT":
                return getConcreteMethod("ftp_port", mPORT, Collections.emptyList());
            //case "STOR":
            //    return getConcreteMethod("ftp_stor", mSTOR, Collections.emptyList());
            case "RETR":
                return getConcreteMethod("ftp_retr", mRETR, Collections.emptyList());
            case "LIST":
                return getConcreteMethod("ftp_list", mLIST, Collections.emptyList());
            case "CWD":
                return getConcreteMethod("ftp_cwd", mCWD, Collections.emptyList());
            case "DELE":
                return getConcreteMethod("ftp_dele", mDELE, Collections.emptyList());
            case "QUIT":
                return getConcreteMethod("ftp_quit", mQUIT, Collections.emptyList());
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
            // 每轮开始前恢复服务端目录状态
            client.arrangeServerDir();
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

