package gtrboy.learning;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import gtrboy.learning.FTP.FTPServerAdapterConfig;
import gtrboy.learning.FTP.FTPLearningMapper;
import gtrboy.learning.learn.Learner;
//import gtrboy.learning.FTP.FTPClientWrapper;
//import sut.MQTTClientWrapper;

import java.io.*;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

public class FTPMain {

    // add: read from configuration file
    private static String experimentName = "FTPModel";
    private static List<String> in_alphabets = Arrays.asList(
            "USER", "PASS", "PWD", "PORT", "RETR", "LIST", "CWD", "DELE", "QUIT");
    /*
    private static List<String> out_alphabets = Arrays.asList(
            "503_inval_seq", "500_syn_err",
            "200_cmd_ok","331_need_psw", "230_login_succ",
            "227_ent_pasv","150_open","226_trans_over","503_need_user","221_exit","421_timeout","QUIT");

     */

    public static void main(String[] args) throws NoSuchMethodException, IOException, InterruptedException {
        //FTPServerAdapterConfig ftpServerConfig = new FTPServerAdapterConfig(args[1]);
        String configFile = readJSONFile(args[0]);
        FTPServerAdapterConfig ftpServerConfig = JSON.parseObject(configFile, FTPServerAdapterConfig.class);


        // FTPClientWrapper ftpClient = new FTPClientWrapper(ftpServerConfig);
        // define the mapper used for learning (abstract -> concrete inputs)
        Learner ftpLearner = new Learner(new FTPLearningMapper(ftpServerConfig));

        // learning input alphabet
        //
        // invalid covers multiple invalid actions, such as subscribe, unsubscribe and publish with invalid input
        // and publish with system level topic



        // learned model is saved to learnedModels/MosquittoModel.dot
        ftpLearner.learn(3000, experimentName, in_alphabets); // COMMENT OUT if you want to skip learning and usead already existing model

    }

    public static String readJSONFile(String fileName) {
        String jsonStr = "";
        try {
            File jsonFile = new File(fileName);
            FileReader fileReader = new FileReader(jsonFile);
            Reader reader = new InputStreamReader(new FileInputStream(jsonFile),"utf-8");
            int ch = 0;
            StringBuilder sb = new StringBuilder();
            while ((ch = reader.read()) != -1) {
                sb.append((char) ch);
            }
            fileReader.close();
            reader.close();
            jsonStr = sb.toString();
            return jsonStr;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
