package gtrboy.learning.main;

import gtrboy.learning.IKEv2.IKEv2Config;
import gtrboy.learning.IKEv2.IKEv2LearningMapper;
import gtrboy.learning.learn.Learner;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.Arrays;
import java.util.List;

public class IKEv2Main {

    private static final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    // add: read from configuration file
    private static String experimentName = "IKEv2Model";

    /*
    private static List<String> in_alphabets = Arrays.asList(
            "SA_INIT_ACC", "AUTH_PSK", "REKEY_IKE_SA", "DEL_CUR_IKE_SA", "DEL_OLD_IKE_SA", "REKEY_CHILD_SA_CUR_IKE",
            "REKEY_CHILD_SA_OLD_IKE", "DEL_CUR_CHILD_SA_CUR_IKE", "DEL_CUR_CHILD_SA_OLD_IKE", "DEL_OLD_CHILD_SA_CUR_IKE",
            "DEL_OLD_CHILD_SA_OLD_IKE");
     */

    private static List<String> in_alphabets = Arrays.asList(
            "AUTH_PSK", "REKEY_IKE_SA", "DEL_CUR_IKE_SA", "DEL_OLD_IKE_SA", "REKEY_CHILD_SA_CUR_IKE", "REKEY_CHILD_SA_OLD_IKE",
            "DEL_CUR_CHILD_SA_CUR_IKE", "DEL_CUR_CHILD_SA_OLD_IKE", "DEL_OLD_CHILD_SA_CUR_IKE", "DEL_OLD_CHILD_SA_OLD_IKE"
            //"EMP_INFO_CUR", "EMP_ENC_INFO_CUR", "EMP_INFO_OLD", "EMP_ENC_INFO_CUR",
            //"EMP_INFO_CUR_RESP", "EMP_ENC_INFO_CUR_RESP", "EMP_INFO_OLD_RESP", "EMP_ENC_INFO_CUR_RESP"
    );

    public static void main(String[] args) throws NoSuchMethodException, IOException, InterruptedException {
        IKEv2Config config = new IKEv2Config("IKEv2/ikev2_config.properties");
        //LogUtils.LOG_LEVEL = config.getDebug();
        //LogUtils.logDebug("MAIN", "Enter Main");

        // FTPClientWrapper ftpClient = new FTPClientWrapper(ftpServerConfig);
        // define the mapper used for learning (abstract -> concrete inputs)
        Learner ikeLearner = new Learner(new IKEv2LearningMapper(config));

        // learning input alphabet
        //
        // invalid covers multiple invalid actions, such as subscribe, unsubscribe and publish with invalid input
        // and publish with system level topic



        // learned model is saved to learnedModels/MosquittoModel.dot
        ikeLearner.learn(3000, experimentName, in_alphabets); // COMMENT OUT if you want to skip learning and usead already existing model

    }

}
