package gtrboy.learning.main;


import gtrboy.learning.IKEv2.IKEv2Client;
import gtrboy.learning.IKEv2.IKEv2Config;
import gtrboy.learning.utils.LogUtils;

import java.io.File;


public class TestMain {

    private static int totallen = 0;
    private static final String KEY_DH = "DH";
    private static final int KEY_SIZE = 2048;
    private static final int DH_GROUP = 14;
    private static final int DH_GROUP_1024_BIT_MODP_DATA_LEN = 128;
    private static final int DH_GROUP_2048_BIT_MODP_DATA_LEN = 256;
    private static final String MODEL_DIR = "learnedModels/";


    public static void main(String[] args) throws Exception{


        IKEv2Config config = new IKEv2Config("IKEv2/ikev2_config.properties");
        LogUtils.LOG_LEVEL = config.getDebug();
        IKEv2Client client = new IKEv2Client(config);
        client.prepare();


        test(client);


        //client.telRemoveSession();

        //ret = client.delOldIkeSa();
        //System.out.println("ret: " + ret);

        //ret = client.delCurIkeSa();
        //System.out.println("ret: " + ret);

        //Thread.sleep(10000);



/*
        TelnetMain tel = new TelnetMain("100.1.1.100", "cisco");
        tel.connect();
        tel.sendCommand("clear crypto ikev2 sa fast");
        tel.disconnect();
 */


/*
        byte[] key = DataUtils.hexStrToBytes("38a7045fb27b57979f4b3e2b8fca6545de1911db8467ede9d1d415c35b81569a");
        byte[] iv = DataUtils.hexStrToBytes("aecb5fdc96e83a0fc3b8ae2f82a25631");
        byte[] encTxt = DataUtils.hexStrToBytes("442201239cfd6f504e0d5a63fae13e347bf86190d36b78b65783944ccdc7bb5bae3d3709f0729d79965180d215da7b1fe16627879060eb69b3e5fc7ccf6c6c912a76dc71c958df99df1fba2548bb8f138351fe4f6e4428ef1c223a16aef10df381a3548ab0569a3822ad8f0004fb37e0c23651f784f9a4d8e61cc52acd5d13431dd450671b2877fbcd1f041c2125dc0141bb93fdc71747e844a786a3a96c52e99f77f3ee7efbebd22e8a9050fd8cef03ecca9208f869eab6a74521a68030ee822386c10a11d5fb0be07821de08eed59029e55c443817b3896ab3f31a20a0adde");
        byte[] decTxt = decrypt(encTxt, key, iv);
        System.out.println(decTxt.length);
        System.out.println(DataUtils.bytesToHexStr(decTxt));
*/


    }

    public static void test(IKEv2Client client){
        String ret;

        ret = client.saInitWithAcceptedSa();
        System.out.println("ret: " + ret);

        ret = client.authWithPsk();
        System.out.println("ret: " + ret);

        ret = client.rekeyIkeSa();
        System.out.println("ret: " + ret);

        ret = client.delOldIkeSa();
        System.out.println("ret: " + ret);


    }

    public static void test5(IKEv2Client client){
        String ret;

        ret = client.saInitWithAcceptedSa();
        System.out.println("ret: " + ret);

        ret = client.authWithPsk();
        System.out.println("ret: " + ret);

        ret = client.delCurIkeSa();
        System.out.println("ret: " + ret);


    }

    public static void test4(IKEv2Client client){
        String ret;

        ret = client.saInitWithAcceptedSa();
        System.out.println("ret: " + ret);

        ret = client.authWithPsk();
        System.out.println("ret: " + ret);

        ret = client.rekeyIkeSa();
        System.out.println("ret: " + ret);

        ret = client.delOldIkeSa();
        System.out.println("ret: " + ret);

        ret = client.delCurIkeSa();
        System.out.println("ret: " + ret);


    }

    public static void test3(IKEv2Client client){
        String ret;

        ret = client.saInitWithAcceptedSa();
        System.out.println("ret: " + ret);

        ret = client.authWithPsk();
        System.out.println("ret: " + ret);

        // Rekey IKE SA
        ret = client.rekeyIkeSa();
        System.out.println("ret: " + ret);

        // Use New IKE SA (before deletion) to rekey child SA
        // Child SA 继承于旧的SA，但是未删除之前是否能够使用？
        ret = client.rekeyChildSaWithCurIkeSa();
        System.out.println("ret: " + ret);
    }

    public static void test2(IKEv2Client client){
        String ret;

        ret = client.saInitWithAcceptedSa();
        System.out.println("ret: " + ret);

        ret = client.authWithPsk();
        System.out.println("ret: " + ret);

        ret = client.rekeyChildSaWithCurIkeSa();
        System.out.println("ret: " + ret);

        ret = client.delOldChildSaWithCurIkeSa();
        System.out.println("ret: " + ret);

        ret = client.delCurIkeSa();
        System.out.println("ret: " + ret);
    }

    public static void test1(IKEv2Client client){
        String ret;

        ret = client.saInitWithAcceptedSa();
        System.out.println("ret: " + ret);

        ret = client.authWithPsk();
        System.out.println("ret: " + ret);

        // rekey IKE SA
        ret = client.rekeyIkeSa();
        System.out.println("ret: " + ret);

        // rekey Child SA over Old IKE SA
        ret = client.rekeyChildSaWithOldIkeSa();
        System.out.println("ret: " + ret);

        // delete Child SA over Old IKE SA
        ret = client.delOldChildSaWithOldIkeSa();
        System.out.println("ret: " + ret);

        // delete Old IKE SA
        ret = client.delOldIkeSa();
        System.out.println("ret: " + ret);

        // delete Current IKE SA
        ret = client.delCurIkeSa();
        System.out.println("ret: " + ret);
    }

}
