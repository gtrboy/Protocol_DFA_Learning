package gtrboy.learning.main;


import gtrboy.learning.IKEv2.IKEv2Client;
import gtrboy.learning.IKEv2.IKEv2Config;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import net.automatalib.visualization.Visualization;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class TestMain {

    private static final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);


    public static void main(String[] args) throws Exception{



        String dateStart = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss:SSS").format(new Date());
        long st = DataUtils.fromDateStringToLong(dateStart);
        LOGGER.debug("Start Time: " + dateStart);


        //client.prepare();

        int i=0;
        while(true)
        {
            System.out.println("------------");
            test1();
            System.out.println(i++);
            System.out.println("------------\n");
        }
        //calc();

        //calcRSADigest();

        //test1();

        //client.reset();

//        String dateEnd = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss:SSS").format(new Date());
////        long et = DataUtils.fromDateStringToLong(dateEnd);
////        float diffTime = (float) (et - st) / 1000;
////        LOGGER.debug("End Time: " + dateEnd);
////        LOGGER.debug("Use Time: " + diffTime + "s");

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


    /*
    public static void test(IKEv2Client client) throws IOException {
        String ret;
        while(true){
            client.InitSocket();
            ret = client.saInitWithAcceptedSa();
            logger.debug("ret: " + ret);
            client.reset();
        }
    }

     */

    public static void calcRSADigest() throws Exception {
        KeyPair keyPair = generatorRsaKey();
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(keyPair.getPrivate());
        //加解密数据
        byte[] data = "hello world".getBytes();
        //数据签名
        signature.update(data);
        byte[] digest = signature.sign();
        System.out.println("Digest: " + DataUtils.bytesToHexStr(digest));
        //数据解密加验证
        signature.initVerify(keyPair.getPublic());
        signature.update(data);
        System.out.println("验证结果:"+signature.verify(digest));
    }

    public static KeyPair generatorRsaKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        random.nextBytes(new byte[1024]);
        keyGen.initialize(1024,random);
        KeyPair keyPair = keyGen.genKeyPair();
        System.out.println(keyPair.getPrivate());
        System.out.println(keyPair.getPublic());
        return keyPair;
    }

    public static void calc(){
        byte[] sKeySeed = DataUtils.hexStrToBytes("45176cfc6ed05876eefb589beb0669c8c67fa576e5be2528668ff3a8cbcec9cb2b09492df056d963e6ecd76ec1b72e4d1aca0198ff012f2fbafbb994c02137ed");
        byte[] i_nonce = DataUtils.hexStrToBytes("ccc7c6e302a46be75f6215124774b59a95d7ffa6581d204ec1864301c04369fe");
        byte[] r_nonce = DataUtils.hexStrToBytes("e1ddc4f676aa58666d4eb155bae8be9138cc703ed18e4bdc12ec20b2659d0849");
        byte[] ispi = DataUtils.hexStrToBytes("fa15ad1044c24146");
        byte[] rspi = DataUtils.hexStrToBytes("a20de285cd16cc2b");

        String _hmacAlg = "HmacSHA512";
        int _encKeyLen = 32;
        int _hmacKeyLen = 64;

        try {
            ByteBuffer dataToSign = ByteBuffer.allocate(i_nonce.length + r_nonce.length + ispi.length + rspi.length);
            dataToSign.put(i_nonce).put(r_nonce).put(ispi).put(rspi);
            int keysLen = _encKeyLen*2 + _hmacKeyLen*3 + _hmacKeyLen*2;
            byte[] keyMats = generateKeyMat(_hmacAlg, sKeySeed, dataToSign.array(), keysLen);
            byte[] skD = new byte[_hmacKeyLen];
            byte[] skAi = new byte[_hmacKeyLen];
            byte[] skAr = new byte[_hmacKeyLen];
            byte[] skEi = new byte[_encKeyLen];
            byte[] skEr = new byte[_encKeyLen];
            byte[] skPi = new byte[_hmacKeyLen];
            byte[] skPr = new byte[_hmacKeyLen];
            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMats);
            keyMatBuffer.get(skD).get(skAi).get(skAr).get(skEi).get(skEr).get(skPi).get(skPr);
            LOGGER.debug("skD: " + DataUtils.bytesToHexStr(skD));
            LOGGER.debug("skAi: " + DataUtils.bytesToHexStr(skAi));
            LOGGER.debug("skAr: " + DataUtils.bytesToHexStr(skAr));
            LOGGER.debug("skEi: " + DataUtils.bytesToHexStr(skEi));
            LOGGER.debug("skEr: " + DataUtils.bytesToHexStr(skEr));
            LOGGER.debug("skPi: " + DataUtils.bytesToHexStr(skPi));
            LOGGER.debug("skPr: " + DataUtils.bytesToHexStr(skPr));
            LOGGER.info("{},{},{},{},\"AES-CBC-256 [RFC3602]\",{},{},\"HMAC_SHA2_512_256 [RFC4868]\"",
                    DataUtils.bytesToHexStr(ispi),
                    DataUtils.bytesToHexStr(rspi),
                    DataUtils.bytesToHexStr(skEi),
                    DataUtils.bytesToHexStr(skEr),
                    DataUtils.bytesToHexStr(skAi),
                    DataUtils.bytesToHexStr(skAr));

        }catch (InvalidKeyException e){
            LOGGER.error("Failed to generate key materials! ");
            e.printStackTrace();
        }catch (Exception e){
            LOGGER.error("Failed to put keys! ");
            e.printStackTrace();
        }
    }

    private static byte[] generateKeyMat(
            String hmacAlgorithm, byte[] prfKey, byte[] dataToSign, int keyMaterialLen)
            throws InvalidKeyException {
        try {
            SecretKeySpec prfKeySpec = new SecretKeySpec(prfKey, hmacAlgorithm);
            Mac prfMac = Mac.getInstance(hmacAlgorithm);

            ByteBuffer keyMatBuffer = ByteBuffer.allocate(keyMaterialLen);

            byte[] previousMac = new byte[0];
            final int padLen = 1;
            byte padValue = 1;

            while (keyMatBuffer.remaining() > 0) {
                prfMac.init(prfKeySpec);

                ByteBuffer dataToSignBuffer =
                        ByteBuffer.allocate(previousMac.length + dataToSign.length + padLen);
                dataToSignBuffer.put(previousMac).put(dataToSign).put(padValue);
                dataToSignBuffer.rewind();

                prfMac.update(dataToSignBuffer);

                previousMac = prfMac.doFinal();
                keyMatBuffer.put(
                        previousMac, 0, Math.min(previousMac.length, keyMatBuffer.remaining()));

                padValue++;
            }

            return keyMatBuffer.array();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            LOGGER.error("Failed to generate keying material");
            e.printStackTrace();
            //throw new IllegalArgumentException("Failed to generate keying material", e);
        }
        return null;
    }


    public static void test() throws IOException {
        String ret;

        IKEv2Config config = new IKEv2Config("IKEv2/ikev2_config.properties");
        //LogUtils.LOG_LEVEL = config.getDebug();
        IKEv2Client client = new IKEv2Client(config);

        client.prepare();

        //ret = client.saInitWithAcceptedSa();
        //logger.debug("ret: " + ret);

        //ret = client.authWithPsk();
        //logger.debug("ret: " + ret);

        //client.authWithCert();
        //client.authWithCertHttp();

        //ret = client.rekeyChildSaWithCurIkeSa();
        //System.out.println("ret: " + ret);
        //client.authWithCertHttp();

        client.authWithPsk();

        client.rekeyIkeSa();

        client.delCurIkeSa();

        // client.rekeyIkeSa();

        client.delOldChildSaWithOldIkeSa();

        //client.emptyInfoCurResp();

        //client.rekeyChildSaWithCurIkeSa();

        //client.authWithPsk();

        //ret = client.rekeyIkeSa();

        //ret = client.rekeyIkeSa();

        //ret = client.rekeyIkeSa();

        //ret = client.delOldIkeSa();
        //System.out.println("ret: " + ret);

        //ret = client.delCurIkeSa();
        //System.out.println("ret: " + ret);

        client.reset();

        //ret = client.authWithPsk();
        //System.out.println("ret: " + ret);

    }

    public static void test1() throws IOException {
        String ret;

        IKEv2Config config = new IKEv2Config("IKEv2/ikev2_config.properties");
        //LogUtils.LOG_LEVEL = config.getDebug();
        IKEv2Client client = new IKEv2Client(config);

        client.prepare();

        //ret = client.saInitWithAcceptedSa();
        //logger.debug("ret: " + ret);

        //ret = client.authWithPsk();
        //logger.debug("ret: " + ret);

        //client.authWithCert();
        //client.authWithCertHttp();

        //ret = client.rekeyChildSaWithCurIkeSa();
        //System.out.println("ret: " + ret);
        //client.authWithCertHttp();

        client.authWithPsk();

        client.rekeyIkeSa();

        client.rekeyChildSaWithCurIkeSa();

        client.delCurIkeSa();

        // client.rekeyChildSaWithCurIkeSa();

        client.delOldChildSaWithOldIkeSa();

        // client.rekeyChildSaWithCurIkeSa();

        // client.rekeyIkeSa();

        // client.delOldChildSaWithOldIkeSa();

        //client.emptyInfoCurResp();

        //client.rekeyChildSaWithCurIkeSa();

        //client.authWithPsk();

        //ret = client.rekeyIkeSa();

        //ret = client.rekeyIkeSa();

        //ret = client.rekeyIkeSa();

        //ret = client.delOldIkeSa();
        //System.out.println("ret: " + ret);

        //ret = client.delCurIkeSa();
        //System.out.println("ret: " + ret);

        client.reset();

        //ret = client.authWithPsk();
        //System.out.println("ret: " + ret);

    }


}
