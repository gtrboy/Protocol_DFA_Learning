package gtrboy.learning.IKEv2;

import gtrboy.learning.utils.BigIntegerUtils;
import gtrboy.learning.utils.DataUtils;
import gtrboy.learning.utils.LogUtils;

import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class IKEv2KeysGener {
    private DHPrivateKeySpec localPrivateKeySpec;
    private byte[] pub_key;
    private byte[] sharedSecret = null;
    private byte[] sKeySeed = null;
    private int integ_key_len = 64;
    private int enc_key_len = 32;
    private int aes_block_size = 16;
    private int prf_key_len = 64;
    private byte[] skD = null;
    private byte[] skAi = null;
    private byte[] skAr = null;
    private byte[] skEi = null;
    private byte[] skEr = null;
    private byte[] skPi = null;
    private byte[] skPr = null;

    private static final String KEY_DH = "DH";
    private int dhGroup = 14;
    private static final int DH_GROUP_1024_BIT_MODP_DATA_LEN = 128;
    private static final int DH_GROUP_2048_BIT_MODP_DATA_LEN = 256;
    private static final String IV_HEX_STR = "a0a0a0a0b0b0b0b0c0c0c0c0d0d0d0d0";
    private byte[] iv;
    public String prfAlg = null;
    public String intgAlg = null;
    private String psk = null;


    public IKEv2KeysGener(int dh_group, String prf, String integrity, String preSecKey, int intKeyLen,
                          int encKeyLen, int prfKeyLen, int aesBlockSize){
        dhGroup = dh_group;
        prfAlg = prf;
        intgAlg = integrity;
        psk = preSecKey;
        integ_key_len = intKeyLen;
        enc_key_len = encKeyLen;
        aes_block_size = aesBlockSize;
        prf_key_len = prfKeyLen;
        iv = DataUtils.hexStrToBytes(IV_HEX_STR);
        InitDHKeys();
    }

    private void InitDHKeys() {
        BigInteger prime = BigInteger.ZERO;
        int keySize = 0;
        switch (dhGroup) {
            case 2:
                prime =
                        BigIntegerUtils.unsignedHexStringToBigInteger(
                                IkeDhParams.PRIME_1024_BIT_MODP);
                keySize = DH_GROUP_1024_BIT_MODP_DATA_LEN;
                break;
            case 14:
                prime =
                        BigIntegerUtils.unsignedHexStringToBigInteger(
                                IkeDhParams.PRIME_2048_BIT_MODP);
                keySize = DH_GROUP_2048_BIT_MODP_DATA_LEN;
                break;
            default:
                LogUtils.logErrExit(this.getClass().getName(), "DH group not supported! ");
        }

        try {
            BigInteger baseGen = BigInteger.valueOf(IkeDhParams.BASE_GENERATOR_MODP);
            DHParameterSpec dhParam = new DHParameterSpec(prime, baseGen);

            KeyPairGenerator dhKeyPairGen = KeyPairGenerator.getInstance(KEY_DH);
            dhKeyPairGen.initialize(dhParam, new SecureRandom());
            KeyPair keyPair = dhKeyPairGen.generateKeyPair();

            DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
            DHPrivateKeySpec dhPrivateKeySpec = new DHPrivateKeySpec(privateKey.getX(), prime, baseGen);
            DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();

            pub_key = BigIntegerUtils.bigIntegerToUnsignedByteArray(publicKey.getY(), keySize);
            localPrivateKeySpec = dhPrivateKeySpec;
            //return pub_key;
            //priv_key = privateKey.toString().getBytes();

        } catch (NoSuchAlgorithmException e) {
            LogUtils.logException(e, this.getClass().getName(), "No such algorithm! ");
        } catch (InvalidAlgorithmParameterException e) {
            LogUtils.logException(e, this.getClass().getName(), "Failed to initialize key generator! ");
        }
        //return null;
    }

    public byte[] getPubKey(){
        return pub_key;
    }

    /************* Keys ***************/

    public void genKeys(byte[] ispi, byte[] rspi, byte[] i_nonce, byte[] r_nonce, byte[] r_ke){
        try {
            sharedSecret = getSharedKey(localPrivateKeySpec, r_ke);
            ByteBuffer keyBuffer = ByteBuffer.allocate(i_nonce.length + r_nonce.length);
            keyBuffer.put(i_nonce).put(r_nonce);
            sKeySeed = generateSKeySeed(prfAlg, keyBuffer.array(), sharedSecret);

            ByteBuffer dataToSign = ByteBuffer.allocate(i_nonce.length + r_nonce.length + ispi.length + rspi.length);
            dataToSign.put(i_nonce).put(r_nonce).put(ispi).put(rspi);
            int keysLen = enc_key_len*2 + prf_key_len*3 + integ_key_len*2;
            byte[] keyMats = generateKeyMat(prfAlg, sKeySeed, dataToSign.array(), keysLen);
            skD = new byte[prf_key_len];
            skAi = new byte[integ_key_len];
            skAr = new byte[integ_key_len];
            skEi = new byte[enc_key_len];
            skEr = new byte[enc_key_len];
            skPi = new byte[prf_key_len];
            skPr = new byte[prf_key_len];
            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMats);
            keyMatBuffer.get(skD).get(skAi).get(skAr).get(skEi).get(skEr).get(skPi).get(skPr);
            LogUtils.logDebug(this.getClass().getName(), "skD: " + DataUtils.bytesToHexStr(skD));
            LogUtils.logDebug(this.getClass().getName(), "skAi: " + DataUtils.bytesToHexStr(skAi));
            LogUtils.logDebug(this.getClass().getName(), "skAr: " + DataUtils.bytesToHexStr(skAr));
            LogUtils.logDebug(this.getClass().getName(), "skEi: " + DataUtils.bytesToHexStr(skEi));
            LogUtils.logDebug(this.getClass().getName(), "skEr: " + DataUtils.bytesToHexStr(skEr));
            LogUtils.logDebug(this.getClass().getName(), "skPi: " + DataUtils.bytesToHexStr(skPi));
            LogUtils.logDebug(this.getClass().getName(), "skPr: " + DataUtils.bytesToHexStr(skPr));
            System.out.printf("\n%s,%s,%s,%s,\"AES-CBC-256 [RFC3602]\",%s,%s,\"HMAC_SHA2_512_256 [RFC4868]\"\n\n",
                    DataUtils.bytesToHexStr(ispi),
                    DataUtils.bytesToHexStr(rspi),
                    DataUtils.bytesToHexStr(skEi),
                    DataUtils.bytesToHexStr(skEr),
                    DataUtils.bytesToHexStr(skAi),
                    DataUtils.bytesToHexStr(skAr));

        }catch (InvalidKeyException e){
            LogUtils.logException(e, this.getClass().getName(), "Failed to generate key materials! ");
        }catch (Exception e){
            LogUtils.logException(e, this.getClass().getName(), "Failed to put keys! ");
        }
    }

    // SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
    public void reGenKeys(byte[] skD_old, byte[] ispi, byte[] rspi, byte[] i_nonce, byte[] r_nonce, byte[] r_ke){
        try {
            sharedSecret = getSharedKey(localPrivateKeySpec, r_ke);
            ByteBuffer bBuf = ByteBuffer.allocate(sharedSecret.length + i_nonce.length + r_nonce.length);
            bBuf.put(sharedSecret).put(i_nonce).put(r_nonce);
            sKeySeed = generateSKeySeed(prfAlg, skD_old, bBuf.array());
            ByteBuffer dataToSign = ByteBuffer.allocate(i_nonce.length + r_nonce.length + ispi.length + rspi.length);
            dataToSign.put(i_nonce).put(r_nonce).put(ispi).put(rspi);
            int keysLen = enc_key_len*2 + prf_key_len*3 + integ_key_len*2;
            byte[] keyMats = generateKeyMat(prfAlg, sKeySeed, dataToSign.array(), keysLen);
            skD = new byte[prf_key_len];
            skAi = new byte[integ_key_len];
            skAr = new byte[integ_key_len];
            skEi = new byte[enc_key_len];
            skEr = new byte[enc_key_len];
            skPi = new byte[prf_key_len];
            skPr = new byte[prf_key_len];
            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMats);
            keyMatBuffer.get(skD).get(skAi).get(skAr).get(skEi).get(skEr).get(skPi).get(skPr);
            LogUtils.logDebug(this.getClass().getName(), "skD: " + DataUtils.bytesToHexStr(skD));
            LogUtils.logDebug(this.getClass().getName(), "skAi: " + DataUtils.bytesToHexStr(skAi));
            LogUtils.logDebug(this.getClass().getName(), "skAr: " + DataUtils.bytesToHexStr(skAr));
            LogUtils.logDebug(this.getClass().getName(), "skEi: " + DataUtils.bytesToHexStr(skEi));
            LogUtils.logDebug(this.getClass().getName(), "skEr: " + DataUtils.bytesToHexStr(skEr));
            LogUtils.logDebug(this.getClass().getName(), "skPi: " + DataUtils.bytesToHexStr(skPi));
            LogUtils.logDebug(this.getClass().getName(), "skPr: " + DataUtils.bytesToHexStr(skPr));
            System.out.printf("\n%s,%s,%s,%s,\"AES-CBC-256 [RFC3602]\",%s,%s,\"HMAC_SHA2_512_256 [RFC4868]\"\n\n",
                    DataUtils.bytesToHexStr(ispi),
                    DataUtils.bytesToHexStr(rspi),
                    DataUtils.bytesToHexStr(skEi),
                    DataUtils.bytesToHexStr(skEr),
                    DataUtils.bytesToHexStr(skAi),
                    DataUtils.bytesToHexStr(skAr));
        }catch (InvalidKeyException e){
            LogUtils.logException(e, this.getClass().getName(), "Failed to generate key materials! ");
        }catch (Exception e){
            LogUtils.logException(e, this.getClass().getName(), "Failed to put keys! ");
        }
    }

    private byte[] generateSKeySeed(String prfAlgorithm, byte[] key, byte[] content) {
        try {
            SecretKeySpec prfKeySpec = new SecretKeySpec(key, prfAlgorithm);
            Mac prfMac = Mac.getInstance(prfAlgorithm);
            prfMac.init(prfKeySpec);
            ByteBuffer sharedKeyBuffer = ByteBuffer.wrap(content);
            prfMac.update(sharedKeyBuffer);
            return prfMac.doFinal();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            LogUtils.logException(e, this.getClass().getName(), "Failed to generate SKEYSEED! ");
            //throw new IllegalArgumentException("Failed to generate SKEYSEED! ", e);
        }
        return null;
    }

    private byte[] getSharedKey(DHPrivateKeySpec privateKeySpec, byte[] peerPubKey) {
        try {
            BigInteger publicKeyValue = BigIntegerUtils.unsignedByteArrayToBigInteger(peerPubKey);
            BigInteger primeValue = privateKeySpec.getP();

            BigInteger baseGenValue = privateKeySpec.getG();

            DHPublicKeySpec publicKeySpec = new DHPublicKeySpec(publicKeyValue, primeValue, baseGenValue);

            KeyFactory dhKeyFac = KeyFactory.getInstance(KEY_DH);
            DHPublicKey publicKey = (DHPublicKey) dhKeyFac.generatePublic(publicKeySpec);
            DHPrivateKey privateKey = (DHPrivateKey) dhKeyFac.generatePrivate(privateKeySpec);

            // Calculate shared secret
            KeyAgreement dhKeyAgreement = KeyAgreement.getInstance(KEY_DH);
            dhKeyAgreement.init(privateKey);
            dhKeyAgreement.doPhase(publicKey, true);

            return dhKeyAgreement.generateSecret();

        } catch (Exception e){
            LogUtils.logException(e, this.getClass().getName(), "Failed to generate shared key! ");
        }
        return null;
    }

    private byte[] generateKeyMat(
            String prfAlgorithm, byte[] prfKey, byte[] dataToSign, int keyMaterialLen)
            throws InvalidKeyException {
        try {
            SecretKeySpec prfKeySpec = new SecretKeySpec(prfKey, prfAlgorithm);
            Mac prfMac = Mac.getInstance(prfAlgorithm);

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
            LogUtils.logException(e, this.getClass().getName(), "Failed to generate keying material");
            //throw new IllegalArgumentException("Failed to generate keying material", e);
        }
        return null;
    }

    public byte[] getSkD(){
        return skD;
    }

    public byte[] getSkAi(){
        return skAi;
    }

    public byte[] getSkAr(){
        return skAr;
    }

    public byte[] getSkEi(){
        return skEi;
    }

    public byte[] getSkEr(){
        return skEr;
    }

    public byte[] getSkPi(){
        return skPi;
    }

    public byte[] getSkPr(){
        return skPr;
    }

    public String getPsk(){
        return psk;
    }

    public byte[] encrypt(byte[] contentBytes, byte[] keyBytes)
            throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(DataUtils.hexStrToBytes(IV_HEX_STR));
        // Do not use AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        byte[] byEnd = cipher.doFinal(contentBytes);
        return byEnd;
    }

    public byte[] encrypt(byte[] contentBytes, byte[] keyBytes, byte[] iv)
            throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Do not use AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        byte[] byEnd = cipher.doFinal(contentBytes);
        return byEnd;
    }


    public byte[] decrypt(byte[] encryptedBytes, byte[] keyBytes)
            throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(DataUtils.hexStrToBytes(IV_HEX_STR));
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        byte[] byEnd = cipher.doFinal(encryptedBytes);
        return byEnd;
    }

    public byte[] decrypt(byte[] encryptedBytes, byte[] keyBytes, byte[] iv)
            throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        byte[] byEnd = cipher.doFinal(encryptedBytes);
        return byEnd;
    }

    public static byte[] getMacDigest(byte[] key, byte[] content, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey sKey = new SecretKeySpec(key, algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(sKey);
        mac.update(content);
        return mac.doFinal();
    }

    public boolean isKeysPrepared(){
        if(skAi!=null && skAr!=null && skEi!=null && skEr!=null && skPi!=null && skPr!=null && skD!=null){
            return true;
        }
        else{
            return false;
        }
    }

    public int getIVLen(){
        return aes_block_size;
    }

    public int getChecksumLen(){
        return integ_key_len / 2;
    }



}
