package gtrboy.learning.IKEv2;

import gtrboy.learning.utils.BigIntegerUtils;
import gtrboy.learning.utils.DataUtils;
import org.apache.commons.net.util.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;

import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;


/*   Algo    key_len     IV_len( = block_size)
*    DES       64                 64
*  AES-128     128                128
*  AES-192     192                128
*  AES-256     256                128
 */

public class IKEv2KeysGener {
    private DHPrivateKeySpec localPrivateKeySpec;
    private byte[] pub_key;
    private byte[] sharedSecret = null;
    private byte[] sKeySeed = null;
    private final int _hmacKeyLen;
    private final int _checksumLen;
    private final int _encKeyLen;
    private final int _encBlockSize;
    private final byte[] _iv;
    public String _hmacAlg;
    public String[] _encAlg = new String[2];
    private final String _psk;
    private final int _dhGroup;
    
    //private final int _hmacKeyLen;
    private byte[] skD = null;
    private byte[] skAi = null;
    private byte[] skAr = null;
    private byte[] skEi = null;
    private byte[] skEr = null;
    private byte[] skPi = null;
    private byte[] skPr = null;

    private static final String KEY_DH = "DH";
    private static final int DH_GROUP_1024_BIT_MODP_DATA_LEN = 128;
    private static final int DH_GROUP_2048_BIT_MODP_DATA_LEN = 256;
    private static final String KEY_PAD = "Key Pad for IKEv2";
    //private static final String IV_HEX_STR = "a0a0a0a0b0b0b0b0c0c0c0c0d0d0d0d0";
    

    private static final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);


    public IKEv2KeysGener(int dh_group, String encryption, String integrity, String preSecKey){
        switch (encryption){
            case "DES":
                _encAlg[0] = "DES";
                _encAlg[1] = "DES/CBC/NoPadding";
                _encKeyLen = 8;
                _encBlockSize = 8;
                break;
            case "3DES":
                _encAlg[0] = "DESede";
                _encAlg[1] = "DESede/CBC/NoPadding";
                _encKeyLen = 24;
                _encBlockSize = 8;
                break;
            case "AES-CBC-128":
                _encAlg[0] = "AES";
                _encAlg[1] = "AES/CBC/NoPadding";
                _encKeyLen = 16;
                _encBlockSize = 16;
                break;
            case "AES-CBC-256":
                _encAlg[0] = "AES";
                _encAlg[1] = "AES/CBC/NoPadding";
                _encKeyLen = 32;
                _encBlockSize = 16;
                break;
            default:
                _encKeyLen = 0;
                _encBlockSize = 0;
                LOGGER.error("Encryption algorithm is invalid! ");
                System.exit(-1);
        }

        switch (integrity){
            case "MD5":
                _hmacAlg = "HmacMD5";
                _hmacKeyLen = 16;
                _checksumLen = 12;
                break;
            case "SHA1":
                _hmacAlg = "HmacSHA1";
                _hmacKeyLen = 20;
                _checksumLen = 12;
                break;
            case "SHA256":
                _hmacAlg = "HmacSHA256";
                _hmacKeyLen = 32;
                _checksumLen = 16;
                break;
            case "SHA384":
                _hmacAlg = "HmacSHA384";
                _hmacKeyLen = 48;
                _checksumLen = 24;
                break;
            case "SHA512":
                _hmacAlg = "HmacSHA512";
                _hmacKeyLen = 64;
                _checksumLen = 32;
                break;
            default:
                _hmacKeyLen = 0;
                _checksumLen = 0;
                LOGGER.error("Integrity algorithm is invalid! ");
                System.exit(-1);
        }
        
        _dhGroup = dh_group;
        _psk = preSecKey;
        
        //iv = DataUtils.hexStrToBytes(IV_HEX_STR);
        _iv = DataUtils.genRandomBytes(_encBlockSize);
        InitDHKeys();
    }

    private void InitDHKeys() {
        BigInteger prime = BigInteger.ZERO;
        int keySize = 0;
        switch (_dhGroup) {
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
                LOGGER.error("DH group not supported! ");
                System.exit(-1);
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
            LOGGER.error("No such algorithm! ");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.error("Failed to initialize key generator! ");
            e.printStackTrace();
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
            sKeySeed = generateSKeySeed(_hmacAlg, keyBuffer.array(), sharedSecret);

            ByteBuffer dataToSign = ByteBuffer.allocate(i_nonce.length + r_nonce.length + ispi.length + rspi.length);
            dataToSign.put(i_nonce).put(r_nonce).put(ispi).put(rspi);
            int keysLen = _encKeyLen*2 + _hmacKeyLen*3 + _hmacKeyLen*2;
            byte[] keyMats = generateKeyMat(_hmacAlg, sKeySeed, dataToSign.array(), keysLen);
            skD = new byte[_hmacKeyLen];
            skAi = new byte[_hmacKeyLen];
            skAr = new byte[_hmacKeyLen];
            skEi = new byte[_encKeyLen];
            skEr = new byte[_encKeyLen];
            skPi = new byte[_hmacKeyLen];
            skPr = new byte[_hmacKeyLen];
            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMats);
            keyMatBuffer.get(skD).get(skAi).get(skAr).get(skEi).get(skEr).get(skPi).get(skPr);
            LOGGER.debug("skD: " + DataUtils.bytesToHexStr(skD));
            LOGGER.debug("skAi: " + DataUtils.bytesToHexStr(skAi));
            LOGGER.debug("skAr: " + DataUtils.bytesToHexStr(skAr));
            LOGGER.debug("skEi: " + DataUtils.bytesToHexStr(skEi));
            LOGGER.debug("skEr: " + DataUtils.bytesToHexStr(skEr));
            LOGGER.debug("skPi: " + DataUtils.bytesToHexStr(skPi));
            LOGGER.debug("skPr: " + DataUtils.bytesToHexStr(skPr));
            LOGGER.debug("{},{},{},{},\"AES-CBC-256 [RFC3602]\",{},{},\"HMAC_SHA2_512_256 [RFC4868]\"",
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

    // SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
    public void reGenKeys(byte[] skD_old, byte[] ispi, byte[] rspi, byte[] i_nonce, byte[] r_nonce, byte[] r_ke){
        try {
            sharedSecret = getSharedKey(localPrivateKeySpec, r_ke);
            ByteBuffer bBuf = ByteBuffer.allocate(sharedSecret.length + i_nonce.length + r_nonce.length);
            bBuf.put(sharedSecret).put(i_nonce).put(r_nonce);
            sKeySeed = generateSKeySeed(_hmacAlg, skD_old, bBuf.array());
            ByteBuffer dataToSign = ByteBuffer.allocate(i_nonce.length + r_nonce.length + ispi.length + rspi.length);
            dataToSign.put(i_nonce).put(r_nonce).put(ispi).put(rspi);
            int keysLen = _encKeyLen*2 + _hmacKeyLen*3 + _hmacKeyLen*2;
            byte[] keyMats = generateKeyMat(_hmacAlg, sKeySeed, dataToSign.array(), keysLen);
            skD = new byte[_hmacKeyLen];
            skAi = new byte[_hmacKeyLen];
            skAr = new byte[_hmacKeyLen];
            skEi = new byte[_encKeyLen];
            skEr = new byte[_encKeyLen];
            skPi = new byte[_hmacKeyLen];
            skPr = new byte[_hmacKeyLen];
            ByteBuffer keyMatBuffer = ByteBuffer.wrap(keyMats);
            keyMatBuffer.get(skD).get(skAi).get(skAr).get(skEi).get(skEr).get(skPi).get(skPr);
            LOGGER.debug("skD: " + DataUtils.bytesToHexStr(skD));
            LOGGER.debug("skAi: " + DataUtils.bytesToHexStr(skAi));
            LOGGER.debug("skAr: " + DataUtils.bytesToHexStr(skAr));
            LOGGER.debug("skEi: " + DataUtils.bytesToHexStr(skEi));
            LOGGER.debug("skEr: " + DataUtils.bytesToHexStr(skEr));
            LOGGER.debug("skPi: " + DataUtils.bytesToHexStr(skPi));
            LOGGER.debug("skPr: " + DataUtils.bytesToHexStr(skPr));
            LOGGER.debug("{},{},{},{},\"AES-CBC-256 [RFC3602]\",{},{},\"HMAC_SHA2_512_256 [RFC4868]\"",
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

    private byte[] generateSKeySeed(String _hmacAlgorithm, byte[] key, byte[] content) {
        try {
            SecretKeySpec prfKeySpec = new SecretKeySpec(key, _hmacAlgorithm);
            Mac prfMac = Mac.getInstance(_hmacAlgorithm);
            prfMac.init(prfKeySpec);
            ByteBuffer sharedKeyBuffer = ByteBuffer.wrap(content);
            prfMac.update(sharedKeyBuffer);
            return prfMac.doFinal();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            LOGGER.error("Failed to generate SKEYSEED! ");
            e.printStackTrace();
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
            LOGGER.error("Failed to generate shared key! ");
            e.printStackTrace();
        }
        return null;
    }

    private byte[] generateKeyMat(
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

    public String get_psk(){
        return _psk;
    }

    
    // Encryption and Decryption

    public byte[] encrypt(byte[] contentBytes, byte[] keyBytes, byte[] iv) throws Exception {
        SecretKeySpec keySpec;
        keySpec = new SecretKeySpec(keyBytes, _encAlg[0]);
        Cipher cipher = Cipher.getInstance(_encAlg[1]);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Do not use AES/CBC/PKCS5Padding
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        return cipher.doFinal(contentBytes);
    }

    public byte[] decrypt(byte[] encryptedBytes, byte[] keyBytes, byte[] iv) throws Exception {
        SecretKeySpec keySpec;
        keySpec = new SecretKeySpec(keyBytes, _encAlg[0]);
        Cipher cipher = Cipher.getInstance(_encAlg[1]);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Do not use AES/CBC/PKCS5Padding
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        return cipher.doFinal(encryptedBytes);
    }
    
    
    // Integrity
    public byte[] calChecksum(byte[] content){
        //byte[] skAi = keysGenerator.getSkAi();
        byte[] checksum = null;
        if(isKeysPrepared()) {
            try {
                byte[] hash = getMacDigest(skAi, content, _hmacAlg);
                //int checksumLen = hash.length / 2;
                int checksumLen = getChecksumLen();
                checksum = new byte[checksumLen];
                System.arraycopy(hash, 0, checksum, 0, checksumLen);
            }catch (NoSuchAlgorithmException | InvalidKeyException e){
                e.printStackTrace();
            }
        }else{
            LOGGER.error("Keys are not prepared! ");
        }
        return checksum;
    }

    public byte[] getMacDigest(byte[] key, byte[] content, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKey sKey = new SecretKeySpec(key, algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(sKey);
        mac.update(content);
        return mac.doFinal();
    }

    /** Calculate authentication with _psk.
     * InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI
     * MACedIDForI = prf(SK_pi, RestOfInitIDPayload)
     * RestOfInitIDPayload = IDType | RESERVED | InitIDData
     * AUTH = prf( prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
     * */
    public byte[] calcAuthPsk(byte[] iInitSaPkt, byte[] rNonce, byte[] initIDPayload){
        //byte[] skPi = keysGenerator.getSkPi();
        int macLen = skPi.length;
        byte[] macedIDForIBuf;
        byte[] authData = null;
        String prfFunc = _hmacAlg;
        ByteBuffer initSignedOctetsBuf = ByteBuffer.allocate(iInitSaPkt.length + rNonce.length + macLen);
        try{
            macedIDForIBuf = getMacDigest(skPi, initIDPayload, prfFunc);
            initSignedOctetsBuf.put(iInitSaPkt).put(rNonce).put(macedIDForIBuf);
            byte[] tmpKey = getMacDigest(_psk.getBytes(), KEY_PAD.getBytes(), prfFunc);
            authData = getMacDigest(tmpKey, initSignedOctetsBuf.array(), prfFunc);
        } catch (Exception e){
            e.printStackTrace();
        }
        return authData;
    }

    public byte[] calcAuthCert(byte[] iInitSaPkt, byte[] rNonce, byte[] initIDPayload, String privateKeyFile, String hashMethod){
        //byte[] skPi = keysGenerator.getSkPi();
        int macLen = skPi.length;
        byte[] macedIDForIBuf;
        byte[] authData = null;
        String prfFunc = _hmacAlg;
        ByteBuffer initSignedOctetsBuf = ByteBuffer.allocate(iInitSaPkt.length + rNonce.length + macLen);
        try{
            macedIDForIBuf = getMacDigest(skPi, initIDPayload, prfFunc);
            initSignedOctetsBuf.put(iInitSaPkt).put(rNonce).put(macedIDForIBuf);
            authData = getCertSign(initSignedOctetsBuf.array(), privateKeyFile, hashMethod);
        } catch (Exception e){
            e.printStackTrace();
        }
        return authData;
    }



    private String getKey(String certFile) throws IOException {
        // Read key from file
        String strKeyPEM = "";
        InputStream certStream = this.getClass().getClassLoader().getResourceAsStream("IKEv2/certificates/" + certFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(certStream));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }

    public RSAPrivateKey getPrivateKey(String filename) throws IOException, GeneralSecurityException {
        String privateKeyPEM = getKey(filename);
        return getPrivateKeyFromString(privateKeyPEM);
    }

    public RSAPrivateKey getPrivateKeyFromString(String key) throws IOException, GeneralSecurityException {
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.decodeBase64(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
        return privKey;
    }

    private byte[] getCertSign(byte[] dataToSign, String privateKeyFile, String hashMethod) throws Exception{
        RSAPrivateKey privateKey = getPrivateKey(privateKeyFile);
        Signature sign = Signature.getInstance(hashMethod);
        sign.initSign(privateKey);
        sign.update(dataToSign);
        return sign.sign();
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
        return _encBlockSize;
    }

    public int getChecksumLen(){
        return _checksumLen;
    }



}
