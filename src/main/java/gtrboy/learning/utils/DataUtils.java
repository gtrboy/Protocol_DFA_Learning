package gtrboy.learning.utils;

import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Random;

public final class DataUtils {
    private DataUtils(){

    }

    public static byte[] intToBytesB(int value)
    {
        byte[] src = new byte[4];
        src[0] = (byte) ((value>>24) & 0xFF);
        src[1] = (byte) ((value>>16)& 0xFF);
        src[2] = (byte) ((value>>8)&0xFF);
        src[3] = (byte) (value & 0xFF);
        return src;
    }

    public static byte[] shortToBytesB(int value)
    {
        byte[] src = new byte[2];
        src[0] = (byte) ((value>>8)&0xFF);
        src[1] = (byte) (value & 0xFF);
        return src;
    }

    public static int bytesToIntB(byte[] src, int offset) {
        int value;
        value = (int) ((src[offset + 0] & 0xFF << 24) | ((src[offset + 1] & 0xFF) << 16)
                | ((src[offset + 2] & 0xFF) << 8) | ((src[offset + 3] & 0xFF) << 0));
        return value;
    }

    public static int bytesToIntL(byte[] src, int offset) {
        int value;
        value = (int) ((src[offset + 3] & 0xFF << 24) | ((src[offset + 2] & 0xFF) << 16)
                | ((src[offset + 1] & 0xFF) << 8) | ((src[offset + 0] & 0xFF) << 0));
        return value;
    }

    public static short bytesToShortB(byte[] src, int offset) {
        short value;
        value = (short) (((src[offset + 0] & 0xFF) << 8) | (src[offset + 1] & 0xFF));
        return value;
    }

    public static short bytesToShortL(byte[] src, int offset) {
        short value;
        value = (short) (((src[offset + 1] & 0xFF) << 8) | (src[offset + 0] & 0xFF));
        return value;
    }



    public static byte[] hexStrToBytes(String hexString) throws NumberFormatException {
        byte[] result = new byte[hexString.length() / 2];
        for (int len = hexString.length(), index = 0; index <= len - 1; index += 2) {
            String subString = hexString.substring(index, index + 2);
            int intValue = Integer.parseInt(subString, 16);
            result[index / 2] = (byte) intValue;
        }
        return result;
    }

    public static String bytesToHexStr(byte[] bytes){
        if (bytes==null){
            return null;
        }
        StringBuffer sb = new StringBuffer(bytes.length);
        String temp = null;
        for (int i = 0;i< bytes.length;i++){
            temp = Integer.toHexString(0xFF & bytes[i]);
            if (temp.length() <2){
                sb.append(0);
            }
            sb.append(temp);
        }
        return sb.toString();
    }

    public static String byteToArray(byte[]data){
        String result="";
        for (int i = 0; i < data.length; i++) {
            result += Integer.toHexString((data[i] & 0xFF) | 0x100).toUpperCase().substring(1, 3);
        }
        return result;
    }

    public static byte[] ipToBytes(String ipAddress) {

        String[] ipAddressInArray = ipAddress.split("\\.");
        byte[] ipBytes = new byte[4];
        for (int i = 0; i < ipAddressInArray.length; i++) {
            byte tmp = Byte.valueOf(ipAddressInArray[i]);
            ipBytes[i] = tmp;
        }

        return ipBytes;
    }

    public static byte[] genRandomBytes(int length){
        long t = System.currentTimeMillis();
        Random r = new Random(t);
        byte[] bt = new byte[length];
        r.nextBytes(bt);
        return bt;
    }

    public static byte[] genEmptyBytes(int length){
        byte[] bt = new byte[length];
        Arrays.fill(bt, (byte) 0x00);
        return bt;
    }


    public static long fromDateStringToLong(String inVal) {
        Date date = null;
        SimpleDateFormat inputFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss:SSS");
        try {
            date = inputFormat.parse(inVal);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return date.getTime();
    }

}

