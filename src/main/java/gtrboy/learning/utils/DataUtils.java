package gtrboy.learning.utils;

public final class DataUtils {
    private DataUtils(){

    }

    public static byte[] intToBytes(int value)
    {
        byte[] src = new byte[4];
        src[0] = (byte) ((value>>24) & 0xFF);
        src[1] = (byte) ((value>>16)& 0xFF);
        src[2] = (byte) ((value>>8)&0xFF);
        src[3] = (byte) (value & 0xFF);
        return src;
    }

    public static byte[] hexStrToBytes(String hexString) {
        byte[] result = new byte[hexString.length() / 2];
        for (int len = hexString.length(), index = 0; index <= len - 1; index += 2) {
            String subString = hexString.substring(index, index + 2);
            int intValue = Integer.parseInt(subString, 16);
            result[index / 2] = (byte)intValue;
        }
        return result;
    }

    public static String byteToArray(byte[]data){
        String result="";
        for (int i = 0; i < data.length; i++) {
            result += Integer.toHexString((data[i] & 0xFF) | 0x100).toUpperCase().substring(1, 3);
        }
        return result;
    }
}
