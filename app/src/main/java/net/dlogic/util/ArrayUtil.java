package net.dlogic.util;

public class ArrayUtil {

    public static Byte[] bytesToObjects(byte[] bPrim) {
        Byte[] bObj = new Byte[bPrim.length];
        for (int i = 0; i < bPrim.length; i++) {
            bObj[i] = Byte.valueOf(bPrim[i]);
        }
        return bObj;
    }

    public static byte[] bytesFromObjects(Byte[] bObj) {
        byte[] bPrim = new byte[bObj.length];
        for (int i = 0; i < bObj.length; i++)
        {
            bPrim[i] = bObj[i];
        }
        return bPrim;
    }

    public static String bytesToHex(byte[] byteArray) {
        StringBuilder sBuilder = new StringBuilder(byteArray.length * 2);
        for(byte b: byteArray)
            sBuilder.append(String.format("%02x", b & 0xff));
        return sBuilder.toString();
    }

    /*
    public static String bytesToHex(byte[] bytes) {

        char[] hexChars = new char[bytes.length * 2];
        int j = 0;
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[j++] = hexArray[v >>> 4];
            hexChars[j++] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String bytesToHex(byte[] bytes, char delimiter) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();

        char[] hexChars = new char[bytes.length * 3 - 1];
        int j = 0;
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[j++] = hexArray[v >>> 4];
            hexChars[j++] = hexArray[v & 0x0F];
            if (i < (bytes.length - 1)) {
                hexChars[j++] = delimiter;
            }
        }
        return new String(hexChars);
    }
    */
}
