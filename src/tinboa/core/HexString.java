
package tinboa.core;

/**
 * Convenience class to represent byte arrays as strings
 * and vice versa.
 *
 *
 *  @author Yann Le Gall
 *  ylegall@gmail.com
 *  Feb 18, 2010 7:41:24 PM
 */
public class HexString {

    private char[] symbols = {
        '0','1','2','3','4','5','6','7','8','9',
        'a','b','c','d','e','f'
    };

    /**
     * gets a hex representation of the ytes in
     * the given byte array.
     * @param bytes
     * @return a Hexadecimal String encoding.
     */
    public final String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(symbols[(b >>> 4) & 0x0F]);
            sb.append(symbols[(b & 0x0F)]);
        }
        return sb.toString();
    }

    /**
     * Gets a 'readable' Hex String from the
     * given byte array, where each byte encoding
     * is separated by a ':' (like SSH does)
     * @param bytes
     * @return
     */
    public final String toHexFingerprint(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes) {
            sb.append(symbols[(b >>> 4) & 0x0F]);
            sb.append(symbols[(b & 0x0F)]);
            sb.append(':');
        }
        return sb.toString().substring(0, sb.length() - 1 );
    }

    /**
     * Gets the byte array that corresponds to the given
     * HexString. The length of the string should be
     * at least 2.
     * @param hexString the string to convert to bytes
     * @return byte[]
     */
    public final byte[] toByteArray(String hexString) {

        byte[] bytes = new byte[hexString.length() >> 1];
        int b;
        int i = 0;
        while(i < bytes.length) {
            b = getByte(hexString.charAt(i<<1));
            b = (b << 4);
            try {
                b = b | getByte(hexString.charAt((i << 1) + 1));
            } catch (IndexOutOfBoundsException e) {
                return bytes;
            }
            bytes[i] = (byte)b;
            i++;
        }
        return bytes;
    }

    private final byte getByte(char c) {
        if(Character.isDigit(c)) {
            return (byte)(c - 0x30);
        } else {
            return (byte)(c - 0x57);
        }
    }

//    public static void main(String[] args) {
//        HexString h = new HexString();
//        String s = "hello world";
//        byte[] b = s.getBytes();
//        s = h.toHexString(b);
//        System.out.println(s);
//        b = h.toByteArray(s);
//        System.out.println(new String(b));
//    }

}