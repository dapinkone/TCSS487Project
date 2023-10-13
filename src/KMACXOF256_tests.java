import java.util.Arrays;

public class KMACXOF256_tests {
    public static String getBits(byte b) {
        StringBuilder sb = new StringBuilder();
        for(int i=7; i >= 0; i--)
            sb.append(((b & (1 << i)) != 0) ?"1" : "0");
        return sb.toString();
    }
    public static String getBits(int b) {
        StringBuilder sb = new StringBuilder();
        for(int i=15; i >= 0; i--)
            sb.append(((b & (1 << i)) != 0) ?"1" : "0");
        return sb.toString();
    }
    public static String getBits(long b) {
        StringBuilder sb = new StringBuilder();
        for(int i=63; i >= 0; i--)
            sb.append(((b & (1L << i)) != 0) ?"1" : "0");
        return sb.toString();
    }
    public static boolean tstenc8() {
        byte b = 0b0000_1001;
        byte expected = (byte) 0b1001_0000;
        if (KMACXOF256.enc8(b) != expected) return false;
        if (KMACXOF256.enc8((byte) 0b0000_0001) != (byte) 0b1000_0000) return false;
        if (KMACXOF256.enc8((byte) 0b1110_0000) != (byte) 0b0000_00111) {
            System.out.println(0b1110_0000);
            System.out.println(getBits((byte) 0b1110_0000));
            return false;
        }

        return true;
    }

    public static boolean test_left_encode() { // FIXME: left encode broken?
        var exp = new byte[]{
                (byte) 0b1000_0000, 0 // example given by the spec
        };
        var res = KMACXOF256.left_encode(0);
        for(int i=0; i < res.length; i++) {
            if(res[i] != exp[i]) return false;
        }

        exp = new byte[]{ // non-zero, single byte example
                (byte) 0b1000_0000, (byte) 0b1001_0000
        };
        res = KMACXOF256.left_encode(9);
        for(int i=0; i < res.length; i++) {
            if(res[i] != exp[i]) {
                return false;
            }
        }

        exp = new byte[]{ // multi-byte example
                (byte) 0b0100_0000, (byte) 0b1001_0000, (byte) 0b1111_1010
        };
        res = KMACXOF256.left_encode(0x095F);
        for(int i=0; i < res.length; i++) {
            if(res[i] != exp[i]) {
                System.out.println(Arrays.toString(res));
                System.out.println(Arrays.toString(exp));
                return false;
            }
        }

        return true;
    }
}
