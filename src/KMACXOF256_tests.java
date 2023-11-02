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
    public static boolean cSHAKE256_test_Sample3() {
        // cSHAKE sample #3
        // Strength 256-bits
        // length of data is 32 bits.
        // data is 00 01 02 03
        // requested output len is 512 bits
        // N is ""
        // S is "Email Signature"
        var ctx = new Sha3.sha3_ctx_t();
        Sha3.shake256_init(ctx);
        var N = new byte[]{};
        var S = "Email Signature".getBytes();
        var X = new byte[]{0, 1, 2, 3};
        var L = 512; // # of requested bits output.

        var out = KMACXOF256.cSHAKE256(X, L, N, S);
        var exp_text = """
        D0 08 82 8E 2B 80 AC 9D 22 18 FF EE 1D 07 0C 48
        B8 E4 C8 7B FF 32 C9 69 9D 5B 68 96 EE E0 ED D1
        64 02 0E 2B E0 56 08 58 D9 C0 0C 03 7E 34 A9 69
        37 C5 61 A7 4C 41 2B B4 C7 46 46 95 27 28 1C 8C""";
        Sha3.phex(out);
        return true;
    }
}
