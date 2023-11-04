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
        var exp_text = "D0 08 82 8E 2B 80 AC 9D 22 18 FF EE 1D 07 0C 48 " +
        "B8 E4 C8 7B FF 32 C9 69 9D 5B 68 96 EE E0 ED D1 " +
        "64 02 0E 2B E0 56 08 58 D9 C0 0C 03 7E 34 A9 69 " +
        "37 C5 61 A7 4C 41 2B B4 C7 46 46 95 27 28 1C 8C ";
        // translate the output into a string. compare with expected text.
        //Sha3.phex(out);
        return Sha3.bytesToHex(out).equals(exp_text);
    }

    public static boolean cSHAKE256_test_Sample4() {
        // cSHAKE sample #4
        // Strength 256-bits
        // length of data is 1600 bits.
        // data is ....
        // requested output len is 512 bits
        // N is ""
        // S is "Email Signature"
        var ctx = new Sha3.sha3_ctx_t();
        Sha3.shake256_init(ctx);
        var N = new byte[]{};
        var S = "Email Signature".getBytes();
        var X = new byte[200];
        Sha3_tests.test_readhex(X,
                "000102030405060708090A0B0C0D0E0F" +
        "101112131415161718191A1B1C1D1E1F" +
        "202122232425262728292A2B2C2D2E2F" +
        "303132333435363738393A3B3C3D3E3F" +
        "404142434445464748494A4B4C4D4E4F" +
        "505152535455565758595A5B5C5D5E5F" +
        "606162636465666768696A6B6C6D6E6F" +
        "707172737475767778797A7B7C7D7E7F" +
        "808182838485868788898A8B8C8D8E8F" +
        "909192939495969798999A9B9C9D9E9F" +
        "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
        "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
        "C0C1C2C3C4C5C6C7", 200);
        var L = 512; // # of requested bits output.

        var out = KMACXOF256.cSHAKE256(X, L, N, S);
        var exp_text = "07 DC 27 B1 1E 51 FB AC 75 BC 7B 3C 1D 98 3E 8B " +
                "4B 85 FB 1D EF AF 21 89 12 AC 86 43 02 73 09 17 " +
                "27 F4 2B 17 ED 1D F6 3E 8E C1 18 F0 4B 23 63 3C " +
                "1D FB 15 74 C8 FB 55 CB 45 DA 8E 25 AF B0 92 BB ";
        // translate the output into a string. compare with expected text.
        //Sha3.phex(out);
        var res = Sha3.bytesToHex(out).equals(exp_text);
        if(res) return true;
        Sha3.phex(out);
        System.out.println(exp_text);
        return false;
    }
}
