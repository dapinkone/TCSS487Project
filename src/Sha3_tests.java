public class Sha3_tests {
    public static boolean words_test() {
        var ctx = new Sha3.sha3_ctx_t();
        //// test setWords()
        Sha3.shake128_init(ctx);
        var words = new long[]{
                0xFFFF_FFFF_FFFF_FFFFL, 0xABCD_EFAB_CDEF_1234L
        };
        ctx.setWord(words);
        var expected = new byte[]{
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0xAB,
                (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34
        };
        for(int i=0; i < expected.length; i++) {
            if(expected[i] != ctx.b[i]) {
                System.out.println("failed setWord()");
                return false;
            }
        }
        // test byWord()

        var rcvd = ctx.byWord();
        for(int i=0; i < words.length; i++) {
            if(words[i] != rcvd[i]) {
                System.out.println("failed byWord()");
                return false;
            }
        }
        /////
        Sha3.shake128_init(ctx);
        var data = new byte[] { // two words/longs worth of bytes.
                0x0, 1, 2, 3, 4, 5, 6, 7,
                0x0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70
        };
        ctx.setBytes(data);

        ctx.setWord(ctx.byWord()); // inverse test
        for(int i=0; i < data.length; i++) {
            if(data[i] != ctx.b[i]) {
                System.out.println("Failed inverse word test");
                return false;
            }
        }
        return true;
    }
}
