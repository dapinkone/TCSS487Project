// see documentation/spec here:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
// C reference implementation here: https://github.com/mjosaarinen/tiny_sha3/
// Referenced 2023-10-03.

import java.nio.ByteOrder;

// translation notes:
// uint8_t  => byte
// uint64_t => long
public class Sha3 {
    // TODO: these are all static methods. sha_ctx could be tied to the sha3 object, and save on arguments & complexity.

//#ifndef SHA3_H
//#define SHA3_H
//
//#include <stddef.h>
//#include <stdint.h>

    //#ifndef KECCAKF_ROUNDS
//#define KECCAKF_ROUNDS 24
    public static int KECCAKF_ROUNDS = 24;
    public static final long BYTE_MASK = 0xFF;
//            #endif

    //#ifndef ROTL64
//#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
// In java, use Long.rotateLeft() instead.
    static long ROTL64(long x, long y) {
        var u = (((x) << (y)) | ((x) >>> (64 - (y))));
        if(64 - y < 0) {
            throw new RuntimeException("y out of valid range for uint");
        }
        return u;
    }
//            #endif

    // state context
//    typedef struct {
//        union {                                 // state:
//            uint8_t b[200];                     // 8-bit bytes
//            uint64_t q[25];                     // 64-bit words
//        } st;
//        int pt, rsiz, mdlen;                    // these don't overflow
//    } sha3_ctx_t;
//
    /**
     * This static class is implemented to behave as a union sharing the same st memory space.
     */
    static class sha3_ctx_t {
        public byte[] b;
        //public long[] q;
        public int pt, rsiz, mdlen;

        sha3_ctx_t() { // TODO: proper instantiation/arguments? getters/setters?
            // b(uint8_t) and q(uint64_t) are originally a union named st.
            this.b = new byte[200]; // uint8_t
            //this.q = new long[25]; // uint64_t, removed in favor of byWord() / setWord()
            // to simulate underlying mechanics of union sharing the st memory space.
        }

        /**
         * 
         * @return an array of longs/words form of ctx.b
         */
        public long[] byWord() { // ctx.st.q is supposed to be uint64_t
            // returns ctx.b as an array of longs/words
            long[] words = new long[b.length/8];
            for(int word=0; word < words.length; word++) {
                for(int i=0; i < 8; i++) { // storing 8 bytes into the long
                    words[word] |= (b[word * 8 + i] & 0xFFL) << (7-i)*8;
                }
            }
            return words;
        }
        public void setWord(long[] words) {
            // feeds the data given as words, into the bytewise store.
            for(int w = 0; w < words.length; w++) {
                long word = words[w];
                // extract each byte from the given word
                for(int i=0; i < 8; i++) { // extract 8 bytes from the long
                    b[w*8 + i] = (byte) (((word >>> (7-i)*8)) & 0xFF);
                }
            }
        }
        public void setBytes(byte[] bytes) {
            if(this.b.length < bytes.length) {
                this.b = new byte[bytes.length];
            }
            System.arraycopy(bytes, 0, this.b, 0, bytes.length);
        }
    }
    // Compression function.
    //void sha3_keccakf(uint64_t st[25]);

    // OpenSSL - like interfece
    //int sha3_init(sha3_ctx_t c, int mdlen);    // mdlen = len of output in bytes
    //int sha3_update(sha3_ctx_t c, const void *data, size_t len);
    //int sha3_final(void *md, sha3_ctx_t *c);    // digest goes to md

// compute a sha3 hash (md) of given byte length from "in"
    //void sha3(int in, int inlen, sha3_ctx_t md, int mdlen);

    // SHAKE128 and SHAKE256 extensible-output functions
//#define shake128_init(c) sha3_init(c, 16)
    static sha3_ctx_t shake128_init(sha3_ctx_t c) {
        sha3_init(c, 16);
        return c;
    }

    //#define shake256_init(c) sha3_init(c, 32)
    static sha3_ctx_t shake256_init(sha3_ctx_t c) {
        sha3_init(c, 32);
        return c;
    }

//    define shake_update sha3_update
//    void shake_xof(sha3_ctx_t *c);
//
//    void shake_out(sha3_ctx_t *c, void *out, size_t len);
//
//#endif

    static void sha3_keccakf(/*uint64_t st[25]*/ /*long[] st*/ sha3_ctx_t c) {
        // original takes an array of uint64_t, but ctx.q was utilized only
        // in calls to this function, so we've refactored to pass in a context as
        // is common throughout the codebase.

        // NOTE: copying may not be performant. Possible refactor/optimization?
        long[] st = c.byWord();

        // convert from little-endian to big endian if necessary
        for(int i=0; i < 25; i++)
            st[i] = Long.reverseBytes(st[i]);
        // constants
    long keccakf_rndc[] = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
                    0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
                    0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
                    0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
                    0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
                    0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
                    0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
                    0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
        } ;
     var keccakf_rotc = new int[]{
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
        } ;
    var keccakf_piln = new int[]{
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
        } ;

        // variables
        int j, r;
        long t;
        var bc = new long[5];
        //System.out.println(ByteOrder.nativeOrder()); //little_endian is most common.

        // actual iteration
        for (r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }

            for (int i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ Long.rotateLeft(bc[(i + 1) % 5], 1);
                for (j = 0; j < 25; j += 5) {
                    st[j + i] ^= t;
                }
            }

            // Rho Pi
            t = st[1];
            for (int i = 0; i < 24; i++) {
                j = keccakf_piln[i];
                bc[0] = st[j];
                st[j] = Long.rotateLeft(t, keccakf_rotc[i]);
                t = bc[0];
            }

            //  Chi
            for (j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) {
                    bc[i] = st[j + i];
                }
                for (int i = 0; i < 5; i++) {
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }
            
            // Roate left 64 bit

            //  Iota
            st[0] ^= keccakf_rndc[r];
        }

        for(int i=0; i < 25; i++) {
            st[i] = Long.reverseBytes(st[i]);
        }
        c.setWord(st);
    }

// Initialize the context for SHA3

    static int sha3_init(sha3_ctx_t c, int mdlen) {
//        int i; // arrays  are zero-initialized by default in java.
//
//        for (i = 0; i < 25; i++) {
//            c.q[i] = 0;
//        }
        c.setWord(new long[25]);
        c.mdlen = mdlen;
        c.rsiz = 200 - 2 * mdlen;
        c.pt = 0;

        return 1; // TODO: redesign/refactor. would be better to return the sha3_ctx_t?
    }

// update state with more data

    static int sha3_update(sha3_ctx_t c, byte[] data, long len) { // void pointers?
        int j = c.pt;
        for (int i = 0; i < len; i++) {
            // "data" is void* passed into sha3_update from sha3() void* `in`, which is msg, a uint8_t[256] from main.c.
            c.b[j++] ^= data[i];
            if (j >= c.rsiz) {
                sha3_keccakf(c);
                j = 0;
            }
        }
        c.pt = j;
        return 1; // what purpose does return 1 serve? we never return -1/0 for failures.
    }
    static int shake_update(sha3_ctx_t c, byte[] data, long len) {
        return sha3_update(c, data, len);
    }

// finalize and output a hash

    static int sha3_final(byte[] md, sha3_ctx_t c) {
        int i;

        c.b[c.pt] ^= 0x06;
        c.b[c.rsiz - 1] ^= 0x80;
        sha3_keccakf(c);

        for (i = 0; i < c.mdlen; i++) {
            md[i] = c.b[i];
        }

        return 1;
    }

// compute a SHA-3 hash (md) of given byte length(mdlen) from "in"

    public static void sha3(byte[] in, long inlen, byte[] md, int mdlen) {
        sha3_ctx_t sha3ctx = new sha3_ctx_t();
        System.out.printf("%d %d ", inlen, mdlen);

        sha3_init( sha3ctx, mdlen);
        System.out.printf("init:");
        for(int i=0; i < inlen; i++) System.out.printf("%02X", in[i]);
        System.out.println("\n");

        sha3_update( sha3ctx, in, inlen);
        System.out.printf("update:");
        for(int i=0; i < sha3ctx.b.length; i++) System.out.printf("%02X", sha3ctx.b[i]);
        System.out.println("\n");

        sha3_final(md, sha3ctx);
        System.out.printf("final:");
        for(int i=0; i < sha3ctx.b.length; i++) System.out.printf("%02X", sha3ctx.b[i]);
        System.out.println("\n");
        //return md;
    }

// SHAKE128 and SHAKE256 extensible-output functionality

    static void shake_xof(sha3_ctx_t c) {
        c.b[c.pt] ^= 0x1F;
        c.b[c.rsiz - 1] ^= 0x80;
        sha3_keccakf(c);
        c.pt = 0;
    }

    static void shake_out(sha3_ctx_t c, byte[] out, long len) {        

        int j = c.pt;
        for (int i = 0; i < len; i++) {
            if (j >= c.rsiz) {
                sha3_keccakf(c);
                j = 0;
            }
            out[i] =c.b[j++];
        }
        c.pt = j;
    }
}
