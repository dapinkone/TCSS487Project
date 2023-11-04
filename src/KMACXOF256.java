import java.util.Arrays;

import static java.lang.Math.min;

public class KMACXOF256 {
    // basic operations & functions from FIPS 202
    public static byte[] xor(byte[] X, byte[] Y) {
        // X xor Y for strings of arbitrary but equal bit length.
        for(int i=0; i < min(X.length, Y.length); i++) X[i] ^= Y[i];
        return X;
    }

    // log_2(x)
    // min(x, y)
    // required methods / specialized functions
    public static byte[] left_encode(long x) {
        // FIXME: left_encode should take all x such that 0 <= x < 2**2040
        // find n, the number of bytes required to encode x:
        int n = 0;
        if(x == 0) return new byte[]{1, 0}; // edge case.

        long y = x; // copy x, and count the # of bytes.
        while(y != 0) {
            n++;
            y >>>= 8;
        }
       // extract n bytes of x:
        var b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[n - i - 1] = (byte) (x & 0xFF);
            x >>>= 8; // shift right by one byte.
        }
        return appendBytes(new byte[]{(byte) n}, b);
    }

    /**
     * appends any number of byte arrays into a whole,
     * seen as .... || .... || ... || .... in the spec.
     * @param Xs given arguments of any number of byte arrays
     * @return all arguments appended together.
     */
    public static byte[] appendBytes(byte[]... Xs) {
        // count up the lengths to determine how long the new array is.
        int newlen = 0;
        for (var x : Xs) newlen += x.length;

        byte[] newXs = new byte[newlen];
        int ptr = 0; // keep track of where we are in newXs while copying.
        for (byte[] x : Xs) {
            // copy each array from Xs into newXs.
            System.arraycopy(x, 0, newXs, ptr, x.length);
            ptr += x.length;
        }
        return newXs;
    }

    static public byte[] encode_string(byte[] S) {
//        The encode_string function is used to encode bit strings in a way that may be parsed
//        unambiguously from the beginning of the string, S. The function is defined as follows:
        // Return left_encode(len(S)) || S.
        return appendBytes(left_encode(S.length * 8L), S);
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     *
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    public static byte[] bytepad(byte[] X, int w) {
        // copied from slides UWT TCSS 487
// Validity Conditions: w > 0
        assert w > 0;
// 1. z = left_encode(w) || X.
        byte[] wenc = left_encode(w);
        byte[] z = new byte[w * ((wenc.length + X.length + w - 1) / w)];
// NB: z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
// 2. (nothing to do: len(z) mod 8 = 0 in this byte-oriented implementation)
// 3. while (len(z)/8) mod w ≠ 0: z = z || 00000000
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }
// 4. return z
        return z;
    }
    public byte[] cSHAKE(int mode, byte[] /*bitstring*/ X, int L, byte[] N, byte[] S) {
        /*
         - X is the main input bit string. It may be of any length3, including zero.
         - L is an integer representing the requested output length4 in bits.
         - N is a function-name bit string, used by NIST to define functions based on cSHAKE.
         When no function other than cSHAKE is desired, N is set to the empty string.
         - S is a customization bit string. The user selects this string to define a variant of the
         function. When no customization is desired, S is set to the empty string5.

         An implementation of cSHAKE may reasonably support only input strings and output lengths
         that are whole bytes; if so, a fractional-byte input string or a request for an output length that is
         not a multiple of 8 would result in an error.
         */
        if (L % 8 != 0)
            throw new IllegalArgumentException("Only whole bytes are supported.");
        if (L == 0) return new byte[0];

        if (N.length == 0 && S.length == 0) {
            if (mode == 128) {
                var ctx = new Sha3.sha3_ctx_t();
                Sha3.shake128_init(ctx);
                return ctx.b; // FIXME: what/where is shake128()?
            }
            // default 256
            var ctx = new Sha3.sha3_ctx_t();
            Sha3.shake256_init(ctx);
            return ctx.b; // FIXME: what/where is shake256()?
            // return SHAKE(X, L)
        }
        if (mode == 128) {
            // return keccak256(bytepad(encode_string(N) || encode_string(S), 168) || X || 00, L)
        }
        // return // keccak512(bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)

        var ctx = new Sha3.sha3_ctx_t();
        Sha3.sha3_keccakf(ctx);
        return ctx.b;// FIXME: not properly implemented. see above coments.
    }
    public static void absorb(Sha3.sha3_ctx_t ctx, byte[] X) {
        while(X.length > 136) {
            var d = Arrays.copyOfRange(X, 0, 136);
            xor(ctx.b, d);
            Sha3.sha3_keccakf(ctx);
            X = Arrays.copyOfRange(X, 136, X.length);
        }
        var lastBlock = new byte[200];
        xor(lastBlock, X); // copy remaining data.
        // 0x04 for termination of data
        lastBlock[X.length] ^= 0x04;
        lastBlock[135] ^= 0x80; // 0x80 for reasons, denotes this is last block
        xor(ctx.b, lastBlock);
        Sha3.sha3_keccakf(ctx);
    }
    /**
     * • X is the main input bit string. It may be of any length3, including zero.
     * • L is an integer representing the requested output length4 in bits.
     * • N is a function-name bit string, used by NIST to define functions based on cSHAKE.
     * When no function other than cSHAKE is desired, N is set to the empty string.
     * • S is a customization bit string. The user selects this string to define a variant of the
     * function. When no customization is desired, S is set to the empty string5
     * @return byte[]
     */
    public static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
//        Validity Conditions: len(N)< 2**2040 and len(S)< 2**2040
//        1. If N = "" and S = "": // N is always "KMAC" for this assignment
//        return SHAKE256(X, L);
//        2. Else:
//        return KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L).
        var ctx = new Sha3.sha3_ctx_t();
        Sha3.sha3_init(ctx, L);
        // rate(r) for cSHAKE256 is 136
        var bytepad_data = bytepad(appendBytes(encode_string(N), encode_string(S)), 136);
        absorb(ctx, appendBytes(bytepad_data, X)); // we handle the 00 aka 0x04 in absorb().
        return squeeze(ctx, L/8);
    }
    static byte[] squeeze(Sha3.sha3_ctx_t ctx, int output_length) {
        // very similar to Sha3.shake_out ?
        var rate = 136;
        var c = 1600/8 - rate; // n bits = r + c; c = n - r
        // state size n = r + c, or 200 bytes

        // squeeze?
        byte[] out = new byte[output_length];
        var ptr = 0;
        while(ptr < output_length) {
            if((output_length - ptr) >= rate) {
                System.arraycopy(ctx.b, 0, out, ptr, rate);
                ptr += rate;
            } else {
                // edge case of the end of output, when we don't take the whole rate.
                System.arraycopy(ctx.b, 0, out, ptr, output_length % rate);
                ptr += output_length % rate;
            }
            Sha3.sha3_keccakf(ctx);
        }
        return out;
    }
    private static byte[] right_encode(int i) {
        // we only ever call right_encode(0).
        return new byte[]{(byte) 0, (byte) 1};
    }

    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        // NIST.SP.800-185 page 11
//    Validity Conditions: len(K) <2**2040 and 0 ≤ L and len(S) < 2**2040
//            1. newX = bytepad(encode_string(K), 136) || X || right_encode(0).
//            2. return cSHAKE256(newX, L, “KMAC”, S).
        var newX = appendBytes(bytepad(encode_string(K), 136), X, right_encode(0));
        return cSHAKE256(newX, L, "KMAC".getBytes(), S);
    }
}
