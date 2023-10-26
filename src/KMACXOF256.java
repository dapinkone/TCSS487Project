import java.util.Arrays;

public class KMACXOF256 {
    // basic operations & functions from FIPS 202
    public static long trunc(int s, long X) {
        // trancates some bitstring X, returning the first s bits.
        return 0L;
    }
    public static byte[] newBitString(int s) { // O_s defined in sec 2.3;
        if(s == 0) return new byte[0];
        return new byte[s/8]; // Caveat: if s is not divisible by 8, what do?
    }

    public static byte[] bitstringXor(byte[] X, byte[] Y) {
        // X xor Y for strings of arbitrary but equal bit length.
        byte[] R = new byte[X.length];
        for(int i=0; i< R.length; i++) R[i] = (byte) (X[i] ^ Y[i]);
        return R;
    }
    // log_2(x)
    // min(x, y)
    // required methods / specialized functions
    public static byte[] left_encode(int x) {
        // FIXME: left_encode should take all x such that 0 <= x < 2**2040
        // find n, the number of bytes required to encode x:
        int n = 1;
        //while((1 << 8*n) > x) {
        while(Math.pow(2, 8*n) < x) {
            n++;
        }
        System.out.printf("To store %d req's %d bytes.\n", x, n);
        // need bytes of x:
        var b = new byte[n];
        for(int i=0; i < n; i++) { // extract n bytes from the int
            b[n-i-1] = (byte) (x & 0xFF);
            x >>>= 8; // shift right by one byte.
        }

        var ret = new byte[n+1];
        ret[0] = ((byte) n); // left encode, so we encode the size on the left.
        System.arraycopy(b, 0, ret, 1, n);
        return ret;
    }
    public byte[] appendBytes(byte[] A, byte[] B) {
        var ret = new byte[A.length + B.length];
        System.arraycopy(A, 0, ret, 0, A.length);
        System.arraycopy(B, 0, ret, A.length, B.length);
        return ret;
    }
    public byte[] encode_string(byte[] S) {
//        The encode_string function is used to encode bit strings in a way that may be parsed
//        unambiguously from the beginning of the string, S. The function is defined as follows:
        // Return left_encode(len(S)) || S.
        // TODO: possible refactor for bitwise implementation of || operator?
        // TODO: if the bit string S is not byte-oriented (i.e., len(S) is not a multiple of 8), the bit string
        //returned from encode_string(S) is also not byte-oriented. However, if len(S) is a multiple of 8,
        //then the length of the output of encode_string(S) will also be a multiple of 8
        return appendBytes(left_encode(S.length*8), S);
    }
    public byte[] bytepad(byte[] /* bitstring? */ X, int w) {
        // The bytepad(X, w) function prepends an encoding of the integer w to an input string X, then pads
        //the result with zeros until it is a byte string whose length in bytes is a multiple of w. In general,
        //bytepad is intended to be used on encoded strings—the byte string bytepad(encode_string(S), w)
        //can be parsed unambiguously from its beginning, whereas bytepad does not provide
        //unambiguous padding for all input strings.
        // data returned is a byte string of form [ left_encode(w) || X || 0*n ]
        var z = appendBytes(left_encode(w), X); // TODO: conversion of X to byte[] from bitstring
        while(z.length % w != 0) {
            z = appendBytes(z, new byte[]{ 0 });
        }
        return z;
    }
//    public byte[] substring(byte[] /* bitstring? */ X, int a, int b) {
//        // returns a substring from the bitstring X containing values [a, b-1] inclusive.
//        // FIXME: assumes a and b are multiples of 8, and X is a byte string.
//        // Specifically this function is supposed to work with BIT strings.
//        a = a/8;
//        b = b/8;
//
//        if(a >= b || a >= X.length) {
//            return new byte[]{};
//        }
//        if(b <= X.length) {
//            var R = new byte[b-1 - a]; // new bitstring
//            System.arraycopy(X, a, R, 0, R.length);
//            return R;
//        }
//        return Arrays.copyOfRange(X, a, X.length-1);
//    }
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
        if(L % 8 != 0) throw new IllegalArgumentException("Only whole bytes are supported.");
        if(L == 0) return new byte[0];

        if(N.length == 0 && S.length == 0) {
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
        if(mode == 128) {
            // return keccak256(bytepad(encode_string(N) || encode_string(S), 168) || X || 00, L)
        }
        // return // keccak512(bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)

        var ctx = new Sha3.sha3_ctx_t();
        Sha3.sha3_keccakf(ctx);
        return new byte[]{};// FIXME: not properly implemented. see above coments.
    }
}
