import jdk.jshell.spi.ExecutionControl;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class KMACXOF256 {

    public static final int NUMBER_OF_BYTES = 512; // 64 bytes = 512 bits

    // basic operations & functions from FIPS 202
    public static byte enc8(byte b) {
        // return (byte) (Integer.reverse(b & 0xFF) >>> 24);
        int result = 0;
        for(int i = 0; i < 8; i++) {
            result = ((result << 1) | b & 1);
            b >>>= 1;
        }
        return (byte) result;
    }
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
        ret[0] = enc8((byte) n); // left encode, so we encode the size on the left.
        for(int i=0; i < n; i++) ret[i+1] = enc8(b[i]);
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
    /**
     * Applied the NIST bytepad primitive to a byte array X with encoding factor w.
     * @param X byte array to bytepad
     * @param w encoding factor (the output length must be a multiple of w)
     * @return byte-padded byte array X with encoding factor w.
     */
    public byte[] bytepad(byte[] /* bitstring? */ X, int w) {
        // The bytepad(X, w) function prepends an encoding of the integer w to an input string X, then pads
        //the result with zeros until it is a byte string whose length in bytes is a multiple of w. In general,
        //bytepad is intended to be used on encoded strings—the byte string bytepad(encode_string(S), w)
        //can be parsed unambiguously from its beginning, whereas bytepad does not provide
        //unambiguous padding for all input strings.
        // data returned is a byte string of form [ left_encode(w) || X || 0*n ]
        assert w > 0;
        // 1. z = left_encode(w) || X
        byte[] encodedW = left_encode(w);
        byte[] z = new byte[w * ((encodedW.length + X.length + w -1) / w)];
        // NB: 
        System.arraycopy(encodedW, 0, z, 0, encodedW.length);
        System.arraycopy(X, 0, z, encodedW.length, X.length);
        // 2. (nothing to do in software: Len(z) mod 8 = 0 in this byte-oriented implementation)
        // 3. while  (len(z) / 8) mod w != 0: z = z || 00000000
        for (int i = encodedW.length + X.length; i < z.length; i++) {
            z[i] = (byte)0;
        }
        // var z = appendBytes(left_encode(w), X); // TODO: conversion of X to byte[] from bitstring
        // while(z.length % w != 0) {
        //     z = appendBytes(z, new byte[]{ 0 });
        // }
        return z;
    }
    public byte[] substring(byte[] /* bitstring? */ X, int a, int b) {
        // returns a substring from the bitstring X containing values [a, b-1] inclusive.
        // FIXME: assumes a and b are multiples of 8, and X is a byte string.
        // Specifically this function is supposed to work with BIT strings.
        a = a/8;
        b = b/8;

        if(a >= b || a >= X.length) {
            return new byte[]{};
        }
        if(b <= X.length) {
            var R = new byte[b-1 - a]; // new bitstring
            System.arraycopy(X, a, R, 0, R.length);
            return R;
        }
        return Arrays.copyOfRange(X, a, X.length-1);
    }
    /**
     * Main function of KMACXOF256.
     * @param mode
     * @param X
     * @param L
     * @param N
     * @param S
     * @return
     */
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


        // Check if N and S are empty; default to SHAKE128 and SHAKE256
        if (N.length == 0 && S.length == 0) {
            Sha3.sha3_ctx_t ctx = new Sha3.sha3_ctx_t();
            if (mode == 128 ) {
                Sha3.shake128_init(ctx);
            } else {
                Sha3.shake256_init(ctx);
            }
            Sha3.sha3_update(ctx, X, X.length);
            Sha3.shake_xof(ctx);
            byte[] Z = new byte[L / 8];
            Sha3.shake_out(ctx, Z, L / 8);
            return Z;
        }

        byte[] encodedN = encode_string(N);
        byte[] encodedS = encode_string(S);

        byte[] bytePadded = bytepad(appendBytes(encodedN, encodedS), mode == 128 ? 168 : 136);
        // byte[] newX = appendBytes(bytePadded, X);
        // newX = appendBytes(newX, new byte[]{0});

        // initialize content
        Sha3.sha3_ctx_t ctx = new Sha3.sha3_ctx_t();
        Sha3.sha3_init(ctx, mode == 128 ? 16 : 32);

        // absorb byte-padded N and S
        Sha3.sha3_update(ctx, bytePadded, bytePadded.length);

        // absorb the input X
        Sha3.sha3_update(ctx, X, X.length);

        // Apply domain separation and padding
        Sha3.shake_xof(ctx);
        if(mode == 128) {
            ctx.b[ctx.pt] ^= 0x04;
            // return keccak256(bytepad(encode_string(N) || encode_string(S), 168) || X || 00, L)
        } else {
            ctx.b[ctx.pt] ^= 0x04;
            // return // keccak512(bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)
        }
        ctx.b[ctx.rsiz - 1] ^= 0x08;
        Sha3.sha3_keccakf(ctx);

        // Squeeze out output
        byte[] Z = new byte[L / 8];
        Sha3.shake_out(ctx, Z, L / 8);
        return Z;// FIXME: not properly implemented. see above coments.
    }

    private byte[] randomBytes() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[NUMBER_OF_BYTES / 8]; // 8 bits = 1 byte
        random.nextBytes(bytes);
        return bytes;
    }

    public byte[] symmetricEncrypt(byte[] m, String pw) {
        // 1. generate random 512 bit value
        byte[] z = randomBytes();

        // 2. derive encryption and authentication keys
        byte[] zpw = appendBytes(z, pw.getBytes(StandardCharsets.UTF_8));
        byte[] ke_ka = cSHAKE(256, zpw, 1024, "".getBytes(StandardCharsets.UTF_8), "S".getBytes(StandardCharsets.UTF_8));

        // split (Ke || Ka) into two 512 bits keys
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, 64);
        byte[] ka = Arrays.copyOfRange(ke_ka, 64, 128);

        // c <- KMACXOF256(ke, "", |m|, "SKE") xor m
        byte[] c = cSHAKE(256, ke, NUMBER_OF_BYTES, "".getBytes(StandardCharsets.UTF_8), "SKE".getBytes(StandardCharsets.UTF_8));
        c = bitstringXor(c, m);

        // t <- KMACXOF256(ka, m , 512, "SKA")
        byte[] t = cSHAKE(256, ka, NUMBER_OF_BYTES, m, "SKA".getBytes(StandardCharsets.UTF_8));

        // symmetric cyrptogram: (z, c, t)
        byte[] symmetricCryptogram = appendBytes(z, appendBytes(c, t));
        return symmetricCryptogram;
    }

    public byte[] symmetricDecrypt(byte[] z, byte[] c, byte[] t, String pw) {
        byte[] zpw = appendBytes(z, pw.getBytes(StandardCharsets.UTF_8));
        byte[] ke_ka = cSHAKE(256, zpw, 1024, "".getBytes(StandardCharsets.UTF_8), "S".getBytes(StandardCharsets.UTF_8));

        // split (ke || ka) into two 512-bit keys
        byte[] ke = Arrays.copyOfRange(ke_ka, 0, 64);
        byte[] ka = Arrays.copyOfRange(ke_ka, 64, 128);

        // m <- KMACXOF256(ke, "", |c|, "SKE") xor c
        byte[] m = cSHAKE(256, ke, c.length * 8, "".getBytes(StandardCharsets.UTF_8), "SKE".getBytes(StandardCharsets.UTF_8));
        m = bitstringXor(m, c);

        // tPrime <- KMACXOF256(ka, m, 512, "SKA")
        byte[] tPrime = cSHAKE(256, ka, NUMBER_OF_BYTES, m, "SKA".getBytes(StandardCharsets.UTF_8));

        if (Arrays.equals(tPrime, t)) {
            return m;
        } else {
            throw new IllegalArgumentException("Decryption failed: authentication tag does not match");
        }
    }
}
