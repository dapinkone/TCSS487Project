import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;

public class EllipticCurve {
    /**
     * Neutral element: O := (0, 1)
     * Neutral element has a point of (0, 1)
     */
    public static final GoldilocksPair neutralElement = new GoldilocksPair(BigInteger.ZERO, ONE);
    static final SecureRandom RAND = new SecureRandom();
    // P := 2^448 − 2^224 − 1
    final static BigInteger PRIME_P = (
            TWO.pow(448) // 2^448
                    .subtract(TWO.pow(224)) // - 2^224
                    .subtract(ONE)); // - 1

    // 𝑟 = 2^446 − 13818066809895115352007386748515426880336692474882178609894547503885
    final static BigInteger R = (TWO).pow(446).subtract(
            new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    // data structure to represent goldilocks pair (x, y)
    // Edwards curve equation : x^2 + y^2 = 1 +dx^2y^2 with d = -39081
//    public static final int NUMBER_OF_BITS = 448;
    private final static BigInteger D = new BigInteger("-39081");
    /**
     * public generator G
     * y = -3 (mod p) and x = something
     **/
    private static final BigInteger G_y = PRIME_P.subtract(BigInteger.valueOf(3));
    public static final GoldilocksPair G = new GoldilocksPair(
            //BigInteger.valueOf(-3).mod(PRIME_P),
            // ± √((1 − 𝑦^2)/(1 + 39081𝑦^2)) mod 𝑝.
            false,
            G_y
    );

    /**
     * Generate a Schnorr Signature key pair from a passphrase pw:
     */
    public static KeyPair generateKeyPair(byte[] pw) {

        // s <- KMACXOF256(pw, "", 448, "SK")
        byte[] s = KMACXOF256.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes());
        BigInteger privateKey = new BigInteger(s);

        // x <- 4s(mod r); s is byte[], bytes multiply as a BigInteger?
        privateKey = (BigInteger.valueOf(4)).multiply(privateKey).mod(R);
        GoldilocksPair publicKey = G.exp(privateKey);

        return new KeyPair(privateKey, publicKey);
    }

    /**
     * Currently uses 448 as number of bits in this function.
     *
     * @return
     */
    private static byte[] randomBytes() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[448 / 8];
        random.nextBytes(bytes);
        return bytes;
    }

    /**
     * Encrypts a byte array m, under the (Schnorr/DHIES) public key
     *
     * @param m
     * @param V
     * @return
     */
    public static byte[] encrypt(byte[] m, GoldilocksPair V) {
        // k <- Random(448);
        BigInteger k = new BigInteger(448, RAND)
                // k <- 4k (mod r)
                .shiftLeft(2).mod(R);

        // W <- k *V;
        GoldilocksPair W = V.exp(k);
        // Z <- k*G
        GoldilocksPair Z = G.exp(k);

        // (ka || ke) <- KMACXOF256(W_x, "", 2 * 448, "PK")
        byte[] ka_ke = KMACXOF256.KMACXOF256(
                W.x.toByteArray(),
                "".getBytes(),
                448 * 2,
                "PK".getBytes());

        // split (ka || ke) a (448 * 2) long bits into 448 bits (56 bytes in length)
        byte[] ka = Arrays.copyOfRange(ka_ke, 0, 56); //
        byte[] ke = Arrays.copyOfRange(ka_ke, 56, 112);

        // c <- KMACXOF256(ke, "", |m|, "PKE") xor m
        byte[] c = KMACXOF256.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes());
        KMACXOF256.xor(c, m);
        // append (c.length || c) appendBytes(new byte[]{(byte) xLength}, c)
        byte[] leftEncodedC = KMACXOF256.left_encode(c);
        // t <- KMACXOF256(ka, m, 448, "PKA")
        byte[] t = KMACXOF256.KMACXOF256(ka, m, 448, "PKA".getBytes());
        // append (t.length || t)
        byte[] leftEncodedT = KMACXOF256.left_encode(t);

        //byte x_lsb = (byte) ((Z.x.testBit(Z.x.bitLength()-1)) ? 1 : 0); // (Z.x & 1) == 1
        // cryptogram : (Z, c, t) append Z.y with c and t because Z.x can be retrieved with Z.y
        return KMACXOF256.appendBytes(KMACXOF256.left_encode(Z.x), KMACXOF256.left_encode(Z.y), leftEncodedC, leftEncodedT);
        // t.length = 448, c.length = 448 because ke.length = 448 (?), Z.x = , Z.y =
    }
    /**
     * Decrypt the zct[] message under a passphrase pw
     *
     * @param zct given cryptogram
     * @param pw  passphrase
     * @return
     */
    public static byte[] decrypt(byte[] zct, byte[] pw) {
        // TODO: possible rewrite using a left_decode() function?
        // unpack different left encoded values from (Z, c, t)
        int ptr = 0; // points to the start of the current left_encode we're unpacking.
        int len; // the length of the current left_encode
        // unpack Z_x
        len = zct[ptr] & 0xFF; // need to bitmask to avoid sign extension on the int typecast.
        byte[] z_x = Arrays.copyOfRange(zct, ptr + 1, ptr + 1 + len);
        ptr += 1 + len;

        // unpack Z_y
        len = zct[ptr] & 0xFF; // need to bitmask to avoid sign extension on the int typecast.
        byte[] z_y = Arrays.copyOfRange(zct, ptr + 1, ptr + 1 + len);
        ptr += 1 + len;

        // unpack c
        len = zct[ptr] & 0xFF;
        byte[] c = Arrays.copyOfRange(zct, ptr + 1, ptr + 1 + len); // TODO: not using c?
        ptr += 1 + len;

        // unpack t
        len = zct[ptr] & 0xFF;
        byte[] t = Arrays.copyOfRange(zct, ptr + 1, ptr + 1 + len);

        // unpacking complete, collect (Z_x, Z_y) into data structure for use:
        // TODO: (re?)store x_lsb ? rather than z_x to save space
        GoldilocksPair Z = new GoldilocksPair(new BigInteger(z_x), new BigInteger(z_y));

        // 1. s <- KMACXOF256(pw, "", 448, "SK")
        byte[] s = KMACXOF256.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes());

        // 2. s <- 4s mod r
        BigInteger bigS = new BigInteger(s).shiftLeft(2).mod(R);

        // 3. W <- s*Z
        GoldilocksPair W = Z.exp(bigS);

        // 4. (ka || ke) <- KMACXOF256(W_x, "", 2 x 448, "PK")
        byte[] ka_ke = KMACXOF256.KMACXOF256(W.x.toByteArray(), "".getBytes(), 2 * 448, "PK".getBytes());
        // 4. (ka || ke) <- KMACXOF256(Wx, “”, 2×448, “PK”)
        byte[] ka = Arrays.copyOfRange(ka_ke, 0, 56);
        byte[] ke = Arrays.copyOfRange(ka_ke, 56, 112);

        // 5. m <- KMACXOF256(ke, “”, |c|, “PKE”) ^ c
        byte[] m = KMACXOF256.KMACXOF256(ke, "".getBytes(), c.length*8, "PKE".getBytes());
        KMACXOF256.xor(m, c);

        // 6. t’ <- KMACXOF256(ka, m, 448, “PKA”)
        byte[] tPrime = KMACXOF256.KMACXOF256(ka, m, 448, "PKA".getBytes());

        // 7. accept if, and only if, t’ = t
        if (Arrays.equals(tPrime, t)) {
            return m;
        } else {
            throw new IllegalArgumentException("Decryption failed: authentication tag does not match");
        }
    }

    /**
     * Generates a signature for a byte array m under passphrase pw
     *
     * @param m  given message/plaintext
     * @param pw given passphrase
     * @return KeyPair
     */
    public static byte[][] generateSignature(byte[] m, byte[] pw) {
        //▪ s <- KMACXOF256(pw, “”, 448, “SK”); s <- 4s (mod r)
        var s = new BigInteger(KMACXOF256.KMACXOF256(pw, "".getBytes(), 448, "SK".getBytes()))
                .shiftLeft(2).mod(R);

        //▪ k <- KMACXOF256(s, m, 448, “N”); k <- 4k (mod r)
        var k = new BigInteger(KMACXOF256.KMACXOF256(s.toByteArray(), m, 448, "N".getBytes()))
                .shiftLeft(2).mod(R);

        //▪ U <- k*G;
        var U = G.exp(k);

        //▪ h <- KMACXOF256(Ux, m, 448, “T”); z <- (k – hs) mod r
        var h = KMACXOF256.KMACXOF256(U.x.toByteArray(), m, 448, "T".getBytes());
        var z = (k.subtract((new BigInteger(h)).multiply(s))).mod(R).toByteArray();

        //▪ signature: (h, z)
        return new byte[][]{h, z};
    }

    /**
     * verifies a signature (h, z) for a byte array m under the (Schnorr/ DHIES)
     * public key V
     *
     * @param hz signature (h, z)
     * @param m  message/plaintext
     * @return boolean
     */
    public static boolean verifySignature(byte[][] hz, GoldilocksPair V, byte[] m) {
        // TODO: should be able to pass in and destructure signature (h, z) as byte[]
        var h = hz[0];
        var z = hz[1];

        var U = G.exp(new BigInteger(z)).add(V.exp(new BigInteger(h)));
        var h_prime = KMACXOF256.KMACXOF256(U.x.toByteArray(), m, 448, "T".getBytes());
        return h == h_prime;
    }

    public static BigInteger f(BigInteger x) { // default parameter for lsb
        return f(x, false);
    }

    public static BigInteger f(BigInteger x, boolean lsb) { // formula is symmetrical. x or y are interchangeable.
        // ± √((1 − 𝑦^2)/(1 + 39081𝑦^2)) mod 𝑝.
        return sqrt(
                mult(ONE.subtract(mult(x, x)), // (1 - x^2)
                        // ... / ( 1 + 39081*x^2 )
                        ONE.add(mult(x, x, BigInteger.valueOf(39081)))
                                .modInverse(PRIME_P)
                ),
                PRIME_P,
                lsb
        );
        // TODO: fix or throw null exception
    }

    /**
     * Multiply various given BigIntegers together, mod PRIME_P
     *
     * @param lst list of bigints to be multiplied
     * @return result mod PRIME_P
     */
    private static BigInteger mult(BigInteger... lst) {
        var result = ONE;

        for (var x : lst) {
            result = (x != null) ? result.multiply(x).mod(PRIME_P) : result;
        }
        return result; // 36.489s pre-karatsuba
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @param v   the radicand.
     * @param p   the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1));
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * From x = sqrt ((1-y^2) / (1 + 39081 * y^2)) mod p
     * We are calculating y by swapping x and y in the above equation
     * because x and y are symmetric.
     * If the radicand is negative, then it will be null.
     * 1 out of 2 y_0 value can be null.
     * By default: if both square root values equal to null, throw IllegalArgument Exception
     * if both possible y values are null.
     *
     * @param x BigInteger value of x
     * @return array of possible y_0 values.
     */
    public static BigInteger squareRootModP(BigInteger x) {
        BigInteger[] possibleY_0 = new BigInteger[2];
        BigInteger yValue;

        BigInteger firstPart = ONE.subtract(mult(x, x)).mod(PRIME_P);
        BigInteger secondPart = ONE.add(mult(BigInteger.valueOf(39081), mult(x, x))).mod(PRIME_P);
        BigInteger result = firstPart.multiply(secondPart.modInverse(PRIME_P)).mod(PRIME_P);

        BigInteger firstPossibleY_0 = sqrt(result, PRIME_P, true);
        BigInteger secondPossibleY_0 = sqrt(result, PRIME_P, false);
        // possible value of y could be null.
        possibleY_0[0] = firstPossibleY_0;
        possibleY_0[1] = secondPossibleY_0;

        // both Y values are not null, return 0th index
        if (possibleY_0[0] != null && possibleY_0[1] != null) {
            yValue = possibleY_0[0];
            System.out.println("Both y values are not null");
            // Only 0th index of Y = null
        } else if (possibleY_0[0] == null && possibleY_0[1] != null) {
            yValue = possibleY_0[1];
            // Only 1st index of Y = null
        } else if (possibleY_0[0] != null && possibleY_0[1] == null) {
            yValue = possibleY_0[0];
            // both 0th and 1st index of Y = null
        } else {
            throw new IllegalArgumentException("Both square root values are null");
        }
        return yValue;
    }

    /**
     * @param publicKey Schnorr Signature creates key pair of signature and public key.
     *                  DataStructure to contain the generated keypairs.
     */
    record KeyPair(BigInteger privateKey, GoldilocksPair publicKey) {

        @Override
        public BigInteger privateKey() {
            return privateKey;
        }

        @Override
        public GoldilocksPair publicKey() {
            return publicKey;
        }

        /**
         * Returns a key pair as a (privateKey, goldilocksPair) format.
         *
         * @return String version of key pair as (privateKey value, goldilocksPair)
         */
        public String toString() {
            return String.format("(%s, %s)", privateKey, publicKey);
        }
    }

    static class GoldilocksPair {

        final public BigInteger x;
        final public BigInteger y;

        // Constructor of GoldilocksPair
        //
        public GoldilocksPair(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public GoldilocksPair(boolean x_lsb, BigInteger y) {
            this(f(y, x_lsb), y);
        }

        @Override
        public String toString() {
            return String.format("(%s, %s)", x, y);
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof GoldilocksPair) | o == null) return false;

            var that = (GoldilocksPair) o;
            if (this.x == null | this.y == null) return false;
            if (that.x == null ^ that.y == null) return false;

            return this.x.equals(that.x) && this.y.equals(that.y);
        }

        /**
         * Computing the sum of two goldilocks points below:
         * (x_1, y_1) + (x_2, y_2) = |(x_1 * y_2 + y_1 * x_2) [Part1]         (y_1* y_2 - x_1 * x_2)      [part3]  |
         * | ----------------------              ----------------------                  |
         * |(1 + d*x_1 * x_2 * y_1 * y_2) [Part2] , (1 - d*x_1 * x_2 * y_1 * y_2) [part4]|
         * Given 1st point (x_1, y_1) and 2nd point (x_2, y_2)
         *
         * @param other goldilocks point to add to the current point
         * @return Edward Curve addition of (x_1, y_1) + (x_2, y_2)
         */
        public GoldilocksPair add(GoldilocksPair other) {
            var x1 = this.x;
            var x2 = other.x;
            var y1 = this.y;
            var y2 = other.y;

            // (x_1 * y_2 + y_1 * x_2)
            var part1 = (mult(x1, y2)).add(mult(y1, x2)).mod(PRIME_P);
            var d_x1_x2_y1_y2 = mult(D, x1, x2, y1, y2);
            // (1 + d*x_1 * x_2 * y_1 * y_2)
            var part2 = ONE.add(d_x1_x2_y1_y2).mod(PRIME_P);
            // (y_1 * y_2 - x_1 * x_2)
            var part3 = (mult(y1, y2)).subtract(mult(x1, x2)).mod(PRIME_P);
            // (1 - d*x_1 * x_2 * y_1 * y_2)
            var part4 = ONE.subtract(d_x1_x2_y1_y2).mod(PRIME_P);

            BigInteger x = mult(part1, part2.modInverse(PRIME_P)); // division in modular arithmetic
            BigInteger y = mult(part3, part4.modInverse(PRIME_P));
            // returns ( part1 / part2, part3 / part4)
            return new GoldilocksPair(x, y);
        }

        /**
         * If point is (x, y), returns (-x, y)
         *
         * @return (- x, y)
         */
        public GoldilocksPair opposite() {
            // -x == x * (P - 1)
            var negX = this.x.multiply(PRIME_P.subtract(ONE)).mod(PRIME_P);
            return new GoldilocksPair(negX, this.y);
        }

        /**
         * Multiplication-by-scalar algorithm by invoking Edwards point addition formula
         * Note: exponentiation of a point, and scalar multiplication are equivalent.
         * P**s == s * P
         *
         * @param s integer to multiply a point
         * @return V = s * P
         */
        public GoldilocksPair exp(BigInteger s) {
            // see slide 40, TCSS 487 - 6. Asymmetric Cryptography and modular arithmetic
            // for math pseudocode.
            //------------

            GoldilocksPair V = neutralElement; // initialize V
            // search bits for the first s_k=1 to begin calculations with s_(k-1) ... s_0
            for (int i = s.bitLength() - 1; i >= 0; i--) { // scan over the k bits of s
                V = V.add(V);//edwardsAddition(V.x, V.y, V.x, V.y);   // invoke edwards point addition
                if (s.testBit(i)) {    // test i-th bit of s
                    V = V.add(this); //edwardsAddition(V.x, V.y, P.x, P.y);    // edwards point addition formula
                }
            }
            return V;
        }
    }

    // G
}
