import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class EllipticCurveTest {
    //    EllipticCurve testCurve = new EllipticCurve();
    // constants
    final static BigInteger PRIME_P = ((BigInteger.valueOf(2).pow(448)).subtract(BigInteger.valueOf(2).pow(224))).subtract(BigInteger.ONE);
    final static int sample_size = 50; // number of samples we take for randomized testing.
    final static int N = PRIME_P.bitLength(); // maximum bitlength of our randomly gen'd numbers.
    // (0, 1)
    static final EllipticCurve.GoldilocksPair O = EllipticCurve.neutralElement;
    // ( -3 mod P, sqrt((1 − x^2)/(1 + 39081x^2)) mod P.
    static final EllipticCurve.GoldilocksPair G = EllipticCurve.G;
    private final EllipticCurve.GoldilocksPair publicGenerator = EllipticCurve.G;

    // what tests to create
    // Neutral element: O := (0, 1)
    private final EllipticCurve.GoldilocksPair neutralElement = new EllipticCurve.GoldilocksPair(BigInteger.ZERO, BigInteger.ONE);

    // TODO:
    @Test
    public void testGoldilocksConstructor() {
        EllipticCurve.GoldilocksPair pair = new EllipticCurve.GoldilocksPair(BigInteger.ONE, BigInteger.TWO);
        Assertions.assertEquals(BigInteger.valueOf(1), pair.x);
        Assertions.assertEquals(BigInteger.valueOf(2), pair.y);
    }

    /**
     * Testing if the sqaureRootModsP returns non null value correctly
     */
    @Test
    public void testSquareRootModsP() {
        EllipticCurve.GoldilocksPair pair = new EllipticCurve.GoldilocksPair(BigInteger.valueOf(-3).mod(EllipticCurve.PRIME_P),
                EllipticCurve.squareRootModP(BigInteger.valueOf(-3).mod(EllipticCurve.PRIME_P)));
        // y value of a public generator of Elliptic Curve
        BigInteger yValue = EllipticCurve.squareRootModP(BigInteger.valueOf(-3).mod(EllipticCurve.PRIME_P));
        Assertions.assertNotEquals(yValue, null);

        // y value that is guaranteed to not be negative

    }

    //
    @Test
    public void testNeutralElement() {

    }

    /**
     * Test G + (-G) = O
     * Test opposite & Edwards Addition
     * G = (x, y), then -G = (-x, y)
     */
    @Test
    public void test_G_Plus_Negative_G() {
        EllipticCurve.GoldilocksPair negativeG = publicGenerator.opposite();
        EllipticCurve.GoldilocksPair result = publicGenerator.add(negativeG);
        Assertions.assertEquals(result, neutralElement);

        Assertions.assertEquals(O, O.add(O.opposite()));
    }

    /**
     * Test Case: 0 * G = 0
     * Neutral Element * G = Neutral Element
     */

    @Test
    public void test_P() {
        var P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        assert Arrays.equals(P.toByteArray(), EllipticCurve.PRIME_P.toByteArray());
    }

    @Test
    public void test_opposite() {
        // −𝐺 = (𝑝 − 𝑥, 𝑦)
        Assertions.assertEquals(G.opposite(), new EllipticCurve.GoldilocksPair(PRIME_P.subtract(G.x), G.y));
    }

    @Test
    public void test_scalar_mult_Gzero() {
        //    0 ⋅ 𝐺 = O
        var U = G.exp(BigInteger.ZERO);
        Assertions.assertEquals(O, U);
    }

    @Test
    public void test_scalar_mult_neutralZero() {
        var U = O.exp(BigInteger.ZERO);
        Assertions.assertEquals(O, U);
    }

    @Test
    public void test_scalar_mult_one() {
        //    1 ⋅ 𝐺 = 𝐺
        Assertions.assertEquals(G, G.exp(BigInteger.ONE));
    }

    @Test
    public void test_scalar_mult_two() {
        //    2 ⋅ 𝐺 = 𝐺 + 𝐺
        Assertions.assertEquals(G.exp(BigInteger.TWO), G.add(G));
    }

    @Test
    public void test_exp_4_equals_22G() {
        //    4 ⋅ 𝐺 = 2 ⋅ (2 ⋅ 𝐺)
        Assertions.assertEquals(G.exp(BigInteger.valueOf(4)), G.exp(BigInteger.TWO).exp(BigInteger.TWO));
    }

    @Test
    public void test_4G_ne_neutral() {
        //     4 ⋅ 𝐺 ≠ 𝑂
        Assertions.assertNotEquals(G.exp(BigInteger.valueOf(4)), O);
    }

    @Test
    public void test_rG_equals_neutral() {
        //    𝑟 ⋅ 𝐺 = 𝑂
        System.out.println(PRIME_P.subtract(G.exp(EllipticCurve.R).x));
        Assertions.assertEquals(O, G.exp(EllipticCurve.R));
    }


    @Test
    public void test_random_k_t_1() {
        //𝑘 ⋅ 𝐺 = (𝑘 mod 𝑟) ⋅ 𝐺
        for (int i = 0; i < sample_size; i++) {
            var k = new BigInteger(N, 0, new SecureRandom());
            Assertions.assertEquals(G.exp(k), G.exp(k.mod(EllipticCurve.R)));
        }
    }

    @Test
    public void test_random_k_t_2() {
        var rand = new SecureRandom();
        for (int i = 0; i < sample_size; i++) {
            var k = new BigInteger(N, 0, rand);
            //(𝑘 + 1) ⋅ 𝐺 = (𝑘 ⋅ 𝐺) + 𝐺
            Assertions.assertEquals(G.exp(k.add(BigInteger.ONE)), G.exp(k).add(G));
        }
    }

    @Test
    public void test_random_k_t_3() {
        var rand = new SecureRandom();
        for (int i = 0; i < sample_size; i++) {
            var k = new BigInteger(N, 0, rand);
            var t = new BigInteger(N, 0, rand);
            //(𝑘 + 𝑡) ⋅ 𝐺 = (𝑘 ⋅ 𝐺) + (𝑡 ⋅ 𝐺)
            Assertions.assertEquals(
                    G.exp(k.add(t)),
                    G.exp(k).add(G.exp(t))
            );

            // TODO: what does P represent here? a random point?
            //𝑘 ⋅ (𝑡 ⋅ 𝑃) = 𝑡 ⋅ (𝑘 ⋅ 𝐺) = (𝑘 ⋅ 𝑡 mod 𝑟) ⋅ 𝐺
        }
    }

    @Test
    public void test_add_1() {
        var a = new BigInteger("-1");
        var b = new BigInteger("45");
        var c = PRIME_P.subtract(b.modPow(BigInteger.TEN, PRIME_P));

        var A = new EllipticCurve.GoldilocksPair(a, EllipticCurve.f(a));
        var B = new EllipticCurve.GoldilocksPair(b, EllipticCurve.f(b));
        var C = new EllipticCurve.GoldilocksPair(c, EllipticCurve.f(c));
        // A + (B + C) == (A + B) + C
        Assertions.assertEquals(B.add(C).add(A), A.add(B).add(C));
    }

    @Test
    public void test_add_2() {
        // (𝑘 ⋅ 𝐺) + ((ℓ ⋅ 𝐺) + (𝑚 ⋅ 𝐺)) = ((𝑘 ⋅ 𝐺) + (ℓ ⋅ 𝐺)) + (𝑚 ⋅ 𝐺)
        var rand = new SecureRandom();

        for (int i = 0; i < sample_size; i++) {
            var k = new BigInteger(N, 0, rand);
            var l = new BigInteger(N, 0, rand);
            var m = new BigInteger(N, 0, rand);

            var L = G.exp(l);
            var M = G.exp(m);
            var K = G.exp(k);
            // A + (B + C) == (A + B) + C
            Assertions.assertEquals(
                    K.add(L.add(M)), // K + (L + M)
                    (K.add(L)).add(M)); // (K + L) + M
        }
    }
    @Test
    public void test_encrypt_decrypt_identity2() {
        var passes = 0;
        for(int i=0; i < sample_size; i++) {
            // tests for a longer, random password.
            var pw = new BigInteger(448, EllipticCurve.RAND).toByteArray();
            // need to gen a public / private key pair.
            var keyPair = EllipticCurve.generateKeyPair(pw);

            // encrypt a message
            var m2 = "test message abcdefg".getBytes();
            var zct = EllipticCurve.encrypt(m2, keyPair.publicKey());

            // attempt decyrption
            byte[] result;
            try {
                result = EllipticCurve.decrypt(zct, pw);
            } catch(IllegalArgumentException e) {
                result = new byte[]{};
            }
            //assert Arrays.equals(result, m2);
            if(Arrays.equals(result, m2)) passes++;
        }
        assert passes == sample_size;
    }
    @Test
    public void test_encrypt_decrypt_identity_long() {
        for(int len=100; len < 512; len <<= 1) {
            var pw = "test password".getBytes();
            // need to gen a public / private key pair.
            var keyPair = EllipticCurve.generateKeyPair(pw);

            // encrypt a message
            var m = new byte[len];
            EllipticCurve.RAND.nextBytes(m);
            var zct = EllipticCurve.encrypt(m, keyPair.publicKey());

            // attempt decyrption
            byte[] result = new byte[]{};
            try {
                result = EllipticCurve.decrypt(zct, pw);
            } catch(IllegalArgumentException e) {
                System.out.println(len);
            }
            assert Arrays.equals(result, m);
        }
    }
    @Test
    public void test_verify_signiture() {
        var m = "Lorem Ipsem 12345678910".getBytes();
        var pw = "test password".getBytes();
        var sig = EllipticCurve.generateSignature(m, pw);

        // verifySignature() requires pub key V. generate from pw?
        var V = EllipticCurve.generateKeyPair(pw).publicKey();

        assert EllipticCurve.verifySignature(sig, V, m);
    }
    @Test
    public void test_verify_signiture_long() {
        for(int i=0; i < sample_size; i++) {
            var m = new byte[1024*10];
            EllipticCurve.RAND.nextBytes(m);

            var pw = new byte[300];
            EllipticCurve.RAND.nextBytes(pw);
            var sig = EllipticCurve.generateSignature(m, pw);

            // verifySignature() requires pub key V. generate from pw?
            var V = EllipticCurve.generateKeyPair(pw).publicKey();

            assert (EllipticCurve.verifySignature(sig, V, m));
        }
    }
    /**
     * tests the functionality of recovering V.x from V.y and x_lsb
     */
    @Test
    public void test_f() {
        int passes = 0;
        for(int i=0; i < sample_size; i++) {
            var pw = new BigInteger(448, EllipticCurve.RAND).toByteArray();
            // need to gen a public / private key pair.
            var keyPair = EllipticCurve.generateKeyPair(pw);
            var V = keyPair.publicKey();
            var lsb = V.x.and(BigInteger.ONE).equals(BigInteger.ONE);
            if(EllipticCurve.f(V.y, lsb).equals( V.x)) {
               passes++;
            }
        }
        System.out.println(passes/sample_size*100);
        assert passes==sample_size;
    }
}