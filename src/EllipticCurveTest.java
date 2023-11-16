import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class EllipticCurveTest {

//    EllipticCurve testCurve = new EllipticCurve();
    // constants
    final static BigInteger PRIME_P = ((BigInteger.valueOf(2).pow(448)).subtract(BigInteger.valueOf(2).pow(224))).subtract(BigInteger.ONE);
    private final EllipticCurve.GoldilocksPair publicGenerator = EllipticCurve.G;
    // Neutral element: O := (0, 1)
    private final EllipticCurve.GoldilocksPair neutralElement = new EllipticCurve.GoldilocksPair(BigInteger.ZERO, BigInteger.ONE);

    // TODO:
    @Test
    public void testGoldilocksConstructor() {
        EllipticCurve.GoldilocksPair pair = new EllipticCurve.GoldilocksPair(BigInteger.ONE, BigInteger.TWO);


        Assertions.assertEquals(BigInteger.valueOf(1), pair.x);
        Assertions.assertEquals(BigInteger.valueOf(2), pair.y);

    }

    // what tests to create

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
     *
      */
    @Test
    public void test_G_Plus_Negative_G() {
        EllipticCurve.GoldilocksPair negativeG = publicGenerator.opposite();
        EllipticCurve.GoldilocksPair result = publicGenerator.add(negativeG);
//        Assertions.assertEquals(result, neutralElement);
//        Assertions.assertEquals(result, negativeG);
        Assertions.assertEquals(result, neutralElement);
    }

    /**
     * Test Case: 0 * G = 0
     *      Neutral Element * G = Neutral Element
     */

    /**
     * Runs given tests to verify the integrity of field <F> of the curve
     */
    @Test
    public void field_tests() {
        var O = EllipticCurve.neutralElement; // (0, 1)
        var G = EllipticCurve.G; // ( -3 mod P, sqrt((1 − x^2)/(1 + 39081x^2)) mod P.
        //    0 ⋅ 𝐺 = O

        var U = G.exp(BigInteger.ZERO);
        Assertions.assertEquals(U, O);

        //    1 ⋅ 𝐺 = 𝐺
        Assertions.assertEquals(G.exp(BigInteger.ONE), G);

        //    𝐺 + (−𝐺) = 𝑂 where −𝐺 = (𝑝 − 𝑥, 𝑦) for 𝐺 = (𝑥, 𝑦)
        Assertions.assertEquals(G.add(G.opposite()), O); // 𝐺 + (−𝐺) = 𝑂
            // −𝐺 = (𝑝 − 𝑥, 𝑦)
        Assertions.assertEquals(G.opposite(), new EllipticCurve.GoldilocksPair(PRIME_P.subtract(G.x), G.y));

        //    2 ⋅ 𝐺 = 𝐺 + 𝐺
        Assertions.assertEquals(G.exp(BigInteger.TWO), G.add(G));

        //    4 ⋅ 𝐺 = 2 ⋅ (2 ⋅ 𝐺)
        Assertions.assertEquals(G.exp(BigInteger.valueOf(4)), G.exp(BigInteger.TWO).exp(BigInteger.TWO));

        //     4 ⋅ 𝐺 ≠ 𝑂
        Assertions.assertNotEquals(G.exp(BigInteger.valueOf(4)), O);

        //    𝑟 ⋅ 𝐺 = 𝑂
        Assertions.assertEquals(G.exp(EllipticCurve.R), O);
    }
}
