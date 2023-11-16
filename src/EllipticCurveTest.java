import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class EllipticCurveTest {

//    EllipticCurve testCurve = new EllipticCurve();
    // constants
    final static BigInteger PRIME_P = ((BigInteger.valueOf(2).pow(448)).subtract(BigInteger.valueOf(2).pow(224))).subtract(BigInteger.ONE);
    private EllipticCurve.GoldilocksPair publicGenerator = new EllipticCurve.GoldilocksPair(BigInteger.valueOf(-3).mod(PRIME_P),
        EllipticCurve.GoldilocksPair.squareRootModP(BigInteger.valueOf(-3).mod(PRIME_P)));

    // Neutral element: G := (0, 1)
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
                                                EllipticCurve.GoldilocksPair.squareRootModP(BigInteger.valueOf(-3).mod(EllipticCurve.PRIME_P)));
        // y value of a public generator of Elliptic Curve
        BigInteger yValue = EllipticCurve.GoldilocksPair.squareRootModP(BigInteger.valueOf(-3).mod(EllipticCurve.PRIME_P));
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
        EllipticCurve.GoldilocksPair negativeG = EllipticCurve.GoldilocksPair.opposite(publicGenerator);
        EllipticCurve.GoldilocksPair result = publicGenerator.edwardsAddition(publicGenerator.x, publicGenerator.y,
                                                                                negativeG.x, negativeG.y);
//        Assertions.assertEquals(result, neutralElement);
//        Assertions.assertEquals(result, negativeG);
        Assertions.assertEquals(result, neutralElement);
    }

    /**
     * Test Case: 0 * G = 0
     *      Neutral Element * G = Neutral Element
     */
}
