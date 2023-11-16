import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class EllipticCurveTest {

//    EllipticCurve testCurve = new EllipticCurve();

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
     * Test for opposite
     * P = (x, y), then -P = (-x, y)
     * Can we say that P - P = (x -x, y + y) = (0, 2*y)
      */


}
