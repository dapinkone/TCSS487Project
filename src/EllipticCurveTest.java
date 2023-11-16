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
    @Test
    public void testSquareRootModsP() {
        
    }
    //
    @Test
    public void testNeutralElement() {

    }
}
