import java.math.BigInteger;
import java.util.function.Predicate;

public class EllipticCurve {

    // data structure to represent goldilocks pair (x, y)
    // Edwards curve equation = x^2 + y^2 = 1 +dx^2y^2 with d = -39081

    // modular arithmetic addition example:
    //

    private final static BigInteger D = new BigInteger("-39081");
    private final static BigInteger two = BigInteger.valueOf(2);

    private final static BigInteger negThree = new BigInteger("-3");
    private final static BigInteger PRIME_P = ((two.pow(448)).subtract(two.pow(224))).subtract(BigInteger.ONE);

    // Neutral element: G := (0, 1)
    private GoldilocksPair neutralElement = new GoldilocksPair(BigInteger.ZERO, BigInteger.ONE);

    // x = -3 (mod p) and y = something
    private GoldilocksPair publicGenerator = new GoldilocksPair(BigInteger.valueOf(-3).mod(PRIME_P), BigInteger.ONE);

    static class GoldilocksPair {

        // constructor of neutral element
        final BigInteger x;
        final BigInteger y;

        // Constructor of GoldilocksPair
        //
        public GoldilocksPair(BigInteger x, BigInteger y) {

            // public generator G = (x_0, y_0)
            // x = -3(mod p)

            this.x = x;
            this.y = y;
        }

        /**
         * From x = sqrt ((1-y^2) / (1 + 39081 * y^2)) mod p
         * We are calculating y by swapping x and y in the above equation
         * because x and y are symmetric.
         * If the radicand is negative, then it will be null.
         * 1 out of 2 y_0 value can be null.
         * By default: if both square root values equal to null, throw IllegalArgument Exception
         * if both possible y values are null.
         * TODO: Currently, this method does
         * @return array of possible y_0 values.
         */
        private static BigInteger squareRootModP(BigInteger x) {
            BigInteger[] possibleY_0 = new BigInteger[2];
            BigInteger yValue = BigInteger.valueOf(0);

            BigInteger firstPart = BigInteger.ONE.subtract(multiplication(x, x)).mod(PRIME_P);
            BigInteger secondPart = BigInteger.ONE.add(multiplication(BigInteger.valueOf(39081), multiplication(x, x))).mod(PRIME_P);
            BigInteger result = firstPart.multiply(secondPart.modInverse(PRIME_P)).mod(PRIME_P);

            BigInteger firstPossibleY_0 = sqrt(result, PRIME_P, true);
            BigInteger secondPossibleY_0 = sqrt(result, PRIME_P, false);
            // possible value of y could be null.
            possibleY_0[0] = firstPossibleY_0;
            possibleY_0[1] = secondPossibleY_0;

            // both Y values are null, return 0th index
            if (possibleY_0[0] != null && possibleY_0[1] != null) {
                yValue = possibleY_0[0];
                System.out.println("Both y values are null");
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
         *
         * @param possibleValues
         * @return
         */
        private static BigInteger filterNull(BigInteger[] possibleValues) {
            BigInteger result = BigInteger.ZERO;

            for (int i = 0; i < possibleValues.length; i++) {
                if (possibleValues[i] != null) {
                    result = possibleValues[i];
                }
            }
            return result;
        }
        /**
         * Neutral element has a point of (0, 1)
         */

        // addition methdo
//        public BigInteger addition() {
//
//        }
        // constructor for a elliptic curve itself

        public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
            assert (p.testBit(0) && p.testBit(1));
            if (v.signum() == 0) {
                return BigInteger.ZERO;
            }
            BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
            if (r.testBit(0) != lsb) {
                r = p.subtract(r); // correct the lsb
            }
            return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
        }
    }

    // exponentiation
    private BigInteger exponentiation() {
        BigInteger result = new BigInteger("0");

        return result;
    }
    private static BigInteger multiplication (BigInteger one, BigInteger two) {
        return one.multiply(two).mod(PRIME_P);
    }

    /**
     * TODO: Refactoring the parameter to accept two goldilockspair points
     * Computing the sum of two goldilocks points below:
     * (x_1, y_1) + (x_2, y_2) = |(x_1 * y_1 + y_1 * x_2) [Part1]         (y_1* y_2 - x_1 * x_2)      [part3]  |
     *                           | ----------------------              ----------------------                  |
     *                           |(1 + d*x_1 * x_2 * y_1 * y_2) [Part2] , (1 - d*x_1 * x_2 * y_1 * y_2) [part4]|
     *
     * one = (x_1 * y_1)
     * two = (y_1 * x_2)
     *                            one * two
     *                            ---------
     *                            1 + d * one * two,
     * @param
     * @param
     * @return
     */
    private GoldilocksPair edwardsAddition(BigInteger x_1, BigInteger y_1, BigInteger x_2, BigInteger y_2) {

        BigInteger part1 = (multiplication(x_1, y_1)).add(multiplication(x_2, y_2));
        BigInteger part2 = (BigInteger.ONE).add(multiplication(multiplication( D, multiplication(x_1, x_2)), multiplication(y_1, y_2)));
        BigInteger part3 = (multiplication(y_1, y_2)).subtract(multiplication(x_1, x_2));
        BigInteger part4 = (BigInteger.ONE).subtract(multiplication(multiplication(D, multiplication(x_1, x_2)) , multiplication(y_1, y_2)));

        BigInteger x = part1.multiply(part2.modInverse(PRIME_P)).mod(PRIME_P); // division in modular arithmetic
        BigInteger y = part3.multiply(part4.modInverse(PRIME_P)).mod(PRIME_P);
        return new GoldilocksPair(x, y);
    }

    // G
}
