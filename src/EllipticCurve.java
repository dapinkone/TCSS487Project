import java.math.BigInteger;
import java.util.function.Predicate;

public class EllipticCurve {

    // data structure to represent goldilocks pair (x, y)
    // Edwards curve equation = x^2 + y^2 = 1 +dx^2y^2 with d = -39081

    // modular arithmetic addition example:
    //

    private final static BigInteger D = new BigInteger("-39081");
    private final static BigInteger two = new BigInteger("2");

    private final static BigInteger PRIME_P = ((two.pow(448)).subtract(two.pow(224))).subtract(BigInteger.ONE);

    public class GoldilocksPair {

        // constructor of neutral element
        private BigInteger x;
        private BigInteger y;



        // Constructor of GoldilocksPair
        //
        public GoldilocksPair(BigInteger x, BigInteger y) {

            BigInteger NegThree = new BigInteger("-3");
            // public generator G = (x_0, y_0)
            // x = -3(mod p)

            this.x = x;
            this.y = y;
        }


        /**
         * Neutral element has a point of (0, 1)
         */
        public class NeutralElement {

        }

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
    private BigInteger multiplication (BigInteger one, BigInteger two) {
        return one.multiply(two).mod(PRIME_P);
    }

    /**
     * TODO: Refactoring the parameter to accept two goldilockspair points
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
