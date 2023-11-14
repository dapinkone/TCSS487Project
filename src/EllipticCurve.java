import java.math.BigInteger;

public class EllipticCurve {

    // data structure to represent goldilocks pair (x, y)
    // Edwards curve equation = x^2 + y^2 = 1 +dx^2y^2 with d = -39081

    // modular arithmetic addition example:
    //

    public class GoldilocksPair {

        // constructor of neutral element
        private BigInteger x;
        private BigInteger y;

        private final static BigInteger two = new BigInteger("2");

        private final static BigInteger PRIME_P = ((two.pow(448)).subtract(two.pow(224))).subtract(BigInteger.ONE);

        // Constructor of GoldilocksPair
        //
        public GoldilocksPair(BigInteger x, BigInteger y) {

            BigInteger NegThree = new BigInteger("-3");
            // public generator G = (x_0, y_0)
            // x = -3(mod p)
            BigInteger x_zero = NegThree.mod(PRIME_P);
            // y_0 is a even number
            BigInteger y_zero = new BigInteger("0");

        }

        public neutralElement() {

        }

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
    int modularAddition(int n, int value) {
        int result = 0;
        result = value % n;
        return result;
    }

    // G
}
