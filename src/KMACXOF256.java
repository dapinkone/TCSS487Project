import java.nio.ByteBuffer;

public class KMACXOF256 {
    // basic operations & functions from FIPS 202
    public static byte enc8(byte b) {
        int result = 0;
        for(int i = 0; i < 8; i++) {
            result = ((result << 1) | b & 1);
            b >>= 1;
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
    // X xor Y for strings of arbitrary but equal bit length.
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
}
