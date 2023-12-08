// main.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

// read a hex string, return byte length or -1 on error.
class Main {
    private static final Scanner scanner = new Scanner(System.in);
    enum Mode {
        HASH,TAG, ENCRYPT, DECRYPT, PUBLICKEY, PRIVATEKEY,
        ELLIPTIC_ENCRYPT, ELLIPTIC_DECRYPT, SIGN, VERIFY
    }
    private static final String INPUT_PROMPT = "file input:";
    /**
     * public key is only accepted as a file.
     * private key is only stored in a file.
     */
    private static String fin = null, fout = null, fpw = null, fpriv = null,fpub = null, fsig = null;
    // TODO: fpub may not be used due to its bugginess = public key,
    //  s = signature
    private static byte[] pw = null, m = null, pub = null, priv = null;
    private static String fin = null, fout = null, fpw = null, fpub = null, fsig = null;

    private static byte[] pw = null, m = null, pub = null;
    public static void main(String[] args) throws IOException {
        //run_tests();

        // parse mode flags
        Mode modeSelected = parseModFlags(args);
        parseInputOutputFlags(args);
        handleUserInteraction(modeSelected);
        outputResults(modeSelected,  performOperationBasedOnMode(modeSelected));
    }

    /**
     * Helper function in the Main.
     *
     * @param args Commandline input.
     * @return Chosen mode by the user.
     */
    public static Mode parseModFlags(String[] args) {
        Mode modeSelected = null; // TODO: returns null when no mode indicated?
        if (args.length > 0 && args[0].charAt(0) != '-') { // not a valid flag.
            System.out.printf("unknown command %s", args[0]);
        } else if (args.length > 0) {
            switch (args[0].toLowerCase().charAt(1)) {
                case 'h' -> modeSelected = Mode.HASH;
                case 't' -> modeSelected = Mode.TAG;
                case 'e' -> modeSelected = Mode.ENCRYPT;
                case 'd' -> modeSelected = Mode.DECRYPT;
                case 'p' -> modeSelected = Mode.PUBLICKEY;
                case 'q' -> modeSelected = Mode.PRIVATEKEY;
                case 'i' -> modeSelected = Mode.ELLIPTIC_ENCRYPT;
                case 'k' -> modeSelected = Mode.ELLIPTIC_DECRYPT;
                case 's' -> modeSelected = Mode.SIGN;
                case 'v' -> modeSelected = Mode.VERIFY;
                default -> System.out.printf("Unknown flag: %s\n", args[0]);
            }
        }
        return modeSelected;
    }

    private static void parseInputOutputFlags(String[] args) {
        for (int ptr = 1; ptr < args.length - 1; ptr++) {
            switch (args[ptr].toLowerCase()) {
                // inputs
                case "-fin" -> fin = args[ptr + 1]; // plaintext or ciphertext input from file.
                case "-fpw" -> fpw = args[ptr + 1]; // password as file.
                case "-pw" -> pw = args[ptr + 1].getBytes(); // password as text.

                case "-fpub" -> fpub = args[ptr + 1]; // public key as file.
                case "-fpriv" -> fpriv = args[ptr + 1]; // private key as file.
                case "-fsig" -> fsig = args[ptr + 1]; // signature as a file.

                // file location for output
                case "-fout" -> fout = args[ptr + 1]; // output to file.
            }
        }
    }

    private static void handleUserInteraction(Mode modeSelected) {
        // if no commandline mode given, present menus:
        while (modeSelected == null) {
            System.out.println("Welcome to the encryption");
            System.out.println("\nPlease choose a number below:");
            System.out.println("1. Compute a cryptographic hash of a file");
            System.out.println("2. Compute a cryptographic hash of text");
            System.out.println("3. Compute an authentication tag of a file");
            System.out.println("4. Compute an authentication tag of a text");
            System.out.println("5. Encrypt a data file");
            System.out.println("6. Decrypt a symmetric cryptogram");
            System.out.println("7. Exit");
            System.out.println("8. Generate a public key of a file");
            System.out.println("9. Encrypt a private key");
            System.out.println("10. Encrypt a data file in asymmetric way");
            System.out.println("11. Decrypt an asymmetric cyrptogram");
            System.out.println("12. Generate a public key of a text");
            System.out.println("13. Generate a signature file");
            System.out.println("14. Verify a signature");
            System.out.print("Enter your choice: ");

            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1 -> {//hashFile();
                    modeSelected = Mode.HASH;
                    fin = prompt(INPUT_PROMPT);// collect filename for fin.
                }
                case 2 -> {
                    modeSelected = Mode.HASH;
                    // collect text from STDIN
                }
                case 3 -> {
                    modeSelected = Mode.TAG;
                    fin = prompt(INPUT_PROMPT);
                }
                case 4 -> {
                    modeSelected = Mode.TAG;
                    // collect text from STDIN
                }
                case 5 -> {
                    modeSelected = Mode.ENCRYPT;
                    fin = prompt(INPUT_PROMPT);

                    pw = prompt("password:").getBytes();// collect pw
                }
                case 6 -> {
                    modeSelected = Mode.DECRYPT;
                    fin = prompt(INPUT_PROMPT);

                    pw = prompt("password:").getBytes();// collect pw
                }
                case 7 -> {
                    System.out.println("Exiting Encryption");
                    System.exit(0);
                }
                case 8 -> {
                    modeSelected = Mode.PUBLICKEY;
                    pw = prompt("password").getBytes(); // prompt for password
                }
                case 9 -> {
                    modeSelected = Mode.PRIVATEKEY;
                    pw = prompt("password").getBytes();
                }
                case 10 -> {
                    modeSelected = Mode.ELLIPTIC_ENCRYPT;
                    fin = prompt(INPUT_PROMPT);
                    fpub = prompt("public key input: "); // collect public key file
                }
                case 11 -> {
                    modeSelected = Mode.ELLIPTIC_DECRYPT;
                    fin = prompt(INPUT_PROMPT);
                    pw = prompt("password").getBytes();
                }
                case 12 -> {
                    modeSelected = Mode.PUBLICKEY;
                    // Enter public key via STDIN
                }
                case 13 -> {
                    modeSelected = Mode.SIGN;
                    fin = prompt(INPUT_PROMPT);
                    pw = prompt("password").getBytes();
                }
                case 14 -> {
                    modeSelected = Mode.VERIFY;
                    fin = prompt(INPUT_PROMPT);
                    fsig = prompt("signature file");
                    fpub = prompt("public key input: ");
                }
                default ->
                        System.out.println("Invalid option. Please try again");
            }
        }
    }
    /**
     * Following flags from above should not be used:
     * fin , fout , fpw , fpub
     * Only pw (password), m (message), p (public key), s (signature) should be used.
     *
     * @param modeSelected
     * @return
     * @throws IOException
     */
    private static byte[] performOperationBasedOnMode(Mode modeSelected) throws IOException {
        // handle common preconditions

        // input from file (m is required for all but assymetric keygen)
        if (fin != null) m = readFile(fin);
        // require m ?
        if(m == null) {
            switch (modeSelected) {
                case HASH, TAG, ENCRYPT, ELLIPTIC_ENCRYPT, SIGN:
                    while(m == null)
                        m = prompt("Input file data: ").getBytes();
                    break;
                case PUBLICKEY, PRIVATEKEY: // m not required for keygen.
                    break;
                default: // file(-fin) required for DECRYPT, ELLIPTIC_DECRYPT, VERIFY
                    throw new IllegalArgumentException("Missing required input data, -fin");
            }
        }

        if (fpw != null) pw = readFile(fpw); // password file provided
        if(pw == null) { // password required.
            switch (modeSelected) {
                case HASH:
                    break;
                case ELLIPTIC_ENCRYPT:
                    if(fpub != null) // if we have a public key, we don't need pw
                        break;
                default:
                    while(pw == null) {
                        pw = prompt("Input password: ").getBytes();
                    }
                    assignKeys(pw);
            }
        }
        if (!isSymmetricOperation(modeSelected)) {
            handleAsymmetricPreconditions(modeSelected);
        }


        return switch (Objects.requireNonNull(modeSelected)) {
            case HASH ->
                    KMACXOF256.KMACXOF256("".getBytes(), m, 512, "D".getBytes());// hash(m);
            case TAG ->
                    KMACXOF256.KMACXOF256(pw, m, 512, "T".getBytes()); // tag(m, pw);
            case ENCRYPT -> KMACXOF256.symmetricEncrypt(m, pw);
            case DECRYPT -> KMACXOF256.symmetricDecrypt(m, pw);
            case PUBLICKEY -> {
                try {
                    yield EllipticCurve.generateKeyPair(pw).encodedPublicKey();
                } catch (Exception e) {
                    throw new RuntimeException("Error generating public key: " + e.getMessage(), e);
                }
            }
//                    KMACXOF256.appendBytes(KMACXOF256.left_encode(EllipticCurve.generateKeyPair(pw).publicKey().x),

            // TODO: If private key is encrypted with passphrase,
            //          should it be encrypted with symmetricEncryption(byte[] m, byte[] pw) or
            //      be encrypted in ellipticCurve encryption(byte[] m, GoldilockPair)
            // private key <- password
            case PRIVATEKEY -> KMACXOF256.symmetricEncrypt(EllipticCurve.generateKeyPair(pw).privateKey().toByteArray(), pw);

            case ELLIPTIC_ENCRYPT -> EllipticCurve.encrypt(m, EllipticCurve.publicKeyToGPoint(fpub));
            case ELLIPTIC_DECRYPT -> EllipticCurve.decrypt(m, pw);
            case SIGN -> EllipticCurve.generateSignature(m, pw);
            case VERIFY -> {
                boolean isVerified = (EllipticCurve.verifySignature(EllipticCurve.fileToSignature(fsig),
                                        EllipticCurve.publicKeyToGPoint(fpub), m));
                String result = isVerified ? "Signature is verified" : "Signature has been tampered";
                yield result.getBytes();
            }
            default -> throw new IllegalArgumentException("Unsupported encryption mode: " + modeSelected);
        };
    }

    private static boolean isSymmetricOperation(Mode mode) {
        return mode == Mode.ENCRYPT || mode == Mode.DECRYPT
                || mode == Mode.HASH || mode == Mode.TAG;
    }

//    /**
//     * Symmetric Encryption performs: hash, tag, encrypt, decrypt
//     *
//     * @param modeSelected
//     * @throws IOException
//     */
//    private static void handleSymmetricPreconditions(Mode modeSelected) throws IOException {
//        if (modeSelected != Mode.HASH && pw == null)
//            pw = prompt("password: ").getBytes(); // prompt for password if needed.
//
//        if(m == null)
//            m = prompt("Input file data: ").getBytes();
//    }
    private static void assignKeys(byte[] pw) {
        // password known, gen key pair
        var keypair = EllipticCurve.generateKeyPair(pw);
        priv = keypair.privateKey().toByteArray();
        pub = keypair.encodedPublicKey();
    }
    /**
     * Asymmetric encryption performs elliptic_encrypt, elliptic_decrypt,
     * verify signature, sign a file, write private key
     *
     * Values from these flags are assigned to byte[]
     * fin
     * fpw -> pw
     * fpub -> pub
     */
    private static void handleAsymmetricPreconditions(Mode mode) throws IOException {
        // asymmetric requires a password, or a key

        if (fpub != null) pub = readFile(fpub); // public key provided
        if(pw != null) assignKeys(pw);
        // private key provided
        if (fpriv != null) priv = KMACXOF256.symmetricDecrypt(readFile(fpriv), pw);

        switch (mode) {
            case PUBLICKEY : // public and private key require a password
            case PRIVATEKEY : {
                break;
            }
            case ELLIPTIC_ENCRYPT: {
                // requires data, public key (file only)
                while(m == null) m = prompt("Input file data: ").getBytes();
                break;
            }

            case SIGN:
            case ELLIPTIC_DECRYPT : {
                // Decryption requires file & password
                // read password
                while (pw == null) {
                    pw = prompt("password: ").getBytes();
                }
                assignKeys(pw);

                // reads file
                if (fin != null) {
                    m = readFile(fin);
                } else { m = prompt("Input file data: ").getBytes(); }

                break;
            }
            case VERIFY: {
                // read signature
//                if (fsig != null && sig == null) sig = readFile(fsig);
//                else if (sig == null) {
//                    sig = prompt
//                }
                //read file
//                if (fin != null) { m = readFile(fin);
//                } else { m = prompt(INPUT_PROMPT).getBytes(); }

                // reads public file in side the other case.
            }
        }
    }

    private static void outputResults(Mode modeSelected, byte[] out) {
        // results/output has been gathered, put said results where requested.
        if (fout != null) {
            System.out.println("writing data to " + fout);
            // write out to fout.
            writeFile(fout, out);
            return;
        }
        if (modeSelected == Mode.VERIFY) {
            System.out.println(new String(out));
        } else if (modeSelected != Mode.DECRYPT && modeSelected != Mode.ELLIPTIC_DECRYPT)
            Sha3.phex(out); // not printable if it's binary data.
        else
            for (byte b : out) {
                System.out.print((char) b);
            }
    }

    private static String prompt(String s) {
        System.out.print(s);
        return scanner.nextLine();
    }

    public static byte[] readFile(String filePath) throws IOException {
        try {
            System.out.println("Reading data from file: " + filePath);
            return Files.readAllBytes(Paths.get(filePath));
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
            throw e;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void writeFile(String fout, byte[] data) {
        try {
            Path filePath = Paths.get(fout);
            Files.write(filePath, data);
        } catch (IOException e) {
            System.out.println("Error writing file: " + e.getMessage());
        }
    }

    static int test_hexdigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        return -1;
    }

    static int test_readhex(byte[] buf, String str, int maxbytes) {
        int i, h, l;
        for (i = 0; i < str.length() / 2; i++) {
            h = test_hexdigit(str.charAt(2 * i));
            if (h < 0)
                return i;
            l = test_hexdigit(str.charAt(2 * i + 1));
            if (l < 0)
                return i;
            buf[i] = (byte) ((h << 4) + l);
        }
        return i;
    }

    static int memcmp(byte[] sha, byte[] buf, int sha_len) {
        // TODO: Arrays.compare(sha, 0, sha_len, buf,0, sha_len) ?
        // checking if the first sha_len bytes of sha and buf are equal:
        var eq = true;
        for (int j = 0; j < sha_len; j++) {
            if (sha[j] != buf[j]) {
                eq = false;
                break;
            }
        }
        return eq ? 0 : -1;
    }



    // main
    public static void run_tests() throws IOException {
        if (Sha3_tests.test_sha3() == 0 && Sha3_tests.test_shake() == 0)
            System.out.print("FIPS 202 / SHA3, SHAKE128, SHAKE256 Self-Tests OK!\n");
        //test_speed();

        System.out.printf("sha3 words test: %s\n", Sha3_tests.words_test());
        // Collect plaintext bytes from whatever source necessary.
//        var res =
//                KMACXOF256.KMACXOF256( // NIST sample #1
//                        "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_".getBytes(), // K
//                        new byte[]{0,1,2,3},
//                512,
//                "".getBytes());
        //Sha3.phex(res);
        //Sha3.phex(KMACXOF256.left_encode(0xA8));
        System.out.printf("cSHAKE256 #3: %s\n", KMACXOF256_tests.cSHAKE256_test_Sample3());
        System.out.printf("cSHAKE256 #4: %s\n", KMACXOF256_tests.cSHAKE256_test_Sample4());

        //////////////////////////////////////////////////////
        // requirements:
        var emptystr = new byte[]{};
        var m = "sample message".getBytes();
        var pw = "password".getBytes();
        //------
//Computing a cryptographic hash h of a byte array m:
//▪ h <- KMACXOF256(“”, m, 512, “D”)
        var h = KMACXOF256.KMACXOF256("".getBytes(), m, 512, "D".getBytes());
        System.out.print("Hash:");
        Sha3.phex(h);
        //-----
//• Compute an authentication tag t of a byte array m under passphrase pw:
//▪ t <- KMACXOF256(pw, m, 512, “T”)
        var t = KMACXOF256.KMACXOF256(pw, m, 512, "T".getBytes());
        System.out.print("Tag:");
        Sha3.phex(t);
        //------

//• Encrypting a byte array m symmetrically under passphrase pw:
//▪ z <- Random(512)
        /*
        var z = new byte[64]; // 64B = 512b
        new SecureRandom().nextBytes(z);
        //▪ (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] ke, ka;
        var kz = KMACXOF256.KMACXOF256(
                KMACXOF256.appendBytes(z, pw),
                emptystr,
                1024,
                "S".getBytes());
        // split (ke || ka) <- kz
        ke = Arrays.copyOfRange(kz, 0, kz.length/2);
        ka = Arrays.copyOfRange(kz, kz.length/2, kz.length);
        //▪ c <- KMACXOF256(ke, “”, |m|, “SKE”) xor m
        var c = KMACXOF256.xor(
                    KMACXOF256.KMACXOF256(ke, emptystr, m.length*8, "SKE".getBytes()), m);

        //▪ t <- KMACXOF256(ka, m, 512, “SKA”)
        t =  KMACXOF256.KMACXOF256(ka, m, 512, "SKA".getBytes());
        //▪ symmetric cryptogram: (z, c, t)
        // return cryptogram? what format is (z, c, t)? z || c || t .
        System.out.printf("cryptogram:"); Sha3.phex(KMACXOF256.appendBytes(z, c, t));
         */
        var zct = KMACXOF256.symmetricEncrypt(m, pw);
//---------

//• Decrypting a symmetric cryptogram (z, c, t) under passphrase pw:
        var decrypted = KMACXOF256.symmetricDecrypt(zct, pw);
        for (byte b : decrypted)
            System.out.printf("%c", b);
        System.out.println();
        System.out.printf("Decryption test: %s\n", Arrays.equals(decrypted, m));
        // acquire z || c || t from file.
//        var z = Arrays.copyOfRange(zct, 0, 64);
//        var c = Arrays.copyOfRange(zct, 64, zct.length - 64);
//        t = Arrays.copyOfRange(zct, zct.length - 64, zct.length);
////▪ (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
//        var kz = KMACXOF256.KMACXOF256(
//                KMACXOF256.appendBytes(z, pw),
//                emptystr,
//                1024,
//                "S".getBytes());
//        // split (ke || ka) <- kz
//        var ke = Arrays.copyOfRange(kz, 0, kz.length/2);
//        var ka = Arrays.copyOfRange(kz, kz.length/2, kz.length);
////▪ m <- KMACXOF256(ke, “”, |c|, “SKE”)  c
//        m = KMACXOF256.xor(
//                KMACXOF256.KMACXOF256(ke, emptystr, c.length*8, "SKE".getBytes()),
//                c);
////▪ t_prime <- KMACXOF256(ka, m, 512, “SKA”)
//        var t_prime = KMACXOF256.KMACXOF256(ka, m, 512, "SKA".getBytes());
////▪ accept if, and only if, t_prime == t
//        if (compare(t, t_prime) == 0) {
//            //return decypted plaintext.
//            System.out.print("Message recieved:");
//            for(byte b : m) System.out.printf("%c", b);
//            System.out.println();
//        } else {
//            System.out.println("Mismatch. Incorrect password.");
//            // throw exception/error that password is incorrect.
//        }

    }
}