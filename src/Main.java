// main.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

// read a hex string, return byte length or -1 on error.
class Main {

    private static final Scanner scanner = new Scanner(System.in);
    private static final KMACXOF256 kmacxof256 = new KMACXOF256();
    private static final int DEFAULT_MODE = 256;
    private static final int NUMBER_OF_BYTES = 512;

    public static void main(String[] args) throws IOException {
        //run_tests();

        // parse mode flags
        Mode modeSelected = parseModFlags(args);
        String fin = null, fout = null, fpw = null; // file names
        byte[] pw = null, m = null;

//        if (args.length > 0 && args[0].charAt(0) != '-') { // not a valid flag.
//            System.out.printf("unknown command %s", args[0]);
//        } else if (args.length > 0) {
//            switch (args[0].toLowerCase().charAt(1)) {
//                case 'h' -> modeSelected = Mode.HASH;
//                case 't' -> modeSelected = Mode.TAG;
//                case 'e' -> modeSelected = Mode.ENCRYPT;
//                case 'd' -> modeSelected = Mode.DECRYPT;
//                case 'g' -> modeSelected = Mode.PUBLICKEY;
//                default -> System.out.printf("Unknown flag: %s\n", args[0]);
//            }
//        }

        // parse for input / output flags.
        for (int ptr = 1; ptr < args.length - 1; ptr++) {
            switch (args[ptr].toLowerCase()) {
                case "-fin" -> fin = args[ptr + 1];   // input from file.
                case "-fout" -> fout = args[ptr + 1]; // output to file.
                case "-fpw" -> fpw = args[ptr + 1]; // password as file.
                case "-pw" ->
                        pw = args[ptr + 1].getBytes(); // password as text.
            }
        }

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
            System.out.println("8. Generate a public key");
            System.out.println("9. Encrypt a private key");
            System.out.print("Enter your choice: ");

            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1 -> {//hashFile();
                    modeSelected = Mode.HASH;
                    fin = prompt("file input:");// collect filename for fin.
                }
                case 2 -> {
                    modeSelected = Mode.HASH;
                    // collect text from STDIN
                }
                case 3 -> {
                    modeSelected = Mode.TAG;
                    fin = prompt("file input:");
                }
                case 4 -> {
                    modeSelected = Mode.TAG;
                    // collect text from STDIN
                }
                //tagOfText();
                case 5 -> {
                    modeSelected = Mode.ENCRYPT;
                    fin = prompt("file input:");
                    pw = prompt("password:").getBytes();// collect pw
                }
                case 6 -> {
                    modeSelected = Mode.DECRYPT;
                    fin = prompt("file input:");
                    pw = prompt("password:").getBytes();// collect pw
                }
                case 7 -> {
                    System.out.println("Exiting Encryption");
                    System.exit(0);
                } case 8 -> {
                    modeSelected = Mode.PUBLICKEY;
                    pw = prompt("password").getBytes(); // collect pw
                }case 9 -> {
                    modeSelected = Mode.PRIVATEKEY;
                    pw = prompt("password").getBytes();
                }
                default ->
                        System.out.println("Invalid option. Please try again");
            }
        }

        // collect necessary data from files (fin, fpw)
        if (fpw != null && pw == null) // password file provided
            pw = readFile(fpw);
        else if (modeSelected != Mode.HASH && pw == null)
            pw = prompt("password:").getBytes(); // prompt for password if needed.
        if (fin != null) m = readFile(fin);
        else m = prompt("Input file data: ").getBytes();

        var out = switch (Objects.requireNonNull(modeSelected)) {
            case HASH ->
                    KMACXOF256.KMACXOF256("".getBytes(), m, 512, "D".getBytes());// hash(m);
            case TAG ->
                    KMACXOF256.KMACXOF256(pw, m, 512, "T".getBytes()); // tag(m, pw);
            case ENCRYPT -> KMACXOF256.symmetricEncrypt(m, pw);
            case DECRYPT -> KMACXOF256.symmetricDecrypt(m, pw);
            // returns public key's y coordinate.
            // TODO: Should x and y append together?
            // TODO: If public key is V = s * G, should public key be stored as byte[] or x coordinate of Goldilock
//            case PUBLICKEY -> EllipticCurve.generateKeyPair(pw).publicKey().y.toByteArray();
            case PUBLICKEY -> KMACXOF256.appendBytes(KMACXOF256.left_encode(EllipticCurve.generateKeyPair(pw).publicKey().x),
                                                    KMACXOF256.left_encode(EllipticCurve.generateKeyPair(pw).publicKey().y));
            // TODO: If private key is encrypted with passphrase,
        //          should it be encrypted with symmetricEncryption(byte[] m, byte[] pw) or
            //      be encrypted in ellipticCurve encryption(byte[] m, GoldilockPair)
            case PRIVATEKEY -> KMACXOF256.symmetricEncrypt(EllipticCurve.generateKeyPair(pw).privateKey().toByteArray(), pw);
        };

        // results/output has been gathered, put said results where requested.
        if (fout != null) {
            System.out.println("writing data to " + fout);
            // write out to fout.
            writeFile(fout, out);
        } else {
            if (modeSelected != Mode.DECRYPT)
                Sha3.phex(out); // not printable if it's binary data.
            else
                for (byte b : out) {
                    System.out.print((char) b);
                }
        }
    }

    /**
     * Helper function in the Main.
     *
     * @param args Commandline input.
     * @return Chosen mode by the user.
     */
    public static Mode parseModFlags(String[] args) {
        Mode modeSelected = null;
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
                default -> System.out.printf("Unknown flag: %s\n", args[0]);
            }
        }
        return modeSelected;
    }

    private static String prompt(String s) {
        System.out.print(s);
        return scanner.nextLine();
    }

    private static byte[] readFile(String filePath) throws IOException {
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
//    private static void hashFile() {
//        System.out.print("Enter the file path to hash: ");
//        String filePath = scanner.nextLine();
//        try {
//            byte[] fileData = Files.readAllBytes(Paths.get(filePath));
//            byte[] hash = kmacxof256.cSHAKE(DEFAULT_MODE, fileData, NUMBER_OF_BYTES, new byte[0], new byte[0]);
//            System.out.println("Hash: " + bytesToHex(hash));
//        } catch (IOException e) {
//            System.out.println("Error reading file: " + e.getMessage());
//        }
//    }

    //    private static void macOfFile() {
//        System.out.print("Enter the file path for MAC computation: ");
//        String filePath = scanner.nextLine();
//        System.out.print("Enter the passphrase: ");
//        String passphrase = scanner.nextLine();
//        try {
//            byte[] fileData = Files.readAllBytes(Paths.get(filePath));
//            byte[] mac = kmacxof256.cSHAKE(256, fileData, 512, passphrase.getBytes(), "MAC".getBytes());
//            System.out.println("MAC: " + bytesToHex(mac));
//        } catch (IOException e) {
//            System.out.println("Error reading file: " + e.getMessage());
//        }
//    }
    private static void writeFile(String fout, byte[] data) {
        try {
            Path filePath = Paths.get(fout);
            Files.write(filePath, data);
        } catch (IOException e) {
            System.out.println("Error writing file: " + e.getMessage());
        }
    }

    //    private static void decryptFile() {
//        System.out.print("Enter the encrypted file path to decrypt: ");
//        String filePath = scanner.nextLine();
//        System.out.print("Enter the passphrase: ");
//        String passphrase = scanner.nextLine();
//        try {
//            byte[] encryptedData = Files.readAllBytes(Paths.get(filePath));
//            // Assuming the encrypted file structure is: z || c || t
////            byte[] z = Arrays.copyOfRange(encryptedData, 0, 64); // first 512 bits
////            byte[] c = Arrays.copyOfRange(encryptedData, 64, encryptedData.length - 64); // middle portion
////            byte[] t = Arrays.copyOfRange(encryptedData, encryptedData.length - 64, encryptedData.length); // last 512 bits
//            byte[] decryptedData = KMACXOF256.symmetricDecrypt(encryptedData, passphrase.getBytes());
//            Path decryptedFilePath = Paths.get(filePath + ".decrypted");
//            Files.write(decryptedFilePath, decryptedData);
//            System.out.println("Decrypted file created: " + decryptedFilePath);
//        } catch (IOException e) {
//            System.out.println("Error decrypting file: " + e.getMessage());
//        } catch (IllegalArgumentException e) {
//            System.out.println("Decryption failed: " + e.getMessage());
//        }
//    }
    static int test_hexdigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        return -1;
    }
//    private static byte[] encrypt(byte[] fileData /* m */, byte[] passphrase) {
////        System.out.print("Enter the file path to encrypt: ");
////        String filePath = scanner.nextLine();
////        System.out.print("Enter the passphrase: ");
////        String passphrase = scanner.nextLine();
//            //byte[] fileData = Files.readAllBytes(Paths.get(filePath));
//            return KMACXOF256.symmetricEncrypt(fileData, passphrase);
//    }

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

    static int test_sha3() {
        // message / digest pairs, lifted from ShortMsgKAT_SHA3-xxx.txt files
        // in the official package: https://github.com/gvanas/KeccakCodePackage

        //const char *testvec[][2] = {
        String[][] testvec = {
                {   // SHA3-224, corner case with 0-length message
                        "",
                        "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7",
                },
                {   // SHA3-256, short message
                        "9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10",
                        "2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF"
                },
                {   // SHA3-384, exact block size
                        "E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486" +
                                "F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826D" +
                                "B923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A" +
                                "21691E1069413848",
                        "D1C0FA85C8D183BEFF99AD9D752B263E286B477F79F0710B0103170173978133" +
                                "44B99DAF3BB7B1BC5E8D722BAC85943A"
                },
                {   // SHA3-512, multiblock message
                        "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5" +
                                "623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A" +
                                "15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0" +
                                "A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764" +
                                "B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43" +
                                "C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D" +
                                "817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E08" +
                                "5172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1",
                        "6E8B8BD195BDD560689AF2348BDC74AB7CD05ED8B9A57711E9BE71E9726FDA45" +
                                "91FEE12205EDACAF82FFBBAF16DFF9E702A708862080166C2FF6BA379BC7FFC2"
                }
        };

        int i, fails, msg_len, sha_len;
        //uint8_t sha[ 64],buf[64], msg[256];
        var sha = new byte[64];
        var buf = new byte[64];
        var msg = new byte[256];

        fails = 0;
        for (i = 0; i < 4; i++) { // max 4
//            memset(sha, 0, sizeof(sha)); // arrays auto-initialized to 0 in java.
//            memset(buf, 0, sizeof(buf));
//            memset(msg, 0, sizeof(msg));

//            msg_len = test_readhex(msg, testvec[i][0], sizeof(msg));
//            sha_len = test_readhex(sha, testvec[i][1], sizeof(sha)); // sizeof == .length?
            msg_len = test_readhex(msg, testvec[i][0], msg.length);
            sha_len = test_readhex(sha, testvec[i][1], sha.length);
            Sha3.sha3(msg, msg_len, buf, sha_len);

            // checking if the first sha_len bytes of sha and buf are equal:
            if (memcmp(sha, buf, sha_len) != 0) {
                //fprintf(stderr, "[%d] SHA3-%d, len %d test FAILED.\n",
                System.out.printf(/*stderr, */"[%d] SHA3-%d, len %d test FAILED.\n",
                        i, sha_len * 8, msg_len);
                for (var b : sha)
                    System.out.printf("%02X", b);
                System.out.println();
                fails++;
            } else {
                System.out.print("+\n");
            }
        }

        return fails;
    }
    // returns zero on success, nonzero + stderr messages on failure

    static int test_shake() {
        // Test vectors have bytes 480..511 of XOF output for given inputs.
        // From http://csrc.nist.gov/groups/ST/toolkit/examples.html// aHashing

        //const char *testhex[4] = {
        String[] testhex = {
                // SHAKE128, message of length 0
                "43E41B45A653F2A5C4492C1ADD544512DDA2529833462B71A41A45BE97290B6F",
                // SHAKE256, message of length 0
                "AB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A",
                // SHAKE128, 1600-bit test pattern
                "44C9FB359FD56AC0A9A75A743CFF6862F17D7259AB075216C0699511643B6439",
                // SHAKE256, 1600-bit test pattern
                "6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB"
        };

        int i, j, fails;
//        sha3_ctx_t sha3;
//        uint8_t buf[ 32], ref[32];
        Sha3.sha3_ctx_t sha3 = new Sha3.sha3_ctx_t();
        byte[] buf = new byte[32];
        byte[] ref = new byte[32];

        fails = 0;

        for (i = 0; i < 4; i++) {
            if ((i & 1) == 0) {             // test each twice
                Sha3.shake128_init(sha3);
            } else {
                Sha3.shake256_init(sha3);
            }

            if (i >= 2) {                   // 1600-bit test pattern
                //memset(buf, 0xA3, 20);
                for (int x = 0; x < 20; x++) buf[x] = (byte) 0xA3;

                for (j = 0; j < 200; j += 20)
                    Sha3.sha3_update(sha3, buf, 20);
            }

            Sha3.shake_xof(sha3);               // switch to extensible output

            for (j = 0; j < 512; j += 32)   // output. discard bytes 0..479
                Sha3.shake_out(sha3, buf, 32);

            // compare to reference
            test_readhex(ref, testhex[i], ref.length);
            if (memcmp(buf, ref, 32) != 0) {
                System.out.printf(/*stderr,*/ "[%d] SHAKE%d, len %d test FAILED.\n",
                        i, (i & 1) == 1 ? 256 : 128, i >= 2 ? 1600 : 0);
                fails++;
            }
        }

        return fails;
    }

// test for SHAKE128 and SHAKE256

    /*
    // test speed of the comp

        static void test_speed() {
            int i;
            uint64_t st[ 25],x, n;
            clock_t bg, us;

            for (i = 0; i < 25; i++)
                st[i] = i;

            bg = clock();
            n = 0;
            do {
                for (i = 0; i < 100000; i++)
                    sha3_keccakf(st);
                n += i;
                us = clock() - bg;
            } while (us < 3 * CLOCKS_PER_SEC);

            x = 0;
            for (i = 0; i < 25; i++)
                x += st[i];

            printf("(%016lX) %.3f Keccak-p[1600,24] / Second.\n",
                    (unsigned long)x, (CLOCKS_PER_SEC * ((double) n)) / ((double) us));


        }*/
    // main
    public static void run_tests() {
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

    enum Mode {
        HASH, TAG, ENCRYPT, DECRYPT
        ,PUBLICKEY, PRIVATEKEY,
//        , ELLIPTIC_ENCRYPT, ELLIPTIC_DECRYPT,
//        SIGN, VERIFY
    }

}