import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class MainTest {
    @Test
    void test_sha3() {
        // message / digest pairs, lifted from ShortMsgKAT_SHA3-xxx.txt files
        // in the official package: https://github.com/gvanas/KeccakCodePackage

        //const char *testvec[][2] = {
        String[][] testvec = {{   // SHA3-224, corner case with 0-length message
                "", "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7",}, {   // SHA3-256, short message
                "9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10", "2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF"}, {   // SHA3-384, exact block size
                "E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486" + "F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826D" + "B923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A" + "21691E1069413848", "D1C0FA85C8D183BEFF99AD9D752B263E286B477F79F0710B0103170173978133" + "44B99DAF3BB7B1BC5E8D722BAC85943A"}, {   // SHA3-512, multiblock message
                "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5" + "623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A" + "15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0" + "A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764" + "B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43" + "C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D" + "817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E08" + "5172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1", "6E8B8BD195BDD560689AF2348BDC74AB7CD05ED8B9A57711E9BE71E9726FDA45" + "91FEE12205EDACAF82FFBBAF16DFF9E702A708862080166C2FF6BA379BC7FFC2"}};

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
            msg_len = Main.test_readhex(msg, testvec[i][0], msg.length);
            sha_len = Main.test_readhex(sha, testvec[i][1], sha.length);
            Sha3.sha3(msg, msg_len, buf, sha_len);

            // checking if the first sha_len bytes of sha and buf are equal:
            if (Main.memcmp(sha, buf, sha_len) != 0) {
                //fprintf(stderr, "[%d] SHA3-%d, len %d test FAILED.\n",
                System.out.printf(/*stderr, */"[%d] SHA3-%d, len %d test FAILED.\n", i, sha_len * 8, msg_len);
                for (var b : sha)
                    System.out.printf("%02X", b);
                System.out.println();
                fails++;
            } else {
                System.out.print("+\n");
            }
        }
        assert fails == 0;
        //return fails;
    }
    // returns zero on success, nonzero + stderr messages on failure

    @Test
    void test_shake() {
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
                "6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB"};

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
            Main.test_readhex(ref, testhex[i], ref.length);
            if (Main.memcmp(buf, ref, 32) != 0) {
                System.out.printf(/*stderr,*/ "[%d] SHAKE%d, len %d test FAILED.\n", i, (i & 1) == 1 ? 256 : 128, i >= 2 ? 1600 : 0);
                fails++;
            }
        }
        assert fails == 0;
        //return fails;
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
    @Test
    public void main_test_private_key_to_file() throws IOException {
        // BONUS: Encrypt the private key from that pair under the given
        // password and write it to a different file as well.
        var fn = "test/test_priv.pr";
        var pw = "lorem ipsem";

        Main.main(new String[]{
                "-q", "-pw", pw, "-fout", fn}
        );
        var F = Main.readFile(fn);
        var keypair = EllipticCurve.generateKeyPair(pw.getBytes());
        assert Arrays.equals(
                keypair.privateKey().toByteArray(),
                KMACXOF256.symmetricDecrypt(F, pw.getBytes()));
    }

    @Test
    public void main_test_elliptic_enc_data_file() throws IOException {
        // Encrypt a data file under a given elliptic public key file and
        // write the ciphertext to a file.
        var pw = "lorem ipsem";
        var fn = "test/test_ciphertext.txt";
        var fpub = "test/fpub.pu";
        var fpriv = "test/fpriv.pr";

        Main.main(new String[] { // gen pub key
                "-p", "-pw", pw, "-fout", fpub
        });
        Main.main(new String[] { // gen priv key
                "-q", "-pw", pw, "-fout", fpriv
        });

        Main.main(new String[]{ // encrypt with public key
                "-i", "-fin", "README.md", "-fpub", fpub, "-fout", fn}
        );

        // read ciphertext out, and decrypt to verify
        var A = EllipticCurve.decrypt(Main.readFile("test/scratch.txt"), pw.getBytes());
        var B = Main.readFile("README.md");
        assert Arrays.equals(A, B);
    }

    @Test
    public void main_test_elliptic_enc_user_text_to_file() {
        // BONUS: Encrypt text input by the user directly to the app instead of
        // having to read it from a file (but write the ciphertext to a file).

    }

    @Test
    public void main_test_decrypt_elliptic_enc_file() {
        // Decrypt a given elliptic-encrypted file from a given password and
        // write the decrypted data to a file.

    }

    @Test
    public void main_test_sign_file_sig_to_file() {
        // Sign a given file from a given password and
        // write the signature to a file.

    }

    @Test
    public void main_test_sign_input_sig_to_file() {
        // BONUS: Sign text input by the user directly to the app instead of
        // having to read it from a file (but write the signature to a file).

    }

    @Test
    public void main_test_verify_data_file_sig_pubkey_from_files() {
        // Verify a given data file and its signature file under a given public key file.

    }

    @Test
    public void main_test_verify_input_sig_from_file() {
        // BONUS: Verify text input by the user directly to the app instead of
        // having to read it from a file (but read the signature from a file).

    }
}
