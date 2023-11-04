// main.c
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

// include <stdio.h>
        // include <string.h>
        // include <time.h>
        // include "sha3.h"

import java.security.SecureRandom;
import java.util.Arrays;
import static java.util.Arrays.compare;

// read a hex string, return byte length or -1 on error.
class Main {
    // main
    public static void main(String args[]) {
        if (Sha3_tests.test_sha3() == 0 && Sha3_tests.test_shake() == 0)
            System.out.printf("FIPS 202 / SHA3, SHAKE128, SHAKE256 Self-Tests OK!\n");
        //test_speed();

        //return 0;

//        System.out.println("test_left_encode:");
//        System.out.println(KMACXOF256_tests.test_left_encode());
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
/*
        //////////////////////////////////////////////////////
        // requirements:
        var emptystr = new byte[]{};
        var m = "sample message".getBytes();
        var pw = "password".getBytes();
        //------
//Computing a cryptographic hash h of a byte array m:
//▪ h <- KMACXOF256(“”, m, 512, “D”)
        var h = KMACXOF256.KMACXOF256("".getBytes(), m, 512, "D".getBytes());
        System.out.print("Hash:"); Sha3.phex(h);
        //-----
//• Compute an authentication tag t of a byte array m under passphrase pw:
//▪ t <- KMACXOF256(pw, m, 512, “T”)
        var t = KMACXOF256.KMACXOF256(pw, m, 512, "T".getBytes());
        System.out.print("Tag:");Sha3.phex(t);
        //------

//• Encrypting a byte array m symmetrically under passphrase pw:
//▪ z <- Random(512)
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
                    KMACXOF256.KMACXOF256(ke, emptystr, m.length, "SKE".getBytes()), m);

//▪ t <- KMACXOF256(ka, m, 512, “SKA”)
        t =  KMACXOF256.KMACXOF256(ka, m, 512, "SKA".getBytes());
//▪ symmetric cryptogram: (z, c, t)
        // return cryptogram? what format is (z, c, t)? z || c || t .
        System.out.printf("cryptogram:"); Sha3.phex(KMACXOF256.appendBytes(z, c, t));
//---------

//• Decrypting a symmetric cryptogram (z, c, t) under passphrase pw:
        // acquire z || c || t from file.
//▪ (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        kz = KMACXOF256.KMACXOF256(
                KMACXOF256.appendBytes(z, pw),
                emptystr,
                1024,
                "S".getBytes());
        // split (ke || ka) <- kz
        ke = Arrays.copyOfRange(kz, 0, kz.length/2);
        ka = Arrays.copyOfRange(kz, kz.length/2, kz.length);
//▪ m <- KMACXOF256(ke, “”, |c|, “SKE”)  c
        m = KMACXOF256.xor(
                KMACXOF256.KMACXOF256(ke, emptystr, c.length, "SKE".getBytes()),
                c);
//▪ t_prime <- KMACXOF256(ka, m, 512, “SKA”)
        var t_prime = KMACXOF256.KMACXOF256(ka, m, 512, "SKA".getBytes());
//▪ accept if, and only if, t_prime == t
        if (compare(t, t_prime) == 0) {
            //return decypted plaintext.
            System.out.printf("Message recieved: %s", t);
        } else {
            System.out.println("Mismatch. Incorrect password.");
            // throw exception/error that password is incorrect.
        }
    */
    }

}