package cryptographyJava.HashSecure;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * Argon2i is a secure password-hashing algorithm.
 * Argon2 has three major variants:
 * Argon2i, Argon2d and Argon2id.
 * <p>
 * Argon2d is faster and uses data-depending memory access,
 * which makes it highly resistant against CPU cracking attacks and suitable for applications with
 * no threat from side-channel timing attacks (e.g. cryptocurrencies)
 * <p>
 * Argon2i instead uses data-independent memory access, which is preferred for password hashing and password-
 * based key derivation, but it is slower as it makes more passes over the memory to protect from tradeoff attacks.
 * <p>
 * Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and data-independent memory-
 * accesses, which gives some fo Argon2i´s resistance to side-channel cache timing attacks and much of Argon2d´s
 * resistance to GPU cracking attacks.
 * <p>
 * Argon2i, Argon2d and Argon2id are parametrized by:
 * <p>
 * A time cost, which defines the amount of computation realzed and therefore the execution time, given in number of iterations
 * A memory cost, which defines the memory usage, given in kibibytes
 * A parallelism degree, which defines the number of parallel threads
 */
public class Argon2iHashSecure {

    /* !!!!!IMPORTANT!!!!! - Parameter Guide

            1.  Figure out the maximum number "THREAD_COUNT" of threads that can be initiated
                by each call to Argon2.

            2.  Figure out the maximum amount "MEMORY_PER_CALL_IN_KILOBYTES" of memory that each call can afford.

                Recommended Memory:
                        *   Key derivation for hard-drive encryption: 6gb RAM
                        *   Frontend server authentication: 1gb RAM

            3.  Figure out the maximum amount x of time (in seconds) that each call can afford.

                Recommended Time:
                        *   Key derivation for hard-drive encryption, that takes 3 seconds on a 2GHz CPU
                            using 2 core - Argon2i with 10 Iterations and 6GB of RAM

                        *   Frontend server authentication, that takes 0.5 seconds on a 2GHz CPU using 2
                            cores - Argon2i with 10 Iterations and 1GB of RAM

            4.  Select the salt length, 128 bits is sufficient for most applications.

            5.  Select the tag length, 128 Bits is sufficient for most applications, including key derivation.
                If longer keys are needed, select longer tags.

            6.  Run with "MEMORY_PER_CALL_IN_KILOBYTES" memory and "THREAD_COUNT" threads, using
                different number of Iterations "ITERATIONS_PER_CALL" (minimum = 10). Figure out the maximum
                "ITERATIONS_PER_CALL" such that the running time does not exceed x. If it exceeds x (time) even for
                "ITERATIONS_PER_CALL" = 10, reduce memory "MEMORY_PER_CALL_IN_KILOBYTES" accordingly.

            7.  Hash all the passwords with the just determined values "MEMORY_PER_CALL_IN_KILOBYTES", "THREAD_COUNT" and
                "ITERATIONS_PER_CALL".

     */

    static final int SALT_LENGTH = 16;
    static final int PEPPER_LENGTH = 16;
    static final int HASH_LENGTH = 128;
    static final int ITERATIONS_PER_CALL = 10;
    static final int MEMORY_PER_CALL_IN_KILOBYTES = 1024000;
    static final int THREAD_COUNT = 4;

    /**
     * Hash a given String using argon2i
     *
     * @param plainText plainText to be hashed
     * @return Argon2i Hash of plainText
     */
    public static String hash(String plainText) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder();

        //Salt and Pepper Length of 16 Bytes is sufficient for most applications
        byte[] salt = new byte[SALT_LENGTH];
        byte[] pepper = new byte[PEPPER_LENGTH];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        SecureRandom.getInstanceStrong().nextBytes(pepper);

        //Choose a hash length - for security reason choose 128 for plainText hashing (can be lowered to 16 for non-secure applications)
        byte[] hash = new byte[HASH_LENGTH];

        //Iterations MUST be at least 10 for Argon2i due to a practical tradeoff attack --> https://eprint.iacr.org/2016/759.pdf
        //Set the number of Iterations each call --> More Iterations = Better Security + more Hashing Time --> Set as high as tolerable
        //For other Argon2 Versions > 3 Iterations recommended, Argon2i > 10 Iterations recommended
        builder.withIterations(ITERATIONS_PER_CALL);

        //Figure out how much memory each call can afford (memory_cost).
        //The RFC recommends 6 GB for backend authentication and 1 GB for frontend authentication.
        //The APIs uses Kibibytes (1024 bytes) as base unit.
        builder.withMemoryAsKB(MEMORY_PER_CALL_IN_KILOBYTES);

        //Choose the Number of CPU-Threads you can afford each call (2 Cores = 4 Threads)
        builder.withParallelism(THREAD_COUNT);

        //Choose a "salt" which can be stored non-secure or with the plainText Hash
        builder.withSalt(salt);

        //Choose a Secret "pepper" which has to be stored in a different secure location from the hashes
        builder.withSecret(pepper);

        //Choose whether you want  Argon2d: 0, Argon2i: 1, Argon2id: 2, Argon2_version_10: 16, Argon2_version_13: 19
        //Argon2i is recommended for plainText Hashing
        builder.withVersion(Argon2Version.ARGON2_I.getIdentifier());

        Argon2Parameters parameters = builder.build();
        generator.init(parameters);
        generator.generateBytes(plainText.toCharArray(), hash);
        return Base64.getEncoder().encodeToString(hash);
    }

    enum Argon2Version {
        ARGON_2D(0), ARGON2_I(1), ARGON2_ID(2), ARGON2_VERSION_10(16), ARGON2_VERSION_13(19);
        int argon2Version;

        Argon2Version(int argon2Version) {
            this.argon2Version = argon2Version;
        }

        public int getIdentifier() {
            return this.argon2Version;
        }
    }
}
