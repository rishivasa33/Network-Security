import java.math.BigInteger;
import java.util.InputMismatchException;
import java.util.Scanner;

public class RSAAlgorithm {

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            // 1. Choose two primes p and q (these are the input values).
            System.out.print("Enter the prime numbers, p and q: ");
            BigInteger p = scanner.nextBigInteger();
            BigInteger q = scanner.nextBigInteger();

            if (!checkIfPrime(p) || !checkIfPrime(q)) {
                System.out.println("Invalid Values of P and Q. Please enter a Prime Number.");
                System.exit(0);
            }

            // 2. Find their product n = pq
            BigInteger n = p.multiply(q);

            // Calculate (p-1) * (q-1)
            BigInteger productPQ = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // 3. Choose an integer e that is < n and relatively prime to (p-1)(q-1), that is, e and (p-1)(q-1) do not have common factors
            BigInteger e = getE(n, productPQ);

            // 4. Find an integer d such that ed mod (p-1)(q-1) = 1
            BigInteger d = getD(e, productPQ);

            // Display the public and private keys
            System.out.println("Calculating RSA values... ");
            System.out.println("Public RSA key (e, n) is (" + e + ", " + n + ")");
            System.out.println("Private RSA key (d, n) is (" + d + ", " + n + ")");

            System.out.print("Enter the plaintext message m (an integer): ");
            BigInteger message = scanner.nextBigInteger();

            // Encrypt the message
            BigInteger encryptedMessage = transformMessage(message, e, n);
            System.out.println("Encrypting m =  " + message);
            System.out.println("The ciphertext c = " + encryptedMessage);

            // Decrypt the message
            BigInteger decryptedMessage = transformMessage(encryptedMessage, d, n);
            System.out.println("Decrypting c = " + encryptedMessage);
            System.out.println("The plaintext m = " + decryptedMessage);

        } catch (InputMismatchException e) {
            System.out.println("Invalid Input! Enter a number only please");
        }
    }

    private static boolean checkIfPrime(BigInteger n) {
        if (n.compareTo(BigInteger.ONE) <= 0) {
            return false;
        }
        for (BigInteger i = BigInteger.TWO; i.compareTo(n) < 0; i = i.add(BigInteger.ONE)) {
            if (n.mod(i).equals(BigInteger.ZERO)) {
                return false;
            }
        }
        return true;
    }

    // 3. Choose an integer e that is < n and relatively prime to (p-1)(q-1), that is, e and (p-1)(q-1) do not have common factors
    // Reference for relatively prime numbers: https://www.baeldung.com/java-two-relatively-prime-numbers
    private static BigInteger getE(BigInteger n, BigInteger productPQ) {
        // Initialize e from 2. Ignore 0 and 1.
        BigInteger e = BigInteger.TWO;
        while (e.compareTo(n) < 0) {
            // Numbers are relatively prime if their GCD = 1
            if ((e.gcd(productPQ)).equals(BigInteger.ONE)) {
                return e;
            } else {
                e = e.add(BigInteger.ONE);
            }
        }
        // Should be unreachable and return -1 if by some exception it does reach here
        return BigInteger.valueOf(-1);
    }

    // 4. Find an integer d such that ed mod (p-1)(q-1) = 1
    private static BigInteger getD(BigInteger e, BigInteger productPQ) {
        BigInteger d = BigInteger.ONE;
        //Increment d till ed mod (p-1)(q-1) is != 1
        while (!e.multiply(d).mod(productPQ).equals(BigInteger.ONE)) {
            d = d.add(BigInteger.ONE);
        }
        return d;
    }

    // Encryption and Decryption formula is x = base^exponent % modulus, so I could use the same function to do both
    private static BigInteger transformMessage(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;

        // Calculate value of base^2 % modulus
        BigInteger baseSquaredModulus = base.multiply(base).mod(modulus);

        // Calculate how many times we need to multiply base^2 % modulus
        BigInteger multiplyCount = exponent.divide(BigInteger.TWO);

        // Keep ( multiplying base^2 % modulus ) and % with modulus for multiplyCount number of times
        while (multiplyCount.compareTo(BigInteger.ZERO) > 0) {
            result = result.multiply(baseSquaredModulus);
            result = result.mod(modulus);
            multiplyCount = multiplyCount.subtract(BigInteger.ONE);
        }

        // if the exponent value is odd, multiply the result once again with base % modulus
        if (exponent.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
            result = result.multiply(base.mod(modulus));
            result = result.mod(modulus);
        }

        // % the total result
        return result.mod(modulus);
    }
}