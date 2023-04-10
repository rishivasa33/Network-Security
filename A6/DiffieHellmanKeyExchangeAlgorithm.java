import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class DiffieHellmanKeyExchangeAlgorithm {

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {

            //Alice broadcasts two numbers p and g to Bob
            System.out.print("Enter the value of p: ");
            BigInteger p = scanner.nextBigInteger();
            System.out.print("Enter the value of g: ");
            BigInteger g = scanner.nextBigInteger();


            //Alice picks a secret number SA
            //Bob picks a secret number SB
            //Reference: https://www.freecodecamp.org/news/generate-random-numbers-java/
            System.out.println("Generating Random integers SA (for Alice) and SB (for Bob)... ");
            Random random = new Random();

            int SA = random.nextInt(2, 1000);
            int SB = random.nextInt(2, 1000);

            System.out.println("SA: " + SA);
            System.out.println("SB: " + SB);

            //Alice computes TA = g^SA mod p
            //Bob computes TB = g^SB mod p
            System.out.println("Generating TA and TB for Alice and Bob respectively... ");
            BigInteger TA = modPower(g, BigInteger.valueOf(SA), p);
            BigInteger TB = modPower(g,BigInteger.valueOf(SB) ,p);

            System.out.println("TA: " + TA);
            System.out.println("TB: " + TB);

            //They exchange their T’s: TA <--> TB
            //Alice computes TB^SA mod p
            //Bob computes TA^SB mod p
            BigInteger secretKeyAlice = modPower(TB, BigInteger.valueOf(SA), p);
            BigInteger secretKeyBob = modPower(TA, BigInteger.valueOf(SB), p);

            System.out.println("Secret Key Generated at Alice's End: " + secretKeyAlice);
            System.out.println("Secret Key Generated at Bob's End: " + secretKeyBob);
        }
    }

    private static BigInteger modPower(BigInteger base, BigInteger exponent, BigInteger modulus) {
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
