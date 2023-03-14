import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.ArrayList;
import java.util.Scanner;

public class MatrixTranspositionCipher {

    private static final String DEFAULT_PLAINTEXT_FILE = "testfiles/matrixTranspositionPlaintextNotesProblem2.txt";

    private static int matrixColSize;

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {
            String plaintextFile = getInputPath("Enter path to the file containing the plaintext (Leave blank and Press Enter if you want to use default file): ", DEFAULT_PLAINTEXT_FILE, scanner);
            String plainText = readFileIntoString(plaintextFile);

            System.out.println("Enter Matrix Column Count: ");
            matrixColSize = scanner.nextInt();

            System.out.println("Enter the permutation for " + matrixColSize + " columns as the key: ");
            int i = 0;
            ArrayList<Integer> encryptionKey = new ArrayList<>();
            while (i < matrixColSize) {
                int col = scanner.nextInt();
                if (col >= 1 && col <= matrixColSize && !encryptionKey.contains(col)) {
                    encryptionKey.add(col);
                    i++;
                } else if (encryptionKey.contains(col)) {
                    System.out.println("Error! Entered column number is already entered previously. Try Again!");
                } else {
                    System.out.println("Error! Entered column number is not between 1 and " + matrixColSize + " (The Matrix Column Count). Try Again!");
                }
            }

            //You may assume that the plaintext and ciphertext consist of uppercase letters, lowercase letters, numbers, and spaces.
            //You can represent the space by a % character. No other special characters are required.
            plainText = plainText.replaceAll("[^a-zA-Z0-9] || \\s", "");
            plainText = plainText.replaceAll("\\s", "%");

            System.out.println("\nPlaintext: \n================================================\n" + plainText);
            System.out.println("\nEncryption Key: \n================================================\n" + encryptionKey);

            String cipherText = encryptPlaintext(plainText, encryptionKey);
            System.out.println("\nEncrypted CipherText: \n================================================\n" + cipherText);

            String decryptedPlainText = decryptCipherText(cipherText, encryptionKey);
            System.out.println("\nDecrypted PlainText: \n================================================\n" + decryptedPlainText);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(0);
        }
    }

    private static String encryptPlaintext(String plainText, ArrayList<Integer> encryptionKey) {
        //Reference for floating and rounding in division:
        //https://stackoverflow.com/questions/5203022/division-between-integers-in-java
        int matrixRowSize = (int) Math.ceil(plainText.length() / (float) matrixColSize);
        Character[][] plainTextMatrix = new Character[matrixRowSize][matrixColSize];

        System.out.println("\nPlainText Matrix: \n================================================");

        //Reference for CharacterIterator:
        //https://docs.oracle.com/javase/7/docs/api/java/text/CharacterIterator.html
        CharacterIterator plainTextIterator = new StringCharacterIterator(plainText);
        while (plainTextIterator.current() != CharacterIterator.DONE) {
            for (int i = 0; i < matrixRowSize; i++) {
                for (int j = 0; j < matrixColSize; j++) {
                    if (plainTextIterator.current() != CharacterIterator.DONE) {
                        plainTextMatrix[i][j] = plainTextIterator.current();
                        plainTextIterator.next();
                    } else {
                        plainTextMatrix[i][j] = '%';
                    }
                    System.out.print(plainTextMatrix[i][j] + "\t");
                }
                System.out.print("\n");
            }
        }

        StringBuilder cipherTextBuilder = new StringBuilder();

        for (int keyColumn : encryptionKey) {
            for (int i = 0; i < matrixRowSize; i++)
                cipherTextBuilder.append(plainTextMatrix[i][keyColumn - 1]);
        }

        return cipherTextBuilder.toString();
    }

    private static String decryptCipherText(String cipherText, ArrayList<Integer> encryptionKey) {
        //Using encryptionKey.size() instead of matrixColSize as the recipient will not know the matrix column size, they will only have the key size
        matrixColSize = encryptionKey.size();
        int matrixRowSize = (int) Math.ceil(cipherText.length() / (float) matrixColSize);
        Character[][] plainTextMatrix = new Character[matrixRowSize][matrixColSize];

        CharacterIterator cipherTextIterator = new StringCharacterIterator(cipherText);
        while (cipherTextIterator.current() != CharacterIterator.DONE) {
            for (int keyColumn : encryptionKey) {
                for (int j = 0; j < matrixRowSize; j++) {
                    plainTextMatrix[j][keyColumn - 1] = cipherTextIterator.current();
                    cipherTextIterator.next();
                }
            }
        }

        StringBuilder plainTextBuilder = new StringBuilder();

        for (int i = 0; i < matrixRowSize; i++) {
            for (int j = 0; j < matrixColSize; j++) {
                plainTextBuilder.append(plainTextMatrix[i][j]);
            }
        }

        return plainTextBuilder.toString();
    }

    private static String getInputPath(String displayMessage, String defaultPath, Scanner scanner) {
        System.out.print(displayMessage);
        String inputPath = scanner.nextLine();
        return inputPath.isEmpty() ? defaultPath : inputPath;
    }

    private static String readFileIntoString(String fileName) throws IOException {
        String fileContent;
        StringBuilder builder = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }
        }
        fileContent = builder.toString();

        return fileContent;
    }
}
