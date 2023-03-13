import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Random;
import java.util.Scanner;

public class PlayfairCipher {

    private static final String DEFAULT_KEY_FILE = "testfiles/KeyMain.txt";
    private static final String DEFAULT_PLAINTEXT_FILE = "testfiles/PlaintextMain.txt";

    private static final ArrayList<Integer> REPEATED_CHARACTER_REPLACEMENT_WITH_XorQ_INDEXES = new ArrayList<>();
    private static final ArrayList<Integer> J_CHARACTER_REPLACEMENT_WITH_I_INDEXES = new ArrayList<>();
    private static Boolean ODD_CHARACTERS_PADDING_ADDED = Boolean.FALSE;

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {
            String plaintextFile = getInputPath("Enter path to the file containing the plaintext (Leave blank and Press Enter if you want to use default file): ", DEFAULT_PLAINTEXT_FILE, scanner);
            String keyFile = getInputPath("Enter path to the file containing the key (Leave blank and Press Enter if you want to use default file): ", DEFAULT_KEY_FILE, scanner);

            System.out.println("\nPlaintext file: " + plaintextFile);
            System.out.println("Key file: " + keyFile);

            String plainText = readFileIntoString(plaintextFile);
            String encryptionKey = readFileIntoString(keyFile);

            //Replace all non-alphabet characters with ""
            plainText = plainText.replaceAll("[^a-zA-Z]", "");

            System.out.println("\nPlaintext: \n================================================\n" + plainText);
            System.out.println("\nEncryption Key: \n================================================\n" + encryptionKey);

            Character[][] keyMatrix = generateKeyMatrix(encryptionKey);

            String cipherText = encryptPlaintext(plainText, keyMatrix);
            System.out.println("\nEncrypted CipherText: \n================================================\n" + cipherText);

            String decryptedPlainText = decryptCipherText(cipherText, keyMatrix);
            System.out.println("\nDecrypted Plain Text: \n================================================\n" + decryptedPlainText);
        }
    }

    private static Character[][] generateKeyMatrix(String encryptionKey) {

        //The letters of the key are written row-wise in a 5X5 matrix.
        Character[][] keyMatrix = new Character[5][5];

        //After the key letters are filled, the remaining letters of the alphabet are used to fill the key matrix
        String alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        encryptionKey = encryptionKey + alphabets;

        //J is in the same box as I
        encryptionKey = encryptionKey.replace("J", "I");
        char[] encryptionKeyChars = encryptionKey.toCharArray();

        //Reference for using a data structure with unique values and predictable ordered iteration:
        //https://docs.oracle.com/javase/7/docs/api/java/util/LinkedHashSet.html
        //https://www.geeksforgeeks.org/java-program-to-get-elements-by-index-from-linkedhashset/
        LinkedHashSet<Character> keyCharSet = new LinkedHashSet<>();

        for (Character c : encryptionKeyChars) {
            keyCharSet.add(c);
        }

        System.out.println("\nGenerated Key Matrix: \n================================================");
        Iterator<Character> keyCharSetIterator = keyCharSet.iterator();
        while (keyCharSetIterator.hasNext()) {
            for (int i = 0; i < keyMatrix.length; i++) {
                for (int j = 0; j < keyMatrix[i].length; j++) {
                    keyMatrix[i][j] = keyCharSetIterator.next();
                    System.out.print(keyMatrix[i][j] + "\t");
                }
                System.out.print("\n");
            }
        }
        return keyMatrix;
    }

    private static String encryptPlaintext(String plainText, Character[][] keyMatrix) {

        StringBuilder plainTextBuilder = new StringBuilder(plainText);

        //Repeated letters are replaced with an X or a Q.
        for (int i = 0; i < plainTextBuilder.length() - 1; i += 2) {
            if (plainTextBuilder.charAt(i) == plainTextBuilder.charAt(i + 1)) {
                Character XorQ = new Random().nextInt(2) == 1 ? 'X' : 'Q';
                plainTextBuilder.insert(i + 1, XorQ);
                REPEATED_CHARACTER_REPLACEMENT_WITH_XorQ_INDEXES.add(i + 1);
            }
        }

        //If the number of letters is not even, it is padded with a Z
        if (plainTextBuilder.length() % 2 != 0) {
            plainTextBuilder.append('Z');
            ODD_CHARACTERS_PADDING_ADDED = Boolean.TRUE;
        }

        //Replace each 'J' character in plaintext with 'I' since the encryption matrix will not contain 'J', and store the index of the occurrence for replacing it back later during decryption
        for (int i = 0; i < plainTextBuilder.length(); i++) {
            if (plainTextBuilder.charAt(i) == 'J') {
                plainTextBuilder.setCharAt(i, 'I');
                J_CHARACTER_REPLACEMENT_WITH_I_INDEXES.add(i);
            }
        }

        plainText = plainTextBuilder.toString();
        System.out.println("\nRefined Plaintext with padding and replacements: \n================================================\n" + plainText);

        int rowChar1 = 0;
        int colChar1 = 0;
        int rowChar2 = 0;
        int colChar2 = 0;

        StringBuilder cipherTextBuilder = new StringBuilder();
        for (int i = 0; i < plainText.length(); i += 2) {
            Character pairCharacter1 = plainText.charAt(i);
            Character pairCharacter2 = plainText.charAt(i + 1);


            for (int keyMtxRow = 0; keyMtxRow < 5; keyMtxRow++) {
                for (int keyMtxCol = 0; keyMtxCol < 5; keyMtxCol++) {
                    if (keyMatrix[keyMtxRow][keyMtxCol].equals(pairCharacter1)) {
                        rowChar1 = keyMtxRow;
                        colChar1 = keyMtxCol;
                    }
                    if (keyMatrix[keyMtxRow][keyMtxCol].equals(pairCharacter2)) {
                        rowChar2 = keyMtxRow;
                        colChar2 = keyMtxCol;
                    }
                }
            }

            /*
             *   Rule No. 1: If the two letters of the plaintext pair appear in the same column, replace
             *   each with the letter immediately below (wrapping around to the top of the column if you
             *   reach the end)
             */
            if (colChar1 == colChar2) {
                cipherTextBuilder.append(keyMatrix[(rowChar1 + 1) % 5][colChar1]).append(keyMatrix[(rowChar2 + 1) % 5][colChar2]);
            }

            /*
             *   Rule No. 2: If the two letters of the plaintext pair appear in the same row, replace each
             *   with the letter immediately to the right (wrapping around to the beginning of the row if
             *   you reach the end).
             */
            else if (rowChar1 == rowChar2) {
                cipherTextBuilder.append(keyMatrix[rowChar1][(colChar1 + 1) % 5]).append(keyMatrix[rowChar2][(colChar2 + 1) % 5]);
            }

            /*
             *   Rule No. 3: If the two letters of the plaintext pair are not in the same column or the
             *   same row, replace them with the letters that form a rectangle with them, that is, go to
             *   the opposite corner of the rectangle in the same row of the first plaintext letter, and
             *   then go to the opposite corner in the same row of the second plaintext letter.
             */
            else {
                cipherTextBuilder.append(keyMatrix[rowChar1][colChar2]).append(keyMatrix[rowChar2][colChar1]);
            }
        }
        return cipherTextBuilder.toString();
    }

    private static String decryptCipherText(String cipherText, Character[][] keyMatrix) {
        StringBuilder plainTextBuilder = new StringBuilder();

        int rowChar1 = 0;
        int colChar1 = 0;
        int rowChar2 = 0;
        int colChar2 = 0;

        for (int i = 0; i < cipherText.length(); i += 2) {
            Character pairCharacter1 = cipherText.charAt(i);
            Character pairCharacter2 = cipherText.charAt(i + 1);

            for (int keyMtxRow = 0; keyMtxRow < 5; keyMtxRow++) {
                for (int keyMtxCol = 0; keyMtxCol < 5; keyMtxCol++) {
                    if (keyMatrix[keyMtxRow][keyMtxCol].equals(pairCharacter1)) {
                        rowChar1 = keyMtxRow;
                        colChar1 = keyMtxCol;
                    }
                    if (keyMatrix[keyMtxRow][keyMtxCol].equals(pairCharacter2)) {
                        rowChar2 = keyMtxRow;
                        colChar2 = keyMtxCol;
                    }
                }
            }

            if (colChar1 == colChar2) {
                plainTextBuilder.append(keyMatrix[(rowChar1 + 5 - 1) % 5][colChar1]).append(keyMatrix[(rowChar2 + 5 - 1) % 5][colChar2]);
            } else if (rowChar1 == rowChar2) {
                plainTextBuilder.append(keyMatrix[rowChar1][(colChar1 + 5 - 1) % 5]).append(keyMatrix[rowChar2][(colChar2 + 5 - 1) % 5]);
            } else {
                plainTextBuilder.append(keyMatrix[rowChar1][colChar2]).append(keyMatrix[rowChar2][colChar1]);
            }
        }

        for (Integer i : J_CHARACTER_REPLACEMENT_WITH_I_INDEXES) {
            if (plainTextBuilder.charAt(i) == 'I') {
                plainTextBuilder.setCharAt(i, 'J');
            }
        }

        // Reference for offset method:
        // https://ideone.com/w8PXxg
        int deletedElementsCount = 0; //Used to offset the index shifting caused due to deleting elements from the string
        for (Integer i : REPEATED_CHARACTER_REPLACEMENT_WITH_XorQ_INDEXES) {
            plainTextBuilder.deleteCharAt(i - deletedElementsCount);
            deletedElementsCount++;
        }

        if (ODD_CHARACTERS_PADDING_ADDED == Boolean.TRUE) {
            plainTextBuilder.deleteCharAt(plainTextBuilder.length() - 1);
        }

        return plainTextBuilder.toString();
    }

    private static String getInputPath(String displayMessage, String defaultPath, Scanner scanner) {
        System.out.print(displayMessage);
        String inputPath = scanner.nextLine();
        return inputPath.isEmpty() ? defaultPath : inputPath;
    }

    private static String readFileIntoString(String fileName) {
        String fileContent;
        StringBuilder builder = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        fileContent = builder.toString().trim().toUpperCase();

        return fileContent;
    }
}
