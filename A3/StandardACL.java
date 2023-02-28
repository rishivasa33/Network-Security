import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Scanner;

public class StandardACL {

    private static final String DEFAULT_ACL_FILE = "testfiles/acl_statements_standard_1.txt";
    private static final String DEFAULT_IP_FILE = "testfiles/source_packets_standard_1.txt";
    private static final int ACL_STATEMENT_TYPE_INDEX = 0;
    private static final int ACL_PERMIT_DENY_INDEX = 2;
    private static final int ACL_SRC_IP_INDEX = 3;
    private static final int ACL_SRC_MASK_INDEX = 4;
    private static final int IP_CLASS_COUNT = 4;
    private static final String PERMIT = "permit";
    private static final String DENY = "deny";
    private static final String ANY = "any";
    private static final String ACCESS_LIST = "access-list";
    private static final String ANY_MASK = "255.255.255.255";

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {
            String ACLFile = getInputPath("Enter path to the file containing Standard ACL Statements (Leave blank and Press Enter if you want to use default file): ", DEFAULT_ACL_FILE, scanner);
            String IPFile = getInputPath("Enter path to the file containing list of Source Packets (Leave blank and Press Enter if you want to use default file): ", DEFAULT_IP_FILE, scanner);

            System.out.println("\nACL Statements file: " + ACLFile);
            System.out.println("Source IPs file: " + IPFile + "\n");

            ArrayList<String> ACLStatementList = readFileIntoArrayList(ACLFile);
            ArrayList<String> SourceIPList = readFileIntoArrayList(IPFile);

            validateIPAccessWithACL(ACLStatementList, SourceIPList);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void validateIPAccessWithACL(ArrayList<String> ACLStatementList, ArrayList<String> SourceIPList) {
        for (String packetSourceIP : SourceIPList) {
            boolean isPacketAllowed = false;

            for (String aclStatement : ACLStatementList) {
                String[] aclFields = aclStatement.split("\\s+");

                if (aclFields[ACL_STATEMENT_TYPE_INDEX].equalsIgnoreCase(ACCESS_LIST)) {
                    String permitOrDeny = aclFields[ACL_PERMIT_DENY_INDEX];
                    if (aclFields[ACL_SRC_IP_INDEX].equalsIgnoreCase(ANY)) {
                        if (permitOrDeny.equalsIgnoreCase(PERMIT)) {
                            isPacketAllowed = true;
                            break;
                        } else if (permitOrDeny.equalsIgnoreCase(DENY)) {
                            break;
                        }
                    }

                    String comparingSourceIP = aclFields[ACL_SRC_IP_INDEX];
                    String comparingSourceMask = aclFields[ACL_SRC_MASK_INDEX];
                
                    //If instead of "any", wildcard mask is 255.255.255.255, then match the packets and return true
                    if(comparingSourceMask.equalsIgnoreCase(ANY_MASK)){
                        if (permitOrDeny.equalsIgnoreCase(PERMIT)) {
                            isPacketAllowed = true;
                            break;
                        } else if (permitOrDeny.equalsIgnoreCase(DENY)) {
                            break;
                        }
                    }
                    boolean isPacketMatchingACLStatement = checkIfPacketMatches(packetSourceIP, comparingSourceIP, comparingSourceMask);

                    if (isPacketMatchingACLStatement && permitOrDeny.equalsIgnoreCase(PERMIT)) {
                        isPacketAllowed = true;
                        break;
                    } else if (isPacketMatchingACLStatement && permitOrDeny.equalsIgnoreCase(DENY)) {
                        break;
                    }
                }

            }

            if (isPacketAllowed) {
                System.out.println("Packet from " + packetSourceIP + " permitted");
            } else {
                System.out.println("Packet from " + packetSourceIP + " denied");
            }

        }
    }

    private static boolean checkIfPacketMatches(String packetSourceIP, String comparingSourceIP, String comparingSourceMask) {
        boolean isPacketMatchingACLStatement = false;
        
        String[] packetSourceIPClass = packetSourceIP.split("[.]");
        String[] comparingSourceIPClass = comparingSourceIP.split("[.]");
        String[] comparingSourceMaskClass = comparingSourceMask.split("[.]");

        //Loop for 4 times for each IP Class. If the mask is 0, then compare the IP classes. If not, Ignore.
        for (int i = 0; i < IP_CLASS_COUNT; i++) {
            if (comparingSourceMaskClass[i].equals("0")) {
                if (packetSourceIPClass[i].equals(comparingSourceIPClass[i])) {
                    isPacketMatchingACLStatement = true;
                } else {
                    isPacketMatchingACLStatement = false;
                    break;
                }
            }
        }
        return isPacketMatchingACLStatement;
    }

    private static String getInputPath(String displayMessage, String defaultPath, Scanner scanner) {
        System.out.print(displayMessage);
        String inputPath = scanner.nextLine();
        return inputPath.isEmpty() ? defaultPath : inputPath;
    }

    private static ArrayList<String> readFileIntoArrayList(String fileName) throws IOException {
        ArrayList<String> listOfLines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line = reader.readLine();
            while (line != null) {
                listOfLines.add(line);
                line = reader.readLine();
            }
        } catch (IOException e) {
            System.out.println("Try Again! The system cannot find the file - " + fileName);
            throw e;
        }
        return listOfLines;
    }
}