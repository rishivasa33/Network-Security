import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class ExtendedACL {

    private static final String DEFAULT_ACL_FILE = "testfiles/acl_statements_extended_1.txt";
    private static final String DEFAULT_IP_FILE = "testfiles/source_packets_extended_1.txt";
    private static final int ACL_STATEMENT_TYPE_INDEX = 0;
    private static final int ACL_PERMIT_DENY_INDEX = 2;
    private static final int ACL_PROTOCOL_INDEX = 3;
    private static final int PACKET_SOURCE_IP_INDEX = 0;
    private static final int PACKET_DESTINATION_IP_INDEX = 1;
    private static final int PACKET_PORT_NO_INDEX = 2;
    private static final int IP_CLASS_COUNT = 4;
    private static final String PERMIT = "permit";
    private static final String DENY = "deny";
    private static final String ANY = "any";
    private static final String ACCESS_LIST = "access-list";
    private static final String ANY_MASK = "255.255.255.255";
    private static final String PORT_RANGE = "range";
    private static final String PORT_EQ = "eq";

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {
            String ACLFile = getInputPath("Enter path to the file containing Extended ACL Statements (Leave blank and Press Enter if you want to use default file): ", DEFAULT_ACL_FILE, scanner);
            String IPFile = getInputPath("Enter path to the file containing list of Source Packets (Leave blank and Press Enter if you want to use default file): ", DEFAULT_IP_FILE, scanner);

            System.out.println("\nACL Statements file: " + ACLFile);
            System.out.println("Source IPs file: " + IPFile + "\n");

            ArrayList<String> extendedACLStatementList = readFileIntoArrayList(ACLFile);
            ArrayList<String> sourcePacketsList = readFileIntoArrayList(IPFile);

            validatePacketAccessWithACL(extendedACLStatementList, sourcePacketsList);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void validatePacketAccessWithACL(ArrayList<String> extendedACLStatementList, ArrayList<String> sourcePacketsList) {
        for (String sourcePacket : sourcePacketsList) {

        //Split Packet Fields
        String[] sourcePacketFields = sourcePacket.split("\\s+");
        HashMap<String, String> packetFieldsMap = new HashMap<>();
        packetFieldsMap.put("packetSourceIP", sourcePacketFields[PACKET_SOURCE_IP_INDEX]);
        packetFieldsMap.put("packetDestinationIP", sourcePacketFields[PACKET_DESTINATION_IP_INDEX]);
        if(sourcePacketFields.length>=3){
        packetFieldsMap.put("packetPortNo", sourcePacketFields[PACKET_PORT_NO_INDEX]);
        }
        
        boolean isPacketAllowed = false;

            for (String extendedACLStatement : extendedACLStatementList) {
                String[] extendedACLFields = extendedACLStatement.split("\\s+");
                if (extendedACLFields[ACL_STATEMENT_TYPE_INDEX].equalsIgnoreCase(ACCESS_LIST)) {
                    String permitOrDeny = extendedACLFields[ACL_PERMIT_DENY_INDEX];
                    boolean isPacketMatchingACLStatement = checkIfPacketMatches(packetFieldsMap, extendedACLFields);
                    if (isPacketMatchingACLStatement && permitOrDeny.equalsIgnoreCase(PERMIT)) {
                        isPacketAllowed = true;
                        break;
                    } else if (isPacketMatchingACLStatement && permitOrDeny.equalsIgnoreCase(DENY)) {
                        break;
                    }
                }
            }

            if (isPacketAllowed) {
                System.out.println("Packet from " + sourcePacket + " permitted");
            } else {
                System.out.println("Packet from " + sourcePacket + " denied");
            }

        }
    }

    private static boolean checkIfPacketMatches(HashMap<String, String> packetFieldsMap, String[] extendedACLFields) {
        boolean isPacketMatchingACLStatement = false;

        HashMap<String, String> extendedACLFieldsMap = new HashMap<>();
        extendedACLFieldsMap.put("protocolName",extendedACLFields[ACL_PROTOCOL_INDEX]);

        List<String> comparingPortNumbers = new ArrayList<>();

        //Check if source or destination is ANY. Set fields accordingly. If both are ANY, return true. Also Check existence of port no fields for each condition.
        if(extendedACLFields[4].equalsIgnoreCase(ANY)){
            if(extendedACLFields[5].equalsIgnoreCase(ANY)){
                if(extendedACLFields.length > 6){
                    if(extendedACLFields[6].equals(PORT_RANGE)){
                        String[] range =  extendedACLFields[7].split("-");
                        IntStream stream = IntStream.rangeClosed(Integer.parseInt(range[0]), Integer.parseInt(range[1]));
                        comparingPortNumbers = stream.boxed().map(String::valueOf).collect(Collectors.toList());
                    } else if(extendedACLFields[6].equals(PORT_EQ)){
                        comparingPortNumbers.add(extendedACLFields[7]);
                    }
                }
                
                if(comparingPortNumbers.contains(packetFieldsMap.get("packetPortNo"))){
                    isPacketMatchingACLStatement = true;
                    return isPacketMatchingACLStatement;    
                } else{
                    extendedACLFieldsMap.put("comparingSourceIP", ANY);
                    extendedACLFieldsMap.put("comparingSourceMask", ANY);
                    extendedACLFieldsMap.put("comparingDestinationIP", ANY);
                    extendedACLFieldsMap.put("comparingDestinationMask", ANY);
                }

            } else{
                extendedACLFieldsMap.put("comparingSourceIP", ANY);
                extendedACLFieldsMap.put("comparingSourceMask", ANY);
                extendedACLFieldsMap.put("comparingDestinationIP", extendedACLFields[5]);
                extendedACLFieldsMap.put("comparingDestinationMask", extendedACLFields[6]);
                if(extendedACLFields.length > 7){
                    if(extendedACLFields[7].equals(PORT_RANGE)){
                        String[] range =  extendedACLFields[8].split("-");
                        IntStream stream = IntStream.rangeClosed(Integer.parseInt(range[0]), Integer.parseInt(range[1]));
                        comparingPortNumbers = stream.boxed().map(String::valueOf).collect(Collectors.toList());
                    } else if(extendedACLFields[7].equals(PORT_EQ)){
                        comparingPortNumbers.add(extendedACLFields[8]);
                    }
                }
            }
        } else{
            if(extendedACLFields[6].equalsIgnoreCase(ANY)){
                extendedACLFieldsMap.put("comparingSourceIP", extendedACLFields[4]);
                extendedACLFieldsMap.put("comparingSourceMask", extendedACLFields[5]);
                extendedACLFieldsMap.put("comparingDestinationIP", ANY);
                extendedACLFieldsMap.put("comparingDestinationMask", ANY);
                if(extendedACLFields.length > 7){
                    if(extendedACLFields[7].equals(PORT_RANGE)){
                        String[] range =  extendedACLFields[8].split("-");
                        IntStream stream = IntStream.rangeClosed(Integer.parseInt(range[0]), Integer.parseInt(range[1]));
                        comparingPortNumbers = stream.boxed().map(String::valueOf).collect(Collectors.toList());
                    } else if(extendedACLFields[7].equals(PORT_EQ)){
                        comparingPortNumbers.add(extendedACLFields[8]);
                    }
                }
            } else{
                extendedACLFieldsMap.put("comparingSourceIP", extendedACLFields[4]);
                extendedACLFieldsMap.put("comparingSourceMask", extendedACLFields[5]);
                extendedACLFieldsMap.put("comparingDestinationIP", extendedACLFields[6]);
                extendedACLFieldsMap.put("comparingDestinationMask", extendedACLFields[7]);
                if(extendedACLFields.length > 8){
                    if(extendedACLFields[8].equals(PORT_RANGE)){
                        String[] range =  extendedACLFields[9].split("-");
                        IntStream stream = IntStream.rangeClosed(Integer.parseInt(range[0]), Integer.parseInt(range[1]));
                        comparingPortNumbers = stream.boxed().map(String::valueOf).collect(Collectors.toList());
                    } else if(extendedACLFields[8].equals(PORT_EQ)){
                        comparingPortNumbers.add(extendedACLFields[9]);
                    }
                }
            }
        }

        //If instead of "any", wildcard mask is 255.255.255.255, then match the packets and return true
        if(extendedACLFieldsMap.get("comparingSourceMask").equals(ANY_MASK)){
            if(extendedACLFieldsMap.get("comparingDestinationMask").equals(ANY_MASK)){
                isPacketMatchingACLStatement = true;
                return isPacketMatchingACLStatement;
            } else{
                extendedACLFieldsMap.put("comparingSourceIP", ANY);
                extendedACLFieldsMap.put("comparingSourceMask", ANY);
            }
        } else if(extendedACLFieldsMap.get("comparingDestinationMask").equals(ANY_MASK)){
            extendedACLFieldsMap.put("comparingDestinationIP", ANY);
            extendedACLFieldsMap.put("comparingDestinationMask", ANY);
        }

        String[] packetSourceIPClass = packetFieldsMap.get("packetSourceIP").split("[.]");
        String[] packetDestinationIPClass = packetFieldsMap.get("packetDestinationIP").split("[.]");
        String[] comparingSourceIPClass;
        String[] comparingSourceMaskClass;
        String[] comparingDestinationIPClass; 
        String[] comparingDestinationMaskClass;

        if(extendedACLFieldsMap.get("comparingSourceIP").equals(ANY) && extendedACLFieldsMap.get("comparingSourceMask").equals(ANY) ){
            comparingSourceIPClass = new String[] {ANY};
            comparingSourceMaskClass = new String[] {ANY};
        } else{
            comparingSourceIPClass = extendedACLFieldsMap.get("comparingSourceIP").split("[.]");
            comparingSourceMaskClass = extendedACLFieldsMap.get("comparingSourceMask").split("[.]");
        }
        
        if(extendedACLFieldsMap.get("comparingDestinationIP").equals(ANY) && extendedACLFieldsMap.get("comparingDestinationMask").equals(ANY) ){
            comparingDestinationIPClass = new String[] {ANY};
            comparingDestinationMaskClass = new String[] {ANY};
        } else{    
            comparingDestinationIPClass = extendedACLFieldsMap.get("comparingDestinationIP").split("[.]");
            comparingDestinationMaskClass = extendedACLFieldsMap.get("comparingDestinationMask").split("[.]");
        }

        //Loop for 4 times for each IP Class. If the mask is 0, then compare the IP classes. If not, Ignore.
        for (int i = 0; i < IP_CLASS_COUNT; i++) {
            if(extendedACLFieldsMap.get("comparingSourceIP").equals(ANY) && extendedACLFieldsMap.get("comparingSourceMask").equals(ANY) ){
                isPacketMatchingACLStatement = true;
            } else if (comparingSourceMaskClass[i].equals("0")) {
                if (packetSourceIPClass[i].equals(comparingSourceIPClass[i])) {
                    isPacketMatchingACLStatement = true;
                } else {
                    isPacketMatchingACLStatement = false;
                    break;
                }
            }
            if(extendedACLFieldsMap.get("comparingDestinationIP").equals(ANY) && extendedACLFieldsMap.get("comparingDestinationMask").equals(ANY) ){
                isPacketMatchingACLStatement = true;
            } else if (comparingDestinationMaskClass[i].equals("0")) {
                if (packetDestinationIPClass[i].equals(comparingDestinationIPClass[i])) {
                    isPacketMatchingACLStatement = true;
                } else {
                    isPacketMatchingACLStatement = false;
                    break;
                }
            }
        }

        if(isPacketMatchingACLStatement){
            if (!comparingPortNumbers.isEmpty() && packetFieldsMap.containsKey("packetPortNo")) {
                isPacketMatchingACLStatement = comparingPortNumbers.contains(packetFieldsMap.get("packetPortNo"));
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