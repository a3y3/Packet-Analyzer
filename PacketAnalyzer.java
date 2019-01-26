import java.io.*;

class PacketAnalyzer {
    private DataInputStream in;
    private int length;

    PacketAnalyzer(File dataFile) throws FileNotFoundException {
        this.length = (int) dataFile.length();
        this.in = new DataInputStream(new FileInputStream(dataFile));
    }

    void analyze() throws IOException {
        readEthernetHeader();
        readIPDatagram();
    }

    private String integerToHex(int value) {
        String hex = Integer.toHexString(value);
        if (hex.length() == 1) {
            hex = "0" + hex;
        }
        return hex.toUpperCase();
    }

    private void readEthernetHeader() throws IOException {
        System.out.println("ETHER: ----- Ether Header -----");
        System.out.println("ETHER:");
        System.out.println("ETHER: Packet size = " + length + " bytes");

        readEthernetDestination();
        System.out.println();

        readEthernetSource();
        System.out.println();

        readEthernetLengthOrType();
        System.out.println();

        System.out.println("ETHER:");
    }

    private void readEthernetDestination() throws IOException {
        System.out.print("ETHER: Destination = ");
        readSixEthernetBytes();
    }

    private void readEthernetSource() throws IOException {
        System.out.print("ETHER: Source = ");
        readSixEthernetBytes();
    }

    private void readSixEthernetBytes() throws IOException {
        int counter = 0;
        while (counter < 6) {
            int destination = in.read();
            System.out.print(integerToHex(destination));
            System.out.print(":");
            counter++;
        }
    }

    private void readEthernetLengthOrType() throws IOException {
        System.out.print("ETHER: Ethertype = ");
        int counter = 0;
        while (counter < 2) {
            int nextByte = in.read();
            System.out.print(integerToHex(nextByte));
            counter++;
        }
    }

    private void readIPDatagram() throws IOException {
        System.out.println("IP: ----- IP Header -----");
        System.out.println("IP:");
        int protocol = readIPHeader();

    }

    private int readIPHeader() throws IOException {
        int headerLength = readIPVersionAndLength();

        readIPTOS();

        readIPTotalLength();

        readIPIdentification();

        readFlagsAndFragmentOffset();

        readTTL();

        int protocol = readProtocol();

        readChecksum();

        readSourceIP();

        readDestinationIP();

        if (headerLength > 20){
            readOptions(headerLength);
        }
        else{
            System.out.println("No options");
        }

        System.out.println("IP:");

        return protocol;
    }

    private int readIPVersionAndLength() throws IOException {
        System.out.print("IP: Version = ");
        int nextByte = in.read();
        int version = nextByte >> 4;
        System.out.println(integerToHex(version));

        int headerLength = nextByte & 0b00001111;
        headerLength *= 4; //(* 32/8 bytes) = (* 4 bytes)
        System.out.println("IP: Header length = " + headerLength + "bytes");
        return headerLength;
    }

    private void readIPTOS() throws IOException {
        int nextByte = in.read();
        System.out.println("IP: Type of service = " + integerToHex(nextByte));
    }

    private void read2BytesForIP(int[] data) throws IOException {
        int counter = 0;
        while (counter < 2) {
            data[counter] = in.read();
            counter++;
        }
    }

    private int add2HexBytes(int[] data){
        return (data[0] << 8) + data[1];
    }

    private void readIPTotalLength() throws IOException {
        int[] data = new int[2];
        read2BytesForIP(data);

        int finalNumber = add2HexBytes(data);
        System.out.println("IP: Total length = " + finalNumber + " bytes");

    }

    private void readIPIdentification() throws IOException {
        int[] data = new int[2];
        read2BytesForIP(data);
        int finalNumber = add2HexBytes(data);
        System.out.println("IP: Identification = " + finalNumber);
    }

    private void readFlagsAndFragmentOffset() throws IOException {
        int[] data = new int[2];
        read2BytesForIP(data);
        int flags = data[0] >> 5; //First 3 bits
        System.out.print("IP: Flags = 0x" + flags + "\n");
        String fragmentPresent = ((flags & 0b010) == 0b010) ? ".1.. do not " +
                "fragment" :
                ".0.. fragment";
        String fragment = ((flags & 0b001) == 1) ? "..1. More fragments" :
                "..0. Last fragment";
        System.out.println("IP: \t" +  fragmentPresent);
        System.out.println("IP: \t" + fragment);

        int fragmentOffset = data[0] & 0b00011111;
        fragmentOffset &= 5;
        fragmentOffset |= data[1];

        System.out.println("IP: Fragment offset = "+ fragmentOffset +" bytes");
    }

    private void readTTL() throws IOException {
        int nextByte = in.read();
        System.out.println("IP: Time to live = " + integerToHex(nextByte) +
                " seconds /hops");
    }

    private int readProtocol() throws IOException {
        int nextByte = in.read();
        System.out.print("IP: Protocol = " + nextByte);
        if (nextByte == 1){
            System.out.println(" (ICMP)");
        }
        else if (nextByte == 6){
            System.out.println(" (TCP)");
        }
        else if (nextByte == 17){
            System.out.println(" (UDP)");
        }
        return nextByte;
    }

    private void readChecksum() throws IOException {
        int[] data = new int[2];
        read2BytesForIP(data);
        int result = add2HexBytes(data);
        System.out.println("IP: Header checksum = " + integerToHex(result));
    }

    private void readFourIPBytes() throws IOException {
        int counter = 0;
        while (counter < 4) {
            int destination = in.read();
            System.out.print(destination);
            System.out.print(".");
            counter++;
        }
    }
    private void readSourceIP() throws IOException {
        System.out.print("IP: Source address = " );
        readFourIPBytes();
        System.out.println();
    }

    private void readDestinationIP() throws IOException {
        System.out.print("IP: Destination address = " );
        readFourIPBytes();
        System.out.println();
    }

    private void readOptions(int headerLength) throws IOException { //TODO options?
        int bytesToRead = headerLength - 20;
        System.out.println("Reading " + bytesToRead + " bytes, but not " +
                "displaying yet!");
        int counter = 0;
        while (counter < bytesToRead){
            in.read();
            counter ++;
        }
    }

}

class pktanalyzer {
    public static void main(String[] args) throws IOException {
        String fileName;
        File file;
        try {
            fileName = args[0];
            file = new File(fileName);
            PacketAnalyzer packetAnalyzer = new PacketAnalyzer(file);
            packetAnalyzer.analyze();

        } catch (ArrayIndexOutOfBoundsException a) {
            System.err.println("Usage: java pktanalyzer <file>");
        }
    }
}