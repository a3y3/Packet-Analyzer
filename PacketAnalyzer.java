import java.io.*;

class PacketAnalyzer {
    private DataInputStream in;
    private int length;
    private int NUM_BYTES_TO_READ = 64;

    PacketAnalyzer(File dataFile) throws FileNotFoundException {
        this.length = (int) dataFile.length();
        this.in = new DataInputStream(new FileInputStream(dataFile));
    }

    void analyze() throws IOException {
        readEthernetHeader();
        int protocol = readIPDatagram();
        if (protocol == 1) {
            readICMP();
        } else if (protocol == 6) {
            readTCP();
        } else if (protocol == 17) {
            readUDP();
        }
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

    private int readIPDatagram() throws IOException {
        System.out.println("IP: ----- IP Header -----");
        System.out.println("IP:");
        return readIPHeader();

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

        if (headerLength > 20) {
            readOptions(headerLength);
        } else {
            System.out.println("IP: No options");
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

    private void readNBytes(int[] data, int n) throws IOException {
        int counter = 0;
        while (counter < n) {
            data[counter] = in.read();
            counter++;
        }
    }

    private int add2HexBytes(int[] data) {
        return (data[0] << 8) + data[1];
    }

    private long add4HexBytes(int[] data) {
        return ((long) data[0] << 24) +
                ((long) data[1] << 16) +
                ((long) data[2] << 8) +
                ((long) data[3]);
    }

    private void readIPTotalLength() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);

        int finalNumber = add2HexBytes(data);
        System.out.println("IP: Total length = " + finalNumber + " bytes");

    }

    private void readIPIdentification() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int finalNumber = add2HexBytes(data);
        System.out.println("IP: Identification = " + finalNumber);
    }

    private void readFlagsAndFragmentOffset() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int flags = data[0] >> 5; //First 3 bits
        System.out.print("IP: Flags = 0x" + flags + "\n");
        String fragmentPresent = ((flags & 0b010) == 0b010) ? ".1.. do not " +
                "fragment" :
                ".0.. fragment";
        String fragment = ((flags & 0b001) == 1) ? "..1. More fragments" :
                "..0. Last fragment";
        System.out.println("IP: \t" + fragmentPresent);
        System.out.println("IP: \t" + fragment);

        int fragmentOffset = data[0] & 0b00011111;
        fragmentOffset &= 5;
        fragmentOffset |= data[1];

        System.out.println("IP: Fragment offset = " + fragmentOffset + " bytes");
    }

    private void readTTL() throws IOException {
        int nextByte = in.read();
        System.out.println("IP: Time to live = " + nextByte +
                " seconds /hops");
    }

    private int readProtocol() throws IOException {
        int nextByte = in.read();
        System.out.print("IP: Protocol = " + nextByte);
        if (nextByte == 1) {
            System.out.println(" (ICMP)");
        } else if (nextByte == 6) {
            System.out.println(" (TCP)");
        } else if (nextByte == 17) {
            System.out.println(" (UDP)");
        }
        return nextByte;
    }

    private void readChecksum() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int result = add2HexBytes(data);
        System.out.println("IP: Header checksum = 0x" + integerToHex(result));
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
        System.out.print("IP: Source address = ");
        readFourIPBytes();
        System.out.println();
    }

    private void readDestinationIP() throws IOException {
        System.out.print("IP: Destination address = ");
        readFourIPBytes();
        System.out.println();
    }

    private void readOptions(int headerLength) throws IOException { //TODO options?
        int bytesToRead = headerLength - 20;
        System.out.println("Reading " + bytesToRead + " bytes, but not " +
                "displaying yet!");
        int counter = 0;
        while (counter < bytesToRead) {
            in.read();
            counter++;
        }
    }

    private void readICMP() throws IOException {
        System.out.println("ICMP: ----- ICMP Header -----\n" +
                "ICMP:");
        readICMPType();
        readICMPCode();
        readICMPChecksum();
    }

    private void readICMPType() throws IOException {
        System.out.println("ICMP: Type = " + in.read());
    }

    private void readICMPCode() throws IOException {
        System.out.println("ICMP: Code = " + in.read());
    }

    private void readICMPChecksum() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        System.out.println("ICMP: Checksum = 0x" + integerToHex(add2HexBytes(data)));
    }

    private void readTCP() throws IOException {
        System.out.println("TCP:  ----- TCP Header -----");
        System.out.println("TCP: ");
        readTCPSource();

        readTCPDestination();

        readTCPSequenceNumber();

        readTCPAcknowledgementNumber();

        boolean URGSet = readTCPOffsetAndFlags();

        readTCPWindow();

        readTCPChecksum();

        if (URGSet) {
            readTCPURG();
        } else {
            System.out.println("TCP: Urgent pointer = 0");
        }

        readData("TCP");
    }

    private void readUDP() throws IOException {
        System.out.println("UDP:  ----- UDP Header -----");
        System.out.println("UDP: ");
        readUDPSource();

        readUDPDestination();

        readUDPLength();

        readUDPChecksum();

        System.out.println("UDP:");
        readData("UDP");
    }

    private void readUDPSource() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int result = add2HexBytes(data);
        System.out.println("UDP: Source port = " + result);
    }

    private void readUDPDestination() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int result = add2HexBytes(data);
        System.out.println("UDP: Destination port = " + result);
    }

    private void readUDPLength() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int result = add2HexBytes(data);
        System.out.println("UDP: Length = " + result);
    }

    private void readUDPChecksum() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int result = add2HexBytes(data);
        System.out.println("UDP: Checksum = 0x" + integerToHex(result));
    }

    private void readTCPSource() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int result = add2HexBytes(data);
        System.out.println("TCP: Source port = " + result);
    }

    private void readTCPDestination() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        int result = add2HexBytes(data);
        System.out.println("TCP:  Destination port = " + result);
    }

    private void readTCPSequenceNumber() throws IOException {
        int[] data = new int[4];
        readNBytes(data, 4);
        long result = add4HexBytes(data);
        System.out.println("TCP: Sequence number = " + result);
    }

    private void readTCPAcknowledgementNumber() throws IOException {
        int[] data = new int[4];
        readNBytes(data, data.length);
        long result = add4HexBytes(data);
        System.out.println("TCP: Acknowledgement number = " + result);
    }

    private boolean readTCPOffsetAndFlags() throws IOException {
        boolean isURGSet;
        int offsetAndFlag = in.read();
        int offset = offsetAndFlag >> 4;
        System.out.println("TCP: Data offset = " + offset + "bytes");

        int flags = in.read();
        int[] data = new int[2];
        data[0] = offsetAndFlag & 0b1;
        data[1] = flags;
        System.out.println("TCP: Flags = 0x" + integerToHex(add2HexBytes(data)));
        int NS = data[0];
        String NSPresent = NS == 1 ? "1 .... .... = Concealment Protection set" :
                "0 .... .... = No CE set";
        int CWR = flags >> 7 & 0b1;
        String CWRPresent = CWR == 1 ? "1... .... = CWR Flag" : "0..." +
                " .... = No CWR";
        int ECE = flags >> 6 & 0b1;
        String ECEPresent = ECE == 1 ? ".1.. .... = ECE Flag" : ".0.." +
                " .... = No ECE";
        int URG = flags >> 5 & 0b1;
        String URGPresent = URG == 1 ? "..1. .... = Urgent Pointer" : "..0." +
                " .... = No Urgent Pointer";
        isURGSet = URG == 1;
        int ACK = flags >> 4 & 0b1;
        String ACKPresent = ACK == 1 ? "...1 .... = Acknowledgement " : "...0 " +
                ".... = No Acknowledgement";
        int PSH = flags >> 3 & 0b1;
        String PSHPresent = PSH == 1 ? ".... 1... = Push " : ".... " +
                "0... = No Push";
        int RST = flags >> 2 & 0b1;
        String RSTPresent = RST == 1 ? ".... .1.. = Reset" : ".... " +
                ".0.. = No Reset";
        int SYN = flags >> 1 & 0b1;
        String SYNPresent = SYN == 1 ? ".... ..1. = SYN" : ".... " +
                "..0. = No SYN";
        int FIN = flags & 0b1;
        String FINPresent = FIN == 1 ? ".... ...1 = FIN" : ".... " +
                "...0 = No FIN";
        printFlag(NSPresent);
        printFlag(CWRPresent);
        printFlag(ECEPresent);
        printFlag(URGPresent);
        printFlag(ACKPresent);
        printFlag(PSHPresent);
        printFlag(RSTPresent);
        printFlag(SYNPresent);
        printFlag(FINPresent);
        return isURGSet;
    }

    private void printFlag(String flag) {
        System.out.println("TCP: \t" + flag);
    }

    private void readTCPWindow() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        System.out.println("TCP: Window = " + add2HexBytes(data));
    }

    private void readTCPChecksum() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        System.out.println("TCP: Checksum = 0x" + integerToHex(add2HexBytes(data)));
    }

    private void readTCPURG() throws IOException {
        int[] data = new int[2];
        readNBytes(data, data.length);
        System.out.println("TCP: URG = 0x" + (add2HexBytes(data)));
    }

    private void readData(String protocol) throws IOException {
        int dataCounter = 0;
        int rowCounter;
        boolean EOF = false;
        System.out.println(protocol + ": Data: (first 64 bytes)");
        while (dataCounter <= NUM_BYTES_TO_READ && !EOF) {
            System.out.print(protocol + ": ");
            for (rowCounter = 0; rowCounter < 8; rowCounter++) {
                int[] data = new int[2];
                readNBytes(data, data.length);
                if(data[0] == -1 || data[1] == -1) {
                    EOF = true;
                    break;
                }
                dataCounter += 2;
                System.out.print(integerToHex(add2HexBytes(data)) + " ");
            }
            System.out.println();
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