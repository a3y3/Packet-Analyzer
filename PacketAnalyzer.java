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
    }

    private String integerToHex(int value){
        String hex = Integer.toHexString(value);
        if (hex.length() == 1){
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
        while (counter < 2){
            int destination = in.read();
            System.out.print(integerToHex(destination));
            counter++;
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