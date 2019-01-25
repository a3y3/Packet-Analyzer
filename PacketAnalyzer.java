import java.io.*;
import java.util.Scanner;

class PacketAnalyzer {
    private File dataFile;
    byte buffer[] = new byte[1024];

    PacketAnalyzer(File dataFile) {
        this.dataFile = dataFile;
    }

    void analyze() throws IOException {
        DataInputStream  in =
                new DataInputStream(new FileInputStream(dataFile));
        while(in.read(buffer) != -1){
            byte networkByte = buffer[0];
            System.out.print(networkByte + " ");
        }
    }

}

class pktanalyzer {
    public static void main(String[] args) throws IOException {
        try {
            String fileName = args[0];
            File file = new File(fileName);
            if (!file.exists()) {
                throw new FileNotFoundException();
            }
            PacketAnalyzer packetAnalyzer = new PacketAnalyzer(file);
            packetAnalyzer.analyze();
        }catch (ArrayIndexOutOfBoundsException a){
            System.err.println("Usage: java pktanalyzer <file>");
        }
    }
}