import java.io.*;

class PacketAnalyzer {
    private File dataFile;
    private int[] buffer;

    PacketAnalyzer(File dataFile) {
        this.dataFile = dataFile;
        int length = (int) dataFile.length();
        this.buffer = new int[length];
    }

    void analyze() throws IOException {
        DataInputStream in =
                new DataInputStream(new FileInputStream(dataFile));
        fillArray(in);
        int i = 0;
        while (i < buffer.length) {
            System.out.println(buffer[i]);
            i++;
        }
    }

    private void fillArray(DataInputStream in) throws IOException {
        int b;
        int i = 0;
        while ((b = in.read()) != -1) {
            buffer[i++] = b;
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
        } catch (ArrayIndexOutOfBoundsException a) {
            System.err.println("Usage: java pktanalyzer <file>");
        }
    }
}