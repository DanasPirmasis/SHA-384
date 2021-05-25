package hash;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SHA384 {

    public static void main(String[] args) {
        Path path = Paths.get("input.txt");

        try {
            byte[] input = Files.readAllBytes(path);
            byte[] paddedArray = messagePadding(input);
            long[][] chunks = breakMessageIntoChunks(paddedArray);
            long[][] expandedChunks = expandChunks(chunks);
            long[] workingVariables = Constants.H;

            for (int i = 0; i < expandedChunks.length; i++) {
                long a = workingVariables[0];
                long b = workingVariables[1];
                long c = workingVariables[2];
                long d = workingVariables[3];
                long e = workingVariables[4];
                long f = workingVariables[5];
                long g = workingVariables[6];
                long h = workingVariables[7];

                for (int j = 0; j < expandedChunks[i].length; j++) {
                    long t1 = h + Sum1(e) + Ch(e, f, g) + Constants.K[j] + expandedChunks[i][j];
                    long t2 = Sum0(a) + Maj(a, b, c);

                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                workingVariables[0] += a;
                workingVariables[1] += b;
                workingVariables[2] += c;
                workingVariables[3] += d;
                workingVariables[4] += e;
                workingVariables[5] += f;
                workingVariables[6] += g;
                workingVariables[7] += h;
            }

            StringBuilder stringBuilder = new StringBuilder();

            for (int i = 0; i < 6; i++) {
                stringBuilder.append(Long.toHexString(workingVariables[i]));
            }

            System.out.println(stringBuilder.toString());
        } catch (Exception e) {
            System.out.println(e);
        }

    }

    private static long Maj(long x, long y, long z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static long Ch(long x, long y, long z) {
        return (x & y) ^ (~x & z);
    }

    private static long rotateRight(long x, long n) {
        return (x >>> n) | (x << (Long.SIZE - n));
    }

    private static long Sigma0(long x) {
        return rotateRight(x, 1) ^ rotateRight(x, 8) ^ (x >>> 7);
    }

    private static long Sigma1(long x) {
        return rotateRight(x, 19) ^ rotateRight(x, 61) ^ (x >>> 6);
    }

    private static long Sum0(long x) {
        return rotateRight(x, 28) ^ rotateRight(x, 34) ^ rotateRight(x, 39);
    }

    private static long Sum1(long x) {
        return rotateRight(x, 14) ^ rotateRight(x, 18) ^ rotateRight(x, 41);
    }

    private static long[][] expandChunks(long[][] chunks) {
        //Sis metodas iskleidzia zinutes gabalus pagal dokumentacija
        //sigma0 = ROTR(x,1) ^ ROTR(x, 8) ^ SHR(x, 7)
        //sigma1 = ROTR(x,19) ^ ROTR(x, 61) ^ SHR(x, 6)
        //Zinutes dydis po iskleidimo turi but 80
        //Pirmus 16 64bit zodzius idedam i nauja array ir tada naudojant sigma0/1 isskleidziama i 80 64 bit zodziu
        int messageScheduleSize = 80;

        long[][] messageScheduleArray = new long[chunks.length][messageScheduleSize];

        for (int i = 0; i < chunks.length; i++) {
            System.arraycopy(chunks[i], 0, messageScheduleArray[i], 0, 16);
            System.out.println();
            for (int j = 16; j < messageScheduleSize; j++) {
                long sigma0 = Sigma0(messageScheduleArray[i][j - 15]);
                long sigma1 = Sigma1(messageScheduleArray[i][j - 2]);

                messageScheduleArray[i][j] = messageScheduleArray[i][j - 16] + sigma0 + messageScheduleArray[i][j - 7] + sigma1;
            }
        }

        return messageScheduleArray;
    }

    private static long[][] breakMessageIntoChunks(byte[] paddedArray) {
        //Paddinta zinute reikia isdalinti i 1024 bitu gabalus
        //Kadangi zinute gali but bet koks 1024 kartotinis todel reikia dinamiskai ruosti masyva
        //Taigi tam pasiekti pasirinkau 2D long masyva
        //Masyvo pirmos dimensijos dydis priklauso nuo gabalu kiekio - paddedArray ilgis / 1024 bits
        //Antra dimensija visalaika bus tokio pat ilgio, nes gabalo dydis yra statinis

        int firstDimensionLength = paddedArray.length / 128;
        int secondDimensionLength = 16;
        long[][] chunks = new long[firstDimensionLength][secondDimensionLength];

        for (int i = 0; i < firstDimensionLength; i++) {
            for (int j = 0; j < secondDimensionLength; j++) {
                byte[] subArray = new byte[8];
                System.arraycopy(paddedArray, j * 8, subArray, 0, 8);

                ByteBuffer byteBuffer = ByteBuffer.wrap(subArray);
                long numberToAdd = byteBuffer.getLong();

                chunks[i][j] = numberToAdd;
            }
        }

        return chunks;
    }

    private static byte[] messagePadding(byte[] message) throws IOException {
        //messagePadding funckija padaro, kad zinute butu paruosta hashinimo procesui
        //I zinutes paruosimo procesa ieina:
        //  1. '1' pridejimas pabaigoj zinutes
        //  2. k '0' reiksmes bitu pridejimas, kad ispildytu salyga l + 1 + k = 896mod1024
        //  3. 128 bitu pridejimas kurie isreiskia zinutes ilgi
        //Kadangi naudoju byte masyva, tai reiskia kad kiekviena reiksme yra 8 bitai
        //Todel tam kad ispildyti 1 ir 3 salygas visalaika reikia prideti 17 (17*8 = 136 bits).

        int newMessageLength = message.length + 17;
        while (newMessageLength % 128 != 0) {
            newMessageLength += 1;
        }

        byte[] paddedMessage = new byte[newMessageLength];

        System.arraycopy(message, 0, paddedMessage, 0, message.length);

        paddedMessage[message.length] = (byte) 0x80;

        byte[] lengthInBytes = intToByteArray(message.length * 8);

        for (int i = 0; i < lengthInBytes.length; i++) {
            byte byteToAddToTheEnd = lengthInBytes[lengthInBytes.length - i - 1];
            paddedMessage[paddedMessage.length - i - 1] = byteToAddToTheEnd;
        }

        return paddedMessage;
    }

    private static byte[] intToByteArray(int number) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(number);
        dos.flush();
        return bos.toByteArray();
    }

}
