package main;

import applet.DeriveApplet;
import applet.SECP256k1;
import com.licel.jcardsim.bouncycastle.util.encoders.Hex;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

import javax.smartcardio.*;
import java.util.Random;

public class Run {
    public static void main(String[] args){
        // 1. create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, DeriveApplet.class);

        // 3. select applet
        simulator.selectApplet(appletAID);

        KeyPair ecKeypair = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
        ECPrivateKey privateKey = (ECPrivateKey) ecKeypair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) ecKeypair.getPublic();
        SECP256k1.setCurveParameters(privateKey);
        SECP256k1.setCurveParameters(publicKey);
        ecKeypair.genKeyPair();

        byte[] privBytes = new byte[32];
        privateKey.getS(privBytes, (short) 0);
        byte[] pubBytes = new byte[65];
        publicKey.getW(pubBytes, (short) 0);

        String privString = bytesToHexString(privBytes);
        String pubString = bytesToHexString(pubBytes);
        System.out.println("Private: " + privString);
        System.out.println("Public: " + pubString);

        String chainCode = generateRandomHexString(64);
        System.out.println("Chaincode: " + chainCode);

        String path = generateRandomHexString(8);
        System.out.println("Path: " + path);

        byte[] data = Hex.decode(privString + pubString + chainCode + path);

        // 4. send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0xB0, 0x01, 0x00, 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        System.out.println(new String(response.getData()));
    }

    public static String bytesToHexString(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static String generateRandomHexString(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be a positive integer");
        }

        StringBuilder sb = new StringBuilder(length);
        Random random = new Random();

        for (int i = 0; i < length; i++) {
            int randomInt = random.nextInt(16);
            sb.append(Integer.toHexString(randomInt));
        }

        return sb.toString().toUpperCase();
    }
}
