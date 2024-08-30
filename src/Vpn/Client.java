package Vpn;

import java.net.Socket;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    public static void main(String[] args) {
        String host = "localhost";
        int port = 5000;

        try (Socket socket = new Socket(host, port)) {
            System.out.println("Connected to server.");

            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();

            // Receive server's public key
            byte[] serverPubKeyEnc = new byte[4096];
            int serverKeyLength = input.read(serverPubKeyEnc);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
            PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);

            // Generate client's key pair
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(2048);
            KeyPair clientKeyPair = keyPairGen.generateKeyPair();

            // Send client's public key
            byte[] clientPubKeyEnc = clientKeyPair.getPublic().getEncoded();
            output.write(clientPubKeyEnc);

            // Generate shared secret
            KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
            keyAgree.init(clientKeyPair.getPrivate());
            keyAgree.doPhase(serverPublicKey, true);
            byte[] sharedSecret = keyAgree.generateSecret();

            SecretKey aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
            System.out.println("Shared secret key generated.");

            // Receive IV from server
            byte[] ivBytes = new byte[16];
            input.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Receive and decrypt message
            byte[] encryptedMessage = new byte[256]; // Adjust size as needed
            int encryptedLength = input.read(encryptedMessage);
            byte[] actualEncryptedMessage = new byte[encryptedLength];
            System.arraycopy(encryptedMessage, 0, actualEncryptedMessage, 0, encryptedLength);

            byte[] decryptedMessage = EncryptionUtil.decrypt(actualEncryptedMessage, aesKey, iv);
            System.out.println("Decrypted message from server: " + new String(decryptedMessage));

            socket.close();
            System.out.println("Connection closed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

