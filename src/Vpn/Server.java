package Vpn;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Server {

    public static void main(String[] args) {
    int port=5000;
    try(ServerSocket serverSocket=new ServerSocket(port)){
        System.out.println("Vpn.Server started. waiting for client....");
        Socket socket=serverSocket.accept();
        System.out.println("Vpn.Client Connected.");

        InputStream input=socket.getInputStream();
        OutputStream output=socket.getOutputStream();

        //Generate server's key pair
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(2048);
        KeyPair serverKeyPair=keyPairGenerator.generateKeyPair();

        //send server's public key
        byte[] serverPubKeyEnc=serverKeyPair.getPublic().getEncoded();
        output.write(serverPubKeyEnc);

        //receive client's public key
        byte[] clientPubKeyEnc=new byte[4096];
        int clientKeyLength=input.read(clientPubKeyEnc);

        KeyFactory keyFactory=KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(clientPubKeyEnc);
        PublicKey clientPublicKey= keyFactory.generatePublic(x509EncodedKeySpec);

        //Generate shared secret
        KeyAgreement keyAgreement=KeyAgreement.getInstance("DH");
        keyAgreement.init(serverKeyPair.getPrivate());
        keyAgreement.doPhase(clientPublicKey,true);
        byte[] sharedSecret=keyAgreement.generateSecret();

        SecretKey aesKey=new SecretKeySpec(sharedSecret,0,16,"AES");
        System.out.println("Shared secret key generated.");

        // Generate IV and send to client
        IvParameterSpec iv = EncryptionUtil.generateIV();
        output.write(iv.getIV());
//Encrypt and send
        String message="Hello from server!";
        byte[]  encryptedMessage= EncryptionUtil.encrypt(message.getBytes(),aesKey,iv);
        output.write(encryptedMessage);

    socket.close();
    System.out.println("Connected Closed");
    }catch(Exception e){
        System.out.println(e);
    }
    }
}
