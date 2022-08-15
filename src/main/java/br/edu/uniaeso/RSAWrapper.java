package br.edu.uniaeso;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAWrapper {

    private int rsaKeyBytes = 4096;
    private KeyPair rsaKeys;

    public int getRsaKeyBytes() {
        return rsaKeyBytes;
    }

    public KeyPair getRsaKeys() {
        return rsaKeys;
    }

    public void setRsaKeys(KeyPair rsaKeys) {
        this.rsaKeys = rsaKeys;
    }

    public void setRsaKeyBytes(int rsaKeyBytes) {
        this.rsaKeyBytes = rsaKeyBytes;
    }

    public KeyPair generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(getRsaKeyBytes());
        return generator.generateKeyPair();
    }

    public void savePublicKey() throws IOException {
        FileOutputStream fos = new FileOutputStream("public.key");
        fos.write(getRsaKeys().getPublic().getEncoded());
        fos.close();
    }

    public void savePrivateKey() throws IOException {
        FileOutputStream fos = new FileOutputStream("private.key");
        fos.write(getRsaKeys().getPrivate().getEncoded());
        fos.close();
    }

    public PublicKey readPublicKeyFromFile(String pathToPublicKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File publicKeyFile = new File(pathToPublicKey);
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public PrivateKey readPrivateKeyFromFile(String pathToPrivateKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File privateKeyFile = new File(pathToPrivateKey);
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public byte[] encrypt(byte[] secretMessage) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, readPublicKeyFromFile("public.key"));
        return encryptCipher.doFinal(secretMessage);
    }

    public String encrypt(String secretMessage) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, IOException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException {
        byte[] secretMessageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encrypt(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    public byte[] decrypt(byte[] encryptedMessage)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, readPrivateKeyFromFile("private.key"));
        return decryptCipher.doFinal(encryptedMessage);
    }

    public String decrypt(String encryptedMessage)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IOException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // Cipher decryptCipher = Cipher.getInstance("RSA");
        // decryptCipher.init(Cipher.DECRYPT_MODE, readPrivateKeyFromFile("private.key"));
        byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedMessageBytes = decrypt(encryptedMessageBytes);
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }
}