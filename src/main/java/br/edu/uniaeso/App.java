package br.edu.uniaeso;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class App {
    public static void main(String[] args) {
        String secretMessage = "Fábio Chicout";
        String encryptedMessage = null;
        RSAWrapper rsaw = new RSAWrapper();
        try {
            rsaw.setRsaKeys(rsaw.generateKeys());
            rsaw.savePrivateKey();
            rsaw.savePublicKey();
            encryptedMessage = rsaw.encrypt(secretMessage);
            System.out.println(encryptedMessage);
            System.out.println(rsaw.decrypt(encryptedMessage));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }
}
