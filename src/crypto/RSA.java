/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

import java.awt.Component;
import java.awt.FileDialog;
import java.awt.Frame;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JOptionPane;

/**
 *
 * @author Duc Nguyen Van
 */
public class RSA {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    //Encrypt Function
    public static void encrypt(String key, File inputFile, File outputFile)
            throws CryptoException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }

    //Decrypt Function
    public static void decrypt(String key, File inputFile, File outputFile)
            throws CryptoException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }

    //General Function
    private static void doCrypto(int cipherMode, String key, File inputFile, File outputFile)
            throws CryptoException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException {
        try {
            KeyPair kp;
            PublicKey pub = null;
            PrivateKey pvt = null;
            File keyFile = new File(key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            try {
                if (cipherMode == Cipher.DECRYPT_MODE && keyFile.getName().endsWith(".key")) {
                    byte[] bytes = Files.readAllBytes(keyFile.toPath());
                    PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
                    pvt = kf.generatePrivate(ks);
                } else if (cipherMode == Cipher.ENCRYPT_MODE && keyFile.getName().endsWith(".pub")) {
                    byte[] bytes = Files.readAllBytes(keyFile.toPath());
                    X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
                    pub = kf.generatePublic(ks);
                }
            } catch (InvalidKeySpecException e) {
                throw new CryptoException("Invalid Key", e);
            }
            /*
            File keyFolder = new File(key);
            File[] listOfFiles = keyFolder.listFiles();
            for (int i = 0; i < listOfFiles.length; i++) {
                File file = listOfFiles[i];
                if (file.isFile() && file.getName().endsWith(".pub")) { //read public key
                    byte[] bytes = Files.readAllBytes(file.toPath());
                    X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
                    pub = kf.generatePublic(ks);
                    break;
                }
            }
            for (int i = 0; i < listOfFiles.length; i++) {
                File file = listOfFiles[i];
                if (file.isFile() && file.getName().endsWith(".key")) { //read private key
                    byte[] bytes = Files.readAllBytes(file.toPath());
                    PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
                    pvt = kf.generatePrivate(ks);
                    break;
                }
            }
             */
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            if (cipherMode == Cipher.ENCRYPT_MODE) {
                cipher.init(cipherMode, pub);
            } else {
                cipher.init(cipherMode, pvt);
            }
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }
}
