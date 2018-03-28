/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto;

import java.awt.Component;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.swing.JOptionPane;

/**
 *
 * @author Hieu Tran Trung 
 */
public class DES {
    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES";
    //Encrypt Function
    public static void encrypt(String key, File inputFile, File outputFile)
            throws CryptoException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }
    
    //Decrypt Function
    public static void decrypt(String key, File inputFile, File outputFile)
            throws CryptoException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }
    
    //General Function
    private static void doCrypto(int cipherMode, String key, File inputFile, File outputFile) 
            throws CryptoException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        try {
            DESKeySpec dks = new DESKeySpec(key.getBytes());
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey desKey = skf.generateSecret(dks);
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, desKey);
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
             
            byte[] outputBytes = cipher.doFinal(inputBytes);
             
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
             
            inputStream.close();
            outputStream.close();
            
        } catch ( NoSuchPaddingException    | NoSuchAlgorithmException
                | InvalidKeyException       | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }
}
