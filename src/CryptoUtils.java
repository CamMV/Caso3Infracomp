import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoUtils {

    // Cifrar con AES
    public static byte[] encryptAES(byte[] plaintext, SecretKey aesKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        return cipher.doFinal(plaintext);
    }

    // Descifrar con AES
    public static byte[] decryptAES(byte[] ciphertext, SecretKey aesKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
        return cipher.doFinal(ciphertext);
    }

    // Firmar datos con RSA
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    // Verificar firma RSA
    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    // Cifrar con RSA
    public static byte[] encryptRSA(byte[] plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    // Descifrar con RSA
    public static byte[] decryptRSA(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    // Calcular HMAC
    public static byte[] calculateHMAC(byte[] data, SecretKey hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(data);
    }

    // Convertir llave AES a SecretKeySpec
    public static SecretKey getAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Crear un IV aleatorio de 16 bytes
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Generar llave HMAC desde bytes
    public static SecretKey getHMACKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

}

