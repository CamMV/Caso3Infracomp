import java.nio.file.*;
import java.security.*;

public class KeyGenerator {

    public static final int TAMANIO = 1024; // bits
    public static void main(String[] args) throws Exception {
        // Generar par de llaves
        KeyPairGenerator KeyGenerator = KeyPairGenerator.getInstance("RSA");
        KeyGenerator.initialize(TAMANIO);
        KeyPair keyPair = KeyGenerator.generateKeyPair();

        // Guardar llave privada en archivo
        PrivateKey privateKey = keyPair.getPrivate();
        Files.write(Paths.get("private_key.key"), privateKey.getEncoded());

        // Guardar llave pública en archivo
        PublicKey publicKey = keyPair.getPublic();
        Files.write(Paths.get("public_key.key"), publicKey.getEncoded());

        System.out.println("¡Llaves generadas exitosamente!");
    }
}
