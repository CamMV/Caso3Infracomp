import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.nio.file.*;

public class ClienteConcurrente {

    public static final String IP_SERVIDOR = "127.0.0.1";
    public static final int PUERTO_SERVIDOR = 5000;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) throws Exception {
        cargarLlaveServidor();

        Scanner scanner = new Scanner(System.in);
        System.out.println("Seleccione el número de clientes concurrentes:");
        System.out.println("1) 4 clientes");
        System.out.println("2) 16 clientes");
        System.out.println("3) 32 clientes");
        System.out.println("4) 64 clientes");
        System.out.print("Opción: ");

        int opcion = scanner.nextInt();
        int numClientes = 0;

        switch (opcion) {
            case 1: numClientes = 4; break;
            case 2: numClientes = 16; break;
            case 3: numClientes = 32; break;
            case 4: numClientes = 64; break;
            default:
                System.out.println("Opción inválida. Terminando programa.");
                System.exit(0);
        }

        ExecutorService pool = Executors.newFixedThreadPool(numClientes);

        System.out.println("\nIniciando " + numClientes + " clientes concurrentes...\n");

        for (int i = 0; i < numClientes; i++) {
            pool.execute(new Runnable() {
                public void run() {
                    try {
                        flujoClienteConcurrenteSimple();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
        }

        pool.shutdown();
    }

    private static void flujoClienteConcurrenteSimple() throws Exception {
        Socket socket = new Socket(IP_SERVIDOR, PUERTO_SERVIDOR);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Diffie-Hellman
        KeyPair clientDH = DiffieHellmanHelper.generateDHKeyPair();
        BigInteger p = DiffieHellmanHelper.getPrime(clientDH);
        BigInteger g = DiffieHellmanHelper.getGenerator(clientDH);

        byte[] pBytes = p.toByteArray();
        out.writeInt(pBytes.length);
        out.write(pBytes);

        byte[] gBytes = g.toByteArray();
        out.writeInt(gBytes.length);
        out.write(gBytes);

        int serverPubLen = in.readInt();
        byte[] serverPubKeyEncoded = new byte[serverPubLen];
        in.readFully(serverPubKeyEncoded);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyEncoded));

        byte[] myPubKeyEncoded = clientDH.getPublic().getEncoded();
        out.writeInt(myPubKeyEncoded.length);
        out.write(myPubKeyEncoded);

        byte[] sharedSecret = DiffieHellmanHelper.generateSharedSecret(clientDH.getPrivate(), serverPubKey);

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);

        SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
        SecretKey hmacKey = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HmacSHA256");

        // Recibir tabla
        int ivLen = in.readInt();
        byte[] ivBytes = new byte[ivLen];
        in.readFully(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        int tablaLen = in.readInt();
        byte[] tablaCifrada = new byte[tablaLen];
        in.readFully(tablaCifrada);

        int firmaLen = in.readInt();
        byte[] firma = new byte[firmaLen];
        in.readFully(firma);

        int hmacLen = in.readInt();
        byte[] hmac = new byte[hmacLen];
        in.readFully(hmac);

        long startHmac = System.nanoTime();
        byte[] recalculatedHmac = CryptoUtils.calculateHMAC(tablaCifrada, hmacKey);
        long endHmac = System.nanoTime();
        long tiempoHmacCliente = endHmac - startHmac;
        System.out.println("[Cliente concurrente] Tiempo de cálculo de HMAC de la tabla: " + tiempoHmacCliente + " nanosegundos");

        if (!Arrays.equals(hmac, recalculatedHmac)) {
            
            System.out.println("[ERROR] Cliente concurrente: HMAC de tabla inválido.");
            socket.close();
            return;
        }

        System.out.println("[Cliente concurrente] HMAC verificado correctamente ✅");

        byte[] tablaBytes = CryptoUtils.decryptAES(tablaCifrada, aesKey, iv);

        if (!CryptoUtils.verifySignature(tablaBytes, firma, serverPublicKey)) {
            System.out.println("[ERROR] Cliente concurrente: Firma de tabla inválida.");
            socket.close();
            return;
        }

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(tablaBytes));
        Map<Integer, String[]> servicios = (Map<Integer, String[]>) ois.readObject();

        System.out.println("Listado de servicios:");
        for (Map.Entry<Integer, String[]> entry : servicios.entrySet()) {
            System.out.println("Servicio ID: " + entry.getKey() +
                               ", Nombre: " + entry.getValue()[0] +
                               ", IP: " + entry.getValue()[1] +
                               ", Puerto: " + entry.getValue()[2]);
        }

        socket.close();
    }

    private static void cargarLlaveServidor() throws Exception {
        byte[] publicBytes = Files.readAllBytes(Paths.get("public_key.der"));
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        serverPublicKey = kf.generatePublic(publicSpec);
    }
}
