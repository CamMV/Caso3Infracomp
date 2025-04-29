import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {

    public static final String IP_SERVIDOR = "127.0.0.1";
    public static final int PUERTO_SERVIDOR = 5000;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) throws Exception {
        System.out.println("Cliente iniciando conexión...");

        cargarLlaveServidor();

        Socket socket = new Socket(IP_SERVIDOR, PUERTO_SERVIDOR);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        System.out.println("0.a) Cargando llave pública del servidor...");

        System.out.println("1) Comenzando negociación Diffie-Hellman...");

        KeyPair clientDH = DiffieHellmanHelper.generateDHKeyPair();
        BigInteger p = DiffieHellmanHelper.getPrime(clientDH);
        BigInteger g = DiffieHellmanHelper.getGenerator(clientDH);

        byte[] pBytes = p.toByteArray();
        out.writeInt(pBytes.length);
        out.write(pBytes);

        byte[] gBytes = g.toByteArray();
        out.writeInt(gBytes.length);
        out.write(gBytes);

        System.out.println("2) Recibiendo llave pública del servidor...");
        int serverPubLen = in.readInt();
        byte[] serverPubKeyEncoded = new byte[serverPubLen];
        in.readFully(serverPubKeyEncoded);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyEncoded));

        System.out.println("3) Enviando llave pública del cliente...");
        byte[] myPubKeyEncoded = clientDH.getPublic().getEncoded();
        out.writeInt(myPubKeyEncoded.length);
        out.write(myPubKeyEncoded);

        System.out.println("4) Calculando llave secreta de sesión...");
        byte[] sharedSecret = DiffieHellmanHelper.generateSharedSecret(clientDH.getPrivate(), serverPubKey);

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);

        SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
        SecretKey hmacKey = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HmacSHA256");

        System.out.println("5) Recibiendo tabla de servicios cifrada...");

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

        byte[] recalculatedHmac = CryptoUtils.calculateHMAC(tablaCifrada, hmacKey);

        if (!Arrays.equals(hmac, recalculatedHmac)) {
            System.out.println("[ERROR] HMAC inválido en tabla recibida.");
            socket.close();
            return;
        }

        byte[] tablaBytes = CryptoUtils.decryptAES(tablaCifrada, aesKey, iv);

        if (!CryptoUtils.verifySignature(tablaBytes, firma, serverPublicKey)) {
            System.out.println("[ERROR] Firma inválida en tabla recibida.");
            socket.close();
            return;
        }

        System.out.println("5.b) Tabla recibida y verificada correctamente.");

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(tablaBytes));
        Map<Integer, String[]> servicios = (Map<Integer, String[]>) ois.readObject();

        System.out.println("\nServicios disponibles:");
        for (Map.Entry<Integer, String[]> entry : servicios.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue()[0]);
        }

        // Elegir servicio manualmente
        Scanner scanner = new Scanner(System.in);
        int servicioElegido = -1;
        do {
            System.out.print("\nIngrese el número del servicio que desea consultar: ");
            servicioElegido = scanner.nextInt();
            if (!servicios.containsKey(servicioElegido)) {
                System.out.println("Servicio no válido, intente nuevamente.");
                servicioElegido = -1;
            }
        } while (servicioElegido == -1);

        System.out.println("6) Enviando selección de servicio: " + servicioElegido);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(servicioElegido);
        oos.flush();
        byte[] seleccionBytes = bos.toByteArray();

        byte[] seleccionCifrada = CryptoUtils.encryptAES(seleccionBytes, aesKey, iv);
        byte[] seleccionHmac = CryptoUtils.calculateHMAC(seleccionCifrada, hmacKey);

        out.writeInt(seleccionHmac.length);
        out.write(seleccionHmac);

        out.writeInt(seleccionCifrada.length);
        out.write(seleccionCifrada);

        System.out.println("7) Esperando respuesta del servidor...");

        int hmacRespuestaLen = in.readInt();
        byte[] hmacRespuesta = new byte[hmacRespuestaLen];
        in.readFully(hmacRespuesta);

        int respuestaCifradaLen = in.readInt();
        byte[] respuestaCifrada = new byte[respuestaCifradaLen];
        in.readFully(respuestaCifrada);

        byte[] recalculatedHmacRespuesta = CryptoUtils.calculateHMAC(respuestaCifrada, hmacKey);

        if (!Arrays.equals(hmacRespuesta, recalculatedHmacRespuesta)) {
            System.out.println("[ERROR] HMAC inválido en respuesta.");
            socket.close();
            return;
        }

        byte[] respuestaBytes = CryptoUtils.decryptAES(respuestaCifrada, aesKey, iv);

        ObjectInputStream respuestaOis = new ObjectInputStream(new ByteArrayInputStream(respuestaBytes));
        String[] datosServicio = (String[]) respuestaOis.readObject();

        System.out.println("\nServicio seleccionado:");
        System.out.println("IP: " + datosServicio[1]);
        System.out.println("Puerto: " + datosServicio[2]);

        System.out.println("8) Comunicación finalizada correctamente.");

        socket.close();
    }

    private static void cargarLlaveServidor() throws Exception {
        byte[] publicBytes = Files.readAllBytes(Paths.get("public_key.der"));
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        serverPublicKey = kf.generatePublic(publicSpec);
    }
}
