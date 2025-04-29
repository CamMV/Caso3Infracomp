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
        Socket socket = new Socket(IP_SERVIDOR, PUERTO_SERVIDOR);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // Paso 0.a
        System.out.println("0.a) Cargando llave pública del servidor...");
        cargarLlaveServidor();

        // Paso 1
        System.out.println("1) Comenzando negociación Diffie-Hellman...");
        KeyPair clientDH = DHhelper.generarLlaveDH();
        BigInteger p = DHhelper.getP(clientDH);
        BigInteger g = DHhelper.getG(clientDH);

        // Calculo P
        byte[] pBytes = p.toByteArray();
        out.writeInt(pBytes.length);
        out.write(pBytes);

        // Calculo G
        byte[] gBytes = g.toByteArray();
        out.writeInt(gBytes.length);
        out.write(gBytes);

        // Paso 2
        System.out.println("2) Recibiendo llave pública del servidor...");
        int serverPubLen = in.readInt();
        byte[] serverPubKeyEncoded = new byte[serverPubLen];
        in.readFully(serverPubKeyEncoded);

        //Generar llaves
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyEncoded));

        // Paso 3
        System.out.println("3) Enviando llave pública del cliente...");
        byte[] myPubKeyEncoded = clientDH.getPublic().getEncoded();
        out.writeInt(myPubKeyEncoded.length);
        out.write(myPubKeyEncoded);

        // Paso 4
        System.out.println("4) Calculando llave secreta de sesión...");
        byte[] sharedSecret = DHhelper.generarSecretoCompartido(clientDH.getPrivate(), serverPubKey);

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);

        SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
        SecretKey hmacKey = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HmacSHA256");

        // Paso 5
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

        byte[] recalculatedHmac = CriptUtilities.calcularHMAC(tablaCifrada, hmacKey);
        if (!Arrays.equals(hmac, recalculatedHmac)) {
            System.out.println("[ERROR] HMAC inválido en tabla recibida.");
            socket.close();
            return;
        }
        byte[] tablaBytes = CriptUtilities.decryptAES(tablaCifrada, aesKey, iv);
        if (!CriptUtilities.verificarFirma(tablaBytes, firma, serverPublicKey)) {
            System.out.println("[ERROR] Firma inválida en tabla recibida.");
            socket.close();
            return;
        }

        // Paso 5.b
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

        // Paso 6
        System.out.println("6) Enviando selección de servicio: " + servicioElegido);

        ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);
        objectOutput.writeObject(servicioElegido);
        objectOutput.flush();

        byte[] seleccionBytes = byteOutput.toByteArray();
        byte[] seleccionCifrada = CriptUtilities.encryptAES(seleccionBytes, aesKey, iv);
        byte[] seleccionHmac = CriptUtilities.calcularHMAC(seleccionCifrada, hmacKey);

        out.writeInt(seleccionHmac.length);
        out.write(seleccionHmac);

        out.writeInt(seleccionCifrada.length);
        out.write(seleccionCifrada);

        // Paso 7
        System.out.println("7) Esperando respuesta del servidor...");

        int hmacRespuestaLen = in.readInt();
        byte[] hmacRespuesta = new byte[hmacRespuestaLen];
        in.readFully(hmacRespuesta);

        int respuestaCifradaLen = in.readInt();
        byte[] respuestaCifrada = new byte[respuestaCifradaLen];
        in.readFully(respuestaCifrada);

        byte[] recalculatedHmacRespuesta = CriptUtilities.calcularHMAC(respuestaCifrada, hmacKey);
        if (!Arrays.equals(hmacRespuesta, recalculatedHmacRespuesta)) {
            System.out.println("[ERROR] HMAC inválido en respuesta.");
            socket.close();
            return;
        }
        byte[] respuestaBytes = CriptUtilities.decryptAES(respuestaCifrada, aesKey, iv);

        ObjectInputStream respuestaOis = new ObjectInputStream(new ByteArrayInputStream(respuestaBytes));
        String[] datosServicio = (String[]) respuestaOis.readObject();

        System.out.println("\nServicio seleccionado:");
        System.out.println("IP: " + datosServicio[1]);
        System.out.println("Puerto: " + datosServicio[2]);

        // Paso 8
        System.out.println("8) Comunicación finalizada correctamente.");

        socket.close();
    }

    private static void cargarLlaveServidor() throws Exception {
        byte[] publicBytes = Files.readAllBytes(Paths.get("public_key.key"));
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        serverPublicKey = kf.generatePublic(publicSpec);
    }
}
