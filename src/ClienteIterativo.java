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

public class ClienteIterativo {

    public static final String IP_SERVIDOR = "127.0.0.1";
    public static final int PUERTO_SERVIDOR = 5000;
    private static PublicKey serverPublicKey;

    public static void main(String[] args) throws Exception {
        System.out.println("Cliente Iterativo iniciando...");

        cargarLlaveServidor();

        List<Integer> keys = new ArrayList<>();
        Map<Integer, String[]> servicios = null;

        // ====== PRIMERA CONEXIÓN: solo para recibir la tabla ======
        Socket socketTabla = new Socket(IP_SERVIDOR, PUERTO_SERVIDOR);
        DataInputStream inTabla = new DataInputStream(socketTabla.getInputStream());
        DataOutputStream outTabla = new DataOutputStream(socketTabla.getOutputStream());

        // Diffie-Hellman
        KeyPair clientDH = DHhelper.generarLlaveDH();
        BigInteger p = DHhelper.getP(clientDH);
        BigInteger g = DHhelper.getG(clientDH);

        byte[] pBytes = p.toByteArray();
        outTabla.writeInt(pBytes.length);
        outTabla.write(pBytes);

        byte[] gBytes = g.toByteArray();
        outTabla.writeInt(gBytes.length);
        outTabla.write(gBytes);

        int serverPubLen = inTabla.readInt();
        byte[] serverPubKeyEncoded = new byte[serverPubLen];
        inTabla.readFully(serverPubKeyEncoded);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyEncoded));

        byte[] myPubKeyEncoded = clientDH.getPublic().getEncoded();
        outTabla.writeInt(myPubKeyEncoded.length);
        outTabla.write(myPubKeyEncoded);

        byte[] sharedSecret = DHhelper.generarSecretoCompartido(clientDH.getPrivate(), serverPubKey);

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);

        SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
        SecretKey hmacKey = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HmacSHA256");

        int ivLen = inTabla.readInt();
        byte[] ivBytes = new byte[ivLen];
        inTabla.readFully(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        int tablaLen = inTabla.readInt();
        byte[] tablaCifrada = new byte[tablaLen];
        inTabla.readFully(tablaCifrada);

        int firmaLen = inTabla.readInt();
        byte[] firma = new byte[firmaLen];
        inTabla.readFully(firma);

        int hmacLen = inTabla.readInt();
        byte[] hmac = new byte[hmacLen];
        inTabla.readFully(hmac);

        // Validar tabla
        byte[] recalculatedHmac = CriptUtilities.calcularHMAC(tablaCifrada, hmacKey);
        if (!Arrays.equals(hmac, recalculatedHmac)) {
            System.out.println("[ERROR] HMAC inválido en tabla.");
            socketTabla.close();
            return;
        }

        byte[] tablaBytes = CriptUtilities.decryptAES(tablaCifrada, aesKey, iv);
        if (!CriptUtilities.verificarFirma(tablaBytes, firma, serverPublicKey)) {
            System.out.println("[ERROR] Firma inválida en tabla.");
            socketTabla.close();
            return;
        }

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(tablaBytes));
        servicios = (Map<Integer, String[]>) ois.readObject();
        keys = new ArrayList<>(servicios.keySet());

        socketTabla.close();
        System.out.println("Servicios recibidos correctamente.");

        Random random = new Random();

        // ====== 32 consultas: una conexión por consulta ======
        for (int i = 1; i <= 32; i++) {
            int servicioElegido = keys.get(random.nextInt(keys.size()));
            System.out.println("\nConsulta #" + i + ": solicitando servicio ID " + servicioElegido);

            Socket socketConsulta = new Socket(IP_SERVIDOR, PUERTO_SERVIDOR);
            DataInputStream in = new DataInputStream(socketConsulta.getInputStream());
            DataOutputStream out = new DataOutputStream(socketConsulta.getOutputStream());

            // Hacemos Diffie-Hellman otra vez
            KeyPair clientDHConsulta = DHhelper.generarLlaveDH();
            p = DHhelper.getP(clientDHConsulta);
            g = DHhelper.getG(clientDHConsulta);

            pBytes = p.toByteArray();
            out.writeInt(pBytes.length);
            out.write(pBytes);

            gBytes = g.toByteArray();
            out.writeInt(gBytes.length);
            out.write(gBytes);

            serverPubLen = in.readInt();
            serverPubKeyEncoded = new byte[serverPubLen];
            in.readFully(serverPubKeyEncoded);
            serverPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyEncoded));

            myPubKeyEncoded = clientDHConsulta.getPublic().getEncoded();
            out.writeInt(myPubKeyEncoded.length);
            out.write(myPubKeyEncoded);

            sharedSecret = DHhelper.generarSecretoCompartido(clientDHConsulta.getPrivate(), serverPubKey);
            digest = sha512.digest(sharedSecret);

            aesKey = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
            hmacKey = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HmacSHA256");

            ivLen = in.readInt();
            ivBytes = new byte[ivLen];
            in.readFully(ivBytes);
            iv = new IvParameterSpec(ivBytes);

            tablaLen = in.readInt();
            tablaCifrada = new byte[tablaLen];
            in.readFully(tablaCifrada);

            firmaLen = in.readInt();
            firma = new byte[firmaLen];
            in.readFully(firma);

            hmacLen = in.readInt();
            hmac = new byte[hmacLen];
            in.readFully(hmac);

            recalculatedHmac = CriptUtilities.calcularHMAC(tablaCifrada, hmacKey);
            if (!Arrays.equals(hmac, recalculatedHmac)) {
                System.out.println("[ERROR] HMAC inválido en tabla.");
                socketConsulta.close();
                return;
            }

            tablaBytes = CriptUtilities.decryptAES(tablaCifrada, aesKey, iv);
            if (!CriptUtilities.verificarFirma(tablaBytes, firma, serverPublicKey)) {
                System.out.println("[ERROR] Firma inválida en tabla.");
                socketConsulta.close();
                return;
            }

            // Solicitar el servicio
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(servicioElegido);
            oos.flush();
            byte[] seleccionBytes = bos.toByteArray();

            byte[] seleccionCifrada = CriptUtilities.encryptAES(seleccionBytes, aesKey, iv);
            byte[] seleccionHmac = CriptUtilities.calcularHMAC(seleccionCifrada, hmacKey);

            out.writeInt(seleccionHmac.length);
            out.write(seleccionHmac);

            out.writeInt(seleccionCifrada.length);
            out.write(seleccionCifrada);

            // Recibir respuesta
            int hmacRespuestaLen = in.readInt();
            byte[] hmacRespuesta = new byte[hmacRespuestaLen];
            in.readFully(hmacRespuesta);

            int respuestaCifradaLen = in.readInt();
            byte[] respuestaCifrada = new byte[respuestaCifradaLen];
            in.readFully(respuestaCifrada);

            byte[] recalculatedHmacRespuesta = CriptUtilities.calcularHMAC(respuestaCifrada, hmacKey);
            if (!Arrays.equals(hmacRespuesta, recalculatedHmacRespuesta)) {
                System.out.println("[ERROR] HMAC inválido en respuesta.");
                socketConsulta.close();
                return;
            }

            byte[] respuestaBytes = CriptUtilities.decryptAES(respuestaCifrada, aesKey, iv);

            ObjectInputStream respuestaOis = new ObjectInputStream(new ByteArrayInputStream(respuestaBytes));
            String[] datosServicio = (String[]) respuestaOis.readObject();

            System.out.println("IP: " + datosServicio[1] + ", Puerto: " + datosServicio[2]);

            socketConsulta.close();
        }

        System.out.println("\nTodas las consultas completadas exitosamente.");
    }

    private static void cargarLlaveServidor() throws Exception {
        byte[] publicBytes = Files.readAllBytes(Paths.get("public_key.key"));
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        serverPublicKey = kf.generatePublic(publicSpec);
    }
}
