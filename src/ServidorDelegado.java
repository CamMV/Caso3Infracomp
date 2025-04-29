import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServidorDelegado implements Runnable {

    private Socket socket;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Map<Integer, String[]> servicios;

    public ServidorDelegado(Socket socket, PrivateKey privateKey, PublicKey publicKey, Map<Integer, String[]> servicios) {
        this.socket = socket;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.servicios = servicios;
    }

    public void run() {
        try {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            System.out.println("1) Comenzando negociación Diffie-Hellman...");

            int pLen = in.readInt();
            byte[] pBytes = new byte[pLen];
            in.readFully(pBytes);
            BigInteger p = new BigInteger(pBytes);

            int gLen = in.readInt();
            byte[] gBytes = new byte[gLen];
            in.readFully(gBytes);
            BigInteger g = new BigInteger(gBytes);

            KeyPair serverDH = DHhelper.generateKeyPair(p, g);

            System.out.println("2) Enviando llave pública del servidor...");
            byte[] myPubKeyEncoded = serverDH.getPublic().getEncoded();
            out.writeInt(myPubKeyEncoded.length);
            out.write(myPubKeyEncoded);

            System.out.println("3) Recibiendo llave pública del cliente...");
            int clientPubLen = in.readInt();
            byte[] clientPubKeyEncoded = new byte[clientPubLen];
            in.readFully(clientPubKeyEncoded);

            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey clientPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(clientPubKeyEncoded));

            System.out.println("4) Calculando llave secreta de sesión...");
            byte[] sharedSecret = DHhelper.generateSharedSecret(serverDH.getPrivate(), clientPubKey);

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret);

            SecretKey aesKey = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
            SecretKey hmacKey = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HmacSHA256");

            System.out.println("5) Firmando, cifrando y enviando tabla de servicios...");

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(servicios);
            oos.flush();
            byte[] tablaBytes = bos.toByteArray();

            byte[] firma = CriptUtilities.signData(tablaBytes, privateKey);

            IvParameterSpec iv = CriptUtilities.generateIV();
            byte[] tablaCifrada = CriptUtilities.encryptAES(tablaBytes, aesKey, iv);

            byte[] hmac = CriptUtilities.calculateHMAC(tablaCifrada, hmacKey);

            out.writeInt(iv.getIV().length);
            out.write(iv.getIV());

            out.writeInt(tablaCifrada.length);
            out.write(tablaCifrada);

            out.writeInt(firma.length);
            out.write(firma);

            out.writeInt(hmac.length);
            out.write(hmac);

            System.out.println("6) Esperando selección del cliente...");

            int hmacRecibidoLen = in.readInt();
            byte[] hmacRecibido = new byte[hmacRecibidoLen];
            in.readFully(hmacRecibido);

            int seleccionCifradaLen = in.readInt();
            byte[] seleccionCifrada = new byte[seleccionCifradaLen];
            in.readFully(seleccionCifrada);

            
            long startHmac = System.nanoTime();
            byte[] recalculatedHmac = CriptUtilities.calculateHMAC(seleccionCifrada, hmacKey);
            long endHmac = System.nanoTime();
            long tiempoHmacServidor = endHmac - startHmac;
            System.out.println("Tiempo de cálculo de HMAC en servidor (consulta): " + tiempoHmacServidor + " nanosegundos");
            if (!Arrays.equals(hmacRecibido, recalculatedHmac)) {
                
                System.out.println("[ERROR] HMAC inválido en selección");
                socket.close();
                return;
            }

            byte[] seleccionBytes = CriptUtilities.decryptAES(seleccionCifrada, aesKey, iv);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(seleccionBytes));
            Integer idSeleccionado = (Integer) ois.readObject();

            String[] datosServicio = servicios.getOrDefault(idSeleccionado, new String[]{"-1", "-1"});

            System.out.println("7) Enviando IP y puerto del servicio seleccionado...");

            ByteArrayOutputStream respuestaBos = new ByteArrayOutputStream();
            ObjectOutputStream respuestaOos = new ObjectOutputStream(respuestaBos);
            respuestaOos.writeObject(datosServicio);
            respuestaOos.flush();
            byte[] respuestaBytes = respuestaBos.toByteArray();
            // Cifrado simétrico
            long startSimetrico = System.nanoTime();
            byte[] respuestaCifrada = CriptUtilities.encryptAES(respuestaBytes, aesKey, iv);
            long endSimetrico = System.nanoTime();
            long tiempoSimetrico = endSimetrico - startSimetrico;

            // Cifrado asimétrico (solo para medir)
            long startAsimetrico = System.nanoTime();
            byte[] respuestaCifradaRSA = CriptUtilities.encryptRSA(respuestaBytes, publicKey);
            long endAsimetrico = System.nanoTime();
            long tiempoAsimetrico = endAsimetrico - startAsimetrico;

            // Reportar tiempos en consola
            System.out.println("Tiempo cifrado simétrico (AES): " + tiempoSimetrico + " nanosegundos");
            System.out.println("Tiempo cifrado asimétrico (RSA): " + tiempoAsimetrico + " nanosegundos");

            // Solo enviamos respuesta cifrada con AES
            byte[] respuestaHmac = CriptUtilities.calculateHMAC(respuestaCifrada, hmacKey);

            out.writeInt(respuestaHmac.length);
            out.write(respuestaHmac);

            out.writeInt(respuestaCifrada.length);
            out.write(respuestaCifrada);
            
            

            out.writeInt(respuestaHmac.length);
            out.write(respuestaHmac);

            out.writeInt(respuestaCifrada.length);
            out.write(respuestaCifrada);

            System.out.println("8) Finalizando conexión con cliente.");

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
