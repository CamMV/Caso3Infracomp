import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServidorPrincipal {

    // Variables globales de configuracion
    public static final int PUERTO_PRINCIPAL = 5000;
    public static final int MAX_CLIENTES = 100;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    // Tabla de servicios (ID, [Nombre, IP, Puerto])
    // ID: 1 - 4, Nombre: "Consulta vuelos", "Disponibilidad", "Costo vuelo", "Consulta vuelos"
    private static final Map<Integer, String[]> servicios = new HashMap<>();

    public static void main(String[] args) throws Exception {
        System.out.println("Servidor Principal iniciando...");
        cargarLlaves();
        cargarServicios();
        ServerSocket serverSocket = new ServerSocket(PUERTO_PRINCIPAL);

        // -----------------------------------------------------
        // Revisa el puerto (Aveces no se inicia bien el socket)
        System.out.println("Servidor principal escuchando en puerto " + PUERTO_PRINCIPAL);
        // -----------------------------------------------------

        ExecutorService pool = Executors.newFixedThreadPool(MAX_CLIENTES);
        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("\nNuevo cliente conectado desde " + clientSocket.getInetAddress());
            ServidorDelegado delegado = new ServidorDelegado(clientSocket, privateKey, publicKey, servicios);
            pool.execute(delegado);
        }
    }

    private static void cargarLlaves() throws Exception {
        // Paso 0.a
        System.out.println("0.a) Cargando llave privada del servidor...");
        byte[] privateBytes = Files.readAllBytes(Paths.get("private_key.key"));
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(privateSpec);

        // Paso 0.b
        System.out.println("0.b) Cargando llave pública del servidor...");
        byte[] publicBytes = Files.readAllBytes(Paths.get("public_key.key"));
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicBytes);
        publicKey = keyFactory.generatePublic(publicSpec);
    }

    private static void cargarServicios() {
        servicios.put(1, new String[]{"Consulta vuelos", "127.0.0.1", "6001"});
        servicios.put(2, new String[]{"Disponibilidad ", "127.0.0.1", "6001"});
        servicios.put(3, new String[]{"Costo vuelo ", "127.0.0.1", "6001"});
        servicios.put(4, new String[]{"Consulta vuelos ", "127.0.0.1", "6001"});
        System.out.println("Tabla de servicios cargada.");
    }
}
