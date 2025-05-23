import java.math.BigInteger;
import java.security.*;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DHhelper {

    public static final int PRIME_SIZE = 1024; // bits

    public static KeyPair generarLlaveKeyPair(BigInteger p, BigInteger g) throws Exception {
        DHParameterSpec dhSpec = new DHParameterSpec(p, g);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }

    public static byte[] generarSecretoCompartido(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        return keyAgree.generateSecret();
    }

    public static KeyPair generarLlaveDH() throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(PRIME_SIZE);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }

    public static BigInteger getP(KeyPair keyPair) throws Exception {
        DHPublicKey pubKey = (DHPublicKey) keyPair.getPublic();
        return pubKey.getParams().getP();
    }

    public static BigInteger getG(KeyPair keyPair) throws Exception {
        DHPublicKey pubKey = (DHPublicKey) keyPair.getPublic();
        return pubKey.getParams().getG();
    }
}

