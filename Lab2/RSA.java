import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class RSA {
    public static void hello(){
        System.out.println("Hello from RSA!");
    }

    public static BigInteger encrypt(String message, Key key){
         byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        BigInteger messageNumber = new BigInteger(1, messageBytes);
        if(messageNumber.compareTo(key.Modulus) >= 0){
            throw new IllegalArgumentException("Message too long for one RSA block");
        }
        return messageNumber.modPow(key.Exponent, key.Modulus);
    }

    public static String decrypt(BigInteger cipherText, Key key){
        BigInteger decryptedValue = cipherText.modPow(key.Exponent, key.Modulus);
        byte[] restoredBytes = decryptedValue.toByteArray();
        return new String(restoredBytes, StandardCharsets.UTF_8);
    }

    public static KeyPair generateKeyPair(){
        SecureRandom random = new SecureRandom();

        //Initialization
        BigInteger e = BigInteger.valueOf(65537);
        BigInteger p, q, phi;

        do{
            p = BigInteger.probablePrime(1024, random);
            q = BigInteger.probablePrime(1024, random);

            phi = p.subtract(BigInteger.ONE)
            .multiply(q.subtract(BigInteger.ONE));
        }
        while(p.equals(q) || !e.gcd(phi).equals((BigInteger.ONE)));

        BigInteger n = p.multiply(q);
        BigInteger d = e.modInverse(phi);

        return new KeyPair(new Key(n, e), new Key(n, d));
    }
}