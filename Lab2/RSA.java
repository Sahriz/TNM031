import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class RSA {

    public static BigInteger encrypt(String message, Key key){
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8); //translate String to bytecode
        byte[] encodedBytes = new byte[messageBytes.length + 1]; //
        encodedBytes[0] = 1;

        System.arraycopy(messageBytes, 0, encodedBytes, 1, messageBytes.length);
        BigInteger messageNumber = new BigInteger(1, encodedBytes); //Translate encoded bytes to a BigInteger, which can be handled mathmatically.

        if(messageNumber.compareTo(key.Modulus) >= 0){ //integer fits below n or there encryption/decryption will degenerate.
            throw new IllegalArgumentException("Message too long for one RSA block");
        }

        return messageNumber.modPow(key.Exponent, key.Modulus); // c = (m ^ e)mod(n)
    }

    public static String decrypt(BigInteger cipherText, Key key){
        if(cipherText.signum() < 0 || cipherText.compareTo(key.Modulus) >= 0){ // ciphertext has to be more than one and be smaller than n.
            throw new IllegalArgumentException("Ciphertext must be between 0 and n-1");
        }

        BigInteger decryptedValue = cipherText.modPow(key.Exponent, key.Modulus); // m = (c ^ d)mod(n)
        byte[] encodedBytes = decryptedValue.toByteArray();

        if(encodedBytes[0] != 1){ //Must start with the marker from encrypting.
            throw new IllegalArgumentException("Invalid message encoding");
        }

        return new String(
            encodedBytes,
            1,
            encodedBytes.length - 1,
            StandardCharsets.UTF_8
        );
    }

    public static KeyPair generateKeyPair(){
        SecureRandom random = new SecureRandom();                       //Supplying randomness for generated primes.

        //Initialization
        BigInteger e = BigInteger.valueOf(65537);                   //exponent used in encryption.
        BigInteger p, q, phi;                                           //p and q are secret random probable primes. 

        do{
            //probablePrime() could actually give composite numbers, but the odds are 2^(-100), so zero.
            p = BigInteger.probablePrime(1024, random);
            q = BigInteger.probablePrime(1024, random);

            phi = p.subtract(BigInteger.ONE)                            //Formula to count the amount of coprimes for n.    
            .multiply(q.subtract(BigInteger.ONE));                      // Exmaple: phi(15) = size(1, 2, 4, 7, 8, 11, 13, 14) = 8 <=> (3-1)(5-1) = 2 * 4 = 8
        }
        while(p.equals(q) || !e.gcd(phi).equals((BigInteger.ONE)));     //Make sure to not let p and q be the same secret primes, and also that e and phi are coprime.

        BigInteger n = p.multiply(q);                                   //Sets the modulus for encryption and decryption. Both keys hold this value.
        BigInteger d = e.modInverse(phi);                               //Calculated exponent to match e. Used in decryption.

        return new KeyPair(new Key(n, e), new Key(n, d));               //Public and private key.
    }
}