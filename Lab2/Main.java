import java.math.BigInteger;

public class Main{
    public static void main(String[] args){
        KeyPair keys = RSA.generateKeyPair();

        //encryption
        String message = "Hello, World! Goodbye, Venus? And hello to all the other celestial bodies, except Pluto.";

        BigInteger cipherTextValue = RSA.encrypt(message, keys.publicKey);
        String recoveredString = RSA.decrypt(cipherTextValue, keys.privateKey);

        System.out.println("Orginal: " + message);
        System.out.println("Encrypted: " + cipherTextValue);
        System.out.println("Recovered message: " + recoveredString);
        System.out.println("The original and recovered messages are the same: " + recoveredString.equals(message));
    }
}
