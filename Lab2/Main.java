import java.math.BigInteger;

public class Main{
    public static void main(String[] args){
        KeyPair keys = RSA.generateKeyPair(); //Generate both the private key and the public key used for encryption and decryption.

        String message = "Hello, World! There's mice on venus? Goddness."; //message to encrypt and decrypt

        BigInteger cipherTextValue = RSA.encrypt(message, keys.publicKey); //encryption
        String recoveredString = RSA.decrypt(cipherTextValue, keys.privateKey); //decryption

        //Testing
        System.out.println("Orginal: " + message);
        System.out.println("Encrypted: " + cipherTextValue);
        System.out.println("Recovered message: " + recoveredString);
        System.out.println("The original and recovered messages are the same: " + recoveredString.equals(message));
    }
}
