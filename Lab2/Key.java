import java.math.BigInteger;

public class Key {
    final BigInteger Modulus;
    final BigInteger Exponent;

    Key(BigInteger mod, BigInteger exp){
        this.Modulus = mod;
        this.Exponent = exp;
    }

    
}