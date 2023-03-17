import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.SecureRandom;

class BcECDSASign {
    
    public static void main(String[] args) throws Exception {

	if (args.length != 1) {
	    System.out.println("Usage ./BcECDSAVerify <message>");
	    System.exit(0);
	}	

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
	
	/* Create the key pair objects */
	byte[] skBytes = new byte[32];
	SecureRandom secureRandom = SecureRandom.getInstance("NativePRNG");
	secureRandom.nextBytes(skBytes);	
        KeyFactory factory = KeyFactory.getInstance("EC", provider);
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
	BigInteger d = new BigInteger(1, skBytes);
        ECParameterSpec curveSpec = new ECParameterSpec(
							params.getCurve(),
							params.getG(),
							params.getN(),
							params.getH());
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(d, curveSpec);
        ECPrivateKey sk = (ECPrivateKey)factory.generatePrivate(privSpec);	
	ECPoint Q = params.getG()
	    .multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) sk)
		      .getD());
	ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, params);
	PublicKey pk = factory.generatePublic(pubSpec);

	/* Sign message */
        byte[] messageBytes = args[0].getBytes(StandardCharsets.UTF_8);
	Signature signer = Signature.getInstance("SHA256withECDSA", provider);
        signer.initSign(sk);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(messageBytes);
        signer.update(messageBytes);
        byte[] signature = signer.sign();

	System.out.println("Signing message: "+args[0]);
	System.out.println("Sig: "+Hex.toHexString(signature));
	System.out.println("PK: "+Hex.toHexString(Q.getEncoded(true)));

    }
    
}
