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



class BcECDSAVerify {
    
    public static void main(String[] args) throws Exception {

	if (args.length != 3) {
	    System.out.println("Usage ./BcECDSAVerify <message> <sig> <pk>");
	    System.exit(0);
	}

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);	

	/* Import pk */
	String pkHex = args[2];
	byte[] pkB = Hex.decode(pkHex);

	/* Import sig */
	String sigHex = args[1];
        byte[] sigB = Hex.decode(sigHex);
	
	/* Create a public key object from the raw bytes */
        KeyFactory factory = KeyFactory.getInstance("EC", provider);
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint curvePoints = params.getCurve().decodePoint(pkB);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(curvePoints, params);
        ECPublicKey pk = (ECPublicKey) factory.generatePublic(pubSpec);

        byte[] messageBytes = args[0].getBytes(StandardCharsets.UTF_8);
	
	/* Verify */
        Signature verifier = Signature.getInstance("SHA256withECDSA", provider);
        verifier.initVerify(pk);
        verifier.update(messageBytes);
        Boolean result = verifier.verify(sigB);
        System.out.println("Verifying libsecp256k1 signature: " + (result ? "True" : "False"));
    }
    
}
