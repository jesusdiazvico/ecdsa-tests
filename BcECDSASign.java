import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.ByteArrayOutputStream;

class BcECDSASign {
    
    public static void main(String[] args) throws Exception {

	if (args.length != 1) {
	    System.out.println("Usage ./BcECDSAVerify <message>");
	    System.exit(0);
	}	

	/* Load BC provider */
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

	/* Get secp256k1 params */
	ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
	ECDomainParameters domain = new ECDomainParameters(spec.getCurve(),
							   spec.getG(),
							   spec.getN());

	/* Compute a random private key */
	byte[] skBytes = new byte[32];
	SecureRandom secureRandom = SecureRandom.getInstance("NativePRNG");
	secureRandom.nextBytes(skBytes);	
	ECPrivateKeyParameters skParms =
	    new ECPrivateKeyParameters(
				       new BigInteger(1, skBytes),
				       domain
				       );

	/* Hash the message before signing */
	byte[] messageBytes = args[0].getBytes(StandardCharsets.UTF_8);
	MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(messageBytes);

	/* Sign the message */
	ECDSASigner ecdsa = new ECDSASigner();
	ecdsa.init(true, skParms);
	BigInteger[] sig = ecdsa.generateSignature(hashBytes);
		
	/* Since BTC rejects high s values (those that are larger than the 
	   curve order/2, we compute the additive inverse of s modulo the
	   curve order, if that's the case) */	
	BigInteger rs;
	if (sig[1].compareTo(spec.getN().shiftRight(1)) >= 0) {
	    rs = spec.getN().subtract(sig[1]).mod(spec.getN());
	} else {
	    rs = sig[1];
	}

	/* Export the signature to a DER-encoded object */
	ASN1EncodableVector vector = new ASN1EncodableVector();
	vector.add(new ASN1Integer(sig[0]));
	vector.add(new ASN1Integer(rs));
	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	ASN1OutputStream asnOS = ASN1OutputStream.create(baos,ASN1Encoding.DER);
	asnOS.writeObject(new DERSequence(vector));
	asnOS.flush();
	byte[] sigBytes = baos.toByteArray();


	/* Get the public key from the private key to print it out */	
	ECPoint Q = skParms.getParameters().getG().multiply(skParms.getD());

	System.out.println("Signing message: "+args[0]);
	System.out.println("Sig: "+Hex.toHexString(sigBytes));
	System.out.println("PK: "+Hex.toHexString(Q.getEncoded(true)));	

    }
    
}
