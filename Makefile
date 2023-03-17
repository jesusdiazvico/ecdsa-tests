all:
	gcc btc_sign.c libsecp256k1.a -lssl -lcrypto -o btc_sign
	gcc btc_verify.c libsecp256k1.a -lssl -lcrypto -o btc_verify
	javac -cp bcprov-ext-jdk18on-172.jar BcECDSASign.java
	javac -cp bcprov-ext-jdk18on-172.jar BcECDSAVerify.java

clean:
	rm btc_sign btc_verify BcECDSASign.class BcECDSAVerify.class
