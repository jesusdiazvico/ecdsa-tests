# C

## Compile C code
gcc btc_sign.c libsecp256k1.a -lssl -lcrypto -o btc_sign
gcc btc_verify.c libsecp256k1.a -lssl -lcrypto -o btc_verify

## Run C programs
./btc_sign <msg>
./btc_verify <msg> <sig> <pk>

# Java

# Compile Java code
javac -cp bcprov-ext-jdk18on-172.jar BcECDSASign.java
javac -cp bcprov-ext-jdk18on-172.jar BcECDSAVerify.java

# Run Java code
java -cp .:bcprov-ext-jdk18on-172.jar BcECDSASign <msg>
java -cp .:bcprov-ext-jdk18on-172.jar BcECDSAVerify <msg> <sig> <pk>
