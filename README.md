# C

## Compile C code
`gcc btc_sign.c libsecp256k1.a -lssl -lcrypto -o btc_sign`

`gcc btc_verify.c libsecp256k1.a -lssl -lcrypto -o btc_verify`

## Run C programs
`./btc_sign <msg>`

`./btc_verify <msg> <sig> <pk>`

# Java

## Compile Java code
`javac -cp bcprov-ext-jdk18on-172.jar BcECDSASign.java`

`javac -cp bcprov-ext-jdk18on-172.jar BcECDSAVerify.java`

## Run Java code
`java -cp .:bcprov-ext-jdk18on-172.jar BcECDSASign <msg>`

`java -cp .:bcprov-ext-jdk18on-172.jar BcECDSAVerify <msg> <sig> <pk>`

# Stats
To get some stats about interoperability of BTC and BCC ECDSA (over secp256k1) signatures, run:

`$ ./stats.sh <iters>`

Where `<iters>` is the number of signatures to generate with each signing program. If all is OK, it should output something like:


```
$ ./stats.sh 100
Signing... OK
Baseline (BTC verifies BTC; BC verifies BC)... OK
Crossed verifications (BTC verifies BCC; BCC verifies BTC)... OK
Stats:
BTC signatures successfully verified by BTC: 100/100
BCC signatures successfully verified by BCC: 100/100
BTC signatures successfully verified by BCC: 100/100
BCC signatures successfully verified by BTC: 100/100
```
