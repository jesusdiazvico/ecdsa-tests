#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage $0 <iters>"
	exit
fi

iters=$(($1-1))

echo -n "Signing... "
arrBtcSignedMsgs=()
arrBtcSignedSigs=()
arrBccSignedPKs=()
arrBccSignedMsgs=()
arrBccSignedSigs=()
arrBccSignedPKs=()
for (( i=0; i<=$iters; i++ )); do

	output=$(./btc_sign HelloWorld${i})
	list=($output)
	arrBtcSignedMsgs+=(${list[2]})
	arrBtcSignedSigs+=(${list[4]})
	arrBtcSignedPKs+=(${list[6]})

	output=$(java -cp .:bcprov-ext-jdk18on-172.jar BcECDSASign HelloWorld${i})
	list=($output)
	arrBccSignedMsgs+=(${list[2]})
	arrBccSignedSigs+=(${list[4]})
	arrBccSignedPKs+=(${list[6]})
done
echo "OK"

echo -n "Baseline (BTC verifies BTC; BC verifies BC)... "
btc2btcOK=0
bcc2bccOK=0
for (( i=0; i<=$iters; i++ )); do

	output=$(./btc_verify ${arrBtcSignedMsgs[$i]} ${arrBtcSignedSigs[$i]} ${arrBtcSignedPKs[$i]})
	list=($output)
	if [[ ${list[3]} = "VALID" ]]; then
		btc2btcOK=$((btc2btcOK+1))
	fi

	output=$(java -cp .:bcprov-ext-jdk18on-172.jar BcECDSAVerify ${arrBccSignedMsgs[$i]} ${arrBccSignedSigs[$i]} ${arrBccSignedPKs[$i]})
	list=($output)
	if [[ ${list[3]} = "VALID" ]]; then
		bcc2bccOK=$((bcc2bccOK+1))
	fi

done
echo "OK"
if [ $btc2btcOK -ne $1 ]; then 
	echo "BTC signatures failed to be verified by BTC. Something stupid is probably wrong."
	exit
fi

if [ $bcc2bccOK -ne $1 ]; then 
	echo "BCC signatures failed to be verified by BCC. Something stupid is probably wrong."
	exit
fi

echo -n "Crossed verifications (BTC verifies BCC; BCC verifies BTC)... "
btc2bccOK=0
bcc2btcOK=0
for (( i=0; i<=$iters; i++ )); do

	output=$(./btc_verify ${arrBccSignedMsgs[$i]} ${arrBccSignedSigs[$i]} ${arrBccSignedPKs[$i]})
	list=($output)
	if [[ ${list[3]} = "VALID" ]]; then
		bcc2btcOK=$((bcc2btcOK+1))
	else
		bcc2btcErrMsg=${arrBccSignedMsgs[$i]}
		bcc2btcErrSig=${arrBccSignedSigs[$i]}
		bcc2btcErrPK=${arrBccSignedPKs[$i]}
	fi

	output=$(java -cp .:bcprov-ext-jdk18on-172.jar BcECDSAVerify ${arrBtcSignedMsgs[$i]} ${arrBtcSignedSigs[$i]} ${arrBtcSignedPKs[$i]})
	list=($output)
	if [[ ${list[3]} = "VALID" ]]; then
		btc2bccOK=$((btc2bccOK+1))
	else

		btc2bccErrMsg=${arrBtcSignedMsgs[$i]}
		btc2bccErrSig=${arrBtcSignedSigs[$i]}
		btc2bccErrPK=${arrBtcSignedPKs[$i]}
	fi

done
echo "OK"

echo "Stats:"
echo "BTC signatures successfully verified by BTC: $btc2btcOK/$1"
echo "BCC signatures successfully verified by BCC: $bcc2bccOK/$1"
echo "BTC signatures successfully verified by BCC: $btc2bccOK/$1"
echo "BCC signatures successfully verified by BTC: $bcc2btcOK/$1"

# Output example of sig by btc not verified by bcc, if any
if [ $btc2bccOK -ne $1 ]; then
	echo "Sample <msg> <sig> <pk> from BTC that BCC fails to verify:"
	echo $btc2bccErrMsg $btc2bccErrSig $btc2bccErrPK
fi

# Output example of sig by bcc not verified by btc, if any
if [ $bcc2btcOK -ne $1 ]; then
	echo "Sample <msg> <sig> <pk> from BCC that BTC fails to verify:"
	echo $bcc2btcErrMsg $bcc2btcErrSig $bcc2btcErrPK
fi
