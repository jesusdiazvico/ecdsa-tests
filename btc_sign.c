/*
 *
 *
 *
 */
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include "secp256k1.h"
#include "util.h"

int main(int argc, char *argv[]) {

  secp256k1_context* ctx;
  secp256k1_ecdsa_signature sig;
  secp256k1_pubkey pk;
  unsigned char randomize[32], mh[32], sk[32], ssig[74], cpk[33];
  size_t len;
  char *hsig, *hcpk;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <message to sign>\n", argv[0]);
    return 1;
  }

  memset(mh, 0, 32);
  memset(sk, 0, 32);
  memset(cpk, 0, 33);
  memset(ssig, 0, 74);
    
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (!fill_random(randomize, sizeof(randomize))) {
    return 2;
  }

  if (!secp256k1_context_randomize(ctx, randomize)) {
    return 3;
  }

  while (1) {
    if (!fill_random(sk, sizeof(sk))) {
      return 4;
    }
    if (secp256k1_ec_seckey_verify(ctx, sk)) {
      break;
    }
  }

  if (!SHA256(argv[1], strlen(argv[1]), mh)) {
    return 5;
  }

  if (!secp256k1_ec_pubkey_create(ctx, &pk, sk)) {
    return 6;
  }
  
  if (!secp256k1_ecdsa_sign(ctx, &sig, mh, sk, NULL, NULL)) {
    return 7;
  }

  len = 74;
  if (!secp256k1_ecdsa_signature_serialize_der(ctx, ssig, &len, &sig)) {
    return 8;
  }

  if(!(hsig = bin2hex(ssig, len))) {
    return 9;
  }

  len = sizeof(cpk);
  if(!secp256k1_ec_pubkey_serialize(ctx, cpk, &len, &pk, SECP256K1_EC_COMPRESSED)) {
    return 10;
  }

  if(!(hcpk = bin2hex(cpk, 33))) {
    return 11;
  }

  fprintf(stdout, "Signing message: %s\n", argv[1]);
  fprintf(stdout, "Sig: %s\n", hsig);
  fprintf(stdout, "PK: %s\n", hcpk);
  
  return 0;
  
}
