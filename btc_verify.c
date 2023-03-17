#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include "secp256k1.h"
#include "util.h"

int main(int argc, char *argv[]) {

  secp256k1_context* ctx;
  secp256k1_ecdsa_signature sig;
  secp256k1_pubkey pk;
  unsigned char randomize[32], mh[32], *ssig, *cpk;
  size_t len;
  char *hsig, *hcpk;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s <message to verify> <sig> <pk>\n", argv[0]);
    return 1;
  }

  memset(mh, 0, 32);
  cpk = NULL;
  ssig = NULL;
    
  ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (!fill_random(randomize, sizeof(randomize))) return 2;
  if (!secp256k1_context_randomize(ctx, randomize)) return 3;
  if (!SHA256(argv[1], strlen(argv[1]), mh)) return 4;

  len = hex2bin(argv[2], &ssig);
  if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, ssig, len)) return 5;

  len = hex2bin(argv[3], &cpk);
  if (!secp256k1_ec_pubkey_parse(ctx, &pk, cpk, 33)) return 6;

  fprintf(stdout, "Verifying message: %s\n", argv[1]);    
  if(secp256k1_ecdsa_verify(ctx, &sig, mh, &pk)) fprintf(stdout, "VALID sig\n");
  else fprintf(stdout, "WRONG sig\n");
  
  secp256k1_context_destroy(ctx);
  free(ssig); ssig = NULL;
  free(cpk); cpk = NULL;
      
  return 0;
  
}
