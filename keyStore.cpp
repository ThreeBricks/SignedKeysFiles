//Joan Sebastian Rios-Ruiz and Jordan Lieter
//Key Signing Test

#include "palisade.h"
#include <fstream>

// header files needed for serialization
#include "utils/serialize-binary.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "pubkeylp-ser.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include <stdlib.h>

using namespace lbcrypto;
const std::string DATAFOLDER = "demoData";

int main(){

  int plaintextModulus = 256;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	uint32_t depth = 2;

  CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
      plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);

  LPKeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();

  Plaintext pt=cc->MakeStringPlaintext("OK");
  Ciphertext<DCRTPoly> ct;
  ct=cc->Encrypt(keyPair.publicKey,pt);

  string emailAddress;
  std::cout<<"Please enter an emailAddress\n";
  std::cin>>emailAddress;



  Serial::SerializeToFile(DATAFOLDER + "/public.txt", keyPair.publicKey, SerType::JSON);
  Serial::SerializeToFile(DATAFOLDER + "/private.txt", keyPair.secretKey, SerType::JSON);
  Serial::SerializeToFile(DATAFOLDER + "/verificationString.txt", ct, SerType::JSON);

   return 0;

}
