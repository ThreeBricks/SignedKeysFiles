//Joan Sebastian Rios-Ruiz and Jordan Lieter
//Key Signing Test



#include "signaturecontext.h"
#include <stdlib.h>

int main(){
   lbcrypto::GPVVerificationKey<lbcrypto::NativePoly> vKeyArr[3];
   srand(time(NULL));

   lbcrypto::SignatureContext<lbcrypto::NativePoly> context;
   context.GenerateGPVContext(1024);

   lbcrypto::GPVVerificationKey<lbcrypto::NativePoly> veraVKey;
   lbcrypto::GPVSignKey<lbcrypto::NativePoly> veraSKey;

   context.KeyGen(&veraSKey,&veraVKey);
   vKeyArr[0]=veraVKey;

   lbcrypto::GPVVerificationKey<lbcrypto::NativePoly> zachVKey;
   lbcrypto::GPVSignKey<lbcrypto::NativePoly> zachSKey;
   
   context.KeyGen(&zachSKey,&zachVKey);
   vKeyArr[1]=zachVKey;

   lbcrypto::GPVVerificationKey<lbcrypto::NativePoly> seanVKey;
   lbcrypto::GPVSignKey<lbcrypto::NativePoly> seanSKey;
   
   context.KeyGen(&seanSKey,&seanVKey);
   vKeyArr[2]=seanVKey;


   string pt="Vera's Secret String";
   string pt2="Zach's Secret String";

   //Clean this up to what youre thinkin of
   
   //Regular Signing
   lbcrypto::GPVPlaintext<lbcrypto::NativePoly> plaintext(pt);
   lbcrypto::GPVSignature<lbcrypto::NativePoly> signature;
   context.Sign(plaintext,veraSKey,veraVKey,&signature);

   //Offline Signing with Perturbation Vector
   lbcrypto::PerturbationVector<lbcrypto::NativePoly> zachPertVec;
   lbcrypto::GPVPlaintext<lbcrypto::NativePoly> plaintext2(pt2);
   lbcrypto::GPVSignature<lbcrypto::NativePoly> signature2;
   context.SignOfflinePhase(zachSKey,zachPertVec);

   //Online Signing
   context.SignOnlinePhase(plaintext2,zachSKey,zachVKey,zachPertVec,&signature2);

   bool verificationResult=false;
   int step=0;
   while(!verificationResult && step<5){
      std::cout<<"Verifying Vera's Sign Key"<<std::endl;
      verificationResult=context.Verify(plaintext,signature,vKeyArr[rand()%3]);
      if(verificationResult!=1){
         std::cout<<"Verifcation Attempt "<<step+1<<" failed."<<std::endl;
      }
      else{
         std::cout<<"Vera's Key Verified!"<<std::endl;
      }
      step+=1;
   }
   
   bool verificationResult2=false;
   step=0;
   while(!verificationResult2 && step<5){
      std::cout<<"Verifying Zach's Sign Key"<<std::endl;
      verificationResult2=context.Verify(plaintext2,signature2,vKeyArr[rand()%3]);
      if(verificationResult2!=1){
         std::cout<<"Verifcation Attempt "<<step+1<<" failed."<<std::endl;
      }
      else{
         std::cout<<"Zach's Key Verified!"<<std::endl;
      }
      step+=1;
   }      
   return 0;

}
