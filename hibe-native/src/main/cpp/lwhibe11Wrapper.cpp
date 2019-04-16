//============================================================================
// Name        : lwhibe11Wrapper.cpp
// Author      : Marco Smeets
// Version     : 0.9
// Copyright   : Your copyright notice
// Description : Wrapper for Java (JNI) of the lwhibe.cpp implementation.
//				 The wrapper is implemented with use for the kuKem[1] in mind.
//				 Thus, the setup algorithm directly returns the secret key for a specific
//				 identity and discards the master secret key. Furthermore, there is no
//				 key generation algorithm.
//				 In order that seeds for randomness are working, the relic-toolkit has to be
//				 compiled with an empty 'Seed' option. This way, the caller of the functions
//				 is required to provide a cryptographically secure Seed for randomness.
//
// [1] Asynchronous ratcheted key exchange
// https://eprint.iacr.org/2018/296.pdf
//============================================================================

#include <iostream>
#include "de_rub_rkeinstantiation_hibewrapper_Hibe.h"
extern "C"{
#include <relic.h>
#include "relic_test.h"
}
#include "lwhibe11.h"
using namespace std;

/**
 * Computes and returns size of an encoded integer modulo Z_p
 */
JNIEXPORT jint JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_getSizeOfBnModZp
  (JNIEnv *, jclass){
	if (core_init() != STS_OK) {
		core_clean();
		return 0;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	bn_t bnElement, modulus;
	bn_new(bnElement);
	bn_new(modulus);
	g1_get_ord(modulus);
	bn_rand_mod(bnElement, modulus);
	int size = bn_size_bin(bnElement);
	bn_free(bnElement);
	bn_free(modulus);
	core_clean();
	return size;
}

/**
 * Computes and returns size of an encoded G1 curve point
 */
JNIEXPORT jint JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_getSizeOfG1
  (JNIEnv *, jclass){
	if (core_init() != STS_OK) {
		core_clean();
		return 0;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	g1_t g1Element;
	g1_new(g1Element);
	g1_rand(g1Element);
	int size = g1_size_bin(g1Element,1);
	g1_free(g1Element);
	core_clean();
	return size;
}

/**
 * Computes and returns size of an encoded G2 curve point
 */
JNIEXPORT jint JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_getSizeOfG2
  (JNIEnv *, jclass){
	if (core_init() != STS_OK) {
		core_clean();
		return 0;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	g2_t g2Element;
	g2_new(g2Element);
	g2_rand(g2Element);
	int size = g2_size_bin(g2Element,1);
	g2_free(g2Element);
	core_clean();
	return size;
}

/**
 * Computes and returns size of an encoded compressed GT curve point
 */
JNIEXPORT jint JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_getSizeOfGT
  (JNIEnv *, jclass){
	if (core_init() != STS_OK) {
		core_clean();
		return 0;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	gt_t gtElement;
	gt_new(gtElement);
	gt_rand(gtElement);
	int size = gt_size_bin(gtElement,1);
	gt_free(gtElement);
	core_clean();
	return size;
}

/**
 * Computes and returns size of an encoded uncompressed GT curve point
 */
JNIEXPORT jint JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_getSizeOfuncompressedGT
  (JNIEnv *, jclass){
	if (core_init() != STS_OK) {
		core_clean();
		return 0;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	gt_t gtElement;
	gt_new(gtElement);
	gt_rand(gtElement);
	int size = gt_size_bin(gtElement,0);
	gt_free(gtElement);
	core_clean();
	return size;
}

/**
 * Returns a random encoded compressed GT Element.
 */
JNIEXPORT jbyteArray JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_getRandomGtElement
  (JNIEnv *env, jclass, jbyteArray javaSeed){
	if (core_init() != STS_OK) {
		core_clean();
		return NULL;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return NULL;
	}
	jsize lengthOfSeedArray = env->GetArrayLength(javaSeed);
	jbyte *seedArray = env->GetByteArrayElements(javaSeed,0);
	rand_seed((uint8_t*)seedArray, lengthOfSeedArray);
	env->ReleaseByteArrayElements(javaSeed,seedArray ,JNI_ABORT);

	gt_t randomElement;
	gt_new(randomElement);
	gt_rand(randomElement);

	int sizeOfGt = gt_size_bin(randomElement,1);
	uint8_t encodedGt[sizeOfGt];
	gt_write_bin(encodedGt, sizeOfGt, randomElement,1);
	gt_free(randomElement);

	jbyteArray encodedElement = (jbyteArray)env->NewByteArray(sizeOfGt);
	if(encodedElement==NULL){
		return NULL;
	}

	env->SetByteArrayRegion(encodedElement,0,sizeOfGt,(jbyte*) encodedGt);

	core_clean();
	return encodedElement;
}

/**
 * Performs the Hibe Setup algorithm. Directly generates a key for the provided identity and discards
 * the master secret key.
 */
JNIEXPORT jbyteArray JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_setup
  (JNIEnv *env, jclass, jbyteArray javaIdentity, jint javaIdentityLength, jbyteArray javaSeed){
	if (core_init() != STS_OK) {
		core_clean();
		return NULL;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return NULL;
	}

	jsize lengthOfSeedArray = env->GetArrayLength(javaSeed);
	jbyte *seedArray = env->GetByteArrayElements(javaSeed,0);

	rand_seed((uint8_t*)seedArray, lengthOfSeedArray);
	env->ReleaseByteArrayElements(javaSeed,seedArray ,JNI_ABORT);


	int sizePublicParameter = getSizeOfEncodedPublicParameter();
	int sizeSecretKey = getSizeOfEncodedSecretKeyAtLevel(1);

	uint8_t encodedPP[sizePublicParameter];
	uint8_t encodedSecretKey[sizeSecretKey];

	struct hibeMasterSecretKey *msk= new hibeMasterSecretKey();
	struct hibePublicParameter *publicParameter = new hibePublicParameter();

	if (setup(msk,publicParameter) != STS_OK) {
		core_clean();
		return NULL;
	}

	struct hibeSecretKey *secretKey = new hibeSecretKey(1);

	jbyte *identityArray = env->GetByteArrayElements(javaIdentity, NULL);
	if(keyGen(secretKey, msk, (uint8_t*)identityArray, javaIdentityLength, 1)!= STS_OK){
		core_clean();
		return NULL;
	}
	env->ReleaseByteArrayElements(javaIdentity, identityArray ,JNI_ABORT);

	encodePublicParameter(encodedPP, publicParameter);
	encodeSecretKey(encodedSecretKey, secretKey);

	jbyteArray encodedKeys = (jbyteArray)env->NewByteArray(sizePublicParameter+sizeSecretKey);
	if(encodedKeys==NULL){
		return NULL;
	}

	env->SetByteArrayRegion(encodedKeys,0,sizePublicParameter,(jbyte*) encodedPP);
	env->SetByteArrayRegion(encodedKeys,sizePublicParameter, sizeSecretKey,(jbyte*) encodedSecretKey);

	core_clean();
	return encodedKeys;
}

/**
 * Performs the Hibe encryption algorithm.
 */
JNIEXPORT jbyteArray JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_encrypt
(JNIEnv *env, jclass, jbyteArray javaPublicParameter, jbyteArray javaMessage, jbyteArray javaIdentity, jint javaIdentityLength, jint javaLevel, jbyteArray javaSeed){
	if (core_init() != STS_OK) {
		core_clean();
		return NULL;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return NULL;
	}
	jsize lengthOfSeedArray = env->GetArrayLength(javaSeed);
	jbyte *seedArray = env->GetByteArrayElements(javaSeed,NULL);

	rand_seed((uint8_t*)seedArray, lengthOfSeedArray);
	env->ReleaseByteArrayElements(javaSeed,seedArray ,JNI_ABORT);

	jbyte *publicParameterArray = env->GetByteArrayElements(javaPublicParameter, NULL);
	jsize messageArrayLength = env->GetArrayLength(javaMessage);
	jbyte *messageArray = env->GetByteArrayElements(javaMessage, NULL);

	struct hibePublicParameter *publicParameter = new hibePublicParameter;

	decodePublicParameter(publicParameter, (uint8_t*) publicParameterArray);
	env->ReleaseByteArrayElements(javaPublicParameter,publicParameterArray ,JNI_ABORT);

	gt_t message;
	gt_new(message);
	gt_read_bin(message, (uint8_t*)messageArray, messageArrayLength);
	env->ReleaseByteArrayElements(javaMessage, messageArray ,JNI_ABORT);

	struct hibeCiphertext *ciphertext = new hibeCiphertext(javaLevel);

	jbyte *identityArray = env->GetByteArrayElements(javaIdentity, NULL);

	if(encrypt(ciphertext, publicParameter, message, (uint8_t*)identityArray, javaIdentityLength, javaLevel) == STS_ERR) {
		core_clean();
		return NULL;
	}
	env->ReleaseByteArrayElements(javaIdentity, identityArray ,JNI_ABORT);

	int sizeOfCiphertext = getSizeOfEncodedCiphertextAtLevel(javaLevel);

	uint8_t encodedCiphertext[sizeOfCiphertext];

	encodeCiphertext(encodedCiphertext, ciphertext);

	jbyteArray javaencodedCiphertext = (jbyteArray)env->NewByteArray(sizeOfCiphertext);
	if(javaencodedCiphertext==NULL){
		return NULL;
	}

	env->SetByteArrayRegion(javaencodedCiphertext,0,sizeOfCiphertext,(jbyte*) encodedCiphertext);

	core_clean();
	return javaencodedCiphertext;
}

/**
 * Performs the Hibe decryption algorithm.
 */
JNIEXPORT jbyteArray JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_decrypt
(JNIEnv *env, jclass, jbyteArray javaSecretKey, jbyteArray javaCiphertext, jint javaLevel){
	if (core_init() != STS_OK) {
		core_clean();
		return NULL;
	}
	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return NULL;
	}
	jbyte *javaSecretKeyArray = env->GetByteArrayElements(javaSecretKey, 0);
	jbyte *javaCiphertextArray = env->GetByteArrayElements(javaCiphertext, 0);

	struct hibeSecretKey *secretKey = new hibeSecretKey(javaLevel);
	struct hibeCiphertext *ciphertext = new hibeCiphertext(javaLevel);

	decodeSecretKey(secretKey, (uint8_t*) javaSecretKeyArray);
	env->ReleaseByteArrayElements(javaSecretKey,javaSecretKeyArray ,JNI_ABORT);

	decodeCiphertext(ciphertext, (uint8_t*) javaCiphertextArray);
	env->ReleaseByteArrayElements(javaCiphertext,javaCiphertextArray ,JNI_ABORT);

	gt_t message;
	gt_new(message);

	if(decrypt(message, secretKey, ciphertext)==STS_ERR){
		core_clean();
		return NULL;
	}
	int size = gt_size_bin(message,1);

	uint8_t messageArray[size];
	gt_write_bin(messageArray, size, message, 1);

	jbyteArray javamessage = (jbyteArray)env->NewByteArray(size);
	if(javamessage==NULL){
		return NULL;
	}

	env->SetByteArrayRegion(javamessage,0,size,(jbyte*) messageArray);

	gt_free(message);
	core_clean();
	return javamessage;
}

/**
 * Performs the Hibe delegate algorithm.
 */
JNIEXPORT jbyteArray JNICALL Java_de_rub_rkeinstantiation_hibewrapper_Hibe_delegate
  (JNIEnv *env, jclass, jbyteArray javaDelegatorKey, jbyteArray javaIdentity, jint javaIdentityLength, jint javaLevel, jbyteArray javaSeed){
	if (core_init() != STS_OK) {
		core_clean();
		return NULL;
	}

	if (ep_param_set_any_pairf() == STS_ERR) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return NULL;
	}

	jsize lengthOfSeedArray = env->GetArrayLength(javaSeed);
	jbyte *seedArray = env->GetByteArrayElements(javaSeed,0);
	rand_seed((uint8_t*)seedArray, lengthOfSeedArray);
	env->ReleaseByteArrayElements(javaSeed,seedArray ,JNI_ABORT);

	jbyte *javaSecretKeyArray = env->GetByteArrayElements(javaDelegatorKey, 0);

	struct hibeSecretKey *secretKey = new hibeSecretKey(javaLevel-1);
	decodeSecretKey(secretKey, (uint8_t*) javaSecretKeyArray);
	env->ReleaseByteArrayElements(javaDelegatorKey,javaSecretKeyArray ,JNI_ABORT);

	jbyte *identityArray = env->GetByteArrayElements(javaIdentity, NULL);

	struct hibeSecretKey *delegatedKey = new hibeSecretKey(javaLevel);
	if(keyDelegation(delegatedKey, secretKey, (uint8_t*)identityArray, javaIdentityLength, javaLevel) == STS_ERR) {
		core_clean();
		return NULL;
	}

	env->ReleaseByteArrayElements(javaIdentity, identityArray ,JNI_ABORT);

	int sizeOfSecretKey = getSizeOfEncodedSecretKeyAtLevel(javaLevel);
	uint8_t encodedSecretKey[sizeOfSecretKey];

	encodeSecretKey(encodedSecretKey, delegatedKey);

	jbyteArray javaDelegatedKey = (jbyteArray)env->NewByteArray(sizeOfSecretKey);
	if(javaDelegatedKey==NULL){
		return NULL;
	}
	env->SetByteArrayRegion(javaDelegatedKey,0,sizeOfSecretKey,(jbyte*) encodedSecretKey);
	core_clean();
	return javaDelegatedKey;
}

int main() {
	return 0;
}
