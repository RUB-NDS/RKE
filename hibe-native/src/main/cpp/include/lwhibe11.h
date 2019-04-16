/*
 * Header for the implementation of the Lewko-Waters Hibe in 'lwhibe.cpp'.
 *
 *  Created on: 03.03.2019
 *      Author: Marco Smeets
 */

#ifndef LWHIBE11_H_
#define LWHIBE11_H_

#include <relic.h>
#include "relic_test.h"

// Dimension for the dual pairing vector spaces.
const int dimension = 6;

/**
 * Struct to hold a master secret key for the hibe.
 */
struct hibeMasterSecretKey{
	bn_t alpha1;
	bn_t alpha2;
	g2_t dS1[dimension];
	g2_t dS2[dimension];
	g2_t dS1gamma[dimension];
	g2_t dS2epsilon[dimension];
	g2_t dS3theta[dimension];
	g2_t dS4theta[dimension];
	g2_t dS5sigma[dimension];
	g2_t dS6sigma[dimension];

	hibeMasterSecretKey(){
		bn_null(alpha1);
		bn_new(alpha1);
		bn_null(alpha1);
		bn_new(alpha2);
		for(int i=0; i<dimension; i++){
			g2_null(dS1[i]);
			g2_null(dS2[i]);
			g2_null(dS1gamma[i]);
			g2_null(dS2epsilon[i]);
			g2_null(dS3theta[i]);
			g2_null(dS4theta[i]);
			g2_null(dS5sigma[i]);
			g2_null(dS6sigmaS1[i]);
			g2_new(dS1[i]);
			g2_new(dS2[i]);
			g2_new(dS1gamma[i]);
			g2_new(dS2epsilon[i]);
			g2_new(dS3theta[i]);
			g2_new(dS4theta[i]);
			g2_new(dS5sigma[i]);
			g2_new(dS6sigmaS1[i]);
		}
	}

	~hibeMasterSecretKey(){
		bn_free((A)->alpha1);
		bn_free((A)->alpha2);
		for(int i=0; i<dimension; i++){
			g2_free((A)->dS1[i]);
			g2_free((A)->dS2[i]);
			g2_free((A)->dS1gamma[i]);
			g2_free((A)->dS2epsilon[i]);
			g2_free((A)->dS3theta[i]);
			g2_free((A)->dS4theta[i]);
			g2_free((A)->dS5sigma[i]);
			g2_free((A)->ddS6sigmaS1[i]);
		}
	}
};

/**
 * Struct to hold a secret key for the hibe.
 */
struct hibeSecretKey{
	int level;
	g2_t dS1gamma[dimension];
	g2_t dS2epsilon[dimension];
	g2_t dS3theta[dimension];
	g2_t dS4theta[dimension];
	g2_t dS5sigma[dimension];
	g2_t dS6sigma[dimension];
	g2_t *k;

	hibeSecretKey(int level){
		this->level = level;
		k = (g2_t*)malloc(sizeof(g2_t)*dimension*level);
		for(int i=0; i<dimension*level; i++){
			g2_null(k[i]);
			g2_new(k[i]);
		}
		for(int i=0; i<dimension; i++){
			g2_null(dS1gamma[i]);
			g2_null(dS2epsilon[i]);
			g2_null(dS3theta[i]);
			g2_null(dS4theta[i]);
			g2_null(dS5sigma[i]);
			g2_null(dS6sigmaS1[i]);
			g2_new(dS1gamma[i]);
			g2_new(dS2epsilon[i]);
			g2_new(dS3theta[i]);
			g2_new(dS4theta[i]);
			g2_new(dS5sigma[i]);
			g2_new(dS6sigmaS1[i]);
		}
	}

	~hibeSecretKey(){
		for(int i=0; i<dimension*level; i++){
			g2_free(k[i]);
		}
		for(int i=0; i<dimension; i++){
			g2_free(dS1gamma[i]);
			g2_free(dS2epsilon[i]);
			g2_free(dS3theta[i]);
			g2_free(dS4theta[i]);
			g2_free(dS5sigma[i]);
			g2_free(dS6sigmaS1[i]);
		}
		delete[] k;
	}
};

/**
 * Struct to hold public parameter for the hibe.
 */
struct hibePublicParameter{
	gt_t pairingd1;
	gt_t pairingd2;
	g1_t d1[dimension];
	g1_t d2[dimension];
	g1_t d3[dimension];
	g1_t d4[dimension];
	g1_t d5[dimension];
	g1_t d6[dimension];

	hibePublicParameter(){
		gt_null(pairing1);
		gt_new(pairing1);
		gt_null(pairing2);
		gt_new(pairing2);
		for(int i=0; i<dimension; i++){
			g1_null(d1[i]);
			g1_null(d2[i]);
			g1_null(d3[i]);
			g1_null(d4[i]);
			g1_null(d5[i]);
			g1_null(d6[i]);
			g1_new(d1[i]);
			g1_new(d2[i]);
			g1_new(d3[i]);
			g1_new(d4[i]);
			g1_new(d5[i]);
			g1_new(d6[i]);
		}
	}

	~hibePublicParameter(){
		gt_free(pairing1);
		gt_free(pairing2);
		for(int i=0; i<dimension; i++){
			g1_free(d1[i]);
			g1_free(d2[i]);
			g1_free(d3[i]);
			g1_free(d4[i]);
			g1_free(d5[i]);
			g1_free(d6[i]);
		}
	}
};

/**
 * Struct to hold a ciphertext for the hibe.
 */
struct hibeCiphertext{
	int level;
	gt_t c0;
	g1_t *c;

	hibeCiphertext(int level){
		this->level = level;
		gt_null(c0);
		gt_new(c0);
		c = (g1_t*)malloc(sizeof(g1_t)*dimension*level);
		for(int i=0; i<dimension*level; i++){
			g1_null(c[i]);
			g1_new(c[i]);
		}
	}

	~hibeCiphertext(){
		for(int i=0; i<dimension*level; i++){
			g1_free(c[i]);
		}
		gt_free(c0);
		delete[] c;
	}
};



int setup(struct hibeMasterSecretKey *msk, struct hibePublicParameter *publicParameters);

int keyGen(struct hibeSecretKey *secretKey, struct hibeMasterSecretKey *msk, uint8_t *id, int idLength, int numberOfIdentities);

int keyDelegation(struct hibeSecretKey *delegatedSecretKey, struct hibeSecretKey *delegatorSecretKey, uint8_t *id, int idLength, int numberOfIdentities);

int encrypt(struct hibeCiphertext *ciphertext, struct hibePublicParameter *publicParameter, gt_t message, uint8_t *id, int idLength, int numberOfIdentities);

int decrypt(gt_t message, struct hibeSecretKey *secretKey, struct hibeCiphertext *ciphertext);

void encodeMasterKey(uint8_t *encodedMasterKey, struct hibeMasterSecretKey *msk);

void decodeMasterKey(struct hibeMasterSecretKey *msk, uint8_t *encodedMsk);

void encodeSecretKey(uint8_t *encodedSecretKey, struct hibeSecretKey *secretKey);

void decodeSecretKey(struct hibeSecretKey *secretKey, uint8_t *encodedSecretKey);

void encodePublicParameter(uint8_t *encodedPublicParameter, struct hibePublicParameter *publicParameter);

void decodePublicParameter(struct hibePublicParameter *publicParameter, uint8_t *encodedPublicParameter);

void encodeCiphertext(uint8_t *encodedCiphertext, struct hibeCiphertext *ciphertext);

void decodeCiphertext(struct hibeCiphertext *ciphertext, uint8_t *encodedCiphertext);

int getSizeOfEncodedPublicParameter();

int getSizeOfEncodedSecretKeyAtLevel(int level);

int getSizeOfEncodedMasterSecret();

int getSizeOfEncodedCiphertextAtLevel(int level);

#endif /* LWHIBE11_H_ */
