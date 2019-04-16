//============================================================================
// Name        : lwhibe.cpp
// Author      : Marco Smeets
// Version     : 0.9
// Copyright   : Your copyright notice
// Description : Implementation of the Lewko Waters Unbounded Hibe[1]. This implementation uses the prime
//				 order translation of the LW-Hibe described by Lewko[2]. As the dimension for the Dual Pairing
//				 Vector Spaces (DPVS) we choose 6. Note that dimension 7-10 are only required for the
//				 semi-functional and ephemeral semi-functional key space, which are only used in the
//				 security proof of the HIBE.
//				 Since the description in [2] uses a symmetric Pairing to describe the algorithms and we use
//				 an asymmetric pairing, we have to choose which group (G1 or G2) is used for the ciphertexts
//				 and which group is used for the secret Keys. Similar to Guillevic[5], we set the Ciphertexts
//               in G1 and the secret keys in G2. This reduces the size of the ciphertexts.
//               Pairings are computed with the Relic toolkit [6].
//
// [1] Unbounded HIBE and Attribute-Based Encryption
// https://link.springer.com/content/pdf/10.1007/978-3-642-20465-4_30.pdf
// [2] Tools for Simulating Features of Composite Order Bilinear Groups in the Prime Order Setting
//  https://link.springer.com/content/pdf/10.1007/978-3-642-29011-4_20.pdf
// [3] Dual Pairing Vector Spaces
// https://www.uow.edu.au/~fuchun/seminars/031014.pdf
// [4] Hierarchical Predicate Encryption for Inner-Products
// https://link.springer.com/content/pdf/10.1007/978-3-642-10366-7_13.pdf
// [5] Comparing the Pairing Efficiency over Composite-Order and Prime-Order Elliptic Curves
// https://hal.inria.fr/hal-00812960/document
// [6] relic-toolkit
// https://github.com/relic-toolkit/relic
//============================================================================


#include <iostream>
#include <stdio.h>
#include <vector>
#include <functional>
extern "C" {
#include<relic.h>
#include "relic_test.h"
}
#include "lwhibe11.h"


/**
 * This function samples random dual orthonormal bases. These are directly used for the dual pairing vector
 * spaces. Construction of the DPVS (or dual orthonormal bases) are described in [3,4].
 */
static int sampleRandomDualOrthonormalBases(g1_t d1[6], g1_t d2[6], g1_t d3[6], g1_t d4[6], g1_t d5[6], g1_t d6[6], g2_t dS1[6], g2_t dS2[6], g2_t dS3[6], g2_t dS4[6], g2_t dS5[6], g2_t dS6[6]) {
	int result = STS_OK;
	bn_t linearTrans[dimension][dimension];
	bn_t invLinearTrans[dimension][dimension];
	bn_t tempArray[dimension][dimension*2];
	bn_t elementA, elementB, elementC;
	bn_t modulus;
	g1_t basisA1[dimension][dimension];
	g2_t basisA2[dimension][dimension];
	g1_t basisB[dimension][dimension];
	g2_t basisBStar[dimension][dimension];
	g1_t intermediateResult1[dimension];
	g2_t intermediateResult2[dimension];

	bn_null(elementA);
	bn_null(elementB);
	bn_null(elementC);
	bn_null(modulus);
	for(int i=0; i<dimension; i++){
		g1_null(intermediateResult1[i]);
		g2_null(intermediateResult2[i]);
		for(int j=0; j<dimension; j++){
			bn_null(linearTrans[i][j]);
			bn_null(invLinearTrans[i][j]);
			bn_null(tempArray[i][j]);
			g1_null(basisA1[i][j]);
			g2_null(basisA2[i][j]);
			g1_null(basisB[i][j]);
			g2_null(basisBStar[i][j]);
		}
		bn_null(tempArray[i][6]);
		bn_null(tempArray[i][7]);
		bn_null(tempArray[i][8]);
		bn_null(tempArray[i][9]);
		bn_null(tempArray[i][10]);
		bn_null(tempArray[i][11]);
	}
	TRY {
		bn_new(elementA);
		bn_new(elementB);
		bn_new(elementC);
		bn_new(modulus);
		for(int i=0; i<dimension; i++){
			g1_new(intermediateResult1[i]);
			g2_new(intermediateResult2[i]);
			for(int j=0; j<dimension; j++){
				bn_new(linearTrans[i][j]);
				bn_new(invLinearTrans[i][j]);
				bn_new(tempArray[i][j]);
				g1_new(basisA1[i][j]);
				g2_new(basisA2[i][j]);
				g1_new(basisB[i][j]);
				g2_new(basisBStar[i][j]);
			}
			bn_new(tempArray[i][6]);
			bn_new(tempArray[i][7]);
			bn_new(tempArray[i][8]);
			bn_new(tempArray[i][9]);
			bn_new(tempArray[i][10]);
			bn_new(tempArray[i][11]);
		}
		// Get order p of the Curve
		g1_get_ord(modulus);
		// Create random X [3,4]
		// X is a invertible matrix uniformly chosen from the general linear
		// group of degree 6 over F_p
		// linearTrans[x][y] holds matrix X
		// tempArray[x][y] holds transposed matrix X
		for(int i = 0; i<dimension; i++){
			for(int j = 0;j<dimension; j++){
				bn_rand_mod(linearTrans[i][j], modulus);
				bn_copy(tempArray[j][i], linearTrans[i][j]);
			}
		}
		//Prepare tempArray for Inversion (using gauss-jordan elimination)
		for(int i=0; i<dimension; i++){
			bn_set_dig(tempArray[i][i+dimension],1);
		}
		//Inverse tempArray using gauss-jordan elimination in group Z_p
		for(int i=0; i<dimension; i++){
			bn_gcd_ext_basic(elementB, elementA, elementC, tempArray[i][i], modulus);
			for(int j = 0; j<dimension*2; j++){
				bn_mul_basic(tempArray[i][j], tempArray[i][j], elementA);
				bn_mod_basic(tempArray[i][j], tempArray[i][j], modulus);
			}
			for(int k=0; k<dimension; k++){
				if((k-i)!=0){
					bn_copy(elementB, tempArray[k][i]);
					for(int j=0; j<dimension*2;j++){
						bn_mul_basic(elementC, elementB, tempArray[i][j]);
						bn_mod_basic(elementC, elementC, modulus);
						bn_sub(tempArray[k][j], tempArray[k][j], elementC);
						bn_mod_basic(tempArray[k][j], tempArray[k][j], modulus);
					}
				}
			}
		}
		//Save inversed Array in invLinearTrans[x][y]
		for(int i=0; i<dimension;i++){
			for(int j=0; j<dimension; j++){
				bn_copy(invLinearTrans[i][j], tempArray[i][j+6]);
			}
		}
		// Create canonical base A [3,4]
		for(int i=0 ; i<dimension; i++){
			for(int j=0; j<dimension; j++){
				if(i==j){
					g1_get_gen(basisA1[i][i]);
					g2_get_gen(basisA2[i][i]);
				} else {
					g1_set_infty(basisA1[i][j]);
					g2_set_infty(basisA2[i][j]);
				}
			}
		}
		// Compute matrix B [3,4]
		for(int i=0; i<dimension; i++){
			g1_mul(basisB[0][i], basisA1[0][0], linearTrans[i][0]);
			g1_mul(basisB[1][i], basisA1[1][0], linearTrans[i][0]);
			g1_mul(basisB[2][i], basisA1[2][0], linearTrans[i][0]);
			g1_mul(basisB[3][i], basisA1[3][0], linearTrans[i][0]);
			g1_mul(basisB[4][i], basisA1[4][0], linearTrans[i][0]);
			g1_mul(basisB[5][i], basisA1[5][0], linearTrans[i][0]);
			for(int j=1; j<dimension; j++){
				g1_mul(intermediateResult1[0], basisA1[0][j], linearTrans[i][j]);
				g1_mul(intermediateResult1[1], basisA1[1][j], linearTrans[i][j]);
				g1_mul(intermediateResult1[2], basisA1[2][j], linearTrans[i][j]);
				g1_mul(intermediateResult1[3], basisA1[3][j], linearTrans[i][j]);
				g1_mul(intermediateResult1[4], basisA1[4][j], linearTrans[i][j]);
				g1_mul(intermediateResult1[5], basisA1[5][j], linearTrans[i][j]);
				g1_add(basisB[0][i], basisB[0][i],intermediateResult1[0]);
				g1_add(basisB[1][i], basisB[1][i],intermediateResult1[1]);
				g1_add(basisB[2][i], basisB[2][i],intermediateResult1[2]);
				g1_add(basisB[3][i], basisB[3][i],intermediateResult1[3]);
				g1_add(basisB[4][i], basisB[4][i],intermediateResult1[4]);
				g1_add(basisB[5][i], basisB[5][i],intermediateResult1[5]);
			}
		}
		//Compute matrix BStar[3,4]
		for(int i=0; i<dimension; i++){
			g2_mul(basisBStar[0][i], basisA2[0][0], invLinearTrans[i][0]);
			g2_mul(basisBStar[1][i], basisA2[1][0], invLinearTrans[i][0]);
			g2_mul(basisBStar[2][i], basisA2[2][0], invLinearTrans[i][0]);
			g2_mul(basisBStar[3][i], basisA2[3][0], invLinearTrans[i][0]);
			g2_mul(basisBStar[4][i], basisA2[4][0], invLinearTrans[i][0]);
			g2_mul(basisBStar[5][i], basisA2[5][0], invLinearTrans[i][0]);
			for(int j=1; j<dimension; j++){
				g2_mul(intermediateResult2[0], basisA2[0][j], invLinearTrans[i][j]);
				g2_mul(intermediateResult2[1], basisA2[1][j], invLinearTrans[i][j]);
				g2_mul(intermediateResult2[2], basisA2[2][j], invLinearTrans[i][j]);
				g2_mul(intermediateResult2[3], basisA2[3][j], invLinearTrans[i][j]);
				g2_mul(intermediateResult2[4], basisA2[4][j], invLinearTrans[i][j]);
				g2_mul(intermediateResult2[5], basisA2[5][j], invLinearTrans[i][j]);
				g2_add(basisBStar[0][i], basisBStar[0][i],intermediateResult2[0]);
				g2_add(basisBStar[1][i], basisBStar[1][i],intermediateResult2[1]);
				g2_add(basisBStar[2][i], basisBStar[2][i],intermediateResult2[2]);
				g2_add(basisBStar[3][i], basisBStar[3][i],intermediateResult2[3]);
				g2_add(basisBStar[4][i], basisBStar[4][i],intermediateResult2[4]);
				g2_add(basisBStar[5][i], basisBStar[5][i],intermediateResult2[5]);
			}
		}
		// Save B and BStar in d1-d6,dS1-dS6
		for(int i=0; i<dimension; i++){
			g1_copy(d1[i], basisB[i][0]);
			g1_copy(d2[i], basisB[i][1]);
			g1_copy(d3[i], basisB[i][2]);
			g1_copy(d4[i], basisB[i][3]);
			g1_copy(d5[i], basisB[i][4]);
			g1_copy(d6[i], basisB[i][5]);
			g2_copy(dS1[i], basisBStar[i][0]);
			g2_copy(dS2[i], basisBStar[i][1]);
			g2_copy(dS3[i], basisBStar[i][2]);
			g2_copy(dS4[i], basisBStar[i][3]);
			g2_copy(dS5[i], basisBStar[i][4]);
			g2_copy(dS6[i], basisBStar[i][5]);
		}
	}
	CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(elementA);
		bn_free(elementB);
		bn_free(elementC);
		bn_free(modulus);
		for(int i=0; i<dimension; i++){
			g1_free(intermediateResult1[i]);
			g2_free(intermediateResult2[i]);
			for(int j=0; j<dimension; j++){
				bn_free(linearTrans[i][j]);
				bn_free(invLinearTrans[i][j]);
				bn_free(tempArray[i][j]);
				g1_free(basisA1[i][j]);
				g2_free(basisA2[i][j]);
				g1_free(basisB[i][j]);
				g2_free(basisBStar[i][j]);
			}
			bn_free(tempArray[i][6]);
			bn_free(tempArray[i][7]);
			bn_free(tempArray[i][8]);
			bn_free(tempArray[i][9]);
			bn_free(tempArray[i][10]);
			bn_free(tempArray[i][11]);
		}
	}
	return result;
}

/**
 * This function performs the setup algorithm described in [2]. Variable names are
 * the same as the descriptions in [2].
 */
int setup(struct hibeMasterSecretKey *msk, struct hibePublicParameter *publicParameters){
	int result = STS_OK;
	g1_t d1[dimension], d2[dimension], d3[dimension], d4[dimension], d5[dimension], d6[dimension];
	g2_t dS1[dimension], dS2[dimension], dS3[dimension], dS4[dimension], dS5[dimension], dS6[dimension];
	bn_t alpha1, alpha2, theta, sigma, gamma, epsilon, modulus;
	gt_t pairing1, pairing2, intermediatePairing1, intermediatePairing2;
	g1_t intermediateResultG11[dimension], intermediateResultG12[dimension];

	bn_null(alpha1);
	bn_null(alpha2);
	bn_null(theta);
	bn_null(sigma);
	bn_null(gamma);
	bn_null(epsilon);
	bn_null(modulus);
	gt_null(pairing1);
	gt_null(pairing2);
	gt_null(intermediatePairing1);
	gt_null(intermediatePairing2);
	for(int i=0; i<dimension; i++){
		g1_null(intermediateResultG11[i]);
		g1_null(intermediateResultG12[i]);
		g2_null(intermediateResultG21[i]);
		g2_null(intermediateResultG22[i]);
		g1_null(d1[i]);
		g1_null(d2[i]);
		g1_null(d3[i]);
		g1_null(d4[i]);
		g1_null(d5[i]);
		g1_null(d6[i]);
		g2_null(dS1[i]);
		g2_null(dS2[i]);
		g2_null(dS3[i]);
		g2_null(dS4[i]);
		g2_null(dS5[i]);
		g2_null(dS6[i]);
	}
	TRY{
		bn_new(alpha1);
		bn_new(alpha2);
		bn_new(theta);
		bn_new(sigma);
		bn_new(gamma);
		bn_new(epsilon);
		bn_new(modulus);
		gt_new(pairing1);
		gt_new(pairing2);
		gt_new(intermediatePairing1);
		gt_new(intermediatePairing2);
		for(int i=0; i<dimension; i++){
			g1_new(intermediateResultG11[i]);
			g1_new(intermediateResultG12[i]);
			g2_new(intermediateResultG21[i]);
			g2_new(intermediateResultG22[i]);
			g1_new(d1[i]);
			g1_new(d2[i]);
			g1_new(d3[i]);
			g1_new(d4[i]);
			g1_new(d5[i]);
			g1_new(d6[i]);
			g2_new(dS1[i]);
			g2_new(dS2[i]);
			g2_new(dS3[i]);
			g2_new(dS4[i]);
			g2_new(dS5[i]);
			g2_new(dS6[i]);
		}
		sampleRandomDualOrthonormalBases(d1,d2,d3,d4,d5,d6,dS1,dS2,dS3,dS4,dS5,dS6);
		g1_get_ord(modulus);
		bn_rand_mod(alpha1, modulus);
		bn_rand_mod(alpha2, modulus);
		bn_rand_mod(theta, modulus);
		bn_rand_mod(sigma, modulus);
		bn_rand_mod(gamma, modulus);
		bn_rand_mod(epsilon, modulus);
		for(int i=0; i<dimension;i++){
			g1_mul(intermediateResultG11[i], d1[i], alpha1);
			g1_mul(intermediateResultG12[i], d2[i], alpha2);
		}
		pc_map(pairing1, intermediateResultG11[0], dS1[0]); //intermediateResultG11 = d1^alpha1
		pc_map(pairing2, intermediateResultG12[0], dS2[0]); //intermediateResultG12 = d2^alpha2
		for(int i=1; i<dimension; i++){
			pc_map(intermediatePairing1, intermediateResultG11[i], dS1[i]);
			pc_map(intermediatePairing2, intermediateResultG12[i], dS2[i]);
			gt_mul(pairing1, pairing1, intermediatePairing1);
			gt_mul(pairing2, pairing2, intermediatePairing2);
		}
		for(int i=0; i<dimension; i++){
			g2_mul(msk->dS1gamma[i], dS1[i], gamma);
			g2_mul(msk->dS2epsilon[i], dS2[i], epsilon);
			g2_mul(msk->dS3theta[i], dS3[i], theta);
			g2_mul(msk->dS4theta[i], dS4[i], theta);
			g2_mul(msk->dS5sigma[i], dS5[i], sigma);
			g2_mul(msk->dS6sigma[i], dS6[i], sigma);
		}
		gt_copy(publicParameters->pairingd1, pairing1);
		gt_copy(publicParameters->pairingd2, pairing2);
		bn_copy(msk->alpha1, alpha1);
		bn_copy(msk->alpha2, alpha2);
		for(int i=0; i<dimension; i++){
			g1_copy(publicParameters->d1[i], d1[i]);
			g1_copy(publicParameters->d2[i], d2[i]);
			g1_copy(publicParameters->d3[i], d3[i]);
			g1_copy(publicParameters->d4[i], d4[i]);
			g1_copy(publicParameters->d5[i], d5[i]);
			g1_copy(publicParameters->d6[i], d6[i]);
			g2_copy(msk->dS1[i], dS1[i]);
			g2_copy(msk->dS2[i], dS2[i]);

		}
	}
	CATCH_ANY{
		result = STS_ERR;
	}
	FINALLY{
		for(int i=0; i<dimension; i++){
			for(int j=0; j<dimension; j++){
				g1_free(intermediateResultG11[i]);
				g1_free(intermediateResultG12[i]);
				g2_free(intermediateResultG21[i]);
				g2_free(intermediateResultG22[i]);
				g1_free(d1[i]);
				g1_free(d2[i]);
				g1_free(d3[i]);
				g1_free(d4[i]);
				g1_free(d5[i]);
				g1_free(d6[i]);
				g2_free(dS1[i]);
				g2_free(dS2[i]);
				g2_free(dS3[i]);
				g2_free(dS4[i]);
				g2_free(dS5[i]);
				g2_free(dS6[i]);
			}
		}
		bn_free(alpha1);
		bn_free(alpha2);
		bn_free(theta);
		bn_free(sigma);
		bn_free(gamma);
		bn_free(epsilon);
		bn_free(modulus)
		gt_free(pairing1);
		gt_free(pairing2);
		gt_free(intermediatePairing1);
		gt_free(intermediatePairing2);
	}
	return result;
}

/**
 * This function performs the key generation algorithm described in [2]. Variable names are
 * the same as the descriptions in [2].
 * The identity ID has to be provided as uint8_t* (byte).
 * The id array has to have a minimum size of 'idLength*level'. It is interpreted as if all identites are written
 * in succession.
 */
int keyGen(struct hibeSecretKey *secretKey, struct hibeMasterSecretKey *msk, uint8_t *id, int idLength, int level){
	int result = STS_OK;
	bn_t encodedId, y, w, r1, r2, modulus, ySum, wSum;
	g2_t intermediateResult;

	g2_null(intermediateResult);
	bn_null(modulus);
	bn_null(encodedId);
	bn_null(y);
	bn_null(w);
	bn_null(r1);
	bn_null(r2);
	bn_null(ySum);
	bn_null(wSum);
	TRY {
		g2_new(intermediateResult);
		bn_new(modulus);
		bn_new(encodedId);
		bn_new(y);
		bn_new(w);
		bn_new(r1);
		bn_new(r2);
		bn_new(ySum);
		bn_new(wSum);
		g1_get_ord(modulus);
		for(int j=0; j<level-1; j++){
			uint8_t identity[idLength];
			for(int i=idLength*j; i<(idLength*j)+idLength; i++){
				identity[i-(idLength*j)] = id[i];
			}
			bn_read_bin(encodedId, identity, idLength);
			bn_mod_basic(encodedId, encodedId, modulus);
			bn_rand_mod(y, modulus);
			bn_rand_mod(w, modulus);
			bn_rand_mod(r1, modulus);
			bn_rand_mod(r2, modulus);

			bn_add(ySum, ySum, y);
			bn_mod_basic(ySum, ySum, modulus);
			bn_add(wSum, wSum, w);
			bn_mod_basic(wSum, wSum, modulus);

			for(int i=0; i<dimension; i++){
				g2_mul(secretKey->k[i+j*dimension], msk->dS1[i], y);
				g2_mul(intermediateResult, msk->dS2[i], w);
				g2_add(secretKey->k[i+j*dimension], secretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, msk->dS3theta[i], r1);
				g2_mul(intermediateResult, intermediateResult, encodedId);
				g2_add(secretKey->k[i+j*dimension], secretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, msk->dS4theta[i], r1);
				g2_sub(secretKey->k[i+j*dimension], secretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, msk->dS5sigma[i], r2);
				g2_mul(intermediateResult, intermediateResult, encodedId);
				g2_add(secretKey->k[i+j*dimension], secretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, msk->dS6sigma[i], r2);
				g2_sub(secretKey->k[i+j*dimension], secretKey->k[i+j*dimension], intermediateResult);
			}
		}
		uint8_t identity[idLength];
		for(int i=idLength*(level-1); i<(idLength*(level-1))+idLength; i++){
			identity[i-(idLength*(level-1))] = id[i];
		}
		bn_read_bin(encodedId, identity, idLength);
		bn_mod_basic(encodedId, encodedId, modulus);
		bn_rand_mod(r1, modulus);
		bn_rand_mod(r2, modulus);
		bn_sub(y, msk->alpha1, ySum);
		bn_mod_basic(y, y, modulus);
		bn_sub(w, msk->alpha2, wSum);
		bn_mod_basic(w, w, modulus);
		for(int i=0; i<dimension; i++){
			g2_mul(secretKey->k[i+(level-1)*dimension], msk->dS1[i], y);
			g2_mul(intermediateResult, msk->dS2[i], w);
			g2_add(secretKey->k[i+(level-1)*dimension], secretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, msk->dS3theta[i], r1);
			g2_mul(intermediateResult, intermediateResult, encodedId);
			g2_add(secretKey->k[i+(level-1)*dimension], secretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, msk->dS4theta[i], r1);
			g2_sub(secretKey->k[i+(level-1)*dimension], secretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, msk->dS5sigma[i], r2);
			g2_mul(intermediateResult, intermediateResult, encodedId);
			g2_add(secretKey->k[i+(level-1)*dimension], secretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, msk->dS6sigma[i], r2);
			g2_sub(secretKey->k[i+(level-1)*dimension], secretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_copy(secretKey->dS1gamma[i], msk->dS1gamma[i]);
			g2_copy(secretKey->dS2epsilon[i], msk->dS2epsilon[i]);
			g2_copy(secretKey->dS3theta[i], msk->dS3theta[i]);
			g2_copy(secretKey->dS4theta[i], msk->dS4theta[i]);
			g2_copy(secretKey->dS5sigma[i], msk->dS5sigma[i]);
			g2_copy(secretKey->dS6sigma[i], msk->dS6sigma[i]);
		}

	}
	CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		g2_free(intermediateResult);
		bn_free(modulus);
		bn_free(encodedId);
		bn_free(y);
		bn_free(w);
		bn_free(r1);
		bn_free(r2);
		bn_free(ySum);
		bn_free(wSum);
	}
	return result;
}

/**
 * This function performs the key delegation algorithm described in [2]. Variable names are
 * the same as the descriptions in [2].
 * The identity ID has to be provided as uint8_t* (byte).
 * The id array has to have a minimum size of 'idLength*level'. It is interpreted as if all identites are written
 * in succession.
 */
int keyDelegation(struct hibeSecretKey *delegatedSecretKey, struct hibeSecretKey *delegatorSecretKey, uint8_t *id, int idLength, int level){
	int result = STS_OK;
	bn_t encodedId, y, w, omega1, omega2, modulus, ySum, wSum;
	g2_t intermediateResult;

	g2_null(intermediateResult);
	bn_null(modulus);
	bn_null(encodedId);
	bn_null(y);
	bn_null(w);
	bn_null(omega1);
	bn_null(omega2);
	bn_null(ySum);
	bn_null(wSum);
	TRY{
		g2_new(intermediateResult);
		bn_new(modulus);
		bn_new(encodedId);
		bn_new(y);
		bn_new(w);
		bn_new(omega1);
		bn_new(omega2);
		bn_new(ySum);
		bn_new(wSum);
		g1_get_ord(modulus);
		for(int j=0; j<level-1; j++){
			uint8_t identity[idLength];
			for(int i=idLength*j; i<(idLength*j)+idLength; i++){
				identity[i-(idLength*j)] = id[i];
			}
			bn_read_bin(encodedId, identity, idLength);
			bn_mod_basic(encodedId, encodedId, modulus);
			bn_rand_mod(y, modulus);
			bn_rand_mod(w, modulus);
			bn_rand_mod(omega1, modulus);
			bn_rand_mod(omega2, modulus);

			bn_add(ySum, ySum, y);
			bn_mod_basic(ySum, ySum, modulus);
			bn_add(wSum, wSum, w);
			bn_mod_basic(wSum, wSum, modulus);

			for(int i=0; i<dimension; i++){
				g2_mul(delegatedSecretKey->k[i+j*dimension], delegatorSecretKey->dS1gamma[i], y);
				g2_mul(intermediateResult, delegatorSecretKey->dS2epsilon[i], w);
				g2_add(delegatedSecretKey->k[i+j*dimension], delegatedSecretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, delegatorSecretKey->dS3theta[i], omega1);
				g2_mul(intermediateResult, intermediateResult, encodedId);
				g2_add(delegatedSecretKey->k[i+j*dimension], delegatedSecretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, delegatorSecretKey->dS4theta[i], omega1);
				g2_sub(delegatedSecretKey->k[i+j*dimension], delegatedSecretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, delegatorSecretKey->dS5sigma[i], omega2);
				g2_mul(intermediateResult, intermediateResult, encodedId);
				g2_add(delegatedSecretKey->k[i+j*dimension], delegatedSecretKey->k[i+j*dimension], intermediateResult);
				g2_mul(intermediateResult, delegatorSecretKey->dS6sigma[i], omega2);
				g2_sub(delegatedSecretKey->k[i+j*dimension], delegatedSecretKey->k[i+j*dimension], intermediateResult);
				g2_add(delegatedSecretKey->k[i+j*dimension], delegatedSecretKey->k[i+j*dimension], delegatorSecretKey->k[i+j*dimension]);
			}
		}
		uint8_t identity[idLength];
		for(int i=idLength*(level-1); i<(idLength*(level-1))+idLength; i++){
			identity[i-(idLength*(level-1))] = id[i];
		}
		bn_read_bin(encodedId, identity, idLength);
		bn_mod_basic(encodedId, encodedId, modulus);
		bn_rand_mod(omega1, modulus);
		bn_rand_mod(omega2, modulus);
		bn_neg(y,ySum);
		bn_mod_basic(y, y, modulus);
		bn_neg(w,wSum);
		bn_mod_basic(w, w, modulus);
		for(int i=0; i<dimension; i++){
			g2_mul(delegatedSecretKey->k[i+(level-1)*dimension], delegatorSecretKey->dS1gamma[i], y);
			g2_mul(intermediateResult, delegatorSecretKey->dS2epsilon[i], w);
			g2_add(delegatedSecretKey->k[i+(level-1)*dimension], delegatedSecretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, delegatorSecretKey->dS3theta[i], omega1);
			g2_mul(intermediateResult, intermediateResult, encodedId);
			g2_add(delegatedSecretKey->k[i+(level-1)*dimension], delegatedSecretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, delegatorSecretKey->dS4theta[i], omega1);
			g2_sub(delegatedSecretKey->k[i+(level-1)*dimension], delegatedSecretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, delegatorSecretKey->dS5sigma[i], omega2);
			g2_mul(intermediateResult, intermediateResult, encodedId);
			g2_add(delegatedSecretKey->k[i+(level-1)*dimension], delegatedSecretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_mul(intermediateResult, delegatorSecretKey->dS6sigma[i], omega2);
			g2_sub(delegatedSecretKey->k[i+(level-1)*dimension], delegatedSecretKey->k[i+(level-1)*dimension], intermediateResult);
			g2_copy(delegatedSecretKey->dS1gamma[i], delegatorSecretKey->dS1gamma[i]);
			g2_copy(delegatedSecretKey->dS2epsilon[i], delegatorSecretKey->dS2epsilon[i]);
			g2_copy(delegatedSecretKey->dS3theta[i], delegatorSecretKey->dS3theta[i]);
			g2_copy(delegatedSecretKey->dS4theta[i], delegatorSecretKey->dS4theta[i]);
			g2_copy(delegatedSecretKey->dS5sigma[i], delegatorSecretKey->dS5sigma[i]);
			g2_copy(delegatedSecretKey->dS6sigma[i], delegatorSecretKey->dS6sigma[i]);
		}
	}
	CATCH_ANY{
		result = STS_ERR;
	}
	FINALLY{
		g2_free(intermediateResult);
		bn_free(modulus);
		bn_free(encodedId);
		bn_free(y);
		bn_free(w);
		bn_free(omega1);
		bn_free(omega2);
		bn_free(ySum);
		bn_free(wSum);
	}
	return result;
}

/**
 * This function performs the encryption algorithm described in [2]. Variable names are
 * the same as the descriptions in [2].
 * The identity ID has to be provided as uint8_t* (byte).
 * The id array has to have a minimum size of 'idLength*level'. It is interpreted as if all identites are written
 * in succession.
 */
int encrypt(struct hibeCiphertext *ciphertext, struct hibePublicParameter *publicParameter, gt_t message, uint8_t *id, int idLength, int level){
	int result = STS_OK;
	bn_t modulus, s1, s2, t1, t2, encodedId;
	gt_t intermediateResultGT;
	g1_t intermediateResultG1;

	bn_null(modulus);
	bn_null(s1);
	bn_null(s2);
	bn_null(t1);
	bn_null(t2);
	bn_null(encodedId);
	gt_null(intermediateResultGT);
	g1_null(intermediateResultG1);
	TRY{
		bn_new(modulus);
		bn_new(s1);
		bn_new(s2);
		bn_new(t1);
		bn_new(t2);
		bn_new(encodedId);
		gt_new(intermediateResultGT);
		g1_new(intermediateResultG1);
		g1_get_ord(modulus);
		bn_rand_mod(s1, modulus);
		bn_rand_mod(s2, modulus);
		gt_exp(intermediateResultGT, publicParameter->pairingd1, s1);
		gt_mul(ciphertext->c0, message, intermediateResultGT);
		gt_exp(intermediateResultGT, publicParameter->pairingd2, s2);
		gt_mul(ciphertext->c0, ciphertext->c0, intermediateResultGT);

		for(int j=0; j<level; j++){
			uint8_t identity[idLength];
			for(int i=idLength*j; i<(idLength*j)+idLength; i++){
				identity[i-(idLength*j)] = id[i];
			}
			bn_read_bin(encodedId, identity, idLength);
			bn_mod_basic(encodedId, encodedId, modulus);
			bn_rand_mod(t1, modulus);
			bn_rand_mod(t2, modulus);
			for(int i=0; i<dimension; i++){
				g1_mul(ciphertext->c[i+j*dimension], publicParameter->d1[i], s1);
				g1_mul(intermediateResultG1, publicParameter->d2[i], s2);
				g1_add(ciphertext->c[i+j*dimension], ciphertext->c[i+j*dimension], intermediateResultG1);
				g1_mul(intermediateResultG1, publicParameter->d3[i], t1);
				g1_add(ciphertext->c[i+j*dimension], ciphertext->c[i+j*dimension], intermediateResultG1);
				g1_mul(intermediateResultG1, publicParameter->d4[i], t1);
				g1_mul(intermediateResultG1, intermediateResultG1, encodedId);
				g1_add(ciphertext->c[i+j*dimension], ciphertext->c[i+j*dimension], intermediateResultG1);
				g1_mul(intermediateResultG1, publicParameter->d5[i], t2);
				g1_add(ciphertext->c[i+j*dimension], ciphertext->c[i+j*dimension], intermediateResultG1);
				g1_mul(intermediateResultG1, publicParameter->d6[i], t2);
				g1_mul(intermediateResultG1, intermediateResultG1, encodedId);
				g1_add(ciphertext->c[i+j*dimension], ciphertext->c[i+j*dimension], intermediateResultG1);
			}
		}
	}
	CATCH_ANY{
		result = STS_ERR;
	}
	FINALLY{
		bn_free(modulus);
		bn_free(s1);
		bn_free(s2);
		bn_free(t1);
		bn_free(t2);
		bn_free(encodedId);
		gt_free(intermediateResultGT);
		g1_free(intermediateResultG1);
	}
	return result;
}
/**
 * This function performs the decryption algorithm described in [2]. Variable names are
 * the same as the descriptions in [2].
*/
int decrypt(gt_t message, struct hibeSecretKey *secretKey, struct hibeCiphertext *ciphertext){
	int result = STS_OK;
	gt_t intermediatePairingResult, b;

	gt_null(intermediatePairingResult);
	gt_null(b);
	TRY{
		gt_new(intermediatePairingResult);
		gt_new(b);
		pc_map(b, ciphertext->c[0], secretKey->k[0]);
		for(int i=1; i<dimension*ciphertext->level; i++){
			pc_map(intermediatePairingResult, ciphertext->c[i], secretKey->k[i]);
			gt_mul(b, b, intermediatePairingResult);
		}
		gt_inv(b, b);
		gt_mul(message, ciphertext->c0, b);
	}
	CATCH_ANY{
		result = STS_ERR;
	}
	FINALLY{
		gt_free(intermediatePairingResult);
		gt_free(b);
	}
	return result;
}

/**
 * This function encodes a master secret key as a uint8_t(byte) array.
 */
void encodeMasterKey(uint8_t *encodedMasterKey, struct hibeMasterSecretKey *msk){
	int lengthBN, lengthG2, index = 0;
	lengthBN = bn_size_bin(msk->alpha1);
	lengthG2 = g2_size_bin(msk->dS1[0],1);
	uint8_t bnElement[lengthBN];
	uint8_t g2Element[lengthG2];
	bn_write_bin(bnElement, lengthBN, msk->alpha1);
	for(int i = index; i < lengthBN+index; i++){
		encodedMasterKey[i] = bnElement[i-index];
	}
	index += lengthBN;
	bn_write_bin(bnElement, lengthBN, msk->alpha2);
	for(int i = index; i < lengthBN+index; i++){
		encodedMasterKey[i] = bnElement[i-index];
	}
	index += lengthBN;
	for(int j=0; j<dimension; j++){
		g2_write_bin(g2Element, lengthG2, msk->dS1[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, msk->dS2[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, msk->dS1gamma[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, msk->dS2epsilon[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, msk->dS3theta[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, msk->dS4theta[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, msk->dS5sigma[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, msk->dS6sigma[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedMasterKey[i] = g2Element[i-index];
		}
		index += lengthG2;
	}
}

/**
 * This function decodes a master secret key from a uint8_t(byte) array.
 */
void decodeMasterKey(struct hibeMasterSecretKey *msk, uint8_t *encodedMsk){
	int lengthBN, lengthG2, index = 0;
	bn_t bnElement, modulus;
	g2_t g2Element;

	bn_new(bnElement);
	bn_new(modulus);
	g2_new(g2Element);
	g2_get_ord(modulus);
	bn_rand_mod(bnElement, modulus);
	g2_rand(g2Element);

	lengthBN = bn_size_bin(bnElement);
	lengthG2 = g2_size_bin(g2Element,1);
	uint8_t encodedBnElement[lengthBN];
	uint8_t encodedG2Element[lengthG2];

	for(int i = index; i < lengthBN+index; i++){
		encodedBnElement[i-index] = encodedMsk[i];
	}
	index += lengthBN;
	bn_read_bin(msk->alpha1, encodedBnElement, lengthBN);

	for(int i = index; i < lengthBN+index; i++){
		encodedBnElement[i-index] = encodedMsk[i];
	}
	index += lengthBN;
	bn_read_bin(msk->alpha2, encodedBnElement, lengthBN);

	for(int j=0; j<dimension; j++){
		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS1[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS2[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS1gamma[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS2epsilon[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS3theta[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS4theta[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS5sigma[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedMsk[i];
		}
		index += lengthG2;
		g2_read_bin(msk->dS6sigma[j], encodedG2Element, lengthG2);
	}

	bn_free(bnElement);
	bn_free(modulus);
	g2_free(g2Element);
}

/**
 * This function encodes a secret key as a uint8_t(byte) array.
 */
void encodeSecretKey(uint8_t *encodedSecretKey, struct hibeSecretKey *secretKey){
	int lengthG2, index = 0;
	lengthG2 = g2_size_bin(secretKey->dS1gamma[0],1);
	uint8_t g2Element[lengthG2];
	for(int j=0; j<dimension; j++){
		g2_write_bin(g2Element, lengthG2, secretKey->dS1gamma[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedSecretKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, secretKey->dS2epsilon[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedSecretKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, secretKey->dS3theta[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedSecretKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, secretKey->dS4theta[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedSecretKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, secretKey->dS5sigma[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedSecretKey[i] = g2Element[i-index];
		}
		index += lengthG2;

		g2_write_bin(g2Element, lengthG2, secretKey->dS6sigma[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedSecretKey[i] = g2Element[i-index];
		}
		index += lengthG2;
	}
	for(int j=0; j<dimension*secretKey->level; j++){
		g2_write_bin(g2Element, lengthG2, secretKey->k[j],1);
		for(int i = index; i < lengthG2+index; i++){
			encodedSecretKey[i] = g2Element[i-index];
		}
		index += lengthG2;
	}
}

/**
 * This function decodes a secret key from a uint8_t(byte) array.
 */
void decodeSecretKey(struct hibeSecretKey *secretKey, uint8_t *encodedSecretKey){
	int  lengthG2, index = 0;
	g2_t g2Element;

	g2_new(g2Element);
	g2_rand(g2Element);

	lengthG2 = g2_size_bin(g2Element,1);
	uint8_t encodedG2Element[lengthG2];

	for(int j=0; j<dimension; j++){
		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedSecretKey[i];
		}
		index += lengthG2;
		g2_read_bin(secretKey->dS1gamma[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedSecretKey[i];
		}
		index += lengthG2;
		g2_read_bin(secretKey->dS2epsilon[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedSecretKey[i];
		}
		index += lengthG2;
		g2_read_bin(secretKey->dS3theta[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedSecretKey[i];
		}
		index += lengthG2;
		g2_read_bin(secretKey->dS4theta[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedSecretKey[i];
		}
		index += lengthG2;
		g2_read_bin(secretKey->dS5sigma[j], encodedG2Element, lengthG2);

		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedSecretKey[i];
		}
		index += lengthG2;
		g2_read_bin(secretKey->dS6sigma[j], encodedG2Element, lengthG2);
	}

	for(int j=0; j<dimension*secretKey->level; j++){
		for(int i = index; i < lengthG2+index; i++){
			encodedG2Element[i-index] = encodedSecretKey[i];
		}
		g2_read_bin(secretKey->k[j], encodedG2Element, lengthG2);
		index += lengthG2;
	}
	g2_free(g2Element);
}

/**
 * This function encodes the public parameters as a uint8_t(byte) array.
 */
void encodePublicParameter(uint8_t *encodedPublicParameter, struct hibePublicParameter *publicParameter){
	int lengthG1, lengthGT, index = 0;
	lengthG1 = g1_size_bin(publicParameter->d1[0],1);
	lengthGT = gt_size_bin(publicParameter->pairingd1, 1);
	uint8_t g1Element[lengthG1];
	uint8_t gtElement[lengthGT];

	gt_write_bin(gtElement, lengthGT, publicParameter->pairingd1, 1);
	for(int i = index; i < lengthGT+index; i++){
		encodedPublicParameter[i] = gtElement[i-index];
	}
	index += lengthGT;

	gt_write_bin(gtElement, lengthGT, publicParameter->pairingd2, 1);
	for(int i = index; i < lengthGT+index; i++){
		encodedPublicParameter[i] = gtElement[i-index];
	}
	index += lengthGT;

	for(int j=0; j<dimension; j++){
		g1_write_bin(g1Element, lengthG1, publicParameter->d1[j], 1);
		for(int i = index; i < lengthG1+index; i++){
			encodedPublicParameter[i] = g1Element[i-index];
		}
		index += lengthG1;

		g1_write_bin(g1Element, lengthG1, publicParameter->d2[j], 1);
		for(int i = index; i < lengthG1+index; i++){
			encodedPublicParameter[i] = g1Element[i-index];
		}
		index += lengthG1;
		g1_write_bin(g1Element, lengthG1, publicParameter->d3[j], 1);
		for(int i = index; i < lengthG1+index; i++){
			encodedPublicParameter[i] = g1Element[i-index];
		}
		index += lengthG1;
		g1_write_bin(g1Element, lengthG1, publicParameter->d4[j], 1);
		for(int i = index; i < lengthG1+index; i++){
			encodedPublicParameter[i] = g1Element[i-index];
		}
		index += lengthG1;
		g1_write_bin(g1Element, lengthG1, publicParameter->d5[j], 1);
		for(int i = index; i < lengthG1+index; i++){
			encodedPublicParameter[i] = g1Element[i-index];
		}
		index += lengthG1;
		g1_write_bin(g1Element, lengthG1, publicParameter->d6[j], 1);
		for(int i = index; i < lengthG1+index; i++){
			encodedPublicParameter[i] = g1Element[i-index];
		}
		index += lengthG1;
	}
}

/**
 * This function decodes the public parameters from a uint8_t(byte) array.
 */
void decodePublicParameter(struct hibePublicParameter *publicParameter, uint8_t *encodedPublicParameter){
	int lengthG1, lengthGT, index = 0;
	g1_t g1Element;
	gt_t gtElement;

	g1_new(g1Element);
	gt_new(gtElement);

	g1_rand(g1Element);
	gt_rand(gtElement);

	lengthG1 = g1_size_bin(g1Element,1);
	lengthGT = gt_size_bin(gtElement,1);
	uint8_t encodedG1Element[lengthG1];
	uint8_t encodedGTElement[lengthGT];

	for(int i = index; i < lengthGT+index; i++){
		encodedGTElement[i-index] = encodedPublicParameter[i];
	}
	index += lengthGT;
	gt_read_bin(publicParameter->pairingd1, encodedGTElement, lengthGT);

	for(int i = index; i < lengthGT+index; i++){
		encodedGTElement[i-index] = encodedPublicParameter[i];
	}
	index += lengthGT;
	gt_read_bin(publicParameter->pairingd2, encodedGTElement, lengthGT);

	for(int j=0; j<dimension; j++){
		for(int i = index; i < lengthG1+index; i++){
			encodedG1Element[i-index] = encodedPublicParameter[i];
		}
		g1_read_bin(publicParameter->d1[j], encodedG1Element, lengthG1);
		index += lengthG1;

		for(int i = index; i < lengthG1+index; i++){
			encodedG1Element[i-index] = encodedPublicParameter[i];
		}
		g1_read_bin(publicParameter->d2[j], encodedG1Element, lengthG1);
		index += lengthG1;

		for(int i = index; i < lengthG1+index; i++){
			encodedG1Element[i-index] = encodedPublicParameter[i];
		}
		g1_read_bin(publicParameter->d3[j], encodedG1Element, lengthG1);
		index += lengthG1;

		for(int i = index; i < lengthG1+index; i++){
			encodedG1Element[i-index] = encodedPublicParameter[i];
		}
		g1_read_bin(publicParameter->d4[j], encodedG1Element, lengthG1);
		index += lengthG1;

		for(int i = index; i < lengthG1+index; i++){
			encodedG1Element[i-index] = encodedPublicParameter[i];
		}
		g1_read_bin(publicParameter->d5[j], encodedG1Element, lengthG1);
		index += lengthG1;

		for(int i = index; i < lengthG1+index; i++){
			encodedG1Element[i-index] = encodedPublicParameter[i];
		}
		g1_read_bin(publicParameter->d6[j], encodedG1Element, lengthG1);
		index += lengthG1;
	}
	g1_free(g1Element);
	gt_free(gtElement);
}

/**
 * This function encodes a ciphertext as a uint8_t(byte) array.
 */
void encodeCiphertext(uint8_t *encodedCiphertext, struct hibeCiphertext *ciphertext){
	int sizeOfGT, sizeOfG1, index=0;
	sizeOfG1 = g1_size_bin(ciphertext->c[0],1);
	sizeOfGT = gt_size_bin(ciphertext->c0, 0);
	uint8_t g1Element[sizeOfG1];
	uint8_t gtElement[sizeOfGT];

	gt_write_bin(gtElement, sizeOfGT, ciphertext->c0, 0);
	for(int i = index; i < sizeOfGT+index; i++){
		encodedCiphertext[i] = gtElement[i-index];
	}
	index += sizeOfGT;

	for(int j=0; j<dimension*ciphertext->level; j++){
		g1_write_bin(g1Element, sizeOfG1, ciphertext->c[j], 1);
		for(int i = index; i < sizeOfG1+index; i++){
			encodedCiphertext[i] = g1Element[i-index];
		}
		index += sizeOfG1;
	}
}

/**
 * This function decodes a ciphertext as a uint8_t(byte) array.
 */
void decodeCiphertext(struct hibeCiphertext *ciphertext, uint8_t *encodedCiphertext){
	int sizeOfGT, sizeOfG1, index=0;
	gt_t gtElement;
	g1_t g1Element;

	gt_new(gtElement);
	g1_new(g1Element);

	gt_rand(gtElement);
	g1_rand(g1Element);

	sizeOfG1 = g1_size_bin(g1Element, 1);
	sizeOfGT = gt_size_bin(gtElement, 0);

	uint8_t encodedG1Element[sizeOfG1];
	uint8_t encodedGtElement[sizeOfGT];

	for(int i = index; i < sizeOfGT+index; i++){
		encodedGtElement[i-index] = encodedCiphertext[i];
	}
	index += sizeOfGT;
	gt_read_bin(ciphertext->c0, encodedGtElement, sizeOfGT);

	for(int j=0; j<dimension*ciphertext->level; j++){
		for(int i = index; i < sizeOfG1+index; i++){
			encodedG1Element[i-index] = encodedCiphertext[i];
		}
		index += sizeOfG1;
		g1_read_bin(ciphertext->c[j], encodedG1Element, sizeOfG1);
	}

	g1_free(g1Element);
	gt_free(gtElement);
}

/**
 * This function computes the size of encoded public parameters.
 */
int getSizeOfEncodedPublicParameter(){
	int lengthG1, lengthGT;
	g1_t g1Element;
	gt_t gtElement;

	g1_new(g1Element);
	gt_new(gtElement);

	g1_rand(g1Element);
	gt_rand(gtElement);

	lengthG1 = g1_size_bin(g1Element,1);
	lengthGT = gt_size_bin(gtElement,1);

	g1_free(g1Element);
	gt_free(gtElement);

	int size = lengthG1*(dimension*dimension)+lengthGT*2;
	return size;
}

/**
 * This function computes the size of a secret key at level i.
 */
int getSizeOfEncodedSecretKeyAtLevel(int level){
	int  lengthG2;
	g2_t g2Element;

	g2_new(g2Element);
	g2_rand(g2Element);

	lengthG2 = g2_size_bin(g2Element,1);

	g2_free(g2Element);

	int size = lengthG2*(dimension*dimension) + (level*dimension)*lengthG2;
	return size;
}

/**
 * This function computes the size of a master secret key.
 */
int getSizeOfEncodedMasterSecret(){
	int lengthBN, lengthG2;
	bn_t bnElement, modulus;
	g2_t g2Element;

	bn_new(bnElement);
	bn_new(modulus);
	g2_new(g2Element);
	g2_get_ord(modulus);

	bn_rand_mod(bnElement, modulus);
	g2_rand(g2Element);

	lengthBN = bn_size_bin(bnElement);
	lengthG2 = g2_size_bin(g2Element,1);

	bn_free(modulus);
	bn_free(bnElement);
	g2_free(g2Element);

	int size = lengthG2*(dimension*(dimension+2))+2*lengthBN;
	return size;
}

/**
 * This function computes the size of a ciphertext at level i.
 */
int getSizeOfEncodedCiphertextAtLevel(int level){
	int lengthGt;
	int lengthG1;
	g1_t g1Element;
	gt_t gtElement

	g1_new(g1Element);
	gt_new(gtElement);
	g1_rand(g1Element);
	gt_rand(gtElement);

	lengthG1 = g1_size_bin(g1Element,1);
	lengthGt = gt_size_bin(gtElement,0);

	g1_free(g1Element);
	gt_free(gtElement);

	int size = lengthGt + (level*dimension)*lengthG1;
	return size;
}

