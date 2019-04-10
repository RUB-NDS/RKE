package de.rub.rkeinstantiation.brkekem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.kems.ECIESKeyEncapsulation;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import de.rub.rke.kem.KemCiphertext;
import de.rub.rke.kem.KemKeyPair;
import de.rub.rke.kem.KemOutput;
import de.rub.rke.kem.KemPublicKey;
import de.rub.rke.kem.KemSecretKey;
import de.rub.rke.kem.KeyEncapsulationMechanism;
import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rkeinstantiation.utility.SecureRandomBuilder;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;

/**
 * Implementation of an ECIES Kem[1] (provided by bouncy castle) for the use in
 * the Brke construction.
 * 
 * 
 * [1] ISO/IEC 18033-2: Information techology - Security techniques 
 * Encryption algorithms - Part 2: Asymmetric Ciphers
 * https://www.shoup.net/iso/std4.pdf
 * 
 * @author Marco Smeets
 *
 */
public class ECIESKeyEncapsulationMechanism implements KeyEncapsulationMechanism {

	private ECIESKeyEncapsulation eciesKem;
	private ECDomainParameters ecParameter;
	private int ciphertextSize;
	private int generatedKeyLength;
	/**
	 * To calculate the size of the ciphertext, we have to calculate the size of an encoded point.
	 * We use the following formula for a point P on a curve for ECIES-Kem[1]:
	 *  1+2*(log_256(F)) , where F is the field size.
	 */
	final int BYTE_SIZE = 8;
	final int TWO = 2;
	final int ONE = 1;

	/**
	 * Creates an ECIES Kem. Uses the provided elliptic curve and key derivation
	 * function.
	 * 
	 * @param ecParameter
	 * @param kdf
	 * @param randomness
	 * @param generatedKeyLength
	 */
	public ECIESKeyEncapsulationMechanism(ECDomainParameters ecParameter, DerivationFunction kdf,
			SecureRandom randomness, int generatedKeyLength) {
		eciesKem = new ECIESKeyEncapsulation(kdf, randomness);
		this.ecParameter = ecParameter;
		ciphertextSize = (ecParameter.getCurve().getFieldSize() / BYTE_SIZE) * TWO + ONE;
		this.generatedKeyLength = generatedKeyLength;
	}

	@Override
	public KemKeyPair gen(SecureRandom randomness) {
		ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
		keyPairGenerator.init(new ECKeyGenerationParameters(ecParameter, randomness));
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
		return new ECIESKemKeyPair(keyPair);
	}

	@Override
	public KemKeyPair gen(KeySeed seed) {
		SecureRandom randomness = SecureRandomBuilder.createSeedableRandomness();
		randomness.setSeed(seed.getSeedAsBytes());
		ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
		keyPairGenerator.init(new ECKeyGenerationParameters(ecParameter, randomness));
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
		return new ECIESKemKeyPair(keyPair);
	}

	/**
	 * We currently do not use this function.
	 */
	@Override
	public KemPublicKey gen(KemSecretKey secretKey) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public KemOutput encapsulate(KemPublicKey publicKey) {
		ECPublicKeyParameters ecPublicKey = ((ECIESKemPublicKey) publicKey).getECPublicParameter();
		byte[] ciphertext = new byte[ciphertextSize];
		eciesKem.init(ecPublicKey);
		CipherParameters generatedKey = eciesKem.encrypt(ciphertext, generatedKeyLength);
		return new ECIESKemOutput((KeyParameter) generatedKey, ciphertext);
	}

	@Override
	public SymmetricKey decapsulate(KemSecretKey secretKey, KemCiphertext ciphertext) {
		ECPrivateKeyParameters ecSecretKey = ((ECIESKemSecretKey) secretKey).getECSecretParameter();
		eciesKem.init(ecSecretKey);
		CipherParameters generatedKey = eciesKem.decrypt(((ECIESKemCiphertext) ciphertext).getCiphertext(),
				generatedKeyLength);
		return new BrkeSymmetricKey(((KeyParameter) generatedKey).getKey());
	}

}
