package de.rub.rkeinstantiation.hibewrapper;

import java.security.SecureRandom;
import java.util.Arrays;

import cz.adamh.utils.NativeUtils;
import java.io.*;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Wrapper for C++ Implementation of the Lewko-Waters Hibe [1].
 * 
 * The C++ implementation uses the prime order translation described in [2].
 * 
 * As the dimension for the Dual Pairing Vector Spaces(DPVS) we use 6.
 * 
 * Since the key-updateable Kem [3] requires the HIBE to be IND-ID-CCA secure we
 * use the CPA -> CCA transformation described in [4].
 * 
 * [1] Unbounded HIBE and Attribute-Based Encryption
 * https://link.springer.com/content/pdf/10.1007/978-3-642-20465-4_30.pdf
 * [2]Tools for Simulating Features of Composite Order Bilinear Groups in the
 * Prime Order Setting
 * https://link.springer.com/content/pdf/10.1007/978-3-642-29011-4_20.pdf
 * [3]Asynchronous ratcheted key exchange https://eprint.iacr.org/2018/296.pdf
 * [4]Chosen-Ciphertext Security from Identity-Based Encryption
 * http://boneh.com/pubs/papers/ccaibejour.pdf
 * 
 * @author Marco Smeets
 *
 */
public class Hibe {

	private static native int getSizeOfBnModZp();

	private static native int getSizeOfG1();

	private static native int getSizeOfG2();

	private static native int getSizeOfGT();

	private static native int getSizeOfuncompressedGT();

	private static native byte[] getRandomGtElement(byte[] seed);

	private static native byte[] setup(byte[] identity, int identityLength, byte[] seed);

	private static native byte[] encrypt(byte[] publicParameter, byte[] message, byte[] identity, int identityLength,
			int numberOfIdentities, byte[] seed);

	public static native byte[] decrypt(byte[] secretKey, byte[] ciphertext, int numberOfIdentities);

	private static native byte[] delegate(byte[] delegatorSecretKey, byte[] identity, int identityLength,
			int numberOfIdentities, byte[] seed);

	/**
	 * GeneratedKeyLength, sizeOfSeed, k, k1 are temporarily set to these values.
	 * k,k1 are required for the CCA transformation[4].
	 */
	private final int generatedKeyLength = 32;
	private final int dpvsDimension = 6;
	private final int sizeOfSeed = 32;
	private final int k = 32;
	private final int k1 = 96;
	private int sizeOfG1;
	private int sizeOfG2;
	private int sizeOfcompressedGT;
	private int sizeOfuncompressedGt;
	private int sizeOfCCAIdentityData;
	/**
	 * Might change those algorithms later. These are required for the CCA
	 * transformation[4].
	 */
	private SHA256Digest encapsulationHash;
	private HKDFBytesGenerator keyedHash;
	private HKDFBytesGenerator keyGenerator;
	private HMac hmacAlgorithm;

	/**
	 * Constructor - Can be used to set specific hash functions (Not sure if
	 * required)
	 * 
	 * @param sizeOfIdentityData   - Size of the data used as identity information
	 * @param hashForEncapsulation - hash function, which is used for the
	 *                             encapsulation
	 * @param hashForKeyGen        - hash function, which is used for key generation
	 * @param hashForHmac          - hash function, which is used for the HMac
	 */
	public Hibe(int sizeOfIdentityData, Digest hashForEncapsulation, Digest hashForKeyGen, Digest hashForHmac) {
		try {
			NativeUtils.loadLibraryFromJar("/liblwhibe11.so");
		} catch (IOException e) {
			e.printStackTrace();
		}
		sizeOfG1 = getSizeOfG1();
		sizeOfG2 = getSizeOfG2();
		sizeOfcompressedGT = getSizeOfGT();
		sizeOfuncompressedGt = getSizeOfuncompressedGT();
		sizeOfCCAIdentityData = sizeOfIdentityData + 1;
		keyedHash = new HKDFBytesGenerator(hashForEncapsulation);
		keyGenerator = new HKDFBytesGenerator(hashForKeyGen);
		hmacAlgorithm = new HMac(hashForHmac);

	}

	/**
	 * Constructor - Uses SHA256 as default hash function in encapsulation, key
	 * generation, and HMac
	 * 
	 * @param sizeOfIdentityData - Size of the data used as identity information
	 */
	public Hibe(int sizeOfIdentityData) {
		try {
			NativeUtils.loadLibraryFromJar("/liblwhibe11.so");
		} catch (IOException e) {
			e.printStackTrace();
		}
		sizeOfG1 = getSizeOfG1();
		sizeOfG2 = getSizeOfG2();
		sizeOfcompressedGT = getSizeOfGT();
		sizeOfuncompressedGt = getSizeOfuncompressedGT();
		sizeOfCCAIdentityData = sizeOfIdentityData + 1;
		SHA256Digest hashForEncapsulation = new SHA256Digest();
		SHA256Digest hashForKeyGen = new SHA256Digest();
		SHA256Digest hashForHmac = new SHA256Digest();
		keyedHash = new HKDFBytesGenerator(hashForEncapsulation);
		keyGenerator = new HKDFBytesGenerator(hashForKeyGen);
		hmacAlgorithm = new HMac(hashForHmac);

	}

	/**
	 * Calls the setup algorithm of the LWHIBE.
	 * 
	 * @param identity   - identity for the secret key
	 * @param randomness - randomness used for generating random values
	 * @return HibeKeyPair
	 */
	public HibeKeyPair setup(byte[] identity, SecureRandom randomness) {
		byte[] seed = new byte[sizeOfSeed];
		randomness.nextBytes(seed);

		/**
		 * Encode the identity as described in [4]
		 */
		byte[] encodedIdentity = new byte[sizeOfCCAIdentityData];
		encodedIdentity[0] = 0;
		System.arraycopy(identity, 0, encodedIdentity, 1, identity.length);

		/**
		 * Call the setup algorithm with the necoded identity.
		 */
		byte[] encodedKeys = setup(encodedIdentity, sizeOfCCAIdentityData, seed);

		/**
		 * Generate a random 'key' used for encapsulation[4].
		 */
		byte[] encapsulationKey = new byte[generatedKeyLength];
		randomness.nextBytes(encapsulationKey);

		/**
		 * The setup algorithm of the Hibe returns a large byte array, which contains
		 * both the public parameters and the secret key. We have to save them
		 * seperately.
		 */
		int sizeOfEncodedPublicKey = sizeOfcompressedGT * 2 + sizeOfG1 * (dpvsDimension * dpvsDimension);
		int sizeOfEncodedSecretKey = sizeOfG2 * (dpvsDimension * dpvsDimension) + sizeOfG2 * dpvsDimension;
		byte[] publicParameter = new byte[sizeOfEncodedPublicKey];
		byte[] secretKey = new byte[sizeOfEncodedSecretKey];

		System.arraycopy(encodedKeys, 0, publicParameter, 0, sizeOfEncodedPublicKey);
		System.arraycopy(encodedKeys, sizeOfEncodedPublicKey, secretKey, 0, sizeOfEncodedSecretKey);
		return new HibeKeyPair(new HibeSecretKey(secretKey, encapsulationKey),
				new HibePublicParameter(publicParameter, encapsulationKey));
	}

	/**
	 * This function generates a random key, and encrypts it with the LWHIBE.
	 * 
	 * @param publicParameter - public Parameters used for encryption
	 * @param identity        - identity to encrypt to
	 * @param level           - 'depth' of the user
	 * @param randomness      - randomness used for generating keys.
	 * @return key and encrypted key
	 */
	public HibeOutput encapsulate(HibePublicParameter publicParameter, byte[] identity, int level,
			SecureRandom randomness) {
		byte[] seed = new byte[sizeOfSeed];
		randomness.nextBytes(seed);
		/**
		 * Since the message space is GT, we generate a random GT Element used to
		 * generate a key, and 'dec' for the encapsulation[4].
		 */
		byte[] randomElement = getRandomGtElement(seed);

		/**
		 * Encapsulate 'dec' for the CCA Transformation[4].
		 */
		byte[] com = new byte[k];
		byte[] r = new byte[k];
		/**
		 * Dec are the first 'k1' bytes of the random element.
		 */
		byte[] dec = Arrays.copyOf(randomElement, k1);
		byte[] inputForBytesGeneration = new byte[dec.length
				+ publicParameter.getEncapsulationPublicParameter().length];
		System.arraycopy(publicParameter.getEncapsulationPublicParameter(), 0, inputForBytesGeneration, 0,
				publicParameter.getEncapsulationPublicParameter().length);
		System.arraycopy(dec, 0, inputForBytesGeneration, publicParameter.getEncapsulationPublicParameter().length,
				dec.length);
		keyedHash.init(new HKDFParameters(inputForBytesGeneration, null, null));

		keyedHash.generateBytes(com, 0, k);
		encapsulationHash = new SHA256Digest();
		encapsulationHash.update(dec, 0, k1);
		encapsulationHash.doFinal(r, 0);

		/**
		 * Encode the identites for encryption[4]
		 */
		byte[] encodedIdentities = new byte[sizeOfCCAIdentityData * level + sizeOfCCAIdentityData];
		for (int i = 0; i < level; i++) {
			encodedIdentities[i * sizeOfCCAIdentityData] = 0;
			System.arraycopy(identity, i * (sizeOfCCAIdentityData - 1), encodedIdentities,
					i * sizeOfCCAIdentityData + 1, sizeOfCCAIdentityData - 1);
		}
		/**
		 * Append 'com' to the identity information
		 */
		encodedIdentities[sizeOfCCAIdentityData * level] = 1;
		System.arraycopy(com, 0, encodedIdentities, sizeOfCCAIdentityData * level + 1, sizeOfCCAIdentityData - 1);

		/**
		 * Encrypt the random Element
		 */
		randomness.nextBytes(seed);
		byte[] ciphertext = encrypt(publicParameter.getEncodedHibePublicParameter(), randomElement, encodedIdentities,
				sizeOfCCAIdentityData, level + 1, seed);
		/**
		 * Compute the Mac Tag of the ciphertext[4].
		 */
		hmacAlgorithm.init(new KeyParameter(r));
		hmacAlgorithm.update(ciphertext, 0, ciphertext.length);
		byte[] mactag = new byte[hmacAlgorithm.getMacSize()];
		hmacAlgorithm.doFinal(mactag, 0);

		/**
		 * Use the remaining bytes of the random element to generate a key.
		 */
		byte[] keyGenerationSeed = new byte[randomElement.length - k1];
		System.arraycopy(randomElement, k1, keyGenerationSeed, 0, randomElement.length - k1);
		keyGenerator.init(new HKDFParameters(keyGenerationSeed, null, null));
		byte[] generatedKey = new byte[generatedKeyLength];
		keyGenerator.generateBytes(generatedKey, 0, generatedKeyLength);

		return new HibeOutput(generatedKey, new HibeCiphertext(com, ciphertext, mactag));
	}

	/**
	 * Decapsulates a Hibe ciphertext
	 * 
	 * @param secretKey  - secret key used for decryption
	 * @param ciphertext - hibe ciphertext
	 * @param identity   - identity vector
	 * @param level      - 'depth' of the user
	 * @return decrypted key
	 */
	public byte[] decapsulate(HibeSecretKey secretKey, HibeCiphertext ciphertext, byte[] identity, int level) {
		/**
		 * Encode the identites[4].
		 */
		byte[] encodedIdentities = new byte[sizeOfCCAIdentityData * level + sizeOfCCAIdentityData];
		for (int i = 0; i < level; i++) {
			encodedIdentities[i * sizeOfCCAIdentityData] = 0;
			System.arraycopy(identity, i * (sizeOfCCAIdentityData - 1), encodedIdentities,
					i * sizeOfCCAIdentityData + 1, sizeOfCCAIdentityData - 1);
		}
		/**
		 * Append com to identites[4].
		 */
		encodedIdentities[sizeOfCCAIdentityData * level] = 1;
		System.arraycopy(ciphertext.getCom(), 0, encodedIdentities, sizeOfCCAIdentityData * level + 1,
				sizeOfCCAIdentityData - 1);

		/**
		 * Key Delegation needs a seed. Since this key is only used once, I think we can
		 * generate a randomness here, use it once and discard it. Since the decryption
		 * is deterministic I think it is unpleasent to let the caller of the
		 * decapsulate function provide a randomness.
		 */
		SecureRandom randomness = new SecureRandom();
		byte[] seed = new byte[sizeOfSeed];
		randomness.nextBytes(seed);
		/**
		 * Delegate a key for the encoded identity[4].
		 */
		byte[] decryptionKey = delegate(secretKey.getEncodedHibeSecretKey(), encodedIdentities, sizeOfCCAIdentityData,
				level + 1, seed);

		/**
		 * Decrypt the message(which is a random GT Element).
		 */
		byte[] message = decrypt(decryptionKey, ciphertext.getCiphertext(), level + 1);

		/**
		 * Perform encapsulation check[4]
		 */
		byte[] compareCom = new byte[k];
		byte[] r = new byte[k];
		byte[] dec = Arrays.copyOf(message, k1);
		byte[] inputForBytesGeneration = new byte[dec.length + secretKey.getEncapsulationKey().length];
		System.arraycopy(secretKey.getEncapsulationKey(), 0, inputForBytesGeneration, 0,
				secretKey.getEncapsulationKey().length);
		System.arraycopy(dec, 0, inputForBytesGeneration, secretKey.getEncapsulationKey().length, dec.length);
		keyedHash.init(new HKDFParameters(inputForBytesGeneration, null, null));

		/**
		 * Check if com' = com (from ciphertext)[4]
		 */
		keyedHash.generateBytes(compareCom, 0, k);
		if (!Arrays.equals(compareCom, ciphertext.getCom())) {
			return null;
		}
		/**
		 * Compute r[4]
		 */
		encapsulationHash = new SHA256Digest();
		encapsulationHash.update(dec, 0, k1);
		encapsulationHash.doFinal(r, 0);

		/**
		 * Check the Mac Tag[4]
		 */
		hmacAlgorithm.init(new KeyParameter(r));
		hmacAlgorithm.update(ciphertext.getCiphertext(), 0, ciphertext.getCiphertext().length);
		byte[] mactag = new byte[hmacAlgorithm.getMacSize()];
		hmacAlgorithm.doFinal(mactag, 0);
		if (!Arrays.equals(mactag, ciphertext.getMacTag())) {
			return null;
		}
		/**
		 * Compute the key
		 */
		byte[] keyGenerationSeed = new byte[message.length - k1];
		System.arraycopy(message, k1, keyGenerationSeed, 0, message.length - k1);
		keyGenerator.init(new HKDFParameters(keyGenerationSeed, null, null));
		byte[] generatedKey = new byte[generatedKeyLength];
		keyGenerator.generateBytes(generatedKey, 0, generatedKeyLength);

		return generatedKey;
	}

	/**
	 * Performs the delegation algorithm
	 * 
	 * @param secretKey  - secret key of the delegator
	 * @param identity   - identity which gets a secret key
	 * @param level      - 'depth' of the new user
	 * @param randomness - randomness used for value generation
	 * @return secret key for 'identity'
	 */
	public HibeSecretKey delegate(HibeSecretKey secretKey, byte[] identity, int level, SecureRandom randomness) {
		byte[] seed = new byte[sizeOfSeed];
		randomness.nextBytes(seed);

		/**
		 * Encode identity[4]
		 */
		byte[] encodedIdentities = new byte[sizeOfCCAIdentityData * level];
		for (int i = 0; i < level; i++) {
			encodedIdentities[i * sizeOfCCAIdentityData] = 0;
			System.arraycopy(identity, i * (sizeOfCCAIdentityData - 1), encodedIdentities,
					i * sizeOfCCAIdentityData + 1, sizeOfCCAIdentityData - 1);
		}
		/**
		 * Delegate Secret Key
		 */
		byte[] delegatedSecretKey = delegate(secretKey.getEncodedHibeSecretKey(), encodedIdentities,
				sizeOfCCAIdentityData, level, seed);

		return new HibeSecretKey(delegatedSecretKey, secretKey.getEncapsulationKey());
	}

}
