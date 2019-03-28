package de.rub.rkeinstantiation.factories;

import org.bouncycastle.crypto.digests.SHA256Digest;

import de.rub.rke.factories.KeyedRandomOracleFactory;
import de.rub.rke.randomoracle.KeyedRandomOracle;
import de.rub.rkeinstantiation.brkerandomoracle.HKDFRandomOracle;

/**
 * Factory for the HKDF based random oracle.
 * 
 * @author Marco Smeets
 *
 */
public class HKDFRandomOracleFactory implements KeyedRandomOracleFactory {

	/**
	 * Specifies the internal and generated Key Size for the HKDF Random Oracle (in
	 * Bytes)
	 */
	private final int generatedKeySize = 16;
	private final int internalKeySize = 16;

	/**
	 * Creates a HKDF-Based Random Oracle, which uses SHA256.
	 */
	@Override
	public KeyedRandomOracle createKeyedRandomOracleAlgorithm() {
		SHA256Digest hash = new SHA256Digest();
		return new HKDFRandomOracle(hash, internalKeySize, generatedKeySize);
	}

}
