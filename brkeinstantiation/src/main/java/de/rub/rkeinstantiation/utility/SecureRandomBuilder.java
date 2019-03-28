package de.rub.rkeinstantiation.utility;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class that creates a SecureRandom object.
 * 
 * Sometimes we need a seedable SecureRandom object. Since the standard
 * SecureRandom in Linux environments uses the 'NativePRNG', which can not be
 * seeded, we sometimes use this class to create a SecureRandom object, which
 * can be seeded.
 * 
 * @author Marco Smeets
 *
 */
public class SecureRandomBuilder {

	/**
	 * Create a SecureRandom object using a SHA1PRNG.
	 * 
	 * TODO: I'm currently not that satisfied with this solution, since I read that
	 * SHA1PRNG is not available on every platform, so this would decrease
	 * portability. But I did not find a better solution yet.
	 * 
	 * @return
	 */
	public static SecureRandom createSeedableRandomness() {
		SecureRandom randomness = null;
		try {
			randomness = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return randomness;
	}

}
