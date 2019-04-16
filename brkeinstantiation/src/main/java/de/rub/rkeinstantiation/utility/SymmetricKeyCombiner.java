package de.rub.rkeinstantiation.utility;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * Utility class that combines two symmetric keys.
 * 
 * @author Marco Smeets
 *
 */
public class SymmetricKeyCombiner {

	/**
	 * Uses a HKDF function with SHA256 to mix to keys.
	 * 
	 * @param key1
	 * @param key2
	 * @return
	 */
	public static byte[] mixKeys(byte[] key1, byte[] key2) {
		HKDFBytesGenerator hkdfGenerator = new HKDFBytesGenerator(new SHA256Digest());
		byte[] input = new byte[key1.length + key2.length];
		System.arraycopy(key1, 0, input, 0, key1.length);
		System.arraycopy(key2, 0, input, key1.length, key2.length);
		hkdfGenerator.init(new HKDFParameters(input, null, null));
		byte[] mixedKey = new byte[key1.length];
		hkdfGenerator.generateBytes(mixedKey, 0, key1.length);
		return mixedKey;
	}
}
