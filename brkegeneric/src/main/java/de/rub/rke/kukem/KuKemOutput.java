package de.rub.rke.kukem;

import de.rub.rke.variables.SymmetricKey;

/**
 * Interface for the Output of a kuKem
 *
 * @author Marco Smeets
 *
 */
public interface KuKemOutput {

	/**
	 * @return symmetric key generated by a kuKem
	 */
	SymmetricKey getKey();

	/**
	 * @return ciphertext that is computed by a kuKem
	 */
	KuKemCiphertext getCiphertext();
}
