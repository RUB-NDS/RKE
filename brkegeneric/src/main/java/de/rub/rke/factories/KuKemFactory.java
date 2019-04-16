package de.rub.rke.factories;

import de.rub.rke.kukem.KeyUpdateableKem;

/**
 * Factory for the Key Updateable Kem (KuKem)
 * 
 * @author Marco Smeets
 *
 */
public interface KuKemFactory {

	/**
	 * Function that returns a KuKem
	 * 
	 * @return KeyUpdateableKem object
	 */
	public KeyUpdateableKem createKuKemAlgorithm();
}
