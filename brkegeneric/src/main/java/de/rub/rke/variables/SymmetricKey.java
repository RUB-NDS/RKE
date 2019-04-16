package de.rub.rke.variables;

/**
 * Interface for Symmetric Keys
 * 
 * @author Marco Smeets
 *
 */
public interface SymmetricKey {

	/**
	 * Mixes a key to another key
	 * 
	 * @param key
	 */
	public void mixToKey(SymmetricKey key);
}
