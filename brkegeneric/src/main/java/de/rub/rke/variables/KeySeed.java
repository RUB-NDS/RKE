package de.rub.rke.variables;

/**
 * Interface for seeds used to generate keys. Since it might be desirable to
 * generate keys from different data types we use a interface, so that the data
 * types are interchangeable.
 * 
 * @author Marco Smeets
 *
 */
public interface KeySeed {

	public byte[] getSeedAsByte();
}
