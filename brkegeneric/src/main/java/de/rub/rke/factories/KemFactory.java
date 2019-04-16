package de.rub.rke.factories;

import de.rub.rke.kem.KeyEncapsulationMechanism;

/**
 * Factory for the Key Encapsulation Mechanism
 * 
 * @author Marco Smeets
 *
 */
public interface KemFactory {

	public KeyEncapsulationMechanism createKem();
}
