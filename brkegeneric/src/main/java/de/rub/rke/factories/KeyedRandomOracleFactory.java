package de.rub.rke.factories;

import de.rub.rke.randomoracle.KeyedRandomOracle;

/**
 * Factory for the Random Oracle
 * 
 * @author Marco Smeets
 *
 */
public interface KeyedRandomOracleFactory {

	/**
	 * Function that returns a Random Oracle
	 * 
	 * @return RandomOracle object
	 */
	public KeyedRandomOracle createKeyedRandomOracleAlgorithm();
}
