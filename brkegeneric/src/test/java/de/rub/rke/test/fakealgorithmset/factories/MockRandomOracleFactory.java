package de.rub.rke.test.fakealgorithmset.factories;

import de.rub.rke.factories.KeyedRandomOracleFactory;
import de.rub.rke.randomoracle.KeyedRandomOracle;
import de.rub.rke.test.fakealgorithmset.mockrandomoracle.MockRandomOracle;

/**
 * Implementation of RandomOracleFactory that returns a fake random oracle
 * 
 * @author Marco Smeets
 *
 */
public class MockRandomOracleFactory implements KeyedRandomOracleFactory {

	@Override
	public KeyedRandomOracle createKeyedRandomOracleAlgorithm() {
		return new MockRandomOracle();
	}

}
