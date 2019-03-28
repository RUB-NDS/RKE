package de.rub.rke.test.fakealgorithmset.mockrandomoracle;

import de.rub.rke.randomoracle.KeyedRandomOracleOutput;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockKeySeed;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockSymmetricKey;
import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;

/**
 * Implementation of RandomOracleOutput for the mock random oracle
 * 
 * @author Marco Smeets
 *
 */
public class MockRandomOracleOutput implements KeyedRandomOracleOutput {

	MockSymmetricKey sessionKey;
	MockKeySeed keyseed;

	public MockRandomOracleOutput(MockSymmetricKey sessionKey, MockKeySeed keyseed) {
		this.sessionKey = sessionKey;
		this.keyseed = keyseed;
	}

	@Override
	public SymmetricKey getSessionKey() {
		// TODO Auto-generated method stub
		return sessionKey;
	}

	@Override
	public KeySeed getSecretKeySeed() {
		// TODO Auto-generated method stub
		return keyseed;
	}

}
