package de.rub.rkeinstantiation.brkerandomoracle;

import de.rub.rke.randomoracle.KeyedRandomOracleOutput;
import de.rub.rke.variables.KeySeed;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rkeinstantiation.variables.BrkeKeySeed;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;

/**
 * Class for the Output of the HKDF Random Oracle
 * 
 * @author Marco Smeets
 *
 */
public class HKDFRandomOracleOutput implements KeyedRandomOracleOutput {

	BrkeSymmetricKey sessionKey;
	BrkeKeySeed keySeed;

	public HKDFRandomOracleOutput(byte[] sessionKey, byte[] keySeed) {
		this.sessionKey = new BrkeSymmetricKey(sessionKey);
		this.keySeed = new BrkeKeySeed(keySeed);
	}

	@Override
	public SymmetricKey getSessionKey() {
		return sessionKey;
	}

	@Override
	public KeySeed getSecretKeySeed() {
		return keySeed;
	}

}
