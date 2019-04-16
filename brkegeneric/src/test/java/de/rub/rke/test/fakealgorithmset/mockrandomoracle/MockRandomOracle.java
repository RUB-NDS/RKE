package de.rub.rke.test.fakealgorithmset.mockrandomoracle;

import java.security.SecureRandom;
import java.util.Random;

import de.rub.rke.randomoracle.KeyedRandomOracle;
import de.rub.rke.randomoracle.KeyedRandomOracleOutput;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockKeySeed;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockSymmetricKey;
import de.rub.rke.test.fakealgorithmset.mockvariables.MockTranscript;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rke.variables.Transcript;

/**
 * Implements the random oracle as mock random oracle
 * 
 * Since all values of the fake algorithms are represented by integers, we
 * compute the output of the random oracle by adding all input values.
 * 
 * @author Marco Smeets
 *
 */
public class MockRandomOracle implements KeyedRandomOracle {

	/**
	 * Stores two symmetric keys for random output generation
	 */
	private MockSymmetricKey chainingKeySend;
	private MockSymmetricKey chainingKeyReceive;

	public MockRandomOracle() {

	}

	/**
	 * Initializes the random oracle
	 */
	@Override
	public void init(SecureRandom randomness, boolean initiator) {
		if (initiator) {
			chainingKeySend = new MockSymmetricKey(randomness.nextInt());
			chainingKeyReceive = new MockSymmetricKey(randomness.nextInt());
		} else {
			chainingKeyReceive = new MockSymmetricKey(randomness.nextInt());
			chainingKeySend = new MockSymmetricKey(randomness.nextInt());
		}

	}

	/**
	 * Produces the output for the send algorithm and updates the send chaining key
	 */
	@Override
	public KeyedRandomOracleOutput querySendRandomOracle(SymmetricKey kemOutputKey, Transcript transcript) {
		MockSymmetricKey kemOutKey = (MockSymmetricKey) kemOutputKey;
		int seedforRandom = chainingKeySend.getId() + kemOutKey.getId() + ((MockTranscript) transcript).getTranscript();
		Random rng = new Random(seedforRandom);
		chainingKeySend.mixToKey(new MockSymmetricKey(rng.nextInt()));
		return new MockRandomOracleOutput(new MockSymmetricKey(rng.nextInt()), new MockKeySeed(rng.nextInt()));
	}

	/**
	 * Produces the output for the receive algorithm and updates the receive
	 * chaining key
	 */
	@Override
	public KeyedRandomOracleOutput queryReceiveRandomOracle(SymmetricKey kemOutputKey, Transcript transcript) {
		MockSymmetricKey kemOutKey = (MockSymmetricKey) kemOutputKey;
		int seedforRandom = chainingKeyReceive.getId() + kemOutKey.getId()
				+ ((MockTranscript) transcript).getTranscript();
		Random rng = new Random(seedforRandom);
		chainingKeyReceive.mixToKey(new MockSymmetricKey(rng.nextInt()));
		return new MockRandomOracleOutput(new MockSymmetricKey(rng.nextInt()), new MockKeySeed(rng.nextInt()));
	}

}
