package de.rub.rkeinstantiation.brkerandomoracle;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import de.rub.rke.randomoracle.KeyedRandomOracle;
import de.rub.rke.randomoracle.KeyedRandomOracleOutput;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rke.variables.Transcript;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;
import de.rub.rkeinstantiation.variables.BrkeTranscript;

/**
 * Realizes the RandomOracle used in the Brke construction through HKDF[1]. HKDF
 * uses a Hash function to generate pseudo random output. This class uses the
 * implementation of HKDF by Bouncycastle.
 * 
 * @author Marco Smeets
 *
 */
public class HKDFRandomOracle implements KeyedRandomOracle {

	private HKDFBytesGenerator hkdfGenerator;
	private byte[] chainingKeySend;
	private byte[] chainingKeyReceive;
	private int internalKeySize;
	private int generatedKeySize;

	/**
	 * Constructs the HKDF RandomOracle. We can specify the hash function, the
	 * internal key size (used for the 'chaining keys'), and the generated key size.
	 * (session key and seed for queued kuKem Key Generation)
	 * 
	 * @param hashFunction     - Hash function to be used in HKDF
	 * @param internalKeySize  - internal key size
	 * @param generatedKeySize - key size of generated keys
	 */
	public HKDFRandomOracle(Digest hashFunction, int internalKeySize, int generatedKeySize) {
		hkdfGenerator = new HKDFBytesGenerator(hashFunction);
		chainingKeySend = new byte[internalKeySize];
		chainingKeyReceive = new byte[internalKeySize];
		this.internalKeySize = internalKeySize;
		this.generatedKeySize = generatedKeySize;
	}

	/**
	 * Initializes the HKDF Random Oracle
	 */
	@Override
	public void init(SecureRandom randomness, boolean initiator) {
		byte[] seed = new byte[internalKeySize];
		randomness.nextBytes(seed);
		hkdfGenerator.init(new HKDFParameters(seed, null, null));
		if (initiator) {
			hkdfGenerator.generateBytes(chainingKeyReceive, 0, internalKeySize);
			hkdfGenerator.generateBytes(chainingKeySend, 0, internalKeySize);
		} else {
			hkdfGenerator.generateBytes(chainingKeySend, 0, internalKeySize);
			hkdfGenerator.generateBytes(chainingKeyReceive, 0, internalKeySize);
		}
	}

	/**
	 * Queries the Send random oracle and produces a session key and key seed.
	 */
	@Override
	public KeyedRandomOracleOutput querySendRandomOracle(SymmetricKey kemOutputKey, Transcript transcript) {
		byte kemKey[] = ((BrkeSymmetricKey) kemOutputKey).getKeyBytes();
		byte transcriptState[] = ((BrkeTranscript) transcript).getTranscriptState();
		byte hkdfInput[] = new byte[kemKey.length + transcriptState.length + internalKeySize];
		System.arraycopy(kemKey, 0, hkdfInput, 0, kemKey.length);
		System.arraycopy(transcriptState, 0, hkdfInput, kemKey.length, transcriptState.length);
		System.arraycopy(chainingKeySend, 0, hkdfInput, kemKey.length + transcriptState.length, internalKeySize);
		hkdfGenerator.init(new HKDFParameters(hkdfInput, null, null));
		byte[] sessionKey = new byte[generatedKeySize];
		byte[] keySeed = new byte[generatedKeySize];
		hkdfGenerator.generateBytes(sessionKey, 0, generatedKeySize);
		hkdfGenerator.generateBytes(keySeed, 0, generatedKeySize);
		hkdfGenerator.generateBytes(chainingKeySend, 0, internalKeySize);
		return new HKDFRandomOracleOutput(sessionKey, keySeed);
	}

	/**
	 * Queries the Receive random oracle and produces a session key and key seed.
	 */
	@Override
	public KeyedRandomOracleOutput queryReceiveRandomOracle(SymmetricKey kemOutputKey, Transcript transcript) {
		byte kemKey[] = ((BrkeSymmetricKey) kemOutputKey).getKeyBytes();
		byte transcriptState[] = ((BrkeTranscript) transcript).getTranscriptState();
		byte hkdfInput[] = new byte[kemKey.length + transcriptState.length + internalKeySize];
		System.arraycopy(kemKey, 0, hkdfInput, 0, kemKey.length);
		System.arraycopy(transcriptState, 0, hkdfInput, kemKey.length, transcriptState.length);
		System.arraycopy(chainingKeyReceive, 0, hkdfInput, kemKey.length + transcriptState.length, internalKeySize);
		hkdfGenerator.init(new HKDFParameters(hkdfInput, null, null));
		byte[] sessionKey = new byte[generatedKeySize];
		byte[] keySeed = new byte[generatedKeySize];
		hkdfGenerator.generateBytes(sessionKey, 0, generatedKeySize);
		hkdfGenerator.generateBytes(keySeed, 0, generatedKeySize);
		hkdfGenerator.generateBytes(chainingKeyReceive, 0, internalKeySize);
		return new HKDFRandomOracleOutput(sessionKey, keySeed);
	}

}
