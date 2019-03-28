package de.rub.rkeinstantiation.brkekem;

import org.bouncycastle.crypto.params.KeyParameter;

import de.rub.rke.kem.KemCiphertext;
import de.rub.rke.kem.KemOutput;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;

/**
 * Class that holds the output of an ECIES Kem
 * 
 * @author Marco Smeets
 *
 */
public class ECIESKemOutput implements KemOutput {

	BrkeSymmetricKey generatedKey;
	ECIESKemCiphertext ciphertext;

	public ECIESKemOutput(KeyParameter generatedKey, byte[] ciphertext) {
		this.generatedKey = new BrkeSymmetricKey(generatedKey.getKey());
		this.ciphertext = new ECIESKemCiphertext(ciphertext);
	}

	@Override
	public SymmetricKey getKey() {
		return generatedKey;
	}

	@Override
	public KemCiphertext getCiphertext() {
		return ciphertext;
	}

}
