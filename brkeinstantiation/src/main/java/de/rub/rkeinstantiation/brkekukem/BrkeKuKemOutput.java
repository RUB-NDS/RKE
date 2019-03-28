package de.rub.rkeinstantiation.brkekukem;

import java.util.Arrays;

import de.rub.rke.kukem.KuKemCiphertext;
import de.rub.rke.kukem.KuKemOutput;
import de.rub.rke.variables.SymmetricKey;
import de.rub.rkeinstantiation.variables.BrkeSymmetricKey;

/**
 * Class for the kuKemOutput
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemOutput implements KuKemOutput {

	byte[] key;
	BrkeKuKemCiphertext ciphertext;

	public BrkeKuKemOutput(byte[] key, BrkeKuKemCiphertext ciphertext) {
		this.key = Arrays.copyOf(key, key.length);
		this.ciphertext = ciphertext;
	}

	@Override
	public SymmetricKey getKey() {

		return new BrkeSymmetricKey(key);
	}

	@Override
	public KuKemCiphertext getCiphertext() {

		return ciphertext;
	}

}
