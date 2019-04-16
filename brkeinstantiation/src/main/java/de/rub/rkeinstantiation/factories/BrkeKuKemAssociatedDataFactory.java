package de.rub.rkeinstantiation.factories;

import org.bouncycastle.crypto.digests.SHA256Digest;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.factories.KuKemAssociatedDataFactory;
import de.rub.rke.kukem.KuKemAssociatedData;
import de.rub.rke.variables.AssociatedData;
import de.rub.rkeinstantiation.brkekukem.BrkeKuKemAssociatedData;
import de.rub.rkeinstantiation.utility.CiphertextEncoder;

/**
 * Factory for the BrkeKuKemAssociatedData.
 * 
 * The idea is to hash the ciphertext and associated data to 32 Bytes
 * (currently) and use this as the identity information in the HIBE.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemAssociatedDataFactory implements KuKemAssociatedDataFactory {

	@Override
	public KuKemAssociatedData createAssociatedData(AssociatedData ad, BrkeCiphertext ciphertext) {
		SHA256Digest hashFunction = new SHA256Digest();
		byte[] hashedInput = CiphertextEncoder.hashAdCiphertext(ad, ciphertext);
		hashFunction.update(hashedInput, 0, hashedInput.length);
		byte[] associatedData = new byte[32];
		hashFunction.doFinal(associatedData, 0);
		return new BrkeKuKemAssociatedData(associatedData);
	}

}
