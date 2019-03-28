package de.rub.rkeinstantiation.brkekukem;

import java.util.Arrays;

import de.rub.rke.kukem.KuKemAssociatedData;

/**
 * Class for the associated Data for the kuKem.
 * 
 * The AssociatedData is created by the AssociatedDataFactory, which essentially
 * hashes ciphertext||ad to a byte array.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeKuKemAssociatedData implements KuKemAssociatedData {
	byte[] associatedData;

	public BrkeKuKemAssociatedData(byte[] associatedData) {
		this.associatedData = Arrays.copyOf(associatedData, associatedData.length);
	}

	public byte[] getAssociatedData() {
		return associatedData;
	}
}
