package de.rub.rkeinstantiation.variables;

import java.util.Arrays;

import de.rub.rke.variables.AssociatedData;

/**
 * Class for the associated Data used in the Brke construction.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeAssociatedData implements AssociatedData {

	private byte associatedData[];

	public BrkeAssociatedData(byte[] associatedData) {
		this.associatedData = Arrays.copyOf(associatedData, associatedData.length);
	}

	public byte[] getAsBytes() {
		return associatedData;
	}
}
