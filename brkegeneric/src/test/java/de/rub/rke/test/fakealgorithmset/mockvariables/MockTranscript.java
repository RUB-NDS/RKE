package de.rub.rke.test.fakealgorithmset.mockvariables;

import java.util.LinkedList;
import java.util.Queue;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.test.Encoder;
import de.rub.rke.variables.AssociatedData;
import de.rub.rke.variables.Transcript;

/**
 * Implements the Transcript used in the Brke construction.
 * 
 * We update a transcript by adding all individual parts of the input to the
 * transcript. This makes the transcript queue easier to handle, because we only
 * have to store the sum of the parts, instead of the individual parts.
 * 
 * @author Marco Smeets
 *
 */
public class MockTranscript implements Transcript {

	private int transcript;
	private Queue<Integer> transcriptqueue;

	public MockTranscript() {
		transcript = 0;
		transcriptqueue = new LinkedList<Integer>();
	}

	@Override
	public void updateTranscript(boolean sender, AssociatedData ad, BrkeCiphertext ciphertext) {
		MockAssociatedData associatedData = (MockAssociatedData) ad;
		int[] encodedCiphertext = Encoder.encodeFakeBrkeCiphertext(ciphertext);
		transcript += sender ? 1 : 0;
		transcript += associatedData.getIntRepresentation();
		for (int i = 0; i < encodedCiphertext.length; i++) {
			transcript += encodedCiphertext[i];
		}
	}

	@Override
	public void updateTranscriptfromQueue(int until) {
		for (int i = 0; i < until - 1; i++) {
			transcript += transcriptqueue.remove();
		}
	}

	@Override
	public void addToTranscriptQueue(boolean sender, AssociatedData ad, BrkeCiphertext ciphertext) {
		int temporaryTranscript = 0;
		MockAssociatedData associatedData = (MockAssociatedData) ad;
		int[] encodedCiphertext = Encoder.encodeFakeBrkeCiphertext(ciphertext);
		temporaryTranscript += sender ? 1 : 0;
		temporaryTranscript += associatedData.getIntRepresentation();
		for (int i = 0; i < encodedCiphertext.length; i++) {
			temporaryTranscript += encodedCiphertext[i];
		}
		transcriptqueue.add(temporaryTranscript);
	}

	public int getTranscript() {
		return transcript;
	}

}
