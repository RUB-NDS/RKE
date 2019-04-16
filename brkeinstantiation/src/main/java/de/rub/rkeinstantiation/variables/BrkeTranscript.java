package de.rub.rkeinstantiation.variables;

import java.util.LinkedList;
import java.util.Queue;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Memoable;

import de.rub.rke.brke.BrkeCiphertext;
import de.rub.rke.variables.AssociatedData;
import de.rub.rke.variables.Transcript;
import de.rub.rkeinstantiation.utility.CiphertextEncoder;

/**
 * Class for the Transcript used in the Brke construction.
 * 
 * Currently uses SHA256 to hash all input, so the transcript is a 32 Byte
 * State.
 * 
 * @author Marco Smeets
 *
 */
public class BrkeTranscript implements Transcript {

	private Memoable state;
	private SHA256Digest hashFunction;
	private Queue<byte[]> updateQueue;

	public BrkeTranscript() {
		hashFunction = new SHA256Digest();
		updateQueue = new LinkedList<byte[]>();
	}

	/**
	 * Updates the transcript with the provided input. Before including the input in
	 * the state it is hashed by the CiphertextEncoder.
	 */
	@Override
	public void updateTranscript(boolean sender, AssociatedData ad, BrkeCiphertext ciphertext) {
		if (state != null) {
			hashFunction.reset(state);
		}
		byte[] hashedInput = CiphertextEncoder.hashAdCiphertext(ad, ciphertext);
		hashFunction.update(sender ? (byte) 1 : (byte) 0);
		hashFunction.update(hashedInput, 0, hashedInput.length);
		state = hashFunction.copy();
	}

	/**
	 * Updates the transcript from the update queue.
	 */
	@Override
	public void updateTranscriptfromQueue(int numberOfReceivedMessages) {
		if (state != null) {
			hashFunction.reset(state);
		}
		for (int i = 0; i < numberOfReceivedMessages - 1; i++) {
			byte[] current = updateQueue.poll();
			if (current == null) {
				// TODO: Throw exception.
				return;
			}
			hashFunction.update(current, 0, current.length);
		}
		state = hashFunction.copy();
	}

	/**
	 * Adds the input to the Transcript update queue. Before that, the input is
	 * hashed by the CiphertextEncoder.
	 */
	@Override
	public void addToTranscriptQueue(boolean sender, AssociatedData ad, BrkeCiphertext ciphertext) {
		byte hashedInput[] = CiphertextEncoder.hashAdCiphertext(ad, ciphertext);
		byte update[] = new byte[hashedInput.length + 1];
		System.arraycopy(hashedInput, 0, update, 1, hashedInput.length);
		update[0] = sender ? (byte) 1 : (byte) 0;
		updateQueue.add(update);
	}

	/**
	 * Outputs the current transcript state.
	 * 
	 * @return
	 */
	public byte[] getTranscriptState() {
		if (state != null) {
			hashFunction.reset(state);
		}
		byte[] output = new byte[hashFunction.getDigestSize()];
		hashFunction.doFinal(output, 0);
		return output;
	}
}
