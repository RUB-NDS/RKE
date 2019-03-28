package de.rub.rke.variables;

import de.rub.rke.brke.BrkeCiphertext;

/**
 * Class for Transcripts used in the Brke construction.
 * 
 * A Transcript has a state that gets updated with each call of a update
 * function. Furthermore the receiving transcript has a update queue, where
 * ciphertexts (or hashed ciphertexts) are stored which get included in the
 * transcript if the user (brke construction) can be sure the communication
 * partner has received the messages.
 * 
 * @author Marco Smeets
 *
 */
public interface Transcript {

	/**
	 * Updates the transcript.
	 * 
	 * @param sender     - information if the ciphertext was sent or received
	 * @param ad
	 * @param ciphertext
	 */
	public void updateTranscript(boolean sender, AssociatedData ad, BrkeCiphertext ciphertext);

	/**
	 * Updates the transcript from the queue.
	 * 
	 * @param numberOfReceivedMessages - number of updates needed
	 */
	public void updateTranscriptfromQueue(int numberOfReceivedMessages);

	/**
	 * Adds a ciphertext to the transcript queue for later updates.
	 * 
	 * @param sender
	 * @param ad
	 * @param ciphertext
	 */
	public void addToTranscriptQueue(boolean sender, AssociatedData ad, BrkeCiphertext ciphertext);

}
