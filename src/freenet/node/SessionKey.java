/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import freenet.crypt.BlockCipher;

/**
 * Class representing a single session key.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class SessionKey {
	
	// HO-72: Session key material must not be public. Plugins and any freenet.node.*
	// class can currently read active AES-256 / HMAC session keys directly without
	// reflection. Restrict to package-private so only node-package code accesses them.
	/** Parent PeerNode */
	final PeerNode pn;
	/** Cipher to encrypt outgoing packets with */
	final BlockCipher outgoingCipher;
	/** Key for outgoingCipher */
	final byte[] outgoingKey;

	/** Cipher to decrypt incoming packets */
	final BlockCipher incommingCipher;
	/** Key for incommingCipher */
	final byte[] incommingKey;

	final BlockCipher ivCipher;
	final byte[] ivNonce;
	final byte[] hmacKey;

	final long trackerID;

	final NewPacketFormatKeyContext packetContext;

	SessionKey(PeerNode parent, BlockCipher outgoingCipher, byte[] outgoingKey,
	                BlockCipher incommingCipher, byte[] incommingKey, BlockCipher ivCipher,
			byte[] ivNonce, byte[] hmacKey, NewPacketFormatKeyContext context, long trackerID) {
		this.pn = parent;
		this.outgoingCipher = outgoingCipher;
		this.outgoingKey = outgoingKey;
		this.incommingCipher = incommingCipher;
		this.incommingKey = incommingKey;
		this.ivCipher = ivCipher;
		this.ivNonce = ivNonce;
		this.hmacKey = hmacKey;
		this.packetContext = context;
		this.trackerID = trackerID;
	}
	
	public void disconnected() {
		packetContext.disconnected();
	}
}
