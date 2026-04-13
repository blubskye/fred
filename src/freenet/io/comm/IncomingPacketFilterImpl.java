/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.io.comm;

import java.net.InetAddress;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import freenet.crypt.EntropySource;
import freenet.node.FNPPacketMangler;
import freenet.node.Node;
import freenet.node.NodeCrypto;
import freenet.node.PeerNode;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

public class IncomingPacketFilterImpl implements IncomingPacketFilter {

	private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, IncomingPacketFilterImpl.class);
			}
		});
	}

// HO-49: Rate-limit the brute-force peer search to prevent CPU exhaustion
// when an adversary floods the node with packets from a single source IP.
// Track per-IP failure counts within a rolling 1-second window.
// [0] = fail count in current window, [1] = window start ms
private final ConcurrentHashMap<InetAddress, long[]> bruteForceFailures =
	new ConcurrentHashMap<>();
/** Max brute-force failures per source IP within BRUTE_FORCE_WINDOW_MS. */
private static final int BRUTE_FORCE_MAX_FAILS = 20;
/** Rolling window length in milliseconds. */
private static final long BRUTE_FORCE_WINDOW_MS = 1000L;
/** Evict stale entries every N packets to avoid unbounded map growth. */
private static final int EVICT_EVERY_N = 1000;
private final AtomicLong processedCount = new AtomicLong();
	private FNPPacketMangler mangler;
	private NodeCrypto crypto;
	private Node node;
	private final EntropySource fnpTimingSource;

	public IncomingPacketFilterImpl(FNPPacketMangler mangler, Node node, NodeCrypto crypto) {
		this.mangler = mangler;
		this.node = node;
		this.crypto = crypto;
		fnpTimingSource = new EntropySource();
	}

	@Override
	public boolean isDisconnected(PeerContext context) {
		if(context == null) return false;
		return !context.isConnected();
	}
	
	private static final AtomicLong successfullyDecodedPackets = new AtomicLong();
	private static final AtomicLong failedDecodePackets = new AtomicLong();
	
	public static long[] getDecodedPackets() {
		if(!logMINOR) return null;
		long decoded = successfullyDecodedPackets.get();
		long failed = failedDecodePackets.get();
		return new long[] { decoded, decoded+failed };
	}

	@Override
	public DECODED process(byte[] buf, int offset, int length, Peer peer, long now) {
		if(logMINOR) Logger.minor(this, "Packet length "+length+" from "+peer);
		node.getRandom().acceptTimerEntropy(fnpTimingSource, 0.25);
		PeerNode opn = node.getPeers().getByPeer(peer, mangler);

		if(opn != null) {
			if(opn.handleReceivedPacket(buf, offset, length, now, peer)) {
				if(logMINOR) successfullyDecodedPackets.incrementAndGet();
				return DECODED.DECODED;
			}
		} else {
			Logger.normal(this, "Got packet from unknown address");
		}
		DECODED decoded = mangler.process(buf, offset, length, peer, opn, now);
		if(decoded == DECODED.DECODED) {
			if(logMINOR) successfullyDecodedPackets.incrementAndGet();
		} else if(decoded == DECODED.NOT_DECODED) {
			
			// HO-49: Check rate limit before brute-forcing all peers.
			InetAddress sourceAddr = peer.getAddress();
			boolean rateLimited = false;
			if (sourceAddr != null) {
				long[] entry = bruteForceFailures.computeIfAbsent(
					sourceAddr, k -> new long[]{0L, now});
				synchronized (entry) {
					if (now - entry[1] > BRUTE_FORCE_WINDOW_MS) {
						// New window — reset
						entry[0] = 0L;
						entry[1] = now;
					}
					if (entry[0] >= BRUTE_FORCE_MAX_FAILS) {
						rateLimited = true;
					}
			if (!rateLimited) {
				for(PeerNode pn : crypto.getPeerNodes()) {
					if(pn == opn) continue;
					if(pn.handleReceivedPacket(buf, offset, length, now, peer)) {
						if(logMINOR) successfullyDecodedPackets.incrementAndGet();
						return DECODED.DECODED;
					}
				}
				// Failed — count this attempt
				if (sourceAddr != null) {
					long[] failEntry = bruteForceFailures.get(sourceAddr);
					if (failEntry != null) synchronized (failEntry) { failEntry[0]++; }
				}
			} else {
				Logger.normal(this, "HO-49: brute-force rate limit hit for "+sourceAddr+
					" (>"+BRUTE_FORCE_MAX_FAILS+" failures/s) — dropping");
			}
			// Periodically evict stale entries to prevent map growth.
			if (processedCount.incrementAndGet() % EVICT_EVERY_N == 0) {
				for (Iterator<Map.Entry<InetAddress,long[]>> it =
						bruteForceFailures.entrySet().iterator(); it.hasNext(); ) {
					long[] e = it.next().getValue();
					synchronized(e) {
						if (now - e[1] > BRUTE_FORCE_WINDOW_MS * 10) it.remove();
					}
				}
			}
				}
			}
			
			if(logMINOR) failedDecodePackets.incrementAndGet();
		}
		return decoded;
	}

}
