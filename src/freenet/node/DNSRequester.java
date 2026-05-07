/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/**
 * @author amphibian
 * * Scheduled task that does DNS queries for unconnected peers
 */
public class DNSRequester {

    final Node node;
    private long lastLogTime;
    private final Set<Double> recentNodeIdentitySet = new HashSet<>();
    private final Deque<Double> recentNodeIdentityQueue = new ArrayDeque<>();
    
    static boolean DISABLE = false;

    private static volatile boolean logMINOR;
    static {
        Logger.registerLogThresholdCallback(new LogThresholdCallback() {
            @Override
            public void shouldUpdate() {
                logMINOR = Logger.shouldLog(LogLevel.MINOR, DNSRequester.class);
            }
        });
    }

    DNSRequester(Node node) {
        this.node = node;
    }

    void start() {
        Logger.normal(this, "Starting DNSRequester");
        scheduleRun(0);
    }

    private void scheduleRun(long delayMs) {
        node.getTicker().queueTimedJob(new Runnable() {
            @Override
            public void run() {
                long nextDelay;
                try {
                    nextDelay = realRun();
                } catch (Throwable t) {
                    Logger.error(this, "Caught in DNSRequester: " + t, t);
                    nextDelay = 5000;
                }
                scheduleRun(nextDelay);
            }
        }, delayMs);
    }

    /** Performs one DNS-check cycle. Returns the delay in ms before the next run. */
    private long realRun() {
        if (DISABLE) return 60000;

        // 1. Identify candidates
        PeerNode[] nodesToCheck = Arrays.stream(node.getPeers().myPeers())
            .filter(peerNode -> !peerNode.isConnected())
            .filter(peerNode -> !recentNodeIdentitySet.contains(peerNode.getLocation()))
            .toArray(PeerNode[]::new);

        // 2. Rate-limited Logging
        if(logMINOR) {
            long now = System.currentTimeMillis();
            if((now - lastLogTime) > 5000) {
                Logger.minor(this, "DNS Requester processing " + nodesToCheck.length + " candidates.");
                lastLogTime = now;
            }
        }

        int unconnectedNodesLength = nodesToCheck.length;
        if (unconnectedNodesLength > 0) {
            PeerNode pn = nodesToCheck[node.getFastWeakRandom().nextInt(unconnectedNodesLength)];

            if (unconnectedNodesLength < 5) {
                recentNodeIdentitySet.clear();
                recentNodeIdentityQueue.clear();
            } else {
                Double loc = pn.getLocation();
                recentNodeIdentitySet.add(loc);
                recentNodeIdentityQueue.offerFirst(loc);

                while (recentNodeIdentityQueue.size() > (0.81 * unconnectedNodesLength)) {
                    Double removed = recentNodeIdentityQueue.removeLast();
                    if (removed != null) {
                        recentNodeIdentitySet.remove(removed);
                    }
                }
            }
            pn.maybeUpdateHandshakeIPs(false);
        }

        // 3. Random wait (1-61s) — return the delay; caller will schedule next run
        return 1000 + node.getFastWeakRandom().nextInt(60000);
    }

    public void forceRun() {
        scheduleRun(0);
    }
}