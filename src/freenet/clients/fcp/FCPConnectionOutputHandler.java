/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.fcp;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

import freenet.support.LogThresholdCallback;

import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

public class FCPConnectionOutputHandler implements Runnable {

	final FCPConnectionHandler handler;
	private final LinkedBlockingDeque<FCPMessage> outQueue = new LinkedBlockingDeque<>();
	private volatile boolean closedOutputQueue = false;
	private final CountDownLatch drainLatch = new CountDownLatch(1);

        private static volatile boolean logMINOR;
        private static volatile boolean logDEBUG;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
                                logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	public FCPConnectionOutputHandler(FCPConnectionHandler handler) {
		this.handler = handler;
	}

	void start() {
		if (handler.getSocket() == null)
			return;
		Thread.ofVirtual()
			.name("FCP output handler for " + handler.getSocket().getRemoteSocketAddress()
				+ ':' + handler.getSocket().getPort())
			.start(this);
	}

	@Override
	public void run() {
		try {
			realRun();
		} catch (IOException e) {
			if(logMINOR)
				Logger.minor(this, "Caught "+e, e);
		} catch (Throwable t) {
			Logger.error(this, "Caught "+t, t);
		} finally {
			// Set the closed flag so that onClosed(), both on this thread and the input thread, doesn't wait forever.
			// This happens in realRun() on a healthy exit, but we must do it here too to handle an exceptional exit.
			// I.e. the other side closed the connection, and we threw an IOException.
			closedOutputQueue = true;
		}
		handler.close();
		handler.closedOutput();
	}

	private void realRun() throws IOException {
		OutputStream os = new BufferedOutputStream(handler.getSocket().getOutputStream(), 4096);
		boolean flushed = false;
		while(true) {
			FCPMessage msg;
			try {
				msg = outQueue.poll(200, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				break;
			}
			if(msg == null) {
				if(handler.isClosed()) break;
				if(!flushed) {
					if(logMINOR) Logger.minor(this, "Flushing");
					os.flush();
					flushed = true;
				}
				continue;
			}
			if(logMINOR) Logger.minor(this, "Sending "+msg);
			msg.send(os);
			flushed = false;
		}
		os.flush();
		os.close();
		closedOutputQueue = true;
		drainLatch.countDown();
	}

    /**
     * Queue a message for sending to the FCP client.
     * TODO: Refactor callers to use {@link FCPConnectionHandler#send(FCPMessage)} instead of
     *     accessing the outputHandler member variable directly, then make
     *     {@link FCPConnectionHandler#getOutputHandler()} private.
     */
	public void queue(FCPMessage msg) {
		if(logDEBUG) Logger.debug(this, "Queueing "+msg, new Exception("debug"));
		if(msg == null) throw new NullPointerException();
		if(closedOutputQueue) {
			Logger.error(this, "Closed already: "+this+" queueing message "+msg);
			return;
		}
		boolean neverDropAMessage = handler.getServer().neverDropAMessage();
		int MAX_QUEUE_LENGTH = handler.getServer().maxMessageQueueLength();
		if(outQueue.size() >= MAX_QUEUE_LENGTH) {
			if(neverDropAMessage) {
				Logger.error(this, "FCP message queue length is "+outQueue.size()+" for "+handler+" - not dropping...");
			} else {
				Logger.error(this, "Dropping FCP message to "+handler+" : "+outQueue.size()+" messages queued", new Exception("debug"));
				return;
			}
		}
		outQueue.offer(msg);
	}

	public void onClosed() {
		try {
			drainLatch.await(2, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	public boolean isQueueHalfFull() {
		int MAX_QUEUE_LENGTH = handler.getServer().maxMessageQueueLength();
		return outQueue.size() > MAX_QUEUE_LENGTH / 2;
	}

}
