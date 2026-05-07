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
	private final LinkedBlockingDeque<FCPMessage> outQueue
		= new LinkedBlockingDeque<>();
	private volatile boolean closedOutputQueue = false;
	private final CountDownLatch drainLatch
		= new CountDownLatch(1);

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
		handler.getServer().getNode().getExecutor().execute(this, "FCP output handler for "+handler.getSocket().getRemoteSocketAddress()+ ':' +handler.getSocket().getPort());
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
			drainLatch.countDown();
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
				// Nothing in 200ms — check if we should close
				if(handler.isClosed()) break;
				// Flush pending bytes
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
		// Drain and close
		os.flush();
		os.close();
		closedOutputQueue = true;
		drainLatch.countDown();
	}

    /**
     * @deprecated
     *     Use {@link FCPConnectionHandler#send(FCPMessage)} instead of using public access to the
     *     member variable {@link FCPConnectionHandler#getOutputHandler()} to call this function here
     *     upon the outputHandler. In other words: Replace
     *     <code>fcpConnectionHandler.outputHandler.queue(...)</code>
     *     with <code>fcpConnectionHandler.send(...)</code><br>
     *     TODO: The deprecation is merely to enforce people to stop using the said member variable
     *     in a public way. The function itself is fine to stay. Once the public usage has been
     *     replaced by the suggested way of using send(), please make the member variable
     *     {@link FCPConnectionHandler#getOutputHandler()} private and remove the deprecation at this
     *     function here.
     */
    @Deprecated
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
				Logger.error(this, "FCP message queue length is "+outQueue.size()+" for "+handler+" - not dropping message as configured...");
			} else {
				Logger.error(this, "Dropping FCP message to "+handler+" : "+outQueue.size()+" messages queued - maybe client died?", new Exception("debug"));
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
