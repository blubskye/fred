package freenet.support;

import org.tanukisoftware.wrapper.WrapperManager;

import java.io.IOException;
import java.util.concurrent.locks.LockSupport;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

public class WrapperKeepalive extends Thread implements AutoCloseable {
  private volatile boolean shutdown = false;
  private static final long INTERVAL_NS = MINUTES.toNanos(2);
  private static final int INTERVAL_MS = (int) MINUTES.toMillis(2);

  @Override
  public void run() {
    while (!shutdown) {
      WrapperManager.signalStarting(INTERVAL_MS + (int)SECONDS.toMillis(5));
      LockSupport.parkNanos(INTERVAL_NS);
      if (Thread.interrupted()) {
        Thread.currentThread().interrupt();
        break;
      }
    }
  }

  @Override
  public void close() throws IOException {
    shutdown = true;
    LockSupport.unpark(this);
  }
}
