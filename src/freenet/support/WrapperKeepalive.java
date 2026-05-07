package freenet.support;

import org.tanukisoftware.wrapper.WrapperManager;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

public class WrapperKeepalive extends Thread implements AutoCloseable {
  private volatile boolean shutdown = false;
  private static final long INTERVAL_MS = TimeUnit.MINUTES.toMillis(2);

  @Override
  public void run() {
    while (!shutdown) {
      WrapperManager.signalStarting((int)(INTERVAL_MS + TimeUnit.SECONDS.toMillis(5)));
      LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(INTERVAL_MS));
      if(Thread.currentThread().isInterrupted()) break;
    }
  }

  @Override
  public void close() {
    shutdown = true;
    LockSupport.unpark(this); // wake immediately instead of waiting up to 2 min
  }
}
