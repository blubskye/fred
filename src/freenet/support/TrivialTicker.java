package freenet.support;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import freenet.node.FastRunnable;

/**
 * Ticker implemented using ScheduledThreadPoolExecutor.
 *
 * If deploying this to replace PacketSender, be careful to handle priority changes properly.
 * Hopefully that can be achieved simply by creating at max priority during startup.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 *
 */
public class TrivialTicker implements Ticker {

	private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
		Thread t = new Thread(r, "TrivialTicker-scheduler");
		t.setDaemon(true);
		return t;
	});

	private final Executor executor;

	private final ConcurrentHashMap<Runnable, ScheduledFuture<?>> jobs = new ConcurrentHashMap<>();

	private boolean running = true;

	public TrivialTicker(Executor executor) {
		this.executor = executor;
	}

	@Override
	public void queueTimedJob(final Runnable job, long offset) {
		synchronized(this) {
			if(!running)
				return;

			ScheduledFuture<?> future = scheduler.schedule(() -> {
				synchronized(TrivialTicker.this) {
					jobs.remove(job); // We must do this before job.run() in case the job re-schedules itself.
				}

				if(job instanceof FastRunnable) {
					job.run();
				} else {
					executor.execute(job, "Delayed task: "+job);
				}
			}, offset, MILLISECONDS);
			jobs.put(job, future);
		}
	}

	@Override
	public void queueTimedJob(final Runnable job, final String name, long offset,
			boolean runOnTickerAnyway, boolean noDupes) {
		synchronized(this) {
			if(!running)
				return;

			if(noDupes && jobs.containsKey(job))
				return;

			ScheduledFuture<?> future = scheduler.schedule(() -> {
				synchronized(TrivialTicker.this) {
					jobs.remove(job); // We must do this before job.run() in case the job re-schedules itself.
				}

				if(job instanceof FastRunnable) {
					job.run();
				} else {
					executor.execute(job, name);
				}
			}, offset, MILLISECONDS);
			jobs.put(job, future);
		}
	}

	public void cancelTimedJob(final Runnable job) {
		removeQueuedJob(job);
	}

	@Override
	public void removeQueuedJob(final Runnable job) {
		synchronized(this) {
			if(!running)
				return;

			ScheduledFuture<?> future = jobs.remove(job);
			if(future != null) {
				future.cancel(false);
			}
		}
	}

	/**
	 * Changes the offset of a already-queued job.
	 * If the given job was not queued yet it will be queued nevertheless.
	 */
	public void rescheduleTimedJob(final Runnable job, final String name, long newOffset) {
		synchronized(this) {
			removeQueuedJob(job);
			queueTimedJob(job, name, newOffset, false, false); // Don't dupe-check, we are synchronized
		}
	}

	public void shutdown() {
		synchronized(this) {
			running = false;
		}
		scheduler.shutdown();
		try {
			scheduler.awaitTermination(5, SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	@Override
	public Executor getExecutor() {
		return executor;
	}

    @Override
    public void queueTimedJobAbsolute(Runnable runner, String name, long time,
            boolean runOnTickerAnyway, boolean noDupes) {
        queueTimedJobAbsolute(runner, name, time - System.currentTimeMillis(),
                runOnTickerAnyway, noDupes);
    }

}
