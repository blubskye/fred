package freenet.clients.fcp;

import freenet.node.Node;
import freenet.support.SimpleFieldSet;

public class WatchFeedsMessage extends FCPMessage {

	public static final String NAME = "WatchFeeds";
	public final boolean enabled;

	public WatchFeedsMessage(SimpleFieldSet fs) {
		enabled = fs.getBoolean("Enabled", true);
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node)
			throws MessageInvalidException {
		// HO-25: WatchFeeds subscribes a client to all node alerts/feeds. Restrict to
		// full-access clients — unrestricted clients should not receive node-wide alerts.
		if (!handler.hasFullAccess())
			throw new MessageInvalidException(ProtocolErrorMessage.ACCESS_DENIED,
				"WatchFeeds requires full access", null, false);
		if(enabled)
			node.getClientCore().getAlerts().watch(handler);
		else
			node.getClientCore().getAlerts().unwatch(handler);
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.put("Enabled", enabled);
		return fs;
	}

}
