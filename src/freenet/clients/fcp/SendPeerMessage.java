package freenet.clients.fcp;

import freenet.node.DarknetPeerNode;
import freenet.node.Node;
import freenet.node.PeerNode;
import freenet.support.SimpleFieldSet;

public abstract class SendPeerMessage extends DataCarryingMessage {

	protected final String identifier;
	protected final String nodeIdentifier;
	private final long dataLength;

	public SendPeerMessage(SimpleFieldSet fs) throws MessageInvalidException {
		identifier = fs.get("Identifier");
		nodeIdentifier = fs.get("NodeIdentifier");
		String dataLengthString = fs.get("DataLength");
		if(dataLengthString != null)
			try {
				//May throw NumberFormatException
				dataLength = Long.parseLong(dataLengthString, 10);
				if(dataLength < 0)
					throw new Exception();
			} catch (Exception e) {
				throw new MessageInvalidException(ProtocolErrorMessage.INVALID_FIELD, "Invalid DataLength field", identifier, false);
			}
		else
			dataLength = -1;
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("Identifier", identifier);
		fs.putSingle("NodeIdentifier", nodeIdentifier);
		if(dataLength >= 0)
			fs.put("DataLength", dataLength);
		return fs;
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
		// HO-20: SendPeerMessage (SendBookmark, SendURI, SendText) sends data to a
		// darknet peer. Restrict to full-access FCP clients — a localhost process that
		// hasn't been granted admin access should not be able to inject data to peers.
		if (!handler.hasFullAccess())
			throw new MessageInvalidException(ProtocolErrorMessage.ACCESS_DENIED,
				getName() + " requires full access", null, false);
		PeerNode pn = node.getPeerNode(nodeIdentifier);
		if (pn == null) {
			FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, identifier);
			handler.send(msg);
		} else if (!(pn instanceof DarknetPeerNode)) {
			throw new MessageInvalidException(ProtocolErrorMessage.DARKNET_ONLY,
					getName() + " only available for darknet peers", identifier, false);
		} else {
			int nodeStatus = handleFeed(((DarknetPeerNode) pn));
			handler.send(new SentPeerMessage(identifier, nodeStatus));
		}
	}

	protected abstract int handleFeed(DarknetPeerNode pn) throws MessageInvalidException;

	@Override
	String getIdentifier() {
		return null;
	}

	@Override
	boolean isGlobal() {
		return false;
	}

	@Override
	long dataLength() {
		return dataLength;
	}
	
}
