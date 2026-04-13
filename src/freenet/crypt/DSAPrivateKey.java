/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Random;

import freenet.support.Base64;
import freenet.support.HexUtil;
import freenet.support.IllegalBase64Exception;
import freenet.support.SimpleFieldSet;

public class DSAPrivateKey extends CryptoKey {
	private static final long serialVersionUID = -1;

    private final BigInteger x;

    public DSAPrivateKey(BigInteger x, DSAGroup g) {
        this.x = x;
        if(x.signum() != 1 || x.compareTo(g.getQ()) > -1 || x.compareTo(BigInteger.ZERO) < 1)
        	throw new IllegalArgumentException();
    }

    // this is dangerous...  better to force people to construct the
    // BigInteger themselves so they know what is going on with the sign
    //public DSAPrivateKey(byte[] x) {
    //    this.x = new BigInteger(1, x);
    //}

/**
 * P-1 NOTE: This constructor accepts any Random instance including non-cryptographic ones.
 * The ONLY legitimate caller with a non-CSPRNG is {@code ClientKSK.create()}, which passes
 * MersenneTwister seeded from SHA-256(keyword) to achieve deterministic KSK key derivation —
 * this is intentional by protocol design.  KSK keys MUST be reproducible from the keyword,
 * so a non-deterministic SecureRandom cannot be substituted here without breaking all
 * existing KSK URLs (backward-incompatible protocol change).
 * All other callers MUST pass a cryptographically secure Random (e.g. node.getRandom()).
 * See {@code ClientKSK.java} and P-1 in the private audit findings for full context.
 */
    public DSAPrivateKey(DSAGroup g, Random r) {
        BigInteger tempX;
        do {
            tempX = new BigInteger(256, r);
        } while (tempX.compareTo(g.getQ()) > -1 || tempX.compareTo(BigInteger.ZERO) < 1);
        this.x = tempX;
    }
    
    protected DSAPrivateKey() {
        // For serialization.
        x = null;
    }

    @Override
	public String keyType() {
        return "DSA.s";
    }
    
    public BigInteger getX() {
        return x;
    }
    
    public static CryptoKey read(InputStream i, DSAGroup g) throws IOException {
        return new DSAPrivateKey(Util.readMPI(i), g);
    }
    
    @Override
    public String toLongString() {
        return "x="+HexUtil.biToHex(x);
    }
    
    // what?  why is DSAGroup passed in?
    //public static CryptoKey readFromField(DSAGroup group, String field) {
    //    //BigInteger x=Util.byteArrayToMPI(Util.hexToBytes(field));
    //    return new DSAPrivateKey(new BigInteger(field, 16));
    //}
    
    @Override
	public byte[] asBytes() {
        return Util.MPIbytes(x);
    }
    
    @Override
	public byte[] fingerprint() {
        return fingerprint(new BigInteger[] {x});
    }

	public SimpleFieldSet asFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("x", Base64.encode(x.toByteArray()));
		return fs;
	}

	public static DSAPrivateKey create(SimpleFieldSet fs, DSAGroup group) throws IllegalBase64Exception {
		BigInteger y = new BigInteger(1, Base64.decode(fs.get("x")));
		if(y.bitLength() > 512)
			throw new IllegalBase64Exception("Probably a pubkey");
		return new DSAPrivateKey(y, group);
	}
}

