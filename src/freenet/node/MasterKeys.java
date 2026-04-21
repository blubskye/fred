package freenet.node;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import freenet.crypt.BlockCipher;
import freenet.crypt.MasterSecret;
import freenet.crypt.PCFBMode;
import freenet.crypt.SHA256;
import freenet.crypt.UnsupportedCipherException;
import freenet.crypt.ciphers.Rijndael;
import freenet.support.Fields;
import freenet.support.Logger;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;

/** Keys read from the master keys file */
public class MasterKeys {

	// Currently we only encrypt the client cache

	final byte[] clientCacheMasterKey;
	private final byte[] databaseKey;
	private final byte[] tempfilesMasterSecret;
	final long flags;

	final static long FLAG_ENCRYPT_DATABASE = 2;

	public MasterKeys(byte[] clientCacheKey, byte[] databaseKey, byte[] tempfilesMasterSecret, long flags) {
		this.clientCacheMasterKey = clientCacheKey;
		this.databaseKey = databaseKey;
		this.flags = flags;
		this.tempfilesMasterSecret = tempfilesMasterSecret;
	}
	
    /** Create a MasterKeys with random keys.
     * @param random A secure RNG. Not specifically a SecureRandom because we want to be able to 
     * use this in tests. */
    public static MasterKeys createRandom(Random random) {
        byte[] clientCacheKey = new byte[32];
        random.nextBytes(clientCacheKey);
        byte[] databaseKey = new byte[32];
        random.nextBytes(databaseKey);
        byte[] tempfilesMasterSecret = new byte[64];
        random.nextBytes(tempfilesMasterSecret);
        return new MasterKeys(clientCacheKey, databaseKey, tempfilesMasterSecret, 0);
    }

    void clearClientCacheKeys() {
		clear(clientCacheMasterKey);
	}

	static final int OLD_HASH_LENGTH = 4;
	static final int HASH_LENGTH = 12;
	
	static final int VERSION = 1;
	
	/** Sanity check */
	static final long MAX_ITERATIONS = 1L << 40;
	
	/** Time in milliseconds to iterate for when encrypting a non-empty password. 
	 * FIXME make this configurable. FIXME Have a look at real password to key functions. */
	static int ITERATE_TIME = 1000;

	public static MasterKeys read(File masterKeysFile, Random hardRandom, String password) throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
		Logger.normal(MasterKeys.class, "Trying to read master keys file...");
		if(masterKeysFile != null && masterKeysFile.exists()) {
			// Try to read the keys
			FileInputStream fis = null;
			long len = masterKeysFile.length();
            if(len > 1024) throw new MasterKeysFileSizeException(true);
            if(len < (32 + 32 + 8 + 32)) throw new MasterKeysFileSizeException(false);
			int length = (int) len;
			// Declare sensitive buffers here so the finally block can clear them on any exit path.
			byte[] pwd = null;
			byte[] outerKey = null;
			byte[] dataAndHash = null;
			byte[] data = null;
			byte[] hash = null;
			try {
				fis = new FileInputStream(masterKeysFile);
				DataInputStream dis = new DataInputStream(fis);
				if(len == 140) {
				    MasterKeys ret = readOldFormat(dis, length, hardRandom, password);
				    Logger.normal(MasterKeys.class, "Read old-format master keys file. Writing new format master.keys ...");
                    ret.changePassword(masterKeysFile, password, hardRandom);
                    return ret;
				}
				if(dis.readInt() != VERSION) throw new IOException("Bad version for master.keys");
				long iterations = dis.readLong();
				if(iterations < 0 || iterations > MAX_ITERATIONS) throw new IOException("Bad iterations "+iterations+" for master.keys");

				byte[] salt = new byte[32];
				dis.readFully(salt);
				byte[] iv = new byte[32];
				dis.readFully(iv);
				dataAndHash = new byte[length - salt.length - iv.length - 4 - 8];
				dis.readFully(dataAndHash);
				pwd = password.getBytes(StandardCharsets.UTF_8);
				MessageDigest md = SHA256.getMessageDigest();
				md.update(pwd);
				md.update(salt);
				outerKey = md.digest();
				if(iterations > 0) {
				    Logger.normal(MasterKeys.class, "Decrypting master keys using password with "+iterations+" iterations...");
				    for(long i=0;i<iterations;i++) {
				        md.update(salt);
				        md.update(outerKey);
				        outerKey = md.digest();
				    }
				}
				BlockCipher cipher;
				try {
					cipher = new Rijndael(256, 256);
				} catch (UnsupportedCipherException e) {
					// Impossible
					throw new Error(e);
				}
				cipher.initialize(outerKey);
				Arrays.fill(outerKey, (byte)0); // HO-69: clear password-derived key from heap
				outerKey = null;
				PCFBMode pcfb = PCFBMode.create(cipher, iv);
				pcfb.blockDecipher(dataAndHash, 0, dataAndHash.length);
				data = Arrays.copyOf(dataAndHash, dataAndHash.length - HASH_LENGTH);
				hash = Arrays.copyOfRange(dataAndHash, data.length, dataAndHash.length);
				clear(dataAndHash);
				dataAndHash = null;
				byte[] checkHash = md.digest(data);
				if(!Fields.byteArrayEqual(checkHash, hash, 0, 0, HASH_LENGTH)) {
					throw new MasterKeysWrongPasswordException();
				}

				// It matches. Now decode it.
				ByteArrayInputStream bais = new ByteArrayInputStream(data);
				dis = new DataInputStream(bais);
				long flags = dis.readLong();
				// At the moment there are no interesting flags.
				// In future the flags will tell us whether the database and the datastore are encrypted.
				byte[] clientCacheKey = new byte[32];
				dis.readFully(clientCacheKey);
				byte[] databaseKey = new byte[32];
				dis.readFully(databaseKey);
				byte[] tempfilesMasterSecret = new byte[64];
				boolean mustWrite = false;
				if(data.length >= 8+32+32+64) {
				    dis.readFully(tempfilesMasterSecret);
				} else {
                    Logger.normal(MasterKeys.class, "Created new master secret for encrypted tempfiles");
				    hardRandom.nextBytes(tempfilesMasterSecret);
				    mustWrite = true;
				}
				MasterKeys ret = new MasterKeys(clientCacheKey, databaseKey, tempfilesMasterSecret, flags);
				clear(data);
				data = null;
				clear(hash);
				hash = null;
				Logger.normal(MasterKeys.class, "Read old master keys file");
				if(mustWrite) {
				    ret.changePassword(masterKeysFile, password, hardRandom);
				}
				return ret;
			} catch (FileNotFoundException e) {
				// Ok, create a new one.
			} catch (EOFException e) {
				throw new MasterKeysFileSizeException(false);
			} finally {
				Closer.close(fis);
				// Always clear sensitive data, including on exception paths.
				if(pwd != null) Arrays.fill(pwd, (byte)0);
				clear(outerKey);
				clear(dataAndHash);
				clear(data);
				clear(hash);
			}
		}
		Logger.normal(MasterKeys.class, "Creating new master keys file");
		MasterKeys ret = createRandom(hardRandom);
		ret.write(masterKeysFile, password, hardRandom);
		return ret;
	}

	private static MasterKeys readOldFormat(DataInputStream dis, int length, Random hardRandom,
            String password) throws IOException, MasterKeysWrongPasswordException {
        byte[] salt = new byte[32];
        dis.readFully(salt);
        byte[] iv = new byte[32];
        dis.readFully(iv);
        // Declare sensitive buffers here so the finally block can clear them on any exit path.
        byte[] pwd = null;
        byte[] outerKey = null;
        byte[] dataAndHash = null;
        byte[] data = null;
        byte[] hash = null;
        try {
            dataAndHash = new byte[length - salt.length - iv.length];
            dis.readFully(dataAndHash);
            pwd = password.getBytes(StandardCharsets.UTF_8);
            MessageDigest md = SHA256.getMessageDigest();
            md.update(pwd);
            md.update(salt);
            outerKey = md.digest();
            BlockCipher cipher;
            try {
                cipher = new Rijndael(256, 256);
            } catch (UnsupportedCipherException e) {
                // Impossible
                throw new Error(e);
            }
            cipher.initialize(outerKey);
            Arrays.fill(outerKey, (byte)0); // HO-69: clear password-derived key from heap
            outerKey = null;
            PCFBMode pcfb = PCFBMode.create(cipher, iv);
            pcfb.blockDecipher(dataAndHash, 0, dataAndHash.length);
            data = Arrays.copyOf(dataAndHash, dataAndHash.length - OLD_HASH_LENGTH);
            hash = Arrays.copyOfRange(dataAndHash, data.length, dataAndHash.length);
            clear(dataAndHash);
            dataAndHash = null;
            byte[] checkHash = md.digest(data);
            if(!Fields.byteArrayEqual(checkHash, hash, 0, 0, OLD_HASH_LENGTH)) {
                throw new MasterKeysWrongPasswordException();
            }

            // It matches. Now decode it.
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            DataInputStream innerDis = new DataInputStream(bais);
            byte[] flagsBytes = new byte[8];
            innerDis.readFully(flagsBytes);
            long flags = Fields.bytesToLong(flagsBytes);
            // At the moment there are no interesting flags.
            // In future the flags will tell us whether the database and the datastore are encrypted.
            byte[] clientCacheKey = new byte[32];
            innerDis.readFully(clientCacheKey);
            byte[] databaseKey = new byte[32];
            innerDis.readFully(databaseKey);
            byte[] tempfilesMasterSecret = new byte[64];
            Logger.normal(MasterKeys.class, "Created new master secret for encrypted tempfiles");
            hardRandom.nextBytes(tempfilesMasterSecret);
            MasterKeys ret = new MasterKeys(clientCacheKey, databaseKey, tempfilesMasterSecret, flags);
            clear(data);
            data = null;
            clear(hash);
            hash = null;
            return ret;
        } finally {
            // Always clear sensitive data, including on exception paths.
            if(pwd != null) Arrays.fill(pwd, (byte)0);
            clear(outerKey);
            clear(dataAndHash);
            clear(data);
            clear(hash);
        }
    }

    public static void clear(byte[] buf) {
		if(buf == null) return; // Valid no-op, simplifies code
		Arrays.fill(buf, (byte)0x00);
	}

	public void changePassword(File masterKeysFile, String newPassword, Random hardRandom) throws IOException {
		Logger.normal(MasterKeys.class, "Writing new master.keys file");
		write(masterKeysFile, newPassword, hardRandom);
	}
	
	private void write(File masterKeysFile, String newPassword, Random hardRandom) throws IOException {
		// Write it to a byte[], check size, then replace in-place atomically

		// New IV, new salt, same client cache key, same database key

	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

		byte[] iv = new byte[32];
		hardRandom.nextBytes(iv);
		byte[] salt = new byte[32];
		hardRandom.nextBytes(salt);

		// Declare sensitive buffers here so the finally block can clear them on any exit path.
        byte[] pwd = null;
        byte[] outerKey = null;
        try {
        pwd = newPassword.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = SHA256.getMessageDigest();
        md.update(pwd);
        md.update(salt);
        outerKey = md.digest();
        long iterations = 0;
        if(!newPassword.isEmpty()) {
            long startTime = System.currentTimeMillis();
            while(System.currentTimeMillis() < startTime + ITERATE_TIME && iterations < MAX_ITERATIONS-20) {
                for(int i=0;i<10;i++) {
                    iterations++;
                    md.update(salt);
                    md.update(outerKey);
                    outerKey = md.digest();
                }
            }
            Logger.normal(MasterKeys.class, "Encrypted password with "+iterations+" iterations.");
        }

		DataOutputStream dos = new DataOutputStream(baos);
		dos.writeInt(VERSION);
		dos.writeLong(iterations);
		baos.write(salt);
		baos.write(iv);
		int hashedStart = salt.length + iv.length + 4 + 8;
		dos.writeLong(flags);
		baos.write(clientCacheMasterKey);
		baos.write(databaseKey);
		baos.write(tempfilesMasterSecret);

		byte[] data = baos.toByteArray();

		md.update(data, hashedStart, data.length-hashedStart);
		byte[] hash = md.digest();
		baos.write(hash, 0, HASH_LENGTH);
		data = baos.toByteArray();

		BlockCipher cipher;
		try {
			cipher = new Rijndael(256, 256);
		} catch (UnsupportedCipherException e) {
			// Impossible
			throw new Error(e);
		}
		cipher.initialize(outerKey);
		Arrays.fill(outerKey, (byte)0); // HO-69: clear password-derived key after use
		outerKey = null;
		PCFBMode pcfb = PCFBMode.create(cipher, iv);
		pcfb.blockEncipher(data, hashedStart, data.length - hashedStart);

		// HO-68: Atomic write via temp-file + rename to avoid partial-write corruption on power loss.
		File temp = new File(masterKeysFile.getParentFile(), masterKeysFile.getName() + ".tmp");
		try (FileOutputStream fos = new FileOutputStream(temp)) {
			fos.write(data);
			fos.getFD().sync();
		} finally {
			if (!FileUtil.renameTo(temp, masterKeysFile)) {
				temp.delete();
				throw new IOException("Atomic rename failed: could not replace " + masterKeysFile);
			}
		}
        } finally {
            // Always clear sensitive data, including on exception paths.
            if(pwd != null) Arrays.fill(pwd, (byte)0);
            clear(outerKey);
        }
	}

	public static void killMasterKeys(File masterKeysFile) throws IOException {
		FileUtil.secureDelete(masterKeysFile);
	}

	/**
	 * @param unused randomness source object. Note: this parameter is not used in this call,
	 *               and database key material is generated
	 *               during or before construction of the {@link MasterKeys} object.
	 * @return database key object
	 * @deprecated use other {@link #createDatabaseKey()} method without parameters
	 */
	@Deprecated
	public DatabaseKey createDatabaseKey(Random unused) {
		return createDatabaseKey();
	}

	public DatabaseKey createDatabaseKey() {
		return new DatabaseKey(databaseKey);
	}

	/** Used for creating keys for persistent encrypted tempfiles */
    public MasterSecret getPersistentMasterSecret() {
        return new MasterSecret(tempfilesMasterSecret.clone());
    }

}
