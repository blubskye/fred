package freenet.pluginmanager;

import static java.util.Collections.unmodifiableCollection;

import java.net.MalformedURLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import freenet.keys.FreenetURI;
import freenet.node.updater.NodeUpdater;
import freenet.node.updater.PluginJarUpdater;

/**
 * Container for Freenet’s official plugins.
 *
 * FIXME: Connectivity essential plugins shouldn't have their minimum version increased!
 * @see http://bugs.hyphanet.org/view.php?id=6600
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
 // -------------------------------------------------------------------------
 // HO-39: Official plugin CHK keys are NOT bound to developer identity.
 // A CHK guarantees that the fetched bytes match a specific hash, but it does
 // NOT prove who created the data.  Anyone who can commit to the fred repository
 // (or compromise a committer's account) can insert a malicious plugin JAR and
 // update the CHK here.  No code signing, reproducible-build verification, or
 // multi-party approval is required.
 //
 // Additionally, the WebOfTrustTesting entry below used alwaysFetchLatestVersion()
 // with a USK key.  This allowed the USK key holder to push new plugin versions
 // at every node restart with no change to this source file.  That flag has been
 // removed — the node now pins edition /17 and does not auto-update.
 //
 // FULL FIX REQUIRES EXTERNAL BUILD INFRASTRUCTURE — the following work must be
 // done outside this source tree before the verification code can be enabled:
 //
 //   STEP 1 — KEY MANAGEMENT (maintainer action, not a code change):
 //     Each official plugin developer generates a signing key pair.  The public
 //     key must be pinned in this file (or a companion class).  Suggested format:
 //     Base64-encoded DER SubjectPublicKeyInfo (SPKI), one constant per developer.
 //     Example:
 //       static final String WOT_DEV_PUBKEY_B64 =
 //           "MIIBIjANBgkq..."; // developer generates and publishes this
 //
 //   STEP 2 — BUILD PIPELINE (CI/CD change, not a code change):
 //     Every plugin JAR must be signed before being inserted into Freenet.
 //     Standard tooling:
 //       jarsigner -keystore release.jks -signedjar signed.jar plugin.jar alias
 //     The signed JAR embeds the certificate chain in META-INF/*.SF + *.RSA.
 //     The CHK entered here must be the CHK of the SIGNED jar.
 //
 //   STEP 3 — VERIFICATION CODE (ready to enable once steps 1+2 are complete):
 //     In PluginManager.loadPluginFromJarFile() (or PluginJarUpdater), add before
 //     class instantiation:
 //
 //       // Verify JAR signature and check signer matches pinned developer key.
 //       try (JarFile jar = new JarFile(pluginFile, true /* verify */)) {
 //           Enumeration<JarEntry> entries = jar.entries();
 //           while (entries.hasMoreElements()) {
 //               JarEntry entry = entries.nextElement();
 //               // Consume bytes — JarFile verifies signatures lazily on read.
 //               try (InputStream is = jar.getInputStream(entry)) {
 //                   byte[] buf = new byte[8192];
 //                   while (is.read(buf) != -1) { /* consume to trigger verify */ }
 //               }
 //               if (entry.isDirectory()) continue;
 //               CodeSigner[] signers = entry.getCodeSigners();
 //               if (signers == null || signers.length == 0)
 //                   throw new SecurityException("Unsigned entry: " + entry.getName());
 //               // Compare leaf certificate public key against the pinned SPKI for
 //               // this plugin's declared developer:
 //               PublicKey leafKey = signers[0]
 //                   .getSignerCertPath().getCertificates().get(0)
 //                   .getPublicKey();
 //               if (!Arrays.equals(leafKey.getEncoded(), expectedDevPublicKeyDer))
 //                   throw new SecurityException("Plugin signed by unknown key");
 //           }
 //       }
 //
 //   STEP 4 — POLICY (process change, not a code change):
 //     Require sign-off from >= 2 maintainers in the git review process for any
 //     CHK change in this file.  This limits the blast radius of a single
 //     compromised committer account.
 //
 // DO NOT enable step 3 before steps 1+2 are complete — without signed JARs,
 // turning on verification will make every official plugin fail to load.
 // -------------------------------------------------------------------------

public class OfficialPlugins {

	private final Map<String, OfficialPluginDescription> officialPlugins = new HashMap<String, OfficialPluginDescription>();

	public OfficialPlugins() {
		try {
			addPlugin("Freemail")
					.inGroup("communication")
					.minimumVersion(15)
					.usesXml()
					.loadedFrom("CHK@6dfMgGf7YEfJhF0W~K0HUv0fnbuRwYH6iMqrLIbTI7k,huYBf8oBevwW6lRQnz-0jDP1dl5ej7FKeyVZ3CnH0Ec,AAMC--8/Freemail.jar")
					.deprecated();
			addPlugin("Freemail_wot")
					.inGroup("communication")
					.recommendedVersion(33)
					.minimumVersion(27)
					.loadedFrom("CHK@SeUdM2xx~Pl9bCt3uzafbVM8HijDpxoQXwTxkkgqeUE,5GCNdPxg649uE~5SicWQSETGa8WVEe0RkIOSIC86UrE,AAMC--8/Freemail.jar");
			addPlugin("HelloWorld")
					.inGroup("example")
					.loadedFrom("CHK@ZdTXnWV-ikkt25-y8jmhlHjCY-nikDMQwcYlWHww5eg,Usq3uRHpHuIRmMRRlNQE7BNveO1NwNI7oNKdb7cowFM,AAIC--8/HelloWorld.jar")
					.advanced();
			addPlugin("HelloFCP")
					.inGroup("example")
					.loadedFrom("CHK@0gtXJpw1QUJCmFOhoPRNqhsNbMtVw1CGVe46FUv7-e0,X8QqhtPkHoaFCUd89bgNaKxX1AV0WNBVf3sRgSF51-g,AAIC--8/HelloFCP.jar")
					.advanced();
			addPlugin("JSTUN")
					.inGroup("connectivity")
					.advanced()
					.essential()
					.minimumVersion(2)
					.loadedFrom("CHK@0RcKSZZ~sycAShXZjXANI9cQrPcsNnz6BFgbXzOlsfU,bbKD6TR~oWcodNCr2L8Lw0pQIesX7ZWlPRpw-A5h~DA,AAMC--8/JSTUN.jar");
			addPlugin("KeyUtils")
					.inGroup("technical")
					.minimumVersion(5028)
					.loadedFrom("CHK@IQs-ssTnVh8ZuvYASea-O78hVA2y81FI7AVf2X5PXJI,J7yf0iM5Q1W4MppL0DlTyeKJMDdVQQiVlUFQAJvUzjs,AAMC--8/KeyUtils.jar");
			addPlugin("KeepAlive")
					.inGroup("file-transfer")
					.loadedFrom("CHK@mR-kJQNZYRaMRdO0D36NhLv8WnfF1sqsBe1ixKUg5lo,i-HExcBFiue3u4q5jooqRZUzRBGZJ0DSpd~~1T7fW6Q,AAMC--8/plugin-KeepAlive.jar");
			addPlugin("MDNSDiscovery")
					.advanced()
					.inGroup("connectivity")
					.minimumVersion(2)
					.loadedFrom("CHK@wPyhY61bsDM3OW6arFlxYX8~mBKjo~XtOTIAbT0dk88,Vr3MTAzkW5J28SJs2dTxkj6D4GVNm3u8GFsxJgzTL1M,AAIC--8/MDNSDiscovery.jar");
			addPlugin("SNMP")
					.inGroup("connectivity")
					.loadedFrom("CHK@EykJIv83UE291zONVzfXqyJYX5t66uCQJHkzQrB61MI,-npuolPZj1fcAWane2~qzRNEjKDERx52aQ5bC6NBQgw,AAIC--8/SNMP.jar")
					.advanced();
			addPlugin("TestGallery")
					.inGroup("example")
					.minimumVersion(1)
					.loadedFrom("CHK@LfJVh1EkCr4ry0yDW74vwxkX-3nkr~ztW2z0SUZHfC0,-mz7l39dC6n0RTUiSokjC~pUDO7PWZ89miYesKH0-WA,AAIC--8/TestGallery.jar")
					.experimental();
			addPlugin("ThawIndexBrowser")
					.inGroup("file-transfer")
					.advanced()
					.minimumVersion(6)
					.usesXml()
					.loadedFrom("CHK@9bjNQtl7ndPKh~gi4woH0Xvb7uRunJ81deIlXwGE6qg,clwp0Bhx2LZxt2XCWeARqv24tBNmjlhXDZtwAJpzlIc,AAMC--8/ThawIndexBrowser-v6.jar");
			addPlugin("UPnP")
					.inGroup("connectivity")
					.essential()
					.advanced()
					.recommendedVersion(10007)
					.minimumVersion(10003)
					.loadedFrom("CHK@ZiX8yeMHTUtNfJAgxpwH~jLRnnbb41BKEkAxOD~33tY,aBTvD3IoPKPLjnHOCNQ4-iRwqVED5kHgkmD4UhGdITk,AAMC--8/UPnP-10007.jar");
			addPlugin("UPnP2")
					.inGroup("connectivity")
					.loadedFrom("CHK@oFNunyhic~ug3lWas8Jabpwbt3heHhrFzHswN~GhPNc,j~2AHw~ZyZGNMuqW3zmukTJHysDg5lBTvrySerSPxkI,AAMC--8/freenet-UPnP2.jar");
			addPlugin("XMLLibrarian")
					.inGroup("index")
					.minimumVersion(26)
					.usesXml()
					.loadedFrom("CHK@TvjyCaG1dx0xIBSJkXSKA1ZT4I~NkRKeQqwC0a0bhFM,JiQe4CRjF1RwhQRFFQzP-ih9t2i0peV0tBCfJAeFCdk,AAIC--8/XMLLibrarian.jar")
					.unsupported();
			addPlugin("XMLSpider")
					.inGroup("index")
					.minimumVersion(48)
					.usesXml()
					.loadedFrom("CHK@ne-aaLuzVZLcHj0YmrclaCXJqxsSb7q-J0eYEiL9V9o,v0EdgDGBhTE9k6GsB44UrQ4ADUq5LCUVknLaE4iSEBk,AAMC--8/XMLSpider.jar")
					.unsupported();
			addPlugin("Freereader")
					.inGroup("index")
					.minimumVersion(6)
					.usesXml()
					.loadedFrom("CHK@SjXgPC5IEZa2g7a6gIKmNuxEKN4~eWrPhIwsznmGV-8,QUxm9R3sp3mNwhEHhL8mlx9zbOhIqIyR93tu7jD~0EU,AAMC--8/Freereader-6.jar");
			addPlugin("Library")
					.inGroup("index")
					.recommendedVersion(37)
					.minimumVersion(36)
					.usesXml()
					.loadedFrom("CHK@RrYmOu8RGoEY44LOgGBBgY9qRxmiev0SFAVxWAbwROI,cfYMrDcBdewk4I7AC4J3mAq0g~NH3TxVpfeSkQ9Xaa8,AAMC--8/Library.jar")
					.advanced();
			addPlugin("Spider")
					.inGroup("index")
					.minimumVersion(53)
					.loadedFrom("CHK@AsgPJMi335uI0lW5ZTx7PIauP-O2piHARJQsMZPdRLE,c-WnilzeQ2JApq1GdXQPukUeMQ51teUMjgqDRoBxlpg,AAMC--8/Spider.jar")
					.advanced();
			addPlugin("WebOfTrust")
					.inGroup("communication")
					.minimumVersion(18)
					.recommendedVersion(20)
					.usesXml()
					.loadedFrom("CHK@ic-xihD6BzLwqxuI27CVvDCa71jF39Vs8bWPP00c8II,vgL-dISouZD7NyfpHSE8sVccQP5242dvpvV2XfCilqs,AAMC--8/WebOfTrust.jar");
			addPlugin("WebOfTrustTesting")
					.inGroup("communication")
					.advanced()
					.experimental()
					.usesXml()
					.minimumVersion(17)
					.loadedFrom("USK@QeTBVWTwBldfI-lrF~xf0nqFVDdQoSUghT~PvhyJ1NE,OjEywGD063La2H-IihD7iYtZm3rC0BP6UTvvwyF5Zh4,AQACAAE/WebOfTrustTesting.jar/17");
			addPlugin("FlogHelper")
					.inGroup("communication")
					.minimumVersion(36)
					.usesXml()
					.loadedFrom("CHK@zAvWPxjh2rJ7j2cAiXcm2wnDYlURL9BFDGfLBaVtjqU,Ak90k0Qw1b6CWoWZ1AMdvrUj~evz4p9vl75mg7BsEp0,AAMC--8/FlogHelper.jar");
			addPlugin("Sharesite")
					.inGroup("communication")
					.recommendedVersion(7)
					.minimumVersion(2)
					.loadedFrom("CHK@~JCtW4wZDI3dX1vKejUQ-y19sC6tfc5L87hcknvAT-g,x5jFuw2KkDVEQ5d31zi47y7lXAHDfcvfu6rOgQpZkHs,AAMC--8/Sharesite-0-5-1.jar");
		} catch (MalformedURLException mue1) {
			throw new RuntimeException("Could not create FreenetURI.", mue1);
		}
	}

	private OfficialPluginBuilder addPlugin(String name) {
		return new OfficialPluginBuilder(name);
	}

	public OfficialPluginDescription get(String name) {
		return officialPlugins.get(name);
	}

	public Collection<OfficialPluginDescription> getAll() {
		return unmodifiableCollection(officialPlugins.values());
	}

	private class OfficialPluginBuilder {

		private final String name;
		private String group;
		private boolean essential;
		private long minimumVersion = -1;
		private long recommendedVersion = -1;
		/** @see OfficialPluginDescription#alwaysFetchLatestVersion */
		private boolean alwaysFetchLatestVersion;
		private boolean usesXml;
		/** @see OfficialPluginDescription#uri */
		private FreenetURI uri;
		private boolean deprecated;
		private boolean experimental;
		private boolean advanced;
    private boolean unsupported;

		private OfficialPluginBuilder(String name) {
			this.name = name;
			addCurrentPluginDescription();
		}

		public OfficialPluginBuilder inGroup(String group) {
			this.group = group;
			addCurrentPluginDescription();
			return this;
		}

		public OfficialPluginBuilder essential() {
			essential = true;
			addCurrentPluginDescription();
			return this;
		}

		public OfficialPluginBuilder minimumVersion(int minimumVersion) {
			this.minimumVersion = minimumVersion;
			addCurrentPluginDescription();
			return this;
		}

		public OfficialPluginBuilder recommendedVersion(int recommendedVersion) {
			this.recommendedVersion = recommendedVersion;
			addCurrentPluginDescription();
			return this;
		}

		/** @see OfficialPluginDescription#alwaysFetchLatestVersion */
		public OfficialPluginBuilder alwaysFetchLatestVersion() {
			this.alwaysFetchLatestVersion = true;
			addCurrentPluginDescription();
			return this;
		}

		public OfficialPluginBuilder usesXml() {
			usesXml = true;
			addCurrentPluginDescription();
			return this;
		}

		/**
		 * ATTENTION: Please read {@link OfficialPluginDescription#uri} before deciding whether
		 * to use USK or CHK! */
		public OfficialPluginBuilder loadedFrom(String uri) throws MalformedURLException {
			this.uri = new FreenetURI(uri);
			addCurrentPluginDescription();
			return this;
		}

		public OfficialPluginBuilder deprecated() {
			deprecated = true;
			addCurrentPluginDescription();
			return this;
		}

		public OfficialPluginBuilder experimental() {
			experimental = true;
			addCurrentPluginDescription();
			return this;
		}

		public OfficialPluginBuilder advanced() {
			advanced = true;
			addCurrentPluginDescription();
			return this;
		}

    public OfficialPluginBuilder unsupported() {
      unsupported = true;
      addCurrentPluginDescription();
      return this;
    }

		private void addCurrentPluginDescription() {
            if(recommendedVersion == 0 && minimumVersion > 0)
                recommendedVersion = minimumVersion;
            if(minimumVersion == 0 && recommendedVersion > 0)
                minimumVersion = recommendedVersion;
			officialPlugins.put(name, createOfficialPluginDescription());
		}

		private OfficialPluginDescription createOfficialPluginDescription() {
			return new OfficialPluginDescription(name, group, essential, minimumVersion,
				recommendedVersion, alwaysFetchLatestVersion, usesXml, uri, deprecated,
				experimental, advanced, unsupported);
		}

	}

	public static class OfficialPluginDescription {

		/** The name of the plugin */
		public final String name;

		/**
		 * The group of the plugin. The group is a technical name that needs to
		 * be translated before it is shown to the user.
		 */
		public final String group;

		/**
		 * If true, we will download it, blocking, over HTTP, during startup (unless
		 * explicitly forbidden to use HTTP). If not, we will download it on a
		 * separate thread after startup. Both are assuming we don't have it in a
		 * file.
		 */
		public final boolean essential;
		/**
		 * Minimum getRealVersion(). If the plugin is older than this, we will fail
		 * the load.
		 */
		public final long minimumVersion;
		/**
		 * Recommended getRealVersion(). If the plugin is older than this, we will
		 * download the new version in the background, and either use it on restart,
		 * or offer the user the option to reload it. This is in fact identical to
		 * what happens on a USK-based update...
		 */
		public final long recommendedVersion;
		
		/**
		 * If true, if during startup we already have a copy of the plugin JAR on disk, the
		 * {@link PluginManager} will ignore it and redownload the JAR instead so the user gets a
		 * recent version if there is one.<br><br>
		 * 
		 * This is for being used together with plugins which are fetched from a USK {@link #uri},
		 * and which are not included in the official main Freenet update USK which
		 * {@link PluginJarUpdater} watches.<br>
		 * For plugins which are in the main Freenet update USK, setting this to true is usually
		 * not necessary: The {@link PluginJarUpdater} will update the plugin if there is a new
		 * version.<br><br>
		 * 
		 * In other words: Plugins which are NOT in the official USK but have their own USK will
		 * not have the {@link PluginJarUpdater} monitor their USK, it only monitors the main
		 * USK. Thus, the only chance to update them is during startup by ignoring the JAR and
		 * causing a re-download of it. */
		public final boolean alwaysFetchLatestVersion;
		
		/** Does it use XML? If so, if the JVM is vulnerable, then don't load it */
		public final boolean usesXML;
		/**
		 * FreenetURI to get the latest version from.<br>
		 * Typically a CHK, not USK, since updates are deployed using the main Freenet USK of
		 * {@link NodeUpdater}'s subclass {@link PluginJarUpdater}.<br><br>
		 * 
		 * To allow people to insert plugin updates without giving them write access to the main
		 * USK, this *can* be an USK, but updating when a new version is inserted to the USK will
		 * only happen at certain points in time:<br>
		 * - if the plugin is manually unloaded and loaded again.<br>
		 * - at restart of Freenet if {@link #alwaysFetchLatestVersion} is true. If it is false, the
		 *   cached local JAR file on disk will prevent updating!<br>
		 * So to make updating work using USK, set {@link #alwaysFetchLatestVersion} so we check
		 * for updates when the node is restarted.<br><br>
		 * 
		 * NOTICE the conclusion of the above: It is NOT RECOMMENDED to use USKs here: Updates will
		 * only be delivered at restarts of the node, while the main Freenet USK supports live
		 * updates; and also there is no revocation mechanism for the USKs. Instead of using USKs
		 * here, a CHK should be preferred, and new plugin versions then should be inserted at the
		 * main Freenet update USK of the the {@link NodeUpdater}. A typical usecase for
		 * nevertheless using an USK here is to allow individual plugin developers to push testing
		 * versions of their plugin on their own without giving them write-access to the main
		 * Freenet update USK.*/
		public final FreenetURI uri;
		/** If true, the plugin is obsolete. */
		public final boolean deprecated;
		/** If true, the plugin is experimental. */
		public final boolean experimental;
		/**
		 * If true, the plugin is geeky - it should not be shown except in advanced
		 * mode even though it's not deprecated nor is it experimental.
		 */
		public final boolean advanced;
    /**
     * If true, the plugin used to be official, but is no longer supported.
     * These are not shown even in advanced mode.
     */
    public final boolean unsupported;

		OfficialPluginDescription(String name, String group, boolean essential, long minVer,
				long recVer, boolean alwaysFetchLatestVersion, boolean usesXML, FreenetURI uri,
				boolean deprecated, boolean experimental, boolean advanced, boolean unsupported) {
			
			this.name = name;
			this.group = group;
			this.essential = essential;
			this.minimumVersion = minVer;
			this.recommendedVersion = recVer;
			this.alwaysFetchLatestVersion = alwaysFetchLatestVersion;
			this.usesXML = usesXML;
			this.deprecated = deprecated;
			this.experimental = experimental;
			this.advanced = advanced;
      this.unsupported = unsupported;

			if (alwaysFetchLatestVersion && uri != null) {
				assert(uri.isUSK()) : "Non-USK URIs do not support updates!";
				
				// Force fetching the latest edition by setting a negative USK edition.
				long edition = uri.getSuggestedEdition();
				if (edition >= 0) {
					edition = Math.min(-1, -edition);
				}
				uri = uri.setSuggestedEdition(edition);
			}
			
			this.uri = uri;
		}

		public String getLocalisedPluginName() {
			return PluginManager.getOfficialPluginLocalisedName(name);
		}

		public String getLocalisedPluginDescription() {
			return PluginManager.l10n("pluginDesc." + name);
		}

	}

}
