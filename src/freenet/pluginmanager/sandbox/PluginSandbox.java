package freenet.pluginmanager.sandbox;

import java.io.File;
import java.security.Permission;
import java.util.concurrent.ConcurrentHashMap;

import freenet.support.Logger;

/**
 * SecurityManager that constrains what sandboxed plugins are allowed to do.
 *
 * <h3>Identification of plugin code</h3>
 * Two complementary mechanisms are used so that restrictions apply whether the plugin code is
 * running on its own background thread <em>or</em> on a node thread that dispatched into a plugin
 * handler (HTTP, FCP):
 * <ol>
 *   <li><b>ThreadGroup walk</b> — each plugin's threads live in a dedicated
 *       {@link PluginThreadGroup}; walking up the ThreadGroup tree from the current thread
 *       identifies plugin threads.</li>
 *   <li><b>Dispatch context</b> — node code that calls into plugin handlers
 *       (e.g. {@code FredPluginHTTP.handleHTTPGet}) must call
 *       {@link #enterPluginContext}/{@link #exitPluginContext} around the call so the correct
 *       {@link PluginThreadGroup} is visible on the node's own thread.</li>
 * </ol>
 *
 * <h3>What is blocked</h3>
 * <ul>
 *   <li>Process spawning ({@code Runtime.exec}, {@code ProcessBuilder}) — always blocked.</li>
 *   <li>Native library loading ({@code System.loadLibrary/load}) — always blocked.</li>
 *   <li>JVM shutdown ({@code System.exit}) — always blocked.</li>
 *   <li>Installing a new SecurityManager — always blocked (for all code once sandbox is active).</li>
 *   <li>Creating a ClassLoader — blocked for plugin threads (prevents sandbox escape).</li>
 *   <li>File writes/deletes outside the plugin's data directory and system temp — blocked.</li>
 *   <li>Accessing thread groups outside the plugin's own group — blocked.</li>
 *   <li>Outbound network connections — logged in STANDARD mode, blocked in STRICT mode.</li>
 * </ul>
 *
 * <h3>Java version note</h3>
 * {@link SecurityManager} is deprecated for removal in Java 17 and removed in Java 18+.
 * This sandbox is intentional and appropriate for the Java 17 target of this branch.
 * Migration to process-level isolation is the recommended long-term path.
 */
@SuppressWarnings({"removal", "deprecation"})
public final class PluginSandbox extends SecurityManager {

    // -------------------------------------------------------------------------
    // Singleton install
    // -------------------------------------------------------------------------

    private static volatile boolean installed = false;

    /**
     * Install this sandbox as the JVM-wide {@link SecurityManager}.
     * Must be called before any plugins are loaded (typically from {@code PluginManager}
     * constructor).  Idempotent: calling it more than once is a no-op after the first call.
     * If another SecurityManager is already installed the call logs a warning and returns.
     */
    public static synchronized void install() {
        if (installed) return;
        try {
            if (System.getSecurityManager() != null) {
                Logger.warning(PluginSandbox.class,
                    "A SecurityManager is already installed; plugin sandbox cannot be applied. "
                    + "Existing manager: " + System.getSecurityManager());
                return;
            }
            System.setSecurityManager(new PluginSandbox());
            installed = true;
            Logger.normal(PluginSandbox.class,
                "Plugin sandbox SecurityManager installed — plugins will be restricted.");
        } catch (UnsupportedOperationException e) {
            // Java 18+ or -Djava.security.manager=disallow
            Logger.warning(PluginSandbox.class,
                "SecurityManager cannot be installed on this JVM ("
                + System.getProperty("java.version") + "); plugin sandbox is inactive. "
                + "Consider upgrading to process-level isolation.", e);
        } catch (SecurityException e) {
            Logger.error(PluginSandbox.class,
                "Failed to install plugin sandbox SecurityManager.", e);
        }
    }

    // -------------------------------------------------------------------------
    // Plugin registry (ClassLoader -> PluginThreadGroup)
    // Populated when a plugin is loaded, cleared when it is unloaded.
    // -------------------------------------------------------------------------

    private static final ConcurrentHashMap<ClassLoader, PluginThreadGroup> classLoaderRegistry =
        new ConcurrentHashMap<>();

    /**
     * Register the given ClassLoader as belonging to {@code ptg}.
     * Called by {@code PluginManager} immediately after the plugin JAR is loaded.
     */
    public static void registerPlugin(ClassLoader cl, PluginThreadGroup ptg) {
        if (cl != null && ptg != null) {
            classLoaderRegistry.put(cl, ptg);
        }
    }

    /**
     * Remove the ClassLoader registration when a plugin is unloaded.
     * Called by {@code PluginManager} during plugin shutdown.
     */
    public static void unregisterPlugin(ClassLoader cl) {
        if (cl != null) {
            classLoaderRegistry.remove(cl);
        }
    }

    /** Look up which plugin owns the given ClassLoader (null if not a plugin CL). */
    public static PluginThreadGroup lookupByClassLoader(ClassLoader cl) {
        return (cl != null) ? classLoaderRegistry.get(cl) : null;
    }

    // -------------------------------------------------------------------------
    // Dispatch context (ThreadLocal) — for node threads calling plugin handlers
    // -------------------------------------------------------------------------

    private static final ThreadLocal<PluginThreadGroup> DISPATCH_CONTEXT = new ThreadLocal<>();

    /**
     * Mark the current (node) thread as executing inside the given plugin's context.
     * Must be paired with {@link #exitPluginContext()} in a try-finally block.
     */
    public static void enterPluginContext(PluginThreadGroup ptg) {
        DISPATCH_CONTEXT.set(ptg);
    }

    /** Clear the dispatch context; call in the {@code finally} block after dispatching. */
    public static void exitPluginContext() {
        DISPATCH_CONTEXT.remove();
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private final String tempDir;

    private PluginSandbox() {
        tempDir = normalize(System.getProperty("java.io.tmpdir", "/tmp"));
    }

    /**
     * Find the {@link PluginThreadGroup} for the code currently executing, using both
     * identification mechanisms (dispatch ThreadLocal first, then ThreadGroup walk).
     * Returns {@code null} if the current context is not plugin code.
     */
    private static PluginThreadGroup findPluginContext() {
        // 1. Explicit dispatch context (node thread calling into plugin)
        PluginThreadGroup ctx = DISPATCH_CONTEXT.get();
        if (ctx != null) return ctx;

        // 2. Plugin's own thread — walk up the ThreadGroup tree
        ThreadGroup tg = Thread.currentThread().getThreadGroup();
        while (tg != null) {
            if (tg instanceof PluginThreadGroup) return (PluginThreadGroup) tg;
            tg = tg.getParent();
        }
        return null;
    }

    /** Canonicalize a path for comparison; falls back to absolute path on IOException. */
    private static String normalize(String path) {
        if (path == null || path.isEmpty()) return "";
        try {
            return new File(path).getCanonicalPath();
        } catch (Exception e) {
            return new File(path).getAbsolutePath();
        }
    }

    /** Returns true if {@code path} is inside (or equal to) {@code allowedDir}. */
    private static boolean isUnder(String path, String allowedDir) {
        if (allowedDir == null || allowedDir.isEmpty()) return false;
        String p = normalize(path);
        String d = allowedDir.endsWith(File.separator)
            ? allowedDir : allowedDir + File.separator;
        return p.equals(allowedDir) || p.startsWith(d);
    }

    // -------------------------------------------------------------------------
    // SecurityManager overrides
    // -------------------------------------------------------------------------

    @Override
    public void checkPermission(Permission perm) {
        String name = perm.getName();

        // Block anyone from replacing the SecurityManager once it is installed.
        if ("setSecurityManager".equals(name)) {
            throw new SecurityException(
                "[PluginSandbox] Replacing the SecurityManager is not permitted.");
        }

        // Block plugin threads from creating ClassLoaders (sandbox-escape vector).
        if ("createClassLoader".equals(name)) {
            PluginThreadGroup ptg = findPluginContext();
            if (ptg != null) {
                throw new SecurityException(
                    "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
                    + "' attempted to create a ClassLoader — denied.");
            }
        }

        // All other permissions pass through for node code.
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        checkPermission(perm);
    }

    /** Block process spawning from plugin code. */
    @Override
    public void checkExec(String cmd) {
        PluginThreadGroup ptg = findPluginContext();
        if (ptg != null) {
            throw new SecurityException(
                "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
                + "' attempted to execute process '" + cmd + "' — denied.");
        }
    }

    /** Block native library loading from plugin code. */
    @Override
    public void checkLink(String lib) {
        PluginThreadGroup ptg = findPluginContext();
        if (ptg != null) {
            throw new SecurityException(
                "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
                + "' attempted to load native library '" + lib + "' — denied.");
        }
    }

    /** Block JVM shutdown from plugin code. */
    @Override
    public void checkExit(int status) {
        PluginThreadGroup ptg = findPluginContext();
        if (ptg != null) {
            throw new SecurityException(
                "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
                + "' attempted to call System.exit(" + status + ") — denied.");
        }
    }

    /** Restrict file writes to plugin data dir + system temp. */
    @Override
    public void checkWrite(String file) {
        PluginThreadGroup ptg = findPluginContext();
        if (ptg == null) return;

        if (isUnder(file, ptg.getPluginDataDir())) return;
        if (isUnder(file, tempDir)) return;

        throw new SecurityException(
            "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
            + "' attempted to write '" + file + "' outside allowed directories"
            + " (plugin data dir: " + ptg.getPluginDataDir() + ") — denied.");
    }

    /** Restrict file deletes to plugin data dir + system temp. */
    @Override
    public void checkDelete(String file) {
        PluginThreadGroup ptg = findPluginContext();
        if (ptg == null) return;

        if (isUnder(file, ptg.getPluginDataDir())) return;
        if (isUnder(file, tempDir)) return;

        throw new SecurityException(
            "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
            + "' attempted to delete '" + file + "' outside allowed directories — denied.");
    }

    /**
     * Network connections: logged in STANDARD mode, blocked in STRICT mode.
     * Freenet's own DHT traffic goes through internal APIs that run as node code, not plugin code,
     * so those are unaffected.
     */
    @Override
    public void checkConnect(String host, int port) {
        PluginThreadGroup ptg = findPluginContext();
        if (ptg == null) return;

        if (ptg.getSandboxLevel() == PluginSandboxLevel.STRICT) {
            throw new SecurityException(
                "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
                + "' attempted outbound connection to " + host + ":" + port
                + " (STRICT sandbox) — denied.");
        }

        // STANDARD: log and allow so existing plugins aren't broken.
        Logger.warning(PluginSandbox.class,
            "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
            + "' is opening connection to " + host + ":" + port);
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        checkConnect(host, port);
    }

    /**
     * Prevent plugin threads from modifying ThreadGroups outside their own group tree.
     * This stops a plugin from interrupting node threads or escaping to the system ThreadGroup.
     */
    @Override
    public void checkAccess(ThreadGroup g) {
        PluginThreadGroup ptg = findPluginContext();
        if (ptg == null) return;

        // Allow access to the plugin's own group or any child of it.
        ThreadGroup check = g;
        while (check != null) {
            if (check == ptg) return;
            check = check.getParent();
        }

        throw new SecurityException(
            "[PluginSandbox] Plugin '" + ptg.getPluginClassName()
            + "' attempted to access ThreadGroup '" + g.getName()
            + "' outside its own group — denied.");
    }
}
