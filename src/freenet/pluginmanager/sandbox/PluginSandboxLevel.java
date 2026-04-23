package freenet.pluginmanager.sandbox;

/**
 * Defines how strictly a plugin is sandboxed.
 *
 * <ul>
 *   <li>{@link #STANDARD} — Blocks the most dangerous operations (exec, native libs, JVM exit,
 *       writes outside the plugin data dir) and logs outbound network connections.
 *       Used for official plugins that are trusted but still should not escape the JVM.</li>
 *   <li>{@link #STRICT} — Everything in STANDARD, plus outbound network connections are blocked
 *       entirely. Intended for unofficial / third-party plugins whose origin is unknown.</li>
 * </ul>
 */
public enum PluginSandboxLevel {
    STANDARD,
    STRICT
}
