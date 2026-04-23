package freenet.pluginmanager.sandbox;

/**
 * A {@link ThreadGroup} that marks every thread it contains as belonging to a specific plugin.
 *
 * The {@link PluginSandbox} SecurityManager identifies plugin threads by walking the ThreadGroup
 * tree from {@code Thread.currentThread().getThreadGroup()} upward; the first
 * {@code PluginThreadGroup} encountered identifies the owning plugin and its sandbox policy.
 *
 * Threads created by the plugin (e.g. via {@code new Thread(runnable)}) automatically inherit this
 * group, so they are also subject to sandbox restrictions without any extra work.
 */
public class PluginThreadGroup extends ThreadGroup {

    private final String pluginClassName;
    /** Absolute path of the directory the plugin may read/write freely. */
    private final String pluginDataDir;
    private final PluginSandboxLevel sandboxLevel;

    public PluginThreadGroup(ThreadGroup parent, String pluginClassName,
                             String pluginDataDir, PluginSandboxLevel sandboxLevel) {
        super(parent, "plugin-" + pluginClassName);
        this.pluginClassName = pluginClassName;
        this.pluginDataDir = pluginDataDir;
        this.sandboxLevel = sandboxLevel;
    }

    public String getPluginClassName() {
        return pluginClassName;
    }

    public String getPluginDataDir() {
        return pluginDataDir;
    }

    public PluginSandboxLevel getSandboxLevel() {
        return sandboxLevel;
    }
}
