// shell_bootstrap.h - command line, engine, DoH pool and policy proxy start-up
// shared by the native shells. Each shell's main() calls init(), then hands
// the ShellContext to its UI, then shutdown() on the way out.
#ifndef LETHE_BROWSER_APP_SHELL_BOOTSTRAP_H
#define LETHE_BROWSER_APP_SHELL_BOOTSTRAP_H

#include <string>

#include "browser/shell_context.h"
#include "core/engine.h"
#include "network/policy_proxy.h"
#include "network/tls_config.h"

namespace lethe {

struct ShellBootstrap {
    Engine engine;
    PolicyProxyServer proxy;
    ShellContext ctx;
    bool useProxy = true;

    // Parses argv, applies environment overrides, starts the engine and the
    // policy proxy (fail-closed). Returns -1 when the shell should run, or
    // the process exit code when it should stop (--help/--version/error).
    // |engineName| is printed by --version, e.g. "Chromium 151.0.7922.174".
    int init(int argc, char** argv, const std::string& engineName);

    // Stops the proxy and the engine. Idempotent.
    void shutdown();

private:
    bool shutDown_ = false;
};

} // namespace lethe

#endif // LETHE_BROWSER_APP_SHELL_BOOTSTRAP_H
