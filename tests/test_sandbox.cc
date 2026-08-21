// test_sandbox.cc — Sandbox enforcement tests
//
// The macOS Seatbelt profile denies file writes outside temp locations.
// These probes verify the policy actually bites (and that temp still works).
// On platforms without sandbox support the checks degrade to no-ops.

#include "test_framework.h"
#include "security/sandbox.h"

#include <cstdio>
#include <string>

using namespace lethe;

LETHE_TEST_CASE(Sandbox_FileWritePolicy_Enforced) {
#if defined(__APPLE__) && defined(LETHE_SANDBOXING)
    // Apply (or re-apply) so this test is order-independent.
    CHECK_TRUE(Sandbox::apply());

    // 1. Writing into the repo workspace must be DENIED by the profile.
    const std::string probe = "/Users/acotech/workspace/lethe/.sandbox_write_probe";
    FILE* bad = fopen(probe.c_str(), "w");
    if (bad) {
        // If it opened, the sandbox is NOT active: fail loudly and clean up.
        fclose(bad);
        ::remove(probe.c_str());
        CHECK_TRUE(!"sandbox did not deny a workspace write");
    }

    // 2. Writing into temp must still WORK.
    FILE* ok = fopen("/tmp/lethe_sandbox_probe", "w");
    CHECK_TRUE(ok != nullptr);
    if (ok) {
        fputs("ok", ok);
        fclose(ok);
    }
    ::remove("/tmp/lethe_sandbox_probe");
#else
    // No enforceable backend on this platform/configuration.
    CHECK_TRUE(true);
#endif
}

LETHE_TEST_CASE(Sandbox_RestrictionAPI_HonestAboutFixedPolicies) {
    // Runtime restriction changes are rejected rather than silently ignored.
    CHECK_FALSE(Sandbox::restrictFS({"/some/dir"}));
    CHECK_FALSE(Sandbox::restrictNetwork(false));
    CHECK_FALSE(Sandbox::restrictSyscalls({999}));
}
