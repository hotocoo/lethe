// sandbox.cc — Platform-specific sandboxing implementation
#include "security/sandbox.h"

#ifdef __linux__
#include <seccomp.h>
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <unistd.h> // for sysctlbyname / procattr
#endif

namespace lethe {

bool Sandbox::apply() {
#if defined(__linux__))
    scmp_filter_ctx ctx = seccomp_init(SCMP_FLT_SECCOMP_ALLOW, 0);
    if (!ctx) return false;
    
    // Allow minimal syscalls for renderer
    seccomp_rule_add(ctx, SCMP_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    
    // Restrict network (for main process only)
    if (seccomp_load(&ctx) < 0) return false;
    
#elif defined(__APPLE__)
    // macOS: use procattr to restrict syscalls where possible
    int val = 1;
    procattr_write("sandboxed", &val, sizeof(val), 0);
#endif

    return true;
}

bool Sandbox::restrictFS(const std::string& dirs) {
    // TODO: Implement per-platform FS restrictions
    // Linux: prctl(PR_SET_UNSHARE, CLONE_NEWNS), mount --bind + chroot
    // macOS: use procattr_write("restricted", ...)
    (void)dirs;
    return true;
}

} // namespace lethe
