// sandbox.cc - Platform-specific sandboxing implementation
//
// Real, enforced sandboxing for the engine process:
//   - macOS: Seatbelt profile via sandbox_init(). Default-allow with an
//     explicit DENY on file writes outside temp locations: a compromised
//     engine cannot persist malware, touch user documents, or tamper with
//     dotfiles, while networking and reads keep working.
//   - Linux: seccomp-bpf default-DENY filter with an explicit syscall
//     allowlist sized for a networked browser engine.

#include <cstdlib>
#include <iostream>
#include <string>
#include "security/sandbox.h"

#ifdef __linux__
#include <errno.h>
#include <seccomp.h>
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <sandbox.h>
#endif

namespace lethe {

namespace {

#if defined(__APPLE__)
// Deny-by-default for the highest-risk dimension (filesystem writes) while
// keeping everything else working in a single-process engine.
// Beyond temp locations, the browser shell may write ONLY to the user's
// Downloads folder (saved files) and its own per-bundle Library subtrees
// (WebKit caches/storage for the persistent profile, window-state
// restore). Documents, dotfiles and every other app's data stay closed.
std::string seatbeltProfile() {
    std::string profile =
        "(version 1)\n"
        "(allow default)\n"
        "(deny file-write*)\n"
        "(allow file-write*\n"
        "  (subpath \"/private/tmp\")\n"
        "  (subpath \"/var/tmp\")\n"
        "  (regex #\"^/private/var/folders/\")\n"
        "  (regex #\"^/var/folders/\")\n";
    const char* home = std::getenv("HOME");
    if (home && *home && std::string(home).find('"') == std::string::npos) {
        const std::string h(home);
        const char* const kBundle = "org.aletheia.lethe";
        const std::string paths[] = {
            h + "/Downloads",
            h + "/Library/Caches/" + kBundle,
            h + "/Library/WebKit/" + kBundle,
            h + "/Library/HTTPStorages/" + kBundle,
            h + "/Library/Saved Application State/" + kBundle + ".savedState",
            // CEF helper data: chromium's process singleton + crashpad + cef cache
            h + "/Library/Application Support/Lethe CEF",
            h + "/Library/Caches/Lethe CEF",
        };
        for (const auto& p : paths) profile += "  (subpath \"" + p + "\")\n";
    }
    profile += ")\n";
    return profile;
}
#endif

#if defined(__linux__) && defined(LETHE_SANDBOXING)
// Syscalls a networked browser engine needs. Everything else gets EPERM.
const int kAllowedSyscalls[] = {
    // Process / thread lifecycle
    SCMP_SYS(exit), SCMP_SYS(exit_group), SCMP_SYS(rt_sigreturn),
    SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(futex),
    SCMP_SYS(clone), SCMP_SYS(clone3), SCMP_SYS(getpid), SCMP_SYS(gettid),
    SCMP_SYS(getppid), SCMP_SYS(sched_getaffinity), SCMP_SYS(sched_yield),
    SCMP_SYS(prctl), SCMP_SYS(madvise), SCMP_SYS(mincore), SCMP_SYS(rseq),
    SCMP_SYS(membarrier), SCMP_SYS(sigaltstack),
    // Memory
    SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mprotect), SCMP_SYS(brk),
    // File descriptors / IO multiplexing
    SCMP_SYS(read), SCMP_SYS(readv), SCMP_SYS(write), SCMP_SYS(writev),
    SCMP_SYS(close), SCMP_SYS(close_range), SCMP_SYS(fcntl), SCMP_SYS(dup),
    SCMP_SYS(dup2), SCMP_SYS(dup3), SCMP_SYS(ioctl), SCMP_SYS(poll),
    SCMP_SYS(ppoll), SCMP_SYS(select), SCMP_SYS(pselect6), SCMP_SYS(lseek),
    SCMP_SYS(pipe), SCMP_SYS(pipe2), SCMP_SYS(socketpair),
    SCMP_SYS(epoll_create1), SCMP_SYS(epoll_ctl), SCMP_SYS(epoll_wait),
    SCMP_SYS(epoll_pwait), SCMP_SYS(eventfd2),
    // Filesystem access (path-based)
    SCMP_SYS(openat), SCMP_SYS(openat2), SCMP_SYS(statx),
    SCMP_SYS(newfstatat), SCMP_SYS(faccessat), SCMP_SYS(faccessat2),
    SCMP_SYS(getcwd), SCMP_SYS(readlink), SCMP_SYS(readlinkat),
    SCMP_SYS(getdents64), SCMP_SYS(unlink), SCMP_SYS(unlinkat),
    SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(rename), SCMP_SYS(renameat),
    SCMP_SYS(renameat2),
    // Networking
    SCMP_SYS(socket), SCMP_SYS(connect), SCMP_SYS(bind), SCMP_SYS(listen),
    SCMP_SYS(accept), SCMP_SYS(accept4), SCMP_SYS(sendto), SCMP_SYS(recvfrom),
    SCMP_SYS(sendmsg), SCMP_SYS(recvmsg), SCMP_SYS(shutdown),
    SCMP_SYS(getsockname), SCMP_SYS(getpeername), SCMP_SYS(setsockopt),
    SCMP_SYS(getsockopt),
    // Time / clocks / randomness
    SCMP_SYS(clock_gettime), SCMP_SYS(clock_nanosleep), SCMP_SYS(nanosleep),
    SCMP_SYS(gettimeofday), SCMP_SYS(time), SCMP_SYS(clock_getres),
    SCMP_SYS(getrandom),
    // System info / limits / signals
    SCMP_SYS(uname), SCMP_SYS(sysinfo), SCMP_SYS(getrusage), SCMP_SYS(wait4),
    SCMP_SYS(kill), SCMP_SYS(tgkill), SCMP_SYS(getuid), SCMP_SYS(geteuid),
    SCMP_SYS(getgid), SCMP_SYS(getegid), SCMP_SYS(getresuid),
    SCMP_SYS(getresgid), SCMP_SYS(getgroups), SCMP_SYS(prlimit64),
    SCMP_SYS(getrlimit), SCMP_SYS(setrlimit), SCMP_SYS(seccomp),
};

bool applySeccompAllowlist() {
    // Default-deny: every unlisted syscall returns EPERM.
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx) {
        std::cerr << "[lethe] Failed to create seccomp context" << std::endl;
        return false;
    }

    size_t allowed = 0;
    for (int sys : kAllowedSyscalls) {
        // Ignore failures for syscalls unknown to the running kernel's
        // libseccomp: they would fail anyway under default-deny.
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sys, 0) == 0) {
            allowed++;
        }
    }

    // No new privileges: even a setuid exec cannot escape the filter.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        std::cerr << "[lethe] PR_SET_NO_NEW_PRIVS failed" << std::endl;
        seccomp_release(ctx);
        return false;
    }

    if (seccomp_load(ctx) != 0) {
        std::cerr << "[lethe] Failed to load seccomp filter" << std::endl;
        seccomp_release(ctx);
        return false;
    }
    seccomp_release(ctx);

    std::cout << "[lethe] Seccomp allowlist active (" << allowed
              << " syscalls permitted)" << std::endl;
    return true;
}
#endif

} // namespace

bool Sandbox::apply() {
#if defined(__linux__) && defined(LETHE_SANDBOXING)
    std::cout << "[lethe] Applying Linux sandbox (seccomp-bpf, default-deny)..."
              << std::endl;
    return applySeccompAllowlist();

#elif defined(__APPLE__) && defined(LETHE_SANDBOXING)
    // Seatbelt is once-per-process: a second sandbox_init inside an already
    // sandboxed process fails with EPERM (observed on locked-down hosts and
    // GitHub runners). Re-application is a no-op success by definition -
    // the profile is already active.
    static bool alreadyApplied = false;
    if (alreadyApplied) {
        return true;
    }
    std::cout << "[lethe] Applying macOS sandbox (Seatbelt)..." << std::endl;

    // The Seatbelt API is deprecated but remains the only supported way to
    // apply a sandbox profile to an already-running, non-app-bundle process.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    char* errorbuf = nullptr;
    // flags = 0: compile the profile TEXT (SANDBOX_NAMED would treat the
    // string as the name of a system-installed profile instead).
    const std::string profile = seatbeltProfile();
    if (::sandbox_init(profile.c_str(), 0, &errorbuf) != 0) {
        std::cerr << "[lethe] sandbox_init failed: "
                  << (errorbuf ? errorbuf : "unknown error") << std::endl;
        if (errorbuf) ::sandbox_free_error(errorbuf);
        return false;
    }
#pragma clang diagnostic pop
    alreadyApplied = true;
    std::cout << "[lethe] Seatbelt profile active (file writes limited to temp, "
                 "~/Downloads and Lethe's own Library subtrees)"
              << std::endl;
    return true;

#else
    // Sandbox support not compiled in.
    return true;
#endif
}

bool Sandbox::restrictFS(const std::vector<std::string>& dirs) {
    // Post-apply restriction changes are not supported by either backend:
    // policies are fixed at apply() time by design (no runtime escape hatch).
    (void)dirs;
    std::cerr << "[lethe] restrictFS is fixed at apply() time; ignoring" << std::endl;
    return false;
}

bool Sandbox::restrictNetwork(bool allow) {
    (void)allow;
    std::cerr << "[lethe] restrictNetwork is fixed at apply() time; ignoring" << std::endl;
    return false;
}

bool Sandbox::restrictSyscalls(const std::vector<int>& syscalls) {
    (void)syscalls;
    std::cerr << "[lethe] restrictSyscalls is fixed at apply() time; ignoring" << std::endl;
    return false;
}

} // namespace lethe
