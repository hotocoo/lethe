#ifndef LETHE_SECURITY_SANDBOX_H
#define LETHE_SECURITY_SANDBOX_H

namespace lethe {

// Process sandboxing via seccomp-bpf (Linux), pledge/unveil (OpenBSD), 
// or JobControls (macOS) depending on platform.
class Sandbox {
public:
    // Apply strict syscall restrictions for renderer
    static bool apply();
    
    // Restrict filesystem access to specified dirs
    static bool restrictFS(const std::string& dirs);
};

} // namespace lethe

#endif // LETHE_SECURITY_SANDBOX_H
