#ifndef LETHE_SECURITY_SANDBOX_H
#define LETHE_SECURITY_SANDBOX_H

#include <string>
#include <vector>

namespace lethe {

class Sandbox {
public:
    static bool apply();
    static bool restrictFS(const std::vector<std::string>& dirs);
    static bool restrictNetwork(bool allow);
    static bool restrictSyscalls(const std::vector<int>& syscalls);
};

} // namespace lethe

#endif // LETHE_SECURITY_SANDBOX_H