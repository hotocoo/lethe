// test_main.cc — Lethe test suite entry point
//
// Runs all Lethe tests using the lightweight test framework.

#include "test_framework.h"
#include <iostream>

int main(int argc, char** argv) {
    std::cout << "Lethe Test Suite" << std::endl;
    std::cout << "================" << std::endl;

    std::string filter;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--filter" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg.rfind("--filter=", 0) == 0) {
            filter = arg.substr(9);
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: lethe_tests [--filter <substring>]" << std::endl;
            return 0;
        }
    }

    return lethe::test::Registry::instance().runAll(filter);
}
