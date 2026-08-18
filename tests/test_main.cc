// test_main.cc — Lethe test suite entry point
//
// Runs all Lethe tests using the lightweight test framework.

#include "test_framework.h"
#include <iostream>

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    std::cout << "Lethe Test Suite" << std::endl;
    std::cout << "================" << std::endl;

    return lethe::test::Registry::instance().runAll();
}

