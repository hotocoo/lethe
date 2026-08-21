#ifndef LETHE_TESTS_TEST_FRAMEWORK_H
#define LETHE_TESTS_TEST_FRAMEWORK_H

// test_framework.h — Lightweight test harness for Lethe (no external deps)
//
// A minimal test framework that provides TEST_CASE, CHECK, CHECK_EQ, etc.
// so we don't need GTest. Tracks pass/fail and prints a summary.

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>

namespace lethe {
namespace test {

// Exception thrown when a test check fails.
class TestFailure : public std::runtime_error {
public:
    explicit TestFailure(const std::string& msg) : std::runtime_error(msg) {}
};

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

class Registry {
public:
    static Registry& instance() {
        static Registry reg;
        return reg;
    }

    void add(const std::string& name, std::function<void()> fn) {
        tests_.push_back({name, std::move(fn)});
    }

    int runAll() {
        int passed = 0;
        int failed = 0;
        std::vector<std::string> failures;

        std::cout << "Running " << tests_.size() << " test cases..." << std::endl;
        std::cout << "========================================" << std::endl;

        for (const auto& tc : tests_) {
            bool ok = true;
            std::string errorMsg;
            try {
                tc.fn();
            } catch (const TestFailure& e) {
                ok = false;
                errorMsg = e.what();
            } catch (const std::exception& e) {
                ok = false;
                errorMsg = std::string("Exception: ") + e.what();
            }

            if (ok) {
                std::cout << "  [PASS] " << tc.name << std::endl;
                passed++;
            } else {
                std::cout << "  [FAIL] " << tc.name << std::endl;
                if (!errorMsg.empty()) {
                    std::cout << "         " << errorMsg << std::endl;
                }
                failures.push_back(tc.name);
                failed++;
            }
        }

        std::cout << "========================================" << std::endl;
        std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;

        if (!failures.empty()) {
            std::cout << "Failed tests:" << std::endl;
            for (const auto& f : failures) {
                std::cout << "  - " << f << std::endl;
            }
        }

        return failed == 0 ? 0 : 1;
    }

private:
    std::vector<TestCase> tests_;
};

struct Registrar {
    Registrar(const std::string& name, std::function<void()> fn) {
        Registry::instance().add(name, std::move(fn));
    }
};

} // namespace test
} // namespace lethe

// Helper to build error messages
static inline std::string lethe_test_error(const char* check, const char* file, int line) {
    return std::string(check) + " at " + file + ":" + std::to_string(line);
}

// Macros
#define LETHE_TEST_CASE(name) \
    static void lethe_test_fn_##name(); \
    static lethe::test::Registrar lethe_test_reg_##name(#name, lethe_test_fn_##name); \
    static void lethe_test_fn_##name()

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            throw lethe::test::TestFailure(lethe_test_error("CHECK failed: " #cond, __FILE__, __LINE__)); \
        } \
    } while (0)

#define CHECK_EQ(a, b) \
    do { \
        auto _va = (a); \
        auto _vb = (b); \
        if (!(_va == _vb)) { \
            throw lethe::test::TestFailure(lethe_test_error("CHECK_EQ failed: " #a " == " #b, __FILE__, __LINE__)); \
        } \
    } while (0)

#define CHECK_NE(a, b) \
    do { \
        auto _va = (a); \
        auto _vb = (b); \
        if (_va == _vb) { \
            throw lethe::test::TestFailure(lethe_test_error("CHECK_NE failed: " #a " != " #b, __FILE__, __LINE__)); \
        } \
    } while (0)

#define CHECK_GE(a, b) \
    do { \
        auto _va = (a); \
        auto _vb = (b); \
        if (!(_va >= _vb)) { \
            throw lethe::test::TestFailure(lethe_test_error("CHECK_GE failed: " #a " >= " #b, __FILE__, __LINE__)); \
        } \
    } while (0)

#define CHECK_LT(a, b) \
    do { \
        auto _va = (a); \
        auto _vb = (b); \
        if (!(_va < _vb)) { \
            throw lethe::test::TestFailure(lethe_test_error("CHECK_LT failed: " #a " < " #b, __FILE__, __LINE__)); \
        } \
    } while (0)

#define CHECK_TRUE(cond) CHECK(cond)
#define CHECK_FALSE(cond) CHECK(!(cond))

#endif // LETHE_TESTS_TEST_FRAMEWORK_H

