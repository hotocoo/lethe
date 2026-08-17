
#include <gtest/gtest.h>
#include "core/engine.h"
#include "config.h"

TEST(EngineTest, InitializeAndShutdown) {
    lethe::Config cfg;
    cfg.incognitoMode = true;
    
    lethe::Engine engine;
    EXPECT_EQ(engine.initialize(cfg), 0);
    engine.shutdown();
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
