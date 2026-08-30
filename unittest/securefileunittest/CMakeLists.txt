ENABLE_TESTING()

set(securefileunittest_bin_SRCS securefileunittest.cpp)

add_executable(securefileunittest ${securefileunittest_bin_SRCS})
target_link_qca_test_libraries(securefileunittest)

add_qca_test(securefileunittest "SecureFile")
