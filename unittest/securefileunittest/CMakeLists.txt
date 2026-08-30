ENABLE_TESTING()

set(securefileunittest_bin_SRCS securefileunittest.cpp)

add_executable(securefileunittest ${securefileunittest_bin_SRCS})
target_link_qca_test_libraries(securefileunittest)

add_test(NAME "SecureFile"
         WORKING_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
         COMMAND securefileunittest -v2)
set_tests_properties("SecureFile" PROPERTIES
                     ENVIRONMENT "QCA_PLUGIN_PATH=${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME}")
