add_executable(wincryptounittest wincryptounittest.cpp ../../plugins/qca-wincrypto/aesmodes.cpp)
target_include_directories(wincryptounittest PRIVATE ../../plugins/qca-wincrypto)
target_link_qca_test_libraries(wincryptounittest)
add_dependencies(wincryptounittest qca-wincrypto)
add_qca_test(wincryptounittest "WinCrypto")
set_tests_properties(WinCrypto PROPERTIES TIMEOUT 60 ENVIRONMENT
  "QCA_PLUGIN_PATH=${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME};QT_FORCE_STDERR_LOGGING=1")

add_executable(wincryptorsaunittest wincryptorsaunittest.cpp)
target_link_qca_test_libraries(wincryptorsaunittest)
add_dependencies(wincryptorsaunittest qca-wincrypto)
add_qca_test(wincryptorsaunittest "WinCryptoRSA")
set_tests_properties(WinCryptoRSA PROPERTIES TIMEOUT 90 ENVIRONMENT
  "QCA_PLUGIN_PATH=${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME};QT_FORCE_STDERR_LOGGING=1")

add_executable(wincryptotlsunittest wincryptotlsunittest.cpp)
target_link_qca_test_libraries(wincryptotlsunittest)
target_link_libraries(wincryptotlsunittest crypt32 secur32 advapi32)
add_dependencies(wincryptotlsunittest qca-wincrypto)
add_qca_test(wincryptotlsunittest "WinCryptoTLS")
set_tests_properties(WinCryptoTLS PROPERTIES TIMEOUT 60 ENVIRONMENT
  "QCA_PLUGIN_PATH=${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME};QT_FORCE_STDERR_LOGGING=1")

add_executable(wincryptodtlsunittest wincryptodtlsunittest.cpp)
target_link_qca_test_libraries(wincryptodtlsunittest)
target_link_libraries(wincryptodtlsunittest ncrypt)
add_dependencies(wincryptodtlsunittest qca-wincrypto)
add_qca_test(wincryptodtlsunittest "WinCryptoDTLS")
set_tests_properties(WinCryptoDTLS PROPERTIES TIMEOUT 60 ENVIRONMENT
  "QCA_PLUGIN_PATH=${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME};QT_FORCE_STDERR_LOGGING=1")

option(WINCRYPTO_TEST_OPENSSL_INTEROP "Test native DTLS and RSA against an independent OpenSSL peer" OFF)
if(WINCRYPTO_TEST_OPENSSL_INTEROP)
  find_package(OpenSSL REQUIRED)
  add_executable(wincryptoopensslunittest wincryptoopensslunittest.cpp)
  target_link_qca_test_libraries(wincryptoopensslunittest)
  target_link_libraries(wincryptoopensslunittest OpenSSL::SSL OpenSSL::Crypto ws2_32 crypt32)
  add_dependencies(wincryptoopensslunittest qca-wincrypto)
  add_qca_test(wincryptoopensslunittest "WinCryptoOpenSSL")
  set_tests_properties(WinCryptoOpenSSL PROPERTIES TIMEOUT 60 ENVIRONMENT
    "QCA_PLUGIN_PATH=${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME};QT_FORCE_STDERR_LOGGING=1")
endif()
