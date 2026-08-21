if(WITH_cyrus-sasl_PLUGIN STREQUAL "yes")
  find_package(Sasl2 REQUIRED)
else()
  find_package(Sasl2)
endif()

if(SASL2_FOUND)
  enable_plugin("cyrus-sasl")

  include(CheckSymbolExists)
  include(CMakePushCheckState)
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_INCLUDES ${SASL2_INCLUDE_DIR})
  check_symbol_exists(SASL_CHANNEL_BINDING "sasl/sasl.h" HAVE_SASL_CHANNEL_BINDING)
  check_symbol_exists(SASL_BADBINDING "sasl/sasl.h" HAVE_SASL_BADBINDING)
  cmake_pop_check_state()

  set(QCA_SASL_SOURCES qca-cyrus-sasl.cpp)
  add_library(qca-cyrus-sasl ${PLUGIN_TYPE} ${QCA_SASL_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-cyrus-sasl PROPERTY SUFFIX ".dylib")
  endif()

  target_link_libraries(qca-cyrus-sasl Qt${QT_MAJOR_VERSION}::Core ${QCA_LIB_NAME} Sasl2::Sasl2)

  # Our Windows/macOS/Android dependency bundles contain a PIC static
  # libsasl2 with PLAIN, SCRAM and DIGEST-MD5 built in. Those mechanisms
  # use libcrypto, so resolve it in the final QCA plugin rather than making
  # libsasl2 another runtime dependency.
  if(SASL2_STATIC)
    include(QcaOpenSSL)
    qca_find_openssl(REQUIRED)
    target_link_libraries(qca-cyrus-sasl OpenSSL::Crypto)
    if(WIN32)
      # Cyrus' public Windows headers otherwise declare the API dllimport.
      # The private dependency bundle is a real static library.
      target_compile_definitions(qca-cyrus-sasl PRIVATE WIN32 LIBSASL_EXPORTS)
    endif()
  endif()
  if(HAVE_SASL_CHANNEL_BINDING AND HAVE_SASL_BADBINDING)
    target_compile_definitions(qca-cyrus-sasl PRIVATE HAVE_SASL_CHANNEL_BINDING)
  endif()

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-cyrus-sasl
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-cyrus-sasl ${QCA_CRYPTO_INSTALL_DIR})
  endif()
else()
  disable_plugin("cyrus-sasl")
endif()
