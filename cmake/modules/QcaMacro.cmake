
MACRO(SETUP_QT5_DIRS)
  GET_TARGET_PROPERTY(QMAKE_EXECUTABLE ${Qt5Core_QMAKE_EXECUTABLE} LOCATION)
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_LIBS" OUTPUT_VARIABLE QT_LIBRARY_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_PREFIX" OUTPUT_VARIABLE QT_PREFIX_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_PLUGINS" OUTPUT_VARIABLE QT_PLUGINS_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_BINS" OUTPUT_VARIABLE QT_BINARY_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_HEADERS" OUTPUT_VARIABLE QT_HEADERS_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_DOCS" OUTPUT_VARIABLE QT_DOC_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_DATA" OUTPUT_VARIABLE QT_DATA_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_HOST_DATA" OUTPUT_VARIABLE QT_ARCHDATA_DIR )
  SET( QT_MKSPECS_DIR "${QT_ARCHDATA_DIR}/mkspecs" )
ENDMACRO(SETUP_QT5_DIRS)

# from msys2 mingw patches
if(MINGW)
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_LIBRARY_DIR}" OUTPUT_VARIABLE QT_LIBRARY_DIR )
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_PREFIX_DIR}" OUTPUT_VARIABLE QT_PREFIX_DIR )
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_PLUGINS_DIR}" OUTPUT_VARIABLE QT_PLUGINS_DIR )
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_BINARY_DIR}" OUTPUT_VARIABLE QT_BINARY_DIR )
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_HEADERS_DIR}" OUTPUT_VARIABLE QT_HEADERS_DIR )
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_DOC_DIR}" OUTPUT_VARIABLE QT_DOC_DIR )
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_DATA_DIR}" OUTPUT_VARIABLE QT_DATA_DIR )
  EXEC_PROGRAM( "cygpath" ARGS "-u ${QT_ARCHDATA_DIR}" OUTPUT_VARIABLE QT_ARCHDATA_DIR )
endif()

macro(set_enabled_plugin PLUGIN ENABLED)
  # To nice looks
  if(ENABLED)
    set(ENABLED "on")
  else()
    set(ENABLED "off")
  endif()
  set(WITH_${PLUGIN}_PLUGIN_INTERNAL ${ENABLED} CACHE INTERNAL "")
endmacro(set_enabled_plugin)

macro(enable_plugin PLUGIN)
  set_enabled_plugin(${PLUGIN} "on")
endmacro(enable_plugin)

macro(disable_plugin PLUGIN)
  set_enabled_plugin(${PLUGIN} "off")
endmacro(disable_plugin)

# it used to build examples and tools
macro(target_link_qca_libraries TARGET)
  # Link with QCA library
  target_link_libraries(${TARGET} ${QCA_LIB_NAME})

  # Statically link with all enabled QCA plugins
  if(STATIC_PLUGINS)
    target_link_libraries(${TARGET} ${QT_QTCORE_LIB_DEPENDENCIES})
    foreach(PLUGIN IN LISTS PLUGINS)
      # Check plugin for enabled
      if(WITH_${PLUGIN}_PLUGIN_INTERNAL)
        target_link_libraries(${TARGET} qca-${PLUGIN})
      endif()
    endforeach(PLUGIN)
  endif()
endmacro(target_link_qca_libraries)

# it used to build unittests
macro(target_link_qca_test_libraries TARGET)
  target_link_qca_libraries(${TARGET})
  target_link_libraries(${TARGET} Qt5::Test)
endmacro(target_link_qca_test_libraries)

# it used to build unittests
macro(add_qca_test TARGET DESCRIPTION)
  add_test(NAME "${DESCRIPTION}"
           WORKING_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
           COMMAND "${TARGET}")
endmacro(add_qca_test)

macro(install_pdb TARGET INSTALL_PATH)
  if(MSVC AND BUILD_SHARED_LIBS)
    install(FILES $<TARGET_PDB_FILE:${TARGET}> DESTINATION ${INSTALL_PATH} CONFIGURATIONS Debug)
    install(FILES $<TARGET_PDB_FILE:${TARGET}> DESTINATION ${INSTALL_PATH} CONFIGURATIONS RelWithDebInfo)
  endif()
endmacro(install_pdb)

macro(normalize_path PATH)
  get_filename_component(${PATH} "${${PATH}}" ABSOLUTE)
  # Strip trailing slashes
  string(REGEX REPLACE "/+$" "" PATH ${PATH})
endmacro()
