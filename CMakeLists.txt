cmake_minimum_required(VERSION 3.25)

# Load the IDA SDK bootstrap (requires the IDASDK environment variable)
include("$ENV{IDASDK}/src/cmake/idasdk_init.cmake")

project(diaphora-ng-idafree C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(idasdk REQUIRED)

# static CRT (/MT). Not IDA_USE_STATIC_RUNTIME: the SDK's x64_win_64_s libs
# ship no ida.lib. ida.lib is only an import library, so it works with /MT.
# Must come after find_package (which sets /MD) and before ida_add_plugin.
option(DPH_STATIC_CRT "Link the MSVC runtime statically (/MT)" OFF)
if(MSVC AND DPH_STATIC_CRT)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(DIAPHORA_SOURCES
    src/common.hpp
    src/config.hpp
    src/util.cpp
    src/db.hpp
    src/db.cpp
    src/difflib.hpp
    src/difflib.cpp
    src/algorithms.hpp
    src/algorithms.cpp
    src/heuristics.hpp
    src/heuristics.cpp
    src/heuristics_data.inc
    src/bindiff.hpp
    src/bindiff_impl.hpp
    src/bindiff.cpp
    src/exporter.cpp
    src/compunits.hpp
    src/compunits.cpp
    src/differ.cpp
    src/vulns.hpp
    src/vulns.cpp
    src/results.hpp
    src/results.cpp
    src/importer.cpp
    src/ui.hpp
    src/ui.cpp
    src/clauderays_link.hpp
    src/clauderays_link.cpp
    src/claude_diff.hpp
    src/claude_diff.cpp
    src/ghidradec_link.hpp
    src/ghidradec_link.cpp
    src/ghidra_diff.hpp
    src/ghidra_diff.cpp
    src/commands.cpp
    src/plugin.cpp
)

# SQLite: use the amalgamation if it was dropped in third_party/sqlite,
# otherwise the system winsqlite3.dll shipped with Windows 10/11.
set(SQLITE_AMALGAMATION "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite/sqlite3.c")
if(EXISTS "${SQLITE_AMALGAMATION}")
    message(STATUS "diaphora-ng: using the SQLite amalgamation in third_party/sqlite")
    set(DIAPHORA_SQLITE_SOURCES "${SQLITE_AMALGAMATION}")
    set(DIAPHORA_SQLITE_DEFINES SQLITE_THREADSAFE=1 SQLITE_DEFAULT_FOREIGN_KEYS=0)
    set(DIAPHORA_SQLITE_LIBS "")
    set(DIAPHORA_SQLITE_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite")
elseif(WIN32)
    message(STATUS "diaphora-ng: using the system winsqlite3.dll")
    set(DIAPHORA_SQLITE_SOURCES "")
    set(DIAPHORA_SQLITE_DEFINES DIAPHORA_USE_WINSQLITE)
    set(DIAPHORA_SQLITE_LIBS winsqlite3)
    set(DIAPHORA_SQLITE_INCLUDES "")
else()
    find_package(SQLite3 REQUIRED)
    set(DIAPHORA_SQLITE_SOURCES "")
    set(DIAPHORA_SQLITE_DEFINES "")
    set(DIAPHORA_SQLITE_LIBS SQLite::SQLite3)
    set(DIAPHORA_SQLITE_INCLUDES "")
endif()

# installed as diaphora-ng.dll, so it can live next to diaphora.dll (diaphora-idafree)
ida_add_plugin(diaphora-ng-idafree
    OUTPUT_NAME diaphora-ng
    SOURCES
        ${DIAPHORA_SOURCES}
        ${DIAPHORA_SQLITE_SOURCES}
    DEFINES
        ${DIAPHORA_SQLITE_DEFINES}
    LIBRARIES
        ${DIAPHORA_SQLITE_LIBS}
)

# build into <project>/bin instead of the SDK's bin/plugins, next to the sources
set_target_properties(diaphora-ng-idafree PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

if(DIAPHORA_SQLITE_INCLUDES)
    target_include_directories(diaphora-ng-idafree PRIVATE ${DIAPHORA_SQLITE_INCLUDES})
endif()

if(MSVC)
    # big translation units (heuristics SQL strings)
    target_compile_options(diaphora-ng-idafree PRIVATE /bigobj)
endif()
