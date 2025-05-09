# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

cmake_minimum_required(VERSION 3.0.2...4.0)
project("Redex")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules" ${CMAKE_MODULE_PATH})
include(Commons)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

if(NOT BUILD_TYPE)
    set(BUILD_TYPE Shared)
endif ()
if (MINGW)
    set(BUILD_TYPE Static)
endif ()

if(BUILD_TYPE STREQUAL Static)
    set(ENABLE_STATIC ON CACHE BOOL "" FORCE)
    if (MINGW)
        set(STATIC_LINK_FLAG "-static")
    else (MINGW)
        set(STATIC_LINK_FLAG "")
    endif (MINGW)
elseif (BUILD_TYPE STREQUAL Shared)
    set(ENABLE_STATIC OFF CACHE BOOL "" FORCE)
    set(STATIC_LINK_FLAG "")
endif ()

set_common_cxx_flags_for_redex()
add_dependent_packages_for_redex()

file(GLOB includes
        "analysis"
        "libredex"
        "service/*"
        "opt/*"
        "util"
        "liblocator"
        "libresource"
        "shared"
        "sparta/include"
        "tools/common"
        )

include_directories(
        ${Boost_INCLUDE_DIRS}
        ${JSONCPP_INCLUDE_DIRS}
        ${ZLIB_INCLUDE_DIRS}
        ${includes})

install(DIRECTORY libredex util libresource shared service
        DESTINATION include/redex
        FILES_MATCHING PATTERN "*.h" PATTERN "*.def")
install(DIRECTORY sparta/include/
        DESTINATION include/redex/sparta
        FILES_MATCHING PATTERN "*.h")
install(DIRECTORY tools/common tools/tool
        DESTINATION include/redex/tools
        FILES_MATCHING PATTERN "*.h")

file(GLOB_RECURSE redex_srcs
        "analysis/max-depth/*.cpp"
        "analysis/max-depth/*.h"
        "analysis/ip-reflection-analysis/*.cpp"
        "analysis/ip-reflection-analysis/*.h"
        "libredex/*.cpp"
        "libredex/*.h"
        "service/*.cpp"
        "service/*.h"
        "opt/*.cpp"
        "opt/*.h"
        "util/CommandProfiling.cpp"
        "util/CommandProfiling.h"
        "util/JemallocUtil.cpp"
        "util/JemallocUtil.h"
        "util/Sha1.cpp"
        "util/Sha1.h"
        "shared/DexDefs.cpp"
        "shared/DexDefs.h"
        "shared/DexEncoding.cpp"
        "shared/DexEncoding.h"
        "shared/file-utils.cpp"
        "shared/file-utils.h"
        "liblocator/locator.cpp"
        "liblocator/locator.h"
        )

add_library(redex STATIC ${redex_srcs})

install(TARGETS redex ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)

file(GLOB_RECURSE tool_srcs
        "tools/tool/*.cpp"
        "tools/tool/*.h"
        )

add_library(tool STATIC ${tool_srcs})

install(TARGETS tool ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)

file(GLOB_RECURSE resource_srcs
        "libresource/*.cpp"
        "libresource/*.h"
        )

add_library(resource STATIC ${resource_srcs})

install(TARGETS resource ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)

file(GLOB redex_all_srcs
        "tools/redex-all/*.cpp"
        "tools/redex-all/*.h"
        "tools/common/ToolsCommon.cpp"
        "tools/common/ToolsCommon.h"
        )

add_executable(redex-all ${redex_all_srcs})

if (MINGW)
    set(MINGW_EXTRA_LIBS -Wl,-Bstatic ws2_32)
else (MINGW)
    set(MINGW_EXTRA_LIBS "")
endif (MINGW)

target_link_libraries(redex-all
        ${STATIC_LINK_FLAG}
        ${Boost_LIBRARIES}
        ${REDEX_JSONCPP_LIBRARY}
        ZLIB::ZLIB
        ${CMAKE_DL_LIBS}
        redex
        resource
        ${MINGW_EXTRA_LIBS}
        m
        )

target_compile_definitions(redex-all PRIVATE)

set_link_whole(redex-all redex)

install(TARGETS redex-all DESTINATION bin)

# redex.py things...

install(FILES redex.py DESTINATION bin)
install(DIRECTORY pyredex DESTINATION bin)

file(GLOB gen_packed_apilevels "gen_packed_apilevels.py")
file(GLOB api_level_srcs "service/api-levels/framework_classes_api_*.txt")

add_custom_command(
    OUTPUT  generated_apilevels.py
    COMMAND python3 ${gen_packed_apilevels} -o generated_apilevels.py ${api_level_srcs}
    DEPENDS ${api_level_srcs} ${gen_packed_apilevels}
)
add_custom_target(generated_apilevels ALL DEPENDS generated_apilevels.py)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/generated_apilevels.py DESTINATION bin)

# Misc stuff, for good measure.
install(FILES LICENSE README.md config/default.config DESTINATION share/doc/redex)

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_GENERATOR "ZIP")
include(CPack)
