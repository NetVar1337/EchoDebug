# Agent test host: the official AngelScript SDK (pinned release zip, hash-checked; the archive's sdk/ root is stripped) + host.cpp.
#   cmake -S tests/agent -B build/agent-tests && cmake --build build/agent-tests -j
#   ctest --test-dir build/agent-tests --output-on-failure
cmake_minimum_required(VERSION 3.16)
project(echo_agent_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(angelscript
  URL https://www.angelcode.com/angelscript/sdk/files/angelscript_2.38.0.zip
  URL_HASH SHA256=b33b5dbcda10317ef67d628353d83246984ce6fcac102d4dc2aed121eba52e6f
  SOURCE_SUBDIR angelscript/projects/cmake
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(angelscript)
set(AS_ADDONS ${angelscript_SOURCE_DIR}/add_on)

add_executable(agent_test
  host.cpp
  ${AS_ADDONS}/scriptarray/scriptarray.cpp
  ${AS_ADDONS}/scriptbuilder/scriptbuilder.cpp
  ${AS_ADDONS}/scriptmath/scriptmath.cpp
  ${AS_ADDONS}/scriptstdstring/scriptstdstring.cpp
  ${AS_ADDONS}/scriptstdstring/scriptstdstring_utils.cpp)
target_include_directories(agent_test PRIVATE ${AS_ADDONS})
target_link_libraries(agent_test PRIVATE angelscript)

enable_testing()
set(REPO ${CMAKE_CURRENT_SOURCE_DIR}/../..)
add_test(NAME agent
  COMMAND agent_test ${CMAKE_CURRENT_SOURCE_DIR}/echo_mock.as ${REPO}/agent/echo_debug.as ${CMAKE_CURRENT_SOURCE_DIR}/agent_tests.as)
