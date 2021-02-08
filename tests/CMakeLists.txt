# SPDX-License-Identifier: MIT

option(OQS_ENABLE_TEST_CONSTANT_TIME "Build test suite with support for Valgrind-based detection of non-constant time behaviour." OFF)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
   CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wbad-function-cast)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wcast-qual)
    add_compile_options(-Wnarrowing)
    add_compile_options(-Wconversion)
endif()
if (MINGW OR MSYS OR CYGWIN)
    add_definitions(-D__USE_MINGW_ANSI_STDIO=1)
    add_compile_options(-Wno-unknown-pragmas)
    add_compile_options(-Wno-unused-parameter)
endif()
if(WIN32 AND NOT (MINGW OR MSYS OR CYGWIN))
    # ignore warning for test apps
    add_compile_options(/wd4996 /wd4244)
endif()

if(NOT WIN32)
    set(LIBM m)

    if(OQS_USE_OPENSSL)
        include_directories(${OPENSSL_INCLUDE_DIR})
        set(INTERNAL_TEST_DEPS ${OPENSSL_CRYPTO_LIBRARY} ${LIBM})
    else()
        set(INTERNAL_TEST_DEPS ${LIBM})
    endif()
    if(DEFINED SANITIZER_LD_FLAGS)
        set(INTERNAL_TEST_DEPS "${INTERNAL_TEST_DEPS} ${SANITIZER_LD_FLAGS}")
    endif()
    execute_process(COMMAND ${PROJECT_SOURCE_DIR}/scripts/git_commit.sh OUTPUT_VARIABLE GIT_COMMIT)
    add_definitions(-DOQS_COMPILE_GIT_COMMIT="${GIT_COMMIT}")

    add_executable(test_aes test_aes.c ${COMMON_OBJS})
    target_link_libraries(test_aes PRIVATE ${INTERNAL_TEST_DEPS})

    add_executable(test_hash test_hash.c ${COMMON_OBJS})
    target_link_libraries(test_hash PRIVATE ${INTERNAL_TEST_DEPS})

    add_executable(test_sha3 test_sha3.c ${COMMON_OBJS})
    target_link_libraries(test_sha3 PRIVATE ${INTERNAL_TEST_DEPS})

    set(UNIX_TESTS test_aes test_hash test_sha3)

    set(PYTHON3_EXEC python3)
else()
    set(PYTHON3_EXEC python)
endif()


set(API_TEST_DEPS oqs ${LIBM})

# KEM API tests
add_executable(example_kem example_kem.c)
target_link_libraries(example_kem PRIVATE ${API_TEST_DEPS})

add_executable(kat_kem kat_kem.c)
target_link_libraries(kat_kem PRIVATE ${API_TEST_DEPS})

add_executable(test_kem test_kem.c)
if((CMAKE_C_COMPILER_ID MATCHES "Clang") OR (CMAKE_C_COMPILER_ID STREQUAL "GNU"))
    target_link_libraries(test_kem PRIVATE ${API_TEST_DEPS} Threads::Threads)
else ()
    target_link_libraries(test_kem PRIVATE ${API_TEST_DEPS})
endif()

add_executable(test_kem_mem test_kem_mem.c)
target_link_libraries(test_kem_mem PRIVATE ${API_TEST_DEPS})

add_executable(speed_kem speed_kem.c)
target_link_libraries(speed_kem PRIVATE ${API_TEST_DEPS})

# SIG API tests
add_executable(example_sig example_sig.c)
target_link_libraries(example_sig PRIVATE ${API_TEST_DEPS})

add_executable(kat_sig kat_sig.c)
target_link_libraries(kat_sig PRIVATE ${API_TEST_DEPS})

add_executable(test_sig test_sig.c)
if((CMAKE_C_COMPILER_ID MATCHES "Clang") OR (CMAKE_C_COMPILER_ID STREQUAL "GNU"))
    target_link_libraries(test_sig PRIVATE ${API_TEST_DEPS} Threads::Threads)
else ()
    target_link_libraries(test_sig PRIVATE ${API_TEST_DEPS})
endif()

add_executable(test_sig_mem test_sig_mem.c)
target_link_libraries(test_sig_mem PRIVATE ${API_TEST_DEPS})

add_executable(speed_sig speed_sig.c)
target_link_libraries(speed_sig PRIVATE ${API_TEST_DEPS})

# Enable Valgrind-based timing side-channel analysis for test_kem and test_sig
if(OQS_ENABLE_TEST_CONSTANT_TIME AND NOT OQS_DEBUG_BUILD)
    message(WARNING "OQS_ENABLE_TEST_CONSTANT_TIME is incompatible with CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}.")
    set(OQS_ENABLE_TEST_CONSTANT_TIME OFF)
endif()

if(OQS_DEBUG_BUILD AND USE_SANITIZER MATCHES "Fuzzer")
    add_library(oqs_fuzz fuzz/fuzz.c)
    target_compile_definitions(oqs_fuzz PRIVATE -D_GNU_SOURCE)
    set_target_properties(oqs_fuzz PROPERTIES C_VISIBILITY_PRESET default)

    # Loop over all of the OQS_ENABLE_KEM_X variables and create a fuzz target for each enabled scheme.
    get_cmake_property(_vars CACHE_VARIABLES)
    foreach (_var ${_vars})
        if(_var MATCHES "^OQS_ENABLE_KEM_[a-z]" AND NOT _var MATCHES "_AVAILABLE$|_avx2$|_avx$|_aesni$")
            if (${${_var}})
                string(REPLACE "OQS_ENABLE_KEM_" "" _short_name ${_var})
                add_executable(fuzz_kem_${_short_name} fuzz_kem.c)
                target_include_directories(fuzz_kem_${_short_name} PRIVATE fuzz)
                target_compile_definitions(fuzz_kem_${_short_name} PRIVATE FUZZ_TARGET=OQS_KEM_alg_${_short_name})
                target_link_libraries(fuzz_kem_${_short_name} PRIVATE dl oqs_fuzz ${API_TEST_DEPS})
                target_link_options(fuzz_kem_${_short_name} PRIVATE -fsanitize=fuzzer)
            endif()
        endif()
    endforeach()

    # Likewise for signature schemes
    foreach (_var ${_vars})
        if(_var MATCHES "^OQS_ENABLE_SIG_[a-z]" AND NOT _var MATCHES "_AVAILABLE$|_avx2$|_avx$|_aesni$")
            if (${${_var}})
                string(REPLACE "OQS_ENABLE_SIG_" "" _short_name ${_var})
                add_executable(fuzz_sig_${_short_name} fuzz_sig.c)
                target_include_directories(fuzz_sig_${_short_name} PRIVATE fuzz)
                target_compile_definitions(fuzz_sig_${_short_name} PRIVATE FUZZ_TARGET=OQS_SIG_alg_${_short_name})
                target_link_libraries(fuzz_sig_${_short_name} PRIVATE dl oqs_fuzz ${API_TEST_DEPS})
                target_link_options(fuzz_sig_${_short_name} PRIVATE -fsanitize=fuzzer)
            endif()
        endif()
    endforeach()
endif()

# Record compile options -- from target speed_kem - don't set any options only for speed_kem!
get_property(OQS_COMPILE_OPTIONS TARGET speed_kem PROPERTY COMPILE_OPTIONS)
add_definitions(-DOQS_COMPILE_OPTIONS="[${OQS_COMPILE_OPTIONS}]")

# TODO: Get CMake to find python.
# and set PATH variable in Windows
# for DLL builds.
add_custom_target(
    run_tests
    COMMAND ${PYTHON3_EXEC} -m pytest --verbose --numprocesses=auto
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS oqs example_kem kat_kem test_kem example_sig kat_sig test_sig test_sig_mem test_kem_mem ${UNIX_TESTS}
    USES_TERMINAL)
