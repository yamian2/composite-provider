cmake_minimum_required(VERSION 3.10)
project(composite_provider C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")

# Find OpenSSL.
#
# 3.5 is a hard floor, not a preference: ML-KEM-768/1024 and ML-DSA arrived in
# that release, and src/signature/composite_sig_encoding.c references
# OSSL_PKEY_PARAM_ML_DSA_SEED, which is absent from core_names.h before it.
# Declaring anything lower lets configuration succeed and then fails the build
# with undeclared-identifier errors deep in a source file.
find_package(OpenSSL 3.5 REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/kem
    ${CMAKE_SOURCE_DIR}/src/signature
    ${OPENSSL_INCLUDE_DIR}
)

# Source files
set(PROVIDER_SOURCES
    src/common/provider.c
    src/common/provider_ctx.c
    src/signature/composite_sig.c
    src/signature/composite_sig_key.c
    src/signature/composite_sig_encoding.c
    src/signature/composite_encoder.c
    src/kem/composite_kem_key.c
    src/kem/composite_kem_keymgmt.c
    src/kem/composite_kem_encoding.c
    src/kem/composite_kem_info.c
    src/kem/composite_kem.c
    src/kem/mlkem_composite.c
    src/signature/mldsa_composite.c
    src/signature/composite_keys.c
    src/common/composite_keymgmt.c
    src/signature/composite_decoder.c
)

# Build shared library
add_library(composite SHARED ${PROVIDER_SOURCES})
target_link_libraries(composite ${OPENSSL_CRYPTO_LIBRARY})

# Set output properties
set_target_properties(composite PROPERTIES
    PREFIX ""
    OUTPUT_NAME "composite"
)
if(APPLE)
    set_target_properties(composite PROPERTIES
        SUFFIX ".dylib"
    )
else()
    set_target_properties(composite PROPERTIES
        SUFFIX ".so"
    )
endif()

# Installation
install(TARGETS composite DESTINATION lib)

# Tests
enable_testing()
add_subdirectory(tests)
