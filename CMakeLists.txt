cmake_minimum_required(VERSION 3.10)
project(ca-rpc CXX C)

set(IDLDIR "${CMAKE_CURRENT_SOURCE_DIR}/idl")
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED_DIR}")

# Custom commands to compile each IDL file via dceidl
add_custom_command(
    OUTPUT
        "${GENERATED_DIR}/ms-dtyp.h"
    COMMAND
        dceidl -out "${GENERATED_DIR}" "${IDLDIR}/ms-dtyp.idl"
    WORKING_DIRECTORY
        "${IDLDIR}"
    DEPENDS
        "${IDLDIR}/ms-dtyp.idl"
    COMMENT
        "Compiling ms-dtyp.idl -> ms-dtyp.h"
    VERBATIM
)

add_custom_command(
    OUTPUT
        "${GENERATED_DIR}/ms-icpr.h"
        "${GENERATED_DIR}/ms-icpr_cstub.c"
    COMMAND
        dceidl -out "${GENERATED_DIR}" -server none -keep c_source "${IDLDIR}/ms-icpr.idl"
    WORKING_DIRECTORY
        "${IDLDIR}"
    DEPENDS
        "${IDLDIR}/ms-icpr.idl"
    COMMENT
        "Compiling ms-icpr.idl -> ms-icpr.h, ms-icpr_cstub.c"
    VERBATIM
)

# Create a target that forces those commands to run
add_custom_target(
    compile-idl ALL
    DEPENDS
        "${GENERATED_DIR}/ms-dtyp.h"
        "${GENERATED_DIR}/ms-icpr.h"
        "${GENERATED_DIR}/ms-icpr_cstub.c"
)

# Build a "library" from the generated .o files
add_library(ms-icpr STATIC "${GENERATED_DIR}/ms-icpr_cstub.c")
add_dependencies(ms-icpr compile-idl)
target_include_directories(ms-icpr PUBLIC "${GENERATED_DIR}")

# Build the executable
add_executable(ca-rpc
    src/main.cpp
    src/cert_trans_blob.cpp
    src/encoding.cpp
    src/req_input.cpp
    src/rpc_client.cpp
)

find_package(OpenSSL REQUIRED)

# C++17 support for <filesystem>
target_compile_features(ca-rpc PRIVATE cxx_std_17)

# Include directories
target_include_directories(ca-rpc PRIVATE src)

# Link libraries
target_link_libraries(ca-rpc PRIVATE "/usr/local/lib/libdcerpc.so" ms-icpr OpenSSL::SSL)