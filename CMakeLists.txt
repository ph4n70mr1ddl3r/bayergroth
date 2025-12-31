cmake_minimum_required(VERSION 3.16)
project(BayerGrothShuffle VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMP REQUIRED gmpxx gmp)

add_subdirectory(src)
add_subdirectory(apps)
add_subdirectory(tests)

include(CTest)
enable_testing()

function(print_status MESSAGE)
    message(STATUS "${MESSAGE}")
endfunction()

print_status("=== Bayer-Groth 2012 Shuffle Protocol ===")
print_status("Build configuration:")
print_status("  C++ Standard: ${CMAKE_CXX_STANDARD}")
print_status("  OpenSSL: ${OPENSSL_VERSION}")
print_status("  GMP: ${GMP_VERSION}")
print_status("")
print_status("Executables:")
print_status("  bg12_card_shuffle - Two-player card shuffle demo")
print_status("  bg12_test - Full protocol test")
print_status("")
