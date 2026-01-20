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

include(GNUInstallDirs)
install(EXPORT bg12_targets
    FILE BayerGrothShuffleTargets.cmake
    NAMESPACE BayerGroth::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BayerGrothShuffle
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    cmake/BayerGrothShuffleConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/BayerGrothShuffleConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BayerGrothShuffle
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/BayerGrothShuffleConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/BayerGrothShuffleConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/BayerGrothShuffleConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BayerGrothShuffle
)

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
