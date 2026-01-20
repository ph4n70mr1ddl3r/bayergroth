add_library(bg12_core
    bayer_groth_shuffle.h
    bayer_groth_shuffle.cpp
    card_shuffle_protocol.h
    card_shuffle_protocol.cpp
    crypto_utils.h
    crypto_utils.cpp
)

target_include_directories(bg12_core
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(bg12_core
    PUBLIC
        OpenSSL::Crypto
        ${GMP_LIBRARIES}
)

set_target_properties(bg12_core PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "bg12_core"
)

install(TARGETS bg12_core
    EXPORT bg12_targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION include
)
