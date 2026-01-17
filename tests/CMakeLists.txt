add_executable(bg12_test test_bg12.cpp)

target_link_libraries(bg12_test
    PRIVATE
        bg12_core
        OpenSSL::Crypto
)

target_include_directories(bg12_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(bg12_test PROPERTIES
    OUTPUT_NAME "bg12_test"
)

add_test(NAME bg12_test COMMAND bg12_test)

install(TARGETS bg12_test RUNTIME DESTINATION bin)
