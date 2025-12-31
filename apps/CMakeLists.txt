add_executable(bg12_card_shuffle main.cpp)

target_link_libraries(bg12_card_shuffle
    PRIVATE
        bg12_core
        OpenSSL::Crypto
)

target_include_directories(bg12_card_shuffle PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(bg12_card_shuffle PROPERTIES
    OUTPUT_NAME "bg12_card_shuffle"
)

install(TARGETS bg12_card_shuffle RUNTIME DESTINATION bin)
