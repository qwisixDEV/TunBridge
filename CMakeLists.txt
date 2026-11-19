cmake_minimum_required(VERSION 3.20)

project(TunBridge VERSION 1.0 LANGUAGES CXX)

add_executable(TunBridge WIN32
    src/main.cpp
    src/state.cpp
    src/util.cpp
    src/config.cpp
    src/system.cpp
    src/net.cpp
    src/tun.cpp
    src/probe.cpp
    src/app.cpp
    src/ui.cpp
)

target_include_directories(TunBridge PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(TunBridge PRIVATE cxx_std_17)

target_compile_definitions(TunBridge PRIVATE
    _CRT_SECURE_NO_WARNINGS
    _WIN32_WINNT=0x0601
)

if(MSVC)
    target_compile_options(TunBridge PRIVATE /utf-8)
else()
    target_compile_options(TunBridge PRIVATE -Wall)
endif()

target_link_libraries(TunBridge PRIVATE
    ws2_32
    iphlpapi
    wininet
    comctl32
    gdiplus
    shell32
    advapi32
    crypt32
    user32
    gdi32
    ole32
)

set_target_properties(TunBridge PROPERTIES
    OUTPUT_NAME "TunBridge"
)
