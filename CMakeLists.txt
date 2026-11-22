cmake_minimum_required(VERSION 3.20)

project(TunBridge VERSION 1.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Threads REQUIRED)
enable_testing()

# Compact, LTO-optimised release binaries; no debug symbols in installed files.
if(NOT MSVC)
    add_compile_options(-Wall -Wextra -ffunction-sections -fdata-sections)
    add_link_options(-Wl,--gc-sections)
    if(NOT WIN32)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        add_compile_options(-O2)
        add_link_options($<$<CONFIG:Release>:-s>)
    else()
        add_link_options(-static -static-libgcc -static-libstdc++ -s)
    endif()
endif()

# ---------------------------------------------------------------------------
# Platform-independent core: config model, CLI, SHA-256, URL/HTTP helpers.
# ---------------------------------------------------------------------------
add_library(tb_core STATIC
    src/core.cpp
)
target_include_directories(tb_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(tb_core PUBLIC Threads::Threads)

if(WIN32)
    # -----------------------------------------------------------------------
    # Original Win32 / GDI+ application (unchanged behaviour).
    # -----------------------------------------------------------------------
    target_link_libraries(tb_core PUBLIC crypt32)

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
    target_include_directories(TunBridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(TunBridge PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _WIN32_WINNT=0x0601
    )
    if(MSVC)
        target_compile_options(TunBridge PRIVATE /utf-8)
        set_property(TARGET TunBridge PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
    target_link_libraries(TunBridge PRIVATE
        tb_core
        ws2_32 iphlpapi wininet comctl32 gdiplus shell32 advapi32
        crypt32 user32 gdi32 ole32
    )
    set_target_properties(TunBridge PROPERTIES OUTPUT_NAME "TunBridge")

elseif(UNIX AND NOT APPLE)
    # -----------------------------------------------------------------------
    # Linux (Arch / CachyOS): unprivileged Qt Widgets GUI + root helper.
    # -----------------------------------------------------------------------
    find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets Network)
    set(CMAKE_AUTOMOC ON)
    find_package(CURL REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_package(ZLIB REQUIRED)

    target_link_libraries(tb_core PUBLIC OpenSSL::Crypto)

    set(TB_LINUX_COMMON
        src/platform/linux/helper_protocol.cpp
    )

    add_executable(tunbridge
        src/platform/linux/gui/main.cpp
        src/platform/linux/gui/app_controller.cpp
        src/platform/linux/gui/app_controller.hpp
        src/platform/linux/gui/main_window.cpp
        src/platform/linux/gui/main_window.hpp
        src/platform/linux/gui/tray_icon.cpp
        src/platform/linux/gui/tray_icon.hpp
        src/platform/linux/gui/single_instance.cpp
        src/platform/linux/gui/single_instance.hpp
        src/platform/linux/net_engine.cpp
        src/platform/linux/upstream.cpp
        src/platform/linux/health.cpp
        src/platform/linux/scanner.cpp
        src/platform/linux/xdg.cpp
        src/platform/linux/system_proxy.cpp
        src/platform/linux/traffic.cpp
        src/platform/linux/download.cpp
        ${TB_LINUX_COMMON}
    )
    target_link_libraries(tunbridge PRIVATE
        tb_core Qt6::Widgets Qt6::Network CURL::libcurl OpenSSL::Crypto ZLIB::ZLIB
    )
    set_target_properties(tunbridge PROPERTIES OUTPUT_NAME "tunbridge")

    add_executable(tunbridge-helper
        src/platform/linux/helper_main.cpp
        src/platform/linux/privileged.cpp
        ${TB_LINUX_COMMON}
    )
    target_link_libraries(tunbridge-helper PRIVATE tb_core)
    set_target_properties(tunbridge-helper PROPERTIES OUTPUT_NAME "tunbridge-helper")

    add_executable(tb_net_tests tests/net_engine_tests.cpp)
    target_link_libraries(tb_net_tests PRIVATE tb_core)
    add_test(NAME net_engine COMMAND tb_net_tests)

    add_executable(tb_helper_tests tests/helper_tests.cpp
        src/platform/linux/helper_protocol.cpp
    )
    target_link_libraries(tb_helper_tests PRIVATE tb_core)
    add_test(NAME helper_protocol COMMAND tb_helper_tests)

    install(TARGETS tunbridge tunbridge-helper RUNTIME DESTINATION bin)
    install(FILES packaging/linux/tunbridge.desktop DESTINATION share/applications)
    install(FILES packaging/linux/org.tunbridge.helper.policy
            DESTINATION share/polkit-1/actions)
endif()

# ---------------------------------------------------------------------------
# Smoke/unit tests for the platform-independent core.
# ---------------------------------------------------------------------------
add_executable(tb_core_tests tests/core_tests.cpp)
target_link_libraries(tb_core_tests PRIVATE tb_core)
add_test(NAME core COMMAND tb_core_tests)
