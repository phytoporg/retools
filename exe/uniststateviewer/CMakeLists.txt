cmake_minimum_required(VERSION 3.11)
include_directories(
    ../../lib
    )

file(GLOB SOURCES *.cpp)
add_executable(uniststateviewer ${SOURCES})

if (MSVC)
    target_compile_options(uniststateviewer PRIVATE -D_CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(uniststateviewer PROPERTIES FOLDER ReTools/exe)
target_link_libraries(uniststateviewer utils)
