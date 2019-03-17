cmake_minimum_required(VERSION 3.11)
include_directories(
    ../../lib
    )

SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")
SET (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /SAFESEH:NO")
SET (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /SAFESEH:NO")

file(GLOB SOURCES *.cpp)
add_library(unisthooks SHARED ${SOURCES})

target_link_libraries(unisthooks utils)

if (MSVC)
    target_compile_options(unisthooks PRIVATE -D_CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(unisthooks PROPERTIES FOLDER ReTools/dll)


