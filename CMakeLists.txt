cmake_minimum_required(VERSION 3.11)

project(ReTools CXX C)
set(CMAKE_CXX_STANDARD 17)

if (${CMAKE_SIZEOF_VOID_P} EQUAL "8")
    set (MS_ARCHITECTURE "x64")
else()
    set (MS_ARCHITECTURE "x86")
endif()

#if (NOT CMAKE_CL_64 OR NOT ${MS_ARCHITECTURE} STREQUAL "x64")
#    message(FATAL_ERROR "Only x64-bit is supported right now")
#endif()

add_subdirectory(lib)
add_subdirectory(dll)
add_subdirectory(exe)
