#include_directories(..)

file(GLOB SOURCES *.cpp)
add_library(utils ${SOURCES})

if (MSVC)
    target_compile_options(utils PRIVATE -D_CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(utils PROPERTIES FOLDER ReTools/lib)
