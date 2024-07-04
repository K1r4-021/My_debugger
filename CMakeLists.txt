cmake_minimum_required(VERSION 3.22.1)
project("Debugger")


include_directories(
    src 
    include 
    ext/linenoise 
    ext/libelfin
)

add_executable(My_debugger 
    ext/linenoise/src/ConvertUTF.cpp 
    ext/linenoise/src/linenoise.cpp 
    ext/linenoise/src/wcwidth.cpp 
    src/debugger.cpp 
)

add_custom_target(libelfin 
    COMMAND make 
    WORKING_DIRECTORY 
    ${CMAKE_SOURCE_DIR}/ext/libelfin
)

target_include_directories(My_debugger PUBLIC ext/linenoise/inc)

target_link_libraries(My_debugger 
    ${CMAKE_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so 
    ${CMAKE_SOURCE_DIR}/ext/libelfin/elf/libelf++.so
)

add_dependencies(My_debugger libelfin)

set_target_properties(My_debugger PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY 
    ${CMAKE_SOURCE_DIR}
)
