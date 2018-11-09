project(unpack)
cmake_minimum_required(VERSION 3.4.1)

add_definitions(-DNO_LOCALE_SUPPORT=True)

include_directories(.)

add_subdirectory(AndroidDef)

aux_source_directory(. RootSrc)

add_library(unpack SHARED ${RootSrc} )

target_link_libraries(unpack AndroidDef android c dl log)

