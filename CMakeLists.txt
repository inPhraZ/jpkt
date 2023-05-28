cmake_minimum_required(VERSION 3.10)

project(jpkt C)

set(SHARED_TARGET "${PROJECT_NAME}shared")
set(STATIC_TARGET "${PROJECT_NAME}static")

find_package(PkgConfig REQUIRED)

pkg_search_module(PCAP REQUIRED libpcap)
pkg_search_module(JSONGLIB REQUIRED json-glib-1.0)

file(GLOB JPKTFILES
    ${CMAKE_SOURCE_DIR}/src/*.c
    ${CMAKE_SOURCE_DIR}/include/*.h
)

function(jpkt_build_library TNAME TYPE)
    add_library(${TNAME} ${TYPE} ${JPKTFILES})
    set_target_properties(${TNAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
    target_include_directories(${TNAME}
        PUBLIC
            ${CMAKE_SOURCE_DIR}/include
        PRIVATE
            ${PCAP_INCLUDE_DIRS}
            ${JSONGLIB_INCLUDE_DIRS})

    target_link_libraries(${TNAME}
        PUBLIC
            ${PCAP_LIBRARIES}
            ${JSONGLIB_LIBRARIES})
endfunction()

jpkt_build_library(${SHARED_TARGET} SHARED)
jpkt_build_library(${STATIC_TARGET} STATIC)

add_executable(ex ${CMAKE_SOURCE_DIR}/example/example.c)
target_link_libraries(ex PRIVATE ${STATIC_TARGET})

