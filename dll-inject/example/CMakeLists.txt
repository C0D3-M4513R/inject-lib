cmake_minimum_required(VERSION 3.21)
project(test C)
set(CMAKE_C_STANDARD 17)
include_directories(include)
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -O2 -GL")

add_executable(test test.c)
target_link_libraries(test dll_inject.lib kernel32.lib ws2_32.lib bcrypt.lib advapi32.lib userenv.lib kernel32.lib msvcrt.lib ntdll.lib)
