cmake_minimum_required(VERSION 3.23)

project(traffic_analyzer C)

include_directories(/usr/include/glib-2.0 /usr/lib/x86_64-linux-gnu/glib-2.0/include)

link_libraries(pcap glib-2.0 rt)

add_executable(traffic_analyzer main.c main.h)
