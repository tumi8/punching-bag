cmake_minimum_required(VERSION 3.10)
project(punchingbag)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable
add_executable(punchingbag
    punchingbag.cpp
)

# Include current directory for headers like IPv6-table.hpp
target_include_directories(punchingbag PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    /usr/include/pcap   
)

# Link with pcap and nlohmann_json
target_link_libraries(punchingbag
    PRIVATE
        pcap
        net
        pthread
)
