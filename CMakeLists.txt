cmake_minimum_required(VERSION 3.13)

# Require C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# project information
project(unfolding CXX)

# Third-party libraries
add_subdirectory(third-party)

# Source folder
add_subdirectory(src)

# The executable code
add_subdirectory(app)

# installation
install(TARGETS ${PROJECT_NAME} DESTINATION ${PROJECT_SOURCE_DIR}/bin)